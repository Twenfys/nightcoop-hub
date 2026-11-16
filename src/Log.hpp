#pragma once

#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

// Logging for the mod and the hub. The module knows nothing of RED4ext or Windows: the same core builds into the console
// tools and the hub. An external sink (the RED4ext log, stderr) plugs in through SetSink.
namespace nc::log
{
enum class Level
{
    Trace,
    Info,
    Warn,
    Error
};

const char* LevelName(Level aLevel);

/// "No limit" line budget of a module: module line counters start from it and never run out. A flood from one place is
/// held back by the common kMaxLinesPerSecond in Write.
inline constexpr int32_t kNoLineLimit = 1 << 30;
/// At most this many lines a second: the rest are dropped, and the next second starts with a line saying how many.
inline constexpr uint32_t kMaxLinesPerSecond = 2000;

/// Lines that show whether the process is alive pass the flood limit: a flood from one place must not push them out
/// right when they matter.
inline bool PastFloodLimit(std::string_view aMessage)
{
    for (const std::string_view start : {"frame cost", "netstats", "hang watch"})
        if (aMessage.substr(0, start.size()) == start)
            return true;
    return false;
}
/// Logs of previous runs kept (nightcoop.log of the last run -> logs/nightcoop-session-<time>.log).
inline constexpr size_t kSessionKeep = 20;

/// Opens the log file (UTF-8 path). The previous run's log is not overwritten: it moves to
/// logs/nightcoop-session-<its time>.log.
void Init(const std::string& aDirectory);
void Shutdown();

/// Extra message sink. Called under the same mutex as the file write, so it need not care about races.
using Sink = std::function<void(Level, const char*)>;
void SetSink(Sink aSink);

/// 23.10 (log_hide_ips): dotted IPv4 addresses (players' public and local ones) are written as <ip> into the file, the ring
/// and the sink — players share their logs, the addresses are personal data. 127.x.x.x and 0.0.0.0 stay. Off by default:
/// the plugin turns it on, the hub and the tools keep addresses. Any thread.
void SetHideAddresses(bool aOn);
bool HidingAddresses();

/// 23.10 (log_async): the file and the sink are written by a log thread —
/// a line goes to the ring and to a queue (memory), no thread that logs waits for the disk. Off by default: the plugin turns
/// it on; the hub and the tools write each line by the thread that gives it, as before. Any thread. Returns a line for the
/// console.
std::string SetAsync(bool aOn);
bool Async();
/// The log thread: queued now, the most queued, the longest write, lines not in the file (the queue was full).
std::string DescribeWriter();

/// 07.11 (perf_0711): the edge of a log line on this thread (true — it begins,
/// false — it ends) for the measuring of the plugin's game tick (src/TickSpans.hpp): the plugin sets it on its game thread for
/// the frames it samples and clears it after; nobody else sets it. Empty — nothing: one thread-local read a line.
inline thread_local void (*t_spanHook)(bool aBegin) = nullptr;

/// A log line on this thread as one span of the measuring (formatting, the queue, Due): the hook's two edges, if it is set.
class LineSpan
{
public:
    LineSpan() noexcept : m_hook(t_spanHook)
    {
        if (m_hook)
            m_hook(true);
    }
    ~LineSpan()
    {
        if (m_hook)
            m_hook(false);
    }
    LineSpan(const LineSpan&) = delete;
    LineSpan& operator=(const LineSpan&) = delete;

private:
    void (*m_hook)(bool);
};

void Write(Level aLevel, std::string_view aMessage);

/// Same, but waits for the log lock no longer than aWaitMs: false — not written (someone else holds the lock; a hang
/// watchdog must not get stuck on a lock held by a stuck thread). Nor for the disk: without log_async a write of another
/// thread longer than aWaitMs leaves the line queued for the next one. Any thread.
bool TryWrite(Level aLevel, std::string_view aMessage, uint32_t aWaitMs);

/// A line of one kind at most once per aEveryMs (key: place and subject, e.g. a caller address and an NPC number): a
/// stream of identical lines from hooks and ticks does not drown the log. Any thread.
bool Due(uint64_t aKey, uint64_t aEveryMs);

/// 16.11 (logdiet): a line of a subject (a quest node
/// and its kind of line) that says what the subject's last line of that kind said is folded — counted, not written. The
/// next line of the subject that says another thing carries the count (FoldTail); what is left when the subject's world
/// ends, its owner writes with FoldTail too. aWhat — the line's decision: its text without times, sequence numbers and
/// measures. Not thread-safe: one owner thread or the owner's lock.
struct Fold
{
    uint64_t what = 0;    ///< the decision of the last line of the subject
    bool told = false;    ///< a line of the subject was written
    uint32_t folded = 0;  ///< lines folded since the last written one
    uint64_t firstAt = 0; ///< the time of the first folded (the caller's clock: shared ms)
    uint64_t lastAt = 0;  ///< ...of the last folded
    uint64_t longest = 0; ///< the largest measure of a folded line (ms), 0 — none
};

/// A line that says the same as the last one: counted (the time, the largest measure). Folded lines only.
inline void FoldCount(Fold& aFold, uint64_t aAt, uint64_t aMeasure = 0)
{
    if (aFold.folded++ == 0)
    {
        aFold.firstAt = aAt;
        aFold.longest = 0;
    }
    aFold.lastAt = aAt;
    if (aMeasure > aFold.longest)
        aFold.longest = aMeasure;
}

/// Write the line now (true): the subject's first, or it says another thing than its last line; otherwise it is counted
/// (false).
inline bool FoldTake(Fold& aFold, uint64_t aWhat, uint64_t aAt, uint64_t aMeasure = 0)
{
    if (aFold.told && aFold.what == aWhat)
    {
        FoldCount(aFold, aAt, aMeasure);
        return false;
    }
    aFold.told = true;
    aFold.what = aWhat;
    return true;
}

/// The tail of a line written now about the lines folded before it — « (+N the same line(s) since t=A, the last at t=B,
/// the longest <aMeasure> X s)», or empty; the count starts anew.
inline std::string FoldTail(Fold& aFold, const char* aMeasure = nullptr)
{
    if (!aFold.folded)
        return {};
    std::string text = std::format(" (+{} the same line(s) since t={}, the last at t={}", aFold.folded, aFold.firstAt,
                                   aFold.lastAt);
    if (aMeasure && aFold.longest)
        text += std::format(", the longest {} {:.1f} s", aMeasure, static_cast<double>(aFold.longest) / 1000.0);
    text += ')';
    aFold.folded = 0;
    aFold.longest = 0;
    return text;
}

/// 16.11 (logdiet): our log file is open — the external sink takes only warnings and errors then (Main: the RED4ext
/// log); not open — everything, as before. Any thread.
bool FileOpen();

// ---------------------------------------------------------------- the last minutes

/// The last minutes of the log, kept in memory as a ring. A snapshot of them is a separate file in logs/ next to the log:
/// on request (NightCoopLogSave), on exit and on a crash.
inline constexpr uint32_t kRecentSeconds = 300;
/// Snapshots kept in logs/; older ones are deleted.
inline constexpr size_t kRecentKeep = 40;

/// Pieces of the ring for the last aSeconds. No lock and no allocation — for the crash handler: the line at the edge may
/// be incomplete.
struct RecentSpan
{
    const char* first = nullptr;
    size_t firstSize = 0;
    const char* second = nullptr;
    size_t secondSize = 0;
};
RecentSpan RecentUnlocked(uint32_t aSeconds);

/// Snapshot directory (UTF-8): logs/ next to the log, set by Init.
std::string RecentDirectory();

/// Snapshot header (build, protocol), set at start (up to 511 bytes).
void SetRecentHeader(const std::string& aText);
/// The same header without the lock, for the crash handler.
const char* RecentHeaderUnlocked();

/// Snapshot of the last aSeconds into logs/nightcoop-last-<date>-<time>-<aReason>.log. The ring is copied under the log
/// lock and the file is written without it. Returns the path (UTF-8), or empty with the reason in aError.
std::string SaveRecent(const std::string& aReason, const std::string& aNote, uint32_t aSeconds = kRecentSeconds,
                       std::string* aError = nullptr);

/// Same for the hang watchdog: waits for the log lock no longer than aWaitMs, otherwise copies the ring without it (as the
/// crash handler does: the line at the edge may be incomplete). Any thread.
std::string SaveRecentNoWait(const std::string& aReason, const std::string& aNote, uint32_t aWaitMs,
                             uint32_t aSeconds = kRecentSeconds, std::string* aError = nullptr);

template<class... Args>
void Trace(std::format_string<Args...> aFmt, Args&&... aArgs)
{
    const LineSpan span;
    Write(Level::Trace, std::format(aFmt, std::forward<Args>(aArgs)...));
}

template<class... Args>
void Info(std::format_string<Args...> aFmt, Args&&... aArgs)
{
    const LineSpan span;
    Write(Level::Info, std::format(aFmt, std::forward<Args>(aArgs)...));
}

template<class... Args>
void Warn(std::format_string<Args...> aFmt, Args&&... aArgs)
{
    const LineSpan span;
    Write(Level::Warn, std::format(aFmt, std::forward<Args>(aArgs)...));
}

template<class... Args>
void Error(std::format_string<Args...> aFmt, Args&&... aArgs)
{
    const LineSpan span;
    Write(Level::Error, std::format(aFmt, std::forward<Args>(aArgs)...));
}
} // namespace nc::log
