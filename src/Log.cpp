#include "Log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace nc::log
{
namespace
{
/// The ring, the queue of lines for the file and the flood counters. Held for memory work only: no disk under it.
std::mutex g_mutex;
/// 23.10 (log_async): the file and the sink — the disk part. Lock order:
/// g_ioMutex, then g_mutex (never g_ioMutex while g_mutex is held).
std::mutex g_ioMutex;
FILE* g_file = nullptr; ///< under g_ioMutex
Sink g_sink;            ///< under g_ioMutex

// Ring of the last lines. Static: the crash handler reads it without the lock and without the heap (it may be corrupt).
// 16 MB: room for five minutes of the densest log.
constexpr size_t kRingBytes = size_t(16) << 20;
/// Second marks: the ring byte where each second that had lines begins.
constexpr size_t kMarks = 4096;
struct Mark
{
    int64_t second = 0;
    uint64_t total = 0;
};
char g_ring[kRingBytes];
Mark g_marks[kMarks];
std::atomic<uint64_t> g_ringTotal{0}; ///< bytes ever written into the ring
std::atomic<uint64_t> g_markCount{0};
int64_t g_lastMarkSecond = INT64_MIN; ///< under g_mutex
std::string g_recentDir;              ///< under g_mutex
/// Snapshot header (build, protocol): the crash handler reads it too, hence an array rather than a string.
char g_header[512] = {};

void LocalTime(std::tm& aOut, int* aMs = nullptr)
{
    using namespace std::chrono;
    const auto now = system_clock::now();
    if (aMs)
        *aMs = static_cast<int>((duration_cast<milliseconds>(now.time_since_epoch()) % 1000).count());
    const auto t = system_clock::to_time_t(now);
#ifdef _WIN32
    localtime_s(&aOut, &t);
#else
    localtime_r(&t, &aOut);
#endif
}

std::string Timestamp()
{
    std::tm local{};
    int ms = 0;
    LocalTime(local, &ms);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d", local.tm_hour, local.tm_min, local.tm_sec, ms);
    return buf;
}

int64_t NowSecond()
{
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

/// Under g_mutex: the line goes into the ring, with a second mark if the second is new.
void RingAppend(const char* aData, size_t aSize)
{
    const int64_t second = NowSecond();
    const uint64_t total = g_ringTotal.load(std::memory_order_relaxed);
    if (second != g_lastMarkSecond)
    {
        g_lastMarkSecond = second;
        const uint64_t count = g_markCount.load(std::memory_order_relaxed);
        g_marks[count % kMarks] = {second, total};
        g_markCount.store(count + 1, std::memory_order_release);
    }
    if (aSize > kRingBytes)
    {
        aData += aSize - kRingBytes;
        aSize = kRingBytes;
    }
    const size_t pos = static_cast<size_t>(total % kRingBytes);
    const size_t head = std::min(aSize, kRingBytes - pos);
    std::memcpy(g_ring + pos, aData, head);
    if (head < aSize)
        std::memcpy(g_ring, aData + head, aSize - head);
    g_ringTotal.store(total + aSize, std::memory_order_release);
}

std::filesystem::path Utf8Path(const std::string& aUtf8)
{
    return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(aUtf8.data()), aUtf8.size()));
}

std::string ToUtf8(const std::filesystem::path& aPath)
{
    const std::u8string text = aPath.u8string();
    return std::string(reinterpret_cast<const char*>(text.data()), text.size());
}

std::string Sanitize(const std::string& aText)
{
    std::string out;
    for (const char c : aText)
        out += (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ? c
                                                                                                                 : '_';
    return out.empty() ? std::string("snapshot") : out.substr(0, 32);
}

/// At most aKeep files <aPrefix>*.log in the directory: the oldest (names sort by time) go.
void Prune(const std::filesystem::path& aDir, const char* aPrefix = "nightcoop-last-", size_t aKeep = kRecentKeep)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    std::vector<fs::path> snapshots;
    for (fs::directory_iterator it(aDir, ec), end; !ec && it != end; it.increment(ec))
    {
        const std::string name = ToUtf8(it->path().filename());
        if (name.rfind(aPrefix, 0) == 0 && name.size() > 4 && name.substr(name.size() - 4) == ".log")
            snapshots.push_back(it->path());
    }
    if (snapshots.size() <= aKeep)
        return;
    std::sort(snapshots.begin(), snapshots.end());
    for (size_t i = 0; i + aKeep < snapshots.size(); ++i)
        fs::remove(snapshots[i], ec);
}

/// The previous run's log moves to logs/nightcoop-session-<time of its last write>.log, to be read after a restart.
/// Under g_mutex, before the new one opens.
void KeepPreviousSession(const std::string& aDirectory)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path old = Utf8Path(aDirectory) / "nightcoop.log";
    if (!fs::exists(old, ec) || fs::file_size(old, ec) <= 3)
        return;
    const auto written = fs::last_write_time(old, ec);
    if (ec)
        return;
    // File clock -> system clock without clock_cast (not available on every platform the core builds on)
    const auto system = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        written - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
    const std::time_t t = std::chrono::system_clock::to_time_t(system);
    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &t);
#else
    localtime_r(&t, &local);
#endif
    char name[64];
    std::snprintf(name, sizeof(name), "nightcoop-session-%04d-%02d-%02d-%02d-%02d-%02d.log", local.tm_year + 1900,
                  local.tm_mon + 1, local.tm_mday, local.tm_hour, local.tm_min, local.tm_sec);
    const fs::path dir = Utf8Path(aDirectory) / "logs";
    fs::create_directories(dir, ec);
    fs::rename(old, dir / name, ec);
    if (!ec)
        Prune(dir, "nightcoop-session-", kSessionKeep);
}

// Lines-per-second limit (a flood from one place): under g_mutex
int64_t g_floodSecond = 0;
uint32_t g_floodLines = 0;
uint32_t g_floodDropped = 0;
/// Flushing not on every line: under g_ioMutex
std::chrono::steady_clock::time_point g_lastFlush{};

// ---------------------------------------------------------------- 23.10 (log_async)
//
// Run of 23.10 21:50: the game thread stood in log writes to the disk —
// the host's body tick 500.9 ms in WriteFile of our nightcoop.log (the fflush every 100 ms), a guest's 13 frames of 0.45–1 s in
// a row in the writes of the RED4ext log (the sink: spdlog -> fwrite). 89 lines a second: a slow disk, not a flood. A line now
// goes to the ring and to a queue (memory, under g_mutex), and the log thread writes the file and the sink. Off (the hub, the
// tools, NightCoopQuestSet("log_async", false)) — the thread that gives a line writes it to the disk, as before (the same
// queue, at once).

/// A line for the file and the sink.
struct QueuedLine
{
    Level level = Level::Info;
    std::string line;     ///< "[time] [level] message\n" — as in the file
    size_t messageAt = 0; ///< where the message begins in it (the sink takes the message alone)
    bool toSink = true;   ///< the flood note goes to the file only (as before)
};
std::vector<QueuedLine> g_queue; ///< under g_mutex, oldest first
size_t g_queueBytes = 0;         ///< under g_mutex
bool g_queueUrgent = false;      ///< under g_mutex: a warning or an error waits in the queue
uint64_t g_fileDropped = 0;      ///< under g_mutex: lines not queued — the queue was full (the disk stood)
bool g_closed = false;           ///< under g_mutex: Shutdown is done — lines go to the ring only
std::atomic<bool> g_async{false};
std::condition_variable g_wake;  ///< with g_mutex: the log thread
std::condition_variable g_exitedCv;
bool g_stop = false;             ///< under g_mutex
bool g_writerExited = false;     ///< under g_mutex
/// The log thread. A pointer that is never deleted: a std::thread left joinable in a static at exit would call terminate.
std::thread* g_writer = nullptr;

/// The queue holds at most this much (a disk standing for half a minute: ~2000 lines a second × 300 bytes is 18 MB)
constexpr size_t kQueueMaxBytes = size_t(32) << 20;
/// The log thread wakes at once for a warning, an error or this much queued; otherwise every kWriterPeriodMs
constexpr size_t kWakeBytes = size_t(256) << 10;
constexpr auto kWriterPeriodMs = std::chrono::milliseconds(100);
/// A write to the disk this long is a line of the log thread (not more often than once per kSlowNoteEveryMs)
constexpr uint64_t kSlowWriteUs = 200'000;
constexpr uint64_t kSlowNoteEveryMs = 10'000;
/// Shutdown waits this long for the log thread to write the rest
constexpr uint32_t kShutdownWaitMs = 5000;

// Counters (any thread reads them for Describe)
std::atomic<uint64_t> g_batches{0};
std::atomic<uint64_t> g_batchLines{0};
std::atomic<uint64_t> g_writeMaxUs{0};
std::atomic<uint64_t> g_slowWrites{0};
std::atomic<uint64_t> g_queuePeakBytes{0};
std::atomic<uint64_t> g_droppedTotal{0};
uint64_t g_slowNoteAtMs = 0;  ///< the log thread only
uint64_t g_slowSinceNote = 0; ///< the log thread only
uint64_t g_slowMaxFileUs = 0; ///< the log thread only: since the last note
uint64_t g_slowMaxSinkUs = 0;

uint64_t SteadyUs()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count());
}
} // namespace

const char* LevelName(Level aLevel)
{
    switch (aLevel)
    {
    case Level::Trace: return "trace";
    case Level::Info:  return "info ";
    case Level::Warn:  return "warn ";
    case Level::Error: return "error";
    }
    return "?????";
}

void Init(const std::string& aDirectory)
{
    std::lock_guard io(g_ioMutex);
    if (g_file)
        return;

    const std::string path = aDirectory + "/nightcoop.log";
    {
        std::lock_guard lock(g_mutex);
        g_recentDir = aDirectory + "/logs";
        g_closed = false;
    }
    KeepPreviousSession(aDirectory);

    // Strictly binary mode: the tempting "w, ccs=UTF-8" makes an MSVC stream wide-oriented, and a narrow fprintf into it is
    // undefined behaviour — the CRT goes to __fastfail and the process dies with 0xC0000409 without a word. The sources are
    // UTF-8 already, so the BOM written by hand is enough.
    g_file = std::fopen(path.c_str(), "wb");
    if (g_file)
        std::fwrite("\xEF\xBB\xBF", 1, 3, g_file);
}

bool FileOpen()
{
    std::lock_guard io(g_ioMutex);
    return g_file != nullptr;
}

namespace
{
/// The log lock for no longer than aWaitMs: a hang watchdog must not get stuck on a lock held by a stuck thread.
bool LockFor(std::unique_lock<std::mutex>& aLock, uint32_t aWaitMs)
{
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(aWaitMs);
    while (!aLock.try_lock())
    {
        if (std::chrono::steady_clock::now() >= until)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return true;
}

void DrainIoLocked(bool aLogThread);
} // namespace

void Shutdown()
{
    // 23.10 (log_async): the log thread writes what is queued and ends; stuck in a write longer than kShutdownWaitMs (a disk
    // standing at the exit) — it is left, and so is the file (it may be inside a write of it)
    bool writerAlive = false;
    {
        std::unique_lock lock(g_mutex);
        if (g_writer)
        {
            g_stop = true;
            g_wake.notify_all();
            const bool exited = g_exitedCv.wait_for(lock, std::chrono::milliseconds(kShutdownWaitMs),
                                                    [] { return g_writerExited; });
            std::thread* writer = std::exchange(g_writer, nullptr);
            lock.unlock();
            if (exited)
            {
                writer->join();
                delete writer;
            }
            else
            {
                writer->detach(); // the object is leaked on purpose: the thread may still use what it points to
                writerAlive = true;
            }
            lock.lock();
        }
        g_async.store(false);
    }
    std::unique_lock io(g_ioMutex, std::defer_lock);
    if (writerAlive ? !io.try_lock() : !LockFor(io, kShutdownWaitMs))
    {
        std::lock_guard lock(g_mutex);
        g_closed = true;
        return;
    }
    DrainIoLocked(false);
    {
        std::lock_guard lock(g_mutex);
        g_closed = true;
        g_queue.clear();
        g_queueBytes = 0;
    }
    if (g_file && !writerAlive)
    {
        std::fclose(g_file);
        g_file = nullptr;
    }
    g_sink = nullptr;
}

void SetSink(Sink aSink)
{
    std::lock_guard io(g_ioMutex);
    g_sink = std::move(aSink);
}

namespace
{
enum class Queued
{
    Dropped, ///< the flood limit: not written anywhere
    Quiet,   ///< in the ring and in the queue
    Wake     ///< and the log thread should wake now (a warning, an error, much queued, lines not queued)
};

Queued QueueLocked(Level aLevel, std::string_view aMessage);
void WakeOrDrain(Queued aQueued);

std::atomic<bool> g_hideAddresses{false}; ///< 23.10 (log_hide_ips): IPv4 addresses as <ip>

bool Digit(char aChar)
{
    return aChar >= '0' && aChar <= '9';
}

/// 23.10 (log_hide_ips): a dotted IPv4 address — four parts 0-255, not inside a longer run of digits and dots (a version like
/// 3.0.88.46235 or 1.2.3.4.5 is not one) — becomes "<ip>"; 127.x.x.x and 0.0.0.0 stay. A port after it stays too.
void HideAddressesIn(std::string& aText)
{
    if (aText.find('.') == std::string::npos)
        return;
    std::string out;
    size_t last = 0;
    bool changed = false;
    const size_t n = aText.size();
    size_t i = 0;
    while (i < n)
    {
        if (!Digit(aText[i]) || (i > 0 && (Digit(aText[i - 1]) || aText[i - 1] == '.')))
        {
            ++i;
            continue;
        }
        size_t j = i;
        int parts = 0;
        int first = -1;
        bool zero = true;
        bool ok = true;
        while (parts < 4)
        {
            int value = 0;
            int digits = 0;
            while (j < n && Digit(aText[j]) && digits <= 3)
            {
                value = value * 10 + (aText[j] - '0');
                ++j;
                ++digits;
            }
            if (digits == 0 || digits > 3 || value > 255)
            {
                ok = false;
                break;
            }
            if (parts == 0)
                first = value;
            zero = zero && value == 0;
            ++parts;
            if (parts == 4)
                break;
            if (j < n && aText[j] == '.')
                ++j;
            else
            {
                ok = false;
                break;
            }
        }
        const bool longer = j < n && (Digit(aText[j]) || (aText[j] == '.' && j + 1 < n && Digit(aText[j + 1])));
        if (!ok || longer)
        {
            i = std::max(j, i + 1);
            continue;
        }
        if (first != 127 && !zero)
        {
            out.append(aText, last, i - last);
            out += "<ip>";
            last = j;
            changed = true;
        }
        i = j;
    }
    if (!changed)
        return;
    out.append(aText, last, std::string::npos);
    aText.swap(out);
}
} // namespace

void SetHideAddresses(bool aOn)
{
    g_hideAddresses.store(aOn, std::memory_order_relaxed);
}

bool HidingAddresses()
{
    return g_hideAddresses.load(std::memory_order_relaxed);
}

void Write(Level aLevel, std::string_view aMessage)
{
    const LineSpan span; // 07.11 (perf_0711): a line of the measured game tick — its own span
    Queued queued = Queued::Dropped;
    {
        std::lock_guard lock(g_mutex);
        queued = QueueLocked(aLevel, aMessage);
    }
    WakeOrDrain(queued);
}

bool TryWrite(Level aLevel, std::string_view aMessage, uint32_t aWaitMs)
{
    const LineSpan span; // 07.11 (perf_0711)
    std::unique_lock lock(g_mutex, std::defer_lock);
    if (!LockFor(lock, aWaitMs))
        return false;
    const Queued queued = QueueLocked(aLevel, aMessage);
    lock.unlock();
    if (g_async.load(std::memory_order_relaxed))
    {
        if (queued == Queued::Wake)
            g_wake.notify_one();
        return true;
    }
    // Written by this thread, but not waiting for the disk longer than aWaitMs either: the line stays queued for the next
    // writer (a hang watchdog must not stand on a write of a stuck thread)
    std::unique_lock io(g_ioMutex, std::defer_lock);
    if (queued != Queued::Dropped && LockFor(io, aWaitMs))
        DrainIoLocked(false);
    return true;
}

namespace
{
/// Under g_mutex: a line into the queue for the file (the ring has it already). The queue full — the line is counted, not
/// queued (the disk stands; the ring keeps it).
Queued EnqueueLocked(Level aLevel, std::string&& aLine, size_t aMessageAt, bool aToSink)
{
    if (g_closed)
        return Queued::Dropped; // after Shutdown: the ring only — no thread waits for the disk (a log thread left stuck)
    if (g_queueBytes + aLine.size() > kQueueMaxBytes)
    {
        ++g_fileDropped;
        g_droppedTotal.fetch_add(1, std::memory_order_relaxed);
        return Queued::Wake;
    }
    g_queueBytes += aLine.size();
    if (g_queueBytes > g_queuePeakBytes.load(std::memory_order_relaxed))
        g_queuePeakBytes.store(g_queueBytes, std::memory_order_relaxed);
    if (aLevel >= Level::Warn)
        g_queueUrgent = true;
    QueuedLine entry;
    entry.level = aLevel;
    entry.line = std::move(aLine);
    entry.messageAt = aMessageAt;
    entry.toSink = aToSink;
    g_queue.push_back(std::move(entry));
    return g_queueUrgent || g_queueBytes >= kWakeBytes ? Queued::Wake : Queued::Quiet;
}

/// Under g_mutex: the flood limit, the line into the ring and into the queue.
Queued QueueLocked(Level aLevel, std::string_view aMessage)
{
    // Flood: past kMaxLinesPerSecond in a second lines are not written (except errors); the next second starts with how
    // many were dropped
    const int64_t second = NowSecond();
    if (second != g_floodSecond)
    {
        if (g_floodDropped)
        {
            std::string note = std::format("[{}] [warn ] log: {} line(s) dropped in the last second (more than {} a "
                                           "second)\n",
                                           Timestamp(), g_floodDropped, kMaxLinesPerSecond);
            RingAppend(note.data(), note.size());
            EnqueueLocked(Level::Warn, std::move(note), 0, false); // the file only, as before
        }
        g_floodSecond = second;
        g_floodLines = 0;
        g_floodDropped = 0;
    }
    if (++g_floodLines > kMaxLinesPerSecond && aLevel != Level::Error && !PastFloodLimit(aMessage))
    {
        ++g_floodDropped;
        return Queued::Dropped;
    }

    // 23.10 (log_hide_ips): players' addresses do not reach the file, the ring or the sink
    std::string message(aMessage);
    if (g_hideAddresses.load(std::memory_order_relaxed))
        HideAddressesIn(message);

    std::string line = std::format("[{}] [{}] ", Timestamp(), LevelName(aLevel));
    const size_t messageAt = line.size();
    line.append(message);
    line += '\n';
    RingAppend(line.data(), line.size());
    return EnqueueLocked(aLevel, std::move(line), messageAt, true);
}

/// Under g_ioMutex: everything queued so far — to the file and the sink, in order. aLogThread — the log thread (it flushes
/// every batch); otherwise the thread that gave the line, as before: warnings and errors go to disk at once, the rest at
/// most every 100 ms (a crash snapshot comes from the ring).
void DrainIoLocked(bool aLogThread)
{
    // Under g_ioMutex; keeps its capacity. Never destroyed: a log thread stuck in a write at the exit may still hold it
    static auto* const s_batchStore = new std::vector<QueuedLine>();
    std::vector<QueuedLine>& s_batch = *s_batchStore;
    s_batch.clear();
    bool urgent = false;
    uint64_t dropped = 0;
    {
        std::lock_guard lock(g_mutex);
        s_batch.swap(g_queue);
        g_queueBytes = 0;
        urgent = std::exchange(g_queueUrgent, false);
        dropped = std::exchange(g_fileDropped, 0);
    }
    if (s_batch.empty() && !dropped)
        return;
    const uint64_t startUs = SteadyUs();
    if (g_file)
    {
        if (dropped)
        {
            const std::string note = std::format("[{}] [warn ] log: {} line(s) are not in this file — the disk stood longer "
                                                 "than the queue of the log holds ({} MB); the last {} min are in memory "
                                                 "(NightCoopLogSave)\n",
                                                 Timestamp(), dropped, kQueueMaxBytes >> 20, kRecentSeconds / 60);
            std::fwrite(note.data(), 1, note.size(), g_file);
            urgent = true;
        }
        for (const auto& entry : s_batch)
            std::fwrite(entry.line.data(), 1, entry.line.size(), g_file);
        const auto now = std::chrono::steady_clock::now();
        if (aLogThread || urgent || now - g_lastFlush >= std::chrono::milliseconds(100))
        {
            std::fflush(g_file);
            g_lastFlush = now;
        }
    }
    const uint64_t fileUs = SteadyUs() - startUs;
    if (g_sink)
    {
        for (auto& entry : s_batch)
        {
            if (!entry.toSink || entry.line.empty())
                continue;
            entry.line.back() = '\0'; // the newline: sinks expect the message alone, zero-terminated
            g_sink(entry.level, entry.line.c_str() + entry.messageAt);
        }
    }
    const uint64_t allUs = SteadyUs() - startUs;
    g_batches.fetch_add(1, std::memory_order_relaxed);
    g_batchLines.fetch_add(s_batch.size(), std::memory_order_relaxed);
    if (allUs > g_writeMaxUs.load(std::memory_order_relaxed))
        g_writeMaxUs.store(allUs, std::memory_order_relaxed);
    if (allUs >= kSlowWriteUs)
    {
        g_slowWrites.fetch_add(1, std::memory_order_relaxed);
        if (aLogThread)
        {
            ++g_slowSinceNote;
            g_slowMaxFileUs = std::max(g_slowMaxFileUs, fileUs);
            g_slowMaxSinkUs = std::max(g_slowMaxSinkUs, allUs - fileUs);
        }
    }
    s_batch.clear();
}

/// After a line is queued: the log thread is told (async), or this thread writes it now (as before).
void WakeOrDrain(Queued aQueued)
{
    if (aQueued == Queued::Dropped)
        return;
    if (g_async.load(std::memory_order_relaxed))
    {
        if (aQueued == Queued::Wake)
            g_wake.notify_one();
        return;
    }
    std::lock_guard io(g_ioMutex);
    DrainIoLocked(false);
}

/// The log thread: a batch every kWriterPeriodMs, at once on a warning, an error or kWakeBytes queued.
void WriterMain()
{
    std::unique_lock lock(g_mutex);
    for (;;)
    {
        g_wake.wait_for(lock, kWriterPeriodMs,
                        [] { return g_stop || g_queueUrgent || g_queueBytes >= kWakeBytes || g_fileDropped != 0; });
        const bool stop = g_stop;
        if (!g_queue.empty() || g_fileDropped)
        {
            lock.unlock();
            {
                std::lock_guard io(g_ioMutex);
                DrainIoLocked(true);
            }
            // Its own line about a slow disk — queued only (this thread never waits for itself)
            const uint64_t nowMs = SteadyUs() / 1000;
            if (g_slowSinceNote && nowMs - g_slowNoteAtMs >= kSlowNoteEveryMs)
            {
                std::string text = std::format(
                    "log: {} write(s) of the log to the disk took {} ms and longer here (the longest: the file {} ms, the "
                    "RED4ext log {} ms) — on the log thread: the game thread did not wait (log_async; {} such so far)",
                    g_slowSinceNote, kSlowWriteUs / 1000, g_slowMaxFileUs / 1000, g_slowMaxSinkUs / 1000,
                    g_slowWrites.load(std::memory_order_relaxed));
                g_slowNoteAtMs = nowMs;
                g_slowSinceNote = 0;
                g_slowMaxFileUs = 0;
                g_slowMaxSinkUs = 0;
                lock.lock();
                QueueLocked(Level::Info, text);
                continue;
            }
            lock.lock();
            continue;
        }
        if (stop)
            break;
    }
    g_writerExited = true;
    g_exitedCv.notify_all();
}
} // namespace

std::string SetAsync(bool aOn)
{
    bool started = false;
    {
        std::lock_guard lock(g_mutex);
        if (aOn && !g_writer && !g_closed)
        {
            g_stop = false;
            g_writerExited = false;
            g_writer = new std::thread(&WriterMain);
            started = true;
        }
        g_async.store(aOn && g_writer != nullptr);
    }
    if (!g_async.load())
    {
        // Off: what the log thread has not written yet — now, by this thread; from here on each thread writes its own
        std::lock_guard io(g_ioMutex);
        DrainIoLocked(false);
    }
    return std::format("log: log_async {} — {}{}", g_async.load() ? "ON" : "OFF",
                       g_async.load() ? "the file and the RED4ext log are written by the log thread: no thread of the game "
                                        "waits for the disk"
                                      : "each thread writes its lines to the disk itself (as before 23.10)",
                       started ? " (the log thread started)" : "");
}

bool Async()
{
    return g_async.load(std::memory_order_relaxed);
}

std::string DescribeWriter()
{
    size_t queued = 0;
    size_t queuedBytes = 0;
    {
        std::lock_guard lock(g_mutex);
        queued = g_queue.size();
        queuedBytes = g_queueBytes;
    }
    return std::format("log: log_async {}; queued now {} line(s) ({} KB), the most {} KB; written {} line(s) in {} batch(es), "
                       "the longest write {} ms, {} write(s) of {} ms and longer; not in the file (the queue full) {}",
                       g_async.load() ? "ON" : "OFF", queued, queuedBytes >> 10,
                       g_queuePeakBytes.load(std::memory_order_relaxed) >> 10,
                       g_batchLines.load(std::memory_order_relaxed), g_batches.load(std::memory_order_relaxed),
                       g_writeMaxUs.load(std::memory_order_relaxed) / 1000,
                       g_slowWrites.load(std::memory_order_relaxed), kSlowWriteUs / 1000,
                       g_droppedTotal.load(std::memory_order_relaxed));
}

namespace
{
std::mutex g_dueMutex;
std::unordered_map<uint64_t, uint64_t> g_due; ///< line key -> when it was last written (steady clock, ms)
} // namespace

bool Due(uint64_t aKey, uint64_t aEveryMs)
{
    const LineSpan span; // 07.11 (perf_0711): the check of a line is the line's price too
    using namespace std::chrono;
    const auto now = static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
    std::lock_guard lock(g_dueMutex);
    if (g_due.size() > 65536)
        g_due.clear();
    const auto [it, fresh] = g_due.emplace(aKey, now);
    if (fresh)
        return true;
    if (now - it->second < aEveryMs)
        return false;
    it->second = now;
    return true;
}

// ---------------------------------------------------------------- the last minutes

RecentSpan RecentUnlocked(uint32_t aSeconds)
{
    RecentSpan out;
    const uint64_t total = g_ringTotal.load(std::memory_order_acquire);
    const uint64_t count = g_markCount.load(std::memory_order_acquire);
    const int64_t from = NowSecond() - static_cast<int64_t>(aSeconds);
    uint64_t start = total;
    const uint64_t have = std::min<uint64_t>(count, kMarks);
    for (uint64_t i = count - have; i < count; ++i)
    {
        const Mark mark = g_marks[i % kMarks];
        if (mark.second >= from)
        {
            start = mark.total;
            break;
        }
    }
    if (start > total)
        start = total; // a mark was added while we were reading
    if (total - start > kRingBytes)
    {
        // The ring has already overwritten the start of the window: from the first whole line of what is left
        start = total - kRingBytes;
        for (uint64_t at = start; at < total; ++at)
            if (g_ring[at % kRingBytes] == '\n')
            {
                start = at + 1;
                break;
            }
    }
    const size_t size = static_cast<size_t>(total - start);
    const size_t pos = static_cast<size_t>(start % kRingBytes);
    out.first = g_ring + pos;
    out.firstSize = std::min(size, kRingBytes - pos);
    if (out.firstSize < size)
    {
        out.second = g_ring;
        out.secondSize = size - out.firstSize;
    }
    return out;
}

void SetRecentHeader(const std::string& aText)
{
    std::lock_guard lock(g_mutex);
    const size_t size = std::min(aText.size(), sizeof(g_header) - 1);
    std::memcpy(g_header, aText.data(), size);
    g_header[size] = '\0';
}

const char* RecentHeaderUnlocked()
{
    return g_header;
}

std::string RecentDirectory()
{
    std::lock_guard lock(g_mutex);
    return g_recentDir;
}

namespace
{
/// The ring for the last aSeconds, the snapshot directory and the header, copied into own strings. Under g_mutex (or
/// without it — SaveRecentNoWait).
void CopyRecent(uint32_t aSeconds, std::string& aBody, std::string& aDirectory, std::string& aHeader)
{
    const RecentSpan span = RecentUnlocked(aSeconds);
    aBody.reserve(span.firstSize + span.secondSize);
    aBody.append(span.first, span.firstSize);
    if (span.secondSize)
        aBody.append(span.second, span.secondSize);
    aDirectory = g_recentDir;
    aHeader = g_header;
}

std::string WriteRecentFile(const std::string& aBody, const std::string& aDirectory, const std::string& aHeader,
                            const std::string& aReason, const std::string& aNote, uint32_t aSeconds,
                            std::string* aError);
} // namespace

std::string SaveRecent(const std::string& aReason, const std::string& aNote, uint32_t aSeconds, std::string* aError)
{
    std::string body;
    std::string directory;
    std::string header;
    {
        std::lock_guard lock(g_mutex);
        CopyRecent(aSeconds, body, directory, header);
    }
    return WriteRecentFile(body, directory, header, aReason, aNote, aSeconds, aError);
}

std::string SaveRecentNoWait(const std::string& aReason, const std::string& aNote, uint32_t aWaitMs, uint32_t aSeconds,
                             std::string* aError)
{
    std::string body;
    std::string directory;
    std::string header;
    {
        std::unique_lock lock(g_mutex, std::defer_lock);
        // The lock was not taken within aWaitMs (a stuck thread holds it): copy the ring without it, as the crash handler does
        // (the line at the edge may be incomplete); the directory and the header are set at start and never change
        static_cast<void>(LockFor(lock, aWaitMs));
        CopyRecent(aSeconds, body, directory, header);
    }
    return WriteRecentFile(body, directory, header, aReason, aNote, aSeconds, aError);
}

namespace
{
std::string WriteRecentFile(const std::string& aBody, const std::string& aDirectory, const std::string& aHeader,
                            const std::string& aReason, const std::string& aNote, uint32_t aSeconds,
                            std::string* aError)
{
    namespace fs = std::filesystem;
    const std::string& body = aBody;
    const std::string& directory = aDirectory;
    const std::string& header = aHeader;
    if (directory.empty())
    {
        if (aError)
            *aError = "the log is not open";
        return {};
    }
    std::error_code ec;
    const fs::path dir = Utf8Path(directory);
    fs::create_directories(dir, ec);
    std::tm local{};
    LocalTime(local);
    char stamp[64]; // room to spare: g++ counts int fields as up to 11 characters wide
    std::snprintf(stamp, sizeof(stamp), "%04d-%02d-%02d-%02d-%02d-%02d", local.tm_year + 1900, local.tm_mon + 1,
                  local.tm_mday, local.tm_hour, local.tm_min, local.tm_sec);
    const std::string base = std::string("nightcoop-last-") + stamp + "-" + Sanitize(aReason);
    fs::path path = dir / Utf8Path(base + ".log");
    // Two snapshots in one second: the second goes next to the first, not over it
    for (int n = 2; fs::exists(path, ec) && n < 100; ++n)
        path = dir / Utf8Path(std::format("{}-{}.log", base, n));
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file)
    {
        if (aError)
            *aError = "cannot create " + ToUtf8(path);
        return {};
    }
    char when[64];
    std::snprintf(when, sizeof(when), "%04d-%02d-%02d %02d:%02d:%02d", local.tm_year + 1900, local.tm_mon + 1,
                  local.tm_mday, local.tm_hour, local.tm_min, local.tm_sec);
    const std::string top = std::format("\xEF\xBB\xBFNightCoop: the last {} s of the log, saved {} ({}){}{}{}\n",
                                        aSeconds, when, aReason, header.empty() ? "" : ", ", header,
                                        aNote.empty() ? std::string() : " — " + aNote);
    file.write(top.data(), static_cast<std::streamsize>(top.size()));
    file.write(body.data(), static_cast<std::streamsize>(body.size()));
    file.close();
    if (!file)
    {
        if (aError)
            *aError = "cannot write " + ToUtf8(path);
        return {};
    }
    Prune(dir);
    return ToUtf8(path);
}
} // namespace
} // namespace nc::log
