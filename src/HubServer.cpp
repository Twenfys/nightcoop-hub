#include "HubServer.hpp"

#include "EnetGuard.hpp"
#include "HubCookie.hpp"
#include "HubRules.hpp"
#include "Log.hpp"
#include "NetCrypto.hpp"
#include "ProtocolCore.hpp"

#include <enet/enet.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <format>
#include <random>

namespace nc
{
namespace
{
/// Session code alphabet without look-alikes: zero and O, one and I/L turn into each other when read aloud or typed into
/// a chat.
constexpr char kAlphabet[] = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
constexpr size_t kCodeLength = 6;

/// Keys of rate-limited log lines (log::Due): a line per packet of a hostile client would itself be a way to hurt the hub
constexpr uint64_t kDueRepeat = 0x4855'4252'4550'0001ull;
constexpr uint64_t kDueUnknown = 0x4855'4252'4550'0002ull;
constexpr uint64_t kDueVersion = 0x4855'4252'4550'0003ull;
constexpr uint64_t kDueLimit = 0x4855'4252'4550'0004ull;
constexpr uint64_t kDueBrute = 0x4855'4252'4550'0005ull;
constexpr uint64_t kDueIdle = 0x4855'4252'4550'0006ull;
constexpr uint64_t kDueWitness = 0x4855'4252'4550'0007ull;
constexpr uint64_t kDueForeign = 0x4855'4252'4550'0008ull;
constexpr uint64_t kDueElsewhere = 0x4855'4252'4550'0009ull;
constexpr uint64_t kDueCookie = 0x4855'4252'4550'000Aull;
constexpr uint64_t kDueGuard = 0x4855'4252'4550'000Bull;
constexpr uint64_t kDueCut = 0x4855'4252'4550'000Cull;
constexpr uint64_t kDueQueue = 0x4855'4252'4550'000Dull;
constexpr uint64_t kDueClosed = 0x4855'4252'4550'000Full;
constexpr uint64_t kDueResume = 0x4855'4252'4550'0010ull;
constexpr uint64_t kDueResumeLimit = 0x4855'4252'4550'0011ull;
constexpr uint64_t kDueBusy = 0x4855'4252'4550'0012ull;
constexpr uint64_t kDueEveryMs = 10000;
/// At most this long the stopping hub hands out what is queued (hub_stop_drain): a far player's acknowledgement takes a
/// few hundred ms; whoever is not through by then is cut as before
constexpr uint64_t kStopDrainMs = 1500;

/// CPU time of the calling thread, µs: a hub thread's own share of a core (hub_cpu_gate; the process clock would sum them)
uint64_t ThreadCpuUs()
{
#ifdef _WIN32
    FILETIME created, exited, kernel, user;
    if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user))
        return 0;
    const auto ticks = [](const FILETIME& aTime)
    { return (static_cast<uint64_t>(aTime.dwHighDateTime) << 32) | aTime.dwLowDateTime; };
    return (ticks(kernel) + ticks(user)) / 10u;
#else
    timespec spent{};
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &spent) != 0)
        return 0;
    return static_cast<uint64_t>(spent.tv_sec) * 1000000u + static_cast<uint64_t>(spent.tv_nsec) / 1000u;
#endif
}

/// Packets sent by the hub, for TakeStats. Each hub thread counts its own (one HubServer per thread: its thread calls
/// Service and TakeStats)
thread_local uint64_t g_sent = 0;
thread_local uint64_t g_sentBytes = 0;
thread_local uint64_t g_sentReliable = 0;

uint64_t NowMs()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

/// The hub's clock for signatures (seconds since 1970). Expiry is judged against this clock, carried in the signature,
/// not against the players' clocks
uint64_t NowUnixSec()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

/// The socket receive buffer as the system holds it (bytes; -1: unknown). enet_socket_get_option does not return it,
/// only the error and the TTL
int ReceiveBufferBytes(ENetSocket aSocket)
{
    int value = 0;
#ifdef _WIN32
    int length = sizeof(value);
    if (getsockopt(aSocket, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char*>(&value), &length) != 0)
        return -1;
#else
    socklen_t length = sizeof(value);
    if (getsockopt(aSocket, SOL_SOCKET, SO_RCVBUF, &value, &length) != 0)
        return -1;
#endif
    return value;
}

constexpr uint64_t kDueSealed = 0x4855'4252'4550'000Eull;

/// Bytes in ENet's queues to each recipient: the counter of its slot (HubServer::m_queued). SendTo adds; ENet subtracts
/// when it releases a packet (a reliable one acknowledged, an unreliable one sent, the connection removed). Otherwise a
/// recipient that does not take (acknowledge) would make the hub buffer everything its partner sends it until ENet's
/// timeout (30–60 s)
struct OutQueues
{
    std::vector<size_t>* counts = nullptr;
    const ENetHost* host = nullptr;
    size_t limit = 0;
    std::vector<ENetPeer*>* over = nullptr;
};
thread_local OutQueues t_out;

void ENET_CALLBACK PacketGone(ENetPacket* aPacket)
{
    auto* count = static_cast<size_t*>(aPacket->userData);
    if (count)
        *count -= std::min(*count, aPacket->dataLength);
}

void SendTo(ENetPeer* aPeer, const std::vector<uint8_t>& aData, uint8_t aChannel, bool aReliable)
{
    if (!aPeer)
        return;
    ++g_sent;
    g_sentBytes += aData.size();
    g_sentReliable += aReliable ? 1 : 0;
    size_t* count = nullptr;
    const OutQueues out = t_out;
    if (out.counts && out.host && aPeer >= out.host->peers && aPeer < out.host->peers + out.host->peerCount)
    {
        const auto index = static_cast<size_t>(aPeer - out.host->peers);
        if (index < out.counts->size())
            count = &(*out.counts)[index];
        // The recipient does not take what it gets: do not queue, close it after handling the event (HubServer::CloseOverflow)
        if (count && out.limit && *count + aData.size() > out.limit)
        {
            if (out.over)
                out.over->push_back(aPeer);
            return;
        }
    }
    ENetPacket* packet = enet_packet_create(aData.data(), aData.size(), aReliable ? ENET_PACKET_FLAG_RELIABLE : 0);
    if (!packet)
        return;
    if (count)
    {
        packet->userData = count;
        packet->freeCallback = &PacketGone;
        *count += aData.size();
    }
    if (enet_peer_send(aPeer, aChannel, packet) != 0)
        enet_packet_destroy(packet);
}

void Reject(ENetPeer* aPeer, const std::string& aReason)
{
    proto::Writer w(proto::MsgType::HubJoinRejected);
    w.PutString(aReason);
    SendTo(aPeer, w.Data(), 0, true);
}

/// A session code as MakeCode issues it: exactly kCodeLength characters of the alphabet. Anything else goes neither into
/// the log nor into a lookup
bool ValidCode(const std::string& aCode)
{
    if (aCode.size() != kCodeLength)
        return false;
    for (const char c : aCode)
        if (!std::memchr(kAlphabet, c, sizeof(kAlphabet) - 1))
            return false;
    return true;
}

/// An ENet intercept carries no pointer to the hub and is called only from enet_host_service on this hub's thread, so
/// the hub is remembered for that call
thread_local HubServer* t_serving = nullptr;

int ENET_CALLBACK Intercept(ENetHost*, ENetEvent*)
{
    return t_serving ? t_serving->OnDatagram() : 0;
}

/// Address for the log (ENetAddress.host: octets in memory order)
std::string AddressText(uint32_t aHost)
{
    uint8_t b[4];
    std::memcpy(b, &aHost, 4);
    return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." + std::to_string(b[2]) + "." + std::to_string(b[3]);
}
} // namespace

HubAddressBook::Entry& HubAddressBook::Of(uint32_t aAddress, uint64_t aNowMs)
{
    Entry& entry = m_entries[aAddress];
    if (aNowMs - entry.minuteStartMs > 60000)
    {
        entry.minuteStartMs = aNowMs;
        entry.joinFails = 0;
        entry.creates = 0;
    }
    return entry;
}

uint32_t HubAddressBook::Creates(uint32_t aAddress, uint64_t aNowMs)
{
    std::lock_guard lock(m_mutex);
    return Of(aAddress, aNowMs).creates;
}

void HubAddressBook::AddCreate(uint32_t aAddress, uint64_t aNowMs)
{
    std::lock_guard lock(m_mutex);
    ++Of(aAddress, aNowMs).creates;
}

uint32_t HubAddressBook::AddJoinFail(uint32_t aAddress, uint64_t aNowMs)
{
    std::lock_guard lock(m_mutex);
    return ++Of(aAddress, aNowMs).joinFails;
}

void HubAddressBook::Sweep(uint64_t aNowMs)
{
    std::lock_guard lock(m_mutex);
    if (m_entries.size() > 1024)
        std::erase_if(m_entries, [&](const auto& aItem) { return aNowMs - aItem.second.minuteStartMs > 60000; });
}

void HubAddressBook::Clear()
{
    std::lock_guard lock(m_mutex);
    m_entries.clear();
}

void HubIntroSource::Set(std::shared_ptr<const Data> aData)
{
    std::lock_guard lock(m_mutex);
    m_data = std::move(aData);
}

std::shared_ptr<const HubIntroSource::Data> HubIntroSource::Get() const
{
    std::lock_guard lock(m_mutex);
    return m_data;
}

void HubLocationsSource::Set(std::shared_ptr<const Data> aData)
{
    std::lock_guard lock(m_mutex);
    m_data = std::move(aData);
}

std::shared_ptr<const HubLocationsSource::Data> HubLocationsSource::Get() const
{
    std::lock_guard lock(m_mutex);
    return m_data;
}

HubShards::HubShards(std::vector<uint16_t> aPorts)
    : m_ports(std::move(aPorts)), m_load(new std::atomic<uint32_t>[m_ports.size() ? m_ports.size() : 1]),
      m_cpu(new std::atomic<uint16_t>[m_ports.size() ? m_ports.size() : 1])
{
    for (size_t i = 0; i < m_ports.size(); ++i)
    {
        m_load[i].store(0, std::memory_order_relaxed);
        m_cpu[i].store(0, std::memory_order_relaxed);
    }
}

void HubShards::SetCpu(size_t aShard, uint16_t aPermille)
{
    if (aShard < m_ports.size())
        m_cpu[aShard].store(aPermille, std::memory_order_relaxed);
}

uint16_t HubShards::CpuOf(size_t aShard) const
{
    return aShard < m_ports.size() ? m_cpu[aShard].load(std::memory_order_relaxed) : 0;
}

uint16_t HubShards::LeastCpu() const
{
    uint16_t least = 1000;
    for (size_t i = 0; i < m_ports.size(); ++i)
        if (m_ports[i] != 0)
            least = std::min(least, m_cpu[i].load(std::memory_order_relaxed));
    return least;
}

int HubShards::PickOpen(size_t aSelf, uint32_t aOwnLoad, uint8_t aLimitPct) const
{
    // At most 64 threads (tools/hub/main.cpp --shards)
    std::array<uint32_t, 64> loads{};
    std::array<uint16_t, 64> cpus{};
    std::array<bool, 64> usable{};
    const size_t count = std::min<size_t>(m_ports.size(), loads.size());
    for (size_t i = 0; i < count; ++i)
    {
        loads[i] = m_load[i].load(std::memory_order_relaxed);
        cpus[i] = m_cpu[i].load(std::memory_order_relaxed);
        usable[i] = m_ports[i] != 0;
    }
    return hubrules::PickOpenThread(loads.data(), cpus.data(), usable.data(), count, aSelf, aOwnLoad, aLimitPct);
}

void HubShards::SetLoad(size_t aShard, uint32_t aConnections)
{
    if (aShard < m_ports.size())
        m_load[aShard].store(aConnections, std::memory_order_relaxed);
}

uint32_t HubShards::LoadOf(size_t aShard) const
{
    return aShard < m_ports.size() ? m_load[aShard].load(std::memory_order_relaxed) : 0;
}

size_t HubShards::Pick(size_t aSelf, uint32_t aOwnLoad) const
{
    size_t best = aSelf;
    uint32_t bestLoad = aOwnLoad;
    for (size_t i = 0; i < m_ports.size(); ++i)
    {
        if (i == aSelf || m_ports[i] == 0)
            continue;
        const uint32_t load = m_load[i].load(std::memory_order_relaxed);
        if (load < bestLoad)
        {
            best = i;
            bestLoad = load;
        }
    }
    return best;
}

bool HubShards::Register(const std::string& aCode, size_t aShard)
{
    std::lock_guard lock(m_mutex);
    return m_codes.emplace(aCode, aShard).second;
}

void HubShards::Unregister(const std::string& aCode)
{
    std::lock_guard lock(m_mutex);
    m_codes.erase(aCode);
}

int HubShards::Find(const std::string& aCode)
{
    std::lock_guard lock(m_mutex);
    const auto it = m_codes.find(aCode);
    return it == m_codes.end() ? -1 : static_cast<int>(it->second);
}

HubServer::HubServer() = default;

HubServer::~HubServer()
{
    Stop();
}

std::string HubServer::MakeCode()
{
    // The system generator (getrandom / rand_s) for every character: the code is the only key to a session, and mt19937
    // output can be recovered from a series of issued codes (a client may create sessions in a row and read their codes)
    static thread_local std::random_device device; // one per hub thread
    std::uniform_int_distribution<size_t> pick(0, sizeof(kAlphabet) - 2);

    std::string code;
    code.reserve(kCodeLength);
    for (size_t i = 0; i < kCodeLength; ++i)
        code.push_back(kAlphabet[pick(device)]);
    return code;
}

bool HubServer::Start(uint16_t aPort, size_t aMaxClients)
{
    Limits limits;
    limits.maxClients = aMaxClients;
    return Start(aPort, limits);
}

bool HubServer::Start(uint16_t aPort, const Limits& aLimits, HubShards* aShards, size_t aShard)
{
    Stop();
    m_shards = aShards;
    m_shard = aShards ? aShard : 0;
    m_book = aShards ? &aShards->Book() : &m_ownBook;
    m_limits = aLimits;
    m_limits.maxClients = std::clamp<size_t>(m_limits.maxClients, 1, ENET_PROTOCOL_MAXIMUM_PEER_ID);
    if (m_limits.maxSessions == 0)
        m_limits.maxSessions = std::max<size_t>(1, m_limits.maxClients / 2);
    m_enetUp = enet_initialize() == 0;
    if (!m_enetUp)
    {
        log::Error("hub: enet_initialize failed");
        return false;
    }
    ENetAddress address{};
    address.host = ENET_HOST_ANY;
    address.port = aPort;
    m_host = enet_host_create(&address, m_limits.maxClients, 2, 0, 0);
    if (!m_host)
    {
        log::Error("hub: cannot take port {}", aPort);
        enet_deinitialize();
        m_enetUp = false;
        return false;
    }
    // Socket receive buffer, above the 256 KiB that enet_host_create sets
    if (m_limits.socketReceiveBytes)
    {
        const int asked = static_cast<int>(std::min<size_t>(m_limits.socketReceiveBytes, 1u << 30));
        enet_socket_set_option(m_host->socket, ENET_SOCKOPT_RCVBUF, asked);
        const int got = ReceiveBufferBytes(m_host->socket);
        // Linux reports twice the request (bookkeeping included), but no more than net.core.rmem_max × 2
        if (got >= 0 && got < asked)
            log::Warn("hub: the socket receive buffer is {} KB, {} KB asked — the system caps it (net.core.rmem_max)",
                      got / 1024, asked / 1024);
        else
            log::Info("hub: the socket receive buffer is {} KB ({} KB asked)", got / 1024, asked / 1024);
    }
    // ENet limits: connections from one address (beyond it a CONNECT gets no answer), packet size, data waiting for delivery
    m_host->duplicatePeers = m_limits.maxPerAddress ? m_limits.maxPerAddress : ENET_PROTOCOL_MAXIMUM_PEER_ID;
    if (m_limits.maxPacketBytes)
        m_host->maximumPacketSize = m_limits.maxPacketBytes;
    if (m_limits.maxWaitingBytes)
        m_host->maximumWaitingData = m_limits.maxWaitingBytes;
    m_nextIdleSweepMs = 0;
    // Connection pass: the secret comes from the system generator, the intercept runs before ENet
    if (m_limits.cookieBusy == 0)
        m_limits.cookieBusy = std::max<size_t>(1, m_limits.maxClients / 2);
    m_cookieRequired = m_limits.cookie == Limits::Cookie::Always;
    m_nextBusyCountMs = 0;
    m_busySlots = 0;
    m_passedNoCookie = 0;
    if (m_limits.cookie != Limits::Cookie::Off)
    {
        std::random_device device;
        for (size_t i = 0; i < m_cookieKey.size(); i += 4)
        {
            const uint32_t word = device();
            std::memcpy(m_cookieKey.data() + i, &word, 4);
        }
        m_host->intercept = &Intercept;
    }
    // Waiting data in ENet's queues is limited (EnetGuard.hpp), with the new packet and record costs, before ENet allocates
    // it; a connection outside a session sends no fragments. The same intercept as for passes
    m_guard.reset();
    if (m_limits.guard && m_limits.maxWaitingBytes)
    {
        enetguard::Budget budget;
        budget.perPeer = m_limits.maxWaitingBytes;
        budget.guaranteed = m_limits.guardOwnBytes;
        budget.pool = m_limits.guardPoolBytes;
        budget.preAuth = m_limits.guardPreAuthBytes;
        m_guard = std::make_unique<enetguard::Guard>();
        m_guard->Configure(budget);
        m_host->intercept = &Intercept;
    }
    // Location questions (server picker) use the same intercept even with passes and the guard off (without them
    // OnDatagram hands everything else to ENet as is)
    m_host->intercept = &Intercept;
    m_queued.assign(m_host->peerCount, 0);
    m_overflow.clear();
    log::Info("hub: a recipient that does not take what is sent to it is closed at {} KB in its queue{}; a service turn "
              "lasts up to {} ms",
              m_limits.maxQueuedBytes / 1024, m_limits.maxQueuedBytes ? "" : " (0 — no limit, as before 16.10)",
              m_limits.serviceBudgetMs);
    log::Info("hub: listening on {} — up to {} connection(s), {} from one address, {} session(s), {} guest(s) in a "
              "session; a packet up to {} KB, {} KB waiting per connection; a silent connection closes in {} s, {} "
              "refused join(s) and {} new session(s) a minute from one address",
              aPort, m_limits.maxClients, m_limits.maxPerAddress, m_limits.maxSessions, m_limits.maxGuests,
              m_limits.maxPacketBytes / 1024, m_limits.maxWaitingBytes / 1024, m_limits.idleMs / 1000,
              m_limits.joinFailsPerMinute, m_limits.createsPerMinute);
    if (m_limits.cpuLimitPct)
        log::Info("hub: new sessions go to threads under {}% of a core (--cpu-limit); with every thread there a new session "
                  "is refused as \"{}\" and the server picker takes another server — guests still join the sessions here, "
                  "and sessions come back after a restart, up to {} connection(s) a thread",
                  m_limits.cpuLimitPct, hubrules::kReasonHubFull, m_limits.maxClients);
    else
        log::Info("hub: new sessions are not gated by the threads' share of a core (--cpu-limit 0 — as before 26.10)");
    if (m_guard)
        log::Info("hub: undelivered data in ENet queues is limited before ENet takes it — {} KB per connection with the "
                  "packet that brings it, {} KB its own and a pool of {} MB over that for the thread; a connection "
                  "outside a session sends no fragments and holds up to {} KB (--guard off — as before 16.10)",
                  m_limits.maxWaitingBytes / 1024, m_limits.guardOwnBytes / 1024, m_limits.guardPoolBytes / (1024 * 1024),
                  m_limits.guardPreAuthBytes / 1024);
    else
        log::Info("hub: undelivered data in ENet queues is not limited before ENet (--guard off): a packet up to {} KB "
                  "past the waiting limit, and commands without data are not counted, as before 16.10",
                  m_limits.maxPacketBytes / 1024);
    switch (m_limits.cookie)
    {
    case Limits::Cookie::Off:
        log::Info("hub: connection passes are off — every CONNECT takes a slot, as before 13.10");
        break;
    case Limits::Cookie::Pressure:
        log::Info("hub: a connection pass is asked for while {} slot(s) or more are taken; below that a client without "
                  "one (a build before 13.10) connects as before",
                  m_limits.cookieBusy);
        break;
    case Limits::Cookie::Always:
        log::Info("hub: a connection pass is asked for always — a client built before 13.10 cannot connect");
        break;
    }
    if (m_shards)
        log::Info("hub: port {} is thread {} of {} of the hub — a session lives in one thread; a client that came to "
                  "another one is sent here by HubRedirect",
                  aPort, m_shard, m_shards->Count());
    // The hub's signature on peers' keys. Without a key, sessions go unsigned: clients encrypt links without
    // authentication, and a build that knows the project hub's key refuses sessions through it
    if (m_keys)
        log::Info("hub: players' keys are signed by this hub — public sign key {}, box key {} (the session code may come "
                  "sealed to the box key)",
                  netcrypto::ToHex(m_keys->SignPublic().data(), 32), netcrypto::ToHex(m_keys->BoxPublic().data(), 32));
    else
        log::Info("hub: no signing key (--sign-key) — players' keys go unsigned: links are encrypted without "
                  "authentication, and a build that knows the project hub's key refuses sessions through it");
    if (GivesPasses())
        log::Info("hub: sessions outlive a restart of the hub — the host of each gets a resume pass signed with this key "
                  "(valid {} h) and takes its code back with it within {} s of losing the hub; guests come back by the code "
                  "(--resume off — as before 23.10: a restart ends the sessions)",
                  hubrules::kResumePassLifeSec / 3600, hubrules::kResumeWindowMs / 1000);
    else
        log::Info("hub: no resume passes ({}) — a restart of the hub ends the sessions through it",
                  m_limits.resume ? "no signing key" : "--resume off");
    return true;
}

void HubServer::DrainBeforeStop()
{
    size_t asked = 0;
    for (size_t i = 0; i < m_host->peerCount; ++i)
    {
        ENetPeer* peer = &m_host->peers[i];
        if (peer->state == ENET_PEER_STATE_CONNECTED)
        {
            enet_peer_disconnect_later(peer, 0);
            ++asked;
        }
    }
    if (!asked)
        return;
    const uint64_t start = NowMs();
    size_t closed = 0;
    size_t refused = 0;
    ENetEvent event;
    while (NowMs() - start < kStopDrainMs)
    {
        bool open = false;
        for (size_t i = 0; i < m_host->peerCount && !open; ++i)
            open = m_host->peers[i].state != ENET_PEER_STATE_DISCONNECTED;
        if (!open)
            break;
        t_serving = this;
        const int got = enet_host_service(m_host, &event, 10);
        t_serving = nullptr;
        if (got <= 0)
            continue;
        switch (event.type)
        {
        case ENET_EVENT_TYPE_RECEIVE:
            // Not relayed any more: its recipients are on their way out too (the client keeps what it sends meanwhile)
            enet_packet_destroy(event.packet);
            break;
        case ENET_EVENT_TYPE_CONNECT:
            enet_peer_disconnect_now(event.peer, 0);
            ++refused;
            break;
        case ENET_EVENT_TYPE_DISCONNECT:
            ++closed;
            break;
        default:
            break;
        }
    }
    log::Info("hub: stopping — {} of {} connection(s) took what was queued for them and closed in {} ms (the rest are cut "
              "now; at most {} ms), {} new connection(s) turned away meanwhile (hub_stop_drain)",
              closed, asked, NowMs() - start, kStopDrainMs, refused);
}

void HubServer::Stop()
{
    if (m_host)
    {
        // 26.10 (hub_stop_drain, probe of a restart with a «mission»): what the hub has taken from one player and not yet
        // handed to another goes out before the DISCONNECT — before, disconnect_now dropped the relayed messages in flight
        DrainBeforeStop();
        // A DISCONNECT to every client: without it clients learn that the hub left only by ENet's timeout (30–60 s)
        for (size_t i = 0; i < m_host->peerCount; ++i)
        {
            ENetPeer* peer = &m_host->peers[i];
            if (peer->state != ENET_PEER_STATE_DISCONNECTED)
                enet_peer_disconnect_now(peer, 0);
        }
        enet_host_destroy(m_host);
        m_host = nullptr;
        log::Info("hub: shutting down");
    }
    m_guard.reset();
    // After enet_host_destroy: releasing packets, ENet decremented these counters
    m_queued.clear();
    m_overflow.clear();
    if (m_shards)
    {
        for (const auto& [code, session] : m_sessions)
            m_shards->Unregister(code);
        m_shards->SetLoad(m_shard, 0);
    }
    m_sessions.clear();
    m_clients.clear();
    m_idle.clear();
    m_introAsks.clear();
    m_ownBook.Clear();
    if (m_enetUp)
    {
        enet_deinitialize();
        m_enetUp = false;
    }
}

HubServer::Stats HubServer::TakeStats()
{
    Stats out = m_stats;
    out.sent = g_sent;
    out.sentBytes = g_sentBytes;
    out.sentReliable = g_sentReliable;
    g_sent = g_sentBytes = g_sentReliable = 0;
    m_stats = Stats{};
    if (m_host)
    {
        // u32 with wrap-around: the difference modulo 2^32 is right
        out.datagramsIn = m_host->totalReceivedPackets - m_markRecvPackets;
        out.datagramsOut = m_host->totalSentPackets - m_markSentPackets;
        out.bytesIn = m_host->totalReceivedData - m_markRecvData;
        out.bytesOut = m_host->totalSentData - m_markSentData;
        m_markRecvPackets = m_host->totalReceivedPackets;
        m_markSentPackets = m_host->totalSentPackets;
        m_markRecvData = m_host->totalReceivedData;
        m_markSentData = m_host->totalSentData;
    }
    return out;
}

void HubServer::Service(uint32_t aTimeoutMs)
{
    if (!m_host)
        return;
    CountBusy(NowMs());
    // Queues to recipients: SendTo counts for the whole turn (in event handling and in CloseIdle)
    struct OutScope
    {
        explicit OutScope(const OutQueues& aOut) { t_out = aOut; }
        ~OutScope() { t_out = OutQueues{}; }
    } outScope(OutQueues{&m_queued, m_host, m_limits.maxQueuedBytes, &m_overflow});
    ENetEvent event;
    t_serving = this;
    int result = enet_host_service(m_host, &event, aTimeoutMs);
    t_serving = nullptr;
    // A turn lasts no longer than serviceBudgetMs: a datagram stream does not keep the hub receiving forever. ENet hands
    // over the rest next turn (events it has ready it returns at once, without waiting)
    const uint64_t serviceStartMs = NowMs();
    uint32_t handled = 0;
    while (result > 0)
    {
        switch (event.type)
        {
        case ENET_EVENT_TYPE_CONNECT:
            ++m_stats.connected;
            // The client has said nothing about itself yet: the session appears when CreateSession or JoinSession comes
            enet_peer_timeout(event.peer, 32, 30000, 60000);
            m_idle[event.peer] = NowMs();
            break;

        case ENET_EVENT_TYPE_RECEIVE:
            HandlePacket(event.peer, event.packet->data, event.packet->dataLength, static_cast<uint8_t>(event.channelID));
            enet_packet_destroy(event.packet);
            break;

        case ENET_EVENT_TYPE_DISCONNECT:
            DropClient(event.peer);
            m_idle.erase(event.peer);
            m_introAsks.erase(event.peer);
            break;

        case ENET_EVENT_TYPE_NONE:
        default:
            break;
        }
        if (!m_overflow.empty())
            CloseOverflow();
        if (m_limits.serviceBudgetMs && (++handled & 63) == 0 && NowMs() - serviceStartMs >= m_limits.serviceBudgetMs)
        {
            ++m_stats.serviceCut;
            if (log::Due(kDueCut, kDueEveryMs))
                log::Warn("hub: a service turn handled {} event(s) in {} ms or more — the rest goes next turn ({} such "
                          "turn(s) since the last count)",
                          handled, m_limits.serviceBudgetMs, m_stats.serviceCut);
            break;
        }
        t_serving = this;
        result = enet_host_service(m_host, &event, 0);
        t_serving = nullptr;
    }

    const uint64_t now = NowMs();
    if (now >= m_nextIdleSweepMs)
    {
        m_nextIdleSweepMs = now + 1000;
        CloseIdle(now);
    }
    if (!m_overflow.empty())
        CloseOverflow();
    // The thread's load, for the other threads of the hub: it picks the thread of a new session
    if (m_shards)
        m_shards->SetLoad(m_shard, static_cast<uint32_t>(m_clients.size() + m_idle.size()));
    MeasureCpu(now);
}

void HubServer::MeasureCpu(uint64_t aNowMs)
{
    if (m_cpuMarkMs && aNowMs < m_cpuMarkMs + 1000)
        return;
    const uint64_t cpuUs = ThreadCpuUs();
    // µs of CPU per ms of wall time is the share of a core in ‰
    if (m_cpuMarkMs && aNowMs > m_cpuMarkMs && cpuUs >= m_cpuMarkUs)
    {
        const uint64_t sample = (cpuUs - m_cpuMarkUs) / (aNowMs - m_cpuMarkMs);
        m_cpuPermille = hubrules::CpuSmooth(m_cpuPermille, static_cast<uint32_t>(std::min<uint64_t>(sample, 1000)));
        if (m_shards)
            m_shards->SetCpu(m_shard, m_cpuPermille);
    }
    m_cpuMarkMs = aNowMs;
    m_cpuMarkUs = cpuUs;
}

void HubServer::RefuseBusy(ENetPeer* aPeer)
{
    ++m_stats.refusedBusy;
    Reject(aPeer, hubrules::kReasonHubFull);
    if (log::Due(kDueBusy, kDueEveryMs))
        log::Info("hub: refused a new session from {}: {} — every thread of the hub is at {}% of a core or more "
                  "(--cpu-limit; this one {:.1f}%), the client takes another server; guests still join the {} session(s) "
                  "here ({} refused as busy since the last count)",
                  AddressText(aPeer->address.host), hubrules::kReasonHubFull, m_limits.cpuLimitPct, m_cpuPermille / 10.0,
                  m_sessions.size(), m_stats.refusedBusy);
}

void HubServer::CountBusy(uint64_t aNowMs)
{
    if (m_limits.cookie != Limits::Cookie::Pressure || aNowMs < m_nextBusyCountMs)
        return;
    // Every 100 ms; between counts the threshold uses the number of CONNECTs passed without a pass (OnDatagram)
    m_nextBusyCountMs = aNowMs + 100;
    size_t busy = 0;
    for (size_t i = 0; i < m_host->peerCount; ++i)
        busy += m_host->peers[i].state != ENET_PEER_STATE_DISCONNECTED ? 1 : 0;
    m_busySlots = busy;
    m_passedNoCookie = 0;
    const bool required = busy >= m_limits.cookieBusy;
    if (required == m_cookieRequired)
        return;
    m_cookieRequired = required;
    if (log::Due(kDueCookie, kDueEveryMs))
        log::Warn("hub: {} of {} slot(s) are taken ({} in sessions or naming themselves) — a connection pass is {} now",
                  busy, m_limits.maxClients, m_clients.size() + m_idle.size(),
                  required ? "asked for: a CONNECT without one gets no slot (clients built before 13.10 wait)"
                           : "not asked for again");
}

std::vector<uint8_t> HubServer::AnswerLocations(const uint8_t* aAsk, size_t aSize)
{
    hubrules::LocAsk ask;
    if (!hubrules::ReadLocAsk(aAsk, aSize, ask))
        return {};
    hubrules::LocTell tell;
    tell.nonce = ask.nonce;
    // The hub's live state: connections against the ceiling (with threads, the sum over all of them: the question comes to
    // the entry port)
    size_t connections = ClientCount() + IdleCount();
    size_t capacity = m_limits.maxClients;
    uint16_t leastCpu = m_cpuPermille;
    bool cpuFull = !hubrules::CpuOpen(m_cpuPermille, m_limits.cpuLimitPct);
    if (m_shards)
    {
        connections = 0;
        for (size_t i = 0; i < m_shards->Count(); ++i)
            connections += m_shards->LoadOf(i);
        capacity = m_limits.maxClients * m_shards->Count();
        leastCpu = m_shards->LeastCpu();
        cpuFull = m_shards->PickOpen(m_shard, 0, m_limits.cpuLimitPct) < 0;
    }
    // Fill: connections against the slots or the least busy thread's share of the CPU limit, whichever is more (hub_cpu_gate)
    tell.load = hubrules::FillPercent(connections, capacity, leastCpu, m_limits.cpuLimitPct);
    tell.sessions = static_cast<uint16_t>(std::min<size_t>(65535, SessionCount()));
    // Full: connections nearly at the ceiling (a new session is a host and guests), sessions at the thread's limit or every
    // thread at the CPU limit. Closed: its line in the location list says so (no new sessions)
    const bool full = capacity && (connections + 2 > capacity || cpuFull ||
                                   (!m_shards && m_limits.maxSessions && SessionCount() >= m_limits.maxSessions));
    const auto list = m_locations ? m_locations->Get() : nullptr;
    tell.state = list && list->closedHere ? hubrules::LocState::Closed
                 : full                   ? hubrules::LocState::Full
                                          : hubrules::LocState::Open;
    if (m_keys)
    {
        tell.flags |= hubrules::kLocTellKey;
        tell.key = m_keys->SignPublic();
    }
    if ((ask.flags & hubrules::kLocAskWantList) && list && m_keys)
    {
        if (ask.known >= list->serial)
            tell.flags |= hubrules::kLocTellNotNewer;
        else
        {
            tell.flags |= hubrules::kLocTellList;
            tell.body = list->body;
            tell.signature = list->signature;
            // The root certificate, if there is one: with it the client checks a hub of the project's domain without the build's
            // old key
            const auto intro = m_intro ? m_intro->Get() : nullptr;
            if (intro && !intro->root.empty())
            {
                tell.proofKind = hubrules::kLocProofRoot;
                tell.proof = intro->root;
            }
        }
    }
    // The answer is not longer than the question: a forged address does not amplify anyone's traffic (a list that does not
    // fit is left out, with a flag)
    auto out = hubrules::MakeLocTell(tell, aSize);
    if (out.empty())
        return out;
    ++m_stats.locationAsks;
    hubrules::LocTell sent;
    if (hubrules::ReadLocTell(out.data(), out.size(), sent))
    {
        if (sent.flags & hubrules::kLocTellList)
            ++m_stats.locationLists;
        if (sent.flags & hubrules::kLocTellTooBig)
            ++m_stats.locationTooBig;
    }
    return out;
}

int HubServer::OnDatagram()
{
    const uint8_t* data = m_host->receivedData;
    const size_t size = m_host->receivedDataLength;
    const ENetAddress& from = m_host->receivedAddress;
    const uint64_t now = NowMs();
    // A location question (server picker): before ENet, without a record of the asker; the answer is not longer than the
    // question
    if (hubrules::IsLocAsk(data, size) && !m_testIgnoreLocations)
    {
        const auto out = AnswerLocations(data, size);
        if (!out.empty())
        {
            ENetBuffer buffer;
            buffer.data = const_cast<uint8_t*>(out.data());
            buffer.dataLength = out.size();
            enet_socket_send(m_host->socket, &from, &buffer, 1);
        }
        return 1;
    }
    if (m_limits.cookie != Limits::Cookie::Off)
    {
        if (hubcookie::IsAsk(data, size))
        {
            // The answer is shorter than the ask and goes out without a record of the asker: a forged address takes nothing and
            // amplifies nothing
            uint8_t out[hubcookie::kTellSize];
            hubcookie::WriteTell(out, hubcookie::Make(m_cookieKey, from.host, from.port, now / hubcookie::kBucketMs));
            ENetBuffer buffer;
            buffer.data = out;
            buffer.dataLength = sizeof(out);
            enet_socket_send(m_host->socket, &from, &buffer, 1);
            ++m_stats.cookiesTold;
            return 1;
        }
        uint32_t word = 0;
        if (hubcookie::ReadConnect(data, size, word))
        {
            if (hubcookie::Good(m_cookieKey, from.host, from.port, now, word))
                return 0;
            // Between slot counts (CountBusy, every 100 ms) each CONNECT passed without a pass counts as a taken slot: otherwise a
            // flood faster than "all slots in 100 ms" would take them all before the pass became required
            const bool required = m_cookieRequired || (m_limits.cookie == Limits::Cookie::Pressure &&
                                                       m_busySlots + m_passedNoCookie >= m_limits.cookieBusy);
            if (!required)
            {
                ++m_passedNoCookie;
                return 0;
            }
            ++m_stats.connectsRefused;
            return 1;
        }
    }
    // The connection exists: data. Waiting data in ENet's queues stays within limits (EnetGuard.hpp) before ENet
    // allocates it
    if (!m_guard)
        return 0;
    const enetguard::Verdict verdict =
        m_guard->Judge(*m_host, now, [this](const ENetPeer* aPeer) { return OutsideSession(aPeer); });
    m_stats.guardPoolPeak = std::max<uint64_t>(m_stats.guardPoolPeak, m_guard->PoolUsed());
    if (verdict == enetguard::Verdict::Pass)
        return 0;
    switch (verdict)
    {
    case enetguard::Verdict::PreAuth:
        ++m_stats.guardPreAuth;
        break;
    case enetguard::Verdict::PeerFull:
        ++m_stats.guardPeerFull;
        break;
    default:
        ++m_stats.guardPoolFull;
        break;
    }
    if (log::Due(kDueGuard, kDueEveryMs))
    {
        const auto& last = m_guard->LastDropped();
        log::Warn("hub: a datagram from {} is dropped before ENet: {} — the connection held {} KB undelivered, the "
                  "datagram brought {} KB more in {} command(s){}; the thread's pool holds {} of {} MB ({} dropped "
                  "since the last count)",
                  AddressText(from.host), enetguard::VerdictName(verdict), m_guard->LastHeld() / 1024,
                  last.held / 1024, last.heldCommands,
                  last.biggest ? std::format(", a new packet of {} KB", last.biggest / 1024) : std::string(),
                  m_guard->PoolUsed() / (1024 * 1024), m_limits.guardPoolBytes / (1024 * 1024),
                  m_stats.guardPreAuth + m_stats.guardPeerFull + m_stats.guardPoolFull);
    }
    return 1;
}

void HubServer::CloseOverflow()
{
    // Closing sends by itself (HubPeerDown to the guests of a host who left) and may add here; no more rounds than
    // connections
    for (size_t round = 0; !m_overflow.empty() && m_host && round <= m_host->peerCount; ++round)
    {
        std::vector<ENetPeer*> over;
        over.swap(m_overflow);
        std::sort(over.begin(), over.end());
        over.erase(std::unique(over.begin(), over.end()), over.end());
        for (ENetPeer* peer : over)
        {
            if (peer->state == ENET_PEER_STATE_DISCONNECTED)
                continue;
            ++m_stats.queueClosed;
            const auto index = static_cast<size_t>(peer - m_host->peers);
            if (log::Due(kDueQueue, kDueEveryMs))
                log::Warn("hub: a connection from {} does not take what is sent to it — {} KB wait in its queue (limit {} "
                          "KB): closed ({} such since the last count)",
                          AddressText(peer->address.host), index < m_queued.size() ? m_queued[index] / 1024 : 0,
                          m_limits.maxQueuedBytes / 1024, m_stats.queueClosed);
            CloseClient(peer);
        }
    }
    m_overflow.clear();
}

void HubServer::CloseIdle(uint64_t aNowMs)
{
    if (m_limits.idleMs)
    {
        std::vector<ENetPeer*> silent;
        for (const auto& [peer, since] : m_idle)
            if (aNowMs - since > m_limits.idleMs)
                silent.push_back(peer);
        for (ENetPeer* peer : silent)
        {
            ++m_stats.idleClosed;
            if (log::Due(kDueIdle, kDueEveryMs))
                log::Info("hub: a connection from {} made no session and joined none in {} s — closed ({} such since the "
                          "last count)",
                          AddressText(peer->address.host), m_limits.idleMs / 1000, m_stats.idleClosed);
            CloseClient(peer);
        }
    }
    // Per-address counts are per minute; drop old entries so the map does not grow with addresses that no longer come
    m_book->Sweep(aNowMs);
    // The waiting pool from ENet's queues: what has left stops counting (EnetGuard counts it from above between recounts)
    if (m_guard && m_host)
        m_guard->Tick(*m_host, aNowMs);
}

void HubServer::Redirect(ENetPeer* aPeer, size_t aShard)
{
    ++m_stats.redirected;
    proto::Writer w(proto::MsgType::HubRedirect);
    w.PutU16(m_shards->PortOf(aShard));
    SendTo(aPeer, w.Data(), 0, true);
}

void HubServer::GivePass(ENetPeer* aPeer, Session& aSession, const std::string& aCode)
{
    if (!GivesPasses() || !aSession.hostKeySet)
        return;
    hubrules::ResumePass pass;
    pass.flags = (aSession.hostFlags & netcrypto::Cert::kFlagEncrypts) ? hubrules::kResumePassEncrypts : 0;
    pass.code = aCode;
    pass.protocol = aSession.version;
    pass.session = aSession.cryptoId;
    pass.hostKey = aSession.hostKey;
    pass.issued = NowUnixSec();
    pass.until = pass.issued + hubrules::kResumePassLifeSec;
    m_keys->SignResumePass(pass);
    // Sealed to the host's key: the code inside stays hidden on the path, and only the host can show the pass again
    const std::vector<uint8_t> sealed = m_keys->SealForClient(aSession.hostKey.data(), netcrypto::kBoxPassToHost, pass.Write());
    if (sealed.empty())
        return;
    proto::Writer w(proto::MsgType::HubResumePass);
    w.PutU8(hubrules::kResumeVersion);
    w.PutBytes(std::vector<uint8_t>(m_keys->BoxPublic().begin(), m_keys->BoxPublic().end()));
    w.PutU16(static_cast<uint16_t>(sealed.size()));
    w.PutBytes(sealed);
    SendTo(aPeer, w.Data(), 0, true);
    aSession.passAtMs = NowMs();
    ++m_stats.passesGiven;
}

void HubServer::Resume(ENetPeer* aPeer, proto::Reader& aReader)
{
    // Off, or no key to check passes with: skipped silently, as by a hub that does not know the request
    if (!GivesPasses())
        return;
    const uint32_t version = aReader.GetU32();
    const uint8_t caps = aReader.GetU8();
    const uint32_t nextId = aReader.GetU32();
    netcrypto::ClientExt ext;
    if (!aReader.Ok() || !netcrypto::ReadClientExt(aReader, ext) || !ext.present || !(ext.flags & netcrypto::kExtSealed))
        return; // an honest host always sends its key and the sealed pass
    // One session and one role per connection, as in HubCreateSession
    if (m_clients.count(aPeer))
    {
        ++m_stats.ignoredRepeats;
        if (log::Due(kDueRepeat, kDueEveryMs))
            log::Warn("hub: a connection from {} that is in a session already asks to bring one back — ignored ({} such "
                      "since the last count)",
                      AddressText(aPeer->address.host), m_stats.ignoredRepeats);
        return;
    }
    // Hub threads: like a new session, the least loaded thread takes it (before any crypto: the request is opened there).
    // A hub closed in the location list brings its own sessions back: they are not new
    if (m_shards && (caps & proto::kHubCapRedirect) && !(caps & proto::kHubCapPlaced))
    {
        const size_t connections = m_clients.size() + m_idle.size();
        const size_t target = m_shards->Pick(m_shard, static_cast<uint32_t>(connections ? connections - 1 : 0));
        if (target != m_shard)
        {
            Redirect(aPeer, target);
            return;
        }
    }
    const uint64_t now = NowMs();
    const uint32_t from = aPeer->address.host;
    // Sessions from one address per minute count the returns too
    if (m_limits.createsPerMinute && m_book->Creates(from, now) >= m_limits.createsPerMinute)
    {
        ++m_stats.refusedLimits;
        ++m_stats.resumesRefused;
        Reject(aPeer, hubrules::kReasonTooManyCreates);
        if (log::Due(kDueResumeLimit, kDueEveryMs))
            log::Warn("hub: refused to bring a session back for {}: too many new sessions from this address in a minute",
                      AddressText(from));
        return;
    }
    // The request opens only under the key it names: its sender holds that key's secret. Inside: the pass (this hub's
    // signature, bound to that key and to the game protocol) and the hub's time by the host's count
    hubrules::ResumePass pass;
    hubrules::ResumeFacts facts;
    netcrypto::LookAtResume(*m_keys, ext.key.data(), ext.sealed, version, NowUnixSec(), facts, pass);
    const bool honest = hubrules::JudgeResume(facts) == hubrules::ResumeVerdict::Ok;
    if (honest)
    {
        facts.live = m_sessions.count(pass.code) != 0 || (m_shards && m_shards->Find(pass.code) >= 0);
        facts.full = m_sessions.size() >= m_limits.maxSessions;
    }
    hubrules::ResumeVerdict verdict = hubrules::JudgeResume(facts);
    // The code is taken in the shared directory at once (another thread may be bringing the same code back right now)
    if (verdict == hubrules::ResumeVerdict::Ok && m_shards && !m_shards->Register(pass.code, m_shard))
        verdict = hubrules::ResumeVerdict::Live;
    if (verdict != hubrules::ResumeVerdict::Ok)
    {
        ++m_stats.resumesRefused;
        if (verdict == hubrules::ResumeVerdict::Bad)
        {
            // A stream of requests that do not open costs the hub an X25519 each: counted with the refused joins of the
            // address (code guessing), beyond the limit the connection is closed
            const uint32_t fails = m_book->AddJoinFail(from, now);
            if (m_limits.joinFailsPerMinute && fails > m_limits.joinFailsPerMinute)
            {
                ++m_stats.refusedLimits;
                CloseClient(aPeer);
                return;
            }
        }
        if (verdict == hubrules::ResumeVerdict::Full)
            ++m_stats.refusedLimits;
        Reject(aPeer, hubrules::ResumeReason(verdict));
        // The code goes into the log only from a pass this hub signed (a string from the network never does)
        const bool genuine = facts.opened && facts.parsed && facts.signedHere;
        if (log::Due(kDueResume, kDueEveryMs))
            log::Warn("hub: refused to bring session {} back for {}: {} ({} refused since the last count)",
                      genuine ? pass.code : std::string("?"), AddressText(from), hubrules::ResumeReason(verdict),
                      m_stats.resumesRefused);
        return;
    }

    m_book->AddCreate(from, now);
    Session session;
    session.host = aPeer;
    session.version = pass.protocol;
    // The same tag in signatures and the same host key: the session is the one it was, its links' keys stay valid
    session.cryptoId = pass.session;
    session.hostKey = pass.hostKey;
    session.hostFlags = (pass.flags & hubrules::kResumePassEncrypts) ? netcrypto::Cert::kFlagEncrypts : 0;
    session.hostKeySet = !netcrypto::IsZero(pass.hostKey.data(), pass.hostKey.size());
    // Peer numbers go on above every number the session had: a returning guest does not take the number of a partner still
    // playing on the direct path
    session.nextId = hubrules::ResumeNextId(nextId);
    const auto created = m_sessions.emplace(pass.code, std::move(session)).first;
    m_clients[aPeer] = Client{pass.code, 0, true};
    m_idle.erase(aPeer);
    ++m_stats.sessionsResumed;

    // The answer is the one to a creation, without the code (the host has it): the signature on the host's key, then a
    // fresh pass
    const netcrypto::Cert cert = m_keys->Sign(netcrypto::Role::Host, 0, created->second.cryptoId,
                                              created->second.hostKey.data(), created->second.hostFlags, NowUnixSec());
    ++m_stats.certsSigned;
    proto::Writer w(proto::MsgType::HubSessionCreated);
    w.PutString(std::string());
    netcrypto::PutHubExt(w, &cert, nullptr);
    SendTo(aPeer, w.Data(), 0, true);
    GivePass(aPeer, created->second, pass.code);
    log::Info("hub: session {} is back — its host brought it with a pass issued {} min ago (game protocol {}, peer numbers "
              "go on from {}) — {} session(s), {} client(s)",
              pass.code, (facts.nowSec > pass.issued ? facts.nowSec - pass.issued : 0) / 60, pass.protocol,
              created->second.nextId, m_sessions.size(), m_clients.size());
}

void HubServer::Route(Session& aSession, uint32_t aFromId, uint32_t aToId, const std::vector<uint8_t>& aPayload,
                      uint8_t aChannel, bool aReliable)
{
    proto::Writer w(proto::MsgType::HubPayload);
    w.PutU32(aFromId); // the recipient needs to know WHO it came from
    w.PutBytes(aPayload);
    const auto& bytes = w.Data();

    // A guest talks only to the host (Session::FlushGameOut, HybridTransport: a guest has one link, to the host, and the
    // host tells it about the others). Payloads from a guest straight to another guest or broadcast to guests are not
    // relayed: that way a guest could send another guest of the session words "from the host" (Reject, Welcome) that it
    // would accept. A guest's broadcast (Bye of the old hub-only mode) goes to the host
    if (aFromId != 0)
    {
        if (aToId == 0 || aToId == proto::kHubBroadcast)
            SendTo(aSession.host, bytes, aChannel, aReliable);
        else
            ++m_stats.payloadsDropped;
        return;
    }

    if (aToId == proto::kHubBroadcast)
    {
        for (auto& [id, peer] : aSession.guests)
            SendTo(peer, bytes, aChannel, aReliable);
        return;
    }

    const auto it = aSession.guests.find(aToId);
    if (it != aSession.guests.end())
        SendTo(it->second, bytes, aChannel, aReliable);
}

/// A guest coming and going is told to the host only. A guest talks to the host alone, and the host tells it about the
/// others (PeerJoined/PeerLeft); broadcasting to all guests made them take someone else's connection for their own (in
/// a three-player session through the hub a guest reconnected when another one left).
void HubServer::NotifyHost(Session& aSession, uint8_t aType, uint32_t aWho)
{
    proto::Writer w(static_cast<proto::MsgType>(aType));
    w.PutU32(aWho);
    SendTo(aSession.host, w.Data(), 0, true);
}

void HubServer::NotifyPeerUp(Session& aSession, uint32_t aWho)
{
    proto::Writer w(proto::MsgType::HubPeerUp);
    w.PutU32(aWho);
    // A fresh signature on the host's key, which the host shows this guest (a signature lasts an hour, a session as long as
    // it likes). Older hosts do not read the tail
    if (m_keys && aSession.hostKeySet)
    {
        const netcrypto::Cert cert = m_keys->Sign(netcrypto::Role::Host, 0, aSession.cryptoId, aSession.hostKey.data(),
                                                  aSession.hostFlags, NowUnixSec());
        netcrypto::PutHubExt(w, &cert, nullptr);
        ++m_stats.certsSigned;
    }
    SendTo(aSession.host, w.Data(), 0, true);
}

void HubServer::CloseClient(ENetPeer* aPeer)
{
    DropClient(aPeer);
    m_idle.erase(aPeer);
    m_introAsks.erase(aPeer);
    enet_peer_disconnect_now(aPeer, 0);
}

void HubServer::DropClient(ENetPeer* aPeer)
{
    const auto it = m_clients.find(aPeer);
    if (it == m_clients.end())
        return;

    const Client client = it->second;
    m_clients.erase(it);

    const auto sit = m_sessions.find(client.code);
    if (sit == m_sessions.end())
        return;
    Session& session = sit->second;

    if (client.isHost)
    {
        // The host left: the session is gone. Tell the guests and let them go: keeping them in an empty session is pointless,
        // and leaving them silent means making them wait for a timeout.
        proto::Writer w(proto::MsgType::HubPeerDown);
        w.PutU32(0);
        const uint64_t now = NowMs();
        for (auto& [id, peer] : session.guests)
        {
            SendTo(peer, w.Data(), 0, true);
            m_clients.erase(peer);
            // The guest's connection is alive: it becomes a connection without a session, like a newly arrived one — it may create
            // a session or join another like any; silent for idleMs, it is closed by the hub (CloseIdle), and until then it is
            // under the "outside a session" limits (EnetGuard). Otherwise it would be counted nowhere: an honest client leaves by
            // itself (reconnecting with a new connection), while a modified one could hold an ENet slot forever
            m_idle[peer] = now;
            ++m_stats.orphansIdled;
        }
        log::Info("hub: session {} closed (host left, {} guest(s))", client.code, session.guests.size());
        if (m_shards)
            m_shards->Unregister(client.code);
        m_sessions.erase(sit);
        return;
    }

    session.guests.erase(client.id);
    // 13.11: its low byte stays taken while the host keeps its place (hubrules::kPeerByteHoldMs)
    session.held[client.id] = NowMs() + hubrules::kPeerByteHoldMs;
    NotifyHost(session, static_cast<uint8_t>(proto::MsgType::HubPeerDown), client.id);
    log::Info("hub: peer {} left session {} ({} remaining)", client.id, client.code, session.guests.size());
}

void HubServer::HandlePacket(ENetPeer* aPeer, const uint8_t* aData, size_t aSize, uint8_t aChannel)
{
    proto::Reader reader(aData, aSize);
    const auto type = reader.ReadHeader();
    if (!reader.Ok())
        return;

    const bool reliable = (aChannel == 0);

    switch (type)
    {
    case proto::MsgType::HubCreateSession:
    {
        const uint32_t version = reader.GetU32();
        if (!reader.Ok())
            return;
        // Tail of the request: what the client understands (proto::kHubCap*). Older clients do not send it: 0
        const uint8_t caps = reader.Remaining() ? reader.GetU8() : 0;
        // After it: the host's X25519 key for the session (to sign) and a request to seal the code in the answer. A broken tail
        // counts as none
        netcrypto::ClientExt ext;
        if (!netcrypto::ReadClientExt(reader, ext))
            ext = netcrypto::ClientExt{};

        // A connection belongs to one session in one role. A repeated request used to overwrite the client's record while the
        // old session kept a pointer to its ENet slot: after it left, the slot went to the next client, which then received
        // that session's HubPeerUp and HubPayload "from the host". An honest client sends one request per connection
        if (m_clients.count(aPeer))
        {
            ++m_stats.ignoredRepeats;
            if (log::Due(kDueRepeat, kDueEveryMs))
                log::Warn("hub: a connection from {} that is in a session already asks for a new one — ignored ({} such "
                          "since the last count)",
                          AddressText(aPeer->address.host), m_stats.ignoredRepeats);
            return;
        }
        // The owner closed this hub in the location list: no new sessions here; the current ones live on, and guests still
        // join them by code
        if (const auto locations = m_locations ? m_locations->Get() : nullptr; locations && locations->closedHere)
        {
            ++m_stats.refusedClosed;
            Reject(aPeer, "the hub is closed for new sessions");
            if (log::Due(kDueClosed, kDueEveryMs))
                log::Info("hub: refused a new session from {}: this hub is closed in the location list ({} such since the "
                          "last count; {} session(s) here live on)",
                          AddressText(aPeer->address.host), m_stats.refusedClosed, m_sessions.size());
            return;
        }
        // Hub threads: a new session goes to the least loaded thread under the CPU limit (hub_cpu_gate); with every thread at
        // the limit the hub takes none now. A client that understands redirects goes there itself and repeats the request
        // marked "already redirected" (that thread was under the limit a moment ago: taken as is); an older client and a
        // single hub are served here if this thread is under the limit
        if (m_shards && (caps & proto::kHubCapRedirect) && !(caps & proto::kHubCapPlaced))
        {
            const size_t connections = m_clients.size() + m_idle.size();
            const int target =
                m_shards->PickOpen(m_shard, static_cast<uint32_t>(connections ? connections - 1 : 0), m_limits.cpuLimitPct);
            if (target < 0)
            {
                RefuseBusy(aPeer);
                return;
            }
            if (static_cast<size_t>(target) != m_shard)
            {
                Redirect(aPeer, static_cast<size_t>(target));
                return;
            }
        }
        else if (!(caps & proto::kHubCapPlaced) && !hubrules::CpuOpen(m_cpuPermille, m_limits.cpuLimitPct))
        {
            RefuseBusy(aPeer);
            return;
        }
        const uint64_t now = NowMs();
        const bool tooMany =
            m_limits.createsPerMinute && m_book->Creates(aPeer->address.host, now) >= m_limits.createsPerMinute;
        if (tooMany || m_sessions.size() >= m_limits.maxSessions)
        {
            ++m_stats.refusedLimits;
            Reject(aPeer, tooMany ? hubrules::kReasonTooManyCreates : hubrules::kReasonHubFull);
            if (log::Due(kDueLimit, kDueEveryMs))
                log::Warn("hub: refused a new session from {}: {} ({} session(s) of {}; {} refusal(s) by a limit since "
                          "the last count)",
                          AddressText(aPeer->address.host),
                          tooMany ? "too many new sessions from this address in a minute" : "the hub is full",
                          m_sessions.size(), m_limits.maxSessions, m_stats.refusedLimits);
            return;
        }
        m_book->AddCreate(aPeer->address.host, now);

        std::string code = MakeCode();
        // A collision is unlikely, but checking is cheaper than finding out later why two players landed in someone else's
        // session. With hub threads the code is taken in the shared directory, one for the whole hub
        while (m_shards ? !m_shards->Register(code, m_shard) : m_sessions.count(code) != 0)
            code = MakeCode();

        Session session;
        session.host = aPeer;
        session.version = version;
        // The session's tag in signatures, from the system generator (guest and host check by it that the keys belong to one
        // session)
        if (!netcrypto::Random(session.cryptoId.data(), session.cryptoId.size()) && log::Due(kDueSealed ^ 1, kDueEveryMs))
            log::Error("hub: the system random generator failed — the session's signature mark is zero");
        if (ext.present && (ext.flags & netcrypto::kExtEncrypts))
        {
            session.hostKey = ext.key;
            session.hostFlags = netcrypto::Cert::kFlagEncrypts;
            session.hostKeySet = !netcrypto::IsZero(ext.key.data(), ext.key.size());
        }
        const auto created = m_sessions.emplace(code, std::move(session)).first;
        m_clients[aPeer] = Client{code, 0, true};
        m_idle.erase(aPeer);
        ++m_stats.sessionsCreated;

        // Tail of the answer: the signature on the host's key, and the code sealed if the host asked (then the open field is
        // empty). Older hosts send no tail and get the plain answer
        std::vector<uint8_t> sealed;
        if (m_keys && ext.present && (ext.flags & netcrypto::kExtSealed))
            sealed = m_keys->SealCode(ext.key.data(), code);
        netcrypto::Cert cert;
        const bool signs = m_keys && created->second.hostKeySet;
        if (signs)
        {
            cert = m_keys->Sign(netcrypto::Role::Host, 0, created->second.cryptoId, created->second.hostKey.data(),
                                created->second.hostFlags, NowUnixSec());
            ++m_stats.certsSigned;
        }
        m_stats.codesSealed += sealed.empty() ? 0 : 1;
        proto::Writer w(proto::MsgType::HubSessionCreated);
        w.PutString(sealed.empty() ? code : std::string());
        netcrypto::PutHubExt(w, signs ? &cert : nullptr, sealed.empty() ? nullptr : &sealed);
        SendTo(aPeer, w.Data(), 0, true);
        // The pass to bring the session back after a restart of the hub — right after the code (older hosts skip it)
        GivePass(aPeer, created->second, code);
        log::Info("hub: session {} created (game protocol {}){}{} — {} session(s), {} client(s)", code, version,
                  signs ? ", the host's key is signed" : ext.present ? ", the host's key is not signed (no hub key)" : "",
                  created->second.passAtMs ? ", the host holds a resume pass" : "", m_sessions.size(), m_clients.size());
        return;
    }

    case proto::MsgType::HubJoinSession:
    {
        const uint32_t version = reader.GetU32();
        std::string code = reader.GetString();
        if (!reader.Ok())
            return;
        const uint8_t caps = reader.Remaining() ? reader.GetU8() : 0; // as in HubCreateSession
        // The guest's X25519 key for the session (to sign) and the code sealed to the hub's "box"
        netcrypto::ClientExt ext;
        if (!netcrypto::ReadClientExt(reader, ext))
            ext = netcrypto::ClientExt{};

        // One session and one role per connection, as in HubCreateSession above
        if (m_clients.count(aPeer))
        {
            ++m_stats.ignoredRepeats;
            if (log::Due(kDueRepeat, kDueEveryMs))
                log::Warn("hub: a connection from {} that is in a session already asks to join one — ignored ({} such "
                          "since the last count)",
                          AddressText(aPeer->address.host), m_stats.ignoredRepeats);
            return;
        }

        // The code is sealed (the build knows the project hub's "box"): open it. If it does not open, the hub has another key
        // or none
        if (ext.present && (ext.flags & netcrypto::kExtSealed))
        {
            std::string opened;
            if (!m_keys || !m_keys->OpenCode(ext.key.data(), ext.sealed, opened))
            {
                ++m_stats.sealedRefused;
                ++m_stats.joinsRefused;
                // The per-address refusal count is shared with "no such session": a stream of unopenable requests costs the hub an
                // X25519 each
                const uint32_t fails = m_book->AddJoinFail(aPeer->address.host, NowMs());
                if (m_limits.joinFailsPerMinute && fails > m_limits.joinFailsPerMinute)
                {
                    ++m_stats.refusedLimits;
                    CloseClient(aPeer);
                    return;
                }
                Reject(aPeer, m_keys ? "the hub could not open the sealed session code (another hub key?)"
                                     : "this hub has no key to open a sealed session code");
                if (log::Due(kDueSealed, kDueEveryMs))
                    log::Warn("hub: refused a join from {}: its session code is sealed to a key this hub {} ({} such since "
                              "the last count)",
                              AddressText(aPeer->address.host), m_keys ? "does not hold" : "has none of",
                              m_stats.sealedRefused);
                return;
            }
            code = opened;
            ++m_stats.codesSealed;
        }

        for (char& c : code)
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

        const uint64_t now = NowMs();
        // A code not of the form the hub issues cannot be a session; a string from the network never goes into the log (up to
        // 64 KiB per packet)
        const auto sit = ValidCode(code) ? m_sessions.find(code) : m_sessions.end();
        // Hub threads: the session with this code is on another thread, and the client goes there itself. An older client
        // cannot: refused with the reason (the guessing count does not grow: the code is real)
        if (sit == m_sessions.end() && m_shards && ValidCode(code))
        {
            const int where = m_shards->Find(code);
            if (where >= 0 && static_cast<size_t>(where) != m_shard)
            {
                if ((caps & proto::kHubCapRedirect) && !(caps & proto::kHubCapPlaced))
                {
                    Redirect(aPeer, static_cast<size_t>(where));
                    return;
                }
                ++m_stats.joinsRefused;
                Reject(aPeer, (caps & proto::kHubCapPlaced) ? "the session is on another port of the hub"
                                                            : "this session needs a newer NightCoop build");
                if (log::Due(kDueElsewhere, kDueEveryMs))
                    log::Warn("hub: refused a join from {} to session {} of thread {}: the client {} ({} refused join(s) "
                              "since the last count)",
                              AddressText(aPeer->address.host), code, where,
                              (caps & proto::kHubCapPlaced) ? "says it was sent here already"
                                                            : "does not follow HubRedirect (a build before 12.10)",
                              m_stats.joinsRefused);
                return;
            }
        }
        if (sit == m_sessions.end())
        {
            ++m_stats.joinsRefused;
            const uint32_t fails = m_book->AddJoinFail(aPeer->address.host, now);
            if (m_limits.joinFailsPerMinute && fails > m_limits.joinFailsPerMinute)
            {
                // Code guessing: no more answers to this connection
                ++m_stats.refusedLimits;
                if (log::Due(kDueBrute, kDueEveryMs))
                    log::Warn("hub: {} asked for {} unknown session(s) in a minute — its connection is closed", AddressText(aPeer->address.host),
                              fails);
                CloseClient(aPeer);
                return;
            }
            Reject(aPeer, hubrules::kReasonNoSession);
            if (log::Due(kDueUnknown, kDueEveryMs))
                log::Info("hub: refused a join from {} for an unknown session ({} refused join(s) since the last count)",
                          AddressText(aPeer->address.host), m_stats.joinsRefused);
            return;
        }

        Session& session = sit->second;
        if (version != session.version)
        {
            ++m_stats.joinsRefused;
            Reject(aPeer, "protocol mismatch");
            if (log::Due(kDueVersion, kDueEveryMs))
                log::Warn("hub: refused a join to session {}: the guest has game protocol {}, the host {}", code, version,
                          session.version);
            return;
        }
        if (session.guests.size() >= m_limits.maxGuests)
        {
            ++m_stats.joinsRefused;
            ++m_stats.refusedLimits;
            Reject(aPeer, "the session is full");
            if (log::Due(kDueLimit, kDueEveryMs))
                log::Warn("hub: refused a join to session {}: {} guest connection(s) there already", code,
                          session.guests.size());
            return;
        }
        // 13.11 (security review; hubrules::NextPeerNumber): the smallest number not given yet whose low byte — the
        // "creator" in entity numbers — is usable and not the byte of a live guest or of one who left less than the host's
        // grace ago
        std::array<bool, 256> taken{};
        taken[0] = true; // the host
        for (const auto& [guestId, guestPeer] : session.guests)
            taken[guestId & 0xFF] = true;
        hubrules::TakeHeldBytes(session.held, now, taken);
        const uint32_t id = hubrules::NextPeerNumber(session.nextId, taken);
        if (!id)
        {
            ++m_stats.joinsRefused;
            ++m_stats.refusedLimits;
            Reject(aPeer, "the session is full");
            if (log::Due(kDueLimit, kDueEveryMs))
                log::Warn("hub: refused a join to session {}: no free peer number — every usable low byte is taken by a guest "
                          "or one who left less than {} s ago ({} held)",
                          code, hubrules::kPeerByteHoldMs / 1000, session.held.size());
            return;
        }
        session.nextId = id + 1;
        session.guests[id] = aPeer;
        m_clients[aPeer] = Client{code, id, false};
        m_idle.erase(aPeer);
        ++m_stats.joinsAccepted;

        proto::Writer accepted(proto::MsgType::HubJoinAccepted);
        accepted.PutU32(id);
        // The signature on the guest's key (its role, its number at the hub, the session's tag). Older guests do not read the
        // tail
        const bool signs = m_keys && ext.present && (ext.flags & netcrypto::kExtEncrypts) &&
                           !netcrypto::IsZero(ext.key.data(), ext.key.size());
        if (signs)
        {
            const netcrypto::Cert cert = m_keys->Sign(netcrypto::Role::Guest, id, session.cryptoId, ext.key.data(),
                                                      netcrypto::Cert::kFlagEncrypts, NowUnixSec());
            // The host holds a resume pass: after a restart of the hub this session comes back with the same code, and the
            // guest that lost the hub waits for it rather than giving up at "no such session"
            netcrypto::PutHubExt(accepted, &cert, nullptr,
                                 (GivesPasses() && session.passAtMs != 0) ? netcrypto::kExtResume : uint8_t{0});
            ++m_stats.certsSigned;
        }
        SendTo(aPeer, accepted.Data(), 0, true);

        NotifyPeerUp(session, id);
        log::Info("hub: peer {} joined session {} ({} guest(s)){}", id, code, session.guests.size(),
                  signs ? ", its key is signed" : "");
        return;
    }

    case proto::MsgType::HubPayload:
    {
        ++m_stats.payloadsIn;
        m_stats.payloadBytesIn += aSize;
        const uint32_t to = reader.GetU32();
        auto payload = reader.GetRest();
        if (!reader.Ok())
            return;

        const auto cit = m_clients.find(aPeer);
        if (cit == m_clients.end())
        {
            ++m_stats.payloadsDropped;
            if (log::Due(kDueForeign, kDueEveryMs))
                log::Info("hub: a payload from {} that is in no session — dropped ({} dropped since the last count)",
                          AddressText(aPeer->address.host), m_stats.payloadsDropped);
            return;
        }
        const auto sit = m_sessions.find(cit->second.code);
        if (sit == m_sessions.end())
            return;

        // Witness: the biggest thing that went through the hub guides the packet limit (Limits::maxPacketBytes)
        if (aSize > m_stats.biggestPayload)
            m_stats.biggestPayload = aSize;
        if (aSize > kWitnessBytes && log::Due(kDueWitness, 60000))
            log::Warn("hub: a payload of {} KB in session {} from peer {} (bigger than {} KB — tell the packet limit about "
                      "it)",
                      aSize / 1024, cit->second.code, cit->second.id, kWitnessBytes / 1024);

        Route(sit->second, cit->second.id, to, payload, aChannel, reliable);
        return;
    }

    case proto::MsgType::HubAddrQuery:
    {
        // The address the client came from is its external address behind NAT, a candidate for the direct path. Answer any
        // connected client: it knows its own address anyway, and the answer is not many times bigger than the question
        proto::Writer seen(proto::MsgType::HubAddrSeen);
        seen.PutU32(aPeer->address.host);
        seen.PutU16(aPeer->address.port);
        SendTo(aPeer, seen.Data(), 0, true);
        return;
    }

    case proto::MsgType::HubIntroAsk:
    {
        // Who this hub is, before the client's request. The answer is ready-made bytes (certificates are signed in advance),
        // with the hub list only if the client's one is older. Answer any connected client (like HubAddrQuery), but no more
        // than kMaxIntroAsks times per connection: the answer is bigger than the question
        if (m_testIgnoreIntro)
            return;
        reader.GetU8(); // question version: fields are only ever added
        const uint64_t known = reader.Remaining() >= 8 ? reader.GetU64() : 0;
        uint8_t& asked = m_introAsks[aPeer];
        if (asked >= kMaxIntroAsks)
        {
            ++m_stats.introsIgnored;
            return;
        }
        ++asked;
        const auto intro = m_intro ? m_intro->Get() : nullptr;
        static const std::vector<uint8_t> kNone;
        const bool withList = intro && !intro->list.empty() && intro->listSerial > known;
        proto::Writer w(proto::MsgType::HubIntro);
        netcrypto::PutHubIntro(w, intro ? intro->root : kNone, intro ? intro->self : kNone, withList ? intro->list : kNone);
        SendTo(aPeer, w.Data(), 0, true);
        ++m_stats.intros;
        m_stats.listsSent += withList ? 1 : 0;
        return;
    }

    case proto::MsgType::HubResumeSession:
        Resume(aPeer, reader);
        return;

    case proto::MsgType::HubResumeAsk:
    {
        // A fresh pass for the host of a running session (its pass is getting old), at most once a minute
        if (!GivesPasses())
            return;
        const auto cit = m_clients.find(aPeer);
        if (cit == m_clients.end() || !cit->second.isHost)
            return;
        const auto sit = m_sessions.find(cit->second.code);
        if (sit == m_sessions.end() || !sit->second.hostKeySet)
            return;
        if (sit->second.passAtMs && NowMs() - sit->second.passAtMs < hubrules::kResumeAskEveryMs)
            return;
        GivePass(aPeer, sit->second, sit->first);
        return;
    }

    default:
        // Game messages must not come here: they ride inside HubPayload. Everything else is skipped silently.
        return;
    }
}
} // namespace nc
