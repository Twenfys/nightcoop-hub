#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct _ENetHost;
struct _ENetPeer;

namespace nc::enetguard
{
class Guard;
}

namespace nc::netcrypto
{
class HubKeys;
}

namespace nc::proto
{
class Reader;
}

namespace nc
{
/// Requests from an address in the current minute (code guessing, a stream of creations). A single hub has its own; the
/// threads of a hub share one (HubShards), so the limit is per hub, not per thread. Under a lock: touched only when a
/// session is created or joined.
class HubAddressBook
{
public:
    /// Session creations from the address in this minute
    uint32_t Creates(uint32_t aAddress, uint64_t aNowMs);
    void AddCreate(uint32_t aAddress, uint64_t aNowMs);
    /// A refused join: add one and return this minute's count
    uint32_t AddJoinFail(uint32_t aAddress, uint64_t aNowMs);
    /// Drop old entries, so that the map does not grow with addresses that no longer come
    void Sweep(uint64_t aNowMs);
    void Clear();

private:
    struct Entry
    {
        uint64_t minuteStartMs = 0;
        uint32_t joinFails = 0;
        uint32_t creates = 0;
    };
    Entry& Of(uint32_t aAddress, uint64_t aNowMs); ///< under m_mutex

    std::mutex m_mutex;
    std::unordered_map<uint32_t, Entry> m_entries;
};

/// What the hub shows a client on HubIntroAsk: the certificate from the root (if the owner issued one), the
/// self-certificate (the hub's keys signed by itself: for the fingerprint) and the project's hub list. Shared by the
/// hub's threads; tools/hub/main.cpp replaces it when the files on disk change (a new certificate or list without a
/// restart).
class HubIntroSource
{
public:
    struct Data
    {
        std::vector<uint8_t> root; ///< root certificate (HubCert::Write); empty: none
        std::vector<uint8_t> self; ///< self-certificate; empty: the hub has no key
        std::vector<uint8_t> list; ///< hub list (HubList::Write); empty: none
        uint64_t listSerial = 0;
    };
    void Set(std::shared_ptr<const Data> aData);
    std::shared_ptr<const Data> Get() const;

private:
    mutable std::mutex m_mutex;
    std::shared_ptr<const Data> m_data;
};

/// The project's location list signed with this hub's key (the owner's file --locations, reread by tools/hub/main.cpp
/// every 30 s). The hub gives it, with its own state, in answer to a client's connectionless question
/// (hubrules::kLocAskMagic). Shared by the hub's threads.
class HubLocationsSource
{
public:
    struct Data
    {
        std::vector<uint8_t> body;           ///< hubrules::WriteLocationBody
        std::array<uint8_t, 64> signature{}; ///< HubKeys::SignLocations
        uint64_t serial = 0;
        size_t count = 0;
        /// This hub's line in the list is "closed" (hubrules::SelfLocation): no new sessions here, the current ones live on
        bool closedHere = false;
    };
    void Set(std::shared_ptr<const Data> aData);
    std::shared_ptr<const Data> Get() const;

private:
    mutable std::mutex m_mutex;
    std::shared_ptr<const Data> m_data;
};

/// State shared by the hub's threads. A hub on several cores runs several HubServers, each with its own thread, ENetHost
/// and port; a session lives entirely in one of them, and relaying (HubPayload) works as in a single hub — no locks and
/// no shared state. Only the cold path is shared, under a lock: the "session code -> thread" directory, the per-address
/// request counts and the threads' load (used to pick the thread for a new session).
///
/// The client comes to the entry port (thread 0). If the session is on another thread, the hub answers HubRedirect with
/// that thread's port, and the client connects to the same address on it and repeats its request. A client that does
/// not understand redirects gets its session created on the thread it came to and cannot join a session of another
/// thread (refused with the reason).
class HubShards
{
public:
    /// Ports of the threads: the first is the entry port (hubrules::ShardPort)
    explicit HubShards(std::vector<uint16_t> aPorts);

    size_t Count() const { return m_ports.size(); }
    uint16_t PortOf(size_t aShard) const { return aShard < m_ports.size() ? m_ports[aShard] : 0; }
    /// A thread's load is its number of connections; the thread itself writes it every turn
    void SetLoad(size_t aShard, uint32_t aConnections);
    uint32_t LoadOf(size_t aShard) const;
    /// A thread's share of a core, ‰, smoothed (hub_cpu_gate); the thread itself writes it once a second
    void SetCpu(size_t aShard, uint16_t aPermille);
    uint16_t CpuOf(size_t aShard) const;
    /// The least busy thread's share of a core, ‰ (threads with a port)
    uint16_t LeastCpu() const;
    /// The thread for a new session: the least loaded among those less loaded than the own one (aOwnLoad: the own thread's
    /// connections without the asker); if there is none, aSelf — no extra hop
    size_t Pick(size_t aSelf, uint32_t aOwnLoad) const;
    /// The same among the threads under aLimitPct of a core (hubrules::PickOpenThread); -1: every thread is at the limit
    int PickOpen(size_t aSelf, uint32_t aOwnLoad, uint8_t aLimitPct) const;
    /// Binds a code to a thread. False: the code exists already (on any thread)
    bool Register(const std::string& aCode, size_t aShard);
    void Unregister(const std::string& aCode);
    /// The thread of the session with this code; -1: no such session
    int Find(const std::string& aCode);
    HubAddressBook& Book() { return m_book; }

private:
    std::vector<uint16_t> m_ports;
    std::unique_ptr<std::atomic<uint32_t>[]> m_load;
    std::unique_ptr<std::atomic<uint16_t>[]> m_cpu;
    std::mutex m_mutex;
    std::unordered_map<std::string, size_t> m_codes;
    HubAddressBook m_book;
};

/// The NightCoop hub: a meeting point and relay (tools/hub is the program around it; tests run it in their own process).
///
/// A direct connection needs a reachable address at the host — a public IP and a forwarded port — which most players do
/// not have. Outgoing connections work from anywhere, so both sides come here, and the hub relays bytes between them and
/// tells each one the address it sees (HubAddrSeen): the hybrid transport uses it to punch a direct path.
///
/// What it does NOT do is parse the session. Game messages and the transport's direct-path messages ride inside
/// HubPayload as opaque bytes; the hub only knows whom to hand them to. It does not impose the game protocol version
/// either: the session's host sets it, and a guest with another one is refused. The hub's own protocol is the Hub*
/// message numbers and the header magic.
///
/// A hub client is a stranger, possibly running a modified mod. A connection belongs to one session in one role
/// (repeated HubCreateSession / HubJoinSession are ignored: they used to leave a pointer to the ENet slot in the
/// abandoned session, and whoever took the slot next received its traffic "from the host"); everything has limits
/// (Limits); strings from the network do not go into the log as they are; session codes come from the system's random
/// generator.
///
/// Single-threaded: Service and Stop are called by one thread (Start by the same or another one, before the first
/// Service). A hub on several cores runs several of these, one per thread (HubShards).
class HubServer
{
public:
    HubServer(); ///< in .cpp: m_guard is an incomplete type here
    ~HubServer();

    HubServer(const HubServer&) = delete;
    HubServer& operator=(const HubServer&) = delete;

    /// Hub limits. Each one follows from what an honest client sends (RelayTransport / HybridTransport):
    struct Limits
    {
        /// ENet slots (connections in total). Every player keeps a connection to the hub for the whole session, on the direct
        /// path too
        size_t maxClients = 64;
        /// Connections from one IPv4 address (ENetHost::duplicatePeers); beyond it a CONNECT gets no answer. Honest use: players
        /// of one home or one CGNAT address (the host and the guests, one connection each) plus the old connections of those
        /// who came back, which the hub buries after ENet's 30–60 s timeout. Up to eight players in a session: a home router
        /// blinks and all eight come back while their eight old connections still linger, plus two spare. 0: no limit (a load
        /// test from one machine).
        size_t maxPerAddress = 18;
        /// Sessions at once; 0: half of maxClients (a session has at least two connections)
        size_t maxSessions = 0;
        /// Guests in a session, counting the old connections of returning guests (until their timeout). A session has the host
        /// and up to seven guests (Session::kMaxGuests; the host refuses extra ones itself, with the reason); the spare is for
        /// returns: all seven come back at once — 14 connections, plus two.
        size_t maxGuests = 16;
        /// A whole ENet packet (HubPayload: a session message or a stream frame). No receiver accepts more: the largest message,
        /// an animation stream message, stays under 7.8 MiB with all its wrappers, while real sessions send at most a few tens
        /// of KiB at a time. Payloads above kWitnessBytes are logged.
        size_t maxPacketBytes = 8u * 1024u * 1024u;
        /// Received but not yet delivered to the hub, per connection (ENetHost::maximumWaitingData and EnetGuard's strict
        /// limit, with the new packet and record costs): the biggest honest packet plus 1 MiB of queue behind it while it is
        /// reassembled
        size_t maxWaitingBytes = 9u * 1024u * 1024u;
        /// Data waiting in ENet's queues (EnetGuard.hpp): each connection's own share and the thread's shared pool above the
        /// shares. Worst case for a hub thread: maxClients × guardOwnBytes + guardPoolBytes (512 × 128 KiB + 192 MiB = 256 MiB;
        /// the process is meant to fit in 1 GiB, so tools/hub/main.cpp splits the pool between threads). An honest connection
        /// holds here only what arrived out of order after a lost datagram — tens of KiB.
        size_t guardOwnBytes = 128u * 1024u;
        size_t guardPoolBytes = 192u * 1024u * 1024u;
        /// A connection outside a session (it neither created nor joined one, or it is a guest whose host left): an honest one
        /// sends only requests of tens of bytes, so no fragments are accepted and no more than this may wait
        size_t guardPreAuthBytes = 16u * 1024u;
        /// The pre-ENet waiting limit (EnetGuard); off: --guard off
        bool guard = true;
        /// At most this much work per Service turn (ms): a datagram stream from one connection does not keep the hub in the
        /// receive loop forever, ENet hands the rest over next turn. 0: no limit
        uint32_t serviceBudgetMs = 20;
        /// At most this much in ENet's queue to one recipient (bytes): whoever does not take (acknowledge) is closed by the hub
        /// rather than buffered until ENet's timeout. An honest hybrid keeps up to 512 KiB of reliable data in flight to its
        /// partner (its window) plus unreliable snapshots; hub-only mode has no window and no compressed stream. 0: no limit
        size_t maxQueuedBytes = 32u * 1024u * 1024u;
        /// Receive buffer of the thread's UDP socket: while the thread is busy with a turn, datagrams wait here and the kernel
        /// drops the excess. ENet's default is 256 KiB; Linux caps the request at net.core.rmem_max. 0: as ENet sets it
        size_t socketReceiveBytes = 4u * 1024u * 1024u;
        /// A connection that neither created nor joined a session within this time is closed: a client announces itself as
        /// soon as it connects (RelayTransport::Service, HybridTransport::OnHubLinked). 0: never
        uint32_t idleMs = 30000;
        /// Refused joins ("no such session") per address per minute; beyond it the connection is closed without an answer (code
        /// guessing). An honest player mistypes a code only a few times. 0: no limit
        uint32_t joinFailsPerMinute = 12;
        /// Session creations per address per minute (an honest host makes one per visit to the menu). 0: no limit
        uint32_t createsPerMinute = 12;
        /// Connection pass (HubCookie.hpp): a CONNECT without a valid pass gets no ENet slot
        enum class Cookie : uint8_t
        {
            Off,      ///< no passes are issued or checked
            Pressure, ///< always issued, required while cookieBusy or more slots are taken (clients that carry
                      ///< no pass get in at quiet times, not under a CONNECT flood)
            Always,   ///< always required: clients without passes cannot get in
        };
        Cookie cookie = Cookie::Pressure;
        /// Taken ENet slots (connections and those waiting for a CONNECT answer) from which a pass is required in Pressure
        /// mode. 0: half of maxClients — a CONNECT flood from forged addresses takes at most half the slots, the other half
        /// stays for those with a pass
        size_t cookieBusy = 0;
        /// Sessions outlive a restart of the hub (HubRules.hpp ResumePass): the host of each gets a resume pass signed with
        /// the hub's key and brings the session back with it. Needs the key (SetKeys). Off (--resume off): no passes, and
        /// HubResumeSession / HubResumeAsk are skipped silently, as by a hub that does not know them
        bool resume = true;
        /// New sessions go only to threads under this share of a core, % (hub_cpu_gate, HubRules.hpp CpuOpen): with every
        /// thread there, a new session is refused as kReasonHubFull and the location answer says Full — the client's server
        /// picker takes another server. Joins and sessions coming back are not gated. 0: no gate (as before 26.10)
        uint8_t cpuLimitPct = 0;
    };

    /// Binds the port. 64 connections are eight full sessions (a host and seven guests)
    bool Start(uint16_t aPort, size_t aMaxClients = 64);
    /// aShards: state shared by the hub's threads, aShard: this thread's number; without them, a single hub. Limits are per
    /// thread (connections and sessions per thread), the per-address request counts are shared
    bool Start(uint16_t aPort, const Limits& aLimits, HubShards* aShards = nullptr, size_t aShard = 0);
    /// One turn: waits for the first event no longer than aTimeoutMs, then handles what has accumulated
    void Service(uint32_t aTimeoutMs);
    /// Close: clients get a DISCONNECT and learn at once that the hub left, not by timeout. What the hub has taken from one
    /// player and not yet handed to another goes out first (DrainBeforeStop)
    void Stop();

    bool IsRunning() const { return m_host != nullptr; }
    size_t SessionCount() const { return m_sessions.size(); }
    /// Connections in sessions (hosts and guests)
    size_t ClientCount() const { return m_clients.size(); }
    /// Connections that have neither created nor joined a session yet
    size_t IdleCount() const { return m_idle.size(); }
    /// This thread's share of a core, ‰, smoothed (hub_cpu_gate; Service measures it once a second)
    uint16_t CpuPermille() const { return m_cpuPermille; }
    const Limits& GetLimits() const { return m_limits; }

    /// Counts since the last TakeStats (nightcoop_hub --stats): datagrams and bytes of ENet's UDP payload (its headers
    /// included, UDP/IP not), received HubPayloads, packets sent by the hub (a relay sends one per recipient)
    struct Stats
    {
        uint32_t datagramsIn = 0;
        uint32_t datagramsOut = 0;
        uint32_t bytesIn = 0;
        uint32_t bytesOut = 0;
        uint64_t payloadsIn = 0;
        uint64_t payloadBytesIn = 0;
        uint64_t sent = 0;
        uint64_t sentBytes = 0;
        uint64_t sentReliable = 0;
        // For the service log
        uint64_t sessionsCreated = 0;
        uint64_t joinsAccepted = 0;
        uint64_t joinsRefused = 0;   ///< no such session, another protocol, the session is full
        uint64_t refusedLimits = 0;  ///< refused by a hub limit: sessions, creations and joins per address
        uint64_t refusedClosed = 0;  ///< new sessions refused: this hub is closed in the location list
        uint64_t refusedBusy = 0;    ///< new sessions refused: every thread at the CPU limit (hub_cpu_gate)
        uint64_t ignoredRepeats = 0; ///< a repeated HubCreateSession / HubJoinSession from a connection already in a session
        uint64_t idleClosed = 0;     ///< connections closed without announcing themselves
        uint64_t payloadsDropped = 0; ///< HubPayload from a connection outside a session
        uint64_t redirected = 0;      ///< clients sent to another thread of the hub (HubRedirect)
        uint64_t biggestPayload = 0;  ///< the biggest HubPayload in the period, bytes
        // Connection pass
        uint64_t connected = 0;        ///< ENet connections established
        uint64_t cookiesTold = 0;      ///< passes issued (asks accepted); a current client asks once per connection
        uint64_t connectsRefused = 0;  ///< CONNECT datagrams dropped: a pass is required and it is missing or wrong
        // Pre-ENet waiting limit (EnetGuard.hpp): datagrams dropped, by reason
        uint64_t guardPreAuth = 0;  ///< a connection outside a session sent fragments or held more than its share
        uint64_t guardPeerFull = 0; ///< a connection held its limit
        uint64_t guardPoolFull = 0; ///< the thread's pool is full
        uint64_t guardPoolPeak = 0; ///< the most of the pool in use during the period, bytes
        uint64_t orphansIdled = 0;  ///< guests of a host who left, moved to connections without a session (closed after idleMs)
        uint64_t serviceCut = 0;    ///< Service turns cut by serviceBudgetMs
        uint64_t queueClosed = 0;   ///< recipients closed: their ENet queue reached maxQueuedBytes
        // Encryption (NetCrypto.hpp)
        uint64_t certsSigned = 0;   ///< signatures issued on peers' keys
        uint64_t codesSealed = 0;   ///< session codes that came in or went out sealed
        uint64_t sealedRefused = 0; ///< requests with a sealed code that did not open (wrong key, or none)
        // Hub certificate for clients (HubIntro)
        uint64_t intros = 0;        ///< answers to HubIntroAsk
        uint64_t listsSent = 0;     ///< of them with the hub list (the client's one was older)
        uint64_t introsIgnored = 0; ///< questions beyond kMaxIntroAsks from one connection, left unanswered
        // Connectionless location questions (server picker, hubrules::kLocAskMagic)
        uint64_t locationAsks = 0;   ///< answers (state and key): pings of the server picker
        uint64_t locationLists = 0;  ///< of them with the location list
        uint64_t locationTooBig = 0; ///< the list did not fit into the question (answered without it)
        // Sessions brought back after a restart (HubResumeSession)
        uint64_t passesGiven = 0;     ///< resume passes given to hosts (on creation, on return, on HubResumeAsk)
        uint64_t sessionsResumed = 0; ///< sessions brought back by their hosts' passes
        uint64_t resumesRefused = 0;  ///< resume requests refused (the pass, the code is alive, limits)
    };
    Stats TakeStats();

    /// The hub's keys (NetCrypto.hpp): the signature on peers' keys and the "box" for the session code. Set before Start;
    /// shared read-only by the hub's threads. nullptr: no signatures — clients get their partners' keys unsigned (a log line
    /// at Start), and a build carrying the project hub's key (HubRules.hpp) does not play through such a hub.
    void SetKeys(std::shared_ptr<const netcrypto::HubKeys> aKeys) { m_keys = std::move(aKeys); }
    /// What to show on HubIntroAsk (certificates and the hub list). Set before Start; nullptr: an empty answer (the client
    /// treats it as an old hub: the project's hub by its old key, other strict ones are refused)
    void SetIntro(std::shared_ptr<HubIntroSource> aIntro) { m_intro = std::move(aIntro); }
    /// For tests: an older hub that skips HubIntroAsk silently
    void TestIgnoreIntro(bool aIgnore) { m_testIgnoreIntro = aIgnore; }
    /// Location list for connectionless questions (server picker). Set before Start; nullptr: the answer carries only the
    /// state and the key (an own server without a list)
    void SetLocations(std::shared_ptr<HubLocationsSource> aLocations) { m_locations = std::move(aLocations); }
    /// Answer to a location question (aAsk: the question datagram); empty: not a question. The pure part of OnDatagram, for
    /// tests
    std::vector<uint8_t> AnswerLocations(const uint8_t* aAsk, size_t aSize);
    /// For tests: an older hub that drops location questions silently (it still answers pass asks)
    void TestIgnoreLocations(bool aIgnore) { m_testIgnoreLocations = aIgnore; }
    /// At most this many answers to HubIntroAsk per connection (an honest client asks once per connection)
    static constexpr uint8_t kMaxIntroAsks = 4;

    /// ENet intercept: a datagram before ENet parses it. 1: handled here (a pass ask, a CONNECT without a pass); 0: on to
    /// ENet. Called from inside Service
    int OnDatagram();
    /// Whether a pass is required now
    bool CookieRequired() const { return m_cookieRequired; }

    /// A HubPayload bigger than this gets a witness line in the log (at most once a minute) to guide maxPacketBytes
    static constexpr size_t kWitnessBytes = 1024u * 1024u;

private:
    struct Session
    {
        _ENetPeer* host = nullptr;
        /// Peer number inside the session -> its connection. The host is always 0 and is not in this map
        std::unordered_map<uint32_t, _ENetPeer*> guests;
        /// The smallest number not given yet (13.11: the next one is hubrules::NextPeerNumber from here)
        uint32_t nextId = 1;
        /// 13.11: numbers of guests who left -> until when their low byte stays taken (hubrules::kPeerByteHoldMs)
        std::unordered_map<uint32_t, uint64_t> held;
        /// The host's game protocol: a guest with another one is not let in
        uint32_t version = 0;
        /// Encryption: the session's tag in signatures (random, own for each session) and the host's X25519 key, whose
        /// signature the hub refreshes in every HubPeerUp
        std::array<uint8_t, 16> cryptoId{};
        std::array<uint8_t, 32> hostKey{};
        uint8_t hostFlags = 0;
        bool hostKeySet = false;
        /// When the host last got a resume pass (0: never — the session cannot come back after a restart)
        uint64_t passAtMs = 0;
    };

    struct Client
    {
        std::string code;
        uint32_t id = 0; ///< number inside the session; 0: the host
        bool isHost = false;
    };

    void HandlePacket(_ENetPeer* aPeer, const uint8_t* aData, size_t aSize, uint8_t aChannel);
    void DropClient(_ENetPeer* aPeer);
    /// The hub closes a connection itself (silent, guessing codes): its record goes at once — there will be no DISCONNECT
    /// event from enet_peer_disconnect_now, and the ENet slot goes to the next one
    void CloseClient(_ENetPeer* aPeer);
    void CloseIdle(uint64_t aNowMs);
    void Route(Session& aSession, uint32_t aFromId, uint32_t aToId, const std::vector<uint8_t>& aPayload,
               uint8_t aChannel, bool aReliable);
    void NotifyHost(Session& aSession, uint8_t aType, uint32_t aWho);
    /// Sends a client to another thread of the hub
    void Redirect(_ENetPeer* aPeer, size_t aShard);
    /// The host's resume pass for its session, sealed to its key (HubResumePass)
    void GivePass(_ENetPeer* aPeer, Session& aSession, const std::string& aCode);
    /// A host brings its session back with its pass (HubResumeSession)
    void Resume(_ENetPeer* aPeer, proto::Reader& aReader);
    /// The hub gives resume passes: on (Limits::resume) and a key to sign them with
    bool GivesPasses() const { return m_limits.resume && m_keys != nullptr; }
    std::string MakeCode();

    _ENetHost* m_host = nullptr;
    bool m_enetUp = false;
    Limits m_limits;
    Stats m_stats;
    uint32_t m_markSentPackets = 0;
    uint32_t m_markRecvPackets = 0;
    uint32_t m_markSentData = 0;
    uint32_t m_markRecvData = 0;
    uint64_t m_nextIdleSweepMs = 0;
    std::unordered_map<std::string, Session> m_sessions;
    std::unordered_map<_ENetPeer*, Client> m_clients;
    /// Connections without a session, since when. An entry lives from CONNECT until the client announces itself, a
    /// DISCONNECT or the hub closing it; guests of a session whose host left (DropClient) come here too, from the moment
    /// the host left. Every live connection of the hub is either here or in m_clients
    std::unordered_map<_ENetPeer*, uint64_t> m_idle;
    HubShards* m_shards = nullptr; ///< shared by the hub's threads; nullptr: a single hub
    size_t m_shard = 0;            ///< this thread's number
    /// This thread's share of a core, ‰, smoothed (hub_cpu_gate): Service measures it once a second
    uint16_t m_cpuPermille = 0;
    uint64_t m_cpuMarkMs = 0; ///< the last sample: wall time, ms, and the thread's CPU time, µs
    uint64_t m_cpuMarkUs = 0;
    void MeasureCpu(uint64_t aNowMs);
    /// A new session refused: every thread of the hub is at the CPU limit (hub_cpu_gate)
    void RefuseBusy(_ENetPeer* aPeer);
    HubAddressBook m_ownBook;      ///< per-address request counts of a single hub
    HubAddressBook* m_book = &m_ownBook;
    std::array<uint8_t, 16> m_cookieKey{}; ///< secret of the passes: own for each hub thread, new at every start
    bool m_cookieRequired = false;
    uint64_t m_nextBusyCountMs = 0;
    size_t m_busySlots = 0;      ///< taken ENet slots at the last count
    size_t m_passedNoCookie = 0; ///< CONNECTs without a pass handed to ENet since then
    void CountBusy(uint64_t aNowMs);
    /// 26.10 (hub_stop_drain): before Stop closes everything — a DISCONNECT after each connection's queue
    /// (enet_peer_disconnect_later), at most kStopDrainMs; new connections in that time are closed at once (a host
    /// bringing its session back must come to the next hub, not to this one going away)
    void DrainBeforeStop();
    /// Pre-ENet waiting limit (EnetGuard.hpp); nullptr: off (Limits::guard)
    std::unique_ptr<enetguard::Guard> m_guard;
    /// Bytes in ENet's queues per slot (SendTo adds, ENet subtracts when it releases a packet) and recipients above
    /// maxQueuedBytes, to be closed after handling the event
    std::vector<size_t> m_queued;
    std::vector<_ENetPeer*> m_overflow;
    void CloseOverflow();
    /// The hub's keys (SetKeys); nullptr: no signatures
    std::shared_ptr<const netcrypto::HubKeys> m_keys;
    /// Certificates and the hub list (SetIntro); HubIntroAsk questions per connection (removed with the connection)
    std::shared_ptr<HubIntroSource> m_intro;
    std::unordered_map<_ENetPeer*, uint8_t> m_introAsks;
    bool m_testIgnoreIntro = false;
    /// Location list (SetLocations)
    std::shared_ptr<HubLocationsSource> m_locations;
    bool m_testIgnoreLocations = false;
    /// Tells the host that a guest came, with a fresh signature on the host's key (the tail of HubPeerUp)
    void NotifyPeerUp(Session& aSession, uint32_t aWho);
    /// A connection outside a session (for EnetGuard): it has neither created nor joined a session, or its session is gone
    bool OutsideSession(const _ENetPeer* aPeer) const { return m_clients.find(const_cast<_ENetPeer*>(aPeer)) == m_clients.end(); }
};
} // namespace nc
