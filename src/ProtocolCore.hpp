#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// Wire format core shared by the mod and the hub: protocol version, packet magic, message types, hub constants and the
// bounds-checked Writer / Reader. Hand-written on purpose, without protobuf or code generation. Byte order is the
// machine's own: little-endian on every supported platform (x86-64, Apple Silicon); a big-endian port changes Writer and
// Reader only.
namespace nc::proto
{
/// Wire format version: bumped on any incompatible change. Host and guests must match — a mismatch is refused at the
/// handshake instead of surfacing later as broken state.
inline constexpr uint32_t kVersion = 191;

/// Magic number at the start of every packet: a cheap guard against stray traffic on the port.
inline constexpr uint32_t kMagic = 0x4E43'4F50; // 'NCOP'

enum class MsgType : uint8_t
{
    Invalid = 0,

    // Session messages between players. Through a hub they ride inside HubPayload: the hub never parses them.
    Hello = 1,
    Welcome = 2,
    Reject = 3,
    TimeSyncPing = 4,
    TimeSyncPong = 5,
    PlayerState = 6,
    PeerJoined = 7,
    PeerLeft = 8,
    Bye = 9,

    // Client <-> hub. Their format does not depend on kVersion; create and join carry the game protocol version, and the
    // hub admits only guests with the host's one.
    HubCreateSession = 10,  ///< client -> hub: open a session as its host
    HubSessionCreated = 11, ///< hub -> host: the session code
    HubJoinSession = 12,    ///< client -> hub: join the session with this code
    HubJoinAccepted = 13,   ///< hub -> guest: accepted, here is your peer number
    HubJoinRejected = 14,   ///< hub -> guest: refused, with the reason
    HubPeerUp = 15,         ///< hub -> the others: a peer joined
    HubPeerDown = 16,       ///< hub -> the others: a peer left
    HubPayload = 17,        ///< wrapper: [to / from peer][session bytes]

    // From here on: game layer messages, opaque to the hub (they ride inside HubPayload) — except the client <-> hub
    // group at 100 and CryptoHello (147).
    HitClaim = 18,
    HitResult = 19,
    NpcSpawn = 20,
    NpcSnapshot = 21,
    NpcDespawn = 22,
    NpcAnim = 23,
    NpcGrenade = 24,
    Game = 25,
    NpcHandoff = 26,
    NpcHandoffAck = 27,
    NpcClaim = 28,
    PlayerAnim = 29,
    PlayerAnimWant = 30,
    PlayerLook = 31,
    PlayerHit = 32,
    PlayerCustomization = 33,
    PlayerAnimSetup = 34,
    NpcAnimWant = 35,
    NpcDead = 36,
    NpcLookAt = 37,
    ItemTransferOffer = 38,
    ItemTransferDebit = 39,
    ItemTransferGrant = 40,
    ItemTransferAck = 41,
    LootState = 42,
    LootTake = 43,
    LootTakeResult = 44,
    SessionGather = 45,
    GameClock = 46,
    PlayerRevive = 47,
    DownedNotice = 48,
    /// 30.10 (revive_anim): a player helping a downed partner up plays the revive animation — start (placement), stop
    ReviveAnim = 156,
    /// 27.10 (seq_catchup_host): a guest's steps of quest graphs (a node that waited and
    /// then passed) — the host compares them with its own and finishes its body command a step behind all guests
    LedProgress = 49,
    QuestFactAck = 52, ///< the host got a guest's word about the facts of their action (deposit, document, device)
    QuestStepBook = 53, ///< the host's write numbers of writer nodes — a guest counts its own from them
    GuestSteps = 54,    ///< steps of open world activities a guest's graph made first — the host takes them
    QuestState = 57,    ///< a guest asks the host's live quest state, the host answers it (QuestRewriteRules.hpp)
    VehicleSpawn = 60,
    VehicleState = 61,
    VehicleDespawn = 62,
    VehicleSeat = 63,
    VehicleHandover = 64,
    VehicleHit = 65,
    QuestFacts = 70,
    QuestJournal = 71,
    QuestScene = 72,
    QuestWant = 73,
    DialogBallot = 74,
    DialogVote = 75,
    DialogTally = 76,
    QuestTeleport = 77,
    DialogLine = 78,
    DialogGather = 79,
    WorldWant = 80,
    WorldFile = 81,
    WorldStatus = 82,
    SceneGate = 83,
    QuestRide = 84,
    PlayerControl = 85,
    LiftSync = 86,
    StoryPull = 87,
    DoorSync = 88,
    SceneSkip = 89,
    PlayerWorkspot = 90,
    NpcTakeRequest = 91,
    PlayerCarry = 92,
    NpcWorkspot = 93,
    QuestClock = 94,
    WorldReload = 95,
    LiftRide = 97,
    NpcDefeat = 98,
    PlayerGrenade = 99,

    // Client <-> hub, continued: the address the hub sees (direct path), hub threads, hub identity. Older hubs
    // skip HubAddrQuery silently; the client then tries the direct path on the LAN only.
    HubAddrQuery = 100, ///< client -> hub: which address do you see me at (no fields)
    HubAddrSeen = 101,  ///< hub -> client: u32 IPv4 (as ENetAddress.host: octets in order) | u16 port
    /// The session lives on another thread of the hub: same address, the port from the message. The client connects
    /// there and repeats its request. Sent only to clients that declared kHubCapRedirect.
    HubRedirect = 102, ///< hub -> client: u16 port of the hub thread
    /// Before its request the client asks who this hub is. The hub answers with its certificate from the project root
    /// and/or its self-certificate (and its hub list if the client's one is older). Older hubs skip the question
    /// silently: the client learns it from the answer to the HubAddrQuery it sends next (the reliable channel is
    /// ordered).
    HubIntroAsk = 103, ///< client -> hub: u8 version | u64 number of the hub list the client has
    HubIntro = 104,    ///< hub -> client: u8 version | u8 flags | [certificates] | [hub list]
    /// A session outlives a hub restart: the host keeps a pass from the hub and takes the same code back with it
    /// (hubrules::ResumePass). Older hubs give no pass and skip the requests; older clients skip the pass.
    HubResumePass = 105,    ///< hub -> host: u8 version | 32 hub "box" key | u16 length + the pass sealed to the host's key
    HubResumeSession = 106, ///< host -> hub: u32 game protocol | u8 caps | u32 next peer number | host key + sealed pass
    HubResumeAsk = 107,     ///< host -> hub: a fresh pass for the running session (no fields); answer HubResumePass

    Kick = 110,
    PlayerPresence = 111,
    SessionRoster = 112,
    LobbyStart = 113,
    CreationHover = 114,
    SceneGateGo = 115,
    NpcOwnActors = 116,
    NpcAppearances = 117,
    SceneLineSkip = 118,
    SceneCutSkip = 119,
    WorldLoad = 120,
    SceneSkipHere = 121,
    VehicleSceneSeat = 123,
    PvpRules = 124,
    PvpHit = 125,
    PvpResult = 126,
    StoryTrace = 127,
    LedPause = 128,
    Destruction = 129,
    DeviceBlast = 130,
    PlayerBlast = 131,
    VehicleDamage = 132,
    PhoneSync = 133,
    RideAlong = 134,
    ChallengeRules = 135,
    NpcShot = 136,
    Braindance = 137,
    PlayerFx = 138,
    DeviceSync = 139,
    HackSync = 140,
    BuildStats = 141,
    SmsReply = 142,

    /// Not a session message: the first message on every transport link, sent in the clear — role, the per-session
    /// X25519 key and the hub's signature over it (or a refusal with the reason). The transport consumes it; after it
    /// everything on the link is sealed: u8 0xC5 | u64 counter | XChaCha20-Poly1305 | 16-byte tag.
    CryptoHello = 147,

    BraindanceGhost = 149,
    BraindanceClue = 150,
    SceneZonePassed = 151,
    StoryHold = 153,
    CrowdEachHold = 155,
    BraindanceSource = 157,
    HackIcon = 162,
    NpcTag = 220, ///< a player's scanner tag on an NPC set or cleared, or the current tags for a late joiner
    VehicleRemote = 165,
    AvSound = 167,
    CrowdWalkersCover = 168,
    BlackwallNpc = 171,
    PromoScene = 172,
    QuestItemDeposit = 175,
    PoliceFight = 176,
    VehicleAutopilotEnd = 177,
    CarsWord = 181,
    DocumentRead = 187,
    SenseWord = 190,
    SceneAway = 192,
    NpcAction = 197,
    NpcScenePose = 199,
    FrameWitness = 208,
    LedStoryWhy = 203,
    PhotoTogether = 209,
    CyberwareLook = 210,
    NpcCarHit = 213,
    TurretWord = 214,
    NpcTakeAsk = 215,   ///< take the owner's NPC into a sync animation, it is invulnerable here — only if it is there too
    TrackModeWord = 222, ///< the host's «track the same quests» for the session (a guest follows the host's or not)
    TrackedGoals = 223,  ///< a player's tracked objective (journal hash) and its places — partners show them
    PhotoPose = 226,   ///< a player's photo mode V — its pose, place and weapons; "off" when photo mode closes
    VehicleRole = 227, ///< the owner's quest car role (community key of the car and of the npcs in its seats), before its spawn
    ModsWord = 228,    ///< mods check at session entry — the mods fingerprint, the list by hashes, names of the difference
    VehicleRider = 230, ///< a player standing on a shared vehicle (its roof, its bed): their place in its axes
    VehicleColor = 236, ///< the owner's paint of a player vehicle (the game's visual customization template)
    RewardWord = 238,   ///< the host's quest reward for guests; an NPC owner's word "your player neutralized it" to the partner
    SpawnWord = 241,    ///< the open world population system, one envelope with a u16 sub-kind 257..263
    DeviceFacts = 246,  ///< a guest's quest facts set by a device's own operation on their custom action
    CarWord = 248,      ///< a player's quickhack of a partner's car (brakes, explode, speed up) — for its owner to run
    CarHit = 232,       ///< a player's hit on the mirror of a partner's car — for its owner's quest conditions «hit by the player»
    CarClaim = 233,     ///< the damage a player's hit did to the mirror of a partner's car — for its owner to take
    NpcHit = 235,       ///< a player's hit on a partner's NPC that did no damage here — for its owner's quest conditions «hit by the player»
    VoteModeWord = 249, ///< the host's choice voting mode for the session (majority / everyone)
    PerkTime = 251,     ///< a player's perk slows time (Deep Breath, High Noon) — its pace, 1 when it is over
    SyncSave = 254,     ///< the host saved (guests snapshot their character for that save) or loaded a save (its stamp)
    TimeSkipWord = 253, ///< the game fast-forwarded the host's player after its time skip — guests do the same to theirs
    OwnRise = 224,      ///< a player lies by the game's own death, but their own Second Heart gets them up
    ModWord = 200,      ///< data of a mod that uses the NightCoop SDK — channels, shared state, entity state, passports
    PoseWord = 201,     ///< a player's pose source (VR head and hands, aim along the barrel) for partners
    SpawnShare = 202,   ///< an entity a mod spawned and shared — its copy on partners, the owner leads it
    BossWord = 252,     ///< a boss owner's word to the others — its health multiplier by the players in the fight
    LiftAccess = 244,   ///< who a quest keycard lift lets in — a guest's own to the host, the session's to guests
    QuestItemWord = 245, ///< a player gained or handed over a quest item — the others' inventories follow (quest_items_shared)
    WorldItemWord = 143, ///< a player took a world item at the game's place of its object — the others take theirs there (loot_world_own)
    CorpseWord = 247,   ///< a corpse's owner to the others — the corpse (number, who, place) or «the corpse is gone»
    SpawnViewCamera = 204, ///< a player's camera (place, look on the ground, half view angle) — no game spawns where it sees
    PhoneHold = 205,    ///< a player's phone state — what holds its phone's interruption (combat, wanted 3+, …), its place in the interruption round
    DialogLocks = 216,  ///< a guest's choice windows — which options are locked for its V (a blue-line check failed there)
    RestrictSet = 211,  ///< a player's gameplay restrictions with the source of every stack, at world entry and on change (witness)
    WeatherWord = 206,  ///< the host's weather — its current state and request (source, blend, priority, random cycle), on change and to a guest entering its world
    RaceWord = 50,      ///< a race with every player in their own car — the host's dropped NPC teams and a guest's place at the start, the start, a guest's finish, the result and the winner
};

/// Recipient "everyone but the sender" in HubPayload.
inline constexpr uint32_t kHubBroadcast = 0xFFFF'FFFFu;

/// Tail of HubCreateSession / HubJoinSession: u8 — what the client understands in its talk with the hub. Older hubs
/// read their own fields only and skip the tail; older clients send no tail, so the hub reads 0.
inline constexpr uint8_t kHubCapRedirect = 1; ///< understands HubRedirect
inline constexpr uint8_t kHubCapPlaced = 2;   ///< already redirected to this port: serve it here

// ---------------------------------------------------------------- writing

class Writer
{
public:
    explicit Writer(MsgType aType)
    {
        PutU32(kMagic);
        PutU8(static_cast<uint8_t>(aType));
    }

    void PutU8(uint8_t aValue) { m_data.push_back(aValue); }

    void PutU16(uint16_t aValue) { PutRaw(&aValue, sizeof(aValue)); }
    void PutU32(uint32_t aValue) { PutRaw(&aValue, sizeof(aValue)); }
    void PutU64(uint64_t aValue) { PutRaw(&aValue, sizeof(aValue)); }
    void PutF32(float aValue) { PutRaw(&aValue, sizeof(aValue)); }

    /// Strings are capped at 64 KiB: plenty for names and refusal reasons.
    void PutString(const std::string& aValue)
    {
        const auto size = static_cast<uint16_t>(aValue.size() > 0xFFFF ? 0xFFFF : aValue.size());
        PutU16(size);
        PutRaw(aValue.data(), size);
    }

    void PutBytes(const std::vector<uint8_t>& aValue) { PutRaw(aValue.data(), aValue.size()); }

    const std::vector<uint8_t>& Data() const { return m_data; }

private:
    void PutRaw(const void* aSrc, size_t aSize)
    {
        const auto* bytes = static_cast<const uint8_t*>(aSrc);
        m_data.insert(m_data.end(), bytes, bytes + aSize);
    }

    std::vector<uint8_t> m_data;
};

// ---------------------------------------------------------------- reading

/// Reads without trusting the input: any read past the end puts the reader into the failed state and every later read
/// returns zeros, so the caller checks Ok() once at the end of parsing.
class Reader
{
public:
    Reader(const uint8_t* aData, size_t aSize)
        : m_data(aData)
        , m_size(aSize)
    {
    }

    bool Ok() const { return m_ok; }
    /// The parser found nonsense the bounds do not catch (unknown channel, impossible size): stop reading.
    void Fail() { m_ok = false; }
    size_t Remaining() const { return m_ok ? m_size - m_pos : 0; }

    /// Checks the magic and returns the message type.
    MsgType ReadHeader()
    {
        if (GetU32() != kMagic)
        {
            m_ok = false;
            return MsgType::Invalid;
        }
        const auto type = static_cast<MsgType>(GetU8());
        return m_ok ? type : MsgType::Invalid;
    }

    uint8_t GetU8()
    {
        uint8_t value = 0;
        GetRaw(&value, sizeof(value));
        return value;
    }

    uint16_t GetU16()
    {
        uint16_t value = 0;
        GetRaw(&value, sizeof(value));
        return value;
    }

    uint32_t GetU32()
    {
        uint32_t value = 0;
        GetRaw(&value, sizeof(value));
        return value;
    }

    uint64_t GetU64()
    {
        uint64_t value = 0;
        GetRaw(&value, sizeof(value));
        return value;
    }

    float GetF32()
    {
        float value = 0.0f;
        GetRaw(&value, sizeof(value));
        return value;
    }

    /// All unread bytes: for wrappers like HubPayload that carry foreign bytes without looking inside.
    std::vector<uint8_t> GetRest()
    {
        if (!m_ok)
            return {};
        std::vector<uint8_t> out(m_data + m_pos, m_data + m_size);
        m_pos = m_size;
        return out;
    }

    /// aSize bytes in one go (large chunks without per-byte reads).
    void GetBytes(uint8_t* aDst, size_t aSize) { GetRaw(aDst, aSize); }

    std::string GetString()
    {
        const auto size = GetU16();
        if (!m_ok || m_pos + size > m_size)
        {
            m_ok = false;
            return {};
        }
        std::string value(reinterpret_cast<const char*>(m_data + m_pos), size);
        m_pos += size;
        return value;
    }

private:
    void GetRaw(void* aDst, size_t aSize)
    {
        if (!m_ok || m_pos + aSize > m_size)
        {
            m_ok = false;
            std::memset(aDst, 0, aSize);
            return;
        }
        std::memcpy(aDst, m_data + m_pos, aSize);
        m_pos += aSize;
    }

    const uint8_t* m_data;
    size_t m_size;
    size_t m_pos = 0;
    bool m_ok = true;
};
} // namespace nc::proto
