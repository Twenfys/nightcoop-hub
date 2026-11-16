#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace nc::proto
{
class Reader;
class Writer;
} // namespace nc::proto

namespace nc::hubrules
{
struct ResumePass;
struct ResumeFacts;
} // namespace nc::hubrules

/// Transport encryption.
///
/// End to end: the host and each guest form a pair with their own keys; the hub relays envelopes (HubPayload: to/from in
/// the clear) without seeing their content. All cryptography is Monocypher 4.0.2 (vendor/monocypher, built into the DLL,
/// the hub and the tests): X25519 for the pair's shared secret, BLAKE2b to derive keys from the transcript,
/// XChaCha20-Poly1305 for every message of a link, EdDSA (BLAKE2b) for the hub's signature on peers' keys. No primitives
/// of our own here: only glue, formats and the replay window.
///
/// Where it encrypts: in the transport link, after compression (wire_zip in HybridTransport packs a batch, then the
/// batch is encrypted), before sending by any path (through the hub or direct). The session knows nothing: the
/// transport hands it plain bytes.
///
/// Link handshake (CryptoHello, MsgType 147): as soon as a link exists (guest — HubJoinAccepted, host — HubPeerUp,
/// direct connection — CONNECT), each side first sends its own: role, flags, the X25519 public key for this session and
/// the hub's signature on it (certificate). Having the other's, a side checks the signature by policy (Link::Policy),
/// derives the direction keys and from then on sends only sealed messages; until then it holds reliable data (Hold) and
/// drops unreliable data.
namespace nc::netcrypto
{
/// Switch net_crypto (on by default), effective from the next connection. Negotiated in the handshake: a link is
/// encrypted only if both sides can and want to; off at one side — no encryption (for diagnostics, switch it off on both
/// machines: with the project hub's key in the build, the side that has it on refuses such a partner through the
/// project's hub, see Link::Strict)
inline std::atomic<bool> g_enabled{true};

/// A sealed link message: u8 kSealMark | u64 counter | ciphertext | 16-byte tag. The first byte of a plain link message
/// is always the first byte of one of the magics ('NCOP' and the transport's 'NCSQ', 'NCPT', 'NCZQ': 0x50, 0x51, 0x54);
/// 0xC5 matches none, so the receiver tells sealed from plain by the first byte in any link state
inline constexpr uint8_t kSealMark = 0xC5;
inline constexpr size_t kTagSize = 16;
inline constexpr size_t kSealHeader = 1 + 8;
/// Cost per message: 25 bytes (mark 1 + counter 8 + tag 16)
inline constexpr size_t kOverhead = kSealHeader + kTagSize;
/// Replay window per direction, in messages: unreliable messages arrive out of order, and the two paths (hub and
/// direct) have different delays. 23.10: one counter serves both ENet channels, and after a lost packet ENet holds every later reliable message
/// until the resend while the unreliable ones go on and move the window. At 4096 a direct link of ~1350 messages/s
/// dropped such a held batch as "too old" after ~3 s, though ENet had acknowledged it — lost for good (votes, pause
/// releases, facts). 2^18 covers ENet's own patience with a link (enet_peer_timeout up to 60 s) at up to ~4000
/// messages/s; 32 KiB per direction
inline constexpr uint64_t kReplayWindow = uint64_t{1} << 18;
/// The window before 23.10 (net_replay_wide off)
inline constexpr uint64_t kReplayWindowNarrow = 4096;
/// Switch net_replay_wide (on by default; at once, on receiving only — the wire is the same): a late counter is taken
/// within kReplayWindow newer ones; off — within kReplayWindowNarrow, as before 23.10
inline std::atomic<bool> g_replayWide{true};
/// How long to wait for the partner's CryptoHello, ms: then without encryption (where authenticity cannot be checked
/// anyway) or a refusal
inline constexpr uint64_t kHelloWaitMs = 8000;
/// Lifetime of the hub's signature on a peer's key, s: a fresh signature comes with every join (to the host, with every
/// HubPeerUp)
inline constexpr uint64_t kCertLifetimeSec = 3600;
/// The sides see the hub's clock apart only by the messages' travel time: a margin
inline constexpr uint64_t kCertSkewSec = 300;

/// Random bytes from the system generator: Windows — BCryptGenRandom (BCRYPT_USE_SYSTEM_PREFERRED_RNG; under Wine it
/// runs RtlGenRandom from /dev/urandom), Linux — getrandom, macOS — getentropy. False: no generator
bool Random(uint8_t* aOut, size_t aSize);

/// Hex text (log, the hub's key file); FromHex: exactly aSize bytes, otherwise false
std::string ToHex(const uint8_t* aData, size_t aSize);
bool FromHex(std::string_view aText, uint8_t* aOut, size_t aSize);

/// An all-zero key means "not set" (a placeholder in HubRules.hpp)
bool IsZero(const uint8_t* aData, size_t aSize);

/// Link salt in CryptoHello, bytes: own for each link of each side (Link::Begin, system generator)
inline constexpr size_t kSaltSize = 16;

/// Direction keys of a link from the X25519 shared secret: BLAKE2b-512 keyed with aShared over "NightCoop transport 1" |
/// host key | guest key | host salt | guest salt; the first 32 bytes are host -> guest, the second guest -> host. A pure
/// function (vectors are in the tests).
/// Why the salt: the host uses one X25519 pair for all its links, and a guest that substitutes someone else's public key
/// (it needs no secret for that, the hub signs any key it gets) would, without a salt, get from the host the same link
/// keys as the real guest — and the host would encrypt both links with the same nonces from counter 1
/// (XChaCha20-Poly1305 nonce reuse). A fresh host salt per link makes the link keys its own whatever the partner's key
void DeriveLinkKeys(const uint8_t aShared[32], const uint8_t aHostKey[32], const uint8_t aGuestKey[32],
                    const uint8_t aHostSalt[kSaltSize], const uint8_t aGuestSalt[kSaltSize], uint8_t aHostToGuest[32],
                    uint8_t aGuestToHost[32]);

enum class Role : uint8_t
{
    None = 0,
    Host = 1,
    Guest = 2,
};
const char* RoleName(Role aRole);

/// Public keys of the project's hub that the build trusts (HubRules.hpp), and its name: signatures are checked only with
/// it. This is the project hub's "old key", trusted directly (the Pinned policy below) until a root certificate replaces
/// it; other hubs go by certificate (HubCert) or by fingerprint
struct Trust
{
    std::array<uint8_t, 32> sign{}; ///< EdDSA (BLAKE2b): signature on peers' keys
    std::array<uint8_t, 32> box{};  ///< X25519: the session code in the request and in the hub's answer travels sealed
    bool signSet = false;
    bool boxSet = false;
    std::string hubName; ///< the project's hub: the strict policy applies to it only (case-insensitive)
};
Trust HubTrust();
/// For tests: own keys and hub name instead of the built-in ones (nullptr: the built-in ones again)
void SetTrustForTests(const uint8_t* aSign, const uint8_t* aBox, const char* aHubName);
/// This address is the project's hub (by name, case-insensitive; "#fingerprint" and the port do not count)
bool IsProjectHub(const std::string& aHost);

class HubKeys;

// ---------------------------------------------------------------- project root and hub certificates
//
// The build carries the project's public root key (HubRules.hpp kRootKey). Every hub has its own signing and "box" keys
// (HubKeys) and a certificate from the root (HubCert, kind Root): the hub's keys, names, region, validity and the root's
// signature. The hub shows it to the client before the request (HubIntro 104 on HubIntroAsk 103); the client checks the
// chain root -> hub -> peers' signatures (Cert) and seals the session code with the "box" of the hub it talks to. An own
// server without the project's root has a self-certificate (kind Self: the hub's keys signed by itself) and the
// fingerprint of its signing key, which the owner gives to players ("address#fingerprint"). The hub list (HubList:
// letters, regions, revoked keys) is signed by the same root and comes from any hub: new servers without a new build.

/// Switch hub_chain (on by default): the hub's certificate before the request, the project's root and fingerprints. Off:
/// strictly only the project's hub by its old key, other hubs unchecked. Effective from the next hub connection
inline std::atomic<bool> g_hubChain{true};

/// Hub certificate: u8 version | u8 kind | u8 flags | u8 names | u64 serial | u64 from | u64 until (seconds since 1970) |
/// 32 hub signing key | 32 hub "box" | 32 issuer | u8 length + region | names (u8 length + name)… | 64 EdDSA signature
/// over "NightCoop hub identity 1" and everything before it
struct HubCert
{
    static constexpr uint8_t kVersion = 1;
    static constexpr size_t kMaxNames = 4;
    static constexpr size_t kMaxName = 63;
    static constexpr size_t kMaxRegion = 15;
    static constexpr size_t kFixed = 4 + 3 * 8 + 3 * 32 + 1;
    static constexpr size_t kMaxSize = kFixed + kMaxRegion + kMaxNames * (1 + kMaxName) + 64;
    enum class Kind : uint8_t
    {
        Root = 1, ///< signed by the project's root
        Self = 2, ///< signed by the hub's own key (an own server; trusted by fingerprint)
    };

    Kind kind = Kind::Self;
    uint8_t flags = 0;
    uint64_t serial = 0;
    uint64_t notBefore = 0;
    uint64_t notAfter = 0;
    std::array<uint8_t, 32> sign{};   ///< the hub's signing key: the hub signs peers' keys with it (Cert)
    std::array<uint8_t, 32> box{};    ///< the hub's "box": the session code is sealed to it
    std::array<uint8_t, 32> issuer{}; ///< issuer: the root (Root) or the hub itself (Self — equals sign)
    std::string region;               ///< "eu", "na-east"… — for the log and the menu
    std::vector<std::string> names;   ///< hub names (lower case): with a Root certificate the client checks the name it went to
    std::array<uint8_t, 64> signature{};

    std::vector<uint8_t> Body() const;
    std::vector<uint8_t> Write() const;
    /// Exactly one certificate in aSize bytes; false: cannot parse (aWhy says why, without the bytes)
    static bool Read(const uint8_t* aData, size_t aSize, HubCert& aOut, std::string* aWhy = nullptr);
    /// The signature is valid for aKey (the root's for Root, the hub's own for Self)
    bool VerifiedBy(const uint8_t aKey[32]) const;
    /// The name is in the certificate (case-insensitive, a trailing dot ignored)
    bool Names(const std::string& aHost) const;
    /// "root certificate #N for e.hub.nightcoop.net (region eu, valid until 2027-10-22)" — for the log
    std::string Describe() const;
};

/// A hub in the list: letter (the first character of a 7-character code), flags, region, a human label. The name comes
/// from the letter (hubrules::LetterHubName), the port is hubrules::kHubPort
struct HubListEntry
{
    static constexpr uint8_t kOpen = 1u << 0; ///< new sessions go here (cleared: the hub keeps its current sessions and goes away)
    static constexpr size_t kMaxLabel = 63;
    char letter = 0;
    uint8_t flags = 0;
    std::string region;
    std::string label;
};

/// The project's hub list: u8 version | u8 flags | u16 hubs | u64 serial | u64 issued | 32 issuer | u16 revoked | hubs
/// (u8 letter | u8 flags | u8 length + region | u8 length + label)… | revoked hub signing keys (32)… | 64 EdDSA root
/// signature over "NightCoop hub list 1" and everything before it. Newer means a bigger serial; the client never takes
/// one older than it holds
struct HubList
{
    static constexpr uint8_t kVersion = 1;
    static constexpr size_t kMaxEntries = 64;
    static constexpr size_t kMaxRevoked = 256;
    uint64_t serial = 0;
    uint64_t issued = 0;
    std::array<uint8_t, 32> issuer{};
    std::vector<HubListEntry> entries;
    std::vector<std::array<uint8_t, 32>> revoked;
    std::array<uint8_t, 64> signature{};

    std::vector<uint8_t> Body() const;
    std::vector<uint8_t> Write() const;
    static bool Read(const uint8_t* aData, size_t aSize, HubList& aOut, std::string* aWhy = nullptr);
    bool VerifiedBy(const uint8_t aKey[32]) const;
    /// The hub's signing key is revoked (leaked, hub removed): its certificate and old key are no longer trusted
    bool Revoked(const std::array<uint8_t, 32>& aSign) const;
    const HubListEntry* Find(char aLetter) const;
};

/// The project's root key (on the owner's machine: nightcoop_hub --gen-root-key / --issue-cert / --sign-list; never on
/// servers). The file is text; with a passphrase the key seed is sealed (Argon2id 64 MiB -> XChaCha20-Poly1305), without
/// one it is like a hub key file
class RootKeys
{
public:
    RootKeys() = default;
    ~RootKeys();
    RootKeys(const RootKeys&) = delete;
    RootKeys& operator=(const RootKeys&) = delete;

    bool Generate();
    /// File text (a secret!). Empty aPassphrase: the seed in the clear
    std::string Save(const std::string& aPassphrase) const;
    /// The seed in the file is sealed with a passphrase
    static bool Sealed(const std::string& aText);
    bool Load(const std::string& aText, const std::string& aPassphrase, std::string& aError);
    const std::array<uint8_t, 32>& Public() const { return m_public; }
    /// Sign: the issuer is this root (the certificate's Root kind is set here)
    void SignCert(HubCert& aCert) const;
    void SignList(HubList& aList) const;

private:
    void Derive();
    std::array<uint8_t, 32> m_seed{};
    std::array<uint8_t, 64> m_secret{};
    std::array<uint8_t, 32> m_public{};
    bool m_ready = false;
};

/// Fingerprint of a hub's signing key: the first 10 bytes of BLAKE2b over "NightCoop hub fingerprint 1" and the key, as
/// 16 characters (hubrules::FingerprintText). The owner of a hub gives it to players with the address
std::string Fingerprint(const uint8_t aSign[32]);
/// A fingerprint as typed (hubrules::NormalizeFingerprint) belongs to this key
bool FingerprintMatches(const std::string& aGiven, const uint8_t aSign[32]);

/// Roots the build trusts (HubRules.hpp kRootKey and kRootKeyBackup, if not zero)
std::vector<std::array<uint8_t, 32>> TrustedRoots();
/// For tests: own roots instead of the built-in ones (nullptr: the built-in ones again)
void SetRootsForTests(const std::vector<std::array<uint8_t, 32>>* aRoots);
/// The root is among the trusted ones
bool IsTrustedRoot(const std::array<uint8_t, 32>& aKey);

/// The hub's self-certificate (made by the hub at start): its keys signed by itself
HubCert MakeSelfCert(const HubKeys& aKeys, const std::vector<std::string>& aNames, const std::string& aRegion,
                     uint64_t aNowSec);

// ---- the hub list at the client: the last valid one (a newer serial), in memory and in hubs.ncl next to the dll
/// The client's file directory (set when the plugin loads): hubs.ncl (the hub list) and hub.txt (an own server instead
/// of the project's hub). Reads hubs.ncl at once
void SetDataDirectory(const std::string& aDir);
std::string DataDirectory();
/// Offer a list (from HubIntro): a valid signature by a trusted root and a serial newer than the held one — take it (and
/// write the file). False: not taken (aWhy says why; "not newer" is false too, without an error)
bool OfferHubList(const uint8_t* aData, size_t aSize, std::string& aWhy);
std::shared_ptr<const HubList> CachedHubList();
uint64_t CachedHubListSerial();
/// For tests: forget the list (the file stays)
void ForgetHubListForTests();
/// The initial list from the build (hubrules::kSeedHubList): take it if newer than the held one (SetDataDirectory calls
/// it). False: none, not newer, or cannot be checked (a log line)
bool TakeSeedHubList();
/// For tests: own initial list instead of the built-in one (nullptr: the built-in one again)
void SetSeedHubListForTests(const std::string* aHex);

/// Switch hub_file (on by default): hub.txt next to the dll holds "address[:port][#fingerprint]" of an own server; "Host
/// online" and "Join by code" go there instead of the project's hub. Off, or no file: the project's hubs
inline std::atomic<bool> g_hubFile{true};
/// The own server from hub.txt (read on every call: an edit takes effect from the next session). False: no file, or empty
bool HubOverride(std::string& aHub, uint16_t& aPort);

// ---- trust policy for a hub, and the verdict on it
enum class HubPolicy : uint8_t
{
    Open,        ///< another server without a fingerprint (IP, own name): encrypted without authentication
    Pinned,      ///< the project's hub kProjectHubName: a root certificate, otherwise the build's old key
    Chain,       ///< a name in the project's domain: only a root certificate for that name
    Fingerprint, ///< an address with "#fingerprint": only the hub with that key (self-certificate or root certificate)
};
const char* PolicyName(HubPolicy aPolicy);
/// Policy by the hub's address ("name[:port][#fingerprint]"); aChain is the hub_chain switch
HubPolicy PolicyFor(const std::string& aHub, bool aChain);

/// HubIntro from the hub: root certificate, self-certificate and hub list (each if present)
struct HubIntro
{
    bool hasRoot = false;
    HubCert root;
    bool hasSelf = false;
    HubCert self;
    std::vector<uint8_t> list;
};
inline constexpr uint8_t kIntroVersion = 1;
inline constexpr uint8_t kIntroRoot = 1u << 0;
inline constexpr uint8_t kIntroSelf = 1u << 1;
inline constexpr uint8_t kIntroList = 1u << 2;
/// The client's question (HubIntroAsk 103): the serial of the hub list it has
std::vector<uint8_t> MakeHubIntroAsk(uint64_t aKnownListSerial);
/// The hub's answer (HubIntro 104), into aOut after the header: u8 version | u8 flags | [u16 length + root certificate] |
/// [u16 length + self-certificate] | [u16 length + list]. An empty vector: absent
void PutHubIntro(proto::Writer& aOut, const std::vector<uint8_t>& aRoot, const std::vector<uint8_t>& aSelf,
                 const std::vector<uint8_t>& aList);
/// Parses HubIntro after the header; a broken certificate counts as absent (false: the message cannot be parsed)
bool ReadHubIntro(proto::Reader& aIn, HubIntro& aOut);

/// The verdict on a hub: whose it is, and which keys check peers' signatures and seal the code
enum class HubVerdict : uint8_t
{
    Waiting,   ///< waiting for HubIntro (or a sign that the hub does not know it)
    Vouched,   ///< the hub's keys are checked: peers' signatures are required (strict), the code is sealed
    Unvouched, ///< another server without a fingerprint: encrypted without authentication
    Refused,   ///< not the right hub, or it did not prove who it is: no session through it
};
const char* VerdictName(HubVerdict aVerdict);
struct HubIdentity
{
    HubVerdict verdict = HubVerdict::Waiting;
    std::array<uint8_t, 32> sign{};
    std::array<uint8_t, 32> box{};
    bool hasSign = false;
    bool hasBox = false;
    std::string how;    ///< what checked it: "the project's root certificate …", "the build's key of hub.nightcoop.net", …
    std::string reason; ///< why, for Refused
};
/// Decide by the policy, the certificates from HubIntro (nullptr: the hub sent no HubIntro — an old hub) and this
/// machine's clock (seconds since 1970; a root certificate's validity with the kCertClockSlackSec margin). A pure function
/// over the trusted roots, the old key (HubTrust) and the revoked keys of the held list
HubIdentity JudgeHub(HubPolicy aPolicy, const std::string& aHub, const HubIntro* aIntro, uint64_t aNowSec);
/// The player's clock and the certificate's issue time may differ: a margin both ways, s
inline constexpr uint64_t kCertClockSlackSec = 2 * 86400;

/// Whose key signed the location list that hub aHub ("name[:port][#fingerprint]") sent, by the same policy as a session
/// through it. aRoot: the root certificate from the answer (nullptr: none), aKey: the signing key from the answer
/// (nullptr: none). Vouched means id.sign is the key that checks the list (VerifyLocations): the project's hub — a root
/// certificate for its name or the build's old key; a domain hub — a root certificate; a fingerprint — the key with that
/// fingerprint (owning it is proven by the list's signature) or a root certificate for a key with it; Open (IP, own name
/// without a fingerprint) — Unvouched: such a list is not trusted
HubIdentity JudgeLocationsSigner(HubPolicy aPolicy, const std::string& aHub, const HubCert* aRoot,
                                 const std::array<uint8_t, 32>* aKey, uint64_t aNowSec);
/// The signature of the location list by aKey is valid
bool VerifyLocations(const uint8_t aKey[32], const std::vector<uint8_t>& aBody, const std::array<uint8_t, 64>& aSignature);
/// This machine's clock, seconds since 1970 (certificate validity)
uint64_t UnixNowSec();

/// The hub's signature on a peer's key, 136 bytes: u8 version | u8 role | u8 flags (bit 0: the peer encrypts) | u8 0 |
/// u32 number at the hub | 16 the hub's session tag | 32 X25519 key | u64 issued (s, hub clock) | u64 valid until | 64
/// EdDSA signature over kCertDomain and the first 72 bytes
struct Cert
{
    static constexpr size_t kBodySize = 72;
    static constexpr size_t kSize = kBodySize + 64;
    static constexpr uint8_t kVersion = 1;
    static constexpr uint8_t kFlagEncrypts = 1u << 0;

    uint8_t version = kVersion;
    Role role = Role::None;
    uint8_t flags = 0;
    uint32_t hubPeer = 0;
    std::array<uint8_t, 16> session{};
    std::array<uint8_t, 32> key{};
    uint64_t issued = 0;
    uint64_t expires = 0;
    std::array<uint8_t, 64> signature{};

    void Body(uint8_t aOut[kBodySize]) const;
    void Write(std::vector<uint8_t>& aOut) const;
    static bool Read(const uint8_t* aData, size_t aSize, Cert& aOut);
    bool Verify(const uint8_t aHubSign[32]) const;
};

/// The hub's keys (hub side): signing and the "box" for the session code. The key file is text (Save/Load); the secret
/// stays on the server
class HubKeys
{
public:
    HubKeys() = default;
    ~HubKeys();
    HubKeys(const HubKeys&) = delete;
    HubKeys& operator=(const HubKeys&) = delete;

    /// New keys from the system generator
    bool Generate();
    /// Key file text (a secret!) and its parsing. aError says why it is unfit (without the secret in the text)
    std::string Save() const;
    bool Load(const std::string& aText, std::string& aError);

    const std::array<uint8_t, 32>& SignPublic() const { return m_signPublic; }
    const std::array<uint8_t, 32>& BoxPublic() const { return m_boxPublic; }

    /// Sign a peer's key (aNowSec: the hub's clock, s)
    Cert Sign(Role aRole, uint32_t aHubPeer, const std::array<uint8_t, 16>& aSession, const uint8_t aKey[32],
              uint8_t aFlags, uint64_t aNowSec) const;
    /// Self-certificate: own keys into aCert (kind Self, issuer: the hub itself) and the signature with own key
    void SignIdentity(HubCert& aCert) const;
    /// Signature of a location list body (hubrules::WriteLocationBody) with own key, over "NightCoop hub locations 1" and the
    /// body
    std::array<uint8_t, 64> SignLocations(const std::vector<uint8_t>& aBody) const;
    /// The session code from a client's request (aClientKey: its X25519) and the code in the answer to it, sealed
    /// (SealedCode)
    bool OpenCode(const uint8_t aClientKey[32], const std::vector<uint8_t>& aSealed, std::string& aCode) const;
    std::vector<uint8_t> SealCode(const uint8_t aClientKey[32], const std::string& aCode) const;
    /// A session's resume pass (HubRules.hpp): the signature with own key over "NightCoop resume pass 1" and its body
    void SignResumePass(hubrules::ResumePass& aPass) const;
    /// Bytes for a client and from it under the "box" key shared with its X25519 key (aDir: kBoxPassToHost,
    /// kBoxResumeToHub), up to kMaxBoxBytes. A request that opens proves the client holds its key's secret
    std::vector<uint8_t> SealForClient(const uint8_t aClientKey[32], uint8_t aDir, const std::vector<uint8_t>& aPlain) const;
    bool OpenFromClient(const uint8_t aClientKey[32], uint8_t aDir, const std::vector<uint8_t>& aSealed,
                        std::vector<uint8_t>& aPlain) const;

private:
    void Derive();
    std::array<uint8_t, 32> m_signSeed{};
    std::array<uint8_t, 64> m_signSecret{};
    std::array<uint8_t, 32> m_signPublic{};
    std::array<uint8_t, 32> m_boxSecret{};
    std::array<uint8_t, 32> m_boxPublic{};
    bool m_ready = false;
};

/// The own side of the transport for a session: an X25519 pair (new on every Listen/Connect), own signature from the
/// hub, the hub.
class Local
{
public:
    Local() = default;
    ~Local();
    Local(const Local&) = delete;
    Local& operator=(const Local&) = delete;

    /// A new transport session: keys anew (if encryption is on and there is a generator), the signature and the hub
    /// forgotten. aHub: the hub's address (empty: a direct connection without a hub), with "#fingerprint" if given
    void Reset(const std::string& aHub);
    /// We offer encryption (the switch at Reset and a generator)
    bool On() const { return m_on; }
    const std::array<uint8_t, 32>& Public() const { return m_public; }
    bool ViaHub() const { return m_viaHub; }
    /// The hub's keys are checked (the project hub's old key, a root certificate or a fingerprint) and encryption is on: no
    /// hub signature or no partner encryption means a refusal
    bool Strict() const { return m_strict; }
    /// The session code to and from the hub travels sealed (this hub's "box" is known and checked)
    bool SealCodes() const { return m_seal; }

    // ---- who this hub is (HubIntro before the request)
    HubPolicy Policy() const { return m_policy; }
    /// Ask the hub who it is (HubIntroAsk) before the request: encryption on, hub_chain, a policy other than Open (for the
    /// project's hub, when the build has a root: without a root the certificate cannot be checked, and the old key is there
    /// anyway)
    bool NeedsIntro() const { return m_needsIntro; }
    /// The verdict on the hub exists already (or is not needed)
    bool IdentityKnown() const { return m_identity.verdict != HubVerdict::Waiting; }
    const HubIdentity& Identity() const { return m_identity; }
    /// Decide: aIntro is the hub's HubIntro, nullptr — the hub did not send one (an old hub: the answer to the request or
    /// HubAddrSeen came first). aNowSec: this machine's clock (seconds since 1970; 0: now). True: decided now (a second call
    /// returns false and the earlier verdict stays)
    bool Decide(const HubIntro* aIntro, uint64_t aNowSec = 0);
    /// Host before the verdict: ask the hub to send the code sealed (the policy requires a checked hub, so its "box" will be
    /// known by the time of the answer)
    bool AsksSealedReply() const;
    /// The hub's signing key that checks peers' signatures (Strict)
    const std::array<uint8_t, 32>& HubSign() const { return m_identity.sign; }
    /// The hub's name (without the port and the fingerprint, lower case), for the log
    const std::string& HubHost() const { return m_hubHost; }

    /// Own signature from the hub (host: on creating the session and fresh with every HubPeerUp; guest: on joining)
    void SetCert(const Cert& aCert, uint64_t aNowMs);
    bool HasCert() const { return m_hasCert; }
    const Cert& GetCert() const { return m_cert; }
    /// The hub's clock now, s, from our last signature (0: no signature)
    uint64_t HubNowSec(uint64_t aNowMs) const;
    /// Guest: own number at the hub (HubJoinAccepted), for the key transcript
    void SetHubId(uint32_t aId) { m_hubId = aId; }
    uint32_t HubId() const { return m_hubId; }

    /// X25519 shared secret with another key; false: an unfit key (a small-order point)
    bool Shared(const uint8_t aTheirs[32], uint8_t aOut[32]) const;

    /// The session code to the hub, sealed to its "box"; the hub's answer, opened
    std::vector<uint8_t> SealCodeForHub(const std::string& aCode) const;
    bool OpenCodeFromHub(const std::vector<uint8_t>& aSealed, std::string& aCode) const;
    /// Bytes to and from a hub whose "box" is aHubBox (the resume pass comes with it), as HubKeys::SealForClient. False /
    /// empty: no own key (encryption off)
    std::vector<uint8_t> SealToHubBox(const uint8_t aHubBox[32], uint8_t aDir, const std::vector<uint8_t>& aPlain) const;
    bool OpenFromHubBox(const uint8_t aHubBox[32], uint8_t aDir, const std::vector<uint8_t>& aSealed,
                        std::vector<uint8_t>& aPlain) const;

private:
    /// The verdict is in: strictness and the "box" follow it
    void Apply();
    std::array<uint8_t, 32> m_secret{};
    std::array<uint8_t, 32> m_public{};
    std::array<uint8_t, 32> m_hubBox{};
    bool m_on = false;
    bool m_viaHub = false;
    bool m_projectHub = false;
    bool m_strict = false;
    bool m_seal = false;
    HubPolicy m_policy = HubPolicy::Open;
    bool m_needsIntro = false;
    HubIdentity m_identity;
    std::string m_hub;     ///< address as given (with the fingerprint)
    std::string m_hubHost; ///< the hub's name in lower case
    Cert m_cert;
    bool m_hasCert = false;
    uint64_t m_certAtMs = 0;
    uint32_t m_hubId = 0;
};

/// Replay window of one direction: a counter is accepted if newer than all, or within the window and not seen yet
class ReplayWindow
{
public:
    bool Fresh(uint64_t aCounter) const;
    void Mark(uint64_t aCounter);
    uint64_t Top() const { return m_top; }
    /// Refused by Fresh as older than the window, not as a repeat
    bool TooOld(uint64_t aCounter) const;
    /// How many newer counters a late one may be behind now (net_replay_wide)
    static uint64_t Span();
    /// Empty again (the bits keep their memory)
    void Reset();

private:
    uint64_t m_top = 0; ///< the newest accepted (0: none yet)
    /// kReplayWindow bits (32 KiB) on the heap from the first accepted counter: a link stays small — the tests keep
    /// many on the stack, the transport moves them through it
    std::vector<uint64_t> m_bits;
};

// ---------------------------------------------------------------- tails of the talk with the hub

/// Tail of HubCreateSession / HubJoinSession after caps: u8 kExtCrypto | u8 flags | 32 X25519 key | [sealed code, if bit
/// kExtSealed: for a join, the code inside; for a creation, "answer with the code sealed"]. Older hubs do not read the
/// tail
inline constexpr uint8_t kExtCrypto = 0xC1;
inline constexpr uint8_t kExtEncrypts = 1u << 0; ///< request: the peer encrypts its links (net_crypto)
inline constexpr uint8_t kExtSealed = 1u << 1;   ///< request: the code is sealed / answer: the code is sealed
inline constexpr uint8_t kExtCert = 1u << 2;     ///< answer: the hub's signature on the peer's key
/// Answer to a join (HubJoinAccepted): the session's host holds a resume pass — after a hub restart the session comes back
/// with the same code, so a guest that lost the hub waits for it (HubRules.hpp GuestWaitsForHub). Older clients ignore it
inline constexpr uint8_t kExtResume = 1u << 3;

/// Directions of bytes under the "box" key besides the session code (1 and 2): the extra data keeps them apart, so one
/// cannot pass for another
inline constexpr uint8_t kBoxPassToHost = 3;  ///< the resume pass, hub -> host
inline constexpr uint8_t kBoxResumeToHub = 4; ///< the resume request, host -> hub
inline constexpr size_t kMaxBoxBytes = 1024;

/// The resume pass carries a valid signature by the hub signing key aSign
bool VerifyResumePass(const hubrules::ResumePass& aPass, const uint8_t aSign[32]);
/// The hub's look at a resume request (HubResumeSession): it opens under the key it names (aClientKey, aSealed), the pass
/// inside (into aPass), the pass's signature by this hub, the key and the game protocol (aProtocol) it is bound to, its
/// times against the hub's clock aNowSec. Fills aFacts for hubrules::JudgeResume; "live" and "full" are the hub's to add
void LookAtResume(const HubKeys& aKeys, const uint8_t aClientKey[32], const std::vector<uint8_t>& aSealed,
                  uint32_t aProtocol, uint64_t aNowSec, hubrules::ResumeFacts& aFacts, hubrules::ResumePass& aPass);

struct ClientExt
{
    bool present = false;
    uint8_t flags = 0;
    std::array<uint8_t, 32> key{};
    std::vector<uint8_t> sealed;
};
void PutClientExt(proto::Writer& aOut, const Local& aLocal, const std::vector<uint8_t>* aSealed);
bool ReadClientExt(proto::Reader& aIn, ClientExt& aOut);

/// Tail of the hub's answer (HubSessionCreated, HubJoinAccepted, HubPeerUp): u8 kExtCrypto | u8 flags | [Cert, bit
/// kExtCert] | [sealed code, bit kExtSealed]. Older clients do not read the tail
struct HubExt
{
    bool present = false;
    uint8_t flags = 0;
    bool hasCert = false;
    Cert cert;
    std::vector<uint8_t> sealed;
};
/// aFlags: more answer flags (kExtResume); the tail is written when there is a certificate or a sealed code
void PutHubExt(proto::Writer& aOut, const Cert* aCert, const std::vector<uint8_t>* aSealed, uint8_t aFlags = 0);
bool ReadHubExt(proto::Reader& aIn, HubExt& aOut);

// ---------------------------------------------------------------- link

/// CryptoHello (MsgType 147, session message format): u8 version | u8 flags | u8 role | 32 X25519 key | [Cert, bit
/// kHelloCert] | [16 link salt, bit kHelloEncrypt] | [string: the reason, bit kHelloRefuse]
inline constexpr uint8_t kHelloVersion = 1;
inline constexpr uint8_t kHelloEncrypt = 1u << 0; ///< the sender encrypts the link (key in the message)
inline constexpr uint8_t kHelloCert = 1u << 1;    ///< the hub's signature on the key
inline constexpr uint8_t kHelloRefuse = 1u << 2;  ///< the sender refuses the link; the reason follows

/// This message is a CryptoHello (by its header)
bool IsHello(const uint8_t* aData, size_t aSize);

enum class State : uint8_t
{
    Idle,    ///< the link has not started (Begin not called)
    Waiting, ///< own CryptoHello sent, waiting for the partner's; reliable data is held
    Ready,   ///< keys ready: only sealed messages out and in (plus repeated CryptoHello)
    Plain,   ///< no encryption (off at one side, an old partner; only where authenticity cannot be checked anyway)
    Refused, ///< refused (a wrong signature, a partner without encryption under a strict policy): nothing either way
};
const char* StateName(State aState);

/// What a link needs to know about the pair
struct Setup
{
    Role mine = Role::None;
    bool viaHub = false;      ///< a link through the hub: the hub's signature on keys is possible
    uint32_t guestHubId = 0;  ///< this pair's guest number at the hub (the host takes it from the envelope); 0 without a hub
    uint32_t peer = 0;        ///< peer number, for the log
};

class Link
{
public:
    Link() = default;
    ~Link();
    Link(Link&& aOther) noexcept;
    Link& operator=(Link&& aOther) noexcept;
    Link(const Link&) = delete;
    Link& operator=(const Link&) = delete;

    /// Start the link: returns own CryptoHello, to be sent first, reliably and in the clear. Off at our side: the link is
    /// Plain at once (the Hello with the "not encrypting" flag goes anyway, so the partner learns it at once, not by timeout)
    std::vector<uint8_t> Begin(const Local& aLocal, const Setup& aSetup, uint64_t aNowMs);
    State GetState() const { return m_state; }
    bool Started() const { return m_state != State::Idle; }
    /// The handshake is decided (Ready, Plain or Refused): the transport sends what was held and handles a refusal. One-shot
    bool TakeResolved();
    /// Reliable data going out before the handshake ends is held (false: unreliable, or the queue is full — dropped)
    bool Holding() const { return m_state == State::Idle || m_state == State::Waiting; }
    bool Hold(const std::vector<uint8_t>& aData, bool aReliable);
    struct Held
    {
        std::vector<uint8_t> data;
        bool reliable = true;
    };
    std::vector<Held> TakeHeld();

    /// Outgoing. Plain: send aData as is; Sealed: send aOut; Hold: hold it (Hold); Drop: do not send
    enum class Out : uint8_t
    {
        Plain,
        Sealed,
        Hold,
        Drop,
    };
    Out Outgoing(const uint8_t* aData, size_t aSize, std::vector<uint8_t>& aOut);
    /// Seal as is (Ready); false: no keys, or the counter is exhausted
    bool Seal(const uint8_t* aData, size_t aSize, std::vector<uint8_t>& aOut);

    /// Incoming. DeliverAsIs: deliver aData as is (plain in Plain state, or the first plain message from a partner without
    /// encryption); DeliverOpened: deliver aOut (opened); Handshake: it was a CryptoHello (handled; see TakeResolved); Drop
    enum class In : uint8_t
    {
        DeliverAsIs,
        DeliverOpened,
        Handshake,
        Drop,
    };
    In Incoming(const Local& aLocal, const uint8_t* aData, size_t aSize, std::vector<uint8_t>& aOut, uint64_t aNowMs);
    /// Open a sealed message (Ready); false: failed the check, a replay or older than the window (counted in Stats; aCount
    /// false: not counted — probing the keys of several links to find whose it is)
    bool Open(const uint8_t* aData, size_t aSize, std::vector<uint8_t>& aOut, bool aCount = true);

    /// Timeout of waiting for the partner's CryptoHello; true: the handshake was decided now
    bool Tick(const Local& aLocal, uint64_t aNowMs);

    /// Refusal: own CryptoHello with the reason, for the partner (once; empty: sent already, or the partner refused)
    std::vector<uint8_t> TakeRefusal();
    /// The partner refused (not us)
    bool RefusedByPartner() const { return m_partnerRefused; }
    const std::string& Reason() const { return m_reason; }
    /// The partner's keys are signed by the hub and checked
    bool Vouched() const { return m_vouched; }
    /// Short, for the path line and the log: "signed", "unsigned", "direct", "plain", "waiting", "refused"
    std::string Describe() const;

    struct Stats
    {
        uint64_t sealed = 0;
        uint64_t opened = 0;
        uint64_t sealedBytes = 0;
        uint64_t sealNs = 0;
        uint64_t openNs = 0;
        uint64_t failed = 0;   ///< failed the check (tampering, a foreign key)
        uint64_t replayed = 0; ///< a replay or older than the window
        uint64_t tooOld = 0;   ///< of replayed: older than the window
        uint64_t late = 0;     ///< opened behind more than kReplayWindowNarrow newer ones (net_replay_wide)
        uint64_t plain = 0;    ///< plain after the handshake
        uint64_t early = 0;    ///< sealed before our keys were ready
        uint64_t heldDropped = 0;
    };
    const Stats& GetStats() const { return m_stats; }
    /// Dropped since the last call (for a rare transport log line), and whether there is any
    uint64_t TakeDropped();
    bool PendingDrops() const
    {
        return m_stats.failed + m_stats.replayed + m_stats.plain + m_stats.early != m_droppedReported;
    }
    /// Opened late since the last call (net_replay_wide; for a rare log line), and whether there is any
    uint64_t TakeLate();
    bool PendingLate() const { return m_stats.late != m_lateReported; }

    /// For tests: the next send counter (overflow)
    void TestSetNextCounter(uint64_t aCounter) { m_txNext = aCounter; }

private:
    void Resolve(State aState, const std::string& aReason);
    bool OnHello(const Local& aLocal, const uint8_t* aData, size_t aSize, uint64_t aNowMs);
    bool Derive(const Local& aLocal, const std::array<uint8_t, 32>& aTheirs);
    void Wipe();

    State m_state = State::Idle;
    Setup m_setup;
    bool m_strict = false;
    bool m_resolvedPending = false;
    bool m_partnerRefused = false;
    bool m_refusalSent = false;
    bool m_plainByTimeout = false;
    bool m_vouched = false;
    std::string m_reason;
    uint64_t m_beganMs = 0;
    std::array<uint8_t, 32> m_partnerKey{};
    /// Link salt: own (Begin) and the partner's (its CryptoHello), for the key transcript (DeriveLinkKeys)
    std::array<uint8_t, kSaltSize> m_salt{};
    std::array<uint8_t, kSaltSize> m_partnerSalt{};

    std::array<uint8_t, 32> m_tx{};
    std::array<uint8_t, 32> m_rx{};
    uint8_t m_txDir = 0;
    uint8_t m_rxDir = 0;
    uint64_t m_txNext = 1;
    ReplayWindow m_window;

    std::deque<Held> m_held;
    size_t m_heldBytes = 0;
    Stats m_stats;
    uint64_t m_droppedReported = 0;
    uint64_t m_lateReported = 0;
};

/// A synthesized session refusal for a guest (MsgType::Reject "encryption: …"): the transport hands it to the session as
/// if from the host, and the session stops with the reason, as on a host's refusal
std::vector<uint8_t> MakeLocalReject(const std::string& aReason);

/// Log line about the verdict on a hub (aWho: "relay", "hybrid"; aIntro: the hub sent HubIntro):
///   "hybrid: the hub e.hub.nightcoop.net is vouched — the project's root certificate … (policy chain)",
///   "… is NOT vouched — …", "… is refused — …"
void LogHubIdentity(const char* aWho, const Local& aLocal, bool aIntro);
/// HubIntro from the hub: take the hub list (if newer), log an error (aWho: "relay", "hybrid")
void TakeIntroList(const char* aWho, const HubIntro& aIntro);

/// A rare log line about what the link dropped (at most every 10 s per peer; aWho: "transport", "relay", "hybrid"):
/// failed the check (tampering, a foreign key), a replay or older than the window, plain after the key exchange, sealed
/// before own keys
void ReportDrops(Link& aLink, uint32_t aPeer, const char* aWho);
} // namespace nc::netcrypto
