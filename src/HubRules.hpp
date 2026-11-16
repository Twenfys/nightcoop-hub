#pragma once

#include "ProtocolCore.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

/// Rules of the client's talk with the hub, free of network and game code.
namespace nc::hubrules
{
/// The project's hub, by name only: when the server moves, a DNS record changes, not the mod. There is no fallback IP in
/// the code (a server may pass to someone else while players keep knocking on its IP); if the name does not resolve,
/// there is no hub session and the player gets the reason (kReasonUnresolved).
inline constexpr const char* kProjectHubName = "hub.nightcoop.net";

/// Public keys of the project's hub. The secret stays on the server; nightcoop_hub --gen-sign-key prints these two lines
/// for pasting here.
///   kHubSignKey — EdDSA (BLAKE2b): the hub's signature on peers' keys. When set, a link through the project's hub
///                 (kProjectHubName) without a valid signature or without the partner's encryption is refused
///                 (Link::Strict);
///   kHubBoxKey  — X25519: the session code in the request and in the project hub's answer travels sealed.
/// All zeros: not set — signatures are not checked, the code travels in the clear, links are encrypted without
/// authentication ("keys are not vouched" in the log). Another hub (not kProjectHubName) is not checked against these
/// keys. A new key means new lines here and a new build of the mod for everyone.
inline constexpr std::array<uint8_t, 32> kHubSignKey{0xac, 0x41, 0x93, 0x81, 0x2b, 0x52, 0x7f, 0x84, 0x6c, 0xe7, 0xf1,
                                                     0x04, 0xcd, 0xd4, 0xe6, 0x25, 0x01, 0x64, 0x8d, 0xee, 0x80, 0x60,
                                                     0x79, 0x4c, 0x7e, 0x92, 0xaf, 0x44, 0xd2, 0x0c, 0x5b, 0x6b};
inline constexpr std::array<uint8_t, 32> kHubBoxKey{0x8d, 0x61, 0x73, 0x5b, 0x36, 0x8b, 0xa0, 0x25, 0xc3, 0xac, 0xc8,
                                                    0x00, 0xc5, 0x92, 0x1f, 0x3d, 0x3d, 0xe0, 0x7b, 0x88, 0xe5, 0x31,
                                                    0x26, 0x60, 0x3d, 0x90, 0x14, 0xe5, 0x51, 0x4a, 0x9a, 0x0b};

inline const char* ProjectHub()
{
    return kProjectHubName;
}

/// The hub transport's reason (IHubTransport::GetHubReason) when the hub name does not resolve: the session hands it to
/// the menu, which tells the player.
inline constexpr const char* kReasonUnresolved = "hub name not found";
/// Start of the reason when the hub did not prove who it is (root certificate, the old key or the fingerprint did not
/// match); the details follow.
inline constexpr const char* kReasonIdentity = "the hub did not prove who it is";

/// Hub threads: each thread has its own port, and a session lives entirely on one. The client goes to the entry port;
/// if the session is on another thread, the hub answers HubRedirect and the client connects to the same address on the
/// port from the answer and repeats its request. Where the client is in this talk:
enum class Hop : uint8_t
{
    Entry,     ///< on the entry port, understands redirects
    Shard,     ///< redirected to a thread's port (one hop only)
    EntryOnly, ///< the thread's port did not answer (closed on the server): the entry port again, no redirects, like an old client
};

/// Tail of HubCreateSession / HubJoinSession: what the client tells the hub about itself
inline uint8_t CapsFor(Hop aHop)
{
    switch (aHop)
    {
    case Hop::Entry:
        return proto::kHubCapRedirect;
    case Hop::Shard:
        return proto::kHubCapRedirect | proto::kHubCapPlaced;
    case Hop::EntryOnly:
    default:
        return 0;
    }
}

/// Whether to follow HubRedirect: only from the entry port (one hop), only before the hub answered the request, and only
/// to a real port other than the current one
inline bool AcceptRedirect(Hop aHop, bool aAnswered, uint16_t aPort, uint16_t aCurrentPort)
{
    return aHop == Hop::Entry && !aAnswered && aPort != 0 && aPort != aCurrentPort;
}

/// Port of a hub thread: thread 0 is the entry port, the others follow from aEntry + 10 (47810, 47811, …). 0: no such
/// port (past 65535)
inline uint16_t ShardPort(uint16_t aEntry, size_t aShard)
{
    if (aShard == 0)
        return aEntry;
    const size_t port = static_cast<size_t>(aEntry) + 9 + aShard;
    return port <= 65535 ? static_cast<uint16_t>(port) : 0;
}

/// How long to wait for a thread's port to answer, ms (enet_peer_timeout lower and upper bounds). If the port is closed
/// on the server, the client returns to the entry port (Hop::EntryOnly); the hub and the peers keep their usual
/// tolerance of 30–60 s.
inline constexpr uint32_t kShardAnswerMinMs = 4000;
inline constexpr uint32_t kShardAnswerMaxMs = 6000;

// ---------------------------------------------------------------- project root, lettered hubs, own servers
//
// The build carries the project's public root key; every hub has its own keys and a certificate from the root (names,
// region, expiry), and the client checks the chain root -> hub -> peers' signatures, so new servers join without a new
// client build. The old key of the project's hub (kHubSignKey / kHubBoxKey above) stays trusted directly, for
// kProjectHubName only, until a certificate replaces it.

/// The project's public root key (EdDSA-BLAKE2b, Monocypher). The secret is kept by the owner only, offline, never on
/// servers: nightcoop_hub --gen-root-key creates it (and prints this line); hub certificates and the hub list are signed
/// with nightcoop_hub --issue-cert / --sign-list on the owner's machine. All zeros: no root in the build — the project's
/// hub is checked by its old key, *.nightcoop.net hubs with a certificate cannot be checked (refused), no hub list.
inline constexpr std::array<uint8_t, 32> kRootKey{};
/// Backup root, a second key kept apart: if the main one is lost, it signs the certificates without a new build. All
/// zeros: none.
inline constexpr std::array<uint8_t, 32> kRootKeyBackup{};

/// The project's domain: a hub with a name in it needs a root certificate for that name (a server swapped in DNS does
/// not pass); kProjectHubName may also pass by the old key.
inline constexpr const char* kProjectDomain = "nightcoop.net";
/// Lettered hubs: a 7-character session code is the hub's letter plus the hub's code; the hub of a letter is
/// "<letter>.hub.nightcoop.net" (its DNS record and certificate are set up by the owner). A guest reaches the host's hub
/// without a hub list and without a new build.
inline constexpr const char* kHubZone = "hub.nightcoop.net";
/// Entry port of the project's hubs
inline constexpr uint16_t kHubPort = 47800;
/// Initial hub list in the build: hex of a root-signed HubList (nightcoop_hub --sign-list prints the line). With it a
/// host's first session already goes to the nearest hub rather than to kProjectHubName (on release day every new host
/// would otherwise land on one server). Newer lists come from any hub (hubs.ncl next to the dll). Empty: none.
inline constexpr std::string_view kSeedHubList = "";

/// A hub's session code is 6 characters (HubServer::MakeCode); a code with the hub's letter is 7
inline constexpr size_t kCodeChars = 6;
inline constexpr size_t kLetterCodeChars = 7;
/// Code alphabet (as in HubServer): no 0/O and 1/I/L
inline constexpr std::string_view kCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

inline bool IsCodeChar(char aChar)
{
    return aChar != 0 && kCodeAlphabet.find(aChar) != std::string_view::npos;
}

/// A code the player types: 6 characters (the project's hub kProjectHubName) or 7 (the first is the hub's letter)
inline bool ValidPlayerCode(const std::string& aCode)
{
    return (aCode.size() == kCodeChars || aCode.size() == kLetterCodeChars) &&
           std::all_of(aCode.begin(), aCode.end(), IsCodeChar);
}

/// Host name for comparison: lower case, no trailing dot
inline std::string LowerHost(std::string aHost)
{
    for (char& c : aHost)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    while (!aHost.empty() && aHost.back() == '.')
        aHost.pop_back();
    return aHost;
}

/// The hub of a letter: "e.hub.nightcoop.net"
inline std::string LetterHubName(char aLetter)
{
    return std::string(1, static_cast<char>(std::tolower(static_cast<unsigned char>(aLetter)))) + "." + kHubZone;
}

/// Where a guest with a code goes: 7 characters — the letter's hub and the hub's code (the last 6); otherwise the
/// project's hub and the code as is
struct CodeTarget
{
    std::string hub;
    std::string code;
    char letter = 0; ///< 0: a code without a letter
};
inline CodeTarget TargetForCode(const std::string& aCode)
{
    // Case does not matter (codes typed in a console may be lower case; the hub upper-cases the code itself)
    std::string code = aCode;
    for (char& c : code)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (code.size() == kLetterCodeChars && IsCodeChar(code[0]))
        return {LetterHubName(code[0]), code.substr(1), code[0]};
    return {kProjectHubName, aCode, 0};
}

/// A name in the project's domain (*.nightcoop.net or the domain itself)
inline bool UnderProjectDomain(const std::string& aHost)
{
    const std::string host = LowerHost(aHost);
    const std::string domain = kProjectDomain;
    return host == domain || (host.size() > domain.size() + 1 && host.ends_with("." + domain));
}

/// A hub address as a player or the owner of a server writes it: "name[:port][#fingerprint]". The hub prints the
/// fingerprint of its key at start; with it the client accepts only the server holding that key.
struct HubAddress
{
    std::string host;
    uint16_t port = 0; ///< 0: not given
    std::string fingerprint;
};
inline HubAddress SplitHubAddress(const std::string& aText)
{
    HubAddress out;
    std::string text = aText;
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())))
        text.pop_back();
    size_t start = 0;
    while (start < text.size() && std::isspace(static_cast<unsigned char>(text[start])))
        ++start;
    text.erase(0, start);
    const size_t hash = text.find('#');
    if (hash != std::string::npos)
    {
        out.fingerprint = text.substr(hash + 1);
        text.resize(hash);
    }
    // One colon means a port (ENet is IPv4 only, so no IPv6 addresses with colons come here)
    const size_t colon = text.find(':');
    if (colon != std::string::npos && colon == text.rfind(':') && colon + 1 < text.size() && text.size() - colon - 1 <= 5)
    {
        uint32_t port = 0;
        bool digits = true;
        for (size_t i = colon + 1; i < text.size(); ++i)
        {
            digits = digits && std::isdigit(static_cast<unsigned char>(text[i]));
            port = port * 10 + static_cast<uint32_t>(text[i] - '0');
        }
        if (digits && port > 0 && port <= 65535)
        {
            out.port = static_cast<uint16_t>(port);
            text.resize(colon);
        }
    }
    out.host = text;
    return out;
}

/// The host's choice of hub (network thread, Session): the lowest RTT among those that answered (negative: no answer);
/// ties go to the earlier one in the list. -1: nobody answered (the host goes to the project's hub).
inline int PickByRtt(const std::vector<double>& aRtts)
{
    int best = -1;
    for (size_t i = 0; i < aRtts.size(); ++i)
        if (aRtts[i] >= 0.0 && (best < 0 || aRtts[i] < aRtts[static_cast<size_t>(best)]))
            best = static_cast<int>(i);
    return best;
}

/// Fingerprint of a hub's key: 16 characters of Crockford base32 (80 bits, "ABCD-EFGH-JKMN-PQRS") — shorter than the key
/// and readable aloud (no I, L, O, U). The hash itself is netcrypto::Fingerprint.
inline constexpr size_t kFingerprintBytes = 10;
inline constexpr size_t kFingerprintChars = 16;
inline constexpr std::string_view kCrockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

inline std::string FingerprintText(const uint8_t aBytes[kFingerprintBytes])
{
    std::string out;
    uint32_t buffer = 0;
    int bits = 0;
    for (size_t i = 0; i < kFingerprintBytes; ++i)
    {
        buffer = (buffer << 8) | aBytes[i];
        bits += 8;
        while (bits >= 5)
        {
            bits -= 5;
            out.push_back(kCrockford[(buffer >> bits) & 31]);
        }
    }
    std::string grouped;
    for (size_t i = 0; i < out.size(); ++i)
    {
        if (i && i % 4 == 0)
            grouped.push_back('-');
        grouped.push_back(out[i]);
    }
    return grouped;
}

/// A fingerprint as a person typed it, in the FingerprintText form: case, dashes and spaces do not matter, O -> 0, I and
/// L -> 1 (Crockford's rule). Empty: not a fingerprint (not 16 characters of the alphabet).
inline std::string NormalizeFingerprint(const std::string& aText)
{
    std::string plain;
    for (const char c : aText)
    {
        if (c == '-' || c == ' ' || c == '_')
            continue;
        char up = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (up == 'O')
            up = '0';
        else if (up == 'I' || up == 'L')
            up = '1';
        if (kCrockford.find(up) == std::string_view::npos)
            return {};
        plain.push_back(up);
    }
    if (plain.size() != kFingerprintChars)
        return {};
    std::string grouped;
    for (size_t i = 0; i < plain.size(); ++i)
    {
        if (i && i % 4 == 0)
            grouped.push_back('-');
        grouped.push_back(plain[i]);
    }
    return grouped;
}

/// A fingerprint in text (as typed) -> 10 bytes, the inverse of FingerprintText. False: not a fingerprint
inline bool FingerprintBytes(const std::string& aText, uint8_t aOut[kFingerprintBytes])
{
    const std::string grouped = NormalizeFingerprint(aText);
    if (grouped.empty())
        return false;
    uint32_t buffer = 0;
    int bits = 0;
    size_t at = 0;
    for (const char c : grouped)
    {
        if (c == '-')
            continue;
        buffer = (buffer << 5) | static_cast<uint32_t>(kCrockford.find(c));
        bits += 5;
        if (bits >= 8)
        {
            bits -= 8;
            if (at < kFingerprintBytes)
                aOut[at++] = static_cast<uint8_t>((buffer >> bits) & 0xFF);
        }
    }
    return at == kFingerprintBytes;
}

// ---------------------------------------------------------------- project locations: server picker
//
// When creating a session the client asks the main server (or the next one if it does not answer) for the list of all
// locations, with their ping. The question and the answer are single datagrams without an ENet connection (like the
// pass ask in HubCookie.hpp: the hub parses it before ENet and remembers nothing). The hub answers with its state (open
// or full, load), its signing key and — when asked and when it has one — the project's location list (the owner's
// locations.txt on the project's hubs) signed with its key. The client trusts the list if the signing key is the key of
// the hub it asked, under the same policy as a session (NetCrypto: PolicyFor, JudgeLocationsSigner). The answer is never
// longer than the question, so a forged address does not amplify anyone's traffic (a question asking for the list is
// padded with zeros to kLocAskList bytes). An older hub drops the question silently (not its magic): the client then
// measures its ping with a pass ask and takes the list from the next hub or from the build.

/// The first two bytes are the ENet header "peer 0xFFE, no flags" (as in HubCookie.hpp): ENet without our intercept drops
/// such a datagram itself
inline constexpr uint8_t kLocAskMagic[8] = {0x0F, 0xFE, 'N', 'C', 'l', 'o', 'c', '?'};
inline constexpr uint8_t kLocTellMagic[8] = {0x0F, 0xFE, 'N', 'C', 'l', 'o', 'c', '!'};
inline constexpr uint8_t kLocVersion = 1;
/// Question: magic 8 | u8 version | u8 flags | u16 0 | u32 nonce (echoed in the answer) | u64 number of the list the
/// client has | zeros up to the size
inline constexpr size_t kLocAskHead = 24;
/// Status question (ping): the answer with the key is 52 bytes
inline constexpr size_t kLocAskStatus = 64;
/// Question with the list: the answer with the list and the root certificate fits in this many bytes (one datagram,
/// unfragmented on any path with an MTU of 1400 or more)
inline constexpr size_t kLocAskList = 1280;
inline constexpr uint8_t kLocAskWantList = 1u << 0;
/// Answer: magic 8 | u8 version | u8 flags | u16 0 | u32 nonce | u8 state | u8 load % (255: unknown) | u16 sessions |
/// [32 hub signing key, flag kLocTellKey] | [list, flag kLocTellList: u8 proof kind (0: the key above only, 2: root
/// certificate) | u16 length + proof | u16 length + list body | 64 signature by the hub's key]
inline constexpr size_t kLocTellHead = 20;
inline constexpr uint8_t kLocTellKey = 1u << 0;
inline constexpr uint8_t kLocTellList = 1u << 1;
inline constexpr uint8_t kLocTellTooBig = 1u << 2;   ///< there is a list, but it did not fit into this question
inline constexpr uint8_t kLocTellNotNewer = 1u << 3; ///< there is a list, but the client's one is not older
inline constexpr uint8_t kLocProofKey = 0;
inline constexpr uint8_t kLocProofRoot = 2;
/// Limits of the list: locations, bytes of region, label, name
inline constexpr size_t kMaxLocations = 16;
inline constexpr size_t kMaxLocRegion = 15;
inline constexpr size_t kMaxLocLabel = 63;
inline constexpr size_t kMaxLocHost = 63;

enum class LocState : uint8_t
{
    Open = 0,   ///< new sessions go here
    Closed = 1, ///< the hub only keeps its current sessions (closed by the owner in the list)
    Full = 2,   ///< the hub is busy up to its limit (its live state in the answer)
    Unknown = 255,
};

inline const char* LocStateName(LocState aState)
{
    switch (aState)
    {
    case LocState::Open: return "open";
    case LocState::Closed: return "closed";
    case LocState::Full: return "full";
    default: return "unknown";
    }
}

/// A project location. letter 0 is the project's hub hub.nightcoop.net: its codes have no letter (6 characters,
/// understood by every build). The others carry the code's letter (the first of 7 characters). Address: a name or IPv4,
/// a port and the key's fingerprint (empty: none — then the hub is checked by name: the build's old key or a root
/// certificate).
struct Location
{
    char letter = 0;
    LocState state = LocState::Open;
    std::string region; ///< "eu", "na-east"…
    std::string label;  ///< label, Russian and English separated by " | "
    std::string host;   ///< lower case
    uint16_t port = kHubPort;
    std::string fingerprint; ///< "XXXX-XXXX-XXXX-XXXX" or empty

    /// Address for a session and the log: "name[:port][#fingerprint]" (the port if it is not 47800)
    std::string Address() const
    {
        std::string out = host;
        if (port != kHubPort)
            out += ":" + std::to_string(port);
        if (!fingerprint.empty())
            out += "#" + fingerprint;
        return out;
    }
};

struct LocationList
{
    uint64_t serial = 0; ///< grows with every edit of locations.txt; 0: the list of the build
    uint64_t issued = 0; ///< seconds since 1970 (when the hub signed it)
    std::vector<Location> entries;

    const Location* Find(char aLetter) const
    {
        for (const auto& entry : entries)
            if (entry.letter == aLetter)
                return &entry;
        return nullptr;
    }
};

namespace locwire
{
inline void PutU16(std::vector<uint8_t>& aOut, uint16_t aValue)
{
    aOut.push_back(static_cast<uint8_t>(aValue & 0xFF));
    aOut.push_back(static_cast<uint8_t>(aValue >> 8));
}
inline void PutU32(std::vector<uint8_t>& aOut, uint32_t aValue)
{
    for (int i = 0; i < 4; ++i)
        aOut.push_back(static_cast<uint8_t>((aValue >> (8 * i)) & 0xFF));
}
inline void PutU64(std::vector<uint8_t>& aOut, uint64_t aValue)
{
    for (int i = 0; i < 8; ++i)
        aOut.push_back(static_cast<uint8_t>((aValue >> (8 * i)) & 0xFF));
}
inline void PutStr8(std::vector<uint8_t>& aOut, const std::string& aText)
{
    const size_t size = std::min<size_t>(aText.size(), 255);
    aOut.push_back(static_cast<uint8_t>(size));
    aOut.insert(aOut.end(), aText.begin(), aText.begin() + static_cast<std::ptrdiff_t>(size));
}

/// Reading in place: past the end, ok turns false and the reads return zeros
struct In
{
    const uint8_t* data = nullptr;
    size_t size = 0;
    size_t at = 0;
    bool ok = true;

    bool Need(size_t aBytes)
    {
        if (!ok || at > size || size - at < aBytes)
        {
            ok = false;
            return false;
        }
        return true;
    }
    uint8_t U8() { return Need(1) ? data[at++] : 0; }
    uint16_t U16()
    {
        if (!Need(2))
            return 0;
        const uint16_t value = static_cast<uint16_t>(data[at] | (data[at + 1] << 8));
        at += 2;
        return value;
    }
    uint32_t U32()
    {
        if (!Need(4))
            return 0;
        uint32_t value = 0;
        for (int i = 3; i >= 0; --i)
            value = (value << 8) | data[at + static_cast<size_t>(i)];
        at += 4;
        return value;
    }
    uint64_t U64()
    {
        if (!Need(8))
            return 0;
        uint64_t value = 0;
        for (int i = 7; i >= 0; --i)
            value = (value << 8) | data[at + static_cast<size_t>(i)];
        at += 8;
        return value;
    }
    bool Bytes(uint8_t* aOut, size_t aCount)
    {
        if (!Need(aCount))
            return false;
        std::copy(data + at, data + at + aCount, aOut);
        at += aCount;
        return true;
    }
    std::string Str8(size_t aMax)
    {
        const size_t length = U8();
        if (!ok || length > aMax || !Need(length))
        {
            ok = false;
            return {};
        }
        std::string out(reinterpret_cast<const char*>(data + at), length);
        at += length;
        return out;
    }
};
} // namespace locwire

/// A hub name in the list: lower-case letters, digits, dot, dash (a DNS name or IPv4)
inline bool LocHostChars(const std::string& aHost)
{
    return !aHost.empty() && aHost.size() <= kMaxLocHost &&
           std::all_of(aHost.begin(), aHost.end(), [](char c)
                       { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'; });
}

/// Region: lower-case Latin letters, digits, dash
inline bool LocRegionChars(const std::string& aRegion)
{
    return !aRegion.empty() && aRegion.size() <= kMaxLocRegion &&
           std::all_of(aRegion.begin(), aRegion.end(),
                       [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; });
}

/// Label: printable characters and UTF-8, no control characters
inline bool LocLabelChars(const std::string& aLabel)
{
    return aLabel.size() <= kMaxLocLabel &&
           std::all_of(aLabel.begin(), aLabel.end(), [](char c) { return static_cast<unsigned char>(c) >= 0x20 && c != 0x7F; });
}

/// Body of the location list (signed by the hub): u8 version | u8 0 | u64 serial | u64 issued | u8 locations |
/// locations (u8 letter | u8 state | u8+region | u8+label | u8+name | u16 port | u8 fingerprint bytes (0 or 10) +
/// fingerprint)
inline std::vector<uint8_t> WriteLocationBody(const LocationList& aList)
{
    std::vector<uint8_t> out;
    out.push_back(kLocVersion);
    out.push_back(0);
    locwire::PutU64(out, aList.serial);
    locwire::PutU64(out, aList.issued);
    const size_t count = std::min(aList.entries.size(), kMaxLocations);
    out.push_back(static_cast<uint8_t>(count));
    for (size_t i = 0; i < count; ++i)
    {
        const Location& entry = aList.entries[i];
        out.push_back(static_cast<uint8_t>(entry.letter));
        out.push_back(static_cast<uint8_t>(entry.state));
        locwire::PutStr8(out, entry.region);
        locwire::PutStr8(out, entry.label);
        locwire::PutStr8(out, entry.host);
        locwire::PutU16(out, entry.port);
        uint8_t fp[kFingerprintBytes] = {};
        if (!entry.fingerprint.empty() && FingerprintBytes(entry.fingerprint, fp))
        {
            out.push_back(static_cast<uint8_t>(kFingerprintBytes));
            out.insert(out.end(), fp, fp + kFingerprintBytes);
        }
        else
            out.push_back(0);
    }
    return out;
}

/// Parses a body: exactly one list, fields within limits, letters are code characters (and at most one 0), no repeats
inline bool ReadLocationBody(const uint8_t* aData, size_t aSize, LocationList& aOut, std::string* aWhy = nullptr)
{
    const auto fail = [&](const char* aText)
    {
        if (aWhy)
            *aWhy = aText;
        return false;
    };
    aOut = {};
    locwire::In in{aData, aSize};
    const uint8_t version = in.U8();
    in.U8();
    aOut.serial = in.U64();
    aOut.issued = in.U64();
    const size_t count = in.U8();
    if (!in.ok)
        return fail("the list is cut short");
    if (version != kLocVersion)
        return fail("an unknown version of the list");
    if (count > kMaxLocations)
        return fail("too many locations");
    bool main = false;
    for (size_t i = 0; i < count; ++i)
    {
        Location entry;
        entry.letter = static_cast<char>(in.U8());
        const uint8_t state = in.U8();
        entry.region = in.Str8(kMaxLocRegion);
        entry.label = in.Str8(kMaxLocLabel);
        entry.host = in.Str8(kMaxLocHost);
        entry.port = in.U16();
        const uint8_t fpSize = in.U8();
        if (!in.ok)
            return fail("a location is cut short");
        if (fpSize != 0 && fpSize != kFingerprintBytes)
            return fail("a location's fingerprint has a wrong size");
        if (fpSize)
        {
            uint8_t fp[kFingerprintBytes] = {};
            in.Bytes(fp, kFingerprintBytes);
            entry.fingerprint = FingerprintText(fp);
        }
        if (state > static_cast<uint8_t>(LocState::Full))
            return fail("a location's state is unknown");
        entry.state = static_cast<LocState>(state);
        if (entry.letter != 0 && !IsCodeChar(entry.letter))
            return fail("a location's letter is not a code character");
        if (entry.letter == 0)
        {
            if (main)
                return fail("two locations without a letter");
            main = true;
        }
        if (aOut.Find(entry.letter))
            return fail("two locations with one letter");
        if (!LocHostChars(entry.host) || entry.port == 0 || !LocRegionChars(entry.region) || !LocLabelChars(entry.label))
            return fail("a location's name, port, region or label is not valid");
        aOut.entries.push_back(std::move(entry));
    }
    if (!in.ok || in.at != aSize)
        return fail("bytes after the list");
    return true;
}

/// The owner's locations.txt (the same on every project hub): a line "serial N", then a line per location —
/// "letter|- open|closed region address[:port][#fingerprint] label…" (the label runs to the end of the line, Russian and
/// English separated by " | "). "-" is the project's hub (codes without a letter); # starts a comment. False: aWhy says
/// where and what is wrong.
inline bool ParseLocationsText(const std::string& aText, LocationList& aOut, std::string& aWhy)
{
    aOut = {};
    bool serialSeen = false;
    bool main = false;
    std::vector<std::string> lines;
    for (size_t start = 0; start < aText.size();)
    {
        size_t end = aText.find('\n', start);
        if (end == std::string::npos)
            end = aText.size();
        lines.push_back(aText.substr(start, end - start));
        start = end + 1;
    }
    for (size_t lineNo = 1; lineNo <= lines.size(); ++lineNo)
    {
        std::string line = lines[lineNo - 1];
        if (lineNo == 1 && line.rfind("\xEF\xBB\xBF", 0) == 0)
            line.erase(0, 3);
        while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back())))
            line.pop_back();
        size_t first = 0;
        while (first < line.size() && std::isspace(static_cast<unsigned char>(line[first])))
            ++first;
        line.erase(0, first);
        if (line.empty() || line[0] == '#')
            continue;
        // Words separated by spaces: the first four are letter, state, region, address; the rest is the label
        std::vector<std::string> words;
        size_t at = 0;
        while (at < line.size() && words.size() < 4)
        {
            while (at < line.size() && std::isspace(static_cast<unsigned char>(line[at])))
                ++at;
            size_t wordEnd = at;
            while (wordEnd < line.size() && !std::isspace(static_cast<unsigned char>(line[wordEnd])))
                ++wordEnd;
            if (wordEnd > at)
                words.push_back(line.substr(at, wordEnd - at));
            at = wordEnd;
        }
        while (at < line.size() && std::isspace(static_cast<unsigned char>(line[at])))
            ++at;
        const std::string rest = line.substr(at);
        const auto bad = [&](const std::string& aWhat)
        {
            aWhy = "line " + std::to_string(lineNo) + ": " + aWhat;
            return false;
        };
        if (!words.empty() && words[0] == "serial")
        {
            if (words.size() != 2 || !rest.empty() || words[1].empty() || words[1].size() > 18 ||
                !std::all_of(words[1].begin(), words[1].end(), [](char c) { return c >= '0' && c <= '9'; }))
                return bad("«serial N» — N is a number");
            uint64_t serial = 0;
            for (const char c : words[1])
                serial = serial * 10 + static_cast<uint64_t>(c - '0');
            aOut.serial = serial;
            serialSeen = true;
            continue;
        }
        if (words.size() < 4)
            return bad("a location is «letter|- open|closed region address[:port][#fingerprint] label»");
        if (aOut.entries.size() >= kMaxLocations)
            return bad("more than " + std::to_string(kMaxLocations) + " locations");
        Location entry;
        if (words[0] == "-")
        {
            if (main)
                return bad("a second location without a letter («-» is the project's hub, codes of 6 characters)");
            main = true;
        }
        else
        {
            if (words[0].size() != 1)
                return bad("the letter is one character of the code alphabet (or «-»)");
            entry.letter = static_cast<char>(std::toupper(static_cast<unsigned char>(words[0][0])));
            if (!IsCodeChar(entry.letter))
                return bad(std::string("«") + words[0] + "» is not a code character (" + std::string(kCodeAlphabet) + ")");
            if (aOut.Find(entry.letter))
                return bad(std::string("the letter ") + entry.letter + " twice");
        }
        if (words[1] == "open")
            entry.state = LocState::Open;
        else if (words[1] == "closed")
            entry.state = LocState::Closed;
        else
            return bad("the state is «open» or «closed»");
        entry.region = words[2];
        for (char& c : entry.region)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (!LocRegionChars(entry.region))
            return bad("the region is up to 15 of a-z, 0-9 and «-»");
        const HubAddress address = SplitHubAddress(words[3]);
        entry.host = LowerHost(address.host);
        entry.port = address.port ? address.port : kHubPort;
        if (!LocHostChars(entry.host))
            return bad("the address is a DNS name or IPv4 (a-z, 0-9, «.», «-»), up to 63 characters");
        if (!address.fingerprint.empty())
        {
            entry.fingerprint = NormalizeFingerprint(address.fingerprint);
            if (entry.fingerprint.empty())
                return bad("the fingerprint is 16 characters (XXXX-XXXX-XXXX-XXXX)");
        }
        entry.label = rest;
        if (entry.label.empty())
            return bad("no label");
        if (!LocLabelChars(entry.label))
            return bad("the label is up to 63 bytes of text");
        aOut.entries.push_back(std::move(entry));
    }
    if (!serialSeen)
    {
        aWhy = "no «serial N» line";
        return false;
    }
    if (aOut.entries.empty())
    {
        aWhy = "no locations";
        return false;
    }
    return true;
}

/// This hub's own line in the location list: the one with its key's fingerprint; the project's hub (it holds the key built
/// into the mod, aProjectKey) is listed by name without a fingerprint — the line without a letter. nullptr: not in the list.
/// "closed" there means: no new sessions on this hub, the current ones live on (and guests still join them by code)
inline const Location* SelfLocation(const LocationList& aList, const std::string& aOwnFingerprint, bool aProjectKey)
{
    const std::string own = NormalizeFingerprint(aOwnFingerprint);
    for (const auto& entry : aList.entries)
        if (!own.empty() && !entry.fingerprint.empty() && NormalizeFingerprint(entry.fingerprint) == own)
            return &entry;
    return aProjectKey ? aList.Find(0) : nullptr;
}

/// The client's question
struct LocAsk
{
    uint8_t flags = 0;
    uint32_t nonce = 0;
    uint64_t known = 0;
    size_t size = 0; ///< the whole question, bytes: the answer is not longer
};

inline std::vector<uint8_t> MakeLocAsk(bool aWantList, uint32_t aNonce, uint64_t aKnownSerial)
{
    std::vector<uint8_t> out(kLocAskMagic, kLocAskMagic + sizeof(kLocAskMagic));
    out.push_back(kLocVersion);
    out.push_back(aWantList ? kLocAskWantList : 0);
    locwire::PutU16(out, 0);
    locwire::PutU32(out, aNonce);
    locwire::PutU64(out, aKnownSerial);
    out.resize(aWantList ? kLocAskList : kLocAskStatus, 0);
    return out;
}

inline bool IsLocAsk(const uint8_t* aData, size_t aSize)
{
    return aSize >= kLocAskHead && std::equal(kLocAskMagic, kLocAskMagic + sizeof(kLocAskMagic), aData);
}

inline bool ReadLocAsk(const uint8_t* aData, size_t aSize, LocAsk& aOut)
{
    if (!IsLocAsk(aData, aSize))
        return false;
    locwire::In in{aData, aSize, sizeof(kLocAskMagic)};
    const uint8_t version = in.U8();
    aOut.flags = in.U8();
    in.U16();
    aOut.nonce = in.U32();
    aOut.known = in.U64();
    aOut.size = aSize;
    return in.ok && version >= 1;
}

/// The hub's answer
struct LocTell
{
    uint8_t flags = 0;
    uint32_t nonce = 0;
    LocState state = LocState::Unknown;
    uint8_t load = 255;
    uint16_t sessions = 0;
    std::array<uint8_t, 32> key{};
    uint8_t proofKind = kLocProofKey;
    std::vector<uint8_t> proof; ///< root certificate (kLocProofRoot)
    std::vector<uint8_t> body;  ///< list body (WriteLocationBody)
    std::array<uint8_t, 64> signature{};
};

/// Size of an answer with the list (to check the owner's file: does it fit into a kLocAskList question)
inline size_t LocTellSize(bool aKey, const LocTell& aTell, bool aList)
{
    return kLocTellHead + (aKey ? 32 : 0) + (aList ? 1 + 2 + aTell.proof.size() + 2 + aTell.body.size() + 64 : 0);
}

/// An answer no longer than aLimit (the question's size): a list that does not fit is left out, with kLocTellTooBig
inline std::vector<uint8_t> MakeLocTell(LocTell aTell, size_t aLimit)
{
    const bool key = (aTell.flags & kLocTellKey) != 0;
    bool list = (aTell.flags & kLocTellList) != 0;
    if (list && LocTellSize(key, aTell, true) > aLimit)
    {
        list = false;
        aTell.flags = static_cast<uint8_t>((aTell.flags & ~kLocTellList) | kLocTellTooBig);
    }
    if (LocTellSize(key, aTell, false) > aLimit)
        return {};
    std::vector<uint8_t> out(kLocTellMagic, kLocTellMagic + sizeof(kLocTellMagic));
    out.push_back(kLocVersion);
    out.push_back(aTell.flags);
    locwire::PutU16(out, 0);
    locwire::PutU32(out, aTell.nonce);
    out.push_back(static_cast<uint8_t>(aTell.state));
    out.push_back(aTell.load);
    locwire::PutU16(out, aTell.sessions);
    if (key)
        out.insert(out.end(), aTell.key.begin(), aTell.key.end());
    if (list)
    {
        out.push_back(aTell.proofKind);
        locwire::PutU16(out, static_cast<uint16_t>(aTell.proof.size()));
        out.insert(out.end(), aTell.proof.begin(), aTell.proof.end());
        locwire::PutU16(out, static_cast<uint16_t>(aTell.body.size()));
        out.insert(out.end(), aTell.body.begin(), aTell.body.end());
        out.insert(out.end(), aTell.signature.begin(), aTell.signature.end());
    }
    return out;
}

inline bool ReadLocTell(const uint8_t* aData, size_t aSize, LocTell& aOut)
{
    aOut = {};
    if (aSize < kLocTellHead || !std::equal(kLocTellMagic, kLocTellMagic + sizeof(kLocTellMagic), aData))
        return false;
    locwire::In in{aData, aSize, sizeof(kLocTellMagic)};
    const uint8_t version = in.U8();
    aOut.flags = in.U8();
    in.U16();
    aOut.nonce = in.U32();
    const uint8_t state = in.U8();
    aOut.state = state <= static_cast<uint8_t>(LocState::Full) ? static_cast<LocState>(state) : LocState::Unknown;
    aOut.load = in.U8();
    aOut.sessions = in.U16();
    if (aOut.flags & kLocTellKey)
        in.Bytes(aOut.key.data(), aOut.key.size());
    if (aOut.flags & kLocTellList)
    {
        aOut.proofKind = in.U8();
        const uint16_t proofSize = in.U16();
        if (in.Need(proofSize))
        {
            aOut.proof.assign(aData + in.at, aData + in.at + proofSize);
            in.at += proofSize;
        }
        const uint16_t bodySize = in.U16();
        if (in.Need(bodySize))
        {
            aOut.body.assign(aData + in.at, aData + in.at + bodySize);
            in.at += bodySize;
        }
        in.Bytes(aOut.signature.data(), aOut.signature.size());
    }
    return in.ok && version >= 1;
}

// ---------------------------------------------------------------- a session outlives a hub restart
//
// Sessions live only in the hub's memory. When a host creates a session, the hub gives it a resume pass: the code, the
// game protocol, the session's tag in signatures and the host's X25519 key, signed with the hub's key and sent sealed to
// that key (the code stays hidden on the path). After a restart the host comes back with the pass sealed to the hub's
// "box" with the same key — only the holder of that key's secret can seal it — and the hub, with the same key file, checks
// its own signature and gives the same code back. Guests then join by the code as after any break, and the host gives
// them their old peer numbers (Session: clientId). A pass is worth nothing while a session with its code is alive.

inline constexpr uint8_t kResumeVersion = 1;
/// A pass is valid this long by the hub's clock; the host asks for a fresh one when half of it is gone (HubResumeAsk)
inline constexpr uint64_t kResumePassLifeSec = 12 * 3600;
/// The hub time in a resume request (the host counts it from the pass's issue time on its own monotonic clock) may be
/// off the hub's clock by this much: an old request replayed later is refused
inline constexpr uint64_t kResumeSkewSec = 120;
/// At most one fresh pass per session this often
inline constexpr uint64_t kResumeAskEveryMs = 60000;
/// The host tries to bring its session back for this long after losing the hub, and a guest that lost the hub waits for
/// it as long: as long as the host keeps the place of a guest who dropped out (Session::kAwayGraceMs)
inline constexpr uint64_t kResumeWindowMs = 90000;
/// At least this long between the host's attempts (a hub that is down answers nothing: ENet gives up a CONNECT in 4–6 s)
inline constexpr uint64_t kResumeRetryMs = 2000;
/// A resume request without an answer for this long: the hub does not resume sessions (an older hub, or --resume off)
inline constexpr uint64_t kResumeAnswerMs = 10000;
/// Peer numbers of a resumed session continue above every number it had (the host tells the hub where to go on from):
/// a returning guest's new connection must not take the number of a partner still playing on the direct path. Capped
/// far below the numbers the mod reserves (Transport.hpp kFirstReservedPeer)
inline constexpr uint32_t kResumeMaxNextId = 1u << 24;

/// Refusals of a resume request (HubJoinRejected)
inline constexpr const char* kReasonResumeLive = "the session is live";
inline constexpr const char* kReasonResumeBad = "the resume pass is not valid here";
inline constexpr const char* kReasonResumeExpired = "the resume pass has expired";
inline constexpr const char* kReasonResumeStale = "the resume request is stale";
/// The hub's refusals that are not about the pass (also given to a new session)
inline constexpr const char* kReasonHubFull = "the hub is full";
inline constexpr const char* kReasonTooManyCreates = "too many sessions from your address, try in a minute";
/// A join to a code the hub does not know
inline constexpr const char* kReasonNoSession = "no such session";

/// 26.10 (hub_cpu_gate; the owner: "raise the per-core limit to 75–80 %; once there, no new sessions open, but players can
/// still join the existing ones"). A hub thread holds its sessions alone; on 25.10 at 19:20 Limburg ran out of connection
/// slots (512 a thread) with its busiest thread at 44 % of a core. Now the slots are not the limit (nightcoop-hub.service:
/// --max-clients 1024), the core is: a thread takes new sessions while its share of a core is under --cpu-limit. Joins
/// and sessions coming back after a restart of the hub are not gated — only the slots hold them.
///
/// A thread's share of a core, ‰, smoothed: one sample a second, a quarter of it each time (half of a step in ~2.5 s), so
/// one heavy second does not shut the hub
inline uint16_t CpuSmooth(uint16_t aOld, uint32_t aSample)
{
    const uint32_t sample = std::min<uint32_t>(aSample, 1000u);
    return static_cast<uint16_t>((aOld * 3u + sample + 2u) / 4u);
}

/// A thread takes a new session (aLimitPct 0: no gate, as before 26.10)
inline bool CpuOpen(uint16_t aCpuPermille, uint8_t aLimitPct)
{
    return aLimitPct == 0 || aCpuPermille < static_cast<uint32_t>(aLimitPct) * 10u;
}

/// The thread for a new session: the fewest connections among the threads under the CPU limit; the asking thread (aSelf,
/// aOwnLoad — its connections without the asker) wins a tie, so there is no extra hop. aUsable[i] false: the thread has no
/// port. -1: every thread is at the limit — the hub takes no new session now
inline int PickOpenThread(const uint32_t* aLoads, const uint16_t* aCpus, const bool* aUsable, size_t aCount, size_t aSelf,
                          uint32_t aOwnLoad, uint8_t aLimitPct)
{
    int best = -1;
    uint32_t bestLoad = 0;
    if (aSelf < aCount && aUsable[aSelf] && CpuOpen(aCpus[aSelf], aLimitPct))
    {
        best = static_cast<int>(aSelf);
        bestLoad = aOwnLoad;
    }
    for (size_t i = 0; i < aCount; ++i)
    {
        if (i == aSelf || !aUsable[i] || !CpuOpen(aCpus[i], aLimitPct))
            continue;
        if (best < 0 || aLoads[i] < bestLoad)
        {
            best = static_cast<int>(i);
            bestLoad = aLoads[i];
        }
    }
    return best;
}

/// The hub's fill for the server picker and the bot: the larger of its connections against the slots and the least busy
/// thread's share of the CPU limit — 100 % means the hub takes no new session. 255: no slots (unknown)
inline uint8_t FillPercent(size_t aConnections, size_t aCapacity, uint16_t aLeastCpuPermille, uint8_t aLimitPct)
{
    if (aCapacity == 0)
        return 255;
    size_t fill = aConnections * 100 / aCapacity;
    if (aLimitPct)
        fill = std::max<size_t>(fill, static_cast<size_t>(aLeastCpuPermille) * 10u / aLimitPct);
    return static_cast<uint8_t>(std::min<size_t>(fill, 100));
}

/// Pass flags
inline constexpr uint8_t kResumePassEncrypts = 1u << 0; ///< the host encrypts its links (its key is signed in HubPeerUp)

/// The resume pass: u8 version | u8 flags | u8 code length | 8 code (zero padded) | u32 game protocol | 16 the session's
/// tag in signatures | 32 the host's X25519 key | u64 issued | u64 valid until (seconds, the hub's clock) | 64 EdDSA
/// signature by the hub's key over "NightCoop resume pass 1" and the 79 bytes before it (NetCrypto: HubKeys::SignResumePass)
struct ResumePass
{
    static constexpr size_t kMaxCode = 8;
    static constexpr size_t kBodySize = 1 + 1 + 1 + kMaxCode + 4 + 16 + 32 + 8 + 8;
    static constexpr size_t kSize = kBodySize + 64;

    uint8_t version = kResumeVersion;
    uint8_t flags = 0;
    std::string code;
    uint32_t protocol = 0;
    std::array<uint8_t, 16> session{};
    std::array<uint8_t, 32> hostKey{};
    uint64_t issued = 0;
    uint64_t until = 0;
    std::array<uint8_t, 64> signature{};

    std::vector<uint8_t> Body() const
    {
        std::vector<uint8_t> out;
        out.reserve(kBodySize);
        out.push_back(version);
        out.push_back(flags);
        const size_t length = std::min(code.size(), kMaxCode);
        out.push_back(static_cast<uint8_t>(length));
        for (size_t i = 0; i < kMaxCode; ++i)
            out.push_back(i < length ? static_cast<uint8_t>(code[i]) : 0);
        locwire::PutU32(out, protocol);
        out.insert(out.end(), session.begin(), session.end());
        out.insert(out.end(), hostKey.begin(), hostKey.end());
        locwire::PutU64(out, issued);
        locwire::PutU64(out, until);
        return out;
    }
    std::vector<uint8_t> Write() const
    {
        std::vector<uint8_t> out = Body();
        out.insert(out.end(), signature.begin(), signature.end());
        return out;
    }
    /// Exactly one pass of a known version with a code of session code characters (the signature is checked by NetCrypto)
    static bool Read(const uint8_t* aData, size_t aSize, ResumePass& aOut)
    {
        aOut = {};
        if (aSize != kSize)
            return false;
        locwire::In in{aData, aSize};
        aOut.version = in.U8();
        aOut.flags = in.U8();
        const size_t length = in.U8();
        uint8_t code[kMaxCode] = {};
        in.Bytes(code, kMaxCode);
        aOut.protocol = in.U32();
        in.Bytes(aOut.session.data(), aOut.session.size());
        in.Bytes(aOut.hostKey.data(), aOut.hostKey.size());
        aOut.issued = in.U64();
        aOut.until = in.U64();
        in.Bytes(aOut.signature.data(), aOut.signature.size());
        if (!in.ok || aOut.version != kResumeVersion || length != kCodeChars)
            return false;
        aOut.code.assign(reinterpret_cast<const char*>(code), length);
        return std::all_of(aOut.code.begin(), aOut.code.end(), IsCodeChar);
    }
};

/// What a resume request carries sealed to the hub: the pass as the hub gave it and the hub's time by the host's count
inline std::vector<uint8_t> WriteResumeAsk(const std::vector<uint8_t>& aPass, uint64_t aHubNowSec)
{
    std::vector<uint8_t> out = aPass;
    locwire::PutU64(out, aHubNowSec);
    return out;
}

inline bool ReadResumeAsk(const uint8_t* aData, size_t aSize, ResumePass& aPass, uint64_t& aHubNowSec)
{
    if (aSize != ResumePass::kSize + 8 || !ResumePass::Read(aData, ResumePass::kSize, aPass))
        return false;
    locwire::In in{aData, aSize, ResumePass::kSize};
    aHubNowSec = in.U64();
    return in.ok;
}

/// The hub's judgement of a resume request
enum class ResumeVerdict : uint8_t
{
    Ok,      ///< the same code back, with the same tag and the same host key
    Bad,     ///< not this hub's pass, not this host's (the request did not open with the key it names), another protocol
    Expired, ///< the pass is out of its time (or from the hub's future)
    Stale,   ///< the request carries a hub time far from now: an old request replayed
    Live,    ///< a session with this code is alive (the pass gives nothing then)
    Full,    ///< the hub thread is at its session limit
};

struct ResumeFacts
{
    bool opened = false;       ///< the request opened under the key it names: the sender holds that key's secret
    bool parsed = false;       ///< a pass of the known layout was inside
    bool signedHere = false;   ///< the pass carries this hub's signature
    bool sameKey = false;      ///< the pass is bound to the key that sealed the request
    bool sameProtocol = false; ///< the request's game protocol is the pass's
    uint64_t nowSec = 0;       ///< the hub's clock
    uint64_t issued = 0;
    uint64_t until = 0;
    uint64_t askedSec = 0; ///< the hub time in the request
    bool live = false;     ///< a session with the code exists on this hub (any thread)
    bool full = false;     ///< sessions on this thread are at the limit
};

/// The order matters: what the pass is comes first (a stranger learns nothing about the session), whether the code is free
/// last
inline ResumeVerdict JudgeResume(const ResumeFacts& aFacts)
{
    if (!aFacts.opened || !aFacts.parsed || !aFacts.signedHere || !aFacts.sameKey || !aFacts.sameProtocol)
        return ResumeVerdict::Bad;
    if (aFacts.nowSec >= aFacts.until || aFacts.issued > aFacts.nowSec + kResumeSkewSec)
        return ResumeVerdict::Expired;
    if (aFacts.askedSec + kResumeSkewSec < aFacts.nowSec || aFacts.askedSec > aFacts.nowSec + kResumeSkewSec)
        return ResumeVerdict::Stale;
    if (aFacts.live)
        return ResumeVerdict::Live;
    if (aFacts.full)
        return ResumeVerdict::Full;
    return ResumeVerdict::Ok;
}

inline const char* ResumeReason(ResumeVerdict aVerdict)
{
    switch (aVerdict)
    {
    case ResumeVerdict::Bad: return kReasonResumeBad;
    case ResumeVerdict::Expired: return kReasonResumeExpired;
    case ResumeVerdict::Stale: return kReasonResumeStale;
    case ResumeVerdict::Live: return kReasonResumeLive;
    case ResumeVerdict::Full: return kReasonHubFull;
    case ResumeVerdict::Ok: break;
    }
    return "";
}

/// Where the peer numbers of a resumed session go on from: what the host asks (one above every number it has seen),
/// within 1..kResumeMaxNextId
inline uint32_t ResumeNextId(uint32_t aAsked)
{
    return std::clamp<uint32_t>(aAsked, 1, kResumeMaxNextId);
}

// 13.11 (security review): the low byte of a peer number is its "creator" in the session's entity numbers
// (Protocol.hpp NpcNetId / VehicleNetId: peer & 0xFF in the top byte; SdkSpawnsRules / SdkCoopRules: "ours" / "theirs" by that
// byte; Vehicles: byte 0xFE — a scene car). Numbers went up by one on every join, without a limit: after 255 joins and leaves a
// guest got byte 0 (the host's), 0xFE (scene cars) or the byte of another guest still playing — two entities of two creators
// under one number at the others, also by itself in a long session with reconnects. A number is never given twice in a session:
// the host remembers every number it welcomed (Session: m_welcomed, m_knownClients — a second Hello under a welcomed number is
// refused) and the relay maps hub numbers to game ones (RelayTransport m_hubToGame, m_staleHubIds: "the hub does not reuse
// numbers"). So the next number is the smallest not given yet whose low byte is usable and free: not 0 (the host), not 0xFE
// (scene cars), not 0xFF (all ones: proto::kAllPeers / kHubBroadcast / kNoKiller end in it), not the byte of a live participant
// and not the byte of one who left less than kPeerByteHoldMs ago — the host keeps a gone guest's place that long
// (Session::kAwayGraceMs, the same 90 s as kResumeWindowMs), then gives it up and every partner drops its entities (Bye).

/// A departed participant's low byte stays taken this long (see above)
inline constexpr uint64_t kPeerByteHoldMs = kResumeWindowMs;
/// Numbers from here up are not participants (Transport.hpp kFirstReservedPeer)
inline constexpr uint32_t kPeerNumberCeiling = 0xFFFF'FFF0u;

/// The low byte may be a participant's
inline constexpr bool PeerByteUsable(uint8_t aByte)
{
    return aByte != 0x00 && aByte != 0xFE && aByte != 0xFF;
}

/// The smallest number from aFrom (numbers below are given already) below aCeiling whose low byte is usable and not in aTaken
/// (bytes of live participants and of the recently gone). 0 — none: every usable byte is taken (the session is full of
/// numbers until a hold ends).
inline uint32_t NextPeerNumber(uint32_t aFrom, const std::array<bool, 256>& aTaken, uint32_t aCeiling = kPeerNumberCeiling)
{
    uint32_t id = std::max<uint32_t>(aFrom, 1);
    for (uint32_t step = 0; step < 256 && id < aCeiling; ++step, ++id)
    {
        const auto byte = static_cast<uint8_t>(id & 0xFF);
        if (PeerByteUsable(byte) && !aTaken[byte])
            return id;
    }
    return 0;
}

/// Departed numbers whose hold is over go; the rest mark their bytes in aTaken. aHeld: number -> until (ms)
template<typename Map>
inline void TakeHeldBytes(Map& aHeld, uint64_t aNowMs, std::array<bool, 256>& aTaken)
{
    for (auto it = aHeld.begin(); it != aHeld.end();)
    {
        if (aNowMs >= it->second)
        {
            it = aHeld.erase(it);
            continue;
        }
        aTaken[it->first & 0xFF] = true;
        ++it;
    }
}

/// The host's next step after a refusal: true — try again (the session's old host connection still lingers at the hub
/// until its timeout, the hub is full, too many new sessions from the address); false — the pass will not do
inline bool ResumeRetryable(const std::string& aReason)
{
    return aReason == kReasonResumeLive || aReason == kReasonHubFull || aReason == kReasonTooManyCreates;
}

/// The host's pass is still good: it came at aGotMs (the host's monotonic clock) and lives aLifeSec
inline bool ResumePassGood(uint64_t aGotMs, uint64_t aLifeSec, uint64_t aNowMs)
{
    return aGotMs != 0 && aLifeSec != 0 && aNowMs >= aGotMs && aNowMs - aGotMs < aLifeSec * 1000;
}

/// Half of the pass's life is gone: time to ask for a fresh one
inline bool ResumeAskDue(uint64_t aGotMs, uint64_t aLifeSec, uint64_t aNowMs)
{
    return aGotMs != 0 && aNowMs >= aGotMs && aNowMs - aGotMs >= aLifeSec * 500;
}

/// The hub's time now by the host's count: the pass's issue time plus what passed since it came
inline uint64_t ResumeHubNow(uint64_t aIssuedSec, uint64_t aGotMs, uint64_t aNowMs)
{
    return aIssuedSec + (aNowMs > aGotMs ? (aNowMs - aGotMs) / 1000 : 0);
}

/// The host's resume attempts: the next one may start (no hub connection now, the pause since the last one is over)
inline bool ResumeTryDue(bool aActive, bool aHubConnection, uint64_t aLastTryMs, uint64_t aNowMs)
{
    return aActive && !aHubConnection && (aLastTryMs == 0 || aNowMs - aLastTryMs >= kResumeRetryMs);
}

/// The host stops trying: the window since the hub was lost is over, or the hub took the request and said nothing
inline bool ResumeOver(uint64_t aSinceMs, uint64_t aSentMs, uint64_t aNowMs)
{
    return aNowMs - aSinceMs >= kResumeWindowMs || (aSentMs != 0 && aNowMs - aSentMs >= kResumeAnswerMs);
}

/// A guest waits for the host to bring the session back: it was in the session, it lost the hub itself (not a refusal,
/// not the host leaving — then the hub tells it HubPeerDown 0), and the hub said at its join that the host holds a pass
inline bool GuestWaitsForHub(bool aOn, bool aWasInSession, bool aHubLost, bool aResumable)
{
    return aOn && aWasInSession && aHubLost && aResumable;
}

/// The guest's wait goes on: within the window since the loss, and the hub's last refusal (if any) is "no such session" —
/// the host has not brought the session back yet. Another refusal (another protocol, a full session) ends the wait
inline bool GuestStillWaits(uint64_t aSinceMs, uint64_t aNowMs, bool aRefused, const std::string& aReason)
{
    return aSinceMs != 0 && aNowMs - aSinceMs < kResumeWindowMs && (!aRefused || aReason == kReasonNoSession);
}
} // namespace nc::hubrules
