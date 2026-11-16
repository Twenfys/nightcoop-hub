// rand_s (the fallback generator on Windows) is declared only if this is defined before the first <stdlib.h>
#if defined(_WIN32) && !defined(_CRT_RAND_S)
#define _CRT_RAND_S
#endif
#include <stdlib.h>

#include "NetCrypto.hpp"

#include "HubRules.hpp"
#include "Log.hpp"
#include "ProtocolCore.hpp"

#include "../vendor/monocypher/monocypher.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__APPLE__)
#include <sys/random.h>
#include <unistd.h>
#else
#include <cerrno>
#include <sys/random.h>
#endif

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <mutex>

namespace nc::netcrypto
{
namespace
{
/// The hub's signature is over this string and the certificate body, so it is good for nothing else
constexpr char kCertDomain[] = "NightCoop hub cert 1";
/// Link key transcript: the string and the host's and guest's keys
constexpr char kLinkDomain[] = "NightCoop transport 1";
/// The key of the hub's "box" for the session code
constexpr char kBoxDomain[] = "NightCoop hub box 1";
/// Sealed code: 24 nonce | u8 length | ciphertext | 16 tag
constexpr size_t kBoxNonce = 24;
constexpr size_t kMaxCode = 64;
/// At most this much held until the handshake ends
constexpr size_t kHeldMax = 8192;
constexpr size_t kHeldMaxBytes = 16u * 1024u * 1024u;

constexpr uint64_t kDueRandom = 0x4352'5950'0000'0001ull;
constexpr uint64_t kDueHeld = 0x4352'5950'0000'0002ull;
constexpr uint64_t kDueCounter = 0x4352'5950'0000'0003ull;
constexpr uint64_t kDueList = 0x4352'5950'0000'0004ull;

// Every signature has its own string, so a signature is good for nothing else
/// Hub certificate (by the root: kind Root; by the hub itself: kind Self)
constexpr char kIdentityDomain[] = "NightCoop hub identity 1";
/// Hub list (by the root)
constexpr char kListDomain[] = "NightCoop hub list 1";
/// Fingerprint of a hub's signing key
constexpr char kFingerprintDomain[] = "NightCoop hub fingerprint 1";
/// The project's location list, signed by the hub that gives it out
constexpr char kLocationsDomain[] = "NightCoop hub locations 1";
/// A session's resume pass (HubRules.hpp ResumePass), signed by the hub that gave it
constexpr char kResumeDomain[] = "NightCoop resume pass 1";
/// Root seed sealed with a passphrase: the extra data is the string and the public key (the seed cannot be swapped)
constexpr char kRootSealDomain[] = "NightCoop root key 1";
/// Argon2id for the root passphrase: 64 MiB, 3 passes (the owner's machine, once per command)
constexpr uint32_t kRootArgonBlocks = 65536;
constexpr uint32_t kRootArgonPasses = 3;
/// The client's hub list file and own-server file, next to the dll (SetDataDirectory)
constexpr char kListFile[] = "hubs.ncl";
constexpr char kOverrideFile[] = "hub.txt";
constexpr size_t kMaxListBytes = 32 * 1024;

uint64_t NowUnixSec()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

/// Date for the log (UTC, "2027-10-22"): days since 1970 -> year, month, day (Hinnant's algorithm, without the C++20
/// calendar)
std::string DateText(uint64_t aUnixSec)
{
    const int64_t days = static_cast<int64_t>(aUnixSec / 86400);
    const int64_t z = days + 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const int64_t doe = z - era * 146097;
    const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const int64_t mp = (5 * doy + 2) / 153;
    const int64_t day = doy - (153 * mp + 2) / 5 + 1;
    const int64_t month = mp < 10 ? mp + 3 : mp - 9;
    const int64_t year = yoe + era * 400 + (month <= 2 ? 1 : 0);
    return std::format("{:04}-{:02}-{:02}", year, month, day);
}

void PutU64To(std::vector<uint8_t>& aOut, uint64_t aValue)
{
    uint8_t bytes[8];
    std::memcpy(bytes, &aValue, 8);
    aOut.insert(aOut.end(), bytes, bytes + 8);
}

void PutU16To(std::vector<uint8_t>& aOut, uint16_t aValue)
{
    uint8_t bytes[2];
    std::memcpy(bytes, &aValue, 2);
    aOut.insert(aOut.end(), bytes, bytes + 2);
}

/// Signed message: the domain string and the body
std::vector<uint8_t> Signed(const char* aDomain, size_t aDomainSize, const std::vector<uint8_t>& aBody)
{
    std::vector<uint8_t> message(aDomain, aDomain + aDomainSize);
    message.insert(message.end(), aBody.begin(), aBody.end());
    return message;
}

/// Path from UTF-8 (as in Log.cpp): the plugin's directory may contain non-ASCII characters
std::filesystem::path Utf8Path(const std::string& aUtf8)
{
    return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(aUtf8.data()), aUtf8.size()));
}

/// A hub name in a certificate: lower-case letters, digits, dot and dash (a DNS name or an IPv4 address)
bool NameChars(const std::string& aName)
{
    return !aName.empty() && std::all_of(aName.begin(), aName.end(), [](char c)
                                         { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'; });
}

/// Text for the log and the menu: printable ASCII and UTF-8 bytes (a hub's label in the list may be non-Latin)
bool TextChars(const std::string& aText)
{
    return std::all_of(aText.begin(), aText.end(), [](char c)
                       { return static_cast<unsigned char>(c) >= 0x20 && c != 0x7F; });
}

std::mutex g_rootsMutex;
bool g_rootsOverride = false;
std::vector<std::array<uint8_t, 32>> g_rootsTest;

/// The client's hub list and its file directory
std::mutex g_listMutex;
std::shared_ptr<const HubList> g_list;
std::string g_dataDir;

uint64_t NowNs()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
}

std::mutex g_trustMutex;
bool g_trustOverride = false;
Trust g_trustTest;

std::string Lower(std::string aText)
{
    for (char& c : aText)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    while (!aText.empty() && aText.back() == '.')
        aText.pop_back();
    return aText;
}

/// The key of the hub's "box": BLAKE2b over the X25519 shared secret, the string and both keys
void BoxKey(const uint8_t aShared[32], const uint8_t aClient[32], const uint8_t aHub[32], uint8_t aOut[32])
{
    uint8_t info[sizeof(kBoxDomain) - 1 + 64];
    std::memcpy(info, kBoxDomain, sizeof(kBoxDomain) - 1);
    std::memcpy(info + sizeof(kBoxDomain) - 1, aClient, 32);
    std::memcpy(info + sizeof(kBoxDomain) - 1 + 32, aHub, 32);
    crypto_blake2b_keyed(aOut, 32, aShared, 32, info, sizeof(info));
}

/// Seal a code with the "box" key; aDir: 1 client -> hub, 2 hub -> client (in the extra data, so that an answer cannot
/// pass for a request)
std::vector<uint8_t> SealBox(const uint8_t aKey[32], uint8_t aDir, const std::string& aCode)
{
    if (aCode.size() > kMaxCode)
        return {};
    std::vector<uint8_t> out(kBoxNonce + 1 + aCode.size() + kTagSize);
    if (!Random(out.data(), kBoxNonce))
        return {};
    out[kBoxNonce] = static_cast<uint8_t>(aCode.size());
    const uint8_t ad[2] = {aDir, static_cast<uint8_t>(aCode.size())};
    crypto_aead_lock(out.data() + kBoxNonce + 1, out.data() + kBoxNonce + 1 + aCode.size(), aKey, out.data(), ad,
                     sizeof(ad), reinterpret_cast<const uint8_t*>(aCode.data()), aCode.size());
    return out;
}

bool OpenBox(const uint8_t aKey[32], uint8_t aDir, const std::vector<uint8_t>& aSealed, std::string& aCode)
{
    if (aSealed.size() < kBoxNonce + 1 + kTagSize)
        return false;
    const size_t length = aSealed[kBoxNonce];
    if (length > kMaxCode || aSealed.size() != kBoxNonce + 1 + length + kTagSize)
        return false;
    std::vector<uint8_t> plain(length + 1);
    const uint8_t ad[2] = {aDir, static_cast<uint8_t>(length)};
    if (crypto_aead_unlock(plain.data(), aSealed.data() + kBoxNonce + 1 + length, aKey, aSealed.data(), ad, sizeof(ad),
                           aSealed.data() + kBoxNonce + 1, length) != 0)
        return false;
    aCode.assign(reinterpret_cast<const char*>(plain.data()), length);
    return true;
}

/// Bytes under a "box" key (the resume pass and request): 24 nonce | ciphertext | 16 tag; the extra data is the direction,
/// a mark and the length, so neither a sealed code nor the other direction passes for it
std::vector<uint8_t> SealBytes(const uint8_t aKey[32], uint8_t aDir, const std::vector<uint8_t>& aPlain)
{
    if (aPlain.size() > kMaxBoxBytes)
        return {};
    std::vector<uint8_t> out(kBoxNonce + aPlain.size() + kTagSize);
    if (!Random(out.data(), kBoxNonce))
        return {};
    const uint8_t ad[4] = {aDir, 'R', static_cast<uint8_t>(aPlain.size() & 0xFF), static_cast<uint8_t>(aPlain.size() >> 8)};
    crypto_aead_lock(out.data() + kBoxNonce, out.data() + kBoxNonce + aPlain.size(), aKey, out.data(), ad, sizeof(ad),
                     aPlain.data(), aPlain.size());
    return out;
}

bool OpenBytes(const uint8_t aKey[32], uint8_t aDir, const std::vector<uint8_t>& aSealed, std::vector<uint8_t>& aPlain)
{
    if (aSealed.size() < kBoxNonce + kTagSize || aSealed.size() - kBoxNonce - kTagSize > kMaxBoxBytes)
        return false;
    const size_t size = aSealed.size() - kBoxNonce - kTagSize;
    std::vector<uint8_t> plain(size + 1);
    const uint8_t ad[4] = {aDir, 'R', static_cast<uint8_t>(size & 0xFF), static_cast<uint8_t>(size >> 8)};
    if (crypto_aead_unlock(plain.data(), aSealed.data() + kBoxNonce + size, aKey, aSealed.data(), ad, sizeof(ad),
                           aSealed.data() + kBoxNonce, size) != 0)
        return false;
    plain.resize(size);
    aPlain = std::move(plain);
    return true;
}

void PutRaw(proto::Writer& aOut, const uint8_t* aData, size_t aSize)
{
    for (size_t i = 0; i < aSize; ++i)
        aOut.PutU8(aData[i]);
}

/// CryptoHello
struct Hello
{
    uint8_t version = 0;
    uint8_t flags = 0;
    Role role = Role::None;
    std::array<uint8_t, 32> key{};
    bool hasCert = false;
    Cert cert;
    std::array<uint8_t, kSaltSize> salt{};
    std::string reason;
};

/// aSalt: the link salt, only for an encrypting side (kHelloEncrypt)
std::vector<uint8_t> MakeHello(Role aRole, uint8_t aFlags, const uint8_t* aKey, const Cert* aCert, const uint8_t* aSalt,
                               const std::string* aReason)
{
    proto::Writer out(proto::MsgType::CryptoHello);
    out.PutU8(kHelloVersion);
    uint8_t flags = aFlags;
    if (aCert)
        flags |= kHelloCert;
    if (aReason)
        flags |= kHelloRefuse;
    out.PutU8(flags);
    out.PutU8(static_cast<uint8_t>(aRole));
    uint8_t zero[32] = {};
    PutRaw(out, aKey ? aKey : zero, 32);
    if (aCert)
    {
        std::vector<uint8_t> cert;
        aCert->Write(cert);
        out.PutBytes(cert);
    }
    if (flags & kHelloEncrypt)
    {
        uint8_t zeroSalt[kSaltSize] = {};
        PutRaw(out, aSalt ? aSalt : zeroSalt, kSaltSize);
    }
    if (aReason)
        out.PutString(aReason->substr(0, std::min<size_t>(aReason->size(), 200)));
    return out.Data();
}

bool ParseHello(const uint8_t* aData, size_t aSize, Hello& aOut)
{
    proto::Reader in(aData, aSize);
    if (in.ReadHeader() != proto::MsgType::CryptoHello)
        return false;
    aOut.version = in.GetU8();
    aOut.flags = in.GetU8();
    aOut.role = static_cast<Role>(in.GetU8());
    in.GetBytes(aOut.key.data(), aOut.key.size());
    if (!in.Ok() || aOut.version < 1)
        return false;
    if (aOut.flags & kHelloCert)
    {
        uint8_t cert[Cert::kSize];
        in.GetBytes(cert, sizeof(cert));
        aOut.hasCert = in.Ok() && Cert::Read(cert, sizeof(cert), aOut.cert);
        if (!aOut.hasCert)
            return false;
    }
    if (aOut.flags & kHelloEncrypt)
        in.GetBytes(aOut.salt.data(), aOut.salt.size());
    if (aOut.flags & kHelloRefuse)
    {
        std::string reason;
        for (const char c : in.GetString().substr(0, 200))
            if (static_cast<unsigned char>(c) >= 0x20 && c != 0x7F)
                reason.push_back(c);
        aOut.reason = reason.empty() ? std::string("no reason given") : reason;
    }
    return in.Ok();
}

Role Partner(Role aMine)
{
    return aMine == Role::Host ? Role::Guest : Role::Host;
}
} // namespace

// ---------------------------------------------------------------- common

bool Random(uint8_t* aOut, size_t aSize)
{
#ifdef _WIN32
    uint8_t* const start = aOut;
    const size_t total = aSize;
    while (aSize)
    {
        const ULONG chunk = static_cast<ULONG>(std::min<size_t>(aSize, 1u << 20));
        const NTSTATUS status = BCryptGenRandom(nullptr, aOut, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status))
        {
            // Fallback: rand_s (CRT -> RtlGenRandom, the same system generator; under Wine it reads /dev/urandom), for Wine
            // builds where BCryptGenRandom without an algorithm handle does not answer
            if (log::Due(kDueRandom ^ 1, 600000))
                log::Warn("crypto: BCryptGenRandom failed (status 0x{:08x}) — the random bytes come from rand_s",
                          static_cast<uint32_t>(status));
            for (size_t i = 0; i < total; i += 4)
            {
                unsigned int word = 0;
                if (rand_s(&word) != 0)
                    return false;
                std::memcpy(start + i, &word, std::min<size_t>(4, total - i));
                crypto_wipe(&word, sizeof(word));
            }
            return true;
        }
        aOut += chunk;
        aSize -= chunk;
    }
    return true;
#elif defined(__APPLE__)
    while (aSize)
    {
        const size_t chunk = std::min<size_t>(aSize, 256);
        if (getentropy(aOut, chunk) != 0)
            return false;
        aOut += chunk;
        aSize -= chunk;
    }
    return true;
#else
    while (aSize)
    {
        const ssize_t got = getrandom(aOut, aSize, 0);
        if (got < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }
        aOut += got;
        aSize -= static_cast<size_t>(got);
    }
    return true;
#endif
}

std::string ToHex(const uint8_t* aData, size_t aSize)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(aSize * 2);
    for (size_t i = 0; i < aSize; ++i)
    {
        out.push_back(kDigits[aData[i] >> 4]);
        out.push_back(kDigits[aData[i] & 15]);
    }
    return out;
}

bool FromHex(std::string_view aText, uint8_t* aOut, size_t aSize)
{
    if (aText.size() != aSize * 2)
        return false;
    auto digit = [](char aChar) -> int
    {
        if (aChar >= '0' && aChar <= '9')
            return aChar - '0';
        if (aChar >= 'a' && aChar <= 'f')
            return aChar - 'a' + 10;
        if (aChar >= 'A' && aChar <= 'F')
            return aChar - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < aSize; ++i)
    {
        const int high = digit(aText[2 * i]);
        const int low = digit(aText[2 * i + 1]);
        if (high < 0 || low < 0)
            return false;
        aOut[i] = static_cast<uint8_t>(high * 16 + low);
    }
    return true;
}

bool IsZero(const uint8_t* aData, size_t aSize)
{
    uint8_t any = 0;
    for (size_t i = 0; i < aSize; ++i)
        any |= aData[i];
    return any == 0;
}

const char* RoleName(Role aRole)
{
    switch (aRole)
    {
    case Role::Host: return "host";
    case Role::Guest: return "guest";
    case Role::None: break;
    }
    return "nobody";
}

const char* StateName(State aState)
{
    switch (aState)
    {
    case State::Idle: return "idle";
    case State::Waiting: return "waiting";
    case State::Ready: return "encrypted";
    case State::Plain: return "plain";
    case State::Refused: return "refused";
    }
    return "?";
}

Trust HubTrust()
{
    std::lock_guard lock(g_trustMutex);
    if (g_trustOverride)
        return g_trustTest;
    Trust trust;
    trust.sign = hubrules::kHubSignKey;
    trust.box = hubrules::kHubBoxKey;
    trust.signSet = !IsZero(trust.sign.data(), trust.sign.size());
    trust.boxSet = !IsZero(trust.box.data(), trust.box.size());
    trust.hubName = hubrules::kProjectHubName;
    return trust;
}

void SetTrustForTests(const uint8_t* aSign, const uint8_t* aBox, const char* aHubName)
{
    std::lock_guard lock(g_trustMutex);
    g_trustOverride = aSign || aBox || aHubName;
    g_trustTest = Trust{};
    if (aSign)
        std::memcpy(g_trustTest.sign.data(), aSign, 32);
    if (aBox)
        std::memcpy(g_trustTest.box.data(), aBox, 32);
    g_trustTest.signSet = aSign && !IsZero(aSign, 32);
    g_trustTest.boxSet = aBox && !IsZero(aBox, 32);
    g_trustTest.hubName = aHubName ? aHubName : hubrules::kProjectHubName;
}

bool IsProjectHub(const std::string& aHost)
{
    const Trust trust = HubTrust();
    // The address may carry a port and "#fingerprint": compare the name
    const std::string host = hubrules::SplitHubAddress(aHost).host;
    return !host.empty() && Lower(host) == Lower(trust.hubName);
}

// ---------------------------------------------------------------- hub certificate

std::vector<uint8_t> HubCert::Body() const
{
    std::vector<uint8_t> out;
    out.reserve(kMaxSize);
    const size_t count = std::min(names.size(), kMaxNames);
    out.push_back(kVersion);
    out.push_back(static_cast<uint8_t>(kind));
    out.push_back(flags);
    out.push_back(static_cast<uint8_t>(count));
    PutU64To(out, serial);
    PutU64To(out, notBefore);
    PutU64To(out, notAfter);
    out.insert(out.end(), sign.begin(), sign.end());
    out.insert(out.end(), box.begin(), box.end());
    out.insert(out.end(), issuer.begin(), issuer.end());
    const std::string shownRegion = region.substr(0, std::min(region.size(), kMaxRegion));
    out.push_back(static_cast<uint8_t>(shownRegion.size()));
    out.insert(out.end(), shownRegion.begin(), shownRegion.end());
    for (size_t i = 0; i < count; ++i)
    {
        const std::string name = names[i].substr(0, std::min(names[i].size(), kMaxName));
        out.push_back(static_cast<uint8_t>(name.size()));
        out.insert(out.end(), name.begin(), name.end());
    }
    return out;
}

std::vector<uint8_t> HubCert::Write() const
{
    std::vector<uint8_t> out = Body();
    out.insert(out.end(), signature.begin(), signature.end());
    return out;
}

bool HubCert::Read(const uint8_t* aData, size_t aSize, HubCert& aOut, std::string* aWhy)
{
    const auto fail = [&](const char* aText)
    {
        if (aWhy)
            *aWhy = aText;
        return false;
    };
    aOut = HubCert{};
    if (!aData || aSize < kFixed + 64)
        return fail("too short for a hub certificate");
    if (aSize > kMaxSize)
        return fail("too long for a hub certificate");
    const size_t end = aSize - 64; // the signature is the last 64 bytes
    size_t at = 0;
    if (aData[at++] != kVersion)
        return fail("an unknown version of the hub certificate");
    const uint8_t kind = aData[at++];
    if (kind != static_cast<uint8_t>(Kind::Root) && kind != static_cast<uint8_t>(Kind::Self))
        return fail("an unknown kind of the hub certificate");
    aOut.kind = static_cast<Kind>(kind);
    aOut.flags = aData[at++];
    const size_t count = aData[at++];
    if (count > kMaxNames)
        return fail("too many names in the hub certificate");
    std::memcpy(&aOut.serial, aData + at, 8);
    std::memcpy(&aOut.notBefore, aData + at + 8, 8);
    std::memcpy(&aOut.notAfter, aData + at + 16, 8);
    at += 24;
    std::memcpy(aOut.sign.data(), aData + at, 32);
    std::memcpy(aOut.box.data(), aData + at + 32, 32);
    std::memcpy(aOut.issuer.data(), aData + at + 64, 32);
    at += 96;
    const size_t regionSize = aData[at++];
    if (regionSize > kMaxRegion || at + regionSize > end)
        return fail("a broken region in the hub certificate");
    aOut.region.assign(reinterpret_cast<const char*>(aData + at), regionSize);
    at += regionSize;
    if (!TextChars(aOut.region))
        return fail("a broken region in the hub certificate");
    for (size_t i = 0; i < count; ++i)
    {
        if (at >= end)
            return fail("a broken name in the hub certificate");
        const size_t size = aData[at++];
        if (size == 0 || size > kMaxName || at + size > end)
            return fail("a broken name in the hub certificate");
        std::string name(reinterpret_cast<const char*>(aData + at), size);
        at += size;
        if (!NameChars(name))
            return fail("a name with odd characters in the hub certificate");
        aOut.names.push_back(std::move(name));
    }
    if (at != end)
        return fail("extra bytes in the hub certificate");
    std::memcpy(aOut.signature.data(), aData + end, 64);
    return true;
}

bool HubCert::VerifiedBy(const uint8_t aKey[32]) const
{
    const auto message = Signed(kIdentityDomain, sizeof(kIdentityDomain) - 1, Body());
    return crypto_eddsa_check(signature.data(), aKey, message.data(), message.size()) == 0;
}

bool HubCert::Names(const std::string& aHost) const
{
    const std::string host = hubrules::LowerHost(aHost);
    return !host.empty() && std::any_of(names.begin(), names.end(),
                                        [&](const std::string& aName) { return hubrules::LowerHost(aName) == host; });
}

std::string HubCert::Describe() const
{
    std::string list;
    for (const auto& name : names)
        list += (list.empty() ? "" : ", ") + name;
    return std::format("{} certificate #{:016x} for {} (region {}, valid until {})", kind == Kind::Root ? "root" : "self",
                       serial, list.empty() ? std::string("no name") : list, region.empty() ? std::string("-") : region,
                       DateText(notAfter));
}

// ---------------------------------------------------------------- hub list

std::vector<uint8_t> HubList::Body() const
{
    std::vector<uint8_t> out;
    const size_t count = std::min(entries.size(), kMaxEntries);
    const size_t revokedCount = std::min(revoked.size(), kMaxRevoked);
    out.push_back(kVersion);
    out.push_back(0);
    PutU16To(out, static_cast<uint16_t>(count));
    PutU64To(out, serial);
    PutU64To(out, issued);
    out.insert(out.end(), issuer.begin(), issuer.end());
    PutU16To(out, static_cast<uint16_t>(revokedCount));
    for (size_t i = 0; i < count; ++i)
    {
        const auto& entry = entries[i];
        out.push_back(static_cast<uint8_t>(entry.letter));
        out.push_back(entry.flags);
        const std::string region = entry.region.substr(0, std::min(entry.region.size(), HubCert::kMaxRegion));
        out.push_back(static_cast<uint8_t>(region.size()));
        out.insert(out.end(), region.begin(), region.end());
        const std::string label = entry.label.substr(0, std::min(entry.label.size(), HubListEntry::kMaxLabel));
        out.push_back(static_cast<uint8_t>(label.size()));
        out.insert(out.end(), label.begin(), label.end());
    }
    for (size_t i = 0; i < revokedCount; ++i)
        out.insert(out.end(), revoked[i].begin(), revoked[i].end());
    return out;
}

std::vector<uint8_t> HubList::Write() const
{
    std::vector<uint8_t> out = Body();
    out.insert(out.end(), signature.begin(), signature.end());
    return out;
}

bool HubList::Read(const uint8_t* aData, size_t aSize, HubList& aOut, std::string* aWhy)
{
    const auto fail = [&](const char* aText)
    {
        if (aWhy)
            *aWhy = aText;
        return false;
    };
    aOut = HubList{};
    constexpr size_t kHead = 2 + 2 + 8 + 8 + 32 + 2;
    if (!aData || aSize < kHead + 64 || aSize > kMaxListBytes)
        return fail("not the size of a hub list");
    const size_t end = aSize - 64;
    if (aData[0] != kVersion)
        return fail("an unknown version of the hub list");
    uint16_t count = 0;
    uint16_t revokedCount = 0;
    std::memcpy(&count, aData + 2, 2);
    std::memcpy(&aOut.serial, aData + 4, 8);
    std::memcpy(&aOut.issued, aData + 12, 8);
    std::memcpy(aOut.issuer.data(), aData + 20, 32);
    std::memcpy(&revokedCount, aData + 52, 2);
    if (count > kMaxEntries || revokedCount > kMaxRevoked)
        return fail("too many hubs or revoked keys in the hub list");
    size_t at = kHead;
    for (size_t i = 0; i < count; ++i)
    {
        if (at + 3 > end)
            return fail("a broken hub entry in the list");
        HubListEntry entry;
        entry.letter = static_cast<char>(aData[at++]);
        entry.flags = aData[at++];
        const size_t regionSize = aData[at++];
        if (regionSize > HubCert::kMaxRegion || at + regionSize + 1 > end)
            return fail("a broken hub entry in the list");
        entry.region.assign(reinterpret_cast<const char*>(aData + at), regionSize);
        at += regionSize;
        const size_t labelSize = aData[at++];
        if (labelSize > HubListEntry::kMaxLabel || at + labelSize > end)
            return fail("a broken hub entry in the list");
        entry.label.assign(reinterpret_cast<const char*>(aData + at), labelSize);
        at += labelSize;
        if (!hubrules::IsCodeChar(entry.letter) || !TextChars(entry.region) || !TextChars(entry.label))
            return fail("a hub entry with odd characters in the list");
        if (aOut.Find(entry.letter))
            return fail("two hubs with one letter in the list");
        aOut.entries.push_back(std::move(entry));
    }
    if (at + 32u * revokedCount != end)
        return fail("the hub list does not end where it should");
    for (size_t i = 0; i < revokedCount; ++i)
    {
        std::array<uint8_t, 32> key{};
        std::memcpy(key.data(), aData + at + 32 * i, 32);
        aOut.revoked.push_back(key);
    }
    std::memcpy(aOut.signature.data(), aData + end, 64);
    return true;
}

bool HubList::VerifiedBy(const uint8_t aKey[32]) const
{
    const auto message = Signed(kListDomain, sizeof(kListDomain) - 1, Body());
    return crypto_eddsa_check(signature.data(), aKey, message.data(), message.size()) == 0;
}

bool HubList::Revoked(const std::array<uint8_t, 32>& aSign) const
{
    return std::find(revoked.begin(), revoked.end(), aSign) != revoked.end();
}

const HubListEntry* HubList::Find(char aLetter) const
{
    for (const auto& entry : entries)
        if (entry.letter == aLetter)
            return &entry;
    return nullptr;
}

// ---------------------------------------------------------------- root key (the owner's machine)

RootKeys::~RootKeys()
{
    crypto_wipe(m_seed.data(), m_seed.size());
    crypto_wipe(m_secret.data(), m_secret.size());
}

void RootKeys::Derive()
{
    std::array<uint8_t, 32> seed = m_seed; // crypto_eddsa_key_pair wipes the seed: give it a copy
    crypto_eddsa_key_pair(m_secret.data(), m_public.data(), seed.data());
    crypto_wipe(seed.data(), seed.size());
    m_ready = true;
}

bool RootKeys::Generate()
{
    if (!Random(m_seed.data(), m_seed.size()))
        return false;
    Derive();
    return true;
}

namespace
{
/// Key from the root passphrase: Argon2id (64 MiB, 3 passes), so guessing the passphrase of a leaked file is expensive
bool RootPassKey(const std::string& aPassphrase, const uint8_t aSalt[16], uint32_t aBlocks, uint32_t aPasses,
                 uint8_t aKey[32])
{
    if (aBlocks < 8 || aBlocks > (1u << 22) || aPasses < 1 || aPasses > 64)
        return false;
    std::vector<uint8_t> work;
    try
    {
        work.resize(static_cast<size_t>(aBlocks) * 1024u);
    }
    catch (const std::bad_alloc&)
    {
        return false;
    }
    crypto_argon2_config config{CRYPTO_ARGON2_ID, aBlocks, aPasses, 1};
    crypto_argon2_inputs inputs{reinterpret_cast<const uint8_t*>(aPassphrase.data()), aSalt,
                                static_cast<uint32_t>(aPassphrase.size()), 16};
    crypto_argon2(aKey, 32, work.data(), config, inputs, crypto_argon2_no_extras);
    crypto_wipe(work.data(), work.size());
    return true;
}

void RootSealAd(const std::array<uint8_t, 32>& aPublic, uint8_t aOut[sizeof(kRootSealDomain) - 1 + 32])
{
    std::memcpy(aOut, kRootSealDomain, sizeof(kRootSealDomain) - 1);
    std::memcpy(aOut + sizeof(kRootSealDomain) - 1, aPublic.data(), 32);
}
} // namespace

std::string RootKeys::Save(const std::string& aPassphrase) const
{
    std::string out;
    out.reserve(1024);
    out += "# NightCoop ROOT key — SECRET: the owner's machine only, never a hub server (nightcoop_hub --gen-root-key).\n";
    out += "# It signs hub certificates and the hub list; whoever holds it can vouch for any server to every player.\n";
    out += "# public root key: " + ToHex(m_public.data(), 32) + "\n";
    out += "nightcoop-root-key 1\npublic " + ToHex(m_public.data(), 32) + "\n";
    if (aPassphrase.empty())
    {
        // The seed goes straight into the string with room reserved: no temporary copies (they would have to be wiped)
        out += "seed ";
        static constexpr char kDigits[] = "0123456789abcdef";
        for (const uint8_t byte : m_seed)
        {
            out.push_back(kDigits[byte >> 4]);
            out.push_back(kDigits[byte & 15]);
        }
        out += "\n";
        return out;
    }
    uint8_t salt[16];
    uint8_t nonce[24];
    uint8_t key[32];
    if (!Random(salt, sizeof(salt)) || !Random(nonce, sizeof(nonce)) ||
        !RootPassKey(aPassphrase, salt, kRootArgonBlocks, kRootArgonPasses, key))
        return {};
    uint8_t ad[sizeof(kRootSealDomain) - 1 + 32];
    RootSealAd(m_public, ad);
    uint8_t cipher[32];
    uint8_t tag[16];
    crypto_aead_lock(cipher, tag, key, nonce, ad, sizeof(ad), m_seed.data(), m_seed.size());
    crypto_wipe(key, sizeof(key));
    out += std::format("argon2id {} {} {}\n", ToHex(salt, sizeof(salt)), kRootArgonBlocks, kRootArgonPasses);
    out += "sealed-seed " + ToHex(nonce, sizeof(nonce)) + " " + ToHex(cipher, sizeof(cipher)) + " " + ToHex(tag, sizeof(tag)) +
           "\n";
    return out;
}

bool RootKeys::Sealed(const std::string& aText)
{
    return aText.find("\nsealed-seed ") != std::string::npos || aText.rfind("sealed-seed ", 0) == 0;
}

bool RootKeys::Load(const std::string& aText, const std::string& aPassphrase, std::string& aError)
{
    bool header = false;
    bool havePublic = false;
    bool haveSeed = false;
    bool haveArgon = false;
    bool haveSealed = false;
    std::array<uint8_t, 32> publicKey{};
    uint8_t salt[16] = {};
    uint32_t blocks = 0;
    uint32_t passes = 0;
    uint8_t nonce[24] = {};
    uint8_t cipher[32] = {};
    uint8_t tag[16] = {};
    const std::string_view text(aText);
    size_t number = 0;
    const auto wipe = [&]
    {
        crypto_wipe(m_seed.data(), m_seed.size());
        crypto_wipe(cipher, sizeof(cipher));
    };
    for (size_t at = 0; at < text.size();)
    {
        const size_t end = std::min(text.find('\n', at), text.size());
        std::string_view line = text.substr(at, end - at);
        at = end + 1;
        ++number;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            line.remove_suffix(1);
        if (line.empty() || line[0] == '#')
            continue;
        const size_t space = line.find(' ');
        const std::string_view name = line.substr(0, space);
        const std::string_view value = space == std::string_view::npos ? std::string_view() : line.substr(space + 1);
        if (name == "nightcoop-root-key")
        {
            if (value != "1")
            {
                aError = std::format("line {}: root key file version is unknown (1 expected)", number);
                wipe();
                return false;
            }
            header = true;
        }
        else if (name == "public")
            havePublic = FromHex(value, publicKey.data(), publicKey.size());
        else if (name == "seed")
            haveSeed = FromHex(value, m_seed.data(), m_seed.size());
        else if (name == "argon2id")
        {
            const size_t a = value.find(' ');
            const size_t b = a == std::string_view::npos ? a : value.find(' ', a + 1);
            if (b != std::string_view::npos && FromHex(value.substr(0, a), salt, sizeof(salt)))
            {
                blocks = static_cast<uint32_t>(std::strtoul(std::string(value.substr(a + 1, b - a - 1)).c_str(), nullptr, 10));
                passes = static_cast<uint32_t>(std::strtoul(std::string(value.substr(b + 1)).c_str(), nullptr, 10));
                haveArgon = blocks != 0 && passes != 0;
            }
        }
        else if (name == "sealed-seed")
        {
            const size_t a = value.find(' ');
            const size_t b = a == std::string_view::npos ? a : value.find(' ', a + 1);
            haveSealed = b != std::string_view::npos && FromHex(value.substr(0, a), nonce, sizeof(nonce)) &&
                         FromHex(value.substr(a + 1, b - a - 1), cipher, sizeof(cipher)) &&
                         FromHex(value.substr(b + 1), tag, sizeof(tag));
        }
        else
        {
            // The field name does not go into the reason: a broken line may be the secret itself
            aError = std::format("line {}: unknown field", number);
            wipe();
            return false;
        }
    }
    if (!header || !havePublic)
    {
        aError = !header ? "no 'nightcoop-root-key 1' line" : "no valid 'public' line (64 hex digits)";
        wipe();
        return false;
    }
    if (haveSealed)
    {
        if (!haveArgon)
        {
            aError = "the sealed seed has no 'argon2id' line";
            wipe();
            return false;
        }
        if (aPassphrase.empty())
        {
            aError = "the root key file is sealed with a passphrase — give the passphrase";
            wipe();
            return false;
        }
        uint8_t key[32];
        if (!RootPassKey(aPassphrase, salt, blocks, passes, key))
        {
            aError = "the passphrase parameters in the file are out of range";
            wipe();
            return false;
        }
        uint8_t ad[sizeof(kRootSealDomain) - 1 + 32];
        RootSealAd(publicKey, ad);
        const bool opened =
            crypto_aead_unlock(m_seed.data(), tag, key, nonce, ad, sizeof(ad), cipher, sizeof(cipher)) == 0;
        crypto_wipe(key, sizeof(key));
        if (!opened)
        {
            aError = "the passphrase is wrong (or the file is damaged)";
            wipe();
            return false;
        }
    }
    else if (!haveSeed)
    {
        aError = "no valid 'seed' (64 hex digits) and no sealed seed";
        wipe();
        return false;
    }
    Derive();
    crypto_wipe(cipher, sizeof(cipher));
    if (m_public != publicKey)
    {
        aError = "the seed does not give the public key written in the file";
        crypto_wipe(m_secret.data(), m_secret.size());
        crypto_wipe(m_seed.data(), m_seed.size());
        m_ready = false;
        return false;
    }
    return true;
}

void RootKeys::SignCert(HubCert& aCert) const
{
    aCert.kind = HubCert::Kind::Root;
    aCert.issuer = m_public;
    const auto message = Signed(kIdentityDomain, sizeof(kIdentityDomain) - 1, aCert.Body());
    if (m_ready)
        crypto_eddsa_sign(aCert.signature.data(), m_secret.data(), message.data(), message.size());
}

void RootKeys::SignList(HubList& aList) const
{
    aList.issuer = m_public;
    const auto message = Signed(kListDomain, sizeof(kListDomain) - 1, aList.Body());
    if (m_ready)
        crypto_eddsa_sign(aList.signature.data(), m_secret.data(), message.data(), message.size());
}

// ---------------------------------------------------------------- fingerprint, roots, self-certificate

std::string Fingerprint(const uint8_t aSign[32])
{
    uint8_t message[sizeof(kFingerprintDomain) - 1 + 32];
    std::memcpy(message, kFingerprintDomain, sizeof(kFingerprintDomain) - 1);
    std::memcpy(message + sizeof(kFingerprintDomain) - 1, aSign, 32);
    uint8_t hash[32];
    crypto_blake2b(hash, sizeof(hash), message, sizeof(message));
    return hubrules::FingerprintText(hash);
}

bool FingerprintMatches(const std::string& aGiven, const uint8_t aSign[32])
{
    const std::string given = hubrules::NormalizeFingerprint(aGiven);
    return !given.empty() && given == Fingerprint(aSign);
}

std::vector<std::array<uint8_t, 32>> TrustedRoots()
{
    std::lock_guard lock(g_rootsMutex);
    if (g_rootsOverride)
        return g_rootsTest;
    std::vector<std::array<uint8_t, 32>> out;
    for (const auto& key : {hubrules::kRootKey, hubrules::kRootKeyBackup})
        if (!IsZero(key.data(), key.size()))
            out.push_back(key);
    return out;
}

void SetRootsForTests(const std::vector<std::array<uint8_t, 32>>* aRoots)
{
    std::lock_guard lock(g_rootsMutex);
    g_rootsOverride = aRoots != nullptr;
    g_rootsTest = aRoots ? *aRoots : std::vector<std::array<uint8_t, 32>>{};
}

bool IsTrustedRoot(const std::array<uint8_t, 32>& aKey)
{
    const auto roots = TrustedRoots();
    return !IsZero(aKey.data(), aKey.size()) && std::find(roots.begin(), roots.end(), aKey) != roots.end();
}

HubCert MakeSelfCert(const HubKeys& aKeys, const std::vector<std::string>& aNames, const std::string& aRegion,
                     uint64_t aNowSec)
{
    HubCert cert;
    cert.kind = HubCert::Kind::Self;
    Random(reinterpret_cast<uint8_t*>(&cert.serial), sizeof(cert.serial));
    cert.notBefore = aNowSec > 86400 ? aNowSec - 86400 : 0;
    cert.notAfter = aNowSec + 3650ull * 86400;
    for (const auto& name : aNames)
        if (cert.names.size() < HubCert::kMaxNames && NameChars(hubrules::LowerHost(name)) &&
            name.size() <= HubCert::kMaxName)
            cert.names.push_back(hubrules::LowerHost(name));
    cert.region = aRegion.substr(0, std::min(aRegion.size(), HubCert::kMaxRegion));
    aKeys.SignIdentity(cert);
    return cert;
}

// ---------------------------------------------------------------- the client's hub list

namespace
{
/// Take a list: signed by a root, with a newer serial. aPersist: write the file too (from a hub; not when it was read
/// from the file at start)
bool TakeList(const uint8_t* aData, size_t aSize, bool aPersist, std::string& aWhy)
{
    HubList list;
    if (!HubList::Read(aData, aSize, list, &aWhy))
        return false;
    if (!IsTrustedRoot(list.issuer))
    {
        aWhy = TrustedRoots().empty() ? "this build has no root key of the project to check it"
                                      : "it is not signed by the project's root";
        return false;
    }
    if (!list.VerifiedBy(list.issuer.data()))
    {
        aWhy = "the root's signature on it does not check out";
        return false;
    }
    std::string dir;
    {
        std::lock_guard lock(g_listMutex);
        if (g_list && list.serial <= g_list->serial)
        {
            aWhy.clear(); // not newer is not an error
            return false;
        }
        g_list = std::make_shared<const HubList>(list);
        dir = g_dataDir;
    }
    std::string letters;
    for (const auto& entry : list.entries)
        letters += std::format("{}{} {} ({}){}", letters.empty() ? "" : ", ", entry.letter, entry.region, entry.label,
                               entry.flags & HubListEntry::kOpen ? "" : " closed");
    log::Info("hub list #{} of the project (issued {}): {} hub(s) — {}; {} revoked key(s){}", list.serial,
              DateText(list.issued), list.entries.size(), letters.empty() ? std::string("none") : letters,
              list.revoked.size(), aPersist && !dir.empty() ? " — kept in " + std::string(kListFile) : std::string());
    if (aPersist && !dir.empty())
    {
        const auto path = Utf8Path(dir) / kListFile;
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(aData), static_cast<std::streamsize>(aSize));
        if (!out && log::Due(kDueList, 60000))
            log::Warn("hub list: cannot write {} — the list lives in memory until the game is closed", kListFile);
    }
    return true;
}
} // namespace

namespace
{
std::mutex g_seedMutex;
bool g_seedOverride = false;
std::string g_seedTest;
} // namespace

void SetSeedHubListForTests(const std::string* aHex)
{
    std::lock_guard lock(g_seedMutex);
    g_seedOverride = aHex != nullptr;
    g_seedTest = aHex ? *aHex : std::string();
}

bool TakeSeedHubList()
{
    std::string hex;
    {
        std::lock_guard lock(g_seedMutex);
        hex = g_seedOverride ? g_seedTest : std::string(hubrules::kSeedHubList);
    }
    if (hex.empty())
        return false;
    std::vector<uint8_t> bytes(hex.size() / 2);
    std::string why;
    if (hex.size() % 2 != 0 || bytes.size() > kMaxListBytes || !FromHex(hex, bytes.data(), bytes.size()))
        why = "it is not hex of a hub list";
    else if (TakeList(bytes.data(), bytes.size(), false, why))
        return true;
    if (!why.empty())
        log::Warn("hub list: the build's own list (kSeedHubList) is not taken — {}", why);
    return false;
}

void SetDataDirectory(const std::string& aDir)
{
    {
        std::lock_guard lock(g_listMutex);
        g_dataDir = aDir;
    }
    if (aDir.empty())
        return;
    // The build's initial list first: a newer one from the file replaces it, an older file is not taken (TakeList checks
    // the serial)
    TakeSeedHubList();
    std::error_code error;
    const auto path = Utf8Path(aDir) / kListFile;
    if (!std::filesystem::exists(path, error))
        return;
    std::ifstream in(path, std::ios::binary);
    std::vector<uint8_t> bytes(kMaxListBytes + 1);
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    bytes.resize(static_cast<size_t>(in.gcount()));
    std::string why;
    if (!TakeList(bytes.data(), bytes.size(), false, why) && !why.empty())
        log::Warn("hub list: {} is not taken — {} (the next hub brings a new one)", kListFile, why);
}

std::string DataDirectory()
{
    std::lock_guard lock(g_listMutex);
    return g_dataDir;
}

bool OfferHubList(const uint8_t* aData, size_t aSize, std::string& aWhy)
{
    aWhy.clear();
    return TakeList(aData, aSize, true, aWhy);
}

std::shared_ptr<const HubList> CachedHubList()
{
    std::lock_guard lock(g_listMutex);
    return g_list;
}

uint64_t CachedHubListSerial()
{
    std::lock_guard lock(g_listMutex);
    return g_list ? g_list->serial : 0;
}

void ForgetHubListForTests()
{
    std::lock_guard lock(g_listMutex);
    g_list.reset();
}

bool HubOverride(std::string& aHub, uint16_t& aPort)
{
    if (!g_hubFile.load(std::memory_order_relaxed))
        return false;
    const std::string dir = DataDirectory();
    if (dir.empty())
        return false;
    std::error_code error;
    const auto path = Utf8Path(dir) / kOverrideFile;
    if (!std::filesystem::exists(path, error))
        return false;
    std::ifstream in(path, std::ios::binary);
    std::string line;
    while (std::getline(in, line))
    {
        // The first non-comment line: "address[:port][#fingerprint]"
        const size_t start = line.find_first_not_of(" \t\r");
        if (start == std::string::npos || line[start] == '#')
            continue;
        const auto address = hubrules::SplitHubAddress(line);
        if (address.host.empty())
            continue;
        aHub = address.host + (address.fingerprint.empty() ? std::string() : "#" + address.fingerprint);
        aPort = address.port ? address.port : hubrules::kHubPort;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------- hub trust policy

const char* PolicyName(HubPolicy aPolicy)
{
    switch (aPolicy)
    {
    case HubPolicy::Open: return "open";
    case HubPolicy::Pinned: return "pinned";
    case HubPolicy::Chain: return "chain";
    case HubPolicy::Fingerprint: return "fingerprint";
    }
    return "?";
}

const char* VerdictName(HubVerdict aVerdict)
{
    switch (aVerdict)
    {
    case HubVerdict::Waiting: return "waiting";
    case HubVerdict::Vouched: return "vouched";
    case HubVerdict::Unvouched: return "unvouched";
    case HubVerdict::Refused: return "refused";
    }
    return "?";
}

HubPolicy PolicyFor(const std::string& aHub, bool aChain)
{
    const auto address = hubrules::SplitHubAddress(aHub);
    const bool pinned = IsProjectHub(address.host) && HubTrust().signSet;
    if (!aChain)
        return pinned ? HubPolicy::Pinned : HubPolicy::Open; // the old behaviour without the chain
    if (!address.fingerprint.empty())
        return HubPolicy::Fingerprint;
    if (pinned)
        return HubPolicy::Pinned;
    if (hubrules::UnderProjectDomain(address.host))
        return HubPolicy::Chain;
    return HubPolicy::Open;
}

std::vector<uint8_t> MakeHubIntroAsk(uint64_t aKnownListSerial)
{
    proto::Writer out(proto::MsgType::HubIntroAsk);
    out.PutU8(kIntroVersion);
    out.PutU64(aKnownListSerial);
    return out.Data();
}

void PutHubIntro(proto::Writer& aOut, const std::vector<uint8_t>& aRoot, const std::vector<uint8_t>& aSelf,
                 const std::vector<uint8_t>& aList)
{
    aOut.PutU8(kIntroVersion);
    aOut.PutU8(static_cast<uint8_t>((aRoot.empty() ? 0 : kIntroRoot) | (aSelf.empty() ? 0 : kIntroSelf) |
                                    (aList.empty() ? 0 : kIntroList)));
    for (const auto* part : {&aRoot, &aSelf, &aList})
    {
        if (part->empty())
            continue;
        aOut.PutU16(static_cast<uint16_t>(part->size()));
        aOut.PutBytes(*part);
    }
}

bool ReadHubIntro(proto::Reader& aIn, HubIntro& aOut)
{
    aOut = HubIntro{};
    const uint8_t version = aIn.GetU8();
    const uint8_t flags = aIn.GetU8();
    if (!aIn.Ok() || version < 1)
        return false;
    const auto part = [&](size_t aLimit, std::vector<uint8_t>& aBytes)
    {
        const uint16_t size = aIn.GetU16();
        if (!aIn.Ok() || size > aLimit || size > aIn.Remaining())
        {
            aIn.Fail();
            return false;
        }
        aBytes.resize(size);
        aIn.GetBytes(aBytes.data(), size);
        return aIn.Ok();
    };
    std::vector<uint8_t> bytes;
    if (flags & kIntroRoot)
    {
        if (!part(HubCert::kMaxSize, bytes))
            return false;
        aOut.hasRoot = HubCert::Read(bytes.data(), bytes.size(), aOut.root) && aOut.root.kind == HubCert::Kind::Root;
    }
    if (flags & kIntroSelf)
    {
        if (!part(HubCert::kMaxSize, bytes))
            return false;
        aOut.hasSelf = HubCert::Read(bytes.data(), bytes.size(), aOut.self) && aOut.self.kind == HubCert::Kind::Self;
    }
    if (flags & kIntroList)
    {
        if (!part(kMaxListBytes, aOut.list))
            return false;
    }
    return aIn.Ok();
}

HubIdentity JudgeHub(HubPolicy aPolicy, const std::string& aHub, const HubIntro* aIntro, uint64_t aNowSec)
{
    HubIdentity id;
    const auto address = hubrules::SplitHubAddress(aHub);
    const std::string host = hubrules::LowerHost(address.host);
    const Trust pin = HubTrust();
    const auto list = CachedHubList();
    const auto revoked = [&](const std::array<uint8_t, 32>& aKey) { return list && list->Revoked(aKey); };
    const auto vouch = [&](const std::array<uint8_t, 32>& aSign, const std::array<uint8_t, 32>& aBox, bool aBoxSet,
                           std::string aHow)
    {
        id.verdict = HubVerdict::Vouched;
        id.sign = aSign;
        id.hasSign = true;
        id.box = aBox;
        id.hasBox = aBoxSet && !IsZero(aBox.data(), aBox.size());
        id.how = std::move(aHow);
    };
    const auto refuse = [&](std::string aWhy)
    {
        id.verdict = HubVerdict::Refused;
        id.reason = std::move(aWhy);
    };
    // Root certificate: signed by a trusted root, for this name (aName), valid by this machine's clock, key not revoked
    const auto rootOk = [&](const HubCert& aCert, bool aName, std::string& aWhy)
    {
        if (aCert.kind != HubCert::Kind::Root)
            aWhy = "it is not a root certificate";
        else if (!IsTrustedRoot(aCert.issuer))
            aWhy = TrustedRoots().empty() ? "this build has no root key of the project to check it"
                                          : "it is signed by a key that is not the project's root";
        else if (!aCert.VerifiedBy(aCert.issuer.data()))
            aWhy = "the root's signature on it does not check out";
        else if (aName && !aCert.Names(host))
            aWhy = std::format("it is issued for {} — not for {}", aCert.Describe(), host);
        else if (aNowSec + kCertClockSlackSec < aCert.notBefore)
            aWhy = std::format("it is valid from {} — this computer's date is {} (check the date)", DateText(aCert.notBefore),
                               DateText(aNowSec));
        else if (aNowSec > aCert.notAfter + kCertClockSlackSec)
            aWhy = std::format("it expired on {} (this computer's date is {})", DateText(aCert.notAfter), DateText(aNowSec));
        else if (revoked(aCert.sign))
            aWhy = "the hub's key is revoked by the project's hub list";
        else
            return true;
        return false;
    };

    switch (aPolicy)
    {
    case HubPolicy::Open:
        id.verdict = HubVerdict::Unvouched;
        id.how = std::format("{} is not the project's hub and no fingerprint was given with its address", host);
        return id;

    case HubPolicy::Pinned:
    {
        std::string why;
        if (aIntro && aIntro->hasRoot && rootOk(aIntro->root, true, why))
        {
            vouch(aIntro->root.sign, aIntro->root.box, true, "the project's " + aIntro->root.Describe());
            return id;
        }
        // The build's old key is trusted directly (an older hub, no certificate, or the certificate failed)
        if (revoked(pin.sign))
        {
            refuse(std::format("the build's key of {} is revoked by the project's hub list{}", host,
                               why.empty() ? std::string() : " (its certificate: " + why + ")"));
            return id;
        }
        vouch(pin.sign, pin.box, pin.boxSet,
              std::format("the build's key of {}{}", pin.hubName,
                          why.empty() ? std::string() : " (its certificate did not check out: " + why + ")"));
        return id;
    }

    case HubPolicy::Chain:
    {
        std::string why = "the hub sent no certificate (a hub before 22.10, or not the project's hub)";
        if (aIntro && aIntro->hasRoot && rootOk(aIntro->root, true, why))
        {
            vouch(aIntro->root.sign, aIntro->root.box, true, "the project's " + aIntro->root.Describe());
            return id;
        }
        if (TrustedRoots().empty())
            why = "this build has no root key of the project to check it";
        refuse(std::format("{} is in the project's domain, but {}", host, why));
        return id;
    }

    case HubPolicy::Fingerprint:
    {
        const std::string want = hubrules::NormalizeFingerprint(address.fingerprint);
        if (want.empty())
        {
            refuse(std::format("the fingerprint '{}' given with the address is not 16 characters of 0-9 and A-Z (without "
                               "I, L, O, U)",
                               address.fingerprint.substr(0, std::min<size_t>(address.fingerprint.size(), 40))));
            return id;
        }
        if (aIntro && aIntro->hasSelf)
        {
            const HubCert& self = aIntro->self;
            const std::string got = Fingerprint(self.sign.data());
            if (got != want)
            {
                refuse(std::format("the hub's key has the fingerprint {}, {} was given — not the server you were given",
                                   got, want));
                return id;
            }
            // The self-certificate is signed by the same key whose fingerprint was given: the "box" in it belongs to this hub
            if (self.issuer == self.sign && self.VerifiedBy(self.sign.data()) && !revoked(self.sign))
            {
                vouch(self.sign, self.box, true, "the fingerprint " + want + " (the hub's own certificate)");
                return id;
            }
            refuse("the hub's own certificate does not check out with its key");
            return id;
        }
        std::string why = "the hub sent no certificate (a hub before 22.10, or not a hub with this fingerprint)";
        // The project's hub with a root certificate whose key matches the given fingerprint: the "box" is bound by the root's
        // signature
        if (aIntro && aIntro->hasRoot && Fingerprint(aIntro->root.sign.data()) == want && rootOk(aIntro->root, false, why))
        {
            vouch(aIntro->root.sign, aIntro->root.box, true, "the fingerprint " + want + " (the project's root certificate)");
            return id;
        }
        refuse(std::format("the hub with the fingerprint {} is not proven: {}", want, why));
        return id;
    }
    }
    refuse("an unknown policy");
    return id;
}

// ---------------------------------------------------------------- location list (server picker)

HubIdentity JudgeLocationsSigner(HubPolicy aPolicy, const std::string& aHub, const HubCert* aRoot,
                                 const std::array<uint8_t, 32>* aKey, uint64_t aNowSec)
{
    // A root certificate goes through the same decision as a session (JudgeHub): name, validity, revocation, trusted root
    if (aRoot)
    {
        HubIntro intro;
        intro.hasRoot = true;
        intro.root = *aRoot;
        const HubIdentity byRoot = JudgeHub(aPolicy, aHub, &intro, aNowSec);
        // The project's hub: if the certificate fails, the build's old key (JudgeHub decides so); fingerprint and domain as
        // decided
        if (byRoot.verdict != HubVerdict::Refused || aPolicy != HubPolicy::Fingerprint || !aKey)
            return byRoot;
    }
    if (aPolicy == HubPolicy::Fingerprint)
    {
        HubIdentity id;
        const auto address = hubrules::SplitHubAddress(aHub);
        const std::string want = hubrules::NormalizeFingerprint(address.fingerprint);
        const auto list = CachedHubList();
        if (want.empty())
        {
            id.verdict = HubVerdict::Refused;
            id.reason = "the fingerprint given with the address is not 16 characters";
        }
        else if (!aKey)
        {
            id.verdict = HubVerdict::Refused;
            id.reason = "the hub did not show its key";
        }
        else if (Fingerprint(aKey->data()) != want)
        {
            id.verdict = HubVerdict::Refused;
            id.reason = std::format("the hub's key has the fingerprint {}, {} was given", Fingerprint(aKey->data()), want);
        }
        else if (list && list->Revoked(*aKey))
        {
            id.verdict = HubVerdict::Refused;
            id.reason = "the hub's key is revoked by the project's hub list";
        }
        else
        {
            // Owning the key is proven by the list's signature (VerifyLocations checks it with this key)
            id.verdict = HubVerdict::Vouched;
            id.sign = *aKey;
            id.hasSign = true;
            id.how = "the fingerprint " + want + " (the hub's key signs the list)";
        }
        return id;
    }
    return JudgeHub(aPolicy, aHub, nullptr, aNowSec);
}

bool VerifyLocations(const uint8_t aKey[32], const std::vector<uint8_t>& aBody, const std::array<uint8_t, 64>& aSignature)
{
    const auto message = Signed(kLocationsDomain, sizeof(kLocationsDomain) - 1, aBody);
    return crypto_eddsa_check(aSignature.data(), aKey, message.data(), message.size()) == 0;
}

uint64_t UnixNowSec()
{
    return NowUnixSec();
}

std::vector<uint8_t> MakeLocalReject(const std::string& aReason)
{
    proto::Writer out(proto::MsgType::Reject);
    out.PutString("encryption: " + aReason);
    return out.Data();
}

bool IsHello(const uint8_t* aData, size_t aSize)
{
    if (aSize < 5)
        return false;
    uint32_t magic = 0;
    std::memcpy(&magic, aData, sizeof(magic));
    return magic == proto::kMagic && aData[4] == static_cast<uint8_t>(proto::MsgType::CryptoHello);
}

// ---------------------------------------------------------------- hub signature

void Cert::Body(uint8_t aOut[kBodySize]) const
{
    std::memset(aOut, 0, kBodySize);
    aOut[0] = version;
    aOut[1] = static_cast<uint8_t>(role);
    aOut[2] = flags;
    std::memcpy(aOut + 4, &hubPeer, 4);
    std::memcpy(aOut + 8, session.data(), 16);
    std::memcpy(aOut + 24, key.data(), 32);
    std::memcpy(aOut + 56, &issued, 8);
    std::memcpy(aOut + 64, &expires, 8);
}

void Cert::Write(std::vector<uint8_t>& aOut) const
{
    uint8_t body[kBodySize];
    Body(body);
    aOut.insert(aOut.end(), body, body + kBodySize);
    aOut.insert(aOut.end(), signature.begin(), signature.end());
}

bool Cert::Read(const uint8_t* aData, size_t aSize, Cert& aOut)
{
    if (aSize < kSize)
        return false;
    aOut.version = aData[0];
    aOut.role = static_cast<Role>(aData[1]);
    aOut.flags = aData[2];
    std::memcpy(&aOut.hubPeer, aData + 4, 4);
    std::memcpy(aOut.session.data(), aData + 8, 16);
    std::memcpy(aOut.key.data(), aData + 24, 32);
    std::memcpy(&aOut.issued, aData + 56, 8);
    std::memcpy(&aOut.expires, aData + 64, 8);
    std::memcpy(aOut.signature.data(), aData + kBodySize, 64);
    return aOut.version >= 1 && (aOut.role == Role::Host || aOut.role == Role::Guest);
}

bool Cert::Verify(const uint8_t aHubSign[32]) const
{
    uint8_t message[sizeof(kCertDomain) - 1 + kBodySize];
    std::memcpy(message, kCertDomain, sizeof(kCertDomain) - 1);
    Body(message + sizeof(kCertDomain) - 1);
    return crypto_eddsa_check(signature.data(), aHubSign, message, sizeof(message)) == 0;
}

HubKeys::~HubKeys()
{
    crypto_wipe(m_signSeed.data(), m_signSeed.size());
    crypto_wipe(m_signSecret.data(), m_signSecret.size());
    crypto_wipe(m_boxSecret.data(), m_boxSecret.size());
}

void HubKeys::Derive()
{
    // crypto_eddsa_key_pair wipes the seed it gets: give it a copy
    std::array<uint8_t, 32> seed = m_signSeed;
    crypto_eddsa_key_pair(m_signSecret.data(), m_signPublic.data(), seed.data());
    crypto_wipe(seed.data(), seed.size());
    crypto_x25519_public_key(m_boxPublic.data(), m_boxSecret.data());
    m_ready = true;
}

bool HubKeys::Generate()
{
    if (!Random(m_signSeed.data(), m_signSeed.size()) || !Random(m_boxSecret.data(), m_boxSecret.size()))
        return false;
    Derive();
    return true;
}

std::string HubKeys::Save() const
{
    // The secret goes straight into one string with room reserved: no temporary copies and no reallocation (an old buffer
    // is not wiped)
    std::string out;
    out.reserve(1024);
    const auto hex = [&](const uint8_t* aData)
    {
        static constexpr char kDigits[] = "0123456789abcdef";
        for (size_t i = 0; i < 32; ++i)
        {
            out.push_back(kDigits[aData[i] >> 4]);
            out.push_back(kDigits[aData[i] & 15]);
        }
    };
    out += "# NightCoop hub key — SECRET: only on the hub's server, mode 0600 (nightcoop_hub --gen-sign-key)\n";
    out += "# public sign key: ";
    hex(m_signPublic.data());
    out += "\n# public box key:  ";
    hex(m_boxPublic.data());
    out += "\nnightcoop-hub-key 1\nsign-seed ";
    hex(m_signSeed.data());
    out += "\nbox-secret ";
    hex(m_boxSecret.data());
    out += "\n";
    return out;
}

bool HubKeys::Load(const std::string& aText, std::string& aError)
{
    // Parse the fields in place, on the text itself: no copies of the secret (they would have to be wiped)
    bool header = false;
    bool seed = false;
    bool box = false;
    const std::string_view text(aText);
    size_t number = 0;
    for (size_t at = 0; at < text.size();)
    {
        const size_t end = std::min(text.find('\n', at), text.size());
        std::string_view line = text.substr(at, end - at);
        at = end + 1;
        ++number;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            line.remove_suffix(1);
        if (line.empty() || line[0] == '#')
            continue;
        const size_t space = line.find(' ');
        const std::string_view name = line.substr(0, space);
        const std::string_view value = space == std::string_view::npos ? std::string_view() : line.substr(space + 1);
        if (name == "nightcoop-hub-key")
        {
            if (value != "1")
            {
                aError = std::format("line {}: key file version '{}' is unknown (1 expected)", number,
                                     value.substr(0, std::min<size_t>(value.size(), 8)));
                return false;
            }
            header = true;
        }
        else if (name == "sign-seed")
            seed = FromHex(value, m_signSeed.data(), m_signSeed.size());
        else if (name == "box-secret")
            box = FromHex(value, m_boxSecret.data(), m_boxSecret.size());
        else
        {
            // The field name does not go into the reason: a broken line may be the secret itself
            aError = std::format("line {}: unknown field", number);
            crypto_wipe(m_signSeed.data(), m_signSeed.size());
            crypto_wipe(m_boxSecret.data(), m_boxSecret.size());
            return false;
        }
    }
    if (!header || !seed || !box)
    {
        aError = !header ? "no 'nightcoop-hub-key 1' line" : !seed ? "no valid 'sign-seed' (64 hex digits)"
                                                                 : "no valid 'box-secret' (64 hex digits)";
        crypto_wipe(m_signSeed.data(), m_signSeed.size());
        crypto_wipe(m_boxSecret.data(), m_boxSecret.size());
        return false;
    }
    Derive();
    return true;
}

Cert HubKeys::Sign(Role aRole, uint32_t aHubPeer, const std::array<uint8_t, 16>& aSession, const uint8_t aKey[32],
                   uint8_t aFlags, uint64_t aNowSec) const
{
    Cert cert;
    cert.role = aRole;
    cert.flags = aFlags;
    cert.hubPeer = aHubPeer;
    cert.session = aSession;
    std::memcpy(cert.key.data(), aKey, 32);
    cert.issued = aNowSec;
    cert.expires = aNowSec + kCertLifetimeSec;
    uint8_t message[sizeof(kCertDomain) - 1 + Cert::kBodySize];
    std::memcpy(message, kCertDomain, sizeof(kCertDomain) - 1);
    cert.Body(message + sizeof(kCertDomain) - 1);
    if (m_ready)
        crypto_eddsa_sign(cert.signature.data(), m_signSecret.data(), message, sizeof(message));
    return cert;
}

void HubKeys::SignIdentity(HubCert& aCert) const
{
    aCert.kind = HubCert::Kind::Self;
    aCert.sign = m_signPublic;
    aCert.box = m_boxPublic;
    aCert.issuer = m_signPublic;
    const auto message = Signed(kIdentityDomain, sizeof(kIdentityDomain) - 1, aCert.Body());
    if (m_ready)
        crypto_eddsa_sign(aCert.signature.data(), m_signSecret.data(), message.data(), message.size());
}

std::array<uint8_t, 64> HubKeys::SignLocations(const std::vector<uint8_t>& aBody) const
{
    std::array<uint8_t, 64> signature{};
    const auto message = Signed(kLocationsDomain, sizeof(kLocationsDomain) - 1, aBody);
    if (m_ready)
        crypto_eddsa_sign(signature.data(), m_signSecret.data(), message.data(), message.size());
    return signature;
}

bool HubKeys::OpenCode(const uint8_t aClientKey[32], const std::vector<uint8_t>& aSealed, std::string& aCode) const
{
    if (!m_ready)
        return false;
    uint8_t shared[32];
    crypto_x25519(shared, m_boxSecret.data(), aClientKey);
    if (IsZero(shared, sizeof(shared)))
        return false;
    uint8_t key[32];
    BoxKey(shared, aClientKey, m_boxPublic.data(), key);
    crypto_wipe(shared, sizeof(shared));
    const bool ok = OpenBox(key, 1, aSealed, aCode);
    crypto_wipe(key, sizeof(key));
    return ok;
}

std::vector<uint8_t> HubKeys::SealCode(const uint8_t aClientKey[32], const std::string& aCode) const
{
    if (!m_ready)
        return {};
    uint8_t shared[32];
    crypto_x25519(shared, m_boxSecret.data(), aClientKey);
    if (IsZero(shared, sizeof(shared)))
        return {};
    uint8_t key[32];
    BoxKey(shared, aClientKey, m_boxPublic.data(), key);
    crypto_wipe(shared, sizeof(shared));
    auto out = SealBox(key, 2, aCode);
    crypto_wipe(key, sizeof(key));
    return out;
}

void HubKeys::SignResumePass(hubrules::ResumePass& aPass) const
{
    const auto message = Signed(kResumeDomain, sizeof(kResumeDomain) - 1, aPass.Body());
    if (m_ready)
        crypto_eddsa_sign(aPass.signature.data(), m_signSecret.data(), message.data(), message.size());
}

bool VerifyResumePass(const hubrules::ResumePass& aPass, const uint8_t aSign[32])
{
    const auto message = Signed(kResumeDomain, sizeof(kResumeDomain) - 1, aPass.Body());
    return crypto_eddsa_check(aPass.signature.data(), aSign, message.data(), message.size()) == 0;
}

void LookAtResume(const HubKeys& aKeys, const uint8_t aClientKey[32], const std::vector<uint8_t>& aSealed,
                  uint32_t aProtocol, uint64_t aNowSec, hubrules::ResumeFacts& aFacts, hubrules::ResumePass& aPass)
{
    aFacts = hubrules::ResumeFacts{};
    aPass = hubrules::ResumePass{};
    std::vector<uint8_t> asked;
    uint64_t askedSec = 0;
    // Only the holder of the named key's secret could seal the request: the X25519 with the hub's "box" proves it
    aFacts.opened = aKeys.OpenFromClient(aClientKey, kBoxResumeToHub, aSealed, asked);
    aFacts.parsed = aFacts.opened && hubrules::ReadResumeAsk(asked.data(), asked.size(), aPass, askedSec);
    aFacts.signedHere = aFacts.parsed && VerifyResumePass(aPass, aKeys.SignPublic().data());
    aFacts.sameKey = aFacts.parsed && std::memcmp(aPass.hostKey.data(), aClientKey, 32) == 0;
    aFacts.sameProtocol = aFacts.parsed && aPass.protocol == aProtocol;
    aFacts.nowSec = aNowSec;
    aFacts.issued = aPass.issued;
    aFacts.until = aPass.until;
    aFacts.askedSec = askedSec;
}

std::vector<uint8_t> HubKeys::SealForClient(const uint8_t aClientKey[32], uint8_t aDir,
                                            const std::vector<uint8_t>& aPlain) const
{
    if (!m_ready)
        return {};
    uint8_t shared[32];
    crypto_x25519(shared, m_boxSecret.data(), aClientKey);
    if (IsZero(shared, sizeof(shared)))
        return {};
    uint8_t key[32];
    BoxKey(shared, aClientKey, m_boxPublic.data(), key);
    crypto_wipe(shared, sizeof(shared));
    auto out = SealBytes(key, aDir, aPlain);
    crypto_wipe(key, sizeof(key));
    return out;
}

bool HubKeys::OpenFromClient(const uint8_t aClientKey[32], uint8_t aDir, const std::vector<uint8_t>& aSealed,
                             std::vector<uint8_t>& aPlain) const
{
    if (!m_ready)
        return false;
    uint8_t shared[32];
    crypto_x25519(shared, m_boxSecret.data(), aClientKey);
    if (IsZero(shared, sizeof(shared)))
        return false;
    uint8_t key[32];
    BoxKey(shared, aClientKey, m_boxPublic.data(), key);
    crypto_wipe(shared, sizeof(shared));
    const bool ok = OpenBytes(key, aDir, aSealed, aPlain);
    crypto_wipe(key, sizeof(key));
    return ok;
}

// ---------------------------------------------------------------- own side

Local::~Local()
{
    crypto_wipe(m_secret.data(), m_secret.size());
}

void Local::Reset(const std::string& aHub)
{
    crypto_wipe(m_secret.data(), m_secret.size());
    m_public = {};
    m_cert = Cert{};
    m_hasCert = false;
    m_certAtMs = 0;
    m_hubId = 0;
    m_viaHub = !aHub.empty();
    m_hub = aHub;
    m_hubHost = hubrules::LowerHost(hubrules::SplitHubAddress(aHub).host);
    const Trust trust = HubTrust();
    m_projectHub = m_viaHub && IsProjectHub(aHub);
    m_on = g_enabled.load(std::memory_order_relaxed);
    if (m_on && !Random(m_secret.data(), m_secret.size()))
    {
        m_on = false;
        if (log::Due(kDueRandom, 60000))
            log::Error("crypto: the system random generator failed — this connection goes without encryption");
    }
    if (m_on)
        crypto_x25519_public_key(m_public.data(), m_secret.data());
    m_identity = HubIdentity{};
    m_needsIntro = false;
    const bool chain = g_hubChain.load(std::memory_order_relaxed);
    m_policy = m_viaHub ? PolicyFor(aHub, chain) : HubPolicy::Open;
    if (!chain || !m_viaHub || !m_on)
    {
        // Without the chain: strict only for the project's hub by the build's old key; other hubs without authentication
        m_strict = m_on && m_projectHub && trust.signSet;
        m_seal = m_on && m_projectHub && trust.boxSet;
        m_hubBox = trust.box;
        m_identity.verdict = m_strict ? HubVerdict::Vouched : HubVerdict::Unvouched;
        m_identity.sign = trust.sign;
        m_identity.box = trust.box;
        m_identity.hasSign = m_strict;
        m_identity.hasBox = m_seal;
        m_identity.how = m_strict ? std::format("the build's key of {}", trust.hubName)
                         : !m_on   ? std::string("net_crypto is off here")
                         : trust.signSet && m_viaHub ? std::string("not the project hub")
                                                     : std::string("this build has no key of the hub");
        return;
    }
    // Who this hub is: by its certificate (HubIntro before the request), the old key or the fingerprint. There is no need
    // to ask the project's hub when the build has no root: the certificate cannot be checked, and the old key is there anyway
    m_needsIntro = m_policy != HubPolicy::Open && !(m_policy == HubPolicy::Pinned && TrustedRoots().empty());
    m_strict = false;
    m_seal = false;
    m_hubBox = {};
    if (!m_needsIntro)
        Decide(nullptr, NowUnixSec());
}

bool Local::Decide(const HubIntro* aIntro, uint64_t aNowSec)
{
    if (IdentityKnown())
        return false;
    m_identity = JudgeHub(m_policy, m_hub, aIntro, aNowSec ? aNowSec : NowUnixSec());
    Apply();
    return true;
}

void LogHubIdentity(const char* aWho, const Local& aLocal, bool aIntro)
{
    const auto& identity = aLocal.Identity();
    const char* came = aIntro ? "it showed its identity" : "it showed no identity (a hub before 22.10)";
    switch (identity.verdict)
    {
    case HubVerdict::Vouched:
        log::Info("{}: the hub {} is vouched — {} (policy {}; {}); its signature on the partners' keys is required{}", aWho,
                  aLocal.HubHost(), identity.how, PolicyName(aLocal.Policy()), came,
                  identity.hasBox ? ", the session code goes sealed to its key" : "");
        break;
    case HubVerdict::Unvouched:
        log::Info("{}: the hub {} is NOT vouched — {} (policy {}): links are encrypted without authentication", aWho,
                  aLocal.HubHost(), identity.how, PolicyName(aLocal.Policy()));
        break;
    case HubVerdict::Refused:
        log::Error("{}: the hub {} is refused — {} (policy {}; {}): no session through it", aWho, aLocal.HubHost(),
                   identity.reason, PolicyName(aLocal.Policy()), came);
        break;
    case HubVerdict::Waiting:
        break;
    }
}

void TakeIntroList(const char* aWho, const HubIntro& aIntro)
{
    if (aIntro.list.empty())
        return;
    std::string why;
    if (!OfferHubList(aIntro.list.data(), aIntro.list.size(), why) && !why.empty() && log::Due(kDueList ^ 1, 60000))
        log::Warn("{}: the hub's list of hubs is not taken — {}", aWho, why);
}

void Local::Apply()
{
    const bool vouched = m_identity.verdict == HubVerdict::Vouched;
    m_strict = m_on && vouched && m_identity.hasSign;
    m_seal = m_on && vouched && m_identity.hasBox;
    m_hubBox = m_identity.box;
}

bool Local::AsksSealedReply() const
{
    if (IdentityKnown())
        return m_seal;
    // No verdict yet (HubIntro comes after the host's request): if the policy requires a checked hub, its "box" will be
    // known by the time of the answer (or the hub is refused). The old key without a "box": the code in the clear
    switch (m_policy)
    {
    case HubPolicy::Chain:
    case HubPolicy::Fingerprint: return m_on;
    case HubPolicy::Pinned: return m_on && HubTrust().boxSet;
    case HubPolicy::Open: break;
    }
    return false;
}

void Local::SetCert(const Cert& aCert, uint64_t aNowMs)
{
    m_cert = aCert;
    m_hasCert = true;
    m_certAtMs = aNowMs;
}

uint64_t Local::HubNowSec(uint64_t aNowMs) const
{
    if (!m_hasCert)
        return 0;
    return m_cert.issued + (aNowMs > m_certAtMs ? (aNowMs - m_certAtMs) / 1000 : 0);
}

bool Local::Shared(const uint8_t aTheirs[32], uint8_t aOut[32]) const
{
    crypto_x25519(aOut, m_secret.data(), aTheirs);
    if (IsZero(aOut, 32))
        return false;
    return true;
}

std::vector<uint8_t> Local::SealCodeForHub(const std::string& aCode) const
{
    if (!m_seal)
        return {};
    uint8_t shared[32];
    if (!Shared(m_hubBox.data(), shared))
        return {};
    uint8_t key[32];
    BoxKey(shared, m_public.data(), m_hubBox.data(), key);
    crypto_wipe(shared, sizeof(shared));
    auto out = SealBox(key, 1, aCode);
    crypto_wipe(key, sizeof(key));
    return out;
}

bool Local::OpenCodeFromHub(const std::vector<uint8_t>& aSealed, std::string& aCode) const
{
    if (!m_seal)
        return false;
    uint8_t shared[32];
    if (!Shared(m_hubBox.data(), shared))
        return false;
    uint8_t key[32];
    BoxKey(shared, m_public.data(), m_hubBox.data(), key);
    crypto_wipe(shared, sizeof(shared));
    const bool ok = OpenBox(key, 2, aSealed, aCode);
    crypto_wipe(key, sizeof(key));
    return ok;
}

std::vector<uint8_t> Local::SealToHubBox(const uint8_t aHubBox[32], uint8_t aDir, const std::vector<uint8_t>& aPlain) const
{
    if (!m_on)
        return {};
    uint8_t shared[32];
    if (!Shared(aHubBox, shared))
        return {};
    uint8_t key[32];
    BoxKey(shared, m_public.data(), aHubBox, key);
    crypto_wipe(shared, sizeof(shared));
    auto out = SealBytes(key, aDir, aPlain);
    crypto_wipe(key, sizeof(key));
    return out;
}

bool Local::OpenFromHubBox(const uint8_t aHubBox[32], uint8_t aDir, const std::vector<uint8_t>& aSealed,
                           std::vector<uint8_t>& aPlain) const
{
    if (!m_on)
        return false;
    uint8_t shared[32];
    if (!Shared(aHubBox, shared))
        return false;
    uint8_t key[32];
    BoxKey(shared, m_public.data(), aHubBox, key);
    crypto_wipe(shared, sizeof(shared));
    const bool ok = OpenBytes(key, aDir, aSealed, aPlain);
    crypto_wipe(key, sizeof(key));
    return ok;
}

// ---------------------------------------------------------------- replay window

uint64_t ReplayWindow::Span()
{
    return g_replayWide.load(std::memory_order_relaxed) ? kReplayWindow : kReplayWindowNarrow;
}

bool ReplayWindow::Fresh(uint64_t aCounter) const
{
    if (aCounter == 0)
        return false;
    if (aCounter > m_top)
        return true;
    // The bits keep the whole kReplayWindow whatever the switch: within the span asked they are exact. No bits with a top
    // cannot happen (Mark makes them) — refused all the same
    if (m_top - aCounter >= Span() || m_bits.empty())
        return false;
    const uint64_t at = aCounter % kReplayWindow;
    return ((m_bits[at / 64] >> (at % 64)) & 1u) == 0;
}

bool ReplayWindow::TooOld(uint64_t aCounter) const
{
    return aCounter != 0 && aCounter <= m_top && m_top - aCounter >= Span();
}

void ReplayWindow::Reset()
{
    m_top = 0;
    std::fill(m_bits.begin(), m_bits.end(), 0);
}

void ReplayWindow::Mark(uint64_t aCounter)
{
    if (m_bits.empty())
        m_bits.assign(kReplayWindow / 64, 0);
    if (aCounter > m_top)
    {
        // The window slides: the slots of counters that fell out of it are for new ones. Count steps rather than
        // "c <= aCounter": for the largest counter a loop by value would never end
        const uint64_t gap = aCounter - m_top;
        if (gap >= kReplayWindow)
        {
            std::fill(m_bits.begin(), m_bits.end(), 0);
        }
        else
        {
            uint64_t c = m_top;
            for (uint64_t step = 0; step < gap; ++step)
            {
                ++c;
                const uint64_t at = c % kReplayWindow;
                m_bits[at / 64] &= ~(uint64_t{1} << (at % 64));
            }
        }
        m_top = aCounter;
    }
    const uint64_t at = aCounter % kReplayWindow;
    m_bits[at / 64] |= uint64_t{1} << (at % 64);
}

// ---------------------------------------------------------------- tails of the talk with the hub

void PutClientExt(proto::Writer& aOut, const Local& aLocal, const std::vector<uint8_t>* aSealed)
{
    if (!aLocal.On())
        return; // off: the request goes without a tail
    aOut.PutU8(kExtCrypto);
    aOut.PutU8(static_cast<uint8_t>(kExtEncrypts | (aSealed ? kExtSealed : 0)));
    PutRaw(aOut, aLocal.Public().data(), 32);
    if (aSealed)
    {
        aOut.PutU16(static_cast<uint16_t>(aSealed->size()));
        aOut.PutBytes(*aSealed);
    }
}

bool ReadClientExt(proto::Reader& aIn, ClientExt& aOut)
{
    aOut = ClientExt{};
    if (aIn.Remaining() == 0)
        return true;
    if (aIn.GetU8() != kExtCrypto)
        return true; // someone else's tail, not ours
    aOut.flags = aIn.GetU8();
    aIn.GetBytes(aOut.key.data(), aOut.key.size());
    if (aOut.flags & kExtSealed)
    {
        const uint16_t size = aIn.GetU16();
        if (size > 512)
            return false;
        aOut.sealed.resize(size);
        aIn.GetBytes(aOut.sealed.data(), size);
    }
    aOut.present = aIn.Ok();
    return aIn.Ok();
}

void PutHubExt(proto::Writer& aOut, const Cert* aCert, const std::vector<uint8_t>* aSealed, uint8_t aFlags)
{
    if (!aCert && !aSealed)
        return;
    aOut.PutU8(kExtCrypto);
    aOut.PutU8(static_cast<uint8_t>((aCert ? kExtCert : 0) | (aSealed ? kExtSealed : 0) |
                                    (aFlags & static_cast<uint8_t>(~(kExtCert | kExtSealed)))));
    if (aCert)
    {
        std::vector<uint8_t> cert;
        aCert->Write(cert);
        aOut.PutBytes(cert);
    }
    if (aSealed)
    {
        aOut.PutU16(static_cast<uint16_t>(aSealed->size()));
        aOut.PutBytes(*aSealed);
    }
}

bool ReadHubExt(proto::Reader& aIn, HubExt& aOut)
{
    aOut = HubExt{};
    if (aIn.Remaining() == 0)
        return true;
    if (aIn.GetU8() != kExtCrypto)
        return true;
    aOut.flags = aIn.GetU8();
    if (aOut.flags & kExtCert)
    {
        uint8_t cert[Cert::kSize];
        aIn.GetBytes(cert, sizeof(cert));
        aOut.hasCert = aIn.Ok() && Cert::Read(cert, sizeof(cert), aOut.cert);
    }
    if (aOut.flags & kExtSealed)
    {
        const uint16_t size = aIn.GetU16();
        if (size > 512)
            return false;
        aOut.sealed.resize(size);
        aIn.GetBytes(aOut.sealed.data(), size);
    }
    aOut.present = aIn.Ok();
    return aIn.Ok();
}

// ---------------------------------------------------------------- link

Link::~Link()
{
    Wipe();
}

Link::Link(Link&& aOther) noexcept
{
    *this = std::move(aOther);
}

Link& Link::operator=(Link&& aOther) noexcept
{
    if (this == &aOther)
        return *this;
    Wipe();
    m_state = aOther.m_state;
    m_setup = aOther.m_setup;
    m_strict = aOther.m_strict;
    m_resolvedPending = aOther.m_resolvedPending;
    m_partnerRefused = aOther.m_partnerRefused;
    m_refusalSent = aOther.m_refusalSent;
    m_plainByTimeout = aOther.m_plainByTimeout;
    m_vouched = aOther.m_vouched;
    m_reason = std::move(aOther.m_reason);
    m_beganMs = aOther.m_beganMs;
    m_partnerKey = aOther.m_partnerKey;
    m_salt = aOther.m_salt;
    m_partnerSalt = aOther.m_partnerSalt;
    m_tx = aOther.m_tx;
    m_rx = aOther.m_rx;
    m_txDir = aOther.m_txDir;
    m_rxDir = aOther.m_rxDir;
    m_txNext = aOther.m_txNext;
    m_window = aOther.m_window;
    m_held = std::move(aOther.m_held);
    m_heldBytes = aOther.m_heldBytes;
    m_stats = aOther.m_stats;
    m_droppedReported = aOther.m_droppedReported;
    aOther.Wipe();
    aOther.m_state = State::Idle;
    aOther.m_held.clear();
    aOther.m_heldBytes = 0;
    return *this;
}

void Link::Wipe()
{
    crypto_wipe(m_tx.data(), m_tx.size());
    crypto_wipe(m_rx.data(), m_rx.size());
}

std::vector<uint8_t> Link::Begin(const Local& aLocal, const Setup& aSetup, uint64_t aNowMs)
{
    Wipe();
    m_setup = aSetup;
    m_beganMs = aNowMs;
    m_strict = aLocal.Strict() && aSetup.viaHub;
    m_partnerRefused = false;
    m_refusalSent = false;
    m_plainByTimeout = false;
    m_vouched = false;
    m_reason.clear();
    m_txNext = 1;
    m_window.Reset();
    m_txDir = aSetup.mine == Role::Host ? 1 : 2;
    m_rxDir = aSetup.mine == Role::Host ? 2 : 1;
    m_partnerKey = {};
    m_partnerSalt = {};
    if (!aLocal.On())
    {
        Resolve(State::Plain, "net_crypto is off here");
        return MakeHello(aSetup.mine, 0, nullptr, nullptr, nullptr, nullptr);
    }
    // The link salt, own for every link (DeriveLinkKeys: the link keys are its own even if the partner sent someone else's
    // public key). If the generator fails, the link is refused at once rather than left plain: plain is not allowed through
    // the project's hub
    if (!Random(m_salt.data(), m_salt.size()))
    {
        Resolve(State::Refused, "the system random generator failed — no salt for the link");
        m_refusalSent = true;
        return MakeHello(aSetup.mine, 0, nullptr, nullptr, nullptr, &m_reason);
    }
    m_state = State::Waiting;
    return MakeHello(aSetup.mine, kHelloEncrypt, aLocal.Public().data(),
                     aSetup.viaHub && aLocal.HasCert() ? &aLocal.GetCert() : nullptr, m_salt.data(), nullptr);
}

bool Link::TakeResolved()
{
    const bool resolved = m_resolvedPending;
    m_resolvedPending = false;
    return resolved;
}

void Link::Resolve(State aState, const std::string& aReason)
{
    m_state = aState;
    m_reason = aReason;
    m_resolvedPending = true;
    if (aState != State::Ready)
        Wipe();
    const std::string who = std::format("{} {}", RoleName(Partner(m_setup.mine)), m_setup.peer);
    switch (aState)
    {
    case State::Ready:
        log::Info("crypto: the link to the {} is encrypted (X25519, XChaCha20-Poly1305) — {}", who, aReason);
        break;
    case State::Plain:
        log::Warn("crypto: the link to the {} is NOT encrypted — {}", who, aReason);
        break;
    case State::Refused:
        log::Error("crypto: the link to the {} is refused — {}", who, aReason);
        break;
    default:
        break;
    }
}

bool Link::Hold(const std::vector<uint8_t>& aData, bool aReliable)
{
    if (!aReliable)
        return false;
    if (m_held.size() >= kHeldMax || m_heldBytes + aData.size() > kHeldMaxBytes)
    {
        ++m_stats.heldDropped;
        if (log::Due(kDueHeld, 10000))
            log::Warn("crypto: {} message(s), {} KB wait for the key exchange with peer {} — a reliable message is dropped "
                      "({} so far)",
                      m_held.size(), m_heldBytes / 1024, m_setup.peer, m_stats.heldDropped);
        return false;
    }
    m_heldBytes += aData.size();
    m_held.push_back({aData, true});
    return true;
}

std::vector<Link::Held> Link::TakeHeld()
{
    std::vector<Held> out(std::make_move_iterator(m_held.begin()), std::make_move_iterator(m_held.end()));
    m_held.clear();
    m_heldBytes = 0;
    return out;
}

Link::Out Link::Outgoing(const uint8_t* aData, size_t aSize, std::vector<uint8_t>& aOut)
{
    switch (m_state)
    {
    case State::Idle:
    case State::Waiting:
        return Out::Hold;
    case State::Ready:
        return Seal(aData, aSize, aOut) ? Out::Sealed : Out::Drop;
    case State::Plain:
        return Out::Plain;
    case State::Refused:
        break;
    }
    return Out::Drop;
}

bool Link::Seal(const uint8_t* aData, size_t aSize, std::vector<uint8_t>& aOut)
{
    if (m_state != State::Ready)
        return false;
    // The counter ran out (never within 2^64 messages; the check makes sure a nonce never repeats after any failure)
    if (m_txNext == 0 || m_txNext == UINT64_MAX)
    {
        if (log::Due(kDueCounter ^ m_setup.peer, 10000))
            log::Error("crypto: the message counter to peer {} is used up — nothing more is sent on this link (it has to "
                       "connect again)",
                       m_setup.peer);
        return false;
    }
    const uint64_t startedNs = NowNs();
    const uint64_t counter = m_txNext++;
    aOut.resize(kSealHeader + aSize + kTagSize);
    aOut[0] = kSealMark;
    std::memcpy(aOut.data() + 1, &counter, 8);
    uint8_t nonce[24] = {};
    std::memcpy(nonce, &counter, 8);
    nonce[8] = m_txDir;
    crypto_aead_lock(aOut.data() + kSealHeader, aOut.data() + kSealHeader + aSize, m_tx.data(), nonce, aOut.data(),
                     kSealHeader, aData, aSize);
    ++m_stats.sealed;
    m_stats.sealedBytes += aSize;
    m_stats.sealNs += NowNs() - startedNs;
    return true;
}

bool Link::Open(const uint8_t* aData, size_t aSize, std::vector<uint8_t>& aOut, bool aCount)
{
    if (m_state != State::Ready || aSize < kOverhead || aData[0] != kSealMark)
    {
        m_stats.failed += aCount ? 1 : 0;
        return false;
    }
    const uint64_t startedNs = NowNs();
    uint64_t counter = 0;
    std::memcpy(&counter, aData + 1, 8);
    if (!m_window.Fresh(counter))
    {
        m_stats.replayed += aCount ? 1 : 0;
        m_stats.tooOld += aCount && m_window.TooOld(counter) ? 1 : 0;
        return false;
    }
    const size_t size = aSize - kOverhead;
    aOut.resize(size ? size : 1);
    uint8_t nonce[24] = {};
    std::memcpy(nonce, &counter, 8);
    nonce[8] = m_rxDir;
    if (crypto_aead_unlock(aOut.data(), aData + kSealHeader + size, m_rx.data(), nonce, aData, kSealHeader,
                           aData + kSealHeader, size) != 0)
    {
        aOut.clear();
        m_stats.failed += aCount ? 1 : 0;
        return false;
    }
    aOut.resize(size);
    // 23.10 (net_replay_wide): behind more newer ones than the old window took — a batch ENet held for a resend
    if (counter < m_window.Top() && m_window.Top() - counter >= kReplayWindowNarrow)
        m_stats.late += aCount ? 1 : 0;
    m_window.Mark(counter);
    ++m_stats.opened;
    m_stats.openNs += NowNs() - startedNs;
    return true;
}

bool Link::Derive(const Local& aLocal, const std::array<uint8_t, 32>& aTheirs)
{
    uint8_t shared[32];
    if (!aLocal.Shared(aTheirs.data(), shared))
    {
        crypto_wipe(shared, sizeof(shared));
        return false;
    }
    // Transcript: the string, the host's key, the guest's key — only what both sides know the same way under any policy of
    // theirs (the keys' authenticity is checked separately by the hub's signature, if the build requires it). Both sides'
    // salts come from their CryptoHello, so the keys differ for every link of the host
    const bool host = m_setup.mine == Role::Host;
    if (host)
        DeriveLinkKeys(shared, aLocal.Public().data(), aTheirs.data(), m_salt.data(), m_partnerSalt.data(), m_tx.data(),
                       m_rx.data());
    else
        DeriveLinkKeys(shared, aTheirs.data(), aLocal.Public().data(), m_partnerSalt.data(), m_salt.data(), m_rx.data(),
                       m_tx.data());
    crypto_wipe(shared, sizeof(shared));
    return true;
}

void DeriveLinkKeys(const uint8_t aShared[32], const uint8_t aHostKey[32], const uint8_t aGuestKey[32],
                    const uint8_t aHostSalt[kSaltSize], const uint8_t aGuestSalt[kSaltSize], uint8_t aHostToGuest[32],
                    uint8_t aGuestToHost[32])
{
    constexpr size_t kDomain = sizeof(kLinkDomain) - 1;
    uint8_t info[kDomain + 64 + 2 * kSaltSize];
    std::memcpy(info, kLinkDomain, kDomain);
    std::memcpy(info + kDomain, aHostKey, 32);
    std::memcpy(info + kDomain + 32, aGuestKey, 32);
    std::memcpy(info + kDomain + 64, aHostSalt, kSaltSize);
    std::memcpy(info + kDomain + 64 + kSaltSize, aGuestSalt, kSaltSize);
    uint8_t okm[64];
    crypto_blake2b_keyed(okm, sizeof(okm), aShared, 32, info, sizeof(info));
    std::memcpy(aHostToGuest, okm, 32);
    std::memcpy(aGuestToHost, okm + 32, 32);
    crypto_wipe(okm, sizeof(okm));
}

bool Link::OnHello(const Local& aLocal, const uint8_t* aData, size_t aSize, uint64_t aNowMs)
{
    Hello hello;
    if (!ParseHello(aData, aSize, hello))
    {
        ++m_stats.failed;
        return false;
    }
    const Role partner = Partner(m_setup.mine);
    if (hello.flags & kHelloRefuse)
    {
        m_partnerRefused = true;
        Resolve(State::Refused, "the " + std::string(RoleName(partner)) + " refused it: " + hello.reason);
        return true;
    }
    if (hello.role != partner)
    {
        Resolve(State::Refused, std::format("the partner says it is a {}, a {} was expected", RoleName(hello.role),
                                            RoleName(partner)));
        return true;
    }
    if (!(hello.flags & kHelloEncrypt))
    {
        if (m_strict)
            Resolve(State::Refused, "the partner has encryption off (net_crypto) — through the project hub this build takes "
                                    "encrypted partners only; for a check without encryption turn it off on both");
        else
            Resolve(State::Plain, "the partner has net_crypto off");
        return true;
    }
    if (IsZero(hello.key.data(), hello.key.size()))
    {
        Resolve(State::Refused, "the partner sent an empty key");
        return true;
    }

    std::string vouch;
    if (m_strict)
    {
        // The signing key is that of the hub we talk to (the project hub's old key, a root certificate or a fingerprint;
        // Local::Decide), not one for the whole build
        const auto& hubSign = aLocal.HubSign();
        const Cert& own = aLocal.GetCert();
        const uint64_t hubNow = aLocal.HubNowSec(aNowMs);
        std::string why;
        if (!aLocal.HasCert())
            why = "the hub did not sign our key (an older hub, or a hub started without --sign-key)";
        else if (!own.Verify(hubSign.data()) || own.key != aLocal.Public() || own.role != m_setup.mine ||
                 (m_setup.mine == Role::Guest && own.hubPeer != m_setup.guestHubId))
            why = "our own key came back from the hub with a signature that does not check out — not the project hub, or "
                  "the way to it is tampered with";
        else if (!hello.hasCert)
            why = "the partner's key has no hub signature";
        else if (!hello.cert.Verify(hubSign.data()))
            why = "the partner's key has a wrong hub signature — a man in the middle?";
        else if (hello.cert.key != hello.key)
            why = "the hub signed another key than the partner sent — a man in the middle?";
        else if (hello.cert.role != partner)
            why = "the partner's key is signed for another role";
        else if (hello.cert.session != own.session)
            why = "the partner's key is signed for another session";
        else if (hello.cert.hubPeer != (m_setup.mine == Role::Host ? m_setup.guestHubId : 0u))
            why = std::format("the partner's key is signed for participant {} of the hub, the link is with {}",
                              hello.cert.hubPeer, m_setup.mine == Role::Host ? m_setup.guestHubId : 0u);
        else if (hello.cert.issued > hubNow + kCertSkewSec || hubNow > hello.cert.expires + kCertSkewSec)
            why = std::format("the hub's signature on the partner's key is out of date (issued {}, until {}, the hub's "
                              "clock {})",
                              hello.cert.issued, hello.cert.expires, hubNow);
        if (!why.empty())
        {
            Resolve(State::Refused, why);
            return true;
        }
        m_vouched = true;
        vouch = std::format("the partner's key is signed by the hub {} ({})", aLocal.HubHost(), aLocal.Identity().how);
    }
    else if (m_setup.viaHub)
    {
        vouch = "the keys are NOT vouched: " + (aLocal.Identity().how.empty() ? std::string("this build has no key of the hub")
                                                                              : aLocal.Identity().how);
    }
    else
    {
        vouch = "without authentication: a direct connection, no hub to vouch for the keys";
    }

    m_partnerKey = hello.key;
    m_partnerSalt = hello.salt;
    if (!Derive(aLocal, hello.key))
    {
        Resolve(State::Refused, "the partner's key is not a usable X25519 key");
        return true;
    }
    Resolve(State::Ready, vouch);
    return true;
}

Link::In Link::Incoming(const Local& aLocal, const uint8_t* aData, size_t aSize, std::vector<uint8_t>& aOut,
                        uint64_t aNowMs)
{
    if (!aData || aSize == 0)
        return In::Drop;
    const bool sealed = aData[0] == kSealMark;
    const bool hello = !sealed && IsHello(aData, aSize);
    switch (m_state)
    {
    case State::Idle:
        ++m_stats.early;
        return In::Drop;

    case State::Waiting:
        if (hello)
        {
            OnHello(aLocal, aData, aSize, aNowMs);
            return In::Handshake;
        }
        if (sealed)
        {
            // The partner encrypts, but its CryptoHello is still on the way (lost and resent): unreliable data overtook it — drop
            ++m_stats.early;
            return In::Drop;
        }
        // Plain data came first: the partner does not encrypt (an older build) — an encrypting side sends CryptoHello before
        // anything else
        if (m_strict)
        {
            ++m_stats.plain;
            Resolve(State::Refused, "the partner does not encrypt (an older build?) — through the project hub this build "
                                    "takes encrypted partners only");
            return In::Drop;
        }
        Resolve(State::Plain, "the partner does not encrypt (an older build?)");
        return In::DeliverAsIs;

    case State::Ready:
        if (sealed)
            return Open(aData, aSize, aOut) ? In::DeliverOpened : In::Drop;
        if (hello)
        {
            Hello again;
            const bool parsed = ParseHello(aData, aSize, again);
            if (parsed && (again.flags & kHelloRefuse))
            {
                m_partnerRefused = true;
                Resolve(State::Refused, std::string("the ") + RoleName(Partner(m_setup.mine)) + " refused it: " +
                                            again.reason);
                return In::Handshake;
            }
            // A repeat of the same exchange: silently; another key or salt in the middle of a link is not taken (link keys do not
            // change)
            if (!parsed || again.key != m_partnerKey || again.salt != m_partnerSalt)
                ++m_stats.plain;
            return In::Handshake;
        }
        ++m_stats.plain;
        return In::Drop;

    case State::Plain:
        if (hello)
        {
            Hello late;
            if (!ParseHello(aData, aSize, late))
                return In::Handshake;
            if (late.flags & kHelloRefuse)
            {
                m_partnerRefused = true;
                Resolve(State::Refused, std::string("the ") + RoleName(Partner(m_setup.mine)) + " refused it: " +
                                            late.reason);
            }
            else if ((late.flags & kHelloEncrypt) && m_plainByTimeout)
            {
                // We already send in the clear while the partner encrypts: the link cannot work — an honest refusal instead of silent
                // breakage
                Resolve(State::Refused, "the partner's key exchange came after the wait was over — connect again");
            }
            else if ((late.flags & kHelloEncrypt) && aLocal.On() == false)
            {
                log::Info("crypto: peer {} offers encryption — net_crypto is off here, the link stays plain", m_setup.peer);
            }
            return In::Handshake;
        }
        if (sealed)
        {
            ++m_stats.early;
            return In::Drop;
        }
        return In::DeliverAsIs;

    case State::Refused:
        if (hello)
            return In::Handshake;
        return In::Drop;
    }
    return In::Drop;
}

bool Link::Tick(const Local& aLocal, uint64_t aNowMs)
{
    (void)aLocal;
    if (m_state != State::Waiting || aNowMs < m_beganMs + kHelloWaitMs)
        return false;
    if (m_strict)
    {
        // 23.10: say what came from the partner meanwhile — its sealed
        // data (it is up and encrypts, its CryptoHello got lost) or nothing (another build, or the hub never told it about us)
        Resolve(State::Refused,
                std::format("no key exchange from the partner in {} s — {}", kHelloWaitMs / 1000,
                            m_stats.early > 0 ? std::format("its encrypted data came ({}), its key exchange did not",
                                                            m_stats.early)
                                              : std::string("nothing came from it on this link")));
        return true;
    }
    // Sealed data from the partner has arrived: it encrypts and its CryptoHello is on the way — wait three times longer,
    // then refuse
    if (m_stats.early > 0)
    {
        if (aNowMs < m_beganMs + 3 * kHelloWaitMs)
            return false;
        Resolve(State::Refused, "the partner encrypts, but its key exchange did not come");
        return true;
    }
    m_plainByTimeout = true;
    Resolve(State::Plain, std::format("no key exchange from the partner in {} s (an older build?)", kHelloWaitMs / 1000));
    return true;
}

std::vector<uint8_t> Link::TakeRefusal()
{
    if (m_state != State::Refused || m_partnerRefused || m_refusalSent)
        return {};
    m_refusalSent = true;
    return MakeHello(m_setup.mine, 0, nullptr, nullptr, nullptr, &m_reason);
}

std::string Link::Describe() const
{
    switch (m_state)
    {
    case State::Ready:
        return m_vouched ? "signed" : m_setup.viaHub ? "unsigned" : "direct";
    case State::Plain:
        return "plain";
    case State::Idle:
    case State::Waiting:
        return "waiting";
    case State::Refused:
        return "refused";
    }
    return "?";
}

uint64_t Link::TakeDropped()
{
    const uint64_t total = m_stats.failed + m_stats.replayed + m_stats.plain + m_stats.early;
    const uint64_t fresh = total - std::min(total, m_droppedReported);
    m_droppedReported = total;
    return fresh;
}

uint64_t Link::TakeLate()
{
    const uint64_t fresh = m_stats.late - std::min(m_stats.late, m_lateReported);
    m_lateReported = m_stats.late;
    return fresh;
}

void ReportDrops(Link& aLink, uint32_t aPeer, const char* aWho)
{
    // 23.10 (net_replay_wide): what the old window would have dropped as too old
    if (aLink.PendingLate() && log::Due(0x4352'5950'0002'0000ull ^ aPeer, 10000))
    {
        const uint64_t late = aLink.TakeLate();
        log::Info("{}: crypto: {} message(s) from peer {} in the last 10 s came behind more than {} newer ones and were "
                  "taken ({} all along; net_replay_wide — before 23.10 dropped as too old)",
                  aWho, late, aPeer, kReplayWindowNarrow, aLink.GetStats().late);
    }
    if (!aLink.PendingDrops() || !log::Due(0x4352'5950'0001'0000ull ^ aPeer, 10000))
        return;
    const uint64_t fresh = aLink.TakeDropped();
    const auto& s = aLink.GetStats();
    log::Warn("{}: crypto: {} message(s) from peer {} dropped in the last 10 s (link {}; all along: {} failed the check, "
              "{} replayed or too old ({} of them behind more than {} newer ones), {} not encrypted after the key "
              "exchange, {} encrypted before our keys)",
              aWho, fresh, aPeer, aLink.Describe(), s.failed, s.replayed, s.tooOld, ReplayWindow::Span(), s.plain,
              s.early);
}
} // namespace nc::netcrypto
