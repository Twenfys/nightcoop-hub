// NightCoop hub: a meeting point and relay.
//
// Why: a direct connection needs a reachable address at the host — a public IP and a forwarded port — which most
// players do not have. Outgoing connections work from anywhere, so both sides come here and the hub relays bytes
// between them. It also tells each side the address it sees (HubAddrSeen): the hybrid transport punches a direct path
// with it, and the bulk of the traffic then bypasses the hub.
//
// What it does NOT do is parse the session. Game messages ride inside HubPayload as opaque bytes; the hub only knows
// whom to hand them to. That keeps it small: the less it knows of the game protocol, the less often it has to be updated
// together with the mod. It does not impose the game protocol version either: the session's host sets it, and a guest
// with another one is refused. The hub's own protocol is the Hub* message numbers and the header magic
// (src/ProtocolCore.hpp).
//
// The heart of the hub is src/HubServer.*.
//
//   nightcoop_hub [port] [--shards N|auto] [--seconds N] [--max-clients N] [--stats N] [--max-per-address N] [--max-sessions N]
//                 [--max-guests N] [--max-packet-kb N] [--idle-seconds N] [--log-dir DIR] [--bench]
//                 [--cookie off|pressure|always] [--cookie-busy N] [--guard on|off] [--guard-pool-mb N] [--max-queue-kb N]
//                 [--rcvbuf-kb N] [--resume on|off] [--sign-key FILE | --sign-key-credential NAME]
//   nightcoop_hub --gen-sign-key FILE
//
// --stats N: every N seconds a "stats:" line — sessions and connections, UDP datagrams and bytes both ways, received and
// sent HubPayloads, the hub's CPU time (share of one core), counts (sessions created, joins, refusals). By default every
// 300 s and only when there was something to count; 0 turns it off.
// --max-clients: the ceiling of ENet connections (64 by default, ENet's limit is 4095). Other limits: HubServer::Limits.
// --cpu-limit N: new sessions go only to threads under N % of a core (their share over the last seconds); with every
// thread there, a new session is refused as "the hub is full" and the location answer says full — the client takes
// another server. Joins and sessions coming back after a restart are not gated, only --max-clients holds them. 0
// (default): no gate, as before 26.10.
// --bench: a load test from one machine — per-address limits and closing silent connections are off.
// --cookie: connection pass (src/HubCookie.hpp): pressure (default) — required while --cookie-busy slots are taken (half
// of --max-clients by default); always — always (clients that carry no pass cannot get in: switch to it when "passes
// given" in the stats line matches "connected"); off — no passes.
// --guard (src/EnetGuard.hpp): data waiting in ENet's queues stays within limits before ENet allocates it: per
// connection --max-packet-kb plus 1 MiB behind it, 128 KiB own share each, and a pool above the shares of
// --guard-pool-mb for the whole hub (384 by default), split between threads; a connection outside a session sends no
// fragments. off: no guard.
// --max-queue-kb: at most this much in ENet's queue to one recipient (32768 by default); whoever does not take it is
// closed by the hub. 0: no limit.
// --rcvbuf-kb: receive buffer of each thread's socket (4096 by default; Linux caps it at net.core.rmem_max, and a log
// line at start says what it got). 0: ENet's 256 KiB.
// --resume on|off: sessions outlive a restart of the hub (on by default; needs the signing key): the host of each session
// holds a resume pass signed with the hub's key and takes its code back with it after the restart, the guests come back
// by the code. off: no passes, the resume requests are skipped — a restart ends the sessions through the hub.
//
// Log: the hub's lines go to stdout — for a service that is the systemd journal (journalctl -u nightcoop-hub) or the
// Docker log, each with its own size and rate limits. The nightcoop.log file is written only with --log-dir: a log file
// without limits, with a line per wrong session code, would be a way to fill the server's disk.
//
// Hub key (transport encryption, src/NetCrypto.hpp):
//   nightcoop_hub --gen-sign-key FILE   create a key: the secret goes into FILE (new, mode 0600, an existing one is
//                                       never overwritten), the public keys to the output with lines for
//                                       src/HubRules.hpp; the hub does not start
//   --sign-key FILE                     sign peers' keys with this key (if the file does not read, the hub does not
//                                       start)
//   --sign-key-credential NAME          the same from $CREDENTIALS_DIRECTORY/NAME (systemd LoadCredential: only the
//                                       service sees the file)
//   nightcoop_hub --check-sign-key FILE check a key file without network: the public keys to the output
// Without a key, sessions go unsigned (a log line at start): clients encrypt links without authentication.

// Project root and hub certificates (src/NetCrypto.hpp): the mod's build carries the project's public root key; every
// hub shows a client, before its request, a certificate from the root (its keys, names, region, validity) and a
// self-certificate (its keys signed by itself — for the fingerprint of an own server). New servers need no new mod
// build. The root's secret stays on the owner's machine and never reaches a server.
//   on the owner's machine:
//   nightcoop_hub --gen-root-key FILE        create the root (asks for a passphrase; empty — none); lines for
//                                            HubRules.hpp
//   nightcoop_hub --root-public FILE         the root's public key from the file (no passphrase needed)
//   nightcoop_hub --issue-cert ROOT HUB.pub OUT --name NAME [--name NAME…] [--region R] [--days N]
//                                            a certificate for a hub (HUB.pub: the output of --hub-public on its server)
//   nightcoop_hub --sign-list ROOT LIST.txt OUT   the project's hub list (letters, regions, revoked keys)
//   nightcoop_hub --show FILE                what a certificate or a list holds and who signed it
//   on the hub's server:
//   nightcoop_hub --hub-public KEY           the hub's public keys and fingerprint (into HUB.pub, for the root's owner)
//   --hub-cert FILE                          the root's certificate for this hub (the keys must match, otherwise it is
//                                            not shown; a bad file does not stop the hub — a "! hub: …" line in the log)
//   --hub-list FILE                          the project's hub list, for clients with an older one
//   --hub-name NAME, --region R              names and region in the self-certificate (for players' logs)
//   --sign-key-auto FILE                     like --sign-key, but creates the key if there is none (Docker: the first
//                                            start makes its own key)
// --hub-cert and --hub-list files are reread every 30 s if they changed: a new certificate or list without a restart.
//
// Server picker: the mod's "Server" window and session creation ask the hub, without a connection, for its state (open,
// full, load), its key and the project's location list:
//   --locations FILE                         the location list (locations.txt, the same on the project's hubs): the hub
//                                            signs it with its key (needs --sign-key) and gives it out; reread every 30 s
//   nightcoop_hub --check-locations FILE     check the file without network or key (parsing and answer size)
// Without --locations the hub answers with its state and key only (right for an own server).

// Threads: --shards N (or auto — by the number of cores) runs N threads, each with its own HubServer and port: thread 0
// is the entry [port], the others follow from [port] + 10 (47810, 47811, …; open them in the firewall together with
// the entry port). A session lives entirely in one thread; the client comes to the entry port and the hub sends it to
// the session's thread port (HubRedirect). --max-clients and --max-sessions are per thread, per-address request counts
// are shared. Each thread has its own "stats[i]:" line with the CPU share of that thread. One thread by default.

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#endif

#include "../../src/HubRules.hpp"
#include "../../src/HubServer.hpp"
#include "../../src/Log.hpp"
#include "../../src/NetCrypto.hpp"
#include "../../src/ProtocolCore.hpp"

#include "../../vendor/monocypher/monocypher.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iostream>
#include <format>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace
{
std::atomic<bool> g_stop{false};

void OnSignal(int)
{
    g_stop.store(true);
}

/// CPU time of the own thread, s: each hub thread has its own share of a core (std::clock is the whole process)
double ThreadCpuSeconds()
{
#ifdef _WIN32
    FILETIME created, exited, kernel, user;
    if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user))
        return 0.0;
    const auto ticks = [](const FILETIME& aTime)
    { return (static_cast<uint64_t>(aTime.dwHighDateTime) << 32) | aTime.dwLowDateTime; };
    return static_cast<double>(ticks(kernel) + ticks(user)) / 1e7;
#else
    timespec spent{};
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &spent) != 0)
        return 0.0;
    return static_cast<double>(spent.tv_sec) + static_cast<double>(spent.tv_nsec) / 1e9;
#endif
}

struct Options
{
    int seconds = 0;
    int statsEvery = 300;
    bool statsAlways = false;
    size_t shards = 1;
};

/// Lines for src/HubRules.hpp: the hub's public keys as byte arrays
std::string KeyLine(const char* aName, const std::array<uint8_t, 32>& aKey)
{
    std::string out = std::string("inline constexpr std::array<uint8_t, 32> ") + aName + "{";
    for (size_t i = 0; i < aKey.size(); ++i)
    {
        char byte[8];
        std::snprintf(byte, sizeof(byte), "%s0x%02x", i ? ", " : "", aKey[i]);
        out += byte;
    }
    return out + "};";
}

/// The secret goes only into a new file with mode 0600 (an existing one is never overwritten). The text is wiped in any
/// case
bool WriteNewSecret(const std::string& aPath, std::string& aText, const char* aWhatIfExists)
{
#ifdef _WIN32
    const int fd = _open(aPath.c_str(), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
#else
    const int fd = open(aPath.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
#endif
    if (fd < 0)
    {
        std::printf("cannot create %s: %s%s\n", aPath.c_str(), std::strerror(errno), errno == EEXIST ? aWhatIfExists : "");
        crypto_wipe(aText.data(), aText.size());
        return false;
    }
#ifdef _WIN32
    const bool written = _write(fd, aText.data(), static_cast<unsigned>(aText.size())) == static_cast<int>(aText.size());
    _close(fd);
#else
    // Mode 0600 under any umask; on disk before saying "done"
    const bool written = fchmod(fd, 0600) == 0 && write(fd, aText.data(), aText.size()) == static_cast<ssize_t>(aText.size()) &&
                         fsync(fd) == 0;
    close(fd);
#endif
    crypto_wipe(aText.data(), aText.size());
    if (!written)
    {
        std::printf("cannot write %s: %s — the file is left as it is: delete it and try again\n", aPath.c_str(),
                    std::strerror(errno));
        return false;
    }
    return true;
}

/// --gen-sign-key FILE: a new hub key. The secret goes only into a new file with mode 0600 (an existing one is never
/// overwritten: losing the old key means new mod builds for everyone); only the public keys go to the output. aQuiet
/// (--sign-key-auto, an own server in Docker): no lines for HubRules.hpp — an own server's key does not go into the
/// build, players take its fingerprint
int GenerateKey(const std::string& aPath, bool aQuiet = false)
{
    nc::netcrypto::HubKeys keys;
    if (!keys.Generate())
    {
        std::printf("the system random generator did not answer — no key created\n");
        return 1;
    }
    std::string text = keys.Save();
    if (!WriteNewSecret(aPath, text, " — the file exists already: the old key is never overwritten (a new key gives the hub a new fingerprint)"))
        return 1;
    if (aQuiet)
    {
        std::printf("Hub key created: %s (a secret, mode 0600 — keep it on the server; its fingerprint is in the log line below)\n",
                    aPath.c_str());
        return 0;
    }
    std::printf("Hub key created: %s (a secret, mode 0600 — keep it on the server)\n\n", aPath.c_str());
    std::printf("Public signing key: %s\n", nc::netcrypto::ToHex(keys.SignPublic().data(), 32).c_str());
    std::printf("Public box key: %s\n\n", nc::netcrypto::ToHex(keys.BoxPublic().data(), 32).c_str());
    std::printf("Lines for src/HubRules.hpp (in place of the zeros):\n%s\n%s\n", KeyLine("kHubSignKey", keys.SignPublic()).c_str(),
                KeyLine("kHubBoxKey", keys.BoxPublic()).c_str());
    return 0;
}

/// Hub key from a file (--sign-key) or from $CREDENTIALS_DIRECTORY (--sign-key-credential). An error stops the hub:
/// signing was asked for explicitly
std::shared_ptr<nc::netcrypto::HubKeys> LoadKey(const std::string& aPath, bool aCredential)
{
    std::FILE* file = std::fopen(aPath.c_str(), "rb");
    if (!file)
    {
        std::printf("cannot open the hub key %s: %s\n", aPath.c_str(), std::strerror(errno));
        return nullptr;
    }
    // No stdio buffer: otherwise a copy of the secret would stay in a buffer that nobody wipes
    std::setvbuf(file, nullptr, _IONBF, 0);
#ifndef _WIN32
    // The key file is read only by the service and root: a mode wider than 0600 gets a warning (systemd puts a credential
    // itself, 0400)
    struct stat info{};
    if (!aCredential && fstat(fileno(file), &info) == 0 && (info.st_mode & 077))
        std::printf("! the hub key %s is readable not only by its owner (mode %03o) — chmod 600 %s\n", aPath.c_str(),
                    static_cast<unsigned>(info.st_mode & 0777), aPath.c_str());
#else
    (void)aCredential;
#endif
    std::string text(4096, '\0');
    const size_t got = std::fread(text.data(), 1, text.size(), file);
    std::fclose(file);
    text.resize(got);
    auto keys = std::make_shared<nc::netcrypto::HubKeys>();
    std::string error;
    const bool ok = got > 0 && got < 4096 && keys->Load(text, error);
    crypto_wipe(text.data(), text.size());
    if (!ok)
    {
        std::printf("the hub key %s is not valid: %s\n", aPath.c_str(), got >= 4096 ? "the file is too big" : error.c_str());
        return nullptr;
    }
    return keys;
}

// ---------------------------------------------------------------- project root and hub certificates

namespace cr = nc::netcrypto;

uint64_t UnixNow()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

/// A console line without echo (the root passphrase). Not a console (piped in): the line as is. The prompt goes to
/// stderr, so the commands' output can be redirected to a file
std::string ReadSecretLine(const char* aPrompt)
{
    std::fprintf(stderr, "%s", aPrompt);
    std::fflush(stderr);
    std::string line;
#ifdef _WIN32
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    const bool console = input != INVALID_HANDLE_VALUE && GetConsoleMode(input, &mode);
    if (console)
        SetConsoleMode(input, mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
    std::getline(std::cin, line);
    if (console)
        SetConsoleMode(input, mode);
#else
    termios saved{};
    const bool tty = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &saved) == 0;
    if (tty)
    {
        termios quiet = saved;
        quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
    }
    std::getline(std::cin, line);
    if (tty)
        tcsetattr(STDIN_FILENO, TCSANOW, &saved);
#endif
    std::fprintf(stderr, "\n");
    if (!line.empty() && line.back() == '\r')
        line.pop_back();
    return line;
}

/// The whole file, at most aLimit bytes; false: missing, empty or bigger
bool ReadFileBytes(const std::string& aPath, size_t aLimit, std::vector<uint8_t>& aOut)
{
    std::FILE* file = std::fopen(aPath.c_str(), "rb");
    if (!file)
        return false;
    aOut.assign(aLimit + 1, 0);
    const size_t got = std::fread(aOut.data(), 1, aOut.size(), file);
    std::fclose(file);
    aOut.resize(got);
    return got > 0 && got <= aLimit;
}

/// A public file (certificate, list): write anew
bool WritePublicFile(const std::string& aPath, const std::vector<uint8_t>& aBytes)
{
    std::FILE* file = std::fopen(aPath.c_str(), "wb");
    if (!file)
        return false;
    const bool written = std::fwrite(aBytes.data(), 1, aBytes.size(), file) == aBytes.size();
    return std::fclose(file) == 0 && written;
}

/// The root from a file; asks for the passphrase if the seed is sealed with one
std::unique_ptr<cr::RootKeys> LoadRoot(const std::string& aPath)
{
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(aPath, 4096, bytes))
    {
        std::printf("cannot read the root %s: no file, it is empty or bigger than 4 KiB\n", aPath.c_str());
        return nullptr;
    }
    std::string text(bytes.begin(), bytes.end());
    crypto_wipe(bytes.data(), bytes.size());
    std::string passphrase;
    if (cr::RootKeys::Sealed(text))
        passphrase = ReadSecretLine("Root passphrase: ");
    auto root = std::make_unique<cr::RootKeys>();
    std::string error;
    const bool ok = root->Load(text, passphrase, error);
    crypto_wipe(text.data(), text.size());
    crypto_wipe(passphrase.data(), passphrase.size());
    if (!ok)
    {
        std::printf("the root %s is not valid: %s\n", aPath.c_str(), error.c_str());
        return nullptr;
    }
    return root;
}

/// --gen-root-key FILE: the project's root (the owner's machine). The passphrase is optional (empty: the seed in the
/// clear in the file)
int GenerateRoot(const std::string& aPath)
{
    std::error_code exists;
    if (std::filesystem::exists(aPath, exists))
    {
        std::printf("%s exists already — the old root is never overwritten (a new root means a new mod build for everyone)\n", aPath.c_str());
        return 1;
    }
    cr::RootKeys root;
    if (!root.Generate())
    {
        std::printf("the system random generator did not answer — no root created\n");
        return 1;
    }
    std::string passphrase = ReadSecretLine("Root passphrase (empty — none: then the file holds the secret in the clear): ");
    if (!passphrase.empty())
    {
        std::string again = ReadSecretLine("Once more: ");
        const bool same = again == passphrase;
        crypto_wipe(again.data(), again.size());
        if (!same)
        {
            crypto_wipe(passphrase.data(), passphrase.size());
            std::printf("the passphrases differ — no root created\n");
            return 1;
        }
    }
    std::string text = root.Save(passphrase);
    const bool sealed = !passphrase.empty();
    crypto_wipe(passphrase.data(), passphrase.size());
    if (text.empty())
    {
        std::printf("cannot write the root: the random generator or Argon2 (64 MiB of memory) did not answer\n");
        return 1;
    }
    if (!WriteNewSecret(aPath, text, " — the file exists already: the old root is never overwritten (a new root means a new mod build for everyone)"))
        return 1;
    std::printf("Project root created: %s (%s). A secret: only on the owner's machine and in a separate offline copy; never put\n"
                "it on hub servers — it signs the certificates of every hub.\n\n",
                aPath.c_str(), sealed ? "the seed is sealed with the passphrase: Argon2id 64 MiB" : "no passphrase");
    std::printf("Root public key: %s\n\n", cr::ToHex(root.Public().data(), 32).c_str());
    std::printf("Line for src/HubRules.hpp (in place of the zeros of kRootKey; a backup root — kRootKeyBackup):\n%s\n",
                KeyLine("kRootKey", root.Public()).c_str());
    return 0;
}

/// --root-public FILE: the root's public key from the file (no passphrase: it is written in the clear)
int RootPublic(const std::string& aPath)
{
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(aPath, 4096, bytes))
    {
        std::printf("cannot read the root %s\n", aPath.c_str());
        return 1;
    }
    const std::string text(bytes.begin(), bytes.end());
    crypto_wipe(bytes.data(), bytes.size());
    const size_t at = text.find("\npublic ");
    std::array<uint8_t, 32> key{};
    if (at == std::string::npos || !cr::FromHex(std::string_view(text).substr(at + 8, 64), key.data(), key.size()))
    {
        std::printf("%s has no public line\n", aPath.c_str());
        return 1;
    }
    std::printf("Root public key: %s\n%s\n", cr::ToHex(key.data(), 32).c_str(), KeyLine("kRootKey", key).c_str());
    return 0;
}

/// --hub-public KEY: the hub's public keys and fingerprint, for the root's owner and --issue-cert (the file is not
/// secret)
int HubPublic(const std::string& aKeyPath)
{
    const auto keys = LoadKey(aKeyPath, false);
    if (!keys)
        return 1;
    std::printf("# NightCoop hub public keys — not secret: give this file to the owner of the project's root\n"
                "# (nightcoop_hub --issue-cert ROOT this-file OUT --name NAME)\n"
                "# fingerprint %s\n"
                "nightcoop-hub-public 1 %s %s\n",
                cr::Fingerprint(keys->SignPublic().data()).c_str(), cr::ToHex(keys->SignPublic().data(), 32).c_str(),
                cr::ToHex(keys->BoxPublic().data(), 32).c_str());
    return 0;
}

/// The line "nightcoop-hub-public 1 <sign> <box>" from a --hub-public file
bool ReadHubPublic(const std::string& aPath, std::array<uint8_t, 32>& aSign, std::array<uint8_t, 32>& aBox)
{
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(aPath, 4096, bytes))
        return false;
    const std::string text(bytes.begin(), bytes.end());
    const size_t at = text.find("nightcoop-hub-public 1 ");
    if (at == std::string::npos)
        return false;
    const std::string_view rest = std::string_view(text).substr(at + 23);
    return rest.size() >= 129 && cr::FromHex(rest.substr(0, 64), aSign.data(), 32) && rest[64] == ' ' &&
           cr::FromHex(rest.substr(65, 64), aBox.data(), 32);
}

/// --issue-cert ROOT HUB.pub OUT --name …: a certificate for a hub from the root (the owner's machine)
int IssueCert(const std::string& aRootPath, const std::string& aPublicPath, const std::string& aOut,
              const std::vector<std::string>& aNames, const std::string& aRegion, int aDays)
{
    cr::HubCert cert;
    if (!ReadHubPublic(aPublicPath, cert.sign, cert.box))
    {
        std::printf("%s has no line 'nightcoop-hub-public 1 …' (nightcoop_hub --hub-public KEY prints it on the hub's "
                    "server)\n",
                    aPublicPath.c_str());
        return 1;
    }
    if (aNames.empty() || aNames.size() > cr::HubCert::kMaxNames)
    {
        std::printf("1 to %zu hub names are needed (--name): the names players reach it by\n", cr::HubCert::kMaxNames);
        return 1;
    }
    for (const auto& name : aNames)
    {
        const std::string lower = nc::hubrules::LowerHost(name);
        const bool chars = !lower.empty() && lower.size() <= cr::HubCert::kMaxName &&
                           std::all_of(lower.begin(), lower.end(), [](char c)
                                       { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'; });
        if (!chars)
        {
            std::printf("'%s' is not a DNS name (letters, digits, dot, hyphen; up to %zu characters)\n", name.c_str(),
                        cr::HubCert::kMaxName);
            return 1;
        }
        if (!nc::hubrules::UnderProjectDomain(lower))
            std::printf("! the name %s is outside the project's domain %s: clients check the certificate only of hubs *.%s\n",
                        lower.c_str(), nc::hubrules::kProjectDomain, nc::hubrules::kProjectDomain);
        cert.names.push_back(lower);
    }
    if (aRegion.size() > cr::HubCert::kMaxRegion)
    {
        std::printf("a region is up to %zu characters ('eu', 'na-east', 'asia')\n", cr::HubCert::kMaxRegion);
        return 1;
    }
    if (aDays < 1 || aDays > 3650)
    {
        std::printf("--days is from 1 to 3650\n");
        return 1;
    }
    const auto root = LoadRoot(aRootPath);
    if (!root)
        return 1;
    const uint64_t now = UnixNow();
    cr::Random(reinterpret_cast<uint8_t*>(&cert.serial), sizeof(cert.serial));
    cert.notBefore = now - 86400; // the hub's and the players' clocks may lag
    cert.notAfter = now + static_cast<uint64_t>(aDays) * 86400;
    cert.region = aRegion;
    root->SignCert(cert);
    const auto bytes = cert.Write();
    cr::HubCert back;
    if (!cr::HubCert::Read(bytes.data(), bytes.size(), back) || !back.VerifiedBy(root->Public().data()))
    {
        std::printf("the certificate failed its own check — not written\n");
        return 1;
    }
    if (!WritePublicFile(aOut, bytes))
    {
        std::printf("cannot write %s: %s\n", aOut.c_str(), std::strerror(errno));
        return 1;
    }
    std::printf("Certificate written: %s — %s\nHub key: fingerprint %s. Not a secret: put it on the hub's server (--hub-cert %s).\n"
                "Root: %s%s\n",
                aOut.c_str(), back.Describe().c_str(), cr::Fingerprint(back.sign.data()).c_str(), aOut.c_str(),
                cr::ToHex(root->Public().data(), 32).c_str(),
                cr::IsTrustedRoot(root->Public()) ? " (this build's root)"
                                                  : " — NOT this build's root: clients of this build will not accept it (kRootKey)");
    return 0;
}

/// --sign-list ROOT LIST.txt OUT: the project's hub list. Text:
///   serial N                               list serial: bigger than the previous one (clients never take an older one)
///   hub E open eu Europe (Frankfurt)       letter (the first character of a 7-character code: e.hub.nightcoop.net),
///                                          open|closed, region, label
///   revoke <64 hex>                        a revoked hub signing key (leaked, hub removed)
int SignListCommand(const std::string& aRootPath, const std::string& aSource, const std::string& aOut)
{
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(aSource, 256 * 1024, bytes))
    {
        std::printf("cannot read the list %s\n", aSource.c_str());
        return 1;
    }
    const std::string text(bytes.begin(), bytes.end());
    cr::HubList list;
    size_t number = 0;
    for (size_t at = 0; at < text.size();)
    {
        const size_t end = std::min(text.find('\n', at), text.size());
        std::string line = text.substr(at, end - at);
        at = end + 1;
        ++number;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        const size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos || line[start] == '#')
            continue;
        line.erase(0, start);
        const auto word = [&](size_t& aAt)
        {
            const size_t from = line.find_first_not_of(' ', aAt);
            if (from == std::string::npos)
            {
                aAt = line.size();
                return std::string();
            }
            const size_t to = std::min(line.find(' ', from), line.size());
            aAt = to;
            return line.substr(from, to - from);
        };
        size_t at2 = 0;
        const std::string kind = word(at2);
        if (kind == "serial")
            list.serial = std::strtoull(word(at2).c_str(), nullptr, 10);
        else if (kind == "hub")
        {
            const std::string letter = word(at2);
            const std::string state = word(at2);
            cr::HubListEntry entry;
            entry.region = word(at2);
            const size_t label = line.find_first_not_of(' ', at2);
            entry.label = label == std::string::npos ? std::string() : line.substr(label);
            if (letter.size() != 1 || !nc::hubrules::IsCodeChar(static_cast<char>(std::toupper(static_cast<unsigned char>(letter[0])))) ||
                (state != "open" && state != "closed") || entry.region.empty() ||
                entry.region.size() > cr::HubCert::kMaxRegion || entry.label.size() > cr::HubListEntry::kMaxLabel)
            {
                std::printf("line %zu: 'hub LETTER open|closed REGION LABEL' — a letter of %s, a region up to %zu characters, "
                            "a label up to %zu bytes\n",
                            number, std::string(nc::hubrules::kCodeAlphabet).c_str(), cr::HubCert::kMaxRegion,
                            cr::HubListEntry::kMaxLabel);
                return 1;
            }
            entry.letter = static_cast<char>(std::toupper(static_cast<unsigned char>(letter[0])));
            entry.flags = state == "open" ? cr::HubListEntry::kOpen : 0;
            if (list.Find(entry.letter))
            {
                std::printf("line %zu: the letter %c is in the list already\n", number, entry.letter);
                return 1;
            }
            list.entries.push_back(entry);
        }
        else if (kind == "revoke")
        {
            std::array<uint8_t, 32> key{};
            if (!cr::FromHex(word(at2), key.data(), key.size()))
            {
                std::printf("line %zu: revoke — 64 hex digits of a hub's signing key\n", number);
                return 1;
            }
            list.revoked.push_back(key);
        }
        else
        {
            std::printf("line %zu: unknown word '%s' (serial, hub, revoke)\n", number, kind.c_str());
            return 1;
        }
    }
    if (list.serial == 0 || list.entries.size() > cr::HubList::kMaxEntries || list.revoked.size() > cr::HubList::kMaxRevoked)
    {
        std::printf("a serial above zero is needed; hubs — up to %zu, revoked keys — up to %zu\n", cr::HubList::kMaxEntries,
                    cr::HubList::kMaxRevoked);
        return 1;
    }
    const auto root = LoadRoot(aRootPath);
    if (!root)
        return 1;
    list.issued = UnixNow();
    root->SignList(list);
    const auto out = list.Write();
    cr::HubList back;
    std::string why;
    if (!cr::HubList::Read(out.data(), out.size(), back, &why) || !back.VerifiedBy(root->Public().data()))
    {
        std::printf("the list failed its own check (%s) — not written\n", why.c_str());
        return 1;
    }
    if (!WritePublicFile(aOut, out))
    {
        std::printf("cannot write %s: %s\n", aOut.c_str(), std::strerror(errno));
        return 1;
    }
    std::printf("Hub list #%llu written: %s (%zu bytes, %zu hubs, %zu revoked keys). Not a secret: put it on every hub\n"
                "of the project (--hub-list %s) — hubs give it to clients with an older list and reread it every 30 s.\n",
                static_cast<unsigned long long>(list.serial), aOut.c_str(), out.size(), list.entries.size(),
                list.revoked.size(), aOut.c_str());
    // The initial list in the build (optional): a new host's first session goes straight to the nearest hub
    const std::string hex = cr::ToHex(out.data(), out.size());
    std::printf("\nLine for src/HubRules.hpp (the initial list in the build, optional — in place of the empty kSeedHubList):\n"
                "inline constexpr std::string_view kSeedHubList =");
    for (size_t at = 0; at < hex.size(); at += 96)
        std::printf("\n    \"%s\"", hex.substr(at, 96).c_str());
    std::printf(";\n");
    return 0;
}

/// --show FILE: a certificate or a list — what it holds and who signed it
int Show(const std::string& aPath)
{
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(aPath, 64 * 1024, bytes))
    {
        std::printf("cannot read %s\n", aPath.c_str());
        return 1;
    }
    cr::HubCert cert;
    std::string whyCert;
    if (cr::HubCert::Read(bytes.data(), bytes.size(), cert, &whyCert))
    {
        const bool signedOk = cert.VerifiedBy(cert.issuer.data());
        std::printf("%s\nhub signing key %s (fingerprint %s)\nhub box key     %s\nsigned by       %s — the signature is %s%s\n",
                    cert.Describe().c_str(), cr::ToHex(cert.sign.data(), 32).c_str(),
                    cr::Fingerprint(cert.sign.data()).c_str(), cr::ToHex(cert.box.data(), 32).c_str(),
                    cr::ToHex(cert.issuer.data(), 32).c_str(), signedOk ? "valid" : "NOT VALID",
                    cert.kind == cr::HubCert::Kind::Self ? " (a self-certificate)"
                    : cr::IsTrustedRoot(cert.issuer)     ? " (this build's root)"
                                                         : " (NOT this build's root)");
        return signedOk ? 0 : 1;
    }
    cr::HubList list;
    std::string whyList;
    if (cr::HubList::Read(bytes.data(), bytes.size(), list, &whyList))
    {
        const bool signedOk = list.VerifiedBy(list.issuer.data());
        std::printf("hub list #%llu, %zu hubs, %zu revoked keys; signed by %s — the signature is %s%s\n",
                    static_cast<unsigned long long>(list.serial), list.entries.size(), list.revoked.size(),
                    cr::ToHex(list.issuer.data(), 32).c_str(), signedOk ? "valid" : "NOT VALID",
                    cr::IsTrustedRoot(list.issuer) ? " (this build's root)" : " (NOT this build's root)");
        for (const auto& entry : list.entries)
            std::printf("  %c  %s  %-8s %s%s\n", entry.letter, nc::hubrules::LetterHubName(entry.letter).c_str(),
                        entry.region.c_str(), entry.label.c_str(), entry.flags & cr::HubListEntry::kOpen ? "" : "  (closed)");
        for (const auto& key : list.revoked)
            std::printf("  revoked %s\n", cr::ToHex(key.data(), 32).c_str());
        return signedOk ? 0 : 1;
    }
    std::printf("%s is neither a certificate (%s) nor a hub list (%s)\n", aPath.c_str(), whyCert.c_str(), whyList.c_str());
    return 1;
}

/// What the hub shows clients: the --hub-cert / --hub-list files and the self-certificate
struct IntroFiles
{
    std::string certPath;
    std::string listPath;
    std::filesystem::file_time_type certTime{};
    std::filesystem::file_time_type listTime{};
};

std::filesystem::file_time_type FileTime(const std::string& aPath)
{
    std::error_code error;
    const auto time = std::filesystem::last_write_time(aPath, error);
    return error ? std::filesystem::file_time_type{} : time;
}

/// Builds HubIntro: the certificate (checked against own keys), the self-certificate, the list. A bad file neither stops
/// the hub nor reaches clients: at start, a log line and the hub runs without that part (clients of the project's hub
/// use the build's old key); on a reread, the previous part stays (a half-written new file does not remove a good one).
/// A certificate for other keys is never shown: with it, clients would refuse this hub's signatures. Returns the number
/// of errors
int BuildIntro(IntroFiles& aFiles, const cr::HubKeys* aKeys, const std::vector<uint8_t>& aSelf, nc::HubIntroSource& aSource,
               bool aFirst)
{
    const auto previous = aSource.Get();
    auto data = std::make_shared<nc::HubIntroSource::Data>();
    data->self = aSelf;
    int errors = 0;
    const auto fail = [&](const std::string& aWhy, bool aCert)
    {
        ++errors;
        const bool keep = !aFirst && previous && !(aCert ? previous->root.empty() : previous->list.empty());
        nc::log::Error("hub: {} — {}", aWhy,
                       keep ? "the previous one stays"
                            : aCert ? "the hub goes without a root certificate (clients of hub.nightcoop.net use the build's "
                                      "key; hubs by letter are refused)"
                                    : "the hub goes without a hub list");
        if (keep && aCert)
            data->root = previous->root;
        if (keep && !aCert)
        {
            data->list = previous->list;
            data->listSerial = previous->listSerial;
        }
    };
    cr::HubCert cert;
    if (!aFiles.certPath.empty())
    {
        std::vector<uint8_t> bytes;
        std::string why;
        aFiles.certTime = FileTime(aFiles.certPath);
        if (!ReadFileBytes(aFiles.certPath, cr::HubCert::kMaxSize, bytes) ||
            !cr::HubCert::Read(bytes.data(), bytes.size(), cert, &why))
            fail("the certificate " + aFiles.certPath + " does not read" + (why.empty() ? "" : ": " + why), true);
        else if (cert.kind != cr::HubCert::Kind::Root)
            fail(aFiles.certPath + " is not a root certificate", true);
        else if (!aKeys || cert.sign != aKeys->SignPublic() || cert.box != aKeys->BoxPublic())
            fail("the certificate " + aFiles.certPath + " is for other keys (" + cert.Describe() +
                     "): no hub key (--sign-key) or another one",
                 true);
        else if (!cert.VerifiedBy(cert.issuer.data()))
            fail("the root's signature on " + aFiles.certPath + " does not check out", true);
        else
        {
            const uint64_t now = UnixNow();
            if (!cr::TrustedRoots().empty() && !cr::IsTrustedRoot(cert.issuer))
                nc::log::Warn("hub: the certificate {} is signed by a root this build does not know — clients of this "
                              "build refuse it",
                              aFiles.certPath);
            if (now > cert.notAfter)
                nc::log::Warn("hub: the certificate expired ({}) — clients refuse it (hub.nightcoop.net falls back to the "
                              "build's key); issue a new one: nightcoop_hub --issue-cert",
                              cert.Describe());
            else if (cert.notAfter - now < 30ull * 86400)
                nc::log::Warn("hub: the certificate ends in {} day(s) — issue a new one soon ({})",
                              (cert.notAfter - now) / 86400, cert.Describe());
            data->root = std::move(bytes);
            nc::log::Info("hub: shows clients its {}", cert.Describe());
        }
    }
    if (!aFiles.listPath.empty())
    {
        std::vector<uint8_t> bytes;
        std::string why;
        cr::HubList list;
        aFiles.listTime = FileTime(aFiles.listPath);
        if (!ReadFileBytes(aFiles.listPath, 32 * 1024, bytes) || !cr::HubList::Read(bytes.data(), bytes.size(), list, &why))
            fail("the hub list " + aFiles.listPath + " does not read" + (why.empty() ? "" : ": " + why), false);
        else if (!list.VerifiedBy(list.issuer.data()))
            fail("the root's signature on the hub list " + aFiles.listPath + " does not check out", false);
        else
        {
            if (!data->root.empty() && list.issuer != cert.issuer)
                nc::log::Warn("hub: the hub list {} is signed by another root than this hub's certificate", aFiles.listPath);
            data->listSerial = list.serial;
            data->list = std::move(bytes);
            nc::log::Info("hub: gives clients with an older list the hub list #{} ({} hub(s), {} revoked key(s))",
                          list.serial, list.entries.size(), list.revoked.size());
        }
    }
    aSource.Set(data);
    return errors;
}

/// Every 30 s: the certificate and list files changed — build again (a new certificate or list without a restart)
void ReloadIntroIfChanged(IntroFiles& aFiles, const cr::HubKeys* aKeys, const std::vector<uint8_t>& aSelf,
                          nc::HubIntroSource& aSource)
{
    const bool certChanged = !aFiles.certPath.empty() && FileTime(aFiles.certPath) != aFiles.certTime;
    const bool listChanged = !aFiles.listPath.empty() && FileTime(aFiles.listPath) != aFiles.listTime;
    if (!certChanged && !listChanged)
        return;
    nc::log::Info("hub: {} changed on disk — reading again", certChanged ? aFiles.certPath : aFiles.listPath);
    BuildIntro(aFiles, aKeys, aSelf, aSource, false);
}

// ---------------------------------------------------------------- location list (server picker)
//
// The owner's locations.txt, the same on every project hub: "serial N" and a line per location "letter|- open|closed
// region address[:port][#fingerprint] label" (hubrules::ParseLocationsText). The hub signs it with its key and gives it
// out on a client's connectionless question (the mod's "Server" window, session creation).

struct LocationsFile
{
    std::string path;
    std::filesystem::file_time_type time{};
};

std::string DescribeLocations(const nc::hubrules::LocationList& aList)
{
    std::string out;
    for (const auto& entry : aList.entries)
        out += std::format("{}{} {} {} «{}» {}", out.empty() ? "" : "; ", entry.letter ? std::string(1, entry.letter) : "-",
                           entry.region, entry.Address(), entry.label, nc::hubrules::LocStateName(entry.state));
    return out;
}

/// Read, sign, give out. A bad file does not stop the hub: at start, no list (clients take it from another hub or from
/// the build); on a reread, the previous one stays. Returns the number of errors
int BuildLocations(LocationsFile& aFile, const cr::HubKeys* aKeys, const nc::HubIntroSource& aIntro,
                   nc::HubLocationsSource& aSource, bool aFirst)
{
    const auto previous = aSource.Get();
    const auto fail = [&](const std::string& aWhy)
    {
        nc::log::Error("hub: the locations {} — {}: {}", aFile.path, aWhy,
                       !aFirst && previous ? "the previous list stays" : "the hub answers without a list");
        return 1;
    };
    aFile.time = FileTime(aFile.path);
    // No file yet is not an error: setup.sh adds --locations to every hub, the owner puts the file later (push-locations.ps1)
    // and the hub takes it within 30 s, without a restart
    std::error_code missing;
    if (aFirst && !std::filesystem::exists(aFile.path, missing))
    {
        nc::log::Info("hub: no locations file {} yet — the hub answers with its state and key only; the file is taken when it "
                      "appears (checked every 30 s)",
                      aFile.path);
        return 0;
    }
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(aFile.path, 64 * 1024, bytes))
        return fail("do not read");
    nc::hubrules::LocationList list;
    std::string why;
    if (!nc::hubrules::ParseLocationsText(std::string(bytes.begin(), bytes.end()), list, why))
        return fail(why);
    if (!aKeys)
        return fail("need the hub's key (--sign-key): the list goes signed by it");
    if (previous && list.serial < previous->serial)
        nc::log::Warn("hub: the locations {} have serial {} — lower than {} before: clients that have the newer one keep it",
                      aFile.path, list.serial, previous->serial);
    list.issued = UnixNow();
    auto data = std::make_shared<nc::HubLocationsSource::Data>();
    data->body = nc::hubrules::WriteLocationBody(list);
    data->signature = aKeys->SignLocations(data->body);
    data->serial = list.serial;
    data->count = list.entries.size();
    // This hub's own line: "closed" there stops new sessions here at once, without a restart; the current ones live on
    const auto& sign = aKeys->SignPublic();
    const bool projectKey = std::equal(sign.begin(), sign.end(), nc::hubrules::kHubSignKey.begin());
    const auto* self = nc::hubrules::SelfLocation(list, cr::Fingerprint(sign.data()), projectKey);
    data->closedHere = self && self->state == nc::hubrules::LocState::Closed;
    const auto was = previous ? previous->closedHere : false;
    if (aFirst || data->closedHere != was)
        nc::log::Info("hub: this hub in the list — {}", !self ? std::string("not there (it serves the list, its state is its own)")
                                                       : std::format("{} {} {}{}", self->letter ? std::string(1, self->letter) : "-",
                                                                     self->region, nc::hubrules::LocStateName(self->state),
                                                                     data->closedHere
                                                                         ? ": no new sessions here, the current ones live on"
                                                                         : ""));
    // Does the answer with the list (and the root certificate, if there is one) fit into a client's question
    nc::hubrules::LocTell probe;
    probe.body = data->body;
    const auto intro = aIntro.Get();
    if (intro && !intro->root.empty())
        probe.proof = intro->root;
    const size_t size = nc::hubrules::LocTellSize(true, probe, true);
    if (size > nc::hubrules::kLocAskList)
        return fail(std::format("the answer with it is {} bytes — more than {} (shorter labels or fewer locations)", size,
                                nc::hubrules::kLocAskList));
    aSource.Set(data);
    nc::log::Info("hub: gives clients the locations list #{} ({} location(s): {}) — the answer is {} of {} bytes",
                  list.serial, list.entries.size(), DescribeLocations(list), size, nc::hubrules::kLocAskList);
    return 0;
}

/// nightcoop_hub --check-locations FILE: check the owner's file without network or key
int CheckLocations(const std::string& aPath)
{
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(aPath, 64 * 1024, bytes))
    {
        std::printf("cannot read %s\n", aPath.c_str());
        return 1;
    }
    nc::hubrules::LocationList list;
    std::string why;
    if (!nc::hubrules::ParseLocationsText(std::string(bytes.begin(), bytes.end()), list, why))
    {
        std::printf("%s: %s\n", aPath.c_str(), why.c_str());
        return 1;
    }
    nc::hubrules::LocTell probe;
    probe.body = nc::hubrules::WriteLocationBody(list);
    const size_t plain = nc::hubrules::LocTellSize(true, probe, true);
    std::printf("location list #%llu, %zu locations: %s\nthe answer with the list — %zu bytes (with a root certificate ~%zu) of %zu\n",
                static_cast<unsigned long long>(list.serial), list.entries.size(), DescribeLocations(list).c_str(), plain,
                plain + 211, nc::hubrules::kLocAskList);
    return plain + 211 > nc::hubrules::kLocAskList ? 1 : 0;
}

/// One hub thread: turns of its HubServer (already started), the "stats" line and the stop. aLabel: "stats:" for a
/// single hub, "stats[i]:" for threads. aEvery30s, on thread 0: reread the certificate and list files
void RunShard(nc::HubServer& aHub, const Options& aOptions, const std::string& aLabel,
              const std::function<void()>& aEvery30s = {})
{
    const auto started = std::chrono::steady_clock::now();
    auto statsAt = started;
    auto reloadAt = started;
    double statsCpu = ThreadCpuSeconds();
    aHub.TakeStats(); // ENet marks from this moment
    size_t peakClients = 0;
    size_t peakSessions = 0;

    while (!g_stop.load())
    {
        aHub.Service(10);
        peakClients = std::max(peakClients, aHub.ClientCount() + aHub.IdleCount());
        peakSessions = std::max(peakSessions, aHub.SessionCount());
        if (aEvery30s && std::chrono::steady_clock::now() - reloadAt >= std::chrono::seconds(30))
        {
            reloadAt = std::chrono::steady_clock::now();
            aEvery30s();
        }

        if (aOptions.statsEvery > 0)
        {
            const auto now = std::chrono::steady_clock::now();
            const double span = std::chrono::duration<double>(now - statsAt).count();
            if (span >= aOptions.statsEvery)
            {
                const double cpu = ThreadCpuSeconds();
                const double cpuShare = 100.0 * (cpu - statsCpu) / span;
                const auto st = aHub.TakeStats();
                const bool busy = st.datagramsIn || st.sessionsCreated || st.joinsAccepted || st.joinsRefused ||
                                  st.refusedLimits || st.refusedClosed || st.idleClosed || st.redirected || st.connectsRefused ||
                                  st.cookiesTold || st.guardPreAuth || st.guardPeerFull || st.guardPoolFull || st.intros ||
                                  st.locationAsks || st.sessionsResumed || st.resumesRefused || st.refusedBusy ||
                                  aHub.SessionCount() || aHub.ClientCount();
                // UDP/IP adds 28 bytes per datagram on top of ENet's count
                if (aOptions.statsAlways || busy)
                    std::printf("%s %.1f s sessions %zu clients %zu | in %.0f dgram/s %.1f KB/s | out %.0f dgram/s "
                                "%.1f KB/s | payload in %.0f/s %.1f KB/s, sent %.0f/s %.1f KB/s (%.0f%% reliable) | cpu "
                                "%.1f%% | peak %zu session(s) %zu connection(s), %zu without a session now | created %llu, "
                                "joined %llu, joins refused %llu, refused by a limit %llu, refused as closed %llu, repeats "
                                "ignored %llu, silent "
                                "closed %llu, payloads dropped %llu, biggest payload %llu B, sent to another thread %llu | "
                                "connected %llu, passes given %llu, CONNECT without a pass dropped %llu, a pass is %s | "
                                "guard: dropped %llu outside a session, %llu over a connection's limit, %llu over the pool, "
                                "pool peak %.1f MB; guests of a gone host left to the silent check %llu; turns cut %llu; "
                                "closed for a full queue %llu | keys signed %llu, sealed codes %llu, sealed codes not "
                                "opened %llu | identity shown %llu (with the hub list %llu, asks over the limit %llu) | "
                                "locations asked %llu (with the list %llu, the list did not fit %llu) | resume passes given "
                                "%llu, sessions brought back %llu, resumes refused %llu | new sessions refused as busy %llu "
                                "(--cpu-limit %u%%), the thread's share of a core now %.1f%%\n",
                                aLabel.c_str(), span, aHub.SessionCount(), aHub.ClientCount(), st.datagramsIn / span,
                                (st.bytesIn + 28.0 * st.datagramsIn) / 1024.0 / span, st.datagramsOut / span,
                                (st.bytesOut + 28.0 * st.datagramsOut) / 1024.0 / span, st.payloadsIn / span,
                                st.payloadBytesIn / 1024.0 / span, st.sent / span, st.sentBytes / 1024.0 / span,
                                st.sent ? 100.0 * st.sentReliable / st.sent : 0.0, cpuShare, peakSessions, peakClients,
                                aHub.IdleCount(), static_cast<unsigned long long>(st.sessionsCreated),
                                static_cast<unsigned long long>(st.joinsAccepted),
                                static_cast<unsigned long long>(st.joinsRefused),
                                static_cast<unsigned long long>(st.refusedLimits),
                                static_cast<unsigned long long>(st.refusedClosed),
                                static_cast<unsigned long long>(st.ignoredRepeats),
                                static_cast<unsigned long long>(st.idleClosed),
                                static_cast<unsigned long long>(st.payloadsDropped),
                                static_cast<unsigned long long>(st.biggestPayload),
                                static_cast<unsigned long long>(st.redirected),
                                static_cast<unsigned long long>(st.connected),
                                static_cast<unsigned long long>(st.cookiesTold),
                                static_cast<unsigned long long>(st.connectsRefused),
                                aHub.CookieRequired() ? "asked for" : "not asked for",
                                static_cast<unsigned long long>(st.guardPreAuth),
                                static_cast<unsigned long long>(st.guardPeerFull),
                                static_cast<unsigned long long>(st.guardPoolFull), st.guardPoolPeak / 1048576.0,
                                static_cast<unsigned long long>(st.orphansIdled),
                                static_cast<unsigned long long>(st.serviceCut),
                                static_cast<unsigned long long>(st.queueClosed),
                                static_cast<unsigned long long>(st.certsSigned),
                                static_cast<unsigned long long>(st.codesSealed),
                                static_cast<unsigned long long>(st.sealedRefused),
                                static_cast<unsigned long long>(st.intros),
                                static_cast<unsigned long long>(st.listsSent),
                                static_cast<unsigned long long>(st.introsIgnored),
                                static_cast<unsigned long long>(st.locationAsks),
                                static_cast<unsigned long long>(st.locationLists),
                                static_cast<unsigned long long>(st.locationTooBig),
                                static_cast<unsigned long long>(st.passesGiven),
                                static_cast<unsigned long long>(st.sessionsResumed),
                                static_cast<unsigned long long>(st.resumesRefused),
                                static_cast<unsigned long long>(st.refusedBusy),
                                static_cast<unsigned>(aHub.GetLimits().cpuLimitPct), aHub.CpuPermille() / 10.0);
                statsAt = now;
                statsCpu = cpu;
                peakClients = aHub.ClientCount() + aHub.IdleCount();
                peakSessions = aHub.SessionCount();
            }
        }

        if (aOptions.seconds > 0)
        {
            const auto elapsed =
                std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started).count();
            if (elapsed >= aOptions.seconds)
                break;
        }
    }
    aHub.Stop();
}
} // namespace

int main(int argc, char** argv)
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    uint16_t port = 47800;
    Options options;
    std::string logDir;
    nc::HubServer::Limits limits;
    size_t guardPoolMb = 384; ///< waiting-data pool for the whole hub (meant to fit a 1 GiB service), split between threads
    std::string keyPath;
    bool keyCredential = false;
    bool keyAuto = false;
    // The hub's certificate and the hub list (project root), names and region of the self-certificate
    IntroFiles introFiles;
    std::vector<std::string> hubNames;
    std::string region;
    // Server picker: the project's location list, for connectionless questions
    LocationsFile locationsFile;
    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        const bool more = i + 1 < argc;
        if (arg == "--gen-sign-key" && more)
            return GenerateKey(argv[++i]);
        if (arg == "--check-locations" && more)
            return CheckLocations(argv[++i]);
        if (arg == "--locations" && more)
        {
            locationsFile.path = argv[++i];
            continue;
        }
        // The root owner's commands (no network) and the hub's public keys for them
        if (arg == "--gen-root-key" && more)
            return GenerateRoot(argv[++i]);
        if (arg == "--root-public" && more)
            return RootPublic(argv[++i]);
        if (arg == "--hub-public" && more)
            return HubPublic(argv[++i]);
        if (arg == "--show" && more)
            return Show(argv[++i]);
        if (arg == "--sign-list")
        {
            if (i + 3 >= argc)
            {
                std::printf("--sign-list ROOT LIST.txt OUT\n");
                return 1;
            }
            return SignListCommand(argv[i + 1], argv[i + 2], argv[i + 3]);
        }
        if (arg == "--issue-cert")
        {
            if (i + 3 >= argc)
            {
                std::printf("--issue-cert ROOT HUB.pub OUT --name NAME [--name NAME…] [--region R] [--days N]\n");
                return 1;
            }
            std::vector<std::string> names;
            std::string certRegion;
            int days = 365;
            for (int j = i + 4; j + 1 < argc; j += 2)
            {
                const std::string option = argv[j];
                if (option == "--name")
                    names.push_back(argv[j + 1]);
                else if (option == "--region")
                    certRegion = argv[j + 1];
                else if (option == "--days")
                    days = std::atoi(argv[j + 1]);
                else
                {
                    std::printf("--issue-cert: unknown '%s' (--name, --region, --days)\n", option.c_str());
                    return 1;
                }
            }
            return IssueCert(argv[i + 1], argv[i + 2], argv[i + 3], names, certRegion, days);
        }
        if (arg == "--hub-cert" && more)
        {
            introFiles.certPath = argv[++i];
            continue;
        }
        if (arg == "--hub-list" && more)
        {
            introFiles.listPath = argv[++i];
            continue;
        }
        if (arg == "--hub-name" && more)
        {
            hubNames.push_back(argv[++i]);
            continue;
        }
        if (arg == "--region" && more)
        {
            region = argv[++i];
            continue;
        }
        if (arg == "--sign-key-auto" && more)
        {
            keyPath = argv[++i];
            keyAuto = true;
            continue;
        }
        // Check a key file without network: the public keys to the output
        if (arg == "--check-sign-key" && more)
        {
            const auto checked = LoadKey(argv[++i], false);
            if (!checked)
                return 1;
            std::printf("the hub key is valid: public signing key %s, box key %s\n",
                        nc::netcrypto::ToHex(checked->SignPublic().data(), 32).c_str(),
                        nc::netcrypto::ToHex(checked->BoxPublic().data(), 32).c_str());
            return 0;
        }
        if (arg == "--sign-key" && more)
            keyPath = argv[++i];
        else if (arg == "--sign-key-credential" && more)
        {
            const char* directory = std::getenv("CREDENTIALS_DIRECTORY");
            const std::string name = argv[++i];
            if (!directory || !*directory || name.find('/') != std::string::npos || name.find('\\') != std::string::npos)
            {
                std::printf("--sign-key-credential %s: no $CREDENTIALS_DIRECTORY (LoadCredential= in the service) or a name with "
                            "a directory\n",
                            name.c_str());
                return 1;
            }
            keyPath = std::string(directory) + "/" + name;
            keyCredential = true;
        }
        else if (arg == "--seconds" && more)
            options.seconds = std::atoi(argv[++i]);
        else if (arg == "--stats" && more)
        {
            options.statsEvery = std::atoi(argv[++i]);
            options.statsAlways = true; // given explicitly (load test): a line every period
        }
        else if (arg == "--shards" && more)
        {
            const std::string value = argv[++i];
            const int asked = value == "auto" ? static_cast<int>(std::thread::hardware_concurrency()) : std::atoi(value.c_str());
            options.shards = static_cast<size_t>(std::clamp(asked, 1, 64));
        }
        else if (arg == "--max-clients" && more)
            limits.maxClients = static_cast<size_t>(std::clamp(std::atoi(argv[++i]), 1, 4095));
        else if (arg == "--cpu-limit" && more)
            limits.cpuLimitPct = static_cast<uint8_t>(std::clamp(std::atoi(argv[++i]), 0, 100));
        else if (arg == "--max-per-address" && more)
            limits.maxPerAddress = static_cast<size_t>(std::clamp(std::atoi(argv[++i]), 0, 4095));
        else if (arg == "--max-sessions" && more)
            limits.maxSessions = static_cast<size_t>(std::clamp(std::atoi(argv[++i]), 0, 4095));
        else if (arg == "--max-guests" && more)
            limits.maxGuests = static_cast<size_t>(std::clamp(std::atoi(argv[++i]), 1, 4095));
        else if (arg == "--max-packet-kb" && more)
            limits.maxPacketBytes = static_cast<size_t>(std::clamp(std::atoi(argv[++i]), 64, 32 * 1024)) * 1024u;
        else if (arg == "--idle-seconds" && more)
            limits.idleMs = static_cast<uint32_t>(std::clamp(std::atoi(argv[++i]), 0, 3600)) * 1000u;
        else if (arg == "--cookie" && more)
        {
            const std::string value = argv[++i];
            limits.cookie = value == "off"      ? nc::HubServer::Limits::Cookie::Off
                            : value == "always" ? nc::HubServer::Limits::Cookie::Always
                                                : nc::HubServer::Limits::Cookie::Pressure;
        }
        else if (arg == "--cookie-busy" && more)
            limits.cookieBusy = static_cast<size_t>(std::clamp(std::atoi(argv[++i]), 1, 4095));
        else if (arg == "--guard" && more)
            limits.guard = std::string(argv[++i]) != "off";
        else if (arg == "--guard-pool-mb" && more)
            guardPoolMb = static_cast<size_t>(std::clamp(std::atoi(argv[++i]), 16, 4096));
        else if (arg == "--max-queue-kb" && more)
            limits.maxQueuedBytes = static_cast<size_t>(std::clamp(std::atoi(argv[++i]), 0, 1024 * 1024)) * 1024u;
        else if (arg == "--rcvbuf-kb" && more)
            limits.socketReceiveBytes = static_cast<size_t>(std::clamp(std::atoi(argv[++i]), 0, 1024 * 1024)) * 1024u;
        else if (arg == "--resume" && more)
            limits.resume = std::string(argv[++i]) != "off";
        else if (arg == "--log-dir" && more)
            logDir = argv[++i];
        else if (arg == "--bench")
        {
            limits.maxPerAddress = 0;
            limits.idleMs = 0;
            limits.joinFailsPerMinute = 0;
            limits.createsPerMinute = 0;
        }
        else
            port = static_cast<uint16_t>(std::atoi(arg.c_str()));
    }

    // Waiting data per connection: the biggest packet and 1 MiB of queue behind it while it is reassembled (EnetGuard); the
    // pool is split evenly per thread — each thread has its own ENetHost and connections
    limits.maxWaitingBytes = std::max<size_t>(limits.maxWaitingBytes, limits.maxPacketBytes + 1024u * 1024u);
    limits.guardPoolBytes = std::max<size_t>(16, guardPoolMb / options.shards) * 1024u * 1024u;

    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);

    if (!logDir.empty())
        nc::log::Init(logDir);
    // Hub lines go to stdout (the service log). The sink is called under the log lock, so printf here does not race with
    // the rest
    nc::log::SetSink([](nc::log::Level aLevel, const char* aText)
                     { std::printf("%s%s\n", aLevel >= nc::log::Level::Warn ? "! " : "", aText); });

    // Hub threads: ports, the shared session directory and request counts. One thread: nothing shared, a single hub
    std::vector<uint16_t> ports;
    for (size_t i = 0; i < options.shards; ++i)
        ports.push_back(nc::hubrules::ShardPort(port, i));
    if (std::find(ports.begin(), ports.end(), 0) != ports.end())
    {
        std::printf("not enough ports for %zu thread(s) from %u\n", options.shards, port);
        nc::log::Shutdown();
        return 1;
    }
    std::unique_ptr<nc::HubShards> shared;
    if (options.shards > 1)
        shared = std::make_unique<nc::HubShards>(ports);

    // The hub's key, shared read-only by the threads. --sign-key-auto: if there is no key, create one (an own server in
    // Docker: the first start makes its own key, its fingerprint goes to the log)
    std::shared_ptr<const nc::netcrypto::HubKeys> keys;
    if (keyAuto && !std::filesystem::exists(keyPath))
    {
        if (GenerateKey(keyPath, true) != 0)
        {
            nc::log::Shutdown();
            return 1;
        }
    }
    if (!keyPath.empty())
    {
        keys = LoadKey(keyPath, keyCredential);
        if (!keys)
        {
            nc::log::Shutdown();
            return 1;
        }
    }

    // What the hub shows clients before their request (HubIntro): root certificate, self-certificate, hub list
    auto intro = std::make_shared<nc::HubIntroSource>();
    std::vector<uint8_t> selfCert;
    if (keys)
    {
        selfCert = cr::MakeSelfCert(*keys, hubNames, region, UnixNow()).Write();
        const std::string fingerprint = cr::Fingerprint(keys->SignPublic().data());
        nc::log::Info("hub: the fingerprint of this hub's key is {} — players of a private hub write its address as "
                      "<name>#{} (the mod menu «Server» → «Add an own server», or NightCoopHostHub/NightCoopJoinHub)",
                      fingerprint, fingerprint);
    }
    // Bad certificate and list files do not stop the hub: it starts without them ("! hub: …" lines in the log)
    BuildIntro(introFiles, keys.get(), selfCert, *intro, true);
    // Server picker: the location list, signed with the hub's key; a bad file does not stop the hub (answers without a list)
    auto locations = std::make_shared<nc::HubLocationsSource>();
    if (!locationsFile.path.empty())
        BuildLocations(locationsFile, keys.get(), *intro, *locations, true);

    std::vector<std::unique_ptr<nc::HubServer>> hubs;
    for (size_t i = 0; i < options.shards; ++i)
    {
        hubs.push_back(std::make_unique<nc::HubServer>());
        hubs.back()->SetKeys(keys);
        hubs.back()->SetIntro(intro);
        hubs.back()->SetLocations(locations);
        if (!hubs.back()->Start(ports[i], limits, shared.get(), i))
        {
            std::printf("cannot bind port %u\n", ports[i]);
            for (auto& hub : hubs)
                hub->Stop();
            nc::log::Shutdown();
            return 1;
        }
    }

    std::printf("NightCoop hub on port %u; the session's host sets the game protocol (built with %u); the address for the "
                "direct path — HubAddrSeen\n",
                port, nc::proto::kVersion);
    if (options.shards > 1)
    {
        std::string list;
        for (size_t i = 1; i < ports.size(); ++i)
            list += (i > 1 ? ", " : "") + std::to_string(ports[i]);
        std::printf("%zu threads: entry port %u, the others' ports — %s (they must be open, like the entry one)\n",
                    options.shards, port, list.c_str());
    }
    std::printf("Ctrl-C to exit\n\n");

    // Thread 0 is this one, the others have their own. Each counts its "stats" and closes its HubServer itself
    std::vector<std::thread> threads;
    for (size_t i = 1; i < options.shards; ++i)
        threads.emplace_back([&, i] { RunShard(*hubs[i], options, "stats[" + std::to_string(i) + "]:"); });
    // Thread 0 rereads the certificate and the list every 30 s if the files changed, and the location list
    const std::function<void()> reload = [&]
    {
        ReloadIntroIfChanged(introFiles, keys.get(), selfCert, *intro);
        if (!locationsFile.path.empty() && FileTime(locationsFile.path) != locationsFile.time)
        {
            nc::log::Info("hub: {} changed on disk — reading again", locationsFile.path);
            BuildLocations(locationsFile, keys.get(), *intro, *locations, false);
        }
    };
    RunShard(*hubs[0], options, options.shards > 1 ? "stats[0]:" : "stats:",
             introFiles.certPath.empty() && introFiles.listPath.empty() && locationsFile.path.empty()
                 ? std::function<void()>()
                 : reload);
    g_stop.store(true); // --seconds ran out on thread 0: time for the others too
    for (auto& thread : threads)
        thread.join();

    std::printf("\nExiting\n");
    hubs.clear();
    nc::log::Shutdown();
    return 0;
}
