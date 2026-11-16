# Your own NightCoop hub

*Русская версия — [README.ru.md](README.ru.md).*

NightCoop players find each other through a **hub**: a small server that hands out session codes, tells each player how the
internet sees him (so that two players behind home routers can open a direct path to each other) and relays the game traffic
when no direct path opens. The official hubs are run by the project. This guide is for running **your own hub** — for your
group of friends, a community or a region far from the official servers.

What the hub sees and what it does not:

- It sees players' IP addresses and how much they send to whom (it has to: it forwards the packets).
- It does **not** see the game itself: every link between the host and a guest is end-to-end encrypted (X25519,
  XChaCha20-Poly1305), the hub only forwards sealed envelopes.
- Your hub has its own key. Players check it by its **fingerprint** — 16 characters you give them together with the address.
  With the fingerprint nobody can put a fake server in your hub's place (a hijacked DNS name, a hostile network on the way):
  the game refuses a server whose key does not match.

## 1. What you need

- A Linux server with a public IPv4 address: a VPS is fine. A hub is light: one CPU core serves roughly 300 players at once
  when about a third of them play through the hub (the rest find a direct path and only keep a tiny link to the hub);
  512 MB of RAM is plenty.
- Open UDP ports: **47800** (entry) and **47810 … 47810+N−1**, one per hub thread (N = the CPU cores you give the hub). With the
  default "one thread per core" on a 4-core server that is 47810–47813. Opening 47810–47873 covers any setup.
- Bandwidth: about **0.5 Mbit/s each way per player who plays through the hub** (up to ~1 Mbit/s in heavy fights and bigger
  sessions); players on a direct path cost almost nothing. Prefer a provider with unmetered or generous traffic.
- Docker Engine 24 or newer with the Compose plugin (`docker compose`). Without Docker — section 6.

## 2. Start the hub with Docker

From the hub's source folder (the NightCoop repository or the hub source bundle — both have the same layout):

```sh
cd tools/hub/docker
cp .env.example .env          # optional: port, threads, name, region
docker compose up -d --build
```

Or skip the build: put `NIGHTCOOP_IMAGE=ghcr.io/twenfys/nightcoop-hub:latest` into `.env`, then run
`docker compose pull && docker compose up -d`. The image is built from
[github.com/Twenfys/nightcoop-hub](https://github.com/Twenfys/nightcoop-hub), for x86-64 servers only.

On the first start the hub creates its key in the `nightcoop-hub-data` volume and prints its fingerprint:

```sh
docker compose logs hub | grep fingerprint
# hub: the fingerprint of this hub's key is K3QF-9X2M-TV7A-0D4R — players of a private hub write its address as
# <name>#K3QF-9X2M-TV7A-0D4R …
```

Open the ports in the firewall (example for `ufw`; also in your provider's security group, if it has one):

```sh
sudo ufw allow 47800/udp
sudo ufw allow 47810:47873/udp
```

Let the hub use a bigger receive buffer (it asks for 4 MB; without this Linux gives it less and says so in the log):

```sh
echo 'net.core.rmem_max = 8388608' | sudo tee /etc/sysctl.d/90-nightcoop-hub.conf
sudo sysctl --system
```

The container runs as its own unprivileged user with a read-only file system; it writes nothing but its key. It uses the
host's network (`network_mode: host`): the hub has to see players' real addresses, and Docker's NAT would cost CPU on every
packet.

## 3. Tell your players

Give your players **the address and the fingerprint**, for example `hub.example.org#K3QF-9X2M-TV7A-0D4R`
(an IP address works too: `203.0.113.7#K3QF-9X2M-TV7A-0D4R`; another port — `hub.example.org:47900#K3QF-…`).

The host adds the server in the game: the mod menu "Co-op" → **"Server: …"** → **"Add an own server"** → type (or paste with
Ctrl+V) the address with the fingerprint → "Save". The server is chosen at once: "Host a session" goes there, and the top
right of the menu shows "SERVER: … · ping · verified". In the session the item **"Copy the invite"** puts a line like
`ABC234@hub.example.org#K3QF-9X2M-TV7A-0D4R` (the session code and the server) on the clipboard — paste it to your partner.
The guest pastes it into "Join by code" (Ctrl+V or "Paste the code") and lands on the same server; the server is remembered
in the guest's own servers. The choice and own servers are kept in `servers.txt` next to `NightCoop.dll`; back to the
official servers — "Server: …" → "Auto: the nearest".

The older way — a file **`hub.txt`** next to `NightCoop.dll` with the one line `hub.example.org#K3QF-9X2M-TV7A-0D4R` — still
works: on the first start of the new version the mod moves it into the own servers and chooses it (once; the file stays and
may be deleted). (With Cyber Engine Tweaks: `print(Game.NightCoopHostHub("hub.example.org#K3QF-9X2M-TV7A-0D4R", 47800))` and
`print(Game.NightCoopJoinHub("hub.example.org#K3QF-9X2M-TV7A-0D4R", 47800, "ABC234"))`.)

What players see when something is wrong:

| In the game | Why | What to do |
|---|---|---|
| "The server failed the key check"; the server window says "the key does not match the fingerprint" | the fingerprint does not match the server's key: a typo, a new key on the server, or not your server at all | check the address ("Server: …" → the own server → "Change the address"); if you re-created the key, give players the new fingerprint |
| "The server is not found" | the name does not resolve | check the DNS record or use the IP address |
| "The server does not answer" | UDP 47800 is closed, or the hub is down | firewall, `docker compose ps`, `docker compose logs hub` |
| creating a session takes 5–6 seconds longer than usual | the thread ports 47810+ are closed: the host waits for a thread port, then falls back to the entry port (it works, but every session crowds onto one thread) | open them (section 2) |

Without a fingerprint (the address `hub.example.org` alone) the game still connects and encrypts, but cannot tell your
server from an impostor (the server window says "encrypted, not verified") — always hand out the fingerprint.

## 4. Keep the key

The key is the identity of your hub: `/data/hub-sign.key` in the `nightcoop-hub-data` volume. **Back it up** and keep the copy
private:

```sh
docker run --rm -v nightcoop-hub-data:/data:ro -v "$PWD":/backup debian:13-slim cp /data/hub-sign.key /backup/
chmod 600 hub-sign.key
```

Lost or leaked key: delete the volume (or the file), restart — the hub creates a new key with a **new fingerprint**; give it
to your players. Whoever has the key file can pretend to be your hub.

## 5. Run it day to day

- Logs: `docker compose logs -f hub`. While players are on the hub, a `stats:` line every 5 minutes per thread: sessions,
  connections, packets and kilobytes per second, `cpu N%` — the share of one core that thread uses.
- When a thread's `cpu` stays above ~60 % at your busy hours, give the hub more cores (and `NIGHTCOOP_SHARDS`) or add a second
  hub for part of your players.
- Update: get the new sources, then `docker compose up -d --build` (with the ready image: `docker compose pull &&
  docker compose up -d`). Sessions outlive the restart: the host of each holds a
  resume pass signed with the hub's key and takes the same code back within 90 s, the guests come back by it (the key must
  stay the same — keep the volume). Players on a direct path keep playing meanwhile. Builds of the mod older than this hub
  lose sessions that go **through** the hub, so restart when it is quiet. `--resume off` turns passes off.
- Threads: `NIGHTCOOP_SHARDS=auto` takes every core the server has. In a container limited to fewer cores, set the number
  yourself. Each thread listens on its own port (47810, 47811, …).
- Settings are in `.env` (see `.env.example`): port, threads, connections per thread, the name and region shown in players'
  logs, and any extra options of `nightcoop_hub`.

## 6. Without Docker

The hub is one small C++20 program. On Debian 13 / Ubuntu 24.04 or newer (g++ 13+):

```sh
sudo apt install g++ git
git clone https://github.com/lsalzman/enet.git /tmp/enet
git -C /tmp/enet checkout 5a9c537fd464b3c6d3c55e1d3bd47588faf71b42
mkdir -p obj
for f in callbacks compress host list packet peer protocol unix; do
  gcc -c -O2 -I/tmp/enet/include -DHAS_FCNTL=1 -DHAS_POLL=1 -DHAS_SOCKLEN_T=1 -DHAS_MSGHDR_FLAGS=1 -DHAS_GETADDRINFO=1 \
      -DHAS_GETNAMEINFO=1 -DHAS_INET_PTON=1 -DHAS_INET_NTOP=1 -DHAS_GETHOSTBYNAME_R=1 -DHAS_GETHOSTBYADDR_R=1 \
      /tmp/enet/$f.c -o obj/enet_$f.o
done
gcc -c -O2 vendor/monocypher/monocypher.c -o obj/monocypher.o
for f in src/Log.cpp src/NetCrypto.cpp src/HubServer.cpp tools/hub/main.cpp; do
  g++ -c -std=c++20 -O2 -I/tmp/enet/include "$f" -o "obj/$(basename "$f" .cpp).o"
done
g++ -o nightcoop_hub obj/*.o -pthread
```

Install it and give it its own user (the key lives in that user's directory; the hub creates it on the first start):

```sh
sudo install -m 755 nightcoop_hub /usr/local/bin/nightcoop_hub
sudo useradd --system --create-home --home-dir /var/lib/nightcoop --shell /usr/sbin/nologin nightcoop
sudo chmod 700 /var/lib/nightcoop
```

A systemd service, `/etc/systemd/system/nightcoop-hub.service`:

```ini
[Unit]
Description=NightCoop hub
After=network-online.target
Wants=network-online.target

[Service]
User=nightcoop
ExecStart=/usr/local/bin/nightcoop_hub 47800 --shards auto --max-clients 512 --sign-key-auto /var/lib/nightcoop/hub-sign.key
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/nightcoop
ProtectHome=true
PrivateTmp=true
MemoryMax=1G

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now nightcoop-hub
journalctl -u nightcoop-hub | grep fingerprint
```

`sudo -u nightcoop nightcoop_hub --hub-public /var/lib/nightcoop/hub-sign.key` prints the hub's public keys and its fingerprint
at any time.

## 7. Good to know

- One hub serves many sessions at once (`--max-clients` connections per thread, one per player); a session (the host and up
  to seven guests) always lives on one hub.
- Players on a direct path use the hub only to meet: their game traffic does not cross your server.
- Your hub is not in the official server list and does not need anything from the NightCoop project: players opt in from
  the menu ("Server: …" → "Add an own server") or with the host's invite.
- The hub keeps nothing on disk but its key; session codes live in memory only.
