# NightCoop hub — run your own server

*Русская версия инструкции — [tools/hub/docker/README.ru.md](tools/hub/docker/README.ru.md).*

The NightCoop hub is the small server that players of [NightCoop](https://nightcoop.net) (a co-op mod for Cyberpunk 2077)
meet through: it hands out session codes, helps two players behind home routers open a direct path to each other and relays
the game traffic when no direct path opens. The game itself is end-to-end encrypted between the players — the hub only
forwards sealed packets.

This repository holds only what the hub is built from. The mod itself is not here.

## Quick start (Docker)

```sh
cd tools/hub/docker
cp .env.example .env          # optional: port, threads, name, region
docker compose up -d --build
docker compose logs hub | grep fingerprint
```

No build: put `NIGHTCOOP_IMAGE=ghcr.io/twenfys/nightcoop-hub:latest` into `.env` and run
`docker compose pull && docker compose up -d` instead (x86-64 servers).

Open UDP **47800** and **47810–47873**, then give your players the address with the fingerprint, for example
`hub.example.org#K3QF-9X2M-TV7A-0D4R`. In the game: the mod menu "Co-op" → "Server: …" → "Add an own server".

**The full guide** — requirements, ports, keeping the key, updates, building without Docker:
[tools/hub/docker/README.md](tools/hub/docker/README.md).

## What is inside

| Path | What |
|---|---|
| `tools/hub/main.cpp` | the hub program (`nightcoop_hub`) |
| `src/` | the hub server, transport crypto and log |
| `tools/hub/docker/` | Dockerfile, Compose file, settings example and the guide |
| `vendor/monocypher/` | Monocypher 4.0.2 — BSD-2-Clause or CC0 1.0 (`LICENCE.md`) |

ENet is not stored here: the build fetches the exact commit it is tested with from https://github.com/lsalzman/enet.
