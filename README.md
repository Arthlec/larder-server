# Larder server

The self-hosted household server for the [Larder](../larder-app) kitchen app. It lets the people who live together share one pantry, one shopping list and their saved recipes.

It is a single Rust binary with an embedded SQLite database: nothing else to install. It is meant to run on a machine at home (a PC, a Raspberry Pi, a NAS).

## What it does

- **Accounts**: username and password, passwords hashed with Argon2id.
- **Households**: one person creates a household and shares its invite code; the others join with it.
- **Sync**: devices push their changes and pull everyone else's. The server keeps the latest version of each item ("last write wins") and never looks inside it.

What it deliberately does not do: talk to recipe websites (the app does that itself) or know anyone's diet (that stays on each phone).

## Status

Done and covered by 74 automated tests, including end-to-end tests of the HTTP API. Also verified with the app's own sync client: two simulated devices sharing a pantry, a shopping list, a hand-written recipe and a favourite.

The container image is verified with Podman: it builds (85 MB), runs as an unprivileged user, keeps accounts and data across restarts and re-created containers, and stops cleanly on `podman stop`. The server has only been run on Linux.

## Run it

```sh
cargo run --release -p larder-server
```

```
larder-server 0.1.0 listening on http://0.0.0.0:8080 (database: larder-server.db, registration open)
```

Check it from another device on the same network: `http://<this-machine's-address>:8080/health`.

In the app, open **Settings → Household sync**, enter that address, and create an account.

### In a container

The same commands work with Docker (replace `podman` with `docker`):

```sh
podman build -t larder-server .
podman run -d --name larder -p 8080:8080 -v larder-data:/data larder-server
```

The database lives in the `larder-data` volume, so the container can be removed and recreated without losing accounts or data. The server runs as an unprivileged user inside the container. Rootless Podman needs a range of sub-IDs for your user; if the build fails with "insufficient UIDs or GIDs", run `sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER && podman system migrate` once.

### Configuration

Environment variables (see `.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `LARDER_BIND` | `0.0.0.0:8080` | Address and port to listen on |
| `LARDER_DATABASE` | `larder-server.db` | SQLite file, created on first start |
| `LARDER_ALLOW_REGISTRATION` | `true` | Set to `false` once everyone has an account |

The secret used to sign access tokens is generated on first start and stored in the database, so there is nothing to configure and sign-ins survive a restart.

### Security notes

- The server speaks plain HTTP. On a home network that is usually acceptable; **do not expose it to the internet as is**. To reach it from outside, put it behind a VPN (WireGuard, Tailscale) or a reverse proxy that adds HTTPS.
- Anyone who can reach the server can create an account while registration is open. An account alone sees nothing: data belongs to a household, and joining one needs its invite code.
- There is no limit on sign-in attempts yet.
- Back up by copying the database file while the server is stopped. In a container: `podman stop larder`, then copy it out with `podman cp larder:/data/larder-server.db .`.

## Tests

```sh
cargo test --workspace
```

## API

Defined by the `larder-api-types` crate, which the app also depends on.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | no | Liveness and version |
| POST | `/auth/register` | no | Create an account, returns a token |
| POST | `/auth/login` | no | Sign in, returns a token |
| GET | `/me` | yes | Username and household |
| POST | `/households` | yes | Create a household |
| POST | `/households/join` | yes | Join with an invite code |
| POST | `/sync/push` | yes | Send changed records |
| GET | `/sync/pull?cursor=N` | yes | Fetch records changed after cursor `N` |

Authenticated routes need `Authorization: Bearer <token>`. Errors are `{"error": "..."}` with a 4xx or 5xx status.

## Architecture

Same clean-architecture layering as the app; dependencies only point inward.

```
crates/
├── api-types/       HTTP contract shared with the app (types only)
├── domain/          Rules: validation, invite codes, "last write wins". No IO.
├── application/     Use cases (auth, households, sync) + ports
├── infrastructure/  Adapters: SQLite via sqlx, Argon2, JWT
└── server/          axum routes, configuration, composition root, binary
migrations/          SQL schema
```

See [docs/DECISIONS.md](docs/DECISIONS.md) for the reasoning behind each choice.

## Roadmap

Done:

- [x] Accounts, households with invite codes
- [x] Record sync with last-write-wins and tombstones
- [x] Zero-configuration start (embedded database, generated signing secret)
- [x] Option to close registration
- [x] Container image (Podman or Docker), built and checked in CI

Next:

- [ ] Limit sign-in attempts
- [ ] Leave a household, remove a member, regenerate the invite code
- [ ] Change password, delete account
- [ ] Guide for remote access (VPN or reverse proxy with HTTPS)

Ideas for later:

- [ ] Built-in HTTPS
- [ ] Push changes to connected devices in real time (WebSocket or server-sent events) instead of waiting for the next sync
- [ ] Scheduled backups and a restore command
- [ ] Purge old tombstones
- [ ] PostgreSQL as an alternative database, for hosting many households
- [ ] Sign in with an external provider (OAuth)
- [ ] Server-side support for future app features: meal plans, shared food-waste statistics, push notifications for expiring food

## License

[MIT](LICENSE)
