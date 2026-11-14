# Larder server

The self-hosted household server for the [Larder](https://github.com/Arthlec/larder-app) kitchen app. It lets the people who live together share one pantry, one shopping list and their saved recipes.

It is a single Rust binary with an embedded SQLite database: nothing else to install. It is meant to run on a machine at home (a PC, a Raspberry Pi, a NAS).

## What it does

- **Accounts**: username and password, passwords hashed with Argon2id (64 MiB, 3 passes). Repeated wrong passwords lock the account for a growing delay.
- **Encrypted connections**: HTTPS only, with a certificate the server makes itself. Each phone checks its fingerprint once, then refuses any other certificate.
- **Sessions you can end**: sign out one device or all of them, from the app or from the server.
- **Households**: one person creates a household and shares its invite code; the others join with it.
- **Sync**: devices push their changes and pull everyone else's. The server keeps the latest version of each item ("last write wins") and never looks inside it.

What it deliberately does not do: talk to recipe websites (the app does that itself) or know anyone's diet (that stays on each phone).

## Status

Done and covered by 105 automated tests, including end-to-end tests of the HTTP API and of the HTTPS listener. Also verified with the app's own sync client: two simulated devices sharing a pantry, a shopping list, a hand-written recipe and a favourite.

The container image is verified with Podman: it builds (88 MB), runs as an unprivileged user, keeps accounts and data across restarts and re-created containers, and stops cleanly on `podman stop`. The server has only been run on Linux.

## Run it

```sh
cargo run --release -p larder-server
```

```
larder-server 0.2.0 listening on https://0.0.0.0:8080 (database: larder-server.db, registration open)
certificate fingerprint (SHA-256): 318e 229d 1fe3 b0c1 ac94 3eee 6d37 14f8 b6ed fae3 ff5e 02f2 31c7 639e 6463 c872
```

Check it from another device on the same network: `curl -k https://<this-machine's-address>:8080/health` (`-k` because the certificate is self-signed; the app checks it by fingerprint instead).

In the app, open **Settings → Household sync**, enter `https://<address>:8080`, and create an account. The first time, the app shows the server's fingerprint: compare it with the line above before tapping **Trust and continue**. That check is what protects the connection, so do it once on each phone.

Upgrading from 0.1: there is no migration. Delete the old database file and sign in again from every phone.

### In a container

The same commands work with Docker (replace `podman` with `docker`):

```sh
podman build -t larder-server .
podman run -d --name larder -p 8080:8080 -v larder-data:/data larder-server
```

The fingerprint is in the start-up log: `podman logs larder`. The database lives in the `larder-data` volume, so the container can be removed and recreated without losing accounts or data. The server runs as an unprivileged user inside the container. Rootless Podman needs a range of sub-IDs for your user; if the build fails with "insufficient UIDs or GIDs", run `sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER && podman system migrate` once.

### Configuration

Environment variables (see `.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `LARDER_BIND` | `0.0.0.0:8080` | Address and port to listen on |
| `LARDER_DATABASE` | `larder-server.db` | SQLite file, created on first start |
| `LARDER_ALLOW_REGISTRATION` | `true` | Set to `false` once everyone has an account |

The TLS certificate and key are generated on first start and stored in the database, so there is nothing to configure and phones keep trusting the server across restarts and restores from backup.

### Commands

```sh
larder-server fingerprint                # print the certificate fingerprint again
larder-server revoke-sessions <username> # sign an account out of every device (lost phone)
larder-server reset-certificate          # new certificate on the next start
```

They read the same `LARDER_DATABASE`. In a container: `podman exec larder larder-server fingerprint`. After `reset-certificate`, every phone reports that the certificate changed and has to sign in again.

### Security notes

- **Connections** are HTTPS only (TLS 1.3). The certificate is self-signed, so its authenticity rests on the fingerprint check the app asks for once per phone: if someone intercepted that very first connection, a careful comparison is what catches it.
- **Passwords** are hashed with Argon2id (64 MiB, 3 passes) and never stored or logged in clear. An unknown username takes as long to refuse as a wrong password, so the answer does not reveal which accounts exist.
- **Guessing** is slowed: after 5 wrong passwords for one username, it is locked for 30 seconds, doubling up to 15 minutes; one address gets 20 failures across all usernames before being locked the same way; account creation is limited to 10 per address per hour. Locked attempts get HTTP 429. The counts are kept in memory and reset on restart.
- **Sessions** end after 30 days unused, a year after signing in, on sign-out, or with `revoke-sessions`. The database holds only a hash of each session token.
- **Registration**: anyone who can reach the server can create an account while it is open. An account alone sees nothing: data belongs to a household, and joining one needs its invite code. Set `LARDER_ALLOW_REGISTRATION=false` once everyone has an account.
- **Remote access**: the server has not been reviewed for exposure to the internet. To reach it from outside, prefer a VPN (WireGuard, Tailscale) over opening a port.
- **The database file** contains the TLS private key and everyone's data: keep it and its backups private. Back up by copying it while the server is stopped. In a container: `podman stop larder`, then `podman cp larder:/data/larder-server.db .`.

## Tests

```sh
cargo test --workspace
```

## API

Defined by the `larder-api-types` crate, which the app also depends on. The app pins it to a git tag of this repository (currently `v0.2.0`), so a change to `crates/api-types` reaches the app only after a new tag is pushed and the app's `Cargo.toml` is updated to it.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | no | Liveness and version |
| POST | `/auth/register` | no | Create an account, returns a token |
| POST | `/auth/login` | no | Sign in, returns a token |
| POST | `/auth/logout` | yes | End this device's session |
| POST | `/auth/logout-all` | yes | End every session of the account |
| GET | `/me` | yes | Username and household |
| POST | `/households` | yes | Create a household |
| POST | `/households/join` | yes | Join with an invite code |
| POST | `/sync/push` | yes | Send changed records |
| GET | `/sync/pull?cursor=N` | yes | Fetch records changed after cursor `N` |

Authenticated routes need `Authorization: Bearer <token>`. Errors are `{"error": "..."}` with a 4xx or 5xx status; too many failed attempts get 429 with a `Retry-After` header.

## Architecture

Same clean-architecture layering as the app; dependencies only point inward.

```
crates/
├── api-types/       HTTP contract shared with the app (types only)
├── domain/          Rules: validation, invite codes, "last write wins", lockout, session lifetime. No IO.
├── application/     Use cases (auth, households, sync), sign-in throttling + ports
├── infrastructure/  Adapters: SQLite via sqlx, Argon2, session tokens, TLS certificate
└── server/          axum routes, HTTPS listener, configuration, commands, binary
migrations/          SQL schema
```

See [docs/DECISIONS.md](docs/DECISIONS.md) for the reasoning behind each choice.

## Roadmap

Done:

- [x] Accounts, households with invite codes
- [x] Record sync with last-write-wins and tombstones
- [x] Zero-configuration start (embedded database, generated signing secret)
- [x] Option to close registration
- [x] HTTPS with a self-signed certificate pinned by the app
- [x] Limit sign-in attempts
- [x] Revocable sessions (sign out one or all devices)
- [x] Container image (Podman or Docker), built and checked in CI

Next:

- [ ] Leave a household, remove a member, regenerate the invite code
- [ ] Change password, delete account
- [ ] Guide for remote access (VPN)

Ideas for later:

- [ ] Push changes to connected devices in real time (WebSocket or server-sent events) instead of waiting for the next sync
- [ ] Scheduled backups and a restore command
- [ ] Purge old tombstones
- [ ] PostgreSQL as an alternative database, for hosting many households
- [ ] Sign in with an external provider (OAuth)
- [ ] Server-side support for future app features: meal plans, shared food-waste statistics, push notifications for expiring food

## License

[MIT](LICENSE)
