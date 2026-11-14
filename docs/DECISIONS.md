# Decisions

Each choice, why it was made, and what was rejected.

## 1. Rust with axum and tokio

**Why.** Same language as the app, so the API contract can be a shared crate (decision 2). axum is the most widely used Rust web framework and builds on the tower middleware ecosystem. The result is one static binary, which suits a machine at home.

**Rejected.** actix-web (equally capable; smaller middleware ecosystem). Python with FastAPI was the first plan and was dropped at the project owner's request.

## 2. The API contract is a crate, `larder-api-types`

Requests and responses are plain structs in a crate that both the server and the app depend on. A change to the API that one side does not follow is a compile error rather than a runtime failure. The crate depends only on `serde` and `uuid`, so it adds almost nothing to the app.

## 3. SQLite, through `sqlx`

**Why SQLite.** A household is a handful of users. SQLite handles that load easily, needs no database service to install, upgrade or secure, and a backup is one file. WAL mode lets reads continue during a write.

**Why `sqlx`.** It is async, so database calls do not block the server's threads, and it embeds the migrations in the binary.

**Note.** Queries are written with `sqlx::query` and checked by tests against a real in-memory SQLite, not with the compile-time-checked `query!` macros. Those need a database available at build time, which would complicate building from a fresh clone.

**Rejected.** PostgreSQL: the right choice for a public service with many households, but a second service to run at home for no benefit at this scale. All SQL sits behind three repository traits, so adding it later is contained.

## 4. The server stores opaque records

A synced record is `(household, kind, id, updated_at, deleted, payload)`, where `payload` is JSON text the server never parses. The app can therefore add fields or whole features without a server change, and the server stays small.

**Cost.** The server cannot validate or query the content. That is acceptable: every member of a household is trusted with its data anyway.

## 5. Last write wins, with a server-assigned change number

Each stored record gets a change number (`seq`) that only grows. Devices ask for "everything after change N", which makes pulls cheap and repeatable. A pushed record replaces the stored one only if its `updated_at` is strictly newer; a tie keeps the stored one, so resending a change is harmless.

Writes are serialised by a lock so change numbers are assigned in commit order. SQLite allows a single writer at a time anyway.

The rule lives in the domain (`incoming_wins`) and is repeated in the SQL `ON CONFLICT ... WHERE` clause so the check and the write are one atomic statement. A test asserts that the two agree.

**Cost.** `updated_at` comes from device clocks; a device with a wrong clock can win or lose conflicts it should not.

## 6. Argon2id for passwords

The current recommended password hash, with the library's default parameters (19 MiB, 2 passes). Hashing runs on a blocking thread because it is deliberately slow. Sign-in failures never reveal whether the username exists.

## 7. JWT access tokens, secret generated on first start

Tokens are stateless, so no session table is needed. The signing secret is created on first start and stored in the database: there is nothing to configure, and tokens survive restarts. Tokens last 180 days; on a home server, frequent re-typing of passwords on a phone mostly encourages weak ones.

**Cost.** A token cannot be revoked individually before it expires. Deleting the account invalidates it, since every request re-checks that the user exists.

## 8. Invite codes instead of member management

Ten characters from an alphabet without look-alikes (no `0`/`O`, `1`/`I`/`L`), about 49 bits. Simple to read aloud across a kitchen. A user belongs to one household; switching is refused rather than silently moving their data.

## 9. Plain HTTP

The server is meant for a home network, where setting up certificates is the main obstacle to self-hosting. The README says plainly not to expose it to the internet and points to a VPN or a reverse proxy for remote access.

## 10. Container image on Debian slim

Two stages: build in the official Rust image, run in `debian:bookworm-slim`, both on the same Debian release so the binary finds the glibc it was linked against. The result is about 85 MB. The server runs as an unprivileged user and keeps its database in the `/data` volume. It handles SIGTERM itself, because as process 1 in a container it would otherwise ignore `stop` and be killed after a timeout.

**Rejected.** A static musl binary on `scratch` or distroless (smaller, but a second build target to maintain for little gain at home); Alpine (musl again).

## 11. MIT license

Chosen by the project owner.
