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

**Rejected.** PostgreSQL: the right choice for a public service with many households, but a second service to run at home for no benefit at this scale. All SQL sits behind repository traits, so adding it later is contained.

## 4. The server stores opaque records

A synced record is `(household, kind, id, updated_at, deleted, payload)`, where `payload` is JSON text the server never parses. The app can therefore add fields or whole features without a server change, and the server stays small.

**Cost.** The server cannot validate or query the content. That is acceptable: every member of a household is trusted with its data anyway.

## 5. Last write wins, with a server-assigned change number

Each stored record gets a change number (`seq`) that only grows. Devices ask for "everything after change N", which makes pulls cheap and repeatable. A pushed record replaces the stored one only if its `updated_at` is strictly newer; a tie keeps the stored one, so resending a change is harmless.

Writes are serialised by a lock so change numbers are assigned in commit order. SQLite allows a single writer at a time anyway.

The rule lives in the domain (`incoming_wins`) and is repeated in the SQL `ON CONFLICT ... WHERE` clause so the check and the write are one atomic statement. A test asserts that the two agree.

**Cost.** `updated_at` comes from device clocks; a device with a wrong clock can win or lose conflicts it should not.

## 6. Argon2id for passwords

**Why Argon2id.** The published attacks on Argon2 (memory-reduction attacks, and one in O(n^7/4 log n) time that needs more than 10 passes to resist in version 1.3) target **Argon2i**, the variant whose memory access does not depend on the password. None is known against Argon2d or the hybrid Argon2id, which is what RFC 9106 recommends by default. Argon2id v1.3 is what the server uses.

**Parameters.** 64 MiB, 3 passes, 1 lane: RFC 9106's recommendation for memory-constrained machines, and above OWASP's minimum (19 MiB, 2 passes). One lane, because the `argon2` crate computes lanes one after the other: more lanes would cost the server the same time and only help an attacker with parallel hardware. A hash takes about 0.15 s on a desktop and somewhat more on a Raspberry Pi. At most two hashes run at once, which caps their memory at 128 MiB and keeps a burst of sign-ins from starving a small machine.

Hashing runs on a blocking thread. The salt is 16 random bytes from the operating system.

**Not revealing accounts.** An unknown username is checked against a dummy hash, so it takes as long as a wrong password and gets the same answer.

## 7. Sessions stored on the server, not JWTs

A sign-in creates a session: a 256-bit random token, stored only as its SHA-256 (a copy of the database gives no usable token; a plain hash is enough because the token is random, unlike a password). Every request looks the session up, which on a household server costs nothing.

**Why.** A session can be ended at once: `POST /auth/logout` for this device, `POST /auth/logout-all` for every device, and `larder-server revoke-sessions <username>` on the server for a lost phone. Sessions end after 30 days unused and a year after signing in in any case. "Last used" is written at most once an hour. Expired sessions are deleted hourly.

**Rejected.** JWTs, the first version: they cannot be revoked before they expire, so their 180-day lifetime was 180 days of exposure for a stolen token. Short JWTs plus refresh tokens: revocable, but two kinds of token and a refresh flow, for a problem a table solves.

## 8. Limiting sign-in attempts

After 5 failed sign-ins for one username, the next failure locks it for 30 seconds, doubling up to 15 minutes. The count is forgotten after 15 minutes without a failure. One address gets 20 free failures across all usernames, to stop one password from being tried against many accounts. IPv6 clients count per /64 prefix, which a client can otherwise rotate through. Account creation is limited to 10 per address per hour, since each one costs a hash.

A locked attempt is refused before hashing, so it costs nothing, and answered the same way whether the account exists or not: HTTP 429 with `Retry-After`. A successful sign-in clears the username's count but not the address's, so signing in to one's own account cannot be used to keep guessing at others.

**Cost.** The counts are kept in memory and reset when the server restarts. Someone who can restart the server already controls it.

## 9. Invite codes instead of member management

Ten characters from an alphabet without look-alikes (no `0`/`O`, `1`/`I`/`L`), about 49 bits. Simple to read aloud across a kitchen. A user belongs to one household; switching is refused rather than silently moving their data.

## 10. HTTPS with a self-signed, pinned certificate

The server only speaks HTTPS (TLS 1.3 through rustls with the ring cryptography; ring rather than aws-lc-rs so that building needs no cmake or NASM). Plain HTTP would send passwords, session tokens and the household's data in clear to anyone on the same Wi-Fi.

**The certificate.** A home server usually has no domain name, so no public certificate authority can issue it a certificate. On first start the server generates an ECDSA P-256 key and a self-signed certificate valid until 2075, stores both in its database (so a backup keeps the same identity), and prints the certificate's SHA-256 fingerprint. `larder-server fingerprint` prints it again.

**How the app trusts it.** The first time a phone connects, the app shows the fingerprint and asks the user to compare it with the server's; once confirmed, the app pins it and refuses any other certificate from then on. A certificate from a public authority (for a server behind a domain) is accepted without that step.

**Changing it.** `larder-server reset-certificate` makes a new one on the next start; every phone then reports that the certificate changed and has to sign in again.

**Rejected.** Plain HTTP, the first version. A mandatory reverse proxy with a public certificate: needs a domain and more software at home. A private certificate authority installed on each phone: more steps than comparing a fingerprint once, and on Android user-installed authorities are not trusted by apps by default.

## 11. Container image on Debian slim

Two stages: build in the official Rust image, run in `debian:bookworm-slim`, both on the same Debian release so the binary finds the glibc it was linked against. The result is about 88 MB. The server runs as an unprivileged user and keeps its database in the `/data` volume. It handles SIGTERM itself, because as process 1 in a container it would otherwise ignore `stop` and be killed after a timeout.

**Rejected.** A static musl binary on `scratch` or distroless (smaller, but a second build target to maintain for little gain at home); Alpine (musl again).

## 12. MIT license

Chosen by the project owner.
