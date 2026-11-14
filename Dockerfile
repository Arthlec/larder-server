# Builds the server in a Rust image, then copies the binary into a small
# Debian image. Both stages use the same Debian release (bookworm), so the
# binary finds the same glibc it was linked against.
# Works with Podman and Docker: `podman build -t larder-server .`

FROM docker.io/library/rust:1-bookworm AS build
WORKDIR /src
COPY . .
# Cache mounts keep downloaded crates and compiled dependencies between builds.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p larder-server \
    && cp target/release/larder-server /larder-server

FROM docker.io/library/debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data larder \
    && mkdir /data && chown larder:larder /data
COPY --from=build /larder-server /usr/local/bin/larder-server
USER larder
WORKDIR /data
ENV LARDER_BIND=0.0.0.0:8080 \
    LARDER_DATABASE=/data/larder-server.db
VOLUME /data
EXPOSE 8080
# No HEALTHCHECK: the slim image has no HTTP client. Check from outside with
# `curl http://<host>:8080/health`.
CMD ["larder-server"]
