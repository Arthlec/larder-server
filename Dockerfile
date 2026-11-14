# Not yet built or tested: Docker was not available where this was written.
FROM rust:1 AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p larder-server

FROM debian:stable-slim
COPY --from=build /src/target/release/larder-server /usr/local/bin/larder-server
ENV LARDER_DATABASE=/data/larder-server.db
VOLUME /data
EXPOSE 8080
CMD ["larder-server"]
