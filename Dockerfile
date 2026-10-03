FROM rust:1.92.0-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY apps apps
RUN cargo build --locked --release -p niceotp-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 niceotp
COPY --from=build /src/target/release/niceotp-server /usr/local/bin/niceotp-server
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.txt /usr/share/doc/niceotp/
USER 10001
ENV LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS http://127.0.0.1:8080/ready || exit 1
ENTRYPOINT ["niceotp-server"]
