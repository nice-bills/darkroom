# The judge relay. Keys arrive as environment variables and are written at start, never into the image.
FROM rust:1.98-slim-trixie AS tools
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev libudev-dev ca-certificates perl make
COPY tools/verify-quote /src
WORKDIR /src
RUN cargo build --release --locked
RUN cargo install outlayer-cli --version 0.2.1 --locked

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils unzip libudev1 libssl3
RUN curl -fsSL https://nodejs.org/dist/v24.11.0/node-v24.11.0-linux-x64.tar.xz | tar -xJ -C /usr/local --strip-components=1
RUN curl -fsSL https://github.com/oven-sh/bun/releases/download/bun-v1.3.5/bun-linux-x64.zip -o /tmp/bun.zip \
  && unzip -j /tmp/bun.zip -d /usr/local/bin && rm /tmp/bun.zip
RUN curl -fsSL https://github.com/near/near-cli-rs/releases/download/v0.30.1/near-cli-rs-x86_64-unknown-linux-gnu.tar.gz \
  | tar -xz -C /usr/local/bin --strip-components=1
COPY --from=tools /usr/local/cargo/bin/outlayer /usr/local/bin/outlayer
COPY . /app
COPY --from=tools /src/target/release/verify-quote /app/tools/verify-quote/target/release/verify-quote
WORKDIR /app
RUN cd cli && bun install --frozen-lockfile
ENTRYPOINT ["relay/start.sh"]
