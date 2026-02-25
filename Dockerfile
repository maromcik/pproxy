FROM rust:1.93-slim as builder

# Install build dependencies (cmake explicitly included)
RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/app

# Copy project files
COPY ./src ./src
COPY ./templates ./templates
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock

# Build the project (release mode)
RUN cargo build --release

RUN ls

FROM debian:trixie-slim AS runtime
RUN apt-get update
RUN apt-get install -y zip pkg-config libssl-dev clang

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app/target/release/pproxy /usr/local/bin
COPY ./static ./static
# Create config directory
RUN mkdir -p /opt/pproxy

VOLUME ["/opt/pproxy"]

CMD ["/usr/local/bin/pproxy", "-c", "/opt/pproxy/pproxy.toml"]