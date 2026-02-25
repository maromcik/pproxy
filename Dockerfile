FROM rust:1.93-slim

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
COPY . .

# Build the project (release mode)
RUN cargo build --release

# Create config directory
RUN mkdir -p /opt/pproxy

# Declare volume for runtime config
VOLUME ["/opt/pproxy"]

# Expose port if relevant (optional)
# EXPOSE 8080

# Run the binary with config
CMD ["/usr/src/app/target/release/pproxy", "-c", "/opt/pproxy/pproxy.toml"]