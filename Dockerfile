FROM rust:1.83-alpine as builder

# Install necessary packages
RUN apk add --no-cache \
  build-base \
  musl-dev \
  openssl-dev \
  pkgconf \
  cmake \
  ca-certificates \
  perl

# Ensure OpenSSL environment variables are set
ENV OPENSSL_DIR=/usr \
  OPENSSL_INCLUDE_DIR=/usr/include \
  OPENSSL_LIB_DIR=/usr/lib \
  PKG_CONFIG_PATH=/usr/lib/pkgconfig \
  SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
  SSL_CERT_DIR=/etc/ssl/certs

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && \
  echo "fn main() {}" > src/main.rs && \
  cargo build --locked --release

RUN rm -rf src

COPY src src
RUN touch src/main.rs && cargo build --locked --release

FROM alpine:latest

# Install runtime dependencies with specific version to match builder
RUN apk add --no-cache \
  openssl \
  ca-certificates \
  && update-ca-certificates

# Copy SSL certs configuration from builder
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

# Set SSL environment variables in runtime
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
  SSL_CERT_DIR=/etc/ssl/certs

# Copy the compiled binary and config
COPY --from=builder /app/target/release/pgproxy /usr/local/bin/

WORKDIR /usr/local/bin
ENTRYPOINT ["pgproxy"]