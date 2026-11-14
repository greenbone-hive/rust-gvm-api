# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.95.0

FROM rust:${RUST_VERSION}-trixie AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git pkg-config wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY .cargo .cargo
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml clippy.toml ./
COPY crates crates
COPY tests tests
COPY packaging packaging

RUN cargo build --locked --release -p gvm-gateway

# Selected only by the advisory enterprise Compose overlay. The final/default
# runtime stage below intentionally cannot inherit either E2E binary.
FROM builder AS enterprise-test-tools

RUN cargo build --locked --release -p gvm-gateway-e2e \
    --bin enterprise-feature-preflight \
    --bin agent-control-scenario-proxy

FROM debian:trixie-slim AS runtime

ARG GVM_GATEWAY_VERSION=dev
ARG GVM_GATEWAY_VCS_REF=unknown
ARG GVM_GATEWAY_UID=65532
ARG GVM_GATEWAY_GID=65532

LABEL org.opencontainers.image.title="gvm-gateway" \
      org.opencontainers.image.description="REST gateway for Greenbone Vulnerability Management" \
      org.opencontainers.image.source="https://github.com/greenbone-hive/rust-gvm-api" \
      org.opencontainers.image.version="${GVM_GATEWAY_VERSION}" \
      org.opencontainers.image.revision="${GVM_GATEWAY_VCS_REF}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && groupadd --system --gid "${GVM_GATEWAY_GID}" gvm-gateway \
    && useradd --system --uid "${GVM_GATEWAY_UID}" --gid "${GVM_GATEWAY_GID}" --no-create-home --shell /usr/sbin/nologin gvm-gateway \
    && install -d -o "${GVM_GATEWAY_UID}" -g "${GVM_GATEWAY_GID}" /var/lib/gvm-gateway \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/gvm-gateway /usr/local/bin/gvm-gateway
COPY packaging/gvm-gateway.container.toml /etc/gvm-gateway/gvm-gateway.toml

USER ${GVM_GATEWAY_UID}:${GVM_GATEWAY_GID}
WORKDIR /var/lib/gvm-gateway

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/gvm-gateway"]
CMD ["--config", "/etc/gvm-gateway/gvm-gateway.toml"]
