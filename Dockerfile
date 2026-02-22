# syntax=docker/dockerfile:1.7

FROM node:22-bookworm-slim AS frontend-builder
WORKDIR /src/frontend

RUN corepack enable

COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY frontend/ ./
RUN pnpm run build


FROM rust:1.91-bookworm AS backend-builder
WORKDIR /src/backend

COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/src ./src
RUN cargo build --release


FROM debian:bookworm-slim AS runtime

ENV RUST_LOG=backend=info,tower_http=info
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /app mlist

COPY --from=backend-builder /src/backend/target/release/backend /app/backend
COPY --from=frontend-builder /src/frontend/dist /app/frontend-dist
COPY backend/config.toml /app/config.toml

RUN mkdir -p /tmp/mlist-files \
    && chown -R mlist:mlist /app /tmp/mlist-files

USER mlist

EXPOSE 3000
CMD ["./backend"]
