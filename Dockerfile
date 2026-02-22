# syntax=docker/dockerfile:1.7

FROM node:22-alpine AS frontend-builder
WORKDIR /src/frontend

RUN corepack enable

COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY frontend/ ./
RUN pnpm run build


FROM rust:1.91-alpine AS backend-builder
WORKDIR /src/backend

COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/src ./src
RUN cargo build --release


FROM alpine:3.21 AS runtime

ENV RUST_LOG=backend=info,tower_http=info
WORKDIR /app

RUN apk add --no-cache ca-certificates \
    && addgroup -S mlist \
    && adduser -S -u 10001 -G mlist mlist

COPY --from=backend-builder /src/backend/target/release/backend /app/backend
COPY --from=frontend-builder /src/frontend/dist /app/frontend-dist
COPY backend/config.toml /app/config.toml

RUN mkdir -p /mlist-files \
    && chown -R mlist:mlist /app /mlist-files

USER mlist

EXPOSE 3000
CMD ["./backend"]
