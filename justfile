default:
    @just --list

backend-dev:
    cd backend && cargo run

frontend-dev:
    cd frontend && npm run dev

dev:
    #!/usr/bin/env bash
    set -euo pipefail

    (cd backend && cargo run) &
    backend_pid=$!

    (cd frontend && npm run dev) &
    frontend_pid=$!

    cleanup() {
      kill "$backend_pid" "$frontend_pid" 2>/dev/null || true
      wait "$backend_pid" "$frontend_pid" 2>/dev/null || true
    }
    trap cleanup EXIT INT TERM

    wait -n "$backend_pid" "$frontend_pid"
