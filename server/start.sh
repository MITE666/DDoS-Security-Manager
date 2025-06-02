#!/usr/bin/env bash

set -euo pipefail

pids=()
function shutdown {
    echo "[start.sh] Caught SIGTERM/SIGINT; forwarding to children..."
    for pid in "${pids[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    wait
    exit 0
}
trap shutdown SIGTERM SIGINT

mkdir -p /app/logs

echo "[start.sh] Starting dispatcher…" >> /app/logs/startup.log
/app/dispatcher \
    > /app/logs/dispatcher.log \
    2> /app/logs/dispatcher.err.log &
pids+=("$!")

sleep 1

echo "[start.sh] Starting server…" >> /app/logs/startup.log
/app/server \
    > /app/logs/server.log \
    2> /app/logs/server.err.log &
pids+=("$!")

while true; do
    for i in "${!pids[@]}"; do
        pid="${pids[$i]}"
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[start.sh] Process PID=$pid has exited unexpectedly."
            for other in "${pids[@]}"; do
                if [ "$other" != "$pid" ] && kill -0 "$other" 2>/dev/null; then
                    echo "[start.sh] Killing sibling PID=$other"
                    kill -TERM "$other" 2>/dev/null || true
                fi
            done
            wait
            exit 1
        fi
    done
    sleep 1
done
