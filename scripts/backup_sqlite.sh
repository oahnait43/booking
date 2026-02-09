#!/usr/bin/env sh
set -eu

DB_PATH="${1:-./booking.db}"
OUT_DIR="${2:-./backups}"

mkdir -p "$OUT_DIR"

TS="$(date +%Y%m%d_%H%M%S)"
OUT_PATH="$OUT_DIR/booking_$TS.db"

cp "$DB_PATH" "$OUT_PATH"
echo "$OUT_PATH"
