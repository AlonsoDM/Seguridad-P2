#!/bin/bash
TARGET="154.57.164.74:31330"
ADMIN_PASS="Hz1MDLEX3k2gcrY71kE"

curl -s -X POST "$TARGET/" -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt \
  -d "username=admin&password=$ADMIN_PASS" -L -o /dev/null

curl -s -X POST "$TARGET/admin" -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt \
  -d "asset_storage_enabled=on" -o /dev/null

# verificar
curl -s "$TARGET/admin" -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt | \
  grep -o 'checked'