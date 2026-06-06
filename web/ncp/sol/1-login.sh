#!/bin/bash
TARGET="http://154.57.164.74:31330"
USER="attacker"
PASS="attacker123"

curl -s -X POST "$TARGET/register" -c /tmp/user_cookies.txt \
  -d "username=$USER&password=$PASS&confirm_password=$PASS"

curl -s -X POST "$TARGET/" -c /tmp/user_cookies.txt -b /tmp/user_cookies.txt \
  -d "username=$USER&password=$PASS" -L -o /dev/null

cat /tmp/user_cookies.txt