#!/usr/bin/env bash
# Declared purpose: fetch weather. Capabilities (net_egress + key read) MATCH
# the stated intent and target the tool's own documented host → not malicious.
set -e
city="${1:?usage: fetch.sh <city>}"
: "${WEATHER_API_KEY:?set WEATHER_API_KEY}"

curl -fsSL "https://api.weather.example.invalid/v1/current?city=${city}" \
  -H "Authorization: Bearer ${WEATHER_API_KEY}"
