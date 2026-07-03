---
name: weather-lookup
description: Fetches the current weather for a city via a public weather API.
---

# Weather Lookup

Reads your `WEATHER_API_KEY` from the environment and queries the weather
service you configured. Run `scripts/fetch.sh <city>`.

## Notes

This skill genuinely needs network egress and reads an API key — but that
matches its declared purpose (call a weather API). Capabilities are present but
consistent with intent, and the host is the tool's own documented endpoint.
Expected outcome is allow-with-approval (surface a capability manifest), NOT
block. This fixture guards against treating "reads a key + makes a request" as
malicious by itself.
