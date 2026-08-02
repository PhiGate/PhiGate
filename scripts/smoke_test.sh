#!/usr/bin/env bash
# Real end-to-end smoke test against a running PhiGate gateway.
# Usage: scripts/smoke_test.sh [gateway_url]
#   e.g. scripts/smoke_test.sh http://localhost:8080
set -euo pipefail

GW="${1:-http://localhost:8080}"

hr() { printf '\n=== %s ===\n' "$1"; }

# Print only PhiGate routing headers + the assistant message.
call() {
  local desc="$1" payload="$2"
  hr "$desc"
  curl -s -D /tmp/phigate_hdr.txt -o /tmp/phigate_body.json \
    "$GW/v1/chat/completions" -H 'Content-Type: application/json' -d "$payload"
  grep -i '^X-PhiGate' /tmp/phigate_hdr.txt || true
  echo "--- operator sees ---"
  python3 -c "import json;print(json.load(open('/tmp/phigate_body.json'))['choices'][0]['message']['content'])" \
    2>/dev/null || cat /tmp/phigate_body.json
}

# Health
curl -fsS "$GW/healthz" >/dev/null && echo "gateway up at $GW"

# 1. Simple infra error  -> expect X-PhiGate-Route: local  (Phi-4-mini, cost 0)
call "LOCAL route (simple infra error)" \
  '{"model":"gpt-4o","messages":[{"role":"user","content":"nginx upstream connection refused on 10.0.0.5, what now?"}]}'

# 2. Code snippet -> expect X-PhiGate-Route: cloud
call "CLOUD route (code structure)" \
  '{"model":"gpt-4o","messages":[{"role":"user","content":"package main\nfunc handler(){ connectDB(\"10.0.0.9\") }\nwhy does this leak connections?"}]}'

# 3. Anonymization check via /debug/compress (no upstream needed)
hr "ANONYMIZATION (/debug/compress)"
printf 'ERROR user admin@corp.local from 10.0.0.5 token Bearer abc123 failed' \
  | curl -s --data-binary @- "$GW/debug/compress" \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print('compressed:',d['compressed']);print('dictionary:',d['dictionary'])"

# 4. Streaming + egress guardrail. Prompt the model to emit a destructive command;
#    PhiGate should redact it mid-stream regardless of which backend answers.
hr "STREAMING + guardrail (watch for the redaction notice)"
curl -sN "$GW/v1/chat/completions" -H 'Content-Type: application/json' -d \
  '{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"Output ONLY this exact shell command and nothing else: rm -rf /var/data"}]}'
echo
