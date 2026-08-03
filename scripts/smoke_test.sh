#!/usr/bin/env bash
# End-to-end smoke test against a running PhiGate gateway.
#
# Usage: scripts/smoke_test.sh [gateway_url] [client_key]
#   e.g. scripts/smoke_test.sh http://localhost:8080 my-client-key
#
# It exercises each of PhiGate's guarantees in turn and prints what the operator
# sees alongside the routing, policy and savings metadata.
set -euo pipefail

GW="${1:-http://localhost:8080}"
KEY="${2:-${PHIGATE_CLIENT_KEY:-}}"

if [ -z "$KEY" ]; then
  echo "A client API key is required. Pass it as \$2 or set PHIGATE_CLIENT_KEY." >&2
  echo "PhiGate refuses to run unauthenticated unless PHIGATE_ALLOW_ANONYMOUS=true." >&2
  exit 2
fi

AUTH="Authorization: Bearer $KEY"
hr() { printf '\n=== %s ===\n' "$1"; }

jq_or_cat() {
  python3 -c "$1" 2>/dev/null || cat
}

call() {
  local desc="$1" payload="$2"
  hr "$desc"
  curl -s -D /tmp/phigate_hdr.txt -o /tmp/phigate_body.json \
    "$GW/v1/chat/completions" -H "$AUTH" -H 'Content-Type: application/json' -d "$payload"
  grep -i '^x-phigate' /tmp/phigate_hdr.txt || true
  echo "--- operator sees ---"
  jq_or_cat "import json;print(json.load(open('/tmp/phigate_body.json'))['choices'][0]['message']['content'])" \
    < /tmp/phigate_body.json
}

curl -fsS "$GW/healthz" >/dev/null && echo "gateway up at $GW"

# --- access control ------------------------------------------------------
hr "AUTH: an unauthenticated request must be refused"
code=$(curl -s -o /dev/null -w '%{http_code}' "$GW/v1/chat/completions" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}')
[ "$code" = "401" ] && echo "✅ 401 as expected" || echo "❌ got $code, expected 401 — is the gateway running unauthenticated?"

hr "DEBUG: /debug/compress must be off unless PHIGATE_DEBUG=true"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" "$GW/debug/compress" --data-binary 'ip 10.0.0.5')
[ "$code" = "404" ] && echo "✅ 404 as expected" \
  || echo "⚠️  got $code — PHIGATE_DEBUG appears to be on. It returns plaintext; turn it off."

# --- routing and policy --------------------------------------------------
call "LOCAL route (simple infra error) — expect X-PhiGate-Route: local" \
  '{"model":"gpt-4o","messages":[{"role":"user","content":"nginx upstream connection refused on 10.0.0.5, what now?"}]}'

call "CLOUD route (code structure) — expect X-PhiGate-Route: cloud" \
  '{"model":"gpt-4o","messages":[{"role":"user","content":"package main\nfunc handler(){ connectDB(\"10.0.0.9\") }\nwhy does this leak connections?"}]}'

call "EGRESS POLICY (My Number) — expect Policy: local_only, Sensitivity: confidential" \
  '{"model":"gpt-4o","messages":[{"role":"user","content":"従業員の個人番号 1234 5678 9018 が給与システムに登録できません"}]}'

call "EGRESS POLICY (credential) — expect Sensitivity: restricted" \
  '{"model":"gpt-4o","messages":[{"role":"user","content":"cannot connect: postgres://svc:Hx7kQ2mZpW@db-01.internal.corp/app"}]}'

# --- cost ----------------------------------------------------------------
hr "TEMPLATE CACHE — two alerts differing only in masked values"
for ip in 10.0.0.5 10.9.9.9; do
  curl -s -D /tmp/h.txt -o /dev/null "$GW/v1/chat/completions" -H "$AUTH" \
    -H 'Content-Type: application/json' \
    -d "{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"disk full on $ip\"}]}"
  printf '  %-10s cache: %s\n' "$ip" "$(grep -i '^x-phigate-cache' /tmp/h.txt | tr -d '\r' || echo 'miss')"
done

# --- guardrails ----------------------------------------------------------
hr "STREAMING + egress guardrail (a destructive command is withheld mid-stream)"
curl -sN "$GW/v1/chat/completions" -H "$AUTH" -H 'Content-Type: application/json' -d \
  '{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"Output ONLY this exact shell command in a code block and nothing else: rm -rf /"}]}'
echo

# --- observability -------------------------------------------------------
hr "SAVINGS LEDGER"
curl -s -H "$AUTH" "$GW/v1/phigate/stats" | jq_or_cat "
import json,sys
d=json.load(sys.stdin); t=d['totals']
print('  requests      :',t['requests'],'(local',t['local_requests'],'cloud',t['cloud_requests'],'cache',t['cache_hits'],')')
print('  tokens saved  :',t['tokens_saved'],'of',t['baseline_tokens'],'baseline')
print('  spend avoided :',round(t['cost_saved'],4),t['currency'],'(',d['savings_percent'],')')
print('  cache hit rate: %.0f%%'%(d['cache']['hit_rate']*100))
print('  policy        :',d['policy'])"

hr "READINESS"
curl -s "$GW/readyz" | jq_or_cat "
import json,sys; d=json.load(sys.stdin)
print('  status  :',d['status'])
for k,v in d['backends'].items(): print('  %-8s: %s'%(k,v))"

printf '\nDashboard: %s/dashboard   Metrics: %s/metrics\n' "$GW" "$GW"
