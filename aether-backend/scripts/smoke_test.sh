#!/usr/bin/env bash
# Run this AFTER `docker compose up --build`, once the API is up on :8000.
# It exercises the real running API end to end: create a case, append custody
# entries, verify the tamper-evident chain, and download both exports.
set -euo pipefail

BASE="${1:-http://localhost:8000}"
EID="AT-2026-0047"

echo "== health =="
curl -sf "$BASE/api/health" | python3 -m json.tool

echo "== create case (ignore 409 if it already exists from a prior run) =="
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$BASE/api/cases" \
  -H "Content-Type: application/json" \
  -d '{
    "evidence_id": "'"$EID"'",
    "actor_name": "APT-091 (RedShark)",
    "aliases": ["ZeroTrace", "ShadowByte"],
    "origin_ip": "185.220.101.42",
    "geo": "Munich, Germany",
    "asn": "AS16276 OVH SAS",
    "pgp_fingerprint": "4D9E27BC918A4F02C73109AE2C5B88E140FA7D3C",
    "btc_root": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "confidence": 94.8,
    "onion_url": "http://p4lx7e22kq6dreadmarket.onion"
  }'

echo "== append custody entries =="
curl -sf -X POST "$BASE/api/cases/$EID/custody" -H "Content-Type: application/json" \
  -d '{"actor":"Analyst-01","action":"Target acquired and logged"}' | python3 -m json.tool
curl -sf -X POST "$BASE/api/cases/$EID/custody" -H "Content-Type: application/json" \
  -d '{"actor":"AETHER Recon Engine","action":"Origin IP recovered"}' | python3 -m json.tool

echo "== verify chain (expect valid: true) =="
curl -sf "$BASE/api/cases/$EID/verify" | python3 -m json.tool

echo "== async investigation (202 Accepted + job polling) =="
ASYNC_JOB=$(curl -sf -X POST "$BASE/api/cases/investigate" -H "Content-Type: application/json" \
  -d '{"case_name":"Smoke Async","evidence_id":"AT-SMOKE-ASYNC","actor_name":"SmokeActor","target":"185.220.101.42","target_type":"ip","mode":"demo"}')
echo "$ASYNC_JOB" | python3 -m json.tool
JOB_ID=$(python3 -c "import json; print(json.loads('''$ASYNC_JOB''')['job_id'])")

# Poll job snapshot
sleep 1
curl -sf "$BASE/api/jobs/$JOB_ID" | python3 -m json.tool

echo "== sync investigation (?sync=true legacy compat) =="
curl -sf -X POST "$BASE/api/cases/investigate?sync=true" -H "Content-Type: application/json" \
  -d '{"case_name":"Smoke Sync","evidence_id":"AT-SMOKE-SYNC","actor_name":"SmokeActorSync","target":"185.220.101.42","target_type":"ip","mode":"demo"}' | python3 -c "import sys, json; d=json.load(sys.stdin); print('Sync complete:', d['case']['evidence_id'], 'confidence:', d['attribution']['confidence_score'])"

echo "== export STIX (saved to /tmp/aether_stix.json) =="
curl -sf "$BASE/api/cases/$EID/export/stix" -o /tmp/aether_stix.json
python3 -c "import json; d=json.load(open('/tmp/aether_stix.json')); print(d['type'], len(d['objects']), 'objects')"

echo "== export CSV (saved to /tmp/aether_matrix.csv) =="
curl -sf "$BASE/api/cases/$EID/export/csv" -o /tmp/aether_matrix.csv
wc -l /tmp/aether_matrix.csv

echo "== ALL SMOKE CHECKS PASSED =="
