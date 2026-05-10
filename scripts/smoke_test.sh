#!/bin/bash
# Run from CloudShell or LOCAL.
# Usage: BASE_URL=https://XXXX.execute-api.ap-south-1.amazonaws.com/staging \
#        bash scripts/smoke_test.sh
set -euo pipefail
BASE="${BASE_URL:?Set BASE_URL to your API Gateway endpoint}"
PASS=0; FAIL=0

check() {
  [ "$3" = "$2" ] \
    && { echo "  ✓ $1"; PASS=$((PASS+1)); } \
    || { echo "  ✗ $1 (expected $2, got $3)"; FAIL=$((FAIL+1)); }
}

echo "=== DeathTrap Smoke Tests: $BASE ==="

echo "-- Health checks --"
for svc in auth locker recovery trigger audit; do
  check "${svc}-service health" 200 \
    $(curl -sf -o /dev/null -w "%{http_code}" $BASE/${svc}/health)
done

echo "-- Unauthenticated must return 401 --"
check "GET /locker/sync no auth"      401 $(curl -sf -o /dev/null -w "%{http_code}" $BASE/locker/sync)
check "GET /recovery/blob no auth"    401 $(curl -sf -o /dev/null -w "%{http_code}" $BASE/recovery/blob)
check "POST /trigger/checkin no auth" 401 $(curl -sf -o /dev/null -w "%{http_code}" -X POST $BASE/trigger/checkin)
check "GET /audit/log no auth"        401 $(curl -sf -o /dev/null -w "%{http_code}" $BASE/audit/log)

echo "-- OTP send (log mode) --"
R=$(curl -sf -o /dev/null -w "%{http_code}" -X POST $BASE/auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{"mobile":"+919999999990","purpose":"registration"}')
check "POST /auth/otp/send" "200" "$R"

echo "-- Security headers --"
H=$(curl -sI -X POST $BASE/auth/otp/send -H "Content-Type: application/json" -d '{}')
echo "$H" | grep -qi "X-Frame-Options" \
  && { echo "  ✓ X-Frame-Options"; PASS=$((PASS+1)); } \
  || { echo "  ✗ X-Frame-Options MISSING"; FAIL=$((FAIL+1)); }
echo "$H" | grep -qi "X-Content-Type-Options" \
  && { echo "  ✓ X-Content-Type-Options"; PASS=$((PASS+1)); } \
  || { echo "  ✗ X-Content-Type-Options MISSING"; FAIL=$((FAIL+1)); }

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && echo "All smoke tests PASSED. Ready for Sprint 10B." \
  || { echo "SMOKE TESTS FAILED."; exit 1; }
