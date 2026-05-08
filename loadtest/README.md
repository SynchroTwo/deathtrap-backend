# DeathTrap Load Tests

k6-based load tests for the auth-service endpoints.

## Prerequisites

Install k6 from https://k6.io/docs/get-started/installation/.

```bash
# macOS
brew install k6

# Windows (via Chocolatey)
choco install k6

# Linux (Debian/Ubuntu)
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
     --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \
     | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6
```

## Running the auth endpoint test

```bash
# Smoke test — 1 VU, 30 s
BASE_URL=https://api.dev.deathtrap.in \
TEST_OTP=000000 \
k6 run --vus 1 --duration 30s loadtest/auth_endpoints.js

# Standard load — uses the scenarios defined in the script
BASE_URL=https://api.dev.deathtrap.in \
TEST_OTP=000000 \
k6 run loadtest/auth_endpoints.js

# Override VUs and duration (ignores the scenarios block)
BASE_URL=https://api.dev.deathtrap.in \
TEST_OTP=000000 \
k6 run --vus 50 --duration 120s loadtest/auth_endpoints.js
```

## Environment variables

| Variable            | Required | Default                       | Description                            |
|---------------------|----------|-------------------------------|----------------------------------------|
| `BASE_URL`          | Yes      | `https://api.dev.deathtrap.in`| API Gateway stage URL (no trailing /)  |
| `MOBILE_COUNTRY_CODE` | No     | `+91`                         | E.164 country prefix for test numbers  |
| `TEST_OTP`          | Yes (staging) | `000000`               | Fixed OTP value accepted by staging DB |

## Staging setup for a fixed OTP

The test uses `TEST_OTP` (default `000000`) as the OTP value in every iteration. For this to succeed in a staging environment, set up one of:

1. **Fixed-hash row**: pre-insert a `party_otp_log` row where `otp_hash = SHA256("000000")` and `verified_at IS NULL` for the test mobile range.
2. **Feature flag**: add a `DISABLE_OTP_VERIFICATION=true` env var to the staging Lambda that bypasses OTP validation. Remove before production.
3. **Test hook endpoint**: add `POST /internal/otp/override` (IP-allowlisted) that returns the live OTP for a given party — usable in a `setup()` function.

## Thresholds (defined in script)

| Metric                            | Threshold   |
|-----------------------------------|-------------|
| `http_req_duration{endpoint:sendOtp}` p95  | < 800 ms |
| `http_req_duration{endpoint:verifyOtp}` p95 | < 800 ms |
| `http_req_duration{endpoint:login}` p95    | < 800 ms |
| `http_req_failed` rate            | < 1 %       |

k6 exits with code 99 if any threshold is breached, making it CI-friendly.

## Results

k6 writes a JSON summary to `loadtest/results/auth_summary.json` after each run. This file is git-ignored — commit only significant baseline snapshots.

Add `loadtest/results/` to `.gitignore` if not already present.
