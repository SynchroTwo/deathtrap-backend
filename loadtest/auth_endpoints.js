/**
 * k6 load test — DeathTrap auth-service endpoints
 *
 * Usage:
 *   BASE_URL=https://api.dev.deathtrap.in \
 *   MOBILE_COUNTRY_CODE=+91 \
 *   k6 run --vus 20 --duration 60s loadtest/auth_endpoints.js
 *
 * Environment variables:
 *   BASE_URL             — API Gateway base URL (no trailing slash)
 *   MOBILE_COUNTRY_CODE  — E.164 country code prefix, default "+91"
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.BASE_URL || "https://api.dev.deathtrap.in";
const COUNTRY  = __ENV.MOBILE_COUNTRY_CODE || "+91";

export const options = {
  scenarios: {
    // Scenario 1: steady-state load — 20 VUs for 60 s
    steady: {
      executor: "constant-vus",
      vus: 20,
      duration: "60s",
      tags: { scenario: "steady" },
    },
    // Scenario 2: ramp up to 100 VUs over 30 s, hold 60 s, ramp down 30 s
    ramp: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { target: 100, duration: "30s" },
        { target: 100, duration: "60s" },
        { target: 0,   duration: "30s" },
      ],
      startTime: "65s", // start after steady scenario finishes
      tags: { scenario: "ramp" },
    },
  },
  thresholds: {
    // p95 latency must stay below 800 ms for each tagged endpoint group
    "http_req_duration{endpoint:sendOtp}":    ["p(95)<800"],
    "http_req_duration{endpoint:verifyOtp}":  ["p(95)<800"],
    "http_req_duration{endpoint:login}":      ["p(95)<800"],
    // Overall error rate must stay below 1 %
    http_req_failed: ["rate<0.01"],
  },
};

// Custom metrics
const otpSendErrors   = new Counter("otp_send_errors");
const otpVerifyErrors = new Counter("otp_verify_errors");
const loginErrors     = new Counter("login_errors");
const otpRoundTrip    = new Trend("otp_round_trip_ms", true);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generate a random 10-digit Indian mobile number */
function randomMobile() {
  const digits = Math.floor(6000000000 + Math.random() * 3999999999);
  return `${COUNTRY}${digits}`;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

function post(path, body, tags) {
  return http.post(`${BASE_URL}${path}`, JSON.stringify(body), {
    headers: JSON_HEADERS,
    tags,
  });
}

// ---------------------------------------------------------------------------
// Default function — one VU iteration
// ---------------------------------------------------------------------------

export default function () {
  const mobile = randomMobile();

  // -------------------------------------------------------------------------
  // Group 1: POST /auth/otp/send
  // -------------------------------------------------------------------------
  let sendRes;
  group("sendOtp", () => {
    sendRes = post(
      "/auth/otp/send",
      { mobileNumber: mobile, channel: "SMS", purpose: "REGISTRATION" },
      { endpoint: "sendOtp" }
    );

    const ok = check(sendRes, {
      "sendOtp 200": (r) => r.status === 200,
      "sendOtp body has otpId": (r) => {
        try { return JSON.parse(r.body).data?.otpId !== undefined; }
        catch { return false; }
      },
    });
    if (!ok) otpSendErrors.add(1);
  });

  if (!sendRes || sendRes.status !== 200) {
    sleep(1);
    return;
  }

  // In a real test, the OTP would arrive via SMS. In a staging environment
  // the test user's OTP can be fixed or returned via a test hook. Here we
  // simulate the round-trip delay and use a well-known test OTP.
  const OTP_VALUE = __ENV.TEST_OTP || "000000";
  sleep(0.5); // simulate short network/SMS delay

  // -------------------------------------------------------------------------
  // Group 2: POST /auth/otp/verify
  // -------------------------------------------------------------------------
  let verifyRes;
  let verifiedToken;
  const otpStart = Date.now();

  group("verifyOtp", () => {
    let otpId;
    try { otpId = JSON.parse(sendRes.body).data?.otpId; } catch { /* ignore */ }

    verifyRes = post(
      "/auth/otp/verify",
      { otpId, otpValue: OTP_VALUE },
      { endpoint: "verifyOtp" }
    );

    otpRoundTrip.add(Date.now() - otpStart);

    const ok = check(verifyRes, {
      "verifyOtp 200": (r) => r.status === 200,
      "verifyOtp has verifiedToken": (r) => {
        try { return !!JSON.parse(r.body).data?.verifiedToken; }
        catch { return false; }
      },
    });
    if (!ok) otpVerifyErrors.add(1);

    try { verifiedToken = JSON.parse(verifyRes.body).data?.verifiedToken; } catch { /* ignore */ }
  });

  // -------------------------------------------------------------------------
  // Group 3: POST /auth/session (login with OTP — reuses same OTP flow)
  // -------------------------------------------------------------------------
  // Note: this group fires only when verifyOtp returned a verified token,
  // which doubles as a login token in the current auth flow.
  if (verifiedToken) {
    group("login", () => {
      const loginRes = post(
        "/auth/session",
        { verifiedToken },
        { endpoint: "login" }
      );

      const ok = check(loginRes, {
        "login 200": (r) => r.status === 200,
        "login has sessionToken": (r) => {
          try { return !!JSON.parse(r.body).data?.sessionToken; }
          catch { return false; }
        },
      });
      if (!ok) loginErrors.add(1);
    });
  }

  sleep(1);
}

// ---------------------------------------------------------------------------
// Summary hook — print pass/fail against thresholds
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  const lines = [
    "=== DeathTrap Auth Load Test Summary ===",
    `Total requests : ${data.metrics.http_reqs?.values?.count ?? "n/a"}`,
    `Error rate     : ${((data.metrics.http_req_failed?.values?.rate ?? 0) * 100).toFixed(2)} %`,
    `sendOtp p95    : ${data.metrics["http_req_duration{endpoint:sendOtp}"]?.values?.["p(95)"]?.toFixed(1) ?? "n/a"} ms`,
    `verifyOtp p95  : ${data.metrics["http_req_duration{endpoint:verifyOtp}"]?.values?.["p(95)"]?.toFixed(1) ?? "n/a"} ms`,
    `login p95      : ${data.metrics["http_req_duration{endpoint:login}"]?.values?.["p(95)"]?.toFixed(1) ?? "n/a"} ms`,
  ];
  console.log(lines.join("\n"));

  return {
    "loadtest/results/auth_summary.json": JSON.stringify(data, null, 2),
    stdout: lines.join("\n") + "\n",
  };
}
