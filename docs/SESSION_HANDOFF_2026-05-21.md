# DeathTrap Backend — Session Handoff (2026-05-21)

Cross-laptop handoff. The new session's per-project memory will be **empty** (memory
lives under `~/.claude/...` on the old machine), so this doc is the source of truth.
Optional: also copy the memory dir for full continuity (see §9).

---

## 1. Repo / environment basics
- **Repo:** `SynchroTwo/deathtrap-backend`, branch `main`, remote
  `https://github.com/SynchroTwo/deathtrap-backend.git`.
- **Working dir (old laptop):** `C:\Temp\deathtrap-backend`. Shell: PowerShell + git-bash.
- **Git identity for commits (REQUIRED):** author as
  `synchrotworepologin <synchrotwo@gmail.com>` using inline
  `git -c user.name=synchrotworepologin -c user.email=synchrotwo@gmail.com commit ...`
  (no persistent git config on the machine).
  - Stage files **explicitly by path**; never `git add -A`/`.`; **never** stage
    `.claude/settings.local.json` (local-only; it's the one always-modified file).
  - Conventional-commit messages (`feat:`/`fix:`/`build:`); keep the `Co-Authored-By` trailer.
  - Confirm commit+push intent per batch (user has been approving "commit + push" when tested).
- **Build env (Java not on PATH by default):**
  ```bash
  export JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-21.0.11.10-hotspot"
  export PATH="$JAVA_HOME/bin:$PATH"
  ```
  Then `./gradlew ...`. (Path will differ on the new laptop — find the JDK 21 install.)

## 2. Git state at handoff
- **HEAD = `9bf6c36`**, pushed (origin/main == HEAD). Working tree clean except
  `.claude/settings.local.json` (do not commit).
- This handoff doc is committed at `docs/SESSION_HANDOFF_2026-05-21.md`.
- Commits added this session (newest first):
  ```
  9bf6c36 fix: A7 PI-12 remediate high/critical CVEs to pass OWASP gate
  e620bc1 build: fix OWASP dependency-check (force commons-io 2.16.1 in buildSrc)
  ac0a320 fix: A7 PI-11 never log plaintext OTPs in prod
  c2cb53b fix: A7 PI-09 enforce revoked-token check on every request
  9610e20 feat: B-A6-5 creator-scoped GET /audit/me (owner-scoped audit query)
  1a5c36a fix: smoke_test.sh -- stale OTP path + curl header-dump misuse
  c07bfc1 fix: emit security headers on Spring MVC responses (shared filter)
  ```
  (Session started at `37587f6`; A6 commits `076dd3a`, `907b1c0`, `37587f6` were already in.)

## 3. Sprint status (backend)
- **A3 / A4 / A5:** complete + live on staging (A5 needed zero backend changes).
- **A6 (trigger↔recovery wiring): FULLY COMPLETE + deployed.** B-A6-1 peel-ciphertext
  relay (`recovery_peel_events.intermediate_ciphertext_b64`; `GET /recovery/session/{id}`
  serves `currentEncryptedB64`+`saltHex`+`blobId`+`layers[]`, migration V013); B-A6-2
  sqs-consumer auto-promotes trigger→approved at 2-of-3; B-A6-3 `PeelResponse.status` +
  true `remainingLayers`; B-A6-4 dev source-injection (`POST /trigger/dev/inject-source`,
  404 in prod); B-A6-5 creator-scoped `GET /audit/me`.
- **A7 (Hardening): all backend-codeable items DONE + deployed.** See §4. Remaining A7
  work is **not backend-only** (E2E + product decisions) — see §6.

## 4. A7 backend hardening — what was done (all deployed to staging)
- **PI-10 security headers** (`c07bfc1`): MVC responses bypass `ResponseBuilder` (raw-handler
  path), so HSTS/X-Frame-Options/X-Content-Type-Options were absent. Added
  `common-response/SecurityHeadersConfig` (a `OncePerRequestFilter` after CORS), auto-applied
  to all 5 HTTP services via `scanBasePackages=in.deathtrap.common`. **Rule: shared response
  behavior goes in a filter here, NOT ResponseBuilder.**
- **PI-09 revoked-token enforcement** (`c2cb53b`): per-request JWT validation only checked
  signature+expiry, so logged-out / passphrase-rotated tokens kept working on
  locker/recovery/trigger/audit until expiry. All 5 `JwtService` copies now take an optional
  `DbClient` and reject any `jti` present in `revoked_tokens` (`AUTH_SESSION_REVOKED`), one
  indexed PK lookup/request. 1-arg ctor kept for tests (db=null → no check).
- **PI-11 no plaintext OTP in prod** (`ac0a320`): `[DEV-OTP]` logs in
  SendMobileOtpHandler/SendEmailOtpHandler/RegisterInitHandler gated to local|staging only
  (matching SnsOtpService). Staging CloudWatch OTP retrieval still works; prod never logs OTPs.
- **4.6 dev endpoints 404 in prod:** verified — only dev endpoint is
  `/trigger/dev/inject-source` (`if(isProd()) throw notFound`). No other server-side dev endpoints.
- **PI-12 OWASP CVE triage + remediation** (`e620bc1`, `9bf6c36`): **OWASP gate now passes,
  0 CVEs ≥7.0 (was 18).** Details in §7.
- Also fixed `scripts/smoke_test.sh` (`1a5c36a`): real OTP path is `/auth/otp/send-mobile`
  (not the removed `/auth/otp/send`); header capture uses `curl -s -D -` (not `-sI -X POST -d`).
  Smoke test is **12/12 green**.

## 5. Staging facts & operational runbook
- **API base URL:** `https://oxr0z2zz81.execute-api.ap-south-1.amazonaws.com/prod`
  — note the stage path is **`/prod`** even on staging (CDK RestApi defaults stage to `prod`).
  Hitting `/staging/...` returns 403 (surfaces as a misleading CORS error in browsers).
- **Region:** ap-south-1. **Lambda fn names:** `deathtrap-staging-{auth-service,locker-service,
  recovery-service,trigger-service,audit-service,sqs-consumer}`. **Jar bucket:**
  `deathtrap-staging-jars`, key prefix `lambda-jars/`. **Blob bucket:** `deathtrap-staging`.
- **OTPs:** log-mode in staging (`ENVIRONMENT=staging` set on all lambdas). Retrieve from
  CloudWatch log group `/aws/lambda/deathtrap-staging-auth-service`, filter `"DEV-OTP"`
  (now gated to non-prod). Lines: `[DEV-OTP] SMS OTP for party=<id>: <otp>`.
- **Deploy mechanics (IMPORTANT):** Lambda code deploy is
  `aws s3 cp <svc>-1.0.0-all.jar s3://deathtrap-staging-jars/lambda-jars/` then
  `aws lambda update-function-code --function-name deathtrap-staging-<svc>
  --s3-bucket deathtrap-staging-jars --s3-key lambda-jars/<svc>-1.0.0-all.jar --region ap-south-1`,
  then `aws lambda wait function-updated ...`. **`cdk deploy` does NOT pick up new jar
  contents** (the S3 key is static). Build jar: `./gradlew :apps:<svc>:shadowJar` →
  `apps/<svc>/build/libs/<svc>-1.0.0-all.jar` (note sqs-consumer's is `sqs-consumer-...`, no `-service`).
  **Changing `common-*` (e.g. common-response/common-db) requires rebuild+redeploy of every
  dependent service** (all 5 HTTP services; sqs-consumer has no common-response dep).
- **Migrations:** staging RDS is `PRIVATE_ISOLATED` (reachable only from a VPC-attached
  CloudShell: Lambda subnet + Lambda SG). Run `ENV=staging bash scripts/migrate_staging.sh`.
  VPC CloudShell has no repo and no persistent home — bootstrap by `aws s3 cp` the script +
  **all** `migrations/sql/V001..Vnnn` (Flyway validates checksums of every applied migration)
  to a temp `s3://deathtrap-staging-jars/migrate-bootstrap/` prefix, then run. Current schema
  version: **V013** (applied).
- **Smoke test:** `BASE_URL=https://oxr0z2zz81.execute-api.ap-south-1.amazonaws.com/prod
  bash scripts/smoke_test.sh` → expect 12/12.
- **Mint a test JWT** (for endpoint verification; HS256, raw SecretString of
  `deathtrap/staging/jwt-secret` is the HMAC key — no JSON wrapper):
  ```bash
  SECRET=$(aws secretsmanager get-secret-value --secret-id deathtrap/staging/jwt-secret \
    --query SecretString --output text --region ap-south-1)
  b64url(){ openssl base64 -A | tr '+/' '-_' | tr -d '='; }
  NOW=$(date +%s)
  P=$(printf '%s' "{\"sub\":\"test\",\"partyType\":\"CREATOR\",\"jti\":\"t-$NOW\",\"iat\":$((NOW-10)),\"exp\":$((NOW+900))}" | b64url)
  H=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)
  SIG=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)
  TOKEN="$H.$P.$SIG"   # use as: Authorization: Bearer $TOKEN
  ```

## 6. OUTSTANDING — what's left for A7 (NOT backend-only)
1. **PI-16 CORS for a deployed preview origin — IMMEDIATE, needs UI input.**
   `CORS_ALLOWED_ORIGINS` is **unset** on staging lambdas → only *any-localhost* is allowed.
   - Localhost dev build → works now (verified OPTIONS from `localhost:5173` → 200).
   - A deployed preview URL (e.g. `*.vercel.app`) → **blocked** (no `Access-Control-Allow-Origin`).
   - **Correction to the UI's checklist:** CORS is enforced in **Spring `CorsFilter`
     (common-response), NOT API Gateway.** Fix = set `CORS_ALLOWED_ORIGINS` env on the 5 HTTP
     lambdas (comma-separated; supports patterns like `https://*.vercel.app`):
     ```bash
     aws lambda update-function-configuration --function-name deathtrap-staging-<svc> \
       --environment "Variables={...existing...,CORS_ALLOWED_ORIGINS=https://<origin>}" --region ap-south-1
     ```
     (Merge with existing env vars — don't drop ENVIRONMENT/JWT_SECRET_ARN/S3_BUCKET_NAME/etc.)
   - **ACTION:** ask the UI side for their exact dev/preview origin; if non-localhost, set the var.
2. **A7 Phase 1–3 staging E2E** — hands-on, needs the UI + a human (esp. 2.7 "HUMAN CONFIRMS:
   real recovery opened a real locker"). Backend prereqs PI-01/02/04/21 are all live (verified §8).
3. **Product decisions (not engineering-resolvable):**
   - **PI-02** trigger approval: currently **auto-promote** at 2-of-3. Decision: keep auto or add
     an admin-approval gate? (changes trust model). 
   - **PI-20** Aadhaar: plaintext vs client-encrypted — blocks real PII in Phase 2.
   - **PI-22** creator audit panel: build now or defer? (BE prereq `GET /audit/me` already shipped).
   - Launch scope: which P1-deferred features are launch-blocking.
4. **Companion doc not yet pulled:** the "Pending Items Register" (PI-01…PI-30) referenced by
   `DeathTrap_Sprint_A7_Hardening_Plan.docx` (in `C:\Temp\Downloads`) — pull it for exact
   acceptance criteria if doing more PI items.

## 7. PI-12 OWASP details (for reference)
- **Tooling fix (`e620bc1`):** dependency-check 12.1.0 failed to init
  (`NoSuchMethodError BOMInputStream.builder()`) because `shadow:8.1.1` leaked an old
  `commons-io` onto the build classpath. Fixed by pinning `commons-io:2.16.1` in
  `buildSrc/build.gradle.kts`. **Run with an NVD API key** or the NVD sync is rate-limited
  (30–60 min): `NVD_API_KEY=<key> ./gradlew dependencyCheckAggregate --no-daemon`. The NVD
  key is a **user secret** — pass via env only, never commit. Report:
  `build/reports/dependency-check/dependency-check-report.html` (set `format="ALL"` in
  `build.gradle.kts` temporarily for JSON; reverted to HTML).
- **Remediation (`9bf6c36`), all in `build.gradle.kts`:** Spring Boot 3.5.6→**3.5.14**;
  embedded **Tomcat pinned 10.1.55** via explicit `dependency(...)` pins for
  tomcat-embed-core/el/websocket (BOM ships 10.1.54; `bomProperty("tomcat.version",...)` did
  NOT work — use explicit pins); **excluded** `software.amazon.awssdk:netty-nio-client`
  globally in `subprojects {}` (async client never instantiated — services use only sync AWS
  clients + url-connection-client; removed 12 netty CVEs + ~4MB/jar); pgjdbc→**42.7.11**.
- Reachability triage (why the 9.8s were lower real risk): Tomcat connector is **never started**
  (aws-serverless-java-container `SpringBootLambdaContainerHandler`); netty was bundled-but-unused.
  Still upgraded for hygiene + to make the gate honest.

## 8. Verified live on staging at handoff
- Smoke test 12/12 (health ×5, unauth-401 ×4, OTP send-mobile 200, security headers ×2).
- `GET /audit/me` with a valid minted JWT → 200; no-auth → 401 `AUTH_UNAUTHORIZED`;
  bad token → 401 `AUTH_SESSION_INVALID`.
- PI-01 `GET /recovery/session/{id}` → 401 (route live). PI-04 `POST /trigger/dev/inject-source`
  → 400 (route live on staging, not 404). PI-21 bucket `deathtrap-staging` exists.
- All 6 lambdas Active/Successful on the latest jars (deployed 2026-05-21 ~13:5x IST).

## 9. Memory continuity (optional)
Old laptop has these (won't transfer automatically). If you want full agent memory on the new
machine, copy the contents of the project memory dir into the new machine's equivalent
`~/.claude/projects/<project>/memory/`:
- `MEMORY.md` (index)
- `feedback_git_commit_workflow.md`, `reference_staging_ops.md`, `project_sprint_status.md`
This handoff doc reproduces the essentials, so copying is nice-to-have, not required.

## 10. Suggested first actions in the new session
1. `git -C <repo> fetch && git log --oneline -8` — confirm HEAD is `9bf6c36`.
2. Set `JAVA_HOME` (JDK 21) for the new machine.
3. Resolve PI-16: get the UI's dev/preview origin; set `CORS_ALLOWED_ORIGINS` if non-localhost.
4. Then it's the UI/human's turn for A7 Phase 1–3 E2E; backend prereqs are all green.
