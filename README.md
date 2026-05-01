# DeathTrap Backend

Zero-knowledge estate planning platform — Java 21 + Spring Boot 3 monorepo targeting AWS Lambda.

## Monorepo Structure

```
deathtrap-backend/
├── packages/
│   ├── common-types/       # Domain records, enums, DTOs, API wrappers
│   ├── common-errors/      # ErrorCode enum, AppException, GlobalExceptionHandler
│   ├── common-response/    # Lambda response builder with security headers
│   ├── common-db/          # HikariCP config, DbClient wrapper
│   ├── common-crypto/      # AES-GCM, HKDF, SHA-256, CSPRNG utilities
│   └── common-audit/       # Tamper-evident audit log writer
├── apps/
│   ├── auth-service/       # OTP, registration, login, session management
│   ├── locker-service/     # Encrypted asset locker (Sprint 2)
│   ├── recovery-service/   # Multi-layer recovery blobs (Sprint 2)
│   ├── trigger-service/    # Death trigger evaluation (Sprint 2)
│   ├── audit-service/      # Audit log queries (Sprint 2)
│   └── sqs-consumer/       # SQS trigger event processor (Sprint 2)
├── infra/                  # AWS CDK in TypeScript
├── migrations/             # Flyway SQL migrations
└── .github/workflows/      # CI/CD pipelines
```

## Prerequisites

- Java 21 (Temurin recommended)
- Gradle 8.7 (via wrapper — `./gradlew`)
- Docker Desktop (for Flyway migrations locally)
- AWS SAM CLI (for local Lambda testing)
- IntelliJ IDEA (recommended)
- Node.js 20+ (for CDK)

## Setup

```bash
git clone <repo-url>
cd deathtrap-backend
cp .env.example .env
# Fill in your Neon PostgreSQL connection string and JWT_SECRET in .env
./gradlew build
./gradlew test
```

## Run Locally (AWS SAM)

```bash
# Auth service
cd apps/auth-service
sam local start-api --template template.yaml

# Set environment variables before starting SAM:
export DB_URL="postgresql://user:pass@host/db?sslmode=require"
export DB_USERNAME="your_username"
export DB_PASSWORD="your_password"
export JWT_SECRET="your_secret"
export ENVIRONMENT="local"
```

## Run Migrations

```bash
docker run --rm \
  -v $(pwd)/migrations/sql:/flyway/sql \
  flyway/flyway:10 \
  -url="jdbc:postgresql://host/deathtrap?sslmode=require" \
  -user="username" \
  -password="password" \
  migrate
```

## CI/CD

| Trigger | Action |
|---------|--------|
| Pull Request | Build, checkstyle, unit tests, CDK synth |
| Push to `main` | Auto-deploy to dev environment |
| Manual workflow dispatch | Deploy to prod (requires approval) |

## Sprint Status

| Sprint | Status | Scope |
|--------|--------|-------|
| Sprint 1 — Foundation | ✅ | Monorepo setup, auth service, common packages, CDK infra, migrations |
| Sprint 2 — Locker | 🔜 | Asset locker, nominee assignment, encrypted blobs |
| Sprint 3 — Recovery | 🔜 | Multi-layer recovery, session peeling |
| Sprint 4 — Trigger | 🔜 | Death trigger sources, dispute resolution |
| Sprint 5 — Production | 🔜 | KYC integration, hardening, penetration testing |
