#!/usr/bin/env bash
# Apply Flyway migrations to a DeathTrap RDS.
#
# NETWORK: the staging RDS lives in a PRIVATE_ISOLATED subnet whose security
# group only accepts inbound from the Lambda SG. Plain CloudShell / a laptop
# CANNOT reach it (you'll get a SocketTimeout). Run this from a VPC-attached
# AWS CloudShell environment configured with:
#   - Subnet:         a "Lambda" (PRIVATE_WITH_EGRESS) subnet of the staging VPC
#   - Security group:  the Lambda SG ("Security group for Lambda functions")
# (See docs/NOMINEE_INVITE_PATH_A.md for how to discover those IDs.)
#
# Credentials are read from the RDS-managed secret (no jq required). Flyway runs
# via Docker if available, else the self-contained Flyway CLI (bundled JRE) is
# downloaded — so this works in VPC CloudShell where Docker may be absent.
#
# Usage:
#   ENV=staging bash scripts/migrate_staging.sh          # info, then migrate
#   ENV=staging bash scripts/migrate_staging.sh info     # info only (no changes)
#   REGION=ap-south-1 ENV=staging bash scripts/migrate_staging.sh
set -euo pipefail

ENV="${ENV:-staging}"
REGION="${REGION:-ap-south-1}"
ACTION="${1:-migrate}"
FLYWAY_VERSION="10.22.0"
FW_HOME="${TMPDIR:-/tmp}/deathtrap-flyway"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_DIR="$SCRIPT_DIR/../migrations/sql"
[ -d "$SQL_DIR" ] || { echo "ERROR: $SQL_DIR not found (run from a clone of the repo)"; exit 1; }
SQL_DIR="$(cd "$SQL_DIR" && pwd)"

echo "=== DeathTrap migrate: env=$ENV region=$REGION action=$ACTION ==="

# 1. Resolve DB credentials from the RDS-managed secret (jq-free).
#    RDS-generated secrets are flat JSON and exclude '\"' from the password by
#    default, so the quoted-string grep is safe.
DB_SECRET_ARN=$(aws cloudformation describe-stacks \
  --stack-name "DeathTrap-Data-$ENV" \
  --query "Stacks[0].Outputs[?OutputKey=='DbSecretArn'].OutputValue" \
  --output text --region "$REGION")
[ -n "$DB_SECRET_ARN" ] && [ "$DB_SECRET_ARN" != "None" ] \
  || { echo "ERROR: DbSecretArn output not found on stack DeathTrap-Data-$ENV"; exit 1; }

SECRET=$(aws secretsmanager get-secret-value --secret-id "$DB_SECRET_ARN" \
  --query SecretString --output text --region "$REGION")

extract_str() { echo "$SECRET" | grep -o "\"$1\":\"[^\"]*\"" | head -1 | sed 's/.*:"//;s/"$//'; }
DB_HOST=$(extract_str host)
DB_USER=$(extract_str username)
DB_PASS=$(extract_str password)
DB_NAME=$(extract_str dbname); DB_NAME="${DB_NAME:-deathtrap}"
DB_PORT=$(echo "$SECRET" | grep -o '"port":[0-9]*' | head -1 | sed 's/.*://'); DB_PORT="${DB_PORT:-5432}"

[ -n "$DB_HOST" ] && [ -n "$DB_USER" ] && [ -n "$DB_PASS" ] \
  || { echo "ERROR: could not parse host/username/password from secret"; exit 1; }
echo "  db: $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME (passlen=${#DB_PASS})"

# Pass connection details via FLYWAY_* env (keeps the password out of argv/ps).
export FLYWAY_URL="jdbc:postgresql://$DB_HOST:$DB_PORT/$DB_NAME"
export FLYWAY_USER="$DB_USER"
export FLYWAY_PASSWORD="$DB_PASS"

run_flyway() {
  local cmd="$1"
  if command -v docker >/dev/null 2>&1; then
    docker run --rm \
      -e FLYWAY_URL -e FLYWAY_USER -e FLYWAY_PASSWORD \
      -v "$SQL_DIR:/flyway/sql" \
      "flyway/flyway:${FLYWAY_VERSION%%.*}" -outOfOrder=false "$cmd"
  else
    local fw_dir="$FW_HOME/flyway-$FLYWAY_VERSION"
    if [ ! -x "$fw_dir/flyway" ]; then
      echo "  docker not found; fetching Flyway CLI $FLYWAY_VERSION (bundled JRE) ..."
      mkdir -p "$FW_HOME"
      curl -fsSL -o "$FW_HOME/flyway.tar.gz" \
        "https://download.red-gate.com/maven/release/com/redgate/flyway/flyway-commandline/$FLYWAY_VERSION/flyway-commandline-$FLYWAY_VERSION-linux-x64.tar.gz"
      tar -xzf "$FW_HOME/flyway.tar.gz" -C "$FW_HOME"
    fi
    FLYWAY_LOCATIONS="filesystem:$SQL_DIR" "$fw_dir/flyway" -outOfOrder=false "$cmd"
  fi
}

# 2. Always show current state first.
run_flyway info

# 3. Apply unless the caller asked for info only.
if [ "$ACTION" = "migrate" ]; then
  run_flyway migrate
  echo "--- post-migrate state ---"
  run_flyway info
else
  echo "Action '$ACTION' is not 'migrate' — skipping apply."
fi

echo "Done."
