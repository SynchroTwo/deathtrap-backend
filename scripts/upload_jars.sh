#!/bin/bash
# Run from LOCAL machine after ./gradlew bootJar.
# Usage: ENV=staging bash scripts/upload_jars.sh
set -euo pipefail
ENV=${ENV:-staging}
BUCKET="deathtrap-${ENV}-jars"
PREFIX="lambda-jars"

echo "=== Uploading Lambda JARs to s3://$BUCKET/$PREFIX/ ==="
SERVICES=(auth-service locker-service recovery-service \
           trigger-service audit-service sqs-consumer)

for svc in "${SERVICES[@]}"; do
  JAR="apps/${svc}/build/libs/${svc}-1.0.0-all.jar"
  [ -f "$JAR" ] || { echo "ERROR: $JAR not found. Run ./gradlew bootJar first."; exit 1; }
  SIZE=$(du -sh "$JAR" | cut -f1)
  echo "  Uploading ${svc} (${SIZE})..."
  aws s3 cp "$JAR" "s3://$BUCKET/$PREFIX/${svc}-1.0.0-all.jar" --region ap-south-1
done

echo ""
echo "Verifying upload:"
aws s3 ls "s3://$BUCKET/$PREFIX/" --region ap-south-1
echo "Done."
