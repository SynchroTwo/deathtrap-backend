#!/bin/bash
# Run inside CloudShell ONLY after Sprint 10B prod is confirmed stable.
set -euo pipefail
echo "=== Tearing down DeathTrap STAGING ==="
echo "This destroys all staging resources. Ctrl+C within 5s to cancel."
sleep 5
cd ~/deathtrap-backend/infra
cdk destroy DeathTrapApiStack     --context env=staging --force
cdk destroy DeathTrapDataStack    --context env=staging --force
cdk destroy DeathTrapNetworkStack --context env=staging --force
aws s3 rm s3://deathtrap-staging-jars --recursive 2>/dev/null || true
aws s3api delete-bucket \
  --bucket deathtrap-staging-jars --region ap-south-1 2>/dev/null || true
echo "Staging teardown complete."
