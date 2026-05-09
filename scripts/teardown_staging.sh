#!/bin/bash
# Run inside CloudShell ONLY after Sprint 10B prod is confirmed stable.
set -euo pipefail
echo "=== Tearing down DeathTrap STAGING ==="
echo "Destroys all staging resources. Ctrl+C within 5s to cancel."
sleep 5
cd ~/deathtrap-backend/infra
cdk destroy DeathTrapApiStack     --context env=staging --force
cdk destroy DeathTrapDataStack    --context env=staging --force
cdk destroy DeathTrapNetworkStack --context env=staging --force
echo "Staging teardown complete."
