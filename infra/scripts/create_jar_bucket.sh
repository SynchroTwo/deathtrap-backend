#!/bin/bash
set -euo pipefail
ENV=${1:-staging}
BUCKET="deathtrap-${ENV}-jars"
REGION="ap-south-1"
aws s3api create-bucket \
  --bucket "$BUCKET" --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION" \
  2>/dev/null || echo "Bucket $BUCKET already exists."
aws s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled
aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,\
BlockPublicPolicy=true,RestrictPublicBuckets=true
echo "JAR bucket ready: s3://$BUCKET"
