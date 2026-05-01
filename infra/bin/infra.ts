#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { NetworkStack } from '../lib/stacks/network-stack';
import { DataStack } from '../lib/stacks/data-stack';
import { ApiStack } from '../lib/stacks/api-stack';

const app = new cdk.App();

const env = app.node.tryGetContext('env') as string;
if (!env || !['dev', 'prod'].includes(env)) {
  throw new Error("Context variable 'env' must be 'dev' or 'prod'. Pass --context env=dev");
}

const accountEnvVar = env === 'prod' ? 'AWS_ACCOUNT_PROD' : 'AWS_ACCOUNT_DEV';
const account = process.env[accountEnvVar];
if (!account) {
  throw new Error(`Environment variable ${accountEnvVar} is required`);
}

const awsEnv: cdk.Environment = { account, region: 'ap-south-1' };

const commonTags = {
  Project: 'DeathTrap',
  Environment: env,
  ManagedBy: 'CDK',
};

const networkStack = new NetworkStack(app, `DeathTrap-Network-${env}`, {
  env: awsEnv,
  deployEnv: env,
  tags: commonTags,
});

const dataStack = new DataStack(app, `DeathTrap-Data-${env}`, {
  env: awsEnv,
  deployEnv: env,
  vpc: networkStack.vpc,
  lambdaSecurityGroup: networkStack.lambdaSecurityGroup,
  dbSecurityGroup: networkStack.dbSecurityGroup,
  tags: commonTags,
});
dataStack.addDependency(networkStack);

const apiStack = new ApiStack(app, `DeathTrap-Api-${env}`, {
  env: awsEnv,
  deployEnv: env,
  vpc: networkStack.vpc,
  lambdaSecurityGroup: networkStack.lambdaSecurityGroup,
  dbSecretArn: dataStack.dbSecretArn,
  s3BucketName: dataStack.s3BucketName,
  sqsTriggerUrl: dataStack.sqsTriggerUrl,
  snsNotifyArn: dataStack.snsNotifyArn,
  kmsKeyId: dataStack.kmsKeyId,
  tags: commonTags,
});
apiStack.addDependency(dataStack);

app.synth();
