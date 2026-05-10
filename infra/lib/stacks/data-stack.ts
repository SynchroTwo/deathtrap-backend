import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as sns from 'aws-cdk-lib/aws-sns';
import { Construct } from 'constructs';
import { getConfig } from '../config';

interface DataStackProps extends cdk.StackProps {
  deployEnv: string;
  vpc: ec2.Vpc;
  lambdaSecurityGroup: ec2.SecurityGroup;
  dbSecurityGroup: ec2.SecurityGroup;
}

/** KMS, RDS Aurora, S3, SQS, SNS resources for the DeathTrap platform. */
export class DataStack extends cdk.Stack {
  public readonly dbSecretArn: string;
  public readonly s3BucketName: string;
  public readonly sqsTriggerUrl: string;
  public readonly sqsTriggerArn: string;
  public readonly sqsTriggerDlqArn: string;
  public readonly snsNotifyArn: string;
  public readonly kmsKeyId: string;

  constructor(scope: Construct, id: string, props: DataStackProps) {
    super(scope, id, props);

    const { deployEnv, vpc, dbSecurityGroup } = props;
    const config = getConfig(deployEnv);
    const isProd = config.environment === 'prod';

    // KMS CMK with annual rotation
    const kmsKey = new kms.Key(this, 'DeathTrapKmsKey', {
      enableKeyRotation: true,
      description: `DeathTrap CMK - ${deployEnv}`,
      removalPolicy: isProd ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });
    this.kmsKeyId = kmsKey.keyId;

    // Aurora Serverless v2 — PostgreSQL 15
    const dbCluster = new rds.DatabaseCluster(this, 'AuroraCluster', {
      engine: rds.DatabaseClusterEngine.auroraPostgres({
        version: rds.AuroraPostgresEngineVersion.VER_15_4,
      }),
      serverlessV2MinCapacity: config.auroraMinAcu,
      serverlessV2MaxCapacity: config.auroraMaxAcu,
      writer: rds.ClusterInstance.serverlessV2('Writer', {
        scaleWithWriter: true,
      }),
      readers: config.auroraInstances > 1
        ? [rds.ClusterInstance.serverlessV2('Reader', { scaleWithWriter: false })]
        : [],
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      securityGroups: [dbSecurityGroup],
      storageEncrypted: true,
      storageEncryptionKey: kmsKey,
      backup: { retention: cdk.Duration.days(config.auroraBackupDays) },
      deletionProtection: config.deletionProtection,
      removalPolicy: isProd ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
      defaultDatabaseName: 'deathtrap',
    });
    this.dbSecretArn = dbCluster.secret!.secretArn;

    // S3 bucket for encrypted blobs
    const bucket = new s3.Bucket(this, 'DeathTrapBucket', {
      bucketName: config.bucketName,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: kmsKey,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: isProd ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: !isProd,
    });
    // Object prefix conventions (comment only — not enforced by CDK):
    //   locker/   — encrypted locker blobs
    //   recovery/ — recovery blobs
    //   audit/    — audit exports
    this.s3BucketName = bucket.bucketName;

    // SQS DLQ
    const dlq = new sqs.Queue(this, 'TriggerDlq', {
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: kmsKey,
      retentionPeriod: cdk.Duration.days(14),
    });

    // SQS trigger queue
    const triggerQueue = new sqs.Queue(this, 'TriggerQueue', {
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: kmsKey,
      visibilityTimeout: cdk.Duration.minutes(5),
      retentionPeriod: cdk.Duration.days(14),
      deadLetterQueue: { queue: dlq, maxReceiveCount: 3 },
    });
    this.sqsTriggerUrl = triggerQueue.queueUrl;
    this.sqsTriggerArn = triggerQueue.queueArn;
    this.sqsTriggerDlqArn = dlq.queueArn;

    // SNS notification topic
    const snsTopic = new sns.Topic(this, 'NotifyTopic', {
      masterKey: kmsKey,
      displayName: `DeathTrap Notifications - ${deployEnv}`,
    });
    this.snsNotifyArn = snsTopic.topicArn;

    new cdk.CfnOutput(this, 'DbSecretArn', { value: this.dbSecretArn });
    new cdk.CfnOutput(this, 'S3BucketName', { value: this.s3BucketName });
    new cdk.CfnOutput(this, 'SqsTriggerUrl', { value: this.sqsTriggerUrl });
    new cdk.CfnOutput(this, 'SnsNotifyArn', { value: this.snsNotifyArn });
    new cdk.CfnOutput(this, 'KmsKeyId', { value: this.kmsKeyId });
  }
}
