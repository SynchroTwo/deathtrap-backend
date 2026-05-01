import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambdaEventSources from 'aws-cdk-lib/aws-lambda-event-sources';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';

interface ApiStackProps extends cdk.StackProps {
  deployEnv: string;
  vpc: ec2.Vpc;
  lambdaSecurityGroup: ec2.SecurityGroup;
  dbSecretArn: string;
  s3BucketName: string;
  sqsTriggerUrl: string;
  snsNotifyArn: string;
  kmsKeyId: string;
}

/** Lambda functions and API Gateway for the DeathTrap platform. */
export class ApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);

    const {
      deployEnv, vpc, lambdaSecurityGroup,
      dbSecretArn, s3BucketName, sqsTriggerUrl, snsNotifyArn, kmsKeyId,
    } = props;
    const isProd = deployEnv === 'prod';

    const logRetention = isProd
      ? logs.RetentionDays.ONE_MONTH
      : logs.RetentionDays.ONE_WEEK;

    const commonEnv: Record<string, string> = {
      DB_SECRET_ARN: dbSecretArn,
      ENVIRONMENT: deployEnv,
      LOG_LEVEL: isProd ? 'INFO' : 'DEBUG',
      S3_BUCKET_NAME: s3BucketName,
      KMS_KEY_ID: kmsKeyId,
    };

    const lambdaDefaults: Partial<lambda.FunctionProps> = {
      runtime: lambda.Runtime.JAVA_21,
      architecture: lambda.Architecture.ARM_64,
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [lambdaSecurityGroup],
      tracing: lambda.Tracing.ACTIVE,
    };

    // Helper to create a Lambda function with SnapStart
    const createLambda = (
      name: string,
      jarPath: string,
      handler: string,
      memorySize: number,
      timeout: cdk.Duration,
      reservedConcurrency: number,
      env: Record<string, string>,
    ): lambda.Function => {
      const fn = new lambda.Function(this, name, {
        ...lambdaDefaults,
        functionName: `deathtrap-${deployEnv}-${name.toLowerCase()}`,
        code: lambda.Code.fromAsset(jarPath),
        handler,
        memorySize,
        timeout,
        reservedConcurrentExecutions: reservedConcurrency,
        environment: { ...commonEnv, ...env },
        logRetention,
      });
      // Enable SnapStart on published version
      const cfnFn = fn.node.defaultChild as lambda.CfnFunction;
      cfnFn.snapStart = { applyOn: 'PublishedVersions' };
      return fn;
    };

    const authFn = createLambda(
      'AuthService', '../apps/auth-service/build/libs/auth-service-1.0.0-all.jar',
      'in.deathtrap.auth.AuthHandler::handleRequest',
      256, cdk.Duration.seconds(15), isProd ? 50 : 10,
      { JWT_SECRET_ARN: `arn:aws:secretsmanager:ap-south-1:${this.account}:secret:deathtrap/${deployEnv}/jwt-secret` },
    );

    const lockerFn = createLambda(
      'LockerService', '../apps/locker-service/build/libs/locker-service-1.0.0-all.jar',
      'in.deathtrap.locker.LockerHandler::handleRequest',
      512, cdk.Duration.seconds(30), isProd ? 100 : 20, {},
    );

    const recoveryFn = createLambda(
      'RecoveryService', '../apps/recovery-service/build/libs/recovery-service-1.0.0-all.jar',
      'in.deathtrap.recovery.RecoveryHandler::handleRequest',
      256, cdk.Duration.seconds(30), isProd ? 20 : 5, {},
    );

    const triggerFn = createLambda(
      'TriggerService', '../apps/trigger-service/build/libs/trigger-service-1.0.0-all.jar',
      'in.deathtrap.trigger.TriggerHandler::handleRequest',
      256, cdk.Duration.seconds(60), isProd ? 10 : 3,
      { SQS_TRIGGER_URL: sqsTriggerUrl, SNS_NOTIFY_ARN: snsNotifyArn },
    );

    const auditFn = createLambda(
      'AuditService', '../apps/audit-service/build/libs/audit-service-1.0.0-all.jar',
      'in.deathtrap.audit.AuditHandler::handleRequest',
      128, cdk.Duration.seconds(15), isProd ? 20 : 5, {},
    );

    const sqsConsumerFn = createLambda(
      'SqsConsumer', '../apps/sqs-consumer/build/libs/sqs-consumer-1.0.0-all.jar',
      'in.deathtrap.sqsconsumer.SqsConsumerHandler::handleRequest',
      256, cdk.Duration.seconds(120), isProd ? 5 : 2,
      { SQS_TRIGGER_URL: sqsTriggerUrl, SNS_NOTIFY_ARN: snsNotifyArn },
    );

    // IAM: Secrets Manager access for all functions
    const secretPolicy = new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [dbSecretArn],
    });
    [authFn, lockerFn, recoveryFn, triggerFn, auditFn, sqsConsumerFn]
      .forEach(fn => fn.addToRolePolicy(secretPolicy));

    // IAM: SNS publish for auth
    authFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['sns:Publish'],
      resources: [snsNotifyArn],
    }));

    // IAM: S3 access
    lockerFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['s3:PutObject', 's3:GetObject'],
      resources: [`arn:aws:s3:::${s3BucketName}/locker/*`],
    }));
    recoveryFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['s3:PutObject', 's3:GetObject'],
      resources: [`arn:aws:s3:::${s3BucketName}/recovery/*`],
    }));
    auditFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['s3:PutObject', 's3:GetObject'],
      resources: [`arn:aws:s3:::${s3BucketName}/audit/*`],
    }));

    // IAM: SQS send for trigger
    triggerFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['sqs:SendMessage'],
      resources: [sqs.Queue.fromQueueUrl(this, 'TriggerQueueRef', sqsTriggerUrl).queueArn],
    }));

    // SQS event source mapping for sqs-consumer
    sqsConsumerFn.addEventSource(new lambdaEventSources.SqsEventSource(
      sqs.Queue.fromQueueUrl(this, 'TriggerQueueConsumerRef', sqsTriggerUrl),
      { batchSize: 1, enabled: true },
    ));

    // API Gateway
    const accessLogGroup = new logs.LogGroup(this, 'ApiAccessLogs', {
      retention: logRetention,
    });

    const api = new apigateway.RestApi(this, 'DeathTrapApi', {
      restApiName: `deathtrap-${deployEnv}-api`,
      endpointConfiguration: { types: [apigateway.EndpointType.REGIONAL] },
      deployOptions: {
        accessLogDestination: new apigateway.LogGroupLogDestination(accessLogGroup),
        accessLogFormat: apigateway.AccessLogFormat.jsonWithStandardFields(),
        tracingEnabled: true,
        throttlingBurstLimit: isProd ? 1000 : 100,
        throttlingRateLimit: isProd ? 500 : 50,
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
      },
    });

    // Route proxy integrations
    const routes: Array<{ path: string; fn: lambda.Function }> = [
      { path: 'auth', fn: authFn },
      { path: 'locker', fn: lockerFn },
      { path: 'recovery', fn: recoveryFn },
      { path: 'trigger', fn: triggerFn },
      { path: 'audit', fn: auditFn },
    ];

    for (const route of routes) {
      const resource = api.root.addResource(route.path);
      const proxy = resource.addResource('{proxy+}');
      const integration = new apigateway.LambdaIntegration(route.fn);
      proxy.addMethod('ANY', integration);
      resource.addMethod('ANY', integration);
    }

    new cdk.CfnOutput(this, 'ApiUrl', { value: api.url });
  }
}
