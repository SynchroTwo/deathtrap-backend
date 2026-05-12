import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambdaEventSources from 'aws-cdk-lib/aws-lambda-event-sources';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';
import { getConfig } from '../config';

interface ApiStackProps extends cdk.StackProps {
  deployEnv: string;
  vpc: ec2.Vpc;
  lambdaSecurityGroup: ec2.SecurityGroup;
  dbSecretArn: string;
  s3BucketName: string;
  sqsTriggerUrl: string;
  sqsTriggerArn: string;
  sqsTriggerDlqArn: string;
  snsNotifyArn: string;
  kmsKeyId: string;
}

/** Lambda functions and API Gateway for the DeathTrap platform. */
export class ApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);

    const {
      deployEnv, vpc, lambdaSecurityGroup,
      dbSecretArn, s3BucketName, sqsTriggerUrl, sqsTriggerArn, sqsTriggerDlqArn, snsNotifyArn, kmsKeyId,
    } = props;
    const config = getConfig(deployEnv);
    const isProd = config.environment === 'prod';

    const logRetention = config.logRetentionDays === 30
      ? logs.RetentionDays.ONE_MONTH
      : logs.RetentionDays.ONE_WEEK;

    const commonEnv: Record<string, string> = {
      DB_SECRET_ARN: dbSecretArn,
      ENVIRONMENT: config.environment,
      LOG_LEVEL: isProd ? 'INFO' : 'DEBUG',
      S3_BUCKET_NAME: s3BucketName,
      KMS_KEY_ID: kmsKeyId,
    };

    const jarBucket = s3.Bucket.fromBucketName(this, 'JarBucket', config.jarBucketName);

    const lambdaDefaults = {
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
      jarKey: string,
      handler: string,
      memorySize: number,
      timeout: cdk.Duration,
      reservedConcurrency: number | undefined,
      env: Record<string, string>,
    ): lambda.Function => {
      const kebabName = name.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase();
      const functionName = `deathtrap-${deployEnv}-${kebabName}`;
      const logGroup = new logs.LogGroup(this, `${name}LogGroup`, {
        logGroupName: `/aws/lambda/${functionName}`,
        retention: logRetention,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      });
      const fn = new lambda.Function(this, name, {
        ...lambdaDefaults,
        functionName,
        code: lambda.Code.fromBucket(jarBucket, jarKey),
        handler,
        memorySize,
        timeout,
        reservedConcurrentExecutions: reservedConcurrency,
        environment: { ...commonEnv, ...env },
        logGroup,
      });
      // Enable SnapStart on published version
      const cfnFn = fn.node.defaultChild as lambda.CfnFunction;
      cfnFn.snapStart = { applyOn: 'PublishedVersions' };
      return fn;
    };

    // Secret name passed to env vars (without random suffix - AWS SDK resolves it).
    // IAM policy resources use the wildcard form so IAM can match the suffixed actual ARN.
    const jwtSecretName = `deathtrap/${deployEnv}/jwt-secret`;
    const webhookSecretName = `deathtrap/${deployEnv}/webhook-secret`;
    const jwtSecretArn = `arn:aws:secretsmanager:ap-south-1:${this.account}:secret:${jwtSecretName}-*`;
    const webhookSecretArn = `arn:aws:secretsmanager:ap-south-1:${this.account}:secret:${webhookSecretName}-*`;
    const authFn = createLambda(
      'AuthService', `${config.jarPrefix}auth-service-1.0.0-all.jar`,
      'in.deathtrap.auth.AuthHandler::handleRequest',
      256, cdk.Duration.seconds(15), config.authConcurrency,
      { JWT_SECRET_ARN: jwtSecretName },
    );

    const lockerFn = createLambda(
      'LockerService', `${config.jarPrefix}locker-service-1.0.0-all.jar`,
      'in.deathtrap.locker.LockerHandler::handleRequest',
      512, cdk.Duration.seconds(30), config.lockerConcurrency,
      { JWT_SECRET_ARN: jwtSecretName },
    );

    const recoveryFn = createLambda(
      'RecoveryService', `${config.jarPrefix}recovery-service-1.0.0-all.jar`,
      'in.deathtrap.recovery.RecoveryHandler::handleRequest',
      256, cdk.Duration.seconds(30), config.recoveryConcurrency,
      { JWT_SECRET_ARN: jwtSecretName },
    );

    const triggerFn = createLambda(
      'TriggerService', `${config.jarPrefix}trigger-service-1.0.0-all.jar`,
      'in.deathtrap.trigger.TriggerHandler::handleRequest',
      256, cdk.Duration.seconds(60), config.triggerConcurrency,
      {
        SQS_TRIGGER_URL: sqsTriggerUrl,
        SNS_NOTIFY_ARN: snsNotifyArn,
        JWT_SECRET_ARN: jwtSecretName,
        WEBHOOK_SECRET_ARN: webhookSecretName,
      },
    );

    const auditFn = createLambda(
      'AuditService', `${config.jarPrefix}audit-service-1.0.0-all.jar`,
      'in.deathtrap.audit.AuditHandler::handleRequest',
      256, cdk.Duration.seconds(15), config.auditConcurrency, {},
    );

    const sqsConsumerFn = createLambda(
      'SqsConsumer', `${config.jarPrefix}sqs-consumer-1.0.0-all.jar`,
      'in.deathtrap.sqsconsumer.SqsConsumerHandler::handleRequest',
      256, cdk.Duration.seconds(120), config.sqsConcurrency,
      { SQS_TRIGGER_URL: sqsTriggerUrl, SNS_NOTIFY_ARN: snsNotifyArn },
    );

    // IAM: JAR bucket read access for all functions
    [authFn, lockerFn, recoveryFn, triggerFn, auditFn, sqsConsumerFn]
      .forEach(fn => jarBucket.grantRead(fn));

    // IAM: Secrets Manager access for all functions
    const secretPolicy = new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [dbSecretArn],
    });
    [authFn, lockerFn, recoveryFn, triggerFn, auditFn, sqsConsumerFn]
      .forEach(fn => fn.addToRolePolicy(secretPolicy));

    // IAM: JWT secret access for all HTTP services (auth, locker, recovery, trigger)
    [authFn, lockerFn, recoveryFn, triggerFn].forEach(fn => fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [jwtSecretArn],
    })));

    // IAM: Webhook secret access for trigger
    triggerFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [webhookSecretArn],
    }));

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
      resources: [sqsTriggerArn],
    }));

    // SQS event source mapping for sqs-consumer
    sqsConsumerFn.addEventSource(new lambdaEventSources.SqsEventSource(
      sqs.Queue.fromQueueArn(this, 'TriggerQueueConsumerRef', sqsTriggerArn),
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

    // WAF WebACL — enabled in prod only
    if (config.enableWaf) {
      const webAcl = new wafv2.CfnWebACL(this, 'ApiWebAcl', {
        defaultAction: { allow: {} },
        scope: 'REGIONAL',
        visibilityConfig: {
          cloudWatchMetricsEnabled: true,
          metricName: `deathtrap-${deployEnv}-waf`,
          sampledRequestsEnabled: true,
        },
        rules: [
          {
            name: 'AWSManagedRulesCommonRuleSet',
            priority: 1,
            overrideAction: { none: {} },
            statement: {
              managedRuleGroupStatement: {
                vendorName: 'AWS',
                name: 'AWSManagedRulesCommonRuleSet',
              },
            },
            visibilityConfig: {
              cloudWatchMetricsEnabled: true,
              metricName: 'AWSManagedRulesCommonRuleSetMetric',
              sampledRequestsEnabled: true,
            },
          },
        ],
      });
      new wafv2.CfnWebACLAssociation(this, 'ApiWebAclAssociation', {
        resourceArn: `arn:aws:apigateway:ap-south-1::/restapis/${api.restApiId}/stages/${api.deploymentStage.stageName}`,
        webAclArn: webAcl.attrArn,
      });
    }

    // ── CloudWatch Alarms ──────────────────────────────────────────────────
    const notifyTopic = sns.Topic.fromTopicArn(this, 'NotifyTopicRef',
      `arn:aws:sns:ap-south-1:${this.account}:deathtrap-${deployEnv}-notify`);

    const authErrorAlarm = new cloudwatch.Alarm(this, 'AuthServiceErrors', {
      metric: authFn.metricErrors({ period: cdk.Duration.minutes(5) }),
      threshold: 10,
      evaluationPeriods: 1,
      alarmDescription: 'auth-service Lambda error rate exceeded threshold',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    authErrorAlarm.addAlarmAction(new cloudwatchActions.SnsAction(notifyTopic));

    const lockerErrorAlarm = new cloudwatch.Alarm(this, 'LockerServiceErrors', {
      metric: lockerFn.metricErrors({ period: cdk.Duration.minutes(5) }),
      threshold: 5,
      evaluationPeriods: 1,
      alarmDescription: 'locker-service Lambda error rate exceeded threshold',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    lockerErrorAlarm.addAlarmAction(new cloudwatchActions.SnsAction(notifyTopic));

    const recoveryErrorAlarm = new cloudwatch.Alarm(this, 'RecoveryServiceErrors', {
      metric: recoveryFn.metricErrors({ period: cdk.Duration.minutes(5) }),
      threshold: 3,
      evaluationPeriods: 1,
      alarmDescription: 'recovery-service Lambda error rate exceeded threshold (critical)',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    recoveryErrorAlarm.addAlarmAction(new cloudwatchActions.SnsAction(notifyTopic));

    const dlqQueue = sqs.Queue.fromQueueArn(this, 'TriggerDlqRef', sqsTriggerDlqArn);
    const sqsDlqAlarm = new cloudwatch.Alarm(this, 'SqsConsumerDLQ', {
      metric: new cloudwatch.Metric({
        namespace: 'AWS/SQS',
        metricName: 'ApproximateNumberOfMessagesVisible',
        dimensionsMap: { QueueName: dlqQueue.queueName },
        period: cdk.Duration.minutes(1),
        statistic: 'Maximum',
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription: 'SQS trigger DLQ has messages - immediate investigation required',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    sqsDlqAlarm.addAlarmAction(new cloudwatchActions.SnsAction(notifyTopic));

    const auditIntegrityFilter = new logs.MetricFilter(this, 'AuditIntegrityFilter', {
      logGroup: auditFn.logGroup,
      metricNamespace: 'DeathTrap/Audit',
      metricName: 'IntegrityFailure',
      filterPattern: logs.FilterPattern.literal('AUDIT_INTEGRITY_FAILURE'),
      metricValue: '1',
    });
    const auditIntegrityAlarm = new cloudwatch.Alarm(this, 'AuditIntegrityFailure', {
      metric: auditIntegrityFilter.metric({ period: cdk.Duration.hours(24) }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription: 'CRITICAL: Audit hash chain integrity failure detected',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    auditIntegrityAlarm.addAlarmAction(new cloudwatchActions.SnsAction(notifyTopic));

    const apiGateway5xxAlarm = new cloudwatch.Alarm(this, 'ApiGateway5xx', {
      metric: new cloudwatch.Metric({
        namespace: 'AWS/ApiGateway',
        metricName: '5XXError',
        dimensionsMap: { ApiName: `deathtrap-${deployEnv}-api` },
        period: cdk.Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 20,
      evaluationPeriods: 1,
      alarmDescription: 'API Gateway 5xx error rate exceeded threshold',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    apiGateway5xxAlarm.addAlarmAction(new cloudwatchActions.SnsAction(notifyTopic));
  }
}
