export interface DeathTrapConfig {
  auroraMinAcu: number;
  auroraMaxAcu: number;
  auroraInstances: number;
  auroraBackupDays: number;
  deletionProtection: boolean;
  natGateways: number;
  bucketName: string;
  enableWaf: boolean;
  enableGuardDuty: boolean;
  authConcurrency: number | undefined;
  lockerConcurrency: number | undefined;
  recoveryConcurrency: number | undefined;
  triggerConcurrency: number | undefined;
  auditConcurrency: number | undefined;
  sqsConcurrency: number | undefined;
  logRetentionDays: number;
  environment: string;
  jarBucketName: string;
  jarPrefix: string;
}

export function getConfig(env: string): DeathTrapConfig {
  const isProd = env === 'prod';
  return {
    auroraMinAcu:        isProd ? 0.5 : 0,
    auroraMaxAcu:        isProd ? 32  : 4,
    auroraInstances:     isProd ? 2   : 1,
    auroraBackupDays:    isProd ? 35  : 1,
    deletionProtection:  isProd,
    natGateways:         isProd ? 3   : 1,
    bucketName:          isProd ? 'deathtrap-prod' : 'deathtrap-staging',
    enableWaf:           isProd,
    enableGuardDuty:     isProd,
    authConcurrency:     isProd ? 50  : undefined,
    lockerConcurrency:   isProd ? 100 : undefined,
    recoveryConcurrency: isProd ? 20  : undefined,
    triggerConcurrency:  isProd ? 10  : undefined,
    auditConcurrency:    isProd ? 20  : undefined,
    sqsConcurrency:      isProd ? 5   : undefined,
    logRetentionDays:    isProd ? 30  : 7,
    environment:         env,
    jarBucketName:       isProd ? 'deathtrap-prod-jars' : 'deathtrap-staging-jars',
    jarPrefix:           'lambda-jars/',
  };
}
