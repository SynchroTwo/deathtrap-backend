import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';
import { getConfig } from '../config';

interface NetworkStackProps extends cdk.StackProps {
  deployEnv: string;
}

/** VPC, subnets, NAT gateways, and security groups for all DeathTrap services. */
export class NetworkStack extends cdk.Stack {
  public readonly vpc: ec2.Vpc;
  public readonly lambdaSecurityGroup: ec2.SecurityGroup;
  public readonly dbSecurityGroup: ec2.SecurityGroup;

  constructor(scope: Construct, id: string, props: NetworkStackProps) {
    super(scope, id, props);

    const { deployEnv } = props;
    const config = getConfig(deployEnv);
    const isProd = config.environment === 'prod';

    this.vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: isProd ? 3 : 2,
      natGateways: config.natGateways,
      subnetConfiguration: [
        {
          name: 'Public',
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 24,
        },
        {
          name: 'Lambda',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 24,
        },
        {
          name: 'Data',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 24,
        },
      ],
    });

    // DB security group: accepts inbound only from Lambda SG on port 5432
    this.dbSecurityGroup = new ec2.SecurityGroup(this, 'DbSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for Aurora RDS — inbound from Lambda only',
      allowAllOutbound: false,
    });

    // Lambda security group: egress HTTPS + DB port only
    this.lambdaSecurityGroup = new ec2.SecurityGroup(this, 'LambdaSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for Lambda functions',
      allowAllOutbound: false,
    });
    this.lambdaSecurityGroup.addEgressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      'Allow HTTPS egress for AWS API calls',
    );
    this.lambdaSecurityGroup.addEgressRule(
      this.dbSecurityGroup,
      ec2.Port.tcp(5432),
      'Allow PostgreSQL egress to DB security group',
    );

    this.dbSecurityGroup.addIngressRule(
      this.lambdaSecurityGroup,
      ec2.Port.tcp(5432),
      'Allow PostgreSQL inbound from Lambda security group',
    );

    if (isProd) {
      new ec2.FlowLog(this, 'VpcFlowLog', {
        resourceType: ec2.FlowLogResourceType.fromVpc(this.vpc),
        trafficType: ec2.FlowLogTrafficType.ALL,
      });
    }

    new cdk.CfnOutput(this, 'VpcId', { value: this.vpc.vpcId });
  }
}
