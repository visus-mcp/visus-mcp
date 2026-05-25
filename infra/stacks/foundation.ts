import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';

export interface FoundationStackProps extends cdk.StackProps {
  environment: string;
}

export class FoundationStack extends cdk.Stack {
  public readonly eventsTable: dynamodb.Table;
  public readonly findingsTable: dynamodb.Table;
  public readonly auditPackagesTable: dynamodb.Table;
  public readonly auditAccessLogTable: dynamodb.Table;
  public readonly remediationLogTable: dynamodb.Table;
  public readonly attestationsTable: dynamodb.Table;
  public readonly orgsTable: dynamodb.Table;

  public readonly dataKey: kms.Key;
  public readonly auditSigningKey: kms.Key;

  public readonly evidenceArchiveBucket: s3.Bucket;
  public readonly reportsBucket: s3.Bucket;

  public readonly signingKeypairSecret: secretsmanager.Secret;
  public readonly pipelineVersionSecret: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: FoundationStackProps) {
    super(scope, id, props);

    this.dataKey = new kms.Key(this, 'VisusDataKey', {
      alias: 'alias/visus-data-key',
      description: 'General data encryption key for DynamoDB and S3',
      enableKeyRotation: false,
    });

    this.auditSigningKey = new kms.Key(this, 'VisusAuditSigningKey', {
      alias: 'alias/visus-audit-signing-key',
      description: 'KMS key for envelope encryption of Ed25519 private key in Secrets Manager',
      enableKeyRotation: false,
    });

    this.eventsTable = new dynamodb.Table(this, 'VisusEventsTable', {
      tableName: 'visus-events',
      partitionKey: { name: 'org_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'timestamp#event_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.dataKey,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'ttl',
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.findingsTable = new dynamodb.Table(this, 'VisusFindingsTable', {
      tableName: 'visus-findings',
      partitionKey: { name: 'org_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'timestamp#finding_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.dataKey,
      pointInTimeRecovery: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.auditPackagesTable = new dynamodb.Table(this, 'VisusAuditPackagesTable', {
      tableName: 'visus-audit-packages',
      partitionKey: { name: 'org_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'package_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.dataKey,
      pointInTimeRecovery: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.auditAccessLogTable = new dynamodb.Table(this, 'VisusAuditAccessLogTable', {
      tableName: 'visus-audit-access-log',
      partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'timestamp', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.dataKey,
      pointInTimeRecovery: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.remediationLogTable = new dynamodb.Table(this, 'VisusRemediationLogTable', {
      tableName: 'visus-remediation-log',
      partitionKey: { name: 'org_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'finding_id#timestamp', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.dataKey,
      pointInTimeRecovery: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.attestationsTable = new dynamodb.Table(this, 'VisusAttestationsTable', {
      tableName: 'visus-attestations',
      partitionKey: { name: 'attestation_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.dataKey,
      pointInTimeRecovery: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.attestationsTable.addToResourcePolicy(
      new cdk.aws_iam.PolicyStatement({
        effect: cdk.aws_iam.Effect.DENY,
        principals: [new cdk.aws_iam.AnyPrincipal()],
        actions: ['dynamodb:DeleteItem', 'dynamodb:DeleteTable'],
        resources: [this.attestationsTable.tableArn],
      }),
    );

    this.orgsTable = new dynamodb.Table(this, 'VisusOrgsTable', {
      tableName: 'visus-orgs',
      partitionKey: { name: 'org_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.dataKey,
      pointInTimeRecovery: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const accountId = cdk.Stack.of(this).account;

    this.evidenceArchiveBucket = new s3.Bucket(this, 'VisusEvidenceArchiveBucket', {
      bucketName: `visus-evidence-archive-${accountId}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.dataKey,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.evidenceArchiveBucket.addLifecycleRule({
      id: 'GlacierAfter30Days',
      enabled: true,
      transitions: [
        {
          storageClass: s3.StorageClass.GLACIER_INSTANT_RETRIEVAL,
          transitionAfter: cdk.Duration.days(30),
        },
      ],
    });

    this.reportsBucket = new s3.Bucket(this, 'VisusReportsBucket', {
      bucketName: `visus-reports-${accountId}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.dataKey,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.signingKeypairSecret = new secretsmanager.Secret(this, 'VisusSigningKeypairSecret', {
      secretName: 'visus/audit/signing-keypair',
      description: 'Ed25519 signing keypair for Visus audit proof system',
      encryptionKey: this.auditSigningKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.pipelineVersionSecret = new secretsmanager.Secret(this, 'VisusPipelineVersionSecret', {
      secretName: 'visus/system/pipeline-version',
      description: 'Current git commit SHA set by CI/CD on deploy',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    new cdk.CfnOutput(this, 'EventsTableName', { value: this.eventsTable.tableName });
    new cdk.CfnOutput(this, 'FindingsTableName', { value: this.findingsTable.tableName });
    new cdk.CfnOutput(this, 'DataKeyArn', { value: this.dataKey.keyArn });
    new cdk.CfnOutput(this, 'AuditSigningKeyArn', { value: this.auditSigningKey.keyArn });
    new cdk.CfnOutput(this, 'EvidenceBucketName', { value: this.evidenceArchiveBucket.bucketName });
  }
}
