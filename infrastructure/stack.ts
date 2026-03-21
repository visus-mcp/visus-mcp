/**
 * Visus MCP - AWS CDK Stack (Phase 2)
 *
 * Infrastructure components:
 * - Lambda function (Playwright + sanitization)
 * - API Gateway REST API (/fetch, /fetch-structured)
 * - Cognito User Pool (authentication)
 * - DynamoDB table (audit logging)
 * - KMS key (encryption at rest)
 * - CloudWatch logs
 *
 * Security compliance per CLAUDE.md:
 * - Scoped IAM roles (no wildcards)
 * - KMS encryption for DynamoDB
 * - Reserved concurrent executions on Lambda
 * - No secrets in code (use Secrets Manager)
 * - VPC isolation (optional for Phase 2, required for Phase 3)
 */

import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

export interface VisusStackProps extends cdk.StackProps {
  environment: string;
}

export class VisusStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: VisusStackProps) {
    super(scope, id, props);

    const { environment } = props;

    // ========================================
    // KMS Key for Encryption at Rest
    // ========================================
    const kmsKey = new kms.Key(this, 'VisusKmsKey', {
      description: `Visus MCP encryption key (${environment})`,
      enableKeyRotation: true,
      alias: `visus-mcp-${environment}`,
      removalPolicy: environment === 'prod'
        ? cdk.RemovalPolicy.RETAIN
        : cdk.RemovalPolicy.DESTROY,
    });

    // ========================================
    // DynamoDB Table - Audit Logging
    // ========================================
    const auditTable = new dynamodb.Table(this, 'VisusAuditLog', {
      tableName: `visus-audit-${environment}`,
      partitionKey: {
        name: 'user_id',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'timestamp',
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST, // On-demand pricing
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: kmsKey,
      pointInTimeRecovery: environment === 'prod',
      removalPolicy: environment === 'prod'
        ? cdk.RemovalPolicy.RETAIN
        : cdk.RemovalPolicy.DESTROY,
    });

    // Global Secondary Index for querying by request_id
    auditTable.addGlobalSecondaryIndex({
      indexName: 'request_id-index',
      partitionKey: {
        name: 'request_id',
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ========================================
    // Cognito User Pool - Authentication
    // ========================================
    const userPool = new cognito.UserPool(this, 'VisusUserPool', {
      userPoolName: `visus-users-${environment}`,
      selfSignUpEnabled: true,
      signInAliases: {
        email: true,
      },
      autoVerify: {
        email: true,
      },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: environment === 'prod'
        ? cdk.RemovalPolicy.RETAIN
        : cdk.RemovalPolicy.DESTROY,
    });

    const userPoolClient = new cognito.UserPoolClient(this, 'VisusUserPoolClient', {
      userPool,
      userPoolClientName: `visus-client-${environment}`,
      authFlows: {
        userPassword: true,
        userSrp: true,
      },
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
        },
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
      },
    });

    // ========================================
    // Lambda Function - Visus Sanitization Service
    // ========================================

    // Lambda execution role
    const lambdaRole = new iam.Role(this, 'VisusLambdaRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Execution role for Visus Lambda function',
    });

    // Grant basic Lambda execution permissions
    lambdaRole.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')
    );

    // Grant DynamoDB write access (scoped to this table only)
    auditTable.grantWriteData(lambdaRole);

    // Grant KMS decrypt access (for reading encrypted DynamoDB data if needed)
    kmsKey.grantEncryptDecrypt(lambdaRole);

    // Lambda function
    const visusFn = new lambda.Function(this, 'VisusFunction', {
      functionName: `visus-mcp-${environment}`,
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('dist'), // Build output directory (relative to project root)
      timeout: cdk.Duration.seconds(30), // Playwright page loads can take time
      memorySize: 1024, // Chromium requires significant memory
      reservedConcurrentExecutions: environment === 'prod' ? 100 : 10, // RULE 7: Cost protection
      role: lambdaRole,
      environment: {
        AUDIT_TABLE_NAME: auditTable.tableName,
        ENVIRONMENT: environment,
        NODE_OPTIONS: '--enable-source-maps', // For debugging
      },
      logRetention: environment === 'prod'
        ? logs.RetentionDays.ONE_MONTH
        : logs.RetentionDays.ONE_WEEK,
      description: `Visus MCP sanitization service (${environment})`,
    });

    // ========================================
    // API Gateway - REST API
    // ========================================
    const api = new apigateway.RestApi(this, 'VisusApi', {
      restApiName: `visus-api-${environment}`,
      description: `Visus MCP REST API (${environment})`,
      deployOptions: {
        stageName: environment,
        throttlingRateLimit: 100,
        throttlingBurstLimit: 200,
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: true,
        metricsEnabled: true,
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS, // Phase 2: Open. Phase 3: Restrict to Lateos
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: ['Content-Type', 'Authorization'],
      },
    });

    // Cognito authorizer
    const authorizer = new apigateway.CognitoUserPoolsAuthorizer(this, 'VisusAuthorizer', {
      cognitoUserPools: [userPool],
      authorizerName: `visus-auth-${environment}`,
    });

    // Lambda integration
    const lambdaIntegration = new apigateway.LambdaIntegration(visusFn, {
      proxy: true,
    });

    // API routes
    const fetch = api.root.addResource('fetch');
    fetch.addMethod('POST', lambdaIntegration, {
      authorizer,
      authorizationType: apigateway.AuthorizationType.COGNITO,
    });

    const fetchStructured = api.root.addResource('fetch-structured');
    fetchStructured.addMethod('POST', lambdaIntegration, {
      authorizer,
      authorizationType: apigateway.AuthorizationType.COGNITO,
    });

    // Health check endpoint (no auth required)
    const health = api.root.addResource('health');
    health.addMethod('GET', lambdaIntegration);

    // ========================================
    // Outputs
    // ========================================
    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: api.url,
      description: 'Visus API Gateway endpoint',
      exportName: `visus-api-url-${environment}`,
    });

    new cdk.CfnOutput(this, 'UserPoolId', {
      value: userPool.userPoolId,
      description: 'Cognito User Pool ID',
      exportName: `visus-user-pool-id-${environment}`,
    });

    new cdk.CfnOutput(this, 'UserPoolClientId', {
      value: userPoolClient.userPoolClientId,
      description: 'Cognito User Pool Client ID',
      exportName: `visus-user-pool-client-id-${environment}`,
    });

    new cdk.CfnOutput(this, 'AuditTableName', {
      value: auditTable.tableName,
      description: 'DynamoDB audit log table name',
      exportName: `visus-audit-table-${environment}`,
    });

    new cdk.CfnOutput(this, 'LambdaFunctionArn', {
      value: visusFn.functionArn,
      description: 'Lambda function ARN',
      exportName: `visus-lambda-arn-${environment}`,
    });
  }
}
