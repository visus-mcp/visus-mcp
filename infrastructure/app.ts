#!/usr/bin/env node
/**
 * AWS CDK App Entry Point
 *
 * Deploys the Visus MCP Phase 2 infrastructure:
 * - Lambda function for sanitization service
 * - API Gateway REST API
 * - Cognito user pools (authentication)
 * - DynamoDB table (audit logging)
 * - KMS keys (encryption at rest)
 */

import * as cdk from 'aws-cdk-lib';
import { VisusStack } from './stack.ts';

const app = new cdk.App();

// Get deployment configuration from context or environment
const environment = app.node.tryGetContext('environment') || process.env.VISUS_ENV || 'dev';
const awsAccount = process.env.CDK_DEFAULT_ACCOUNT || process.env.AWS_ACCOUNT_ID;
const awsRegion = process.env.CDK_DEFAULT_REGION || process.env.AWS_REGION || 'us-east-1';

// Create the Visus stack
new VisusStack(app, `VisusStack-${environment}`, {
  env: {
    account: awsAccount,
    region: awsRegion,
  },
  environment,
  description: `Visus MCP - Phase 2 Hosted Tier (${environment})`,
  tags: {
    Project: 'Visus MCP',
    Phase: '2',
    Environment: environment,
    ManagedBy: 'CDK',
  },
});

app.synth();
