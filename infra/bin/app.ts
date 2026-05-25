#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { FoundationStack } from '../stacks/foundation.js';
import { ApiStack } from '../stacks/api.js';
import { ComputeStack } from '../stacks/compute.js';

const app = new cdk.App();

const environment = app.node.tryGetContext('env') || 'staging';

const foundation = new FoundationStack(app, `VisusFoundation-${environment}`, {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: 'us-east-1',
  },
  environment,
});

const api = new ApiStack(app, `VisusApi-${environment}`, {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: 'us-east-1',
  },
  environment,
  foundation,
});

const compute = new ComputeStack(app, `VisusCompute-${environment}`, {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: 'us-east-1',
  },
  environment,
  foundation,
  api,
});

export {};
