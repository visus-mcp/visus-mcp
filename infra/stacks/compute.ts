import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import { Construct } from 'constructs';
import { FoundationStack } from './foundation.js';
import { ApiStack } from './api.js';
import * as path from 'path';

export interface ComputeStackProps extends cdk.StackProps {
  environment: string;
  foundation: FoundationStack;
  api: ApiStack;
}

const LAMBDAS_DIR = path.join(__dirname, '..', '..', 'lambdas');

export class ComputeStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ComputeStackProps) {
    super(scope, id, props);

    const pipelineVersion = lambda.Code.fromAsset(LAMBDAS_DIR);

    const proofSignerLambda = new lambda.Function(this, 'VisusProofSignerLambda', {
      functionName: 'visus-proof-signer',
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'proof-signer/handler.handler',
      code: pipelineVersion,
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      environment: {
        VISUS_ENV: props.environment,
        SIGNING_KEY_SECRET_ARN: props.foundation.signingKeypairSecret.secretArn,
      },
    });

    proofSignerLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue'],
        resources: [props.foundation.signingKeypairSecret.secretArn],
      }),
    );

    proofSignerLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['kms:Decrypt'],
        resources: [props.foundation.auditSigningKey.keyArn],
      }),
    );

    const ingestNormalizerLambda = new lambda.Function(this, 'VisusIngestNormalizerLambda', {
      functionName: 'visus-ingest-normalizer',
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'ingest-normalizer/handler.handler',
      code: pipelineVersion,
      memorySize: 512,
      timeout: cdk.Duration.seconds(60),
      environment: {
        VISUS_ENV: props.environment,
        EVENTS_TABLE: props.foundation.eventsTable.tableName,
        PIPELINE_VERSION: '0000000000000000000000000000000000000000',
      },
    });

    props.foundation.eventsTable.grantWriteData(ingestNormalizerLambda);
    props.foundation.eventsTable.grantReadData(ingestNormalizerLambda);

    const merakiPollerLambda = new lambda.Function(this, 'VisusMerakiPollerLambda', {
      functionName: 'visus-meraki-poller',
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'meraki-poller/handler.handler',
      code: pipelineVersion,
      memorySize: 512,
      timeout: cdk.Duration.minutes(5),
      environment: {
        VISUS_ENV: props.environment,
        EVENTS_TABLE: props.foundation.eventsTable.tableName,
      },
    });

    props.foundation.eventsTable.grantWriteData(merakiPollerLambda);

    const webhookReceiverLambda = new lambda.Function(this, 'VisusWebhookReceiverLambda', {
      functionName: 'visus-webhook-receiver',
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'webhook-receiver/handler.handler',
      code: pipelineVersion,
      memorySize: 256,
      timeout: cdk.Duration.seconds(10),
      environment: {
        VISUS_ENV: props.environment,
        EVENTS_TABLE: props.foundation.eventsTable.tableName,
        PIPELINE_VERSION: '0000000000000000000000000000000000000000',
      },
    });

    props.foundation.eventsTable.grantWriteData(webhookReceiverLambda);
    props.foundation.eventsTable.grantReadData(webhookReceiverLambda);

    const catalystLambda = new lambda.Function(this, 'VisusCatalystClientLambda', {
      functionName: 'visus-catalyst-client',
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'catalyst-client/handler.handler',
      code: pipelineVersion,
      memorySize: 512,
      timeout: cdk.Duration.minutes(5),
      environment: {
        VISUS_ENV: props.environment,
        EVENTS_TABLE: props.foundation.eventsTable.tableName,
      },
    });

    props.foundation.eventsTable.grantWriteData(catalystLambda);

    const onboardLambda = new lambda.Function(this, 'VisusOnboardLambda', {
      functionName: 'visus-onboard',
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'onboard/handler.handler',
      code: pipelineVersion,
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      environment: {
        VISUS_ENV: props.environment,
        ORGS_TABLE: props.foundation.orgsTable.tableName,
      },
    });

    props.foundation.orgsTable.grantWriteData(onboardLambda);

    const secretsPath = this.formatArn({
      service: 'secretsmanager',
      resource: 'secret',
      resourceName: `visus/customers/*`,
      arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME,
    });

    onboardLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:PutSecretValue', 'secretsmanager:GetSecretValue', 'secretsmanager:CreateSecret'],
        resources: [secretsPath],
      }),
    );

    merakiPollerLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue'],
        resources: [secretsPath],
      }),
    );

    catalystLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue'],
        resources: [secretsPath],
      }),
    );

    webhookReceiverLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue'],
        resources: [secretsPath],
      }),
    );

    const stagingStage = props.api.restApi.deploymentStage;
    if (stagingStage) {
      stagingStage.addApiKey('VisusApiKey');
    }

    const merakiPollRule = new events.Rule(this, 'MerakiPollRule', {
      schedule: events.Schedule.rate(cdk.Duration.seconds(60)),
      description: 'Triggers Meraki API polling for all onboarded orgs',
    });

    merakiPollRule.addTarget(new targets.LambdaFunction(merakiPollerLambda));

    const catalystPollRule = new events.Rule(this, 'CatalystPollRule', {
      schedule: events.Schedule.rate(cdk.Duration.minutes(5)),
      description: 'Triggers Catalyst Center API polling',
    });

    catalystPollRule.addTarget(new targets.LambdaFunction(catalystLambda));

    new cdk.CfnOutput(this, 'ProofSignerLambdaArn', { value: proofSignerLambda.functionArn });
    new cdk.CfnOutput(this, 'IngestNormalizerLambdaArn', { value: ingestNormalizerLambda.functionArn });
    new cdk.CfnOutput(this, 'WebhookReceiverLambdaArn', { value: webhookReceiverLambda.functionArn });
  }
}
