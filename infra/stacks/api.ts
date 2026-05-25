import * as cdk from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';
import { FoundationStack } from './foundation.js';

export interface ApiStackProps extends cdk.StackProps {
  environment: string;
  foundation: FoundationStack;
}

export class ApiStack extends cdk.Stack {
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;
  public readonly restApi: apigateway.RestApi;

  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);

    this.userPool = new cognito.UserPool(this, 'VisusCustomerPool', {
      userPoolName: 'visus-customers',
      selfSignUpEnabled: true,
      signInAliases: { email: true },
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: { sms: false, otp: true },
      passwordPolicy: {
        minLength: 12,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      customAttributes: {
        org_id: new cognito.StringAttribute({
          minLen: 1,
          maxLen: 128,
          mutable: false,
        }),
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.userPoolClient = new cognito.UserPoolClient(this, 'VisusCustomerPoolClient', {
      userPoolClientName: 'visus-spa-client',
      userPool: this.userPool,
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
      generateSecret: false,
      preventUserExistenceErrors: true,
    });

    this.restApi = new apigateway.RestApi(this, 'VisusApi', {
      restApiName: 'Visus API',
      description: 'Visus SaaS API Gateway',
      deployOptions: {
        stageName: props.environment,
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: false,
        metricsEnabled: true,
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: ['Content-Type', 'Authorization', 'X-Cisco-Meraki-Network-Secret'],
      },
      endpointConfiguration: {
        types: [apigateway.EndpointType.REGIONAL],
      },
    });

    const webhooks = this.restApi.root.addResource('webhooks');
    const merakiWebhook = webhooks.addResource('meraki');
    merakiWebhook.addMethod('POST');

    const onboard = this.restApi.root.addResource('onboard');
    onboard.addMethod('POST');

    new cdk.CfnOutput(this, 'ApiUrl', { value: this.restApi.url });
    new cdk.CfnOutput(this, 'UserPoolId', { value: this.userPool.userPoolId });
    new cdk.CfnOutput(this, 'UserPoolClientId', { value: this.userPoolClient.userPoolClientId });
  }
}
