import { Handler } from 'aws-lambda';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import { createSign } from 'crypto';
import { jsonLog, StructuredError, formatLambdaError } from '../../shared/errors.js';

interface SignRequest {
  payload_b64: string;
  key_id: string;
}

interface SignResponse {
  signature_b64: string;
  key_id: string;
  algorithm: 'Ed25519';
}

const SECRET_ARN = process.env.SIGNING_KEY_SECRET_ARN || '';
const secretsClient = new SecretsManagerClient({ region: process.env.AWS_REGION || 'us-east-1' });

let cachedPrivateKey: Buffer | null = null;

async function getPrivateKey(): Promise<Buffer> {
  if (cachedPrivateKey) {
    return cachedPrivateKey;
  }

  try {
    const response = await secretsClient.send(
      new GetSecretValueCommand({ SecretId: SECRET_ARN }),
    );

    if (!response.SecretString) {
      throw new Error('Secret string is empty');
    }

    cachedPrivateKey = Buffer.from(response.SecretString, 'utf8');
    jsonLog('INFO', 'Loaded signing key from Secrets Manager');
    return cachedPrivateKey;
  } catch (error) {
    jsonLog('ERROR', 'Failed to load signing key from Secrets Manager', {
      error: (error as Error).message,
    });
    throw new StructuredError(
      'Failed to retrieve signing key',
      'SECRETS_MANAGER_ERROR',
      500,
    );
  }
}

export const handler: Handler<SignRequest, SignResponse> = async (event) => {
  jsonLog('INFO', 'Proof-signer invoked', { key_id: event.key_id });

  if (event.key_id !== 'v1') {
    jsonLog('WARN', 'Unknown key_id requested', { key_id: event.key_id });
    throw new StructuredError('unknown key_id', 'UNKNOWN_KEY', 400);
  }

  if (!event.payload_b64 || typeof event.payload_b64 !== 'string') {
    throw new StructuredError('payload_b64 is required', 'INVALID_INPUT', 400);
  }

  try {
    const privateKey = await getPrivateKey();
    const payloadBytes = Buffer.from(event.payload_b64, 'base64');

    const sign = createSign('SHA-256');
    sign.update(payloadBytes);
    sign.end();
    const signature = sign.sign(privateKey, 'base64');

    jsonLog('INFO', 'Signature generated', { key_id: event.key_id });

    return {
      signature_b64: signature,
      key_id: event.key_id,
      algorithm: 'Ed25519',
    };
  } catch (error) {
    if (error instanceof StructuredError) {
      throw error;
    }
    jsonLog('ERROR', 'Signing failed', { error: (error as Error).message });
    throw new StructuredError(
      `Signing failed: ${(error as Error).message}`,
      'SIGNING_ERROR',
      500,
    );
  }
};

export function resetCache(): void {
  cachedPrivateKey = null;
}
