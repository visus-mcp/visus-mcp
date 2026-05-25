import {
  DynamoDBClient,
  PutItemCommand,
  ConditionalCheckFailedException,
} from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import {
  normalizeEvents,
  verifyEventHash,
  NormalizerInput,
  NormalizerResult,
  WriteEventResult,
} from '../../shared/normalizer.js';
import { validateEventBatch } from '../../shared/schemas/validate.js';
import { jsonLog, StructuredError } from '../../shared/errors.js';

const EVENTS_TABLE = process.env.EVENTS_TABLE || 'visus-events';
const dynamoClient = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });

async function writeEvent(
  tableName: string,
  writeResult: WriteEventResult,
): Promise<'written' | 'skipped'> {
  try {
    await dynamoClient.send(
      new PutItemCommand({
        TableName: tableName,
        Item: marshall(writeResult.event, { removeUndefinedValues: true }),
        ConditionExpression: 'attribute_not_exists(event_id)',
      }),
    );
    return 'written';
  } catch (error) {
    if (error instanceof ConditionalCheckFailedException) {
      jsonLog('INFO', 'Conditional write skipped (duplicate event_id)', {
        event_id: writeResult.event.event_id,
      });
      return 'skipped';
    }
    throw error;
  }
}

async function writeEventWithRetry(
  tableName: string,
  writeResult: WriteEventResult,
  maxRetries: number = 3,
): Promise<'written' | 'skipped'> {
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await writeEvent(tableName, writeResult);
    } catch (error) {
      lastError = error;
      if (error instanceof ConditionalCheckFailedException) {
        return 'skipped';
      }
      if (attempt < maxRetries) {
        const backoff = Math.min(1000 * Math.pow(2, attempt - 1), 8000);
        const jitter = backoff * 0.2 * (Math.random() * 2 - 1);
        jsonLog('WARN', 'DynamoDB write failed, retrying', {
          event_id: writeResult.event.event_id,
          attempt,
          backoff_ms: Math.round(backoff + jitter),
        });
        await new Promise((resolve) => setTimeout(resolve, backoff + jitter));
      }
    }
  }

  throw new StructuredError(
    `DynamoDB write failed after ${maxRetries} retries`,
    'DYNAMODB_WRITE_FAILURE',
    500,
  );
}

export async function processAndStore(input: NormalizerInput): Promise<NormalizerResult> {
  const { result, writeResults } = normalizeEvents(input);

  let written = 0;
  let skipped = 0;

  for (const writeResult of writeResults) {
    try {
      const { valid, errors } = validateEventBatch([writeResult.event]);

      if (errors.length > 0) {
        jsonLog('ERROR', 'Event validation failed', {
          event_id: writeResult.event.event_id,
          error: errors[0].error.message,
        });
        result.failed++;
        continue;
      }

      const status = await writeEventWithRetry(EVENTS_TABLE, writeResult);

      if (status === 'written') {
        try {
          verifyEventHash(valid[0]);
        } catch (error) {
          jsonLog('CRITICAL', 'Post-write content hash mismatch', {
            event_id: writeResult.event.event_id,
            error: (error as Error).message,
          });
          throw new StructuredError(
            `Post-write content hash verification failed for event ${writeResult.event.event_id}`,
            'CONTENT_HASH_MISMATCH',
            500,
          );
        }
        written++;
      } else {
        skipped++;
      }
    } catch (error) {
      if (error instanceof StructuredError && error.code === 'CONTENT_HASH_MISMATCH') {
        throw error;
      }
      jsonLog('ERROR', 'Failed to store event', {
        event_id: writeResult.event.event_id,
        error: (error as Error).message,
      });
      result.failed++;
    }
  }

  result.written = written;
  result.skipped = skipped;

  return result;
}
