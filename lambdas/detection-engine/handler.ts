import { Handler, DynamoDBStreamEvent } from 'aws-lambda';

export const handler: Handler<DynamoDBStreamEvent, void> = async (event) => {
  // Stub — detection engine implementation in Sprint 2
};
