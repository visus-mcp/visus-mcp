/**
 * Produces canonical JSON: keys sorted alphabetically (recursive),
 * no whitespace, UTF-8 encoded.
 *
 * This is the Visus canonical JSON specification v1.
 * Any change to this function is a BREAKING CHANGE requiring a schema version bump.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      return 'null';
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (Array.isArray(value)) {
    const elements = value.map((item) => canonicalJson(item));
    return '[' + elements.join(',') + ']';
  }
  if (typeof value === 'object') {
    const sorted = Object.keys(value)
      .sort()
      .reduce(
        (acc, key) => {
          acc[key] = (value as Record<string, unknown>)[key];
          return acc;
        },
        {} as Record<string, unknown>,
      );
    const pairs = Object.entries(sorted).map(
      ([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`,
    );
    return '{' + pairs.join(',') + '}';
  }
  return JSON.stringify(value);
}

/**
 * Produces the UTF-8 byte encoding of the canonical JSON representation.
 */
export function canonicalJsonBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), 'utf8');
}
