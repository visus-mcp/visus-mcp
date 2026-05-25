import { canonicalJson, canonicalJsonBytes } from '../../shared/canonical-json.js';

describe('canonicalJson', () => {
  it('field ordering: {b: 1, a: 2} -> {"a":2,"b":1}', () => {
    const result = canonicalJson({ b: 1, a: 2 });
    expect(result).toBe('{"a":2,"b":1}');
  });

  it('nested objects: keys sorted at every level', () => {
    const result = canonicalJson({ z: { c: 3, b: 2, a: 1 }, y: 0 });
    expect(result).toBe('{"y":0,"z":{"a":1,"b":2,"c":3}}');
  });

  it('arrays: element order preserved (not sorted)', () => {
    const result = canonicalJson({ items: [3, 1, 2] });
    expect(result).toBe('{"items":[3,1,2]}');
  });

  it('null values: null -> null', () => {
    expect(canonicalJson(null)).toBe('null');
    expect(canonicalJson({ a: null })).toBe('{"a":null}');
  });

  it('unicode: UTF-8 string round-trips correctly', () => {
    const result = canonicalJson({ name: 'José' });
    expect(result).toBe('{"name":"José"}');
  });

  it('numbers: integers and floats serialize without precision loss', () => {
    const result = canonicalJson({ int: 42, float: 3.14 });
    expect(result).toBe('{"float":3.14,"int":42}');
  });

  it('empty object: {} -> {}', () => {
    const result = canonicalJson({});
    expect(result).toBe('{}');
  });

  it('same output on repeated calls with same input (stability)', () => {
    const obj = { z: 1, m: { n: 2, a: 3 }, q: 0 };
    const r1 = canonicalJson(obj);
    const r2 = canonicalJson(obj);
    const r3 = canonicalJson(obj);
    expect(r1).toBe(r2);
    expect(r2).toBe(r3);
  });

  it('different field order input -> identical output (idempotency)', () => {
    const obj1 = { c: 1, b: 2, a: 3 };
    const obj2 = { a: 3, b: 2, c: 1 };
    expect(canonicalJson(obj1)).toBe(canonicalJson(obj2));
  });

  it('mixed nesting: object containing array containing object -> correct recursive sort', () => {
    const result = canonicalJson({
      b: [{ d: 1, c: 2 }, { f: 3, e: 4 }],
      a: 1,
    });
    expect(result).toBe('{"a":1,"b":[{"c":2,"d":1},{"e":4,"f":3}]}');
  });

  it('boolean values: true/false', () => {
    expect(canonicalJson(true)).toBe('true');
    expect(canonicalJson(false)).toBe('false');
    expect(canonicalJson({ flag: true, enabled: false })).toBe('{"enabled":false,"flag":true}');
  });

  it('arrays of primitives', () => {
    expect(canonicalJson([1, 'two', true, null])).toBe('[1,"two",true,null]');
  });

  it('deeply nested structure', () => {
    const result = canonicalJson({
      level1: {
        level2: {
          z: 1,
          a: 2,
          level3: { g: 7, f: 6 },
        },
      },
    });
    expect(result).toBe('{"level1":{"level2":{"a":2,"level3":{"f":6,"g":7},"z":1}}}');
  });

  it('number edge cases: zero and negative', () => {
    expect(canonicalJson(0)).toBe('0');
    expect(canonicalJson(-1)).toBe('-1');
    expect(canonicalJson({ a: 0, b: -5 })).toBe('{"a":0,"b":-5}');
  });

  it('special characters in strings', () => {
    const result = canonicalJson({ path: 'C:\\Users\\test', message: 'hello "world"' });
    expect(result).toBe('{"message":"hello \\"world\\"","path":"C:\\\\Users\\\\test"}');
  });
});

describe('canonicalJsonBytes', () => {
  it('returns Buffer of UTF-8 bytes', () => {
    const bytes = canonicalJsonBytes({ a: 1 });
    expect(bytes).toBeInstanceOf(Buffer);
    expect(bytes.toString('utf8')).toBe('{"a":1}');
  });

  it('producing identical bytes for same input', () => {
    const b1 = canonicalJsonBytes({ c: 1, b: 2, a: 3 });
    const b2 = canonicalJsonBytes({ a: 3, b: 2, c: 1 });
    expect(b1.equals(b2)).toBe(true);
  });
});
