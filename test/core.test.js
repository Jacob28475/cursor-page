import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createCursor,
  parseCursor,
  InvalidCursorError,
  CursorExpiredError,
  CursorSignatureError,
} from '../src/index.js';

const SECRET = 'test-secret-do-not-use-in-production';
const FIXED_NOW = () => 1_000_000;

test('round-trips a simple payload', () => {
  const c = createCursor({ secret: SECRET, payload: { id: 42 }, now: FIXED_NOW });
  const p = parseCursor({ secret: SECRET, cursor: c, now: FIXED_NOW });
  assert.deepEqual(p, { id: 42 });
});

test('round-trips a string payload', () => {
  const c = createCursor({ secret: SECRET, payload: 'after-id-7', now: FIXED_NOW });
  assert.equal(parseCursor({ secret: SECRET, cursor: c, now: FIXED_NOW }), 'after-id-7');
});

test('round-trips null', () => {
  const c = createCursor({ secret: SECRET, payload: null, now: FIXED_NOW });
  assert.equal(parseCursor({ secret: SECRET, cursor: c, now: FIXED_NOW }), null);
});

test('round-trips nested arrays and objects', () => {
  const payload = { users: [1, 2, 3], meta: { page: 2, tags: ['a', 'b'] } };
  const c = createCursor({ secret: SECRET, payload, now: FIXED_NOW });
  assert.deepEqual(parseCursor({ secret: SECRET, cursor: c, now: FIXED_NOW }), payload);
});

test('cursor is a url-safe base64 string with no padding', () => {
  const c = createCursor({ secret: SECRET, payload: { id: 1 }, now: FIXED_NOW });
  assert.equal(typeof c, 'string');
  assert.match(c, /^[A-Za-z0-9_-]+$/);
  assert.equal(c.includes('='), false);
});

test('rejects a different secret', () => {
  const c = createCursor({ secret: SECRET, payload: { id: 1 }, now: FIXED_NOW });
  assert.throws(
    () => parseCursor({ secret: 'other-secret', cursor: c, now: FIXED_NOW }),
    CursorSignatureError
  );
});

test('detects tampering with the payload portion', () => {
  const c = createCursor({ secret: SECRET, payload: { id: 1 }, now: FIXED_NOW });
  const raw = Buffer.from(c, 'base64');
  raw[raw.length - 1] ^= 0x01; // flip one byte in the body
  const tampered = raw.toString('base64url');
  assert.throws(
    () => parseCursor({ secret: SECRET, cursor: tampered, now: FIXED_NOW }),
    CursorSignatureError
  );
});

test('detects tampering with the MAC portion', () => {
  const c = createCursor({ secret: SECRET, payload: { id: 1 }, now: FIXED_NOW });
  const raw = Buffer.from(c, 'base64');
  raw[5] ^= 0x80; // flip a byte inside the HMAC
  const tampered = raw.toString('base64url');
  assert.throws(
    () => parseCursor({ secret: SECRET, cursor: tampered, now: FIXED_NOW }),
    CursorSignatureError
  );
});

test('rejects truncated cursor', () => {
  const c = createCursor({ secret: SECRET, payload: { id: 1 }, now: FIXED_NOW });
  const short = c.slice(0, 10);
  assert.throws(
    () => parseCursor({ secret: SECRET, cursor: short, now: FIXED_NOW }),
    InvalidCursorError
  );
});

test('rejects non-base64 input', () => {
  assert.throws(
    () => parseCursor({ secret: SECRET, cursor: '!!!not-base64!!!', now: FIXED_NOW }),
    InvalidCursorError
  );
});

test('rejects unsupported version byte', () => {
  const c = createCursor({ secret: SECRET, payload: { id: 1 }, now: FIXED_NOW });
  const raw = Buffer.from(c, 'base64url');
  raw[0] = 99;
  assert.throws(
    () => parseCursor({ secret: SECRET, cursor: raw.toString('base64url'), now: FIXED_NOW }),
    InvalidCursorError
  );
});

test('honours ttl: valid before expiry', () => {
  const c = createCursor({
    secret: SECRET,
    payload: { id: 1 },
    ttlSeconds: 60,
    now: FIXED_NOW,
  });
  const p = parseCursor({ secret: SECRET, cursor: c, now: () => FIXED_NOW() + 59_999 });
  assert.deepEqual(p, { id: 1 });
});

test('honours ttl: expired at exactly the boundary', () => {
  const c = createCursor({
    secret: SECRET,
    payload: { id: 1 },
    ttlSeconds: 60,
    now: FIXED_NOW,
  });
  assert.throws(
    () => parseCursor({ secret: SECRET, cursor: c, now: () => FIXED_NOW() + 60_000 }),
    CursorExpiredError
  );
});

test('refuses a payload that does not survive JSON round-trip', () => {
  // JSON.stringify drops `undefined` field values, so the round-trip is not equal.
  assert.throws(
    () => createCursor({ secret: SECRET, payload: { a: undefined }, now: FIXED_NOW }),
    InvalidCursorError
  );
});

test('refuses a function payload', () => {
  assert.throws(
    () => createCursor({ secret: SECRET, payload: () => 1, now: FIXED_NOW }),
    TypeError
  );
});

test('refuses an empty secret', () => {
  assert.throws(
    () => createCursor({ secret: '', payload: { id: 1 }, now: FIXED_NOW }),
    TypeError
  );
});

test('refuses non-positive ttl', () => {
  assert.throws(
    () => createCursor({ secret: SECRET, payload: { id: 1 }, ttlSeconds: 0, now: FIXED_NOW }),
    TypeError
  );
});

test('cursor without ttl never expires', () => {
  const c = createCursor({ secret: SECRET, payload: { id: 1 }, now: FIXED_NOW });
  const far = () => FIXED_NOW() + 10_000_000_000;
  assert.deepEqual(parseCursor({ secret: SECRET, cursor: c, now: far }), { id: 1 });
});
