import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * The cursor could not be parsed or its structure is invalid.
 */
export class InvalidCursorError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidCursorError';
  }
}

/**
 * The cursor was well-formed and correctly signed, but its TTL has elapsed.
 */
export class CursorExpiredError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CursorExpiredError';
  }
}

/**
 * The cursor's signature did not verify under the configured secret.
 */
export class CursorSignatureError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CursorSignatureError';
  }
}

function assertString(value, name) {
  if (typeof value !== 'string') {
    throw new TypeError(`${name} must be a string`);
  }
}

const encoder = new TextEncoder();

/**
 * Constant-time comparison of two equal-length buffers.
 *
 * We pre-compute a fixed-length HMAC-SHA256 (32 bytes) and encode the cursor
 * deterministically before signing. Because the signed payload is the only
 * variable-length input, we bind its length into the signed bytes via a
 * length prefix. This prevents an attacker from reusing an old (payload,
 * signature) pair with a truncated or extended payload.
 *
 * timingSafeEqual requires equal-length buffers, so we short-circuit on a
 * length mismatch. That length is itself not secret — it is observable in the
 * emitted cursor — so revealing it does not weaken the MAC.
 */
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Build the canonical bytes that the HMAC covers.
 *
 * Layout: version (1 byte) || payloadLen (4 bytes, big-endian) || payload bytes.
 *
 * The version byte lets us change the wire format later without ambiguity.
 * The length prefix exists so that the signature stays bound to exactly the
 * bytes we emitted, even though the base64 payload on the wire could in
 * principle be re-decoded and re-encoded with different padding.
 */
function signedBytes(version, payloadBytes) {
  const len = payloadBytes.length;
  const out = new Uint8Array(1 + 4 + len);
  out[0] = version;
  out[1] = (len >>> 24) & 0xff;
  out[2] = (len >>> 16) & 0xff;
  out[3] = (len >>> 8) & 0xff;
  out[4] = len & 0xff;
  out.set(payloadBytes, 5);
  return out;
}

/**
 * Encode a Uint8Array to URL-safe base64 with no padding.
 * URL-safe so cursors can sit in a query string without further escaping.
 */
function encode(bytes) {
  let s = Buffer.from(bytes).toString('base64');
  s = s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return s;
}

/**
 * Decode URL-safe base64, tolerating missing padding and standard alphabet too.
 */
function decode(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  const rem = s.length % 4;
  if (rem === 2) s += '==';
  else if (rem === 3) s += '=';
  else if (rem !== 0) throw new InvalidCursorError('malformed base64');
  let buf;
  try {
    buf = Buffer.from(s, 'base64');
  } catch {
    throw new InvalidCursorError('malformed base64');
  }
  if (buf.length === 0 && str.length > 0) {
    throw new InvalidCursorError('malformed base64');
  }
  return new Uint8Array(buf);
}

const VERSION = 1;

/**
 * Create a signed, opaque page cursor.
 *
 * @param {object} options
 * @param {string} options.secret - HMAC secret. Must be non-empty.
 * @param {unknown} options.payload - Arbitrary JSON-serializable value that
 *   identifies where in the result set the next page begins.
 * @param {number} [options.ttlSeconds] - Optional maximum age. If present,
 *   the cursor becomes invalid once this many seconds have elapsed since
 *   `now`. Must be a positive integer.
 * @param {() => number} [options.now] - Clock function returning
 *   milliseconds since the Unix epoch. Injected so tests are deterministic.
 * @returns {string} An opaque, tamper-evident cursor string.
 * @throws {TypeError} if `secret` is not a non-empty string, if `payload`
 *   is not JSON-serializable, or if `ttlSeconds` is present but not a
 *   positive integer.
 * @throws {InvalidCursorError} if `payload` round-trips to a value that is
 *   not deep-equal to the input (e.g. it contained a function, `undefined`,
 *   or a BigInt that JSON.stringify refuses).
 */
export function createCursor({ secret, payload, ttlSeconds, now = Date.now }) {
  assertString(secret, 'secret');
  if (secret.length === 0) throw new TypeError('secret must be non-empty');
  if (typeof now !== 'function') throw new TypeError('now must be a function');

  let payloadJson;
  try {
    payloadJson = JSON.stringify(payload);
  } catch (err) {
    throw new TypeError(`payload is not JSON-serializable: ${err.message}`);
  }
  if (payloadJson === undefined) {
    throw new TypeError('payload is not JSON-serializable');
  }

  // Round-trip and deep-compare so we refuse values that silently change
  // shape under JSON (e.g. {a: undefined} becomes {}). The caller should
  // never be surprised by what the cursor actually carries.
  const roundTripped = JSON.parse(payloadJson);
  if (!deepEqual(payload, roundTripped)) {
    throw new InvalidCursorError(
      'payload is not stable under JSON round-trip; functions, undefined ' +
        'values, BigInts, and sparse arrays are not supported'
    );
  }

  const created = Math.floor(now());
  if (!Number.isInteger(created)) {
    throw new TypeError('now() must return an integer number of milliseconds');
  }

  let expiresAt = null;
  if (ttlSeconds !== undefined) {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
      throw new TypeError('ttlSeconds must be a positive integer');
    }
    expiresAt = created + ttlSeconds * 1000;
  }

  const body = {
    v: VERSION,
    p: roundTripped,
    c: created,
    e: expiresAt,
  };
  const bodyJson = JSON.stringify(body);
  const bodyBytes = encoder.encode(bodyJson);
  const mac = createHmac('sha256', secret).update(signedBytes(VERSION, bodyBytes)).digest();

  const out = new Uint8Array(1 + mac.length + bodyBytes.length);
  out[0] = VERSION;
  out.set(mac, 1);
  out.set(bodyBytes, 1 + mac.length);
  return encode(out);
}

/**
 * Verify a cursor's integrity and (optionally) freshness, then return its
 * payload.
 *
 * Verification order: structural parse → signature check → expiry check.
 * We check the signature before the expiry so that an expired-but-forged
 * cursor reports as a signature failure, not a normal expiry — the two
 * indicate very different threat models.
 *
 * @param {object} options
 * @param {string} options.secret - The same secret used at creation.
 * @param {string} options.cursor - The cursor string returned by
 *   `createCursor`.
 * @param {() => number} [options.now] - Clock function returning
 *   milliseconds since the Unix epoch.
 * @returns {unknown} The original payload.
 * @throws {InvalidCursorError} if the cursor is structurally malformed.
 * @throws {CursorSignatureError} if the signature does not verify.
 * @throws {CursorExpiredError} if the cursor carried a TTL and it has elapsed.
 */
export function parseCursor({ secret, cursor, now = Date.now }) {
  assertString(secret, 'secret');
  if (secret.length === 0) throw new TypeError('secret must be non-empty');
  assertString(cursor, 'cursor');
  if (typeof now !== 'function') throw new TypeError('now must be a function');

  const raw = decode(cursor);
  if (raw.length < 1 + 32) {
    throw new InvalidCursorError('cursor too short');
  }
  const version = raw[0];
  if (version !== VERSION) {
    throw new InvalidCursorError(`unsupported cursor version ${version}`);
  }
  const theirMac = raw.subarray(1, 1 + 32);
  const bodyBytes = raw.subarray(1 + 32);

  const ourMac = createHmac('sha256', secret)
    .update(signedBytes(VERSION, bodyBytes))
    .digest();

  if (!safeEqual(theirMac, ourMac)) {
    throw new CursorSignatureError('signature mismatch');
  }

  let body;
  try {
    body = JSON.parse(new TextDecoder().decode(bodyBytes));
  } catch {
    // Unreachable in practice because a valid HMAC means the bytes are
    // exactly what we signed, but guard against a cosmic-bit-flip anyway.
    throw new InvalidCursorError('cursor body is not valid JSON');
  }
  if (
    body === null ||
    typeof body !== 'object' ||
    typeof body.v !== 'number' ||
    typeof body.c !== 'number' ||
    !(body.e === null || typeof body.e === 'number')
  ) {
    throw new InvalidCursorError('cursor body has wrong shape');
  }
  if (body.v !== VERSION) {
    throw new InvalidCursorError(`unsupported cursor version ${body.v}`);
  }

  if (body.e !== null) {
    const current = Math.floor(now());
    if (!Number.isInteger(current)) {
      throw new TypeError('now() must return an integer number of milliseconds');
    }
    if (current >= body.e) {
      throw new CursorExpiredError('cursor has expired');
    }
  }

  return body.p;
}

/**
 * Structural deep equality, supporting the JSON value space only:
 * null, booleans, numbers, strings, arrays, plain objects.
 *
 * Used to confirm that a payload survives a JSON round-trip unchanged.
 * Comparing the original input (which may carry live JS values) against the
 * deserialized JSON is what catches `undefined` fields, functions, etc.
 */
function deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return false;
  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  if (Array.isArray(b)) return false;
  const ak = Object.keys(a);
  const bk = Object.keys(b);
  if (ak.length !== bk.length) return false;
  for (const k of ak) {
    if (!Object.prototype.hasOwnProperty.call(b, k)) return false;
    if (!deepEqual(a[k], b[k])) return false;
  }
  return true;
}
