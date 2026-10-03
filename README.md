# cursor-page

Signed, opaque page cursors for pagination. A cursor is a URL-safe string that
carries an arbitrary JSON payload, an optional TTL, and an HMAC-SHA256 tag
binding them together, so a client cannot forge or alter it.

```js
import { createCursor, parseCursor } from 'cursor-page';

const cursor = createCursor({
  secret: 'your-secret-here',
  payload: { id: 1234, sort: 'created_at' },
  ttlSeconds: 300,
});
// hand `cursor` to the client as the "next page" token.

const payload = parseCursor({
  secret: 'your-secret-here',
  cursor: cursor, // the token the client sends back
});
// payload === { id: 1234, sort: 'created_at' }
```

## Why

Offset/limit pagination leaks row counts and lets clients jump arbitrarily,
which is both an information leak and a source of inconsistent results under
concurrent writes. Cursor pagination fixes both, but only if the cursor itself
is unforgeable — otherwise a client can request pages that do not exist, or
rewind past rows they were never supposed to see. This library makes the
cursor a sealed, signed token so the server can trust whatever the client
hands back.

The trade-off: the cursor is opaque. The client cannot inspect or compose it.
If you need the client to be able to seek freely, this is the wrong tool.

## Shape

`createCursor({ secret, payload, ttlSeconds?, now? }) -> string`
`parseCursor({ secret, cursor, now? }) -> payload`

`payload` may be any JSON-stable value: null, boolean, number, string, array,
or plain object. Functions, `undefined` field values, `BigInt`, and `Symbol`
are rejected at creation time, because they silently change shape under
`JSON.stringify`. The error thrown in that case is `InvalidCursorError`.

`ttlSeconds` is optional. If omitted, the cursor never expires. If present, it
must be a positive integer, and the cursor is rejected once `now()` reaches
`created + ttlSeconds * 1000`.

`now` defaults to `Date.now` and exists so tests can pass a fixed clock.

## Edge you will hit

The payload stability check means `{ a: undefined }` throws. This is
deliberate: `JSON.stringify` silently drops that field, so the cursor would
carry a different object than the one you passed. If your payload contains
`undefined` by accident, the error is pointing at a real bug in your code.

A cursor created with one `secret` will fail verification under another with
`CursorSignatureError`, and an expired-but-validly-signed cursor throws
`CursorExpiredError`. The signature is checked before the TTL so that a forged
*and* expired cursor reports as a forgery, not as a benign expiry.

## Node only

Uses `node:crypto` for HMAC. Not browser-compatible.
