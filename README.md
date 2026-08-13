# twilio-signature-verify

[![npm](https://img.shields.io/npm/v/twilio-signature-verify)](https://www.npmjs.com/package/twilio-signature-verify)
[![CI](https://github.com/drewthomas00/twilio-signature-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/drewthomas00/twilio-signature-verify/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/twilio-signature-verify)](https://www.npmjs.com/package/twilio-signature-verify)
[![license](https://img.shields.io/npm/l/twilio-signature-verify)](LICENSE)

Verify `X-Twilio-Signature` on inbound webhooks — **including behind a reverse proxy**, which is where most implementations quietly break.

```sh
npm install twilio-signature-verify
```

`twilio` is a peer dependency: you almost certainly already have it, and two copies of the SDK in one tree helps nobody.

## The problem

Twilio signs the exact public URL it POSTs to. Verifying a request means reconstructing that same URL — and behind a proxy, the request no longer resembles what Twilio saw. Four things go wrong, and all four produce the same unhelpful `invalid signature` while your webhook rejects real traffic:

**1. The scheme is wrong.** Twilio signed `https://…`, but after TLS termination your app sees `req.protocol === 'http'`. Reconstruct with `http` and every signature fails.

Worse, a chained edge — Cloudflare in front of nginx — sends a *list*:

```
X-Forwarded-Proto: https, http
```

Take that header raw and you build `https, http://host/path`, which is not a URL. Only the leftmost hop is the one the public client spoke.

**2. The host is the internal one.** nginx passes its own upstream name through unless you set `proxy_set_header Host $host`, so `Host` is `app.internal:3000` rather than the public name Twilio signed. `X-Forwarded-Host` wins when present.

**3. The path is missing a segment.** A proxy rule like

```nginx
location /sms/ { proxy_pass http://app/; }
```

strips `/sms` before your app ever sees the path. Twilio signed the URL *with* it.

**4. The query string got dropped.** Twilio signs the URL including its query — load-bearing for outbound-call status callbacks, where the parameters you set are part of what's signed.

This library handles all four, and normalises `pathPrefix` so that `'/sms/'` and `'sms'` both work instead of silently building `//sms` or `example.comsms`.

## Usage

### As Express middleware

```js
const { createTwilioSignatureMiddleware } = require('twilio-signature-verify');

app.post(
  '/webhooks/sms',
  express.urlencoded({ extended: false }),   // body must be parsed first
  createTwilioSignatureMiddleware({
    getAuthToken: async () => process.env.TWILIO_AUTH_TOKEN,
    pathPrefix: '/sms',                      // only if a proxy strips it
  }),
  handleInboundSms,
);
```

Rejections arrive at your error handler as typed errors:

| Error | Status | Meaning |
|---|---|---|
| `ForbiddenError` | 403 | Anything about the request. Their problem. |
| `ConfigurationError` | 500 | Verification could not be performed at all. **Your** problem — page someone. |

That distinction matters. Collapsing both into a 403 means a webhook that silently rejects *all* traffic because a secret failed to load looks identical to ordinary spam being turned away.

The split is by set membership (`CONFIGURATION_REASONS`), not by matching reason strings, and only failures **no request can provoke** are in it — a missing token, a token source that threw, a malformed `pathPrefix`. Otherwise an unauthenticated stranger could manufacture 500s, and your error budget, by choosing what to send.

### As a plain function

When you're not on Express, or want to log the outcome yourself:

```js
const { createTwilioSignatureVerifier, REASONS } = require('twilio-signature-verify');

const verify = createTwilioSignatureVerifier({
  getAuthToken: async () => secrets.get('twilio/auth_token'),
});

const { ok, reason, detail } = await verify(req);
```

The verifier is a pure function of the request: it never throws and it never logs. `reason` is a stable value from `REASONS` you can switch on and alert on; `detail` carries the specifics — the reconstructed URL, or the underlying error message.

| `reason` | Status | |
|---|---|---|
| `valid` | — | |
| `validation_disabled_by_env` | — | dev escape hatch, see below |
| `missing_signature` | 403 | no header |
| `invalid_signature` | 403 | `detail` is the reconstructed URL |
| `missing_host` | 403 | no `Host` to build a URL from |
| `body_not_parsed` | 403 | POST with `req.body === undefined` |
| `raw_body_required` | 403 | JSON webhook, no raw body available |
| `validation_error` | 403 | the SDK threw |
| `no_auth_token_configured` | **500** | |
| `token_resolution_failed` | **500** | `detail` is the error message |
| `invalid_config` | **500** | bad `pathPrefix`, or its thunk threw |

## Options

| Option | Type | Notes |
|---|---|---|
| `getAuthToken` | `() => Promise<string\|null>` | **Required.** Async, so a rotatable token from a database or secret manager works without forking this logic. |
| `pathPrefix` | `string \| () => string` | Segment a fronting proxy strips. Normalised to one leading slash and no trailing one. A function is re-read per request, so config can change without re-wiring. |
| `getRawBody` | `(req) => string \| Buffer` | Only for JSON webhooks. Defaults to `req.rawBody`. |
| `trustProxyHeaders` | `boolean` | Default `true`. Set false when directly exposed. |
| `logger` | `{ warn }` | Defaults to `console`. A partial logger is fine. |

## Behaviour worth knowing

**It fails closed, and it never throws.** Missing token, missing signature, unparsed body, malformed URL — every path resolves to `ok: false`. There is no input that accidentally passes.

**The signature header is checked before the token is fetched.** `getAuthToken` may hit a database or a secret manager, and this endpoint is public. Checking the cheap thing first means an unsigned junk POST costs nothing.

**Failed verifications report the reconstructed URL.** When this fires spuriously it is almost always because the URL isn't what Twilio signed, and `detail` tells you which of the four failure modes you have. The middleware logs exactly one line per rejection, carrying the reason, the detail and the client IP.

**Parse the body first.** Signature validation covers POST parameters. Forgetting the parser is the most common first-run mistake, so it gets its own reason (`body_not_parsed`) rather than looking like a forgery. GET webhooks are signed over the URL alone and need no body.

**JSON webhooks are supported.** Twilio signs those by putting a SHA-256 of the body in the URL as `bodySHA256` and signing the URL alone. Feeding the *parsed* JSON in as form params — which is what a naive implementation does — rejects every legitimate request. Capture the raw body and this handles it:

```js
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf.toString('utf8'); },
}));
```

**Trusting forwarded headers is not a vulnerability here.** An attacker who lies about the scheme or host still cannot produce a signature valid for the URL they claimed, so the only request they break is their own.

**`TWILIO_VALIDATE_SIGNATURES=false` disables verification** and makes your webhook publicly writable by anyone who knows the URL. It is an escape hatch for local development against a tunnel. It logs a `SECURITY:` warning at wiring time and again on first use, so it can never be a silent property of a deploy.

## Testing

```sh
npm test
```

Node's built-in test runner — no test framework dependency. Signatures in the suite are produced by the real Twilio SDK rather than mocked, so the tests exercise the actual algorithm.

## Related packages

Small, dependency-light pieces pulled out of production systems I've built:

- **[tcpa-quiet-hours](https://github.com/drewthomas00/tcpa-quiet-hours)** — is it legal to send this marketing message right now?
- **[pg-cron-lease](https://github.com/drewthomas00/pg-cron-lease)** — make an in-process cron job a singleton across replicas, using Postgres
- **[us-zip-centroids](https://github.com/drewthomas00/us-zip-centroids)** — offline US ZIP → lat/lng, no geocoder

## License

MIT © [Drew Thomas](https://drewthomasbuilds.com)
