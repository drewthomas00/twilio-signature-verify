'use strict';

/**
 * Pins the four reconstruction failures that make a correct signature look
 * invalid behind a proxy — forwarded proto, forwarded host, stripped path
 * prefix, dropped query string — plus the async rotatable token source, the
 * 403/500 split, and the fail-closed behaviour of every malformed input.
 */

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const twilio = require('twilio');

const {
  createTwilioSignatureVerifier,
  createTwilioSignatureMiddleware,
  reconstructUrl,
  normalizePathPrefix,
  validationEnabled,
  REASONS,
  ConfigurationError,
} = require('..');

const TOKEN = 'test-auth-token';
const SILENT = { warn: () => {} };

function makeReq(opts = {}) {
  const {
    url = '/api/messages/webhook',
    host = 'webhooks.example.com',
    method = 'POST',
    headers = {},
    rawBody,
  } = opts;
  // `body` has to be read off the object, not destructured with a default:
  // an explicit `body: undefined` is the case under test (no body parser),
  // and a default would silently turn it back into {}.
  const body = 'body' in opts ? opts.body : {};

  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return {
    originalUrl: url,
    url,
    path: url.split('?')[0],
    protocol: 'http',
    method,
    body,
    rawBody,
    headers: lower,
    ip: '10.0.0.1',
    get(name) {
      const k = name.toLowerCase();
      if (k === 'host') return host === null ? undefined : host;
      return lower[k];
    },
  };
}

/** Sign the way Twilio does, for a given public URL + params. */
const sign = (url, params) => twilio.getExpectedTwilioSignature(TOKEN, url, params);

/** Sign a JSON webhook the way Twilio does: SHA-256 of the body, in the URL. */
function signJson(baseUrl, rawBody) {
  const hash = crypto.createHash('sha256').update(rawBody, 'utf-8').digest('hex');
  const url = `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}bodySHA256=${hash}`;
  return { url, signature: twilio.getExpectedTwilioSignature(TOKEN, url, {}) };
}

const verifier = (opts = {}) =>
  createTwilioSignatureVerifier({ getAuthToken: async () => TOKEN, logger: SILENT, ...opts });

afterEach(() => {
  delete process.env.TWILIO_VALIDATE_SIGNATURES;
});


// ── configuration helpers ────────────────────────────────────────

describe('validationEnabled', () => {
  it("defaults on; only 'false' (any case, trimmed) disables", () => {
    assert.equal(validationEnabled({}), true);
    assert.equal(validationEnabled({ TWILIO_VALIDATE_SIGNATURES: 'FALSE ' }), false);
    assert.equal(validationEnabled({ TWILIO_VALIDATE_SIGNATURES: '0' }), true);
  });

  it('reads process.env by default', () => {
    assert.equal(validationEnabled(), true);
    process.env.TWILIO_VALIDATE_SIGNATURES = 'false';
    assert.equal(validationEnabled(), false);
  });
});

describe('normalizePathPrefix', () => {
  it('gives exactly one leading slash and no trailing one', () => {
    // Both of these are things a person will reasonably type, and either one,
    // used as given, builds a URL that fails to validate with no diagnostic.
    assert.equal(normalizePathPrefix('/sms'), '/sms');
    assert.equal(normalizePathPrefix('sms'), '/sms');
    assert.equal(normalizePathPrefix('/sms/'), '/sms');
    assert.equal(normalizePathPrefix('/sms///'), '/sms');
    assert.equal(normalizePathPrefix('  /sms  '), '/sms');
  });

  it('treats empty values as no prefix', () => {
    for (const empty of ['', '   ', null, undefined]) {
      assert.equal(normalizePathPrefix(empty), '');
    }
  });

  it('rejects a whole URL', () => {
    assert.throws(() => normalizePathPrefix('https://example.com/sms'), ConfigurationError);
  });
});


// ── URL reconstruction ───────────────────────────────────────────

describe('reconstructUrl', () => {
  it('prefers x-forwarded-proto over req.protocol (TLS edge)', () => {
    const req = makeReq({ headers: { 'x-forwarded-proto': 'https' } });
    assert.equal(reconstructUrl(req), 'https://webhooks.example.com/api/messages/webhook');
  });

  it('falls back to req.protocol without the header', () => {
    assert.equal(reconstructUrl(makeReq()), 'http://webhooks.example.com/api/messages/webhook');
  });

  it('takes only the first hop of a chained x-forwarded-proto', () => {
    // Cloudflare in front of nginx sends "https, http". Using the raw header
    // builds "https, http://host/path", which is not a URL and never matches.
    const req = makeReq({ headers: { 'x-forwarded-proto': 'https, http' } });
    assert.equal(reconstructUrl(req), 'https://webhooks.example.com/api/messages/webhook');
  });

  it('prefers x-forwarded-host when the proxy passed its own upstream name', () => {
    const req = makeReq({
      host: 'app.internal:3000',
      headers: { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'webhooks.example.com' },
    });
    assert.equal(reconstructUrl(req), 'https://webhooks.example.com/api/messages/webhook');
  });

  it('takes only the first hop of a chained x-forwarded-host', () => {
    const req = makeReq({
      host: 'app.internal:3000',
      headers: { 'x-forwarded-host': 'webhooks.example.com, edge.internal' },
    });
    assert.equal(reconstructUrl(req), 'http://webhooks.example.com/api/messages/webhook');
  });

  it('ignores proxy headers when told the app is directly exposed', () => {
    const req = makeReq({ headers: { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'evil.example' } });
    assert.equal(
      reconstructUrl(req, '', { trustProxyHeaders: false }),
      'http://webhooks.example.com/api/messages/webhook',
    );
  });

  it('re-prepends a stripped path prefix and preserves the query', () => {
    const req = makeReq({ url: '/callbacks/status?id=42', headers: { 'x-forwarded-proto': 'https' } });
    assert.equal(
      reconstructUrl(req, '/sms'),
      'https://webhooks.example.com/sms/callbacks/status?id=42',
    );
  });

  it('normalises a sloppy prefix rather than building a broken URL', () => {
    assert.equal(reconstructUrl(makeReq(), '/sms/'), 'http://webhooks.example.com/sms/api/messages/webhook');
    assert.equal(reconstructUrl(makeReq(), 'sms'), 'http://webhooks.example.com/sms/api/messages/webhook');
  });

  it('returns null when there is no host to build a URL from', () => {
    assert.equal(reconstructUrl(makeReq({ host: null })), null);
  });
});


// ── verification ─────────────────────────────────────────────────

describe('createTwilioSignatureVerifier', () => {
  const params = { Body: 'STOP', From: '+15551234567' };

  it('accepts a signature computed over the proxied public URL', async () => {
    const publicUrl = 'https://webhooks.example.com/sms/api/messages/webhook';
    const req = makeReq({ body: params, headers: { 'x-forwarded-proto': 'https' } });
    req.headers['x-twilio-signature'] = sign(publicUrl, params);

    const verify = verifier({ pathPrefix: '/sms' });
    assert.deepEqual(await verify(req), { ok: true, reason: REASONS.VALID });
  });

  it('accepts one reconstructed through a chained proxy and a rewritten Host', async () => {
    const publicUrl = 'https://webhooks.example.com/sms/api/messages/webhook';
    const req = makeReq({
      host: 'app.internal:3000',
      body: params,
      headers: {
        'x-forwarded-proto': 'https, http',
        'x-forwarded-host': 'webhooks.example.com',
      },
    });
    req.headers['x-twilio-signature'] = sign(publicUrl, params);

    assert.equal((await verifier({ pathPrefix: '/sms' })(req)).ok, true);
  });

  it('rejects when the prefix is not re-prepended', async () => {
    const publicUrl = 'https://webhooks.example.com/sms/api/messages/webhook';
    const req = makeReq({ body: params, headers: { 'x-forwarded-proto': 'https' } });
    req.headers['x-twilio-signature'] = sign(publicUrl, params);

    const out = await verifier()(req);
    assert.equal(out.ok, false);
    assert.equal(out.reason, REASONS.INVALID_SIGNATURE);
    assert.equal(out.detail, 'https://webhooks.example.com/api/messages/webhook',
      'the reconstructed URL is the whole diagnostic');
  });

  it('resolves the token per request — a rotated token takes effect immediately', async () => {
    let current = 'old-token';
    const verify = verifier({ getAuthToken: async () => current });

    const url = 'http://webhooks.example.com/api/messages/webhook';
    const req = makeReq({ body: params });
    req.headers['x-twilio-signature'] = sign(url, params);

    assert.equal((await verify(req)).reason, REASONS.INVALID_SIGNATURE);
    current = TOKEN; // the token is rotated
    assert.equal((await verify(req)).ok, true);
  });

  it('accepts a signed GET webhook, whose params are the URL alone', async () => {
    const url = 'http://webhooks.example.com/callbacks/status?id=42';
    const req = makeReq({ url: '/callbacks/status?id=42', method: 'GET', body: undefined });
    req.headers['x-twilio-signature'] = sign(url, {});
    assert.equal((await verifier()(req)).ok, true);
  });

  it('verifies a JSON webhook through its bodySHA256', async () => {
    const rawBody = JSON.stringify({ event: 'onMessageAdded' });
    const { url, signature } = signJson('https://webhooks.example.com/events', rawBody);
    const query = url.slice(url.indexOf('?'));

    const req = makeReq({
      url: `/events${query}`,
      rawBody,
      body: { event: 'onMessageAdded' },
      headers: { 'x-forwarded-proto': 'https', 'x-twilio-signature': signature },
    });

    // The ordinary path would append the parsed JSON as form params and
    // reject every legitimate request.
    assert.equal((await verifier()(req)).ok, true);
  });

  it('routes by the bodySHA256 query parameter, not the substring', async () => {
    // A form webhook whose signed query merely CONTAINS 'bodySHA256' in a
    // value is still a form webhook. Substring matching would shunt it onto
    // the body-hash path and reject the legitimate request.
    const url = 'http://webhooks.example.com/callbacks/status?note=xbodySHA256x';
    const req = makeReq({ url: '/callbacks/status?note=xbodySHA256x', body: params });
    req.headers['x-twilio-signature'] = sign(url, params);
    assert.deepEqual(await verifier()(req), { ok: true, reason: REASONS.VALID });
  });

  it('says so when a bodySHA256 webhook arrives without a raw body', async () => {
    const rawBody = JSON.stringify({ event: 'onMessageAdded' });
    const { url, signature } = signJson('https://webhooks.example.com/events', rawBody);
    const req = makeReq({
      url: `/events${url.slice(url.indexOf('?'))}`,
      headers: { 'x-forwarded-proto': 'https', 'x-twilio-signature': signature },
    });
    assert.equal((await verifier()(req)).reason, REASONS.RAW_BODY_REQUIRED);
  });

  it('names an unparsed body instead of calling it a bad signature', async () => {
    const url = 'http://webhooks.example.com/api/messages/webhook';
    const req = makeReq({ body: undefined });
    req.headers['x-twilio-signature'] = sign(url, params);

    const out = await verifier()(req);
    assert.equal(out.ok, false);
    assert.equal(out.reason, REASONS.BODY_NOT_PARSED,
      'forgetting the body parser is the most common first-run mistake');
  });

  it('reports a missing Host rather than building http://undefined/', async () => {
    const req = makeReq({ host: null });
    req.headers['x-twilio-signature'] = 'anything';
    assert.equal((await verifier()(req)).reason, REASONS.MISSING_HOST);
  });

  it('fails closed on a missing signature, missing token, and token-source error', async () => {
    const signed = () => {
      const req = makeReq();
      req.headers['x-twilio-signature'] = 'anything';
      return req;
    };

    assert.equal((await verifier()(makeReq())).reason, REASONS.MISSING_SIGNATURE);
    assert.equal((await verifier({ getAuthToken: async () => null })(signed())).reason,
      REASONS.NO_AUTH_TOKEN);

    const broken = verifier({ getAuthToken: async () => { throw new Error('db down'); } });
    const out = await broken(signed());
    assert.equal(out.ok, false);
    assert.equal(out.reason, REASONS.TOKEN_RESOLUTION_FAILED);
    assert.equal(out.detail, 'db down');
  });

  it('does not touch the token source for an unsigned request', async () => {
    // getAuthToken may hit a database or a secret manager, and this endpoint
    // is public: every junk POST would otherwise cost a round trip.
    let lookups = 0;
    const verify = verifier({ getAuthToken: async () => { lookups += 1; return TOKEN; } });

    await verify(makeReq());
    await verify(makeReq());
    assert.equal(lookups, 0);
  });

  it('reports a malformed pathPrefix thunk as configuration, not as a bad signature', async () => {
    const req = makeReq();
    req.headers['x-twilio-signature'] = 'anything';

    const throws = verifier({ pathPrefix: () => { throw new Error('config unavailable'); } });
    assert.equal((await throws(req)).reason, REASONS.INVALID_CONFIG);

    const bogus = verifier({ pathPrefix: () => 'https://elsewhere.example/sms' });
    assert.equal((await bogus(req)).reason, REASONS.INVALID_CONFIG);
  });

  it('survives a logger with no warn()', async () => {
    // The rejection log must sit outside the try that guards the crypto, or a
    // partial logger would turn every invalid_signature into a
    // validation_error and swallow the one diagnostic line that matters.
    const req = makeReq({ body: {} });
    req.headers['x-twilio-signature'] = 'bogus';

    const verify = createTwilioSignatureVerifier({ getAuthToken: async () => TOKEN, logger: {} });
    assert.equal((await verify(req)).reason, REASONS.INVALID_SIGNATURE);
  });

  it('rejects a wiring mistake at construction, not at the first webhook', () => {
    assert.throws(() => createTwilioSignatureVerifier(), TypeError);
    assert.throws(() => createTwilioSignatureVerifier({ getAuthToken: 'token' }), TypeError);
    assert.throws(
      () => createTwilioSignatureVerifier({ getAuthToken: async () => TOKEN, getRawBody: 'raw' }),
      TypeError,
    );
    assert.throws(
      () => createTwilioSignatureVerifier({ getAuthToken: async () => TOKEN, pathPrefix: 'https://x/y' }),
      ConfigurationError,
    );
  });

  it('never throws, whatever the request looks like', async () => {
    const verify = verifier();
    const weird = [
      makeReq({ url: '', host: '' }),
      makeReq({ headers: { 'x-twilio-signature': ['a', 'b'] } }),
      makeReq({ url: '/x?%%%', headers: { 'x-twilio-signature': 'zz' } }),
      makeReq({ host: 'has space', headers: { 'x-twilio-signature': 'zz' } }),
    ];
    for (const req of weird) {
      const out = await verify(req);
      assert.equal(out.ok, false, `should fail closed: ${JSON.stringify(req.headers)}`);
      assert.equal(typeof out.reason, 'string');
    }
  });
});


// ── the escape hatch ─────────────────────────────────────────────

describe('TWILIO_VALIDATE_SIGNATURES=false', () => {
  it('waves the request through, and says so loudly', async () => {
    process.env.TWILIO_VALIDATE_SIGNATURES = 'false';
    const lines = [];
    const verify = createTwilioSignatureVerifier({
      getAuthToken: async () => null,
      logger: { warn: (m) => lines.push(m) },
    });

    assert.deepEqual(await verify(makeReq()), { ok: true, reason: REASONS.VALIDATION_DISABLED });
    // Disabling verification makes the endpoint publicly writable; that must
    // never be a silent property of a deploy.
    assert.equal(lines.length, 1);
    assert.match(lines[0], /SECURITY/);
    assert.match(lines[0], /DISABLED/);
  });

  it('warns once, not once per request', async () => {
    process.env.TWILIO_VALIDATE_SIGNATURES = 'false';
    const lines = [];
    const verify = createTwilioSignatureVerifier({
      getAuthToken: async () => null,
      logger: { warn: (m) => lines.push(m) },
    });
    await verify(makeReq());
    await verify(makeReq());
    await verify(makeReq());
    assert.equal(lines.length, 1);
  });
});


// ── middleware ───────────────────────────────────────────────────

describe('createTwilioSignatureMiddleware', () => {
  const run = (mw, req) => new Promise((resolve) => { mw(req, {}, resolve); });

  it('calls next() bare on a valid signature', async () => {
    const params = { CallSid: 'CA1' };
    const url = 'https://hooks.example.com/twilio/voice';
    const req = makeReq({
      url: '/twilio/voice', host: 'hooks.example.com', body: params,
      headers: { 'x-forwarded-proto': 'https' },
    });
    req.headers['x-twilio-signature'] = sign(url, params);

    const mw = createTwilioSignatureMiddleware({ getAuthToken: async () => TOKEN, logger: SILENT });
    assert.equal(await run(mw, req), undefined);
  });

  it('maps server-shaped failures to 500 and request-shaped ones to 403', async () => {
    const signed = () => {
      const req = makeReq();
      req.headers['x-twilio-signature'] = 'bogus';
      return req;
    };

    const cases = [
      [{ getAuthToken: async () => '' }, signed(), 500],
      [{ getAuthToken: async () => { throw new Error('vault down'); } }, signed(), 500],
      [{ getAuthToken: async () => TOKEN, pathPrefix: () => { throw new Error('x'); } }, signed(), 500],
      [{ getAuthToken: async () => TOKEN }, makeReq(), 403],
      [{ getAuthToken: async () => TOKEN }, signed(), 403],
      [{ getAuthToken: async () => TOKEN }, makeReq({ host: null, headers: { 'x-twilio-signature': 'b' } }), 403],
      [{ getAuthToken: async () => TOKEN }, makeReq({ body: undefined, headers: { 'x-twilio-signature': 'b' } }), 403],
    ];

    for (const [opts, req, status] of cases) {
      const mw = createTwilioSignatureMiddleware({ logger: SILENT, ...opts });
      const err = await run(mw, req);
      assert.equal(err.status, status);
      assert.equal(err.statusCode, status, 'handlers in the wild read one or the other');
    }
  });

  it('never lets a request-shaped failure produce a 500', async () => {
    // Otherwise an unauthenticated stranger can manufacture your error budget
    // by choosing what to send.
    const mw = createTwilioSignatureMiddleware({ getAuthToken: async () => TOKEN, logger: SILENT });
    const attacks = [
      makeReq(),
      makeReq({ headers: { 'x-twilio-signature': 'b' }, body: undefined }),
      makeReq({ headers: { 'x-twilio-signature': 'b' }, host: null }),
      makeReq({ url: '/x?bodySHA256=deadbeef', headers: { 'x-twilio-signature': 'b' } }),
      makeReq({ url: '/x?%%%', headers: { 'x-twilio-signature': 'b' } }),
    ];
    for (const req of attacks) {
      const err = await run(mw, req);
      assert.equal(err.status, 403, `${req.url} should be 403, not a self-inflicted 500`);
    }
  });

  it('logs exactly one line per rejection, carrying the reason and the URL', async () => {
    const lines = [];
    const mw = createTwilioSignatureMiddleware({
      getAuthToken: async () => TOKEN,
      logger: { warn: (m) => lines.push(m) },
    });
    const req = makeReq({ body: {} });
    req.headers['x-twilio-signature'] = 'bogus';

    await run(mw, req);
    assert.equal(lines.length, 1);
    assert.match(lines[0], /invalid_signature/);
    assert.match(lines[0], /http:\/\/webhooks\.example\.com/);
    assert.match(lines[0], /10\.0\.0\.1/);
  });

  it('will not let anything rewrite which failures are a 500', async () => {
    // Object.freeze does not stop .add()/.clear() on a Set. This one is
    // exported and decides what pages you: a single .clear() would route a
    // missing auth token to 403 and hide an outage behind what looks like
    // ordinary spam being turned away.
    const { CONFIGURATION_REASONS } = require('..');
    assert.throws(() => CONFIGURATION_REASONS.clear(), /read-only/);
    assert.throws(() => CONFIGURATION_REASONS.add(REASONS.MISSING_SIGNATURE), /read-only/);
    assert.throws(() => CONFIGURATION_REASONS.delete(REASONS.NO_AUTH_TOKEN), /read-only/);
    assert.equal(CONFIGURATION_REASONS.has(REASONS.NO_AUTH_TOKEN), true);
    assert.equal(CONFIGURATION_REASONS.has(REASONS.MISSING_SIGNATURE), false);
  });

  it('tolerates a logger with no warn()', async () => {
    const mw = createTwilioSignatureMiddleware({ getAuthToken: async () => TOKEN, logger: {} });
    const err = await run(mw, makeReq());
    assert.equal(err.status, 403);
  });
});


describe('requests outside Express, and odd raw bodies', () => {
  it('verifies a plain Node request that has no req.get()', async () => {
    // The README offers the bare verifier "when you're not on Express"; a
    // plain IncomingMessage has headers and a socket, nothing else.
    const url = 'https://webhooks.example.com/api/messages/webhook';
    const params = { Body: 'hi' };
    const req = {
      url: '/api/messages/webhook',
      method: 'POST',
      body: params,
      socket: { encrypted: true },
      headers: {
        host: 'webhooks.example.com',
        'x-twilio-signature': twilio.getExpectedTwilioSignature(TOKEN, url, params),
      },
    };
    const verify = createTwilioSignatureVerifier({ getAuthToken: async () => TOKEN, logger: SILENT });
    assert.deepEqual(await verify(req), { ok: true, reason: REASONS.VALID });
  });

  it('hashes a non-Buffer Uint8Array raw body as its UTF-8 text', async () => {
    // String(new Uint8Array(...)) is '123,34,…' — a different hash, so every
    // legitimate JSON webhook would be rejected.
    const body = '{"event":"delivered"}';
    const hash = crypto.createHash('sha256').update(body).digest('hex');
    const path = `/api/messages/webhook?bodySHA256=${hash}`;
    const signature = twilio.getExpectedTwilioSignature(TOKEN, `https://webhooks.example.com${path}`, {});
    const verify = createTwilioSignatureVerifier({
      getAuthToken: async () => TOKEN,
      getRawBody: () => new TextEncoder().encode(body),
      logger: SILENT,
    });
    const req = makeReq({ url: path, headers: { 'x-twilio-signature': signature, 'x-forwarded-proto': 'https' } });
    assert.deepEqual(await verify(req), { ok: true, reason: REASONS.VALID });
  });

  it('reports a throwing getRawBody as configuration, and does not throw', async () => {
    const path = '/api/messages/webhook?bodySHA256=abc';
    const verify = createTwilioSignatureVerifier({
      getAuthToken: async () => TOKEN,
      getRawBody: () => { throw new Error('stash missing'); },
      logger: SILENT,
    });
    const out = await verify(makeReq({ url: path, headers: { 'x-twilio-signature': 'sig' } }));
    assert.equal(out.ok, false);
    assert.equal(out.reason, REASONS.INVALID_CONFIG);
  });

  it('never rejects, even on something that is not a request', async () => {
    const verify = createTwilioSignatureVerifier({ getAuthToken: async () => TOKEN, logger: SILENT });
    const out = await verify(null);
    assert.equal(out.ok, false);
    assert.equal(out.reason, REASONS.VALIDATION_ERROR);
  });
});
