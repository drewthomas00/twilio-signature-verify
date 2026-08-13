'use strict';

/**
 * twilio-signature-verify — verify X-Twilio-Signature on inbound webhooks,
 * including behind a reverse proxy.
 *
 * Twilio signs the exact public URL it POSTs to. Verification therefore has to
 * reconstruct that same URL from the request — and behind a proxy the request
 * no longer looks like what Twilio saw. Four things go wrong, and each one
 * produces the same unhelpful "invalid signature" while your webhook silently
 * rejects real traffic:
 *
 *   1. Scheme. Twilio signed `https://…`, but after TLS termination
 *      `req.protocol` is plain `http`. The scheme is read from
 *      `x-forwarded-proto` first, falling back to `req.protocol` when the app
 *      is directly exposed. Chained proxies send a comma-separated list
 *      ("https, http"); only the first hop is the public one.
 *
 *   2. Host. A proxy that does not set `proxy_set_header Host $host` passes
 *      its own upstream name through, so `Host` is `app.internal:3000` rather
 *      than the public name Twilio signed. `x-forwarded-host` wins when present.
 *
 *   3. Stripped path prefixes. A proxy rule like
 *      `location /sms/ { proxy_pass http://app/; }` removes `/sms` before the
 *      app ever sees the path, so the reconstructed URL is missing a segment.
 *      `pathPrefix` puts it back.
 *
 *   4. Dropped query strings. Twilio signs the URL *including* its query, which
 *      is load-bearing for outbound-call status callbacks. Reconstruction uses
 *      `originalUrl`, which preserves both the mount path and the query.
 *
 * The auth token is caller-supplied and async, so a rotatable token from a
 * database or secret manager works without forking this logic.
 *
 * The verifier itself does no logging and never throws: it is a pure function
 * of the request returning `{ok, reason, detail}`. Logging belongs to the
 * middleware, which emits exactly one line per rejection.
 */

const twilio = require('twilio');
const { TwilioSignatureError, ForbiddenError, ConfigurationError } = require('./errors');

/**
 * Every outcome the verifier can report. `detail` carries the specifics
 * (the reconstructed URL, an underlying error message); `reason` is a stable
 * value you can switch on, alert on, and grep for.
 */
const REASONS = Object.freeze({
  /** Signature present and correct. */
  VALID: 'valid',
  /** TWILIO_VALIDATE_SIGNATURES=false. Development only. */
  VALIDATION_DISABLED: 'validation_disabled_by_env',

  // ── Request-shaped: 403. Anyone can provoke these.
  /** No X-Twilio-Signature header. */
  MISSING_SIGNATURE: 'missing_signature',
  /** Header present, signature does not match the reconstructed URL. */
  INVALID_SIGNATURE: 'invalid_signature',
  /** No Host header to build a URL from. */
  MISSING_HOST: 'missing_host',
  /** POST with `req.body` undefined — the body parser has not run. */
  BODY_NOT_PARSED: 'body_not_parsed',
  /** The URL carries `bodySHA256` but no raw body was available. */
  RAW_BODY_REQUIRED: 'raw_body_required',
  /** The Twilio SDK threw while validating. */
  VALIDATION_ERROR: 'validation_error',

  // ── Server-shaped: 500. Independent of what the caller sent.
  /** Validation is on and `getAuthToken` returned nothing. */
  NO_AUTH_TOKEN: 'no_auth_token_configured',
  /** `getAuthToken` threw — secret store down, database unreachable. */
  TOKEN_RESOLUTION_FAILED: 'token_resolution_failed',
  /** `pathPrefix` is malformed, or its thunk threw. */
  INVALID_CONFIG: 'invalid_config',
});

/**
 * A Set whose contents cannot be changed after construction.
 *
 * `Object.freeze` does not stop `.add()` or `.clear()` on a Set, so a plain
 * frozen Set would still be mutable in every way that matters. This set decides
 * which failures page you, and it is exported — one `.clear()` from anywhere in
 * the dependency graph would route a missing auth token to 403 and hide an
 * outage behind what looks like ordinary spam being turned away.
 */
function readOnlySet(values) {
  const set = new Set(values);
  for (const method of ['add', 'delete', 'clear']) {
    Object.defineProperty(set, method, {
      value() {
        throw new TypeError(
          `CONFIGURATION_REASONS is read-only: .${method}() would change which `
          + 'failures are treated as your outage rather than the caller\'s error.',
        );
      },
      writable: false,
      configurable: false,
    });
  }
  return Object.freeze(set);
}

/**
 * Reasons that mean *we* are broken, not that the caller is.
 *
 * The membership test is deliberately narrow: only failures that no request
 * can provoke belong here. A reason an attacker can trigger by choosing what
 * to send must never map to a 500, or an unauthenticated stranger can
 * manufacture your error budget and your alerts.
 */
const CONFIGURATION_REASONS = readOnlySet([
  REASONS.NO_AUTH_TOKEN,
  REASONS.TOKEN_RESOLUTION_FAILED,
  REASONS.INVALID_CONFIG,
]);

/** Call `logger.warn` if there is one. A partial logger must not break a gate. */
function warn(logger, message) {
  if (logger && typeof logger.warn === 'function') logger.warn(message);
}

/**
 * Verification is on unless TWILIO_VALIDATE_SIGNATURES is the literal 'false'.
 * An escape hatch for local development against a tunnel — never set it in
 * production, where it makes your webhook publicly writable by anyone who
 * knows the URL.
 *
 * @param {Object<string, string>} [env] - defaults to `process.env`
 * @returns {boolean}
 */
function validationEnabled(env = process.env) {
  return (env.TWILIO_VALIDATE_SIGNATURES || 'true').trim().toLowerCase() !== 'false';
}

/**
 * The first hop of a comma-separated forwarded header.
 *
 * `X-Forwarded-Proto: https, http` is what a chained edge (Cloudflare in
 * front of nginx, say) sends. Using the raw header builds
 * `https, http://host/path`, which is not a URL and never matches anything.
 * The leftmost value is the one the public client actually spoke.
 */
function firstForwardedValue(raw) {
  if (!raw) return '';
  return String(raw).split(',')[0].trim();
}

/**
 * Normalise a caller-supplied path prefix to exactly one leading slash and no
 * trailing one.
 *
 * Both `'/sms/'` (→ `//`) and `'sms'` (→ `example.comsms`) are things a person
 * will reasonably type, and both produce a URL that silently fails to validate
 * with no diagnostic beyond "invalid signature".
 *
 * @throws {ConfigurationError} if the prefix looks like a whole URL
 */
function normalizePathPrefix(raw) {
  if (raw === null || raw === undefined) return '';
  const trimmed = String(raw).trim();
  if (!trimmed) return '';
  if (trimmed.includes('://')) {
    throw new ConfigurationError(`pathPrefix must be a path segment, not a URL (got '${trimmed}')`);
  }
  const withLeadingSlash = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  return withLeadingSlash.replace(/\/+$/, '');
}

/**
 * Resolve the configured prefix. A thunk is read per request, so a prefix that
 * comes from configuration can change without re-wiring the middleware.
 *
 * @throws {ConfigurationError} if the thunk throws or the value is malformed
 */
function resolvePrefix(pathPrefix) {
  let raw = pathPrefix;
  if (typeof pathPrefix === 'function') {
    try {
      raw = pathPrefix();
    } catch (err) {
      throw new ConfigurationError(`pathPrefix() threw: ${err.message}`);
    }
  }
  return normalizePathPrefix(raw);
}

/**
 * Rebuild the public URL Twilio used when it signed this request.
 *
 * @param {import('express').Request} req
 * @param {string} [pathPrefix] - segment a fronting proxy stripped ('' when none)
 * @param {{trustProxyHeaders?: boolean}} [opts] - set `trustProxyHeaders: false`
 *   when the app is directly exposed and no proxy sets these headers. It is
 *   not a vulnerability to trust them: an attacker who lies about the scheme
 *   or host still cannot produce a signature valid for the URL they claimed,
 *   so the only request they break is their own.
 * @returns {string|null} null when there is no host to build a URL from
 */
function reconstructUrl(req, pathPrefix = '', { trustProxyHeaders = true } = {}) {
  const forwardedProto = trustProxyHeaders ? firstForwardedValue(req.get('x-forwarded-proto')) : '';
  const forwardedHost = trustProxyHeaders ? firstForwardedValue(req.get('x-forwarded-host')) : '';

  const scheme = forwardedProto || req.protocol;
  const host = forwardedHost || req.get('host');
  if (!host || !scheme) return null;

  // originalUrl keeps the mount path AND the query string.
  const pathWithQuery = req.originalUrl || req.url || '';
  return `${scheme}://${host}${normalizePathPrefix(pathPrefix)}${pathWithQuery}`;
}

/**
 * The raw request body, for the JSON-webhook path.
 *
 * `req.rawBody` is the convention body-parser's `verify` hook populates, so it
 * is the default source. Supply `getRawBody` when you stash it elsewhere.
 */
function defaultGetRawBody(req) {
  return req.rawBody !== undefined ? req.rawBody : null;
}

/**
 * Build an async verifier: `verify(req) → {ok, reason, detail}`.
 *
 * Fails closed. A missing token, a missing signature, an unparsed body and a
 * bad signature all resolve to `ok: false` — there is no input that
 * accidentally passes, and the function never throws.
 *
 * @param {object} opts
 * @param {() => Promise<string|null>} opts.getAuthToken - resolves the CURRENT
 *   auth token. Return null or '' when unavailable.
 * @param {string|(() => string)} [opts.pathPrefix] - segment a fronting proxy
 *   strips before the app sees the path (e.g. '/sms'); '' when none.
 * @param {(req) => string|Buffer|null} [opts.getRawBody] - raw request body,
 *   required only for JSON webhooks (Twilio signs those via `bodySHA256`).
 * @param {boolean} [opts.trustProxyHeaders=true]
 * @param {{warn?: Function}} [opts.logger] - used for the one-time warning when
 *   verification is disabled by env. The verifier does not otherwise log.
 * @returns {(req) => Promise<{ok: boolean, reason: string, detail?: string}>}
 * @throws {TypeError} if `getAuthToken` is missing — a wiring bug, at boot
 */
function createTwilioSignatureVerifier({
  getAuthToken,
  pathPrefix = '',
  getRawBody = defaultGetRawBody,
  trustProxyHeaders = true,
  logger = console,
} = {}) {
  if (typeof getAuthToken !== 'function') {
    throw new TypeError('createTwilioSignatureVerifier: getAuthToken (function) is required');
  }
  if (typeof getRawBody !== 'function') {
    throw new TypeError('createTwilioSignatureVerifier: getRawBody must be a function');
  }

  // Fail fast on a statically-bad prefix rather than on the first webhook.
  if (typeof pathPrefix !== 'function') normalizePathPrefix(pathPrefix);

  // Disabling verification makes the endpoint publicly writable. Say so at
  // wiring time and again the first time a request is actually waved through,
  // so it cannot be a silent property of a deploy.
  let warnedDisabled = false;
  const warnDisabledOnce = () => {
    if (warnedDisabled) return;
    warnedDisabled = true;
    warn(logger, 'SECURITY: TWILIO_VALIDATE_SIGNATURES=false — Twilio webhook signature '
      + 'verification is DISABLED. This endpoint accepts unauthenticated requests.');
  };
  if (!validationEnabled()) warnDisabledOnce();

  return async function verifyTwilioSignature(req) {
    if (!validationEnabled()) {
      warnDisabledOnce();
      return { ok: true, reason: REASONS.VALIDATION_DISABLED };
    }

    // Check the header before anything expensive. `getAuthToken` may hit a
    // database or a secret manager, and this endpoint is public: without this
    // ordering every unsigned junk POST costs a round trip to the secret store.
    const rawSignature = req.headers['x-twilio-signature'];
    const signature = (Array.isArray(rawSignature) ? rawSignature[0] : rawSignature) || '';
    if (!signature) {
      return { ok: false, reason: REASONS.MISSING_SIGNATURE };
    }

    let prefix;
    try {
      prefix = resolvePrefix(pathPrefix);
    } catch (err) {
      return { ok: false, reason: REASONS.INVALID_CONFIG, detail: err.message };
    }

    const url = reconstructUrl(req, prefix, { trustProxyHeaders });
    if (!url) {
      return { ok: false, reason: REASONS.MISSING_HOST };
    }

    let authToken;
    try {
      authToken = await getAuthToken();
    } catch (err) {
      return { ok: false, reason: REASONS.TOKEN_RESOLUTION_FAILED, detail: err.message };
    }
    if (!authToken) {
      return { ok: false, reason: REASONS.NO_AUTH_TOKEN };
    }

    // Twilio signs a JSON webhook by putting a SHA-256 of the body in the URL
    // as `bodySHA256` and signing the URL alone. Feeding the parsed JSON in as
    // form params — which is what the ordinary path would do — produces a
    // different signature and rejects every legitimate request.
    //
    // The check is for the actual query PARAMETER, not the substring: a form
    // webhook whose signed query merely contains 'bodySHA256' in a value must
    // not be shunted onto the body-hash path and rejected.
    let usesBodyHash = false;
    try {
      usesBodyHash = new URL(url).searchParams.has('bodySHA256');
    } catch (_err) {
      // A reconstruction that cannot even parse as a URL cannot be what
      // Twilio signed; there is nothing to compare against.
      return { ok: false, reason: REASONS.INVALID_SIGNATURE, detail: url };
    }
    if (usesBodyHash) {
      const rawBody = getRawBody(req);
      if (rawBody === null || rawBody === undefined) {
        return { ok: false, reason: REASONS.RAW_BODY_REQUIRED, detail: url };
      }
      return runValidation(
        () => twilio.validateRequestWithBody(authToken, signature, url, String(rawBody)),
        url,
      );
    }

    // Twilio signs GET webhooks over the URL alone; params belong to POST.
    const isPost = String(req.method || 'POST').toUpperCase() === 'POST';
    if (isPost && req.body === undefined) {
      // Fails closed either way, but saying so turns the most common first-run
      // mistake from an inscrutable rejection into a one-line fix.
      return { ok: false, reason: REASONS.BODY_NOT_PARSED, detail: url };
    }
    const params = isPost ? (req.body || {}) : {};

    return runValidation(() => twilio.validateRequest(authToken, signature, url, params), url);
  };
}

/**
 * Run the SDK's comparison, mapping a throw to a reason rather than letting it
 * escape. `validateRequest` parses the reconstructed URL and throws on
 * anything malformed.
 */
function runValidation(check, url) {
  try {
    if (!check()) {
      // The URL is the whole diagnostic: when this fires spuriously it is
      // almost always because the reconstruction is not what Twilio signed.
      return { ok: false, reason: REASONS.INVALID_SIGNATURE, detail: url };
    }
  } catch (err) {
    return { ok: false, reason: REASONS.VALIDATION_ERROR, detail: err.message };
  }
  return { ok: true, reason: REASONS.VALID };
}

/**
 * Express middleware over the same verifier. Rejections surface through
 * `next(err)` so your existing error handler formats them:
 *
 *   - ConfigurationError (500) — verification could not be performed at all.
 *     Your bug. Should page someone.
 *   - ForbiddenError (403) — everything else. Their problem.
 *
 * The split is by CONFIGURATION_REASONS membership, not by string matching, so
 * renaming a reason cannot silently downgrade an outage into a rejected
 * request. Exactly one line is logged per rejection.
 *
 * @param {object} opts - same as createTwilioSignatureVerifier
 * @returns {import('express').RequestHandler}
 */
function createTwilioSignatureMiddleware(opts) {
  const verify = createTwilioSignatureVerifier(opts);
  const logger = (opts && opts.logger) || console;

  return function validateTwilioSignature(req, res, next) {
    verify(req)
      .then(({ ok, reason, detail }) => {
        if (ok) return next();

        const clientIp = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
        warn(logger, `Twilio signature rejected on ${req.path} from ${clientIp}: `
          + `${reason}${detail ? ` (${detail})` : ''}`);

        if (CONFIGURATION_REASONS.has(reason)) {
          return next(new ConfigurationError('Server misconfiguration'));
        }
        if (reason === REASONS.MISSING_SIGNATURE) {
          return next(new ForbiddenError('Missing Twilio signature'));
        }
        return next(new ForbiddenError('Invalid Twilio signature'));
      })
      .catch(next);
  };
}

module.exports = {
  createTwilioSignatureVerifier,
  createTwilioSignatureMiddleware,
  reconstructUrl,
  normalizePathPrefix,
  validationEnabled,
  REASONS,
  CONFIGURATION_REASONS,
  TwilioSignatureError,
  ForbiddenError,
  ConfigurationError,
};
