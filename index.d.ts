/**
 * twilio-signature-verify — verify X-Twilio-Signature on inbound webhooks,
 * including behind a reverse proxy.
 */

/**
 * Minimal shape this library reads off a request — an Express request, or a
 * plain Node `http.IncomingMessage` (headers are then read from `headers`, and
 * the scheme from the socket).
 *
 * Raw bodies are typed `Uint8Array` rather than `Buffer` deliberately: `Buffer`
 * would make these declarations require `@types/node`, so a consumer without it
 * would get compile errors from inside this package. Every `Buffer` is a
 * `Uint8Array`, so passing one still typechecks.
 */
export interface VerifiableRequest {
  originalUrl?: string;
  url?: string;
  path?: string;
  protocol?: string;
  method?: string;
  body?: unknown;
  rawBody?: string | Uint8Array;
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  socket?: { remoteAddress?: string; encrypted?: boolean };
  get?(name: string): string | undefined;
}

export type Reason =
  | 'valid'
  | 'validation_disabled_by_env'
  | 'missing_signature'
  | 'invalid_signature'
  | 'missing_host'
  | 'body_not_parsed'
  | 'raw_body_required'
  | 'validation_error'
  | 'no_auth_token_configured'
  | 'token_resolution_failed'
  | 'invalid_config';

export interface VerificationResult {
  ok: boolean;
  reason: Reason;
  /** The reconstructed URL, or an underlying error message. */
  detail?: string;
}

export interface VerifierOptions {
  /** Resolves the CURRENT auth token. Return null or '' when unavailable. */
  getAuthToken: () => Promise<string | null | undefined> | string | null | undefined;
  /** Segment a fronting proxy strips before the app sees the path, e.g. '/sms'. */
  pathPrefix?: string | (() => string);
  /**
   * Raw request body, required only for JSON webhooks signed via bodySHA256.
   * Return null when there is none: the request decides whether this is
   * called, and a throw is reported as `invalid_config` (500).
   */
  getRawBody?: (req: VerifiableRequest) => string | Uint8Array | null | undefined;
  /** Set false when the app is directly exposed and no proxy sets the headers. */
  trustProxyHeaders?: boolean;
  logger?: { warn?: (message: string) => void };
}

export interface ReconstructOptions {
  trustProxyHeaders?: boolean;
}

/** Base class for both error types; carries `status` and `statusCode`. */
export declare class TwilioSignatureError extends Error {
  constructor(message: string, status: number);
  status: number;
  statusCode: number;
  expose: boolean;
}

/** 403 — the request did not carry a valid signature. */
export declare class ForbiddenError extends TwilioSignatureError {
  constructor(message?: string);
}

/** 500 — verification could not be performed. Your problem, not the caller's. */
export declare class ConfigurationError extends TwilioSignatureError {
  constructor(message?: string);
}

/**
 * Build an async verifier. Fails closed and never throws — every outcome is a
 * `{ok, reason, detail}`.
 *
 * @throws {TypeError} if `getAuthToken` is missing or `getRawBody` is not a
 *   function (a wiring bug, at boot)
 * @throws {ConfigurationError} if a static `pathPrefix` is malformed
 */
export declare function createTwilioSignatureVerifier(
  opts: VerifierOptions,
): (req: VerifiableRequest) => Promise<VerificationResult>;

/**
 * Express middleware over the same verifier. Rejections reach `next(err)` as
 * `ConfigurationError` (500) or `ForbiddenError` (403).
 */
export declare function createTwilioSignatureMiddleware(
  opts: VerifierOptions,
): (req: VerifiableRequest, res: unknown, next: (err?: Error) => void) => void;

/**
 * Rebuild the public URL Twilio signed. `null` when there is no host.
 *
 * @throws {ConfigurationError} if `pathPrefix` looks like a whole URL
 */
export declare function reconstructUrl(
  req: VerifiableRequest,
  pathPrefix?: string,
  opts?: ReconstructOptions,
): string | null;

/** Exactly one leading slash, no trailing one. Throws on a whole URL. */
export declare function normalizePathPrefix(raw: string | null | undefined): string;

/** False only when TWILIO_VALIDATE_SIGNATURES is 'false' (any case, surrounding whitespace ignored). */
export declare function validationEnabled(env?: Record<string, string | undefined>): boolean;

/** Every outcome the verifier can report, keyed by name. */
export declare const REASONS: Readonly<{
  VALID: 'valid';
  VALIDATION_DISABLED: 'validation_disabled_by_env';
  MISSING_SIGNATURE: 'missing_signature';
  INVALID_SIGNATURE: 'invalid_signature';
  MISSING_HOST: 'missing_host';
  BODY_NOT_PARSED: 'body_not_parsed';
  RAW_BODY_REQUIRED: 'raw_body_required';
  VALIDATION_ERROR: 'validation_error';
  NO_AUTH_TOKEN: 'no_auth_token_configured';
  TOKEN_RESOLUTION_FAILED: 'token_resolution_failed';
  INVALID_CONFIG: 'invalid_config';
}>;

/** The reasons the middleware maps to 500. Nothing request-shaped is in here. */
export declare const CONFIGURATION_REASONS: ReadonlySet<Reason>;
