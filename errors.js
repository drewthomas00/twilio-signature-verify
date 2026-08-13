'use strict';

/**
 * Two errors, so the Express middleware can distinguish "the caller is lying"
 * from "we are misconfigured" — they demand opposite responses. A missing
 * auth token is *your* bug and must page someone; a bad signature is a
 * rejected request and must not.
 *
 * Both carry `status` and `statusCode` because error handlers in the wild read
 * one or the other, and a 500 leaking out as a 403 hides an outage.
 */

class TwilioSignatureError extends Error {
  constructor(message, status) {
    super(message);
    this.name = this.constructor.name;
    this.status = status;
    this.statusCode = status;
    this.expose = status < 500;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

/** 403 — the request did not carry a valid signature. */
class ForbiddenError extends TwilioSignatureError {
  constructor(message = 'Invalid Twilio signature') {
    super(message, 403);
  }
}

/** 500 — verification could not be performed. Your problem, not the caller's. */
class ConfigurationError extends TwilioSignatureError {
  constructor(message = 'Server misconfiguration') {
    super(message, 500);
  }
}

module.exports = { TwilioSignatureError, ForbiddenError, ConfigurationError };
