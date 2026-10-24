'use strict';

const crypto = require('node:crypto');

// jose is ESM-only; load it lazily via dynamic import (works from CommonJS on
// any modern Node) rather than require(), and memoize so it's only loaded
// once. A failed import isn't memoized, so the next request tries again.
let josePromise;
function loadJose() {
  josePromise ??= import('jose').catch(err => {
    josePromise = undefined;
    throw err;
  });
  return josePromise;
}

// The complete set of algorithms this plugin will ever accept -- the only
// ones jose is asked to verify against, full stop, regardless of what an
// issuer's `algorithms` config or its OIDC discovery document names.
// Deliberately asymmetric-only: a JWKS endpoint publishes PUBLIC keys, so a
// legitimate issuer has no reason to ever sign something verifiable as
// HS*-over-that-same-JWKS -- an HS*-"signed" token can only mean someone is
// attempting the classic RSA/EC-public-key-reused-as-HMAC-secret confusion
// attack. `none` is excluded for the same reason. No config path can ever
// add to this set; see _validateAlgorithms() and
// _deriveAlgorithmsFromDiscovery() below, both of which filter through it.
const SAFE_ALGS = new Set([
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
]);

// Used whenever there's no explicit per-issuer `algorithms` config and no
// safe algorithm could be determined from OIDC discovery (field absent,
// malformed, or nothing in it survives the SAFE_ALGS filter) -- matches every
// CI OIDC issuer this plugin ships config for today.
const DEFAULT_ALGORITHMS = ['RS256'];

// jwtVerify() failures with one of these codes mean a key WAS successfully
// resolved and the token was evaluated against it -- the token itself is bad
// (wrong signature, expired, wrong audience/alg, malformed), not the JWKS
// location. Re-running discovery would never fix these, and retrying on them
// would let anyone holding a trusted issuer's name spam garbage tokens to
// force repeated discovery calls. Everything else (key not found, JWKS fetch
// timeout/invalid response, network errors) is treated as "the cached JWKS
// location might be stale" and gets one discovery-refresh-and-retry.
const NON_RETRYABLE_JWT_ERROR_CODES = new Set([
  'ERR_JWT_CLAIM_VALIDATION_FAILED',
  'ERR_JWT_EXPIRED',
  'ERR_JWT_INVALID',
  'ERR_JWS_INVALID',
  'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
  'ERR_JWKS_MULTIPLE_MATCHING_KEYS',
  'ERR_JOSE_ALG_NOT_ALLOWED',
]);

// Mirrors the shape Verdaccio's own auth internals produce for a logged-in
// user (@verdaccio/config's createRemoteUser) -- reproduced here because
// register_middlewares() isn't handed that helper (only the auth-plugin-only
// apiJWTmiddleware(helpers) hook is), and @verdaccio/config isn't a stable
// public dependency of this plugin.
const DEFAULT_LOGGED_IN_GROUPS = [
  '$all',
  '$authenticated',
  '@all',
  '@authenticated',
  'all',
];

// A claim value is not a package name: matchClaim is fully free-form per
// issuer config (GitHub's `repository`, Bitbucket's opaque `repositoryUuid`,
// or whatever claim a future issuer's own token shape happens to carry), so
// this can't assume a package-name-like, single-delimiter structure. Every
// `:` is folded to `/` before matching, so `*` stops at either one -- e.g.
// `fortmesa:verdaccio-*` blocks `*` from also matching past a `:`, the same
// way `fortmesa/*` stops at a `/`. A value/pattern with neither character is
// unaffected.
function foldMatchDelimiters(value) {
  return value.replace(/:/g, '/');
}

// The pattern syntax allow: entries document: `**` matches anything, `*`
// matches anything except `/` (after folding, `:` too), and every other
// character is literal. Nothing else -- no negation, no braces, no
// character classes -- so a pattern can never mean more than it looks like.
function compileAllowPattern(pattern, caseInsensitive) {
  const source = foldMatchDelimiters(pattern)
    .split('**')
    .map(part =>
      part
        .split('*')
        .map(text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
        .join('[^/]*'),
    )
    .join('.*');
  return new RegExp(`^${source}$`, caseInsensitive ? 'i' : '');
}

const TEMPLATE_PLACEHOLDER = /\{(\w+)\}/g;

function isNonEmptyString(value) {
  return typeof value === 'string' && value !== '';
}

class TrustedIssuer {
  constructor(cfg, {clockToleranceSeconds, discoveryCooldownSeconds, logger}) {
    this.id = cfg.id;
    this.issuer = cfg.issuer;
    this.audience = cfg.audience;
    this.usernameTemplate = cfg.usernameTemplate;
    this.groupTemplates = cfg.groupTemplates ?? [];
    this.matchClaim = cfg.matchClaim;
    this.caseInsensitive = cfg.matchCaseInsensitive ?? true;
    this.explicitJwksUri = cfg.jwksUri;
    this.clockToleranceSeconds = clockToleranceSeconds;
    this.logger = logger;
    this._validateConfig(cfg);
    // Each entry is a set of claim patterns that must all match (one of the
    // patterns given for each claim), and any one entry matching allows the
    // token. matchClaim's key is required in every entry; any other key
    // narrows that entry further, e.g. `sub` to tell a publish job's token
    // from one any other job in the same repository could mint.
    this.allow = cfg.allow.map(entry =>
      Object.entries(entry).map(([claim, patterns]) => ({
        claim,
        patterns: []
          .concat(patterns)
          .map(pattern => compileAllowPattern(pattern, this.caseInsensitive)),
      })),
    );
    // Mirrors jose's own default cooldown between JWKS refetches -- bounds how
    // often a flood of bad tokens can force us to re-run OIDC discovery,
    // since a freshly re-discovered key set has no cooldown history of its own.
    this.discoveryCooldownMs = discoveryCooldownSeconds * 1000;
    this._jwks = null;
    this._jwksPromise = null;
    this._lastDiscoveryRefreshAt = 0;
    this._refreshPromise = null;

    // Explicit config wins outright and is validated up front (fail loud on
    // a mistake, same as the duplicate-issuer-URL check in
    // OidcAuthMiddleware's constructor); otherwise the algorithm list is
    // resolved lazily from OIDC discovery, alongside the JWKS lookup -- see
    // _resolveJwksUri() / _deriveAlgorithmsFromDiscovery() below.
    this.explicitAlgorithms = cfg.algorithms
      ? this._validateAlgorithms(cfg.algorithms, 'algorithms config')
      : null;
    this._resolvedAlgorithms = null;
    this._loggedAlgorithmsKey = null;
  }

  // Everything verify() relies on, checked once at startup. A missing
  // audience in particular would make jose skip the audience check, and a
  // missing issuer would claim every token that carries no `iss` at all.
  _validateConfig(cfg) {
    const fail = message => {
      throw new Error(`oidc-auth: issuer '${cfg.id}' ${message}`);
    };
    if (!isNonEmptyString(cfg.id)) {
      throw new Error('oidc-auth: every issuer needs a non-empty id');
    }
    let issuerUrl;
    try {
      issuerUrl = new URL(cfg.issuer);
    } catch {
      fail('needs issuer set to an absolute URL');
    }
    if (issuerUrl.protocol !== 'https:' && issuerUrl.protocol !== 'http:') {
      fail('needs an http(s) issuer URL');
    }
    const audiences = [].concat(cfg.audience ?? []);
    if (audiences.length === 0 || !audiences.every(isNonEmptyString)) {
      fail('needs audience set to a non-empty string or list of strings');
    }
    if (!isNonEmptyString(cfg.matchClaim)) {
      fail('needs a non-empty matchClaim');
    }
    if (!Array.isArray(cfg.groupTemplates ?? [])) {
      fail('needs groupTemplates to be a list');
    }
    const templates = [cfg.usernameTemplate, ...(cfg.groupTemplates ?? [])];
    for (const template of templates) {
      if (!isNonEmptyString(template)) {
        fail(
          'needs usernameTemplate and every groupTemplates entry to be non-empty strings',
        );
      }
      if (/[{}]/.test(template.replace(TEMPLATE_PLACEHOLDER, ''))) {
        fail(
          `has a malformed template '${template}' -- placeholders look like {claimName}`,
        );
      }
    }
    if (!Array.isArray(cfg.allow) || cfg.allow.length === 0) {
      fail('needs a non-empty allow list');
    }
    for (const entry of cfg.allow) {
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
        fail('has an allow entry that is not a map of claim names to patterns');
      }
      if (!(cfg.matchClaim in entry)) {
        fail(`has an allow entry without its matchClaim '${cfg.matchClaim}'`);
      }
      for (const [claim, patterns] of Object.entries(entry)) {
        const list = [].concat(patterns);
        if (list.length === 0 || !list.every(isNonEmptyString)) {
          fail(
            `has an allow entry whose '${claim}' is not a pattern or a list of patterns`,
          );
        }
      }
    }
  }

  _validateAlgorithms(algorithms, source) {
    for (const alg of algorithms) {
      if (!SAFE_ALGS.has(alg)) {
        throw new Error(
          `oidc-auth: issuer '${this.id}' names unsupported algorithm '${alg}' in ${source} -- supported: ${Array.from(SAFE_ALGS).join(', ')}`,
        );
      }
    }
    return algorithms;
  }

  async _resolveJwksUri() {
    if (this.explicitJwksUri) {
      // An explicit jwksUri bypasses discovery entirely -- often *because*
      // the issuer's discovery document is nonstandard or unreachable -- so
      // we must not fetch it anyway just to learn supported algorithms.
      if (!this.explicitAlgorithms)
        this._resolvedAlgorithms = DEFAULT_ALGORITHMS;
      return this.explicitJwksUri;
    }
    const discoveryUrl = `${this.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
    // No redirects, as jose's own JWKS fetch: the document has to come from
    // the issuer itself.
    const res = await fetch(discoveryUrl, {
      signal: AbortSignal.timeout(5000),
      redirect: 'manual',
    });
    if (res.status !== 200) {
      throw new Error(
        `oidc discovery failed for issuer '${this.id}': HTTP ${res.status}`,
      );
    }
    const doc = await res.json();
    // OpenID Connect Discovery requires the document's issuer to be exactly
    // the issuer it was fetched for.
    if (doc.issuer !== this.issuer) {
      throw new Error(
        `oidc discovery for issuer '${this.id}' returned issuer '${doc.issuer}', not '${this.issuer}'`,
      );
    }
    if (!doc.jwks_uri) {
      throw new Error(
        `oidc discovery for issuer '${this.id}' did not return a jwks_uri`,
      );
    }
    if (!this.explicitAlgorithms) {
      this._resolvedAlgorithms = this._deriveAlgorithmsFromDiscovery(doc);
    }
    return doc.jwks_uri;
  }

  // Only consulted when the issuer didn't pin `algorithms` explicitly.
  // Discovery's `id_token_signing_alg_values_supported` describes the
  // issuer's entire capability surface (e.g. algorithms it supports for
  // confidential clients using a shared secret) -- not specifically what's
  // safe for verifying a bearer ID token here -- so it's narrowed to
  // SAFE_ALGS, the hard ceiling nothing can expand. Falls back to
  // RS256-only if the field is absent, malformed, or nothing in it survives
  // the filter (e.g. an issuer that only lists HS256).
  _deriveAlgorithmsFromDiscovery(doc) {
    const advertised = Array.isArray(doc.id_token_signing_alg_values_supported)
      ? doc.id_token_signing_alg_values_supported
      : [];
    const safe = advertised.filter(alg => SAFE_ALGS.has(alg));
    const resolved = safe.length > 0 ? safe : DEFAULT_ALGORITHMS;
    this._logAlgorithmsIfChanged(resolved);
    return resolved;
  }

  // Discovery-derived algorithms can legitimately change over time (the
  // issuer rotates key types, adds a curve, etc.), logged once per distinct
  // result so an operator has something to grep for if behavior shifts.
  // Pure observability, not enforcement -- SAFE_ALGS is what enforces, and
  // it holds regardless of whether anyone reads this line or what level
  // it's at -- so this is debug, not warn, whether it's the first
  // resolution or a later change from a previously-seen one.
  _logAlgorithmsIfChanged(algorithms) {
    const key = algorithms.join(',');
    if (key === this._loggedAlgorithmsKey) return;
    this._loggedAlgorithmsKey = key;
    this.logger.debug(
      {issuer: this.id, algorithms},
      'oidc-auth: issuer @{issuer} trusted signing algorithms resolved via OIDC discovery: @{algorithms}',
    );
  }

  // Pass forceRefresh to discard the cached remote key set and re-run OIDC
  // discovery from scratch -- used when the provider may have moved jwks_uri,
  // not just rotated the keys served at the URL we already know about.
  async _getJwks({forceRefresh = false} = {}) {
    if (forceRefresh) {
      this._jwks = null;
      this._jwksPromise = null;
    }
    if (this._jwks) return this._jwks;
    if (!this._jwksPromise) {
      this._jwksPromise = this._resolveJwksUri()
        .then(async uri => {
          const {createRemoteJWKSet} = await loadJose();
          this._jwks = createRemoteJWKSet(new URL(uri));
          return this._jwks;
        })
        .catch(err => {
          // Allow the next request to retry discovery instead of caching a
          // failure forever (e.g. a transient network blip at pod startup).
          this._jwksPromise = null;
          throw err;
        });
    }
    return this._jwksPromise;
  }

  // A claim a template names but the token doesn't carry (or carries as
  // something other than a string or number) fails the token, rather than
  // rendering as '' or '[object Object]' into an identity some ACL might
  // match. Under case-insensitive matching the claim values are rendered in
  // lower case: Verdaccio compares ACL entries exactly, so a token the allow
  // list accepted as FortMesa/Example would otherwise get an identity no
  // lower-case ACL entry names.
  _render(template, claims) {
    return template.replace(TEMPLATE_PLACEHOLDER, (_, key) => {
      const value = claims[key];
      if (typeof value === 'string' || typeof value === 'number') {
        const text = String(value);
        return this.caseInsensitive ? text.toLowerCase() : text;
      }
      const err = new Error(
        `issuer '${this.id}' token has no usable '${key}' claim for its identity template`,
      );
      err.code = 'OIDC_TEMPLATE_CLAIM_MISSING';
      throw err;
    });
  }

  _isAllowed(claims) {
    return this.allow.some(entry =>
      entry.every(({claim, patterns}) => {
        const value = claims[claim];
        if (typeof value !== 'string') return false;
        const folded = foldMatchDelimiters(value);
        return patterns.some(pattern => pattern.test(folded));
      }),
    );
  }

  _verifyOptions() {
    return {
      issuer: this.issuer,
      audience: this.audience,
      // Explicit config wins outright; otherwise whatever _resolveJwksUri()
      // most recently resolved via discovery (or defaulted to, if discovery
      // was bypassed) -- always already populated by the time this is
      // called, since verify() awaits _getJwks() first.
      algorithms:
        this.explicitAlgorithms ??
        this._resolvedAlgorithms ??
        DEFAULT_ALGORITHMS,
      clockTolerance: this.clockToleranceSeconds,
      // Required so a successful verification always yields an `exp` the
      // caller can bound its own result cache by -- see JwtVerificationCache.
      requiredClaims: ['exp'],
    };
  }

  _discoveryCooldownActive() {
    return Date.now() - this._lastDiscoveryRefreshAt < this.discoveryCooldownMs;
  }

  async verify(token) {
    const {jwtVerify} = await loadJose();

    let payload;
    try {
      const jwks = await this._getJwks();
      ({payload} = await jwtVerify(token, jwks, this._verifyOptions()));
    } catch (err) {
      if (NON_RETRYABLE_JWT_ERROR_CODES.has(err?.code)) throw err;
      // A refresh another request already started is waited for rather than
      // refused by the cooldown it set: the keys it brings back may be the
      // ones this token needs.
      let refresh = this._refreshPromise;
      if (!refresh) {
        if (this._discoveryCooldownActive()) throw err;
        this._lastDiscoveryRefreshAt = Date.now();
        this.logger.debug(
          {issuer: this.id, err: err.code || err.name || err.message},
          'oidc-auth: re-running OIDC discovery after JWKS resolution failure',
        );
        refresh = this._getJwks({forceRefresh: true});
        this._refreshPromise = refresh;
        refresh.then(
          () => (this._refreshPromise = null),
          () => (this._refreshPromise = null),
        );
      }
      const freshJwks = await refresh;
      ({payload} = await jwtVerify(token, freshJwks, this._verifyOptions()));
    }

    if (!this._isAllowed(payload)) {
      const err = new Error(
        `token claims match no allow entry for issuer '${this.id}'`,
      );
      err.code = 'OIDC_NOT_ALLOWED';
      throw err;
    }

    const realGroups = Array.from(
      new Set(this.groupTemplates.map(t => this._render(t, payload))),
    );
    const remoteUser = {
      name: this._render(this.usernameTemplate, payload),
      real_groups: realGroups,
      groups: Array.from(new Set([...realGroups, ...DEFAULT_LOGGED_IN_GROUPS])),
    };
    // payload.exp is seconds-since-epoch per the JWT spec; callers use this to
    // make sure a cached result never outlives the token's own expiry.
    return {remoteUser, expiresAt: payload.exp * 1000};
  }
}

// Caches the *result* of a successful verify() so repeat requests bearing the
// exact same token (the common case -- a single CI job makes many npm requests
// with one token) skip signature verification entirely. This is safe because
// a JWT's payload is exactly the bytes that were signed: if an incoming token
// is byte-identical to one we already fully verified, none of its claims can
// have changed, so nothing about it needs re-checking except "is it still
// within its validity window." Keyed by a hash of the token rather than the
// raw token itself, so a verified bearer credential isn't retained verbatim
// in memory for the cache's lifetime.
class JwtVerificationCache {
  // maxEntries 0 turns caching off.
  constructor({ttlMs, maxEntries}) {
    if (!Number.isFinite(ttlMs) || ttlMs < 0) {
      throw new Error('oidc-auth: jwtCacheTtlSeconds must be 0 or more');
    }
    if (!Number.isInteger(maxEntries) || maxEntries < 0) {
      throw new Error(
        'oidc-auth: jwtCacheMaxEntries must be a whole number, 0 or more',
      );
    }
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this._entries = new Map(); // tokenHash -> { remoteUser, expiresAt }
  }

  _hash(token) {
    // sha512 over sha256: more digest bits, and typically faster on modern
    // 64-bit hardware since it operates on 64-bit words -- there's no reason
    // to prefer the smaller/slower hash for an internal-only cache key.
    return crypto.createHash('sha512').update(token).digest('hex');
  }

  get(token) {
    const key = this._hash(token);
    const entry = this._entries.get(key);
    if (!entry) return undefined;
    if (Date.now() >= entry.expiresAt) {
      this._entries.delete(key);
      return undefined;
    }
    // Move to the most-recently-used end so eviction below drops the entry
    // that's gone longest unused, not just the one inserted longest ago.
    this._entries.delete(key);
    this._entries.set(key, entry);
    // A copy: Verdaccio's middlewares write to req.remote_user (its
    // `error`, for one), and that must not change what later requests with
    // the same token get.
    return structuredClone(entry.remoteUser);
  }

  set(token, remoteUser, tokenExpiresAtMs) {
    if (this.maxEntries === 0) return;
    // Never cache past the token's own expiry, no matter how long ttlMs is --
    // a cache is a performance shortcut, not a way to extend a token's life.
    const expiresAt = Math.min(Date.now() + this.ttlMs, tokenExpiresAtMs);
    if (expiresAt <= Date.now()) return; // already expired, or expiring immediately -- not worth caching
    const key = this._hash(token);
    this._entries.delete(key); // re-inserting moves it to the most-recently-used end
    // Stored as a copy for the same reason get() returns one: the caller
    // hands remoteUser itself to the request that missed.
    this._entries.set(key, {
      remoteUser: structuredClone(remoteUser),
      expiresAt,
    });
    while (this._entries.size > this.maxEntries) {
      this._entries.delete(this._entries.keys().next().value);
    }
  }
}

class OidcAuthMiddleware {
  constructor(config, options) {
    this.logger = options.logger;
    const clockToleranceSeconds = config.clockToleranceSeconds ?? 30;
    const discoveryCooldownSeconds = config.discoveryCooldownSeconds ?? 30;
    this.issuers = (config.issuers ?? []).map(
      cfg =>
        new TrustedIssuer(cfg, {
          clockToleranceSeconds,
          discoveryCooldownSeconds,
          logger: this.logger,
        }),
    );

    const seenIssuerUrls = new Set();
    for (const trustedIssuer of this.issuers) {
      if (seenIssuerUrls.has(trustedIssuer.issuer)) {
        throw new Error(
          `oidc-auth: duplicate issuer URL configured: ${trustedIssuer.issuer}`,
        );
      }
      seenIssuerUrls.add(trustedIssuer.issuer);
    }

    this.jwtCache = new JwtVerificationCache({
      ttlMs: (config.jwtCacheTtlSeconds ?? 300) * 1000,
      maxEntries: config.jwtCacheMaxEntries ?? 1000,
    });
  }

  // Reads `iss` without verifying anything -- used only to pick which
  // TrustedIssuer (if any) should attempt full verification. jwtVerify()
  // re-checks iss/aud/exp/nbf/alg cryptographically; nothing here is trusted.
  _peekIssuer(token) {
    try {
      const payloadSegment = token.split('.')[1];
      const payload = JSON.parse(
        Buffer.from(payloadSegment, 'base64url').toString('utf8'),
      );
      return payload.iss;
    } catch {
      return undefined;
    }
  }

  register_middlewares(app, auth, storage) {
    app.use((req, res, next) => {
      const header = req.headers.authorization;
      if (!header?.startsWith('Bearer ')) return next();

      const token = header.slice('Bearer '.length).trim();

      const cachedUser = this.jwtCache.get(token);
      if (cachedUser) {
        req.remote_user = cachedUser;
        res.locals.remote_user = cachedUser;
        return next();
      }

      const issuer = this.issuers.find(
        candidate => candidate.issuer === this._peekIssuer(token),
      );
      // Not a token from a trusted CI issuer -- leave core auth's decision
      // (a real human session, or $anonymous) untouched.
      if (!issuer) return next();

      // Verification is asynchronous (discovery, the JWKS fetch, the
      // signature check), and Verdaccio's access log has already started
      // reading the request with req.on('data') (verdaccio/verdaccio#1912).
      // Without a pause, a request body would stream past before any body
      // parser is attached. Pausing until next() is what Verdaccio's own
      // apiJWTmiddleware does around its asynchronous auth; the body is left
      // for the real parsers, with their size limit. On a request whose body
      // Verdaccio already parsed (6.10.6 parses before any plugin runs) the
      // pause changes nothing.
      // The two outcomes are separate handlers, so nothing thrown on the way
      // through next() can turn an accepted request into a 401 as well.
      req.pause();
      issuer.verify(token).then(
        ({remoteUser, expiresAt}) => {
          this.jwtCache.set(token, remoteUser, expiresAt);
          this.logger.info(
            {issuer: issuer.id, user: remoteUser.name},
            'oidc-auth: authenticated CI identity',
          );
          req.remote_user = remoteUser;
          res.locals.remote_user = remoteUser;
          req.resume();
          next();
        },
        err => {
          this.logger.warn(
            {issuer: issuer.id, err: err.code || err.name || err.message},
            'oidc-auth: rejected token for trusted issuer',
          );
          req.resume();
          res.status(401).json({
            error: 'unauthorized',
            reason: 'oidc token verification failed',
          });
        },
      );
    });
  }
}

module.exports = (config, options) => new OidcAuthMiddleware(config, options);
// Exported for the local smoke-test harness (test/smoke.js) -- not used by Verdaccio itself.
module.exports.OidcAuthMiddleware = OidcAuthMiddleware;
module.exports.TrustedIssuer = TrustedIssuer;
module.exports.JwtVerificationCache = JwtVerificationCache;
