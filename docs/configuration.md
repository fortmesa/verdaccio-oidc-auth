# Configuration reference

See the [README](../README.md) for installation and a quick-start config. This
page covers everything else in depth.

## Why this is a `middlewares` plugin, not an `auth` plugin

Verdaccio's core auth middleware (`auth.apiJWTmiddleware()`) always runs first
and always sets `req.remote_user`. For a `Bearer` token, it tries to verify it
as a session token _Verdaccio itself issued_, and -- this is the key fact that
makes the design work -- **if that fails for any reason (including "this was
signed by GitHub/Bitbucket, not us"), it does not reject the request. It
silently sets `$anonymous` and calls `next()`.**

That means a `middlewares` plugin registered to run afterward can safely:

- do nothing if the token isn't from a trusted issuer (leaving whatever core
  auth already decided -- a real human session, or anonymous -- untouched),
- or, if it is from a trusted issuer, independently verify it and overwrite
  `req.remote_user` before the ACL/route logic runs.

A more invasive alternative exists -- an `auth:`-configured plugin can implement
`apiJWTmiddleware(helpers)`, which fully _replaces_ Verdaccio's built-in
Bearer/Basic handling for every request. That was deliberately **not** used
here: doing so would require re-implementing Verdaccio's own JWT-secret
verification and Basic-auth-to-`authenticate()` delegation just to avoid
breaking existing password-based users, duplicating internal logic that isn't
part of Verdaccio's public plugin API. The `middlewares` approach needs none of
that -- it's purely additive.

**Consequence**: this plugin must be listed _before_ any other middleware that
reads `req.remote_user` under `middlewares:` in `config.yaml`, so those see the
corrected identity rather than the anonymous fallback.

## Full config

```yaml
middlewares:
  oidc-auth:
    clockToleranceSeconds: 30 # default 30 -- allowed clock drift on exp/nbf
    discoveryCooldownSeconds: 30 # default 30 -- see "Discovery and key caching" below
    jwtCacheTtlSeconds: 300 # default 300 -- see "Result cache" below
    jwtCacheMaxEntries: 1000 # default 1000 -- see "Result cache" below
    issuers:
      - id: github-actions # free-form label, used in logs
        issuer: https://token.actions.githubusercontent.com # must match the token's `iss` exactly
        audience: https://your-registry.example.com # must match the token's `aud`
        # algorithms: [RS256]      # optional -- see "Algorithm selection" below.
        # Defaults to whatever OIDC discovery safely
        # advertises, RS256 if nothing usable is found.
        usernameTemplate: 'gha:{repository}' # {claim} substituted from verified payload
        groupTemplates:
          - 'gha:{repository}'
          - 'gha-org:{repository_owner}'
        matchClaim: repository # which claim is checked against `allow`
        matchCaseInsensitive: true # default true
        allow:
          - repository: your-org/your-repo # one entry per onboarded repo
      - id: bitbucket-pipelines
        issuer: https://api.bitbucket.org/2.0/workspaces/your-workspace/pipelines-config/identity/oidc
        audience: 'ari:cloud:bitbucket::workspace/<workspace-uuid>'
        usernameTemplate: 'bb:{repositoryUuid}'
        groupTemplates:
          - 'bb:{repositoryUuid}'
          - 'bb-workspace:{workspaceUuid}'
        matchClaim: repositoryUuid
        allow:
          - repositoryUuid: '<repo-uuid>' # Bitbucket claims are UUIDs, not slugs -- look this up once via Bitbucket's REST API
```

Each `issuers[]` entry is independent; the plugin throws at startup if two
entries share the same `issuer` URL (a config mistake that would otherwise
silently mean only the first one is ever tried).

## How verification works (per request)

1. If there's no `Authorization: Bearer` header, no-op.
2. Look the token up in the result cache (see "Result cache" below). On a hit,
   jump straight to step 6 with the cached identity -- no base64 decoding, no
   cryptographic work, nothing but a hash lookup and a timestamp comparison.
3. Otherwise, base64-decode the token's payload segment _without verifying
   anything_, just to read `iss`. If it doesn't match a configured issuer, no-op
   -- the token might be a legitimate Verdaccio session token or garbage; either
   way it's not ours to judge.
4. If `iss` matches, run full verification via
   [`jose`](https://github.com/panva/jose)'s `jwtVerify()` against that issuer's
   JWKS (resolved via OIDC discovery --
   `{issuer}/.well-known/openid-configuration` -> `jwks_uri`; see "Discovery and
   key caching" below for exactly what's cached and when it's refreshed),
   checking:
   - signature, against the fetched public key
   - `iss` and `aud` match exactly
   - `exp`/`nbf` within `clockToleranceSeconds`, and `exp` must be present
   - `alg` is one of that issuer's resolved algorithms -- **never read from the
     token's own header**, which is what prevents an algorithm-confusion attack
     (e.g. a token claiming `alg: HS256` signed with a guessable or public
     value). See "Algorithm selection" below for how that set is resolved.
5. Check the claim named by `matchClaim` against the issuer's `allow` list
   (case-insensitive by default).
6. On success: render `usernameTemplate`/`groupTemplates` against the verified
   claims to build `{ name, groups, real_groups }` -- the same shape Verdaccio's
   own internals produce for a logged-in user (`groups` includes `real_groups`
   plus the built-in `$all`/`$authenticated`) -- store it in the result cache
   (skipped on a cache hit, since it's already there), and overwrite
   `req.remote_user`/`res.locals.remote_user` with it.
7. On failure (bad signature, expired, wrong audience, claim not allow-listed,
   JWKS endpoint unreachable): responds `401` directly, **rather than falling
   through to anonymous**. A token that presents itself as CI auth but doesn't
   check out should fail loudly, not silently downgrade to whatever anonymous
   access happens to be configured.

## Discovery and key caching

There are two independent caching layers, and they refresh for different
reasons:

- **jose's own key cache** (inside `createRemoteJWKSet`, one instance per
  issuer, bound to a single `jwks_uri`): reuses fetched keys for up to 10
  minutes, and -- if a token shows up with a `kid` the cached set doesn't
  recognize (ordinary key rotation at a _fixed_ location) -- refetches that same
  URL, rate-limited to once per 30 seconds. This needs no code on our part; it's
  `jose`'s built-in behavior.
- **Our own discovery cache** (`TrustedIssuer._jwks`): the resolved `jwks_uri`
  itself -- and the `createRemoteJWKSet` bound to it -- is normally cached for
  the life of the process, resolved lazily on the first request that matches
  that issuer. This is _not_ the same thing as key rotation: it's "what if the
  provider's discovery document starts pointing somewhere else entirely" (an
  infra migration on their end), which jose's per-URL cache has no way to detect
  on its own since it never revisits the discovery document.

To handle that second case, `verify()` retries once on failure: if `jwtVerify()`
fails with a code indicating the _key couldn't be resolved_
(`ERR_JWKS_NO_MATCHING_KEY`, `ERR_JWKS_TIMEOUT`, `ERR_JWKS_INVALID`, or a raw
network error) -- as opposed to a code indicating the token itself is bad
against a correctly-resolved key (expired, wrong audience, bad signature,
disallowed `alg`, not on the allow list) -- it re-runs OIDC discovery from
scratch, builds a fresh `createRemoteJWKSet` against whatever `jwks_uri`
discovery now returns, and retries verification exactly once before giving up.
The token-is-bad codes are never retried: re-discovering wouldn't fix a forged
signature or an expired token, and retrying on them would let anyone who knows a
trusted issuer's name spam garbage tokens to force repeated discovery calls.

That retry is itself rate-limited by `discoveryCooldownSeconds` (default 30,
matching jose's own default), tracked per issuer. A fresh `createRemoteJWKSet`
has no cooldown memory of its own, so without this our own retry logic would
otherwise let a burst of bad tokens force unbounded re-discovery -- this
cooldown is what keeps that bounded to roughly once per window, independent of
jose's per-URL cooldown underneath it.

## Algorithm selection

`SAFE_ALGS` in the code is a hardcoded, non-configurable ceiling -- the complete
set of signature algorithms this plugin will ever ask `jose` to verify against,
regardless of what any config or discovery document says:
`RS256`/`RS384`/`RS512`, `PS256`/`PS384`/`PS512`, `ES256`/`ES384`/`ES512`,
`EdDSA`. Deliberately asymmetric-only -- a JWKS endpoint publishes _public_
keys, so a legitimate issuer has no reason to ever sign a token verifiable as
`HS*` over that same JWKS; an `HS*`-"signed" token can only mean someone is
attempting the classic RSA/EC-public-key-reused-as-HMAC-secret confusion attack.
`none` is excluded for the same reason.

Per issuer, the algorithm(s) actually accepted are resolved in this order:

1. **`algorithms:` set explicitly in that issuer's config** -- validated against
   `SAFE_ALGS` at startup; the plugin throws if it names anything outside that
   set. Wins outright over everything below.
2. **`jwks_uri` set explicitly** (discovery bypassed for key lookup) **and no
   `algorithms` config** -- defaults to `[RS256]`. Discovery is never fetched
   just to learn algorithms when it's already being bypassed for keys.
3. **Otherwise** -- read from the issuer's own OIDC discovery document
   (`id_token_signing_alg_values_supported`), filtered through `SAFE_ALGS`. This
   is _not_ the same as trusting discovery outright: a discovery document
   describes the issuer's entire capability surface (e.g. algorithms it might
   support elsewhere for confidential clients using a shared secret), not
   specifically what's safe for verifying a bearer ID token here -- so nothing
   it advertises can ever add an algorithm outside `SAFE_ALGS`. It can only
   narrow which of the already-safe algorithms this specific issuer uses.
4. **Falls back to `[RS256]`** if that field is absent, malformed, or nothing in
   it survives the `SAFE_ALGS` filter (e.g. an issuer that only advertises
   `HS256`).

The discovery-derived result is cached and refreshed in lockstep with the JWKS
lookup itself (same `forceRefresh`, same discovery cooldown) -- it comes from
the same discovery document, so there's no reason for it to have an independent
cache lifetime of its own.

An issuer's discovery-derived algorithm set can legitimately change over time
(e.g. the issuer rotates to a new key type) with zero warning from the provider
-- logged at `warn`
(`oidc-auth: issuer ... trusted signing algorithms resolved via OIDC discovery: ...`)
once per distinct result, so an operator has something to grep for if behavior
shifts. This is pure observability, not enforcement: `SAFE_ALGS` is what
enforces, and it holds regardless of whether anyone reads that log line -- an
issuer's discovery document can change unilaterally at any time no matter what
we've recorded about it, so tracking history here wouldn't add any actual
security value.

## Result cache

Everything above (discovery, JWKS fetch, signature verification, claims checks,
allow-list check) is about resolving _one specific token_. A single CI job is
not one request, though -- a typical `npm publish` alone means several requests
(package metadata fetch, tarball upload, `whoami`), and the OIDC ID token in
`.npmrc`'s `_authToken` is identical on every one of them. Re-running full
cryptographic verification on every request for a token we already fully
validated moments ago is pure waste, so successful results are cached and looked
up by a SHA-512 hash of the raw token (`Map< hash, { remoteUser, expiresAt }>`,
one instance shared across all issuers). SHA-512 over the more obvious SHA-256
because it operates on 64-bit words -- typically faster on modern hardware
despite the larger digest -- and there's no reason to prefer the smaller/slower
hash for a key that's never exposed outside this process.

**Why a cache hit needs no revalidation, not just "less" revalidation**: a JWT's
payload is exactly the bytes that were signed. Two requests bearing
byte-identical token strings are, by construction, bearing identical
`iss`/`aud`/`exp`/`repository`/every other claim and an already-proven-valid
signature over those exact bytes -- none of that can have silently changed out
from under us. The only fact that can change between "when we verified this" and
"now" is the current time. So a cache hit does exactly one thing: compare
`Date.now()` against the stored expiry. Nothing is decoded, no signature is
checked, no allow-list is consulted -- there is nothing left that a second check
could tell us that the first one didn't already prove for this exact byte
sequence.

**Never held past the token's own `exp`, regardless of the configured TTL.** On
a successful verify, the cache entry's expiry is
`min(now + jwtCacheTtlSeconds, token's own exp)` -- so a short-lived CI token
(GitHub/Bitbucket ID tokens are typically valid for minutes) is never kept
"valid" by our cache for longer than the issuer itself said it should be, even
if `jwtCacheTtlSeconds` is configured much higher. `exp` is required on every
token (`requiredClaims: ['exp']` in the verify options) specifically so this
bound always has something to work with.

**Bounded size, LRU eviction.** `jwtCacheMaxEntries` (default 1000) caps the
map; once full, inserting a new entry evicts whichever cached token has gone
longest without being seen again (tracked via `Map` insertion order -- a hit
deletes-and-re-inserts its entry to move it to the recently-used end, so
eviction always drops the coldest entry, not just the oldest).

**Keyed by a hash, not the raw token**, so a live bearer credential isn't held
verbatim in memory for the cache's TTL -- only its SHA-512 digest is, which
isn't reversible back into something a request could replay with.

**Known tradeoff**: revoking a specific already-issued, already-cached token
mid-incident (e.g. "this CI run is compromised, kill it now") can't be done by
editing `allow:` alone while the process keeps running -- the cached positive
result stays honored until it naturally expires. This isn't new exposure
specifically from caching, though: most Verdaccio config changes already require
a restart to take effect at all, and a restart clears this in-memory cache along
with everything else. Given OIDC ID tokens are already short-lived by nature,
the realistic window this adds is small, but it's worth knowing the cache
doesn't shrink that window to zero on its own.

## Security properties / known limitations

- **No secrets required** -- verification uses each platform's public JWKS, so
  this plugin needs no client secret, private key, or stored credential on your
  side.
- **Fails closed on JWKS unavailability** for a matched issuer, after one
  self-healing retry (re-run discovery, rebuild the key set, try once more --
  see "Discovery and key caching" above). If the provider is genuinely
  unreachable, or truly did stop serving the key that signed the token, the
  request is rejected rather than falling through to anonymous.
- **No replay protection.** OIDC ID tokens have no built-in single-use
  enforcement; a leaked token is valid until its (short, platform-issued) `exp`.
  Accepted as a residual risk for now -- no `jti` tracking is implemented.
- **Case-insensitive claim matching** by default, so GitHub org/repo casing
  variations and Bitbucket UUID casing don't cause spurious mismatches.
- **Never logs raw tokens or full claim sets** -- only `{issuer, user}` on
  success or `{issuer, err}` on failure, at `warn`.

## Testing

There's no test framework here, but this plugin does signature verification with
no other safety net, so it ships one manual, dependency-free smoke test:

```bash
node test/smoke.js
```

It spins up a pool of throwaway RSA keypairs and a local fake OIDC issuer
(discovery + JWKS endpoints), then asserts: a valid token is accepted and mapped
correctly; an expired token, a wrong-audience token, a non-allow-listed claim,
and a non-RS256-signed token are all rejected; an unreachable JWKS endpoint
fails closed; a simulated provider-side JWKS location change is recovered from
via one discovery-refresh-and-retry; the discovery-refresh cooldown both blocks
a second refresh immediately after the first and allows one again once the
cooldown window elapses; a second request with the same token is served from the
result cache without `verify()` being called again (proven by spying on the call
count, not just by the response looking right); a cached result is rejected once
the token's own `exp` passes even under a much longer configured TTL; and the
cache evicts its least-recently-used entry once `jwtCacheMaxEntries` is
exceeded. It also covers algorithm selection: an explicit `algorithms` config
naming an unsupported algorithm throws at construction; an explicit `algorithms`
config is enforced strictly rather than merged with the default (an RS256-signed
token is rejected when an issuer is pinned to `[ES256]`); and a discovery
document advertising only unsafe algorithms (`HS256`, `none`) still results in a
working issuer, since that falls back to `RS256`. Run this after any change to
`index.js` before relying on a real CI run to catch a regression.

## Dependencies

`jose` -- the only JWT/JWKS/OIDC library in this plugin. Loaded via dynamic
`import()` (it's ESM-only) rather than `require()`, so it works from this
plugin's CommonJS `index.js` on any modern Node version.
