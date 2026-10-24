# Configuration reference

The [README](../README.md) covers installation and a quick-start config. This
page covers the rest.

## Why this is a `middlewares` plugin, not an `auth` plugin

Verdaccio's core auth middleware, `auth.apiJWTmiddleware()`, runs before any
`middlewares` plugin and always sets `req.remote_user`. For a `Bearer` token it
tries to verify a session token Verdaccio itself issued. When that fails for any
reason, including a token GitHub or Bitbucket signed, it does not reject the
request. It sets `$anonymous` and calls `next()`.
`@fortmesa/verdaccio-generic-oidc`, which replaces that middleware, does the
same for any Bearer token that carries an `iss` claim.

So a `middlewares` plugin registered after it can safely do one of two things.
For a token that isn't from a trusted issuer it does nothing, and whatever core
auth decided stands. For a token from a trusted issuer it verifies the token
itself and overwrites `req.remote_user` before the ACL and route logic run.

An `auth:` plugin could implement `apiJWTmiddleware(helpers)` instead and
replace Verdaccio's Bearer and Basic handling for every request. That would mean
re-implementing Verdaccio's own token verification and its Basic-auth handoff to
`authenticate()`, internal logic that isn't part of the public plugin API. As a
`middlewares` plugin this one only adds to what is there.

The consequence is ordering. List this plugin under `middlewares:` before any
other middleware that reads `req.remote_user`, or those see the anonymous
fallback instead of the CI identity.

## Full config

```yaml
middlewares:
  '@fortmesa/verdaccio-oidc-auth':
    clockToleranceSeconds: 30 # default 30, allowed clock drift on exp/nbf
    discoveryCooldownSeconds: 30 # default 30, see "Discovery and key caching"
    jwtCacheTtlSeconds: 300 # default 300, see "Result cache"
    jwtCacheMaxEntries: 1000 # default 1000, see "Result cache"
    issuers:
      - id: github-actions # free-form label, used in logs and errors
        issuer: https://token.actions.githubusercontent.com # must equal the token's iss
        audience: https://your-registry.example.com # must match the token's aud
        # algorithms: [RS256] # optional, see "Algorithm selection"
        # jwksUri: https://... # optional, skips discovery for key lookup
        usernameTemplate: 'gha:{repository}' # {claim} comes from the verified token
        groupTemplates:
          - 'gha:{repository}'
          - 'gha-org:{repository_owner}'
        matchClaim: repository # the claim every allow entry must name
        matchCaseInsensitive: true # default true
        allow:
          - repository: your-org/your-repo
            sub: 'repo:your-org/your-repo:environment:npmjs'
          - repository: your-org/service-*
            sub:
              - 'repo:your-org/service-*:environment:npmjs'
              - 'repo:your-org/service-*:ref:refs/tags/v*'
      - id: bitbucket-pipelines
        issuer: https://api.bitbucket.org/2.0/workspaces/your-workspace/pipelines-config/identity/oidc
        audience: 'ari:cloud:bitbucket::workspace/<workspace-uuid>'
        usernameTemplate: 'bb:{repositoryUuid}'
        groupTemplates:
          - 'bb:{repositoryUuid}'
          - 'bb-workspace:{workspaceUuid}'
        matchClaim: repositoryUuid
        allow:
          # Bitbucket claims are UUIDs, not slugs. Look one up once with
          # GET /2.0/repositories/{workspace}/{repo_slug}.
          - repositoryUuid: '<repo-uuid>'
```

Each `issuers[]` entry is independent.

## Startup checks

The plugin refuses to start, with an error naming the issuer and the problem,
when:

- an issuer has no `id`, or an empty one;
- `issuer` is not an absolute `http:` or `https:` URL;
- `audience` is missing, empty, or a list that is empty or holds anything but
  non-empty strings. Without an audience jose would skip the `aud` check, and
  the issuer's tokens minted for any other audience would be accepted;
- `matchClaim` is missing or empty;
- `usernameTemplate` or a `groupTemplates` entry is missing or empty,
  `groupTemplates` is not a list, or a template has a `{` or `}` outside a
  `{claimName}` placeholder. A claim name is letters, digits and `_`;
- `allow` is missing or empty, an entry is not a map of claim names to patterns,
  an entry has no key for `matchClaim`, or a value is not a non-empty string or
  a non-empty list of them;
- `algorithms` names anything outside the supported set, see
  [Algorithm selection](#algorithm-selection);
- two issuers share an `issuer` URL;
- `jwtCacheTtlSeconds` is not a number of 0 or more, or `jwtCacheMaxEntries` is
  not a whole number of 0 or more.

## Matching `allow:` entries

A token is allowed when any one entry matches. An entry matches when every key
in it matches the claim of the same name. Each value is a pattern or a list of
patterns, and a list matches when any one of its patterns does. A claim that is
missing, or isn't a string, fails its key.

The key named by `matchClaim` is required in every entry. Any other key narrows
that entry. Existing single-key entries behave as before, and adding keys to an
entry only ever makes it stricter.

Patterns have two wildcards and nothing else:

- `*` matches any run of characters except `/` and `:`;
- `**` matches anything, crossing both.

Every other character is literal. A leading `!` is not a negation, and braces,
brackets, `?` and `+(...)` match themselves. Before matching, the plugin turns
every `:` into a `/` in both the pattern and the claim, so `*` stops at either.
A claim value is not a package name, and `matchClaim` can be any claim an issuer
sends. GitHub uses `/`, a `sub` uses `:`, and Bitbucket uses neither.
`your-org/service-*` matches `your-org/service-a` and not
`your-org/service-a/nested`. `repo:your-org/*:environment:npmjs` matches one
repository's publish environment and not `...:environment:npmjs:extra`.

Matching ignores case unless `matchCaseInsensitive` is `false`.

## Telling the publish job apart

Every job in a GitHub Actions workflow run gets a token with the same
`repository` claim. A release workflow's install job runs `yarn install` with
`id-token: write`. A compromised dependency's install script there could request
a token for the registry's audience, since the job picks the audience. An entry
that matches `repository` alone would accept that token as a publish credential.

GitHub's `sub` claim is what differs. A job that declares `environment: <name>`
gets `sub: repo:<org>/<repo>:environment:<name>`. GitHub sets that itself, and
it carries no branch or tag. A job without an environment gets
`repo:<org>/<repo>:ref:<ref>`. So the publish job runs in its own environment,
here `npmjs`, and the entry pins it:

```yaml
allow:
  - repository: fortmesa/verdaccio-oidc-auth
    sub: 'repo:fortmesa/verdaccio-oidc-auth:environment:npmjs'
```

The install job's token carries `...:environment:install`, a job outside any
environment carries a `:ref:` sub, and neither matches. Give the environment a
deployment rule for `v*.*.*` tags so only a release run gets into it.

Roll it out in this order:

1. Release and deploy a plugin version that reads every key of an entry.
2. Add `environment: npmjs` to each repository's publish job and create the
   GitHub environment.
3. Add the `sub` pins to the registry config.

The config change has to come last. Pins on a registry whose publish jobs don't
run in the environment yet make every publish answer 401.

## Identities

On success the plugin renders `usernameTemplate` and each `groupTemplates` entry
against the verified claims and builds `{name, groups, real_groups}`, the shape
Verdaccio's own `createRemoteUser` produces. `real_groups` holds the rendered
groups, without duplicates. `groups` adds Verdaccio's logged-in defaults:
`$all`, `$authenticated`, `@all`, `@authenticated` and `all`.

A placeholder's claim must be a string or a number. A token that lacks the
claim, or carries an object or array there, fails with a 401 and the code
`OIDC_TEMPLATE_CLAIM_MISSING` in the log. That way a missing claim never renders
as an empty string or `[object Object]`.

With `matchCaseInsensitive` on, claim values render in lower case. Verdaccio
compares ACL entries exactly, so a token the allow list accepted as
`FortMesa/Example` gets `gha:fortmesa/example`, matching a lower-case ACL entry.
The template's literal text keeps its case. With `matchCaseInsensitive: false`,
claims render as the token sends them.

Verdaccio matches a `packages:` access or publish entry against the user name
and against every group (`name === group || groups.includes(group)` in
`@verdaccio/auth`). A rendered identity equal to an existing user name or group
name gets that user's or group's access. The `gha:`, `gha-org:` and `bb:`
prefixes in the examples keep CI identities apart from `htpasswd` names, which
cannot contain `:`.

## How verification works per request

1. No `Authorization: Bearer` header: the plugin calls `next()` and changes
   nothing.
2. The plugin looks the token up in the result cache. On a hit it sets
   `req.remote_user` and `res.locals.remote_user` to a copy of the cached
   identity and calls `next()`.
3. Otherwise it reads `iss` from the token's payload without verifying anything.
   If the payload is unreadable or `iss` names no configured issuer, it calls
   `next()` and changes nothing. The token may be one of Verdaccio's own, or
   garbage, and either way it's core auth's to judge.
4. It pauses the request (see [Request bodies](#request-bodies)) and runs
   [`jose`](https://github.com/panva/jose)'s `jwtVerify()` against that issuer's
   JWKS. That checks the signature, an exact `iss` and `aud`, that `exp` is
   present, `exp` and `nbf` within `clockToleranceSeconds`, and that `alg` is in
   the issuer's resolved set. The plugin never takes `alg` from the token's
   header, which is what stops an algorithm-confusion attack such as a token
   claiming `HS256`.
5. It checks the claims against `allow`.
6. It renders the identity, stores it in the result cache, sets
   `req.remote_user` and `res.locals.remote_user`, resumes the request and calls
   `next()`.
7. Any failure in steps 4 to 6 resumes the request and answers `401` with
   `{"error": "unauthorized", "reason": "oidc token verification failed"}`. That
   covers a bad signature, an expiry, a wrong audience, a disallowed claim, a
   missing template claim and an unreachable JWKS or discovery endpoint. A token
   presented as CI auth that doesn't check out fails loudly instead of dropping
   to whatever anonymous access the registry allows.

## Request bodies

Verdaccio's access log calls `req.on('data')` on every request to count bytes
(verdaccio/verdaccio#1912). That starts the body flowing at once. Verifying a
token that isn't cached yet takes a network round trip or two, and an unpaused
body would stream past before any parser was listening.

The plugin calls `req.pause()` before that verification and `req.resume()` right
before `next()` or the 401. Verdaccio's own `apiJWTmiddleware` does the same
around its asynchronous auth. The plugin never reads the body, so Verdaccio's
parsers do, with `max_body_size` and their own content-type and error handling.
A cache hit or a request without a trusted issuer's token is never paused.

This works in both middleware orders Verdaccio 6 uses. 6.7.4 parses JSON inside
its endpoint router, after the plugins. 6.10.6 parses it before the plugins run,
so by then the body is already read and the pause has no effect. Plugin versions
before 1.1.0 read PUT JSON bodies themselves. That read hung every JSON PUT on
6.10.6 and skipped `max_body_size` on 6.7.4.

## Discovery and key caching

There are two caches, and they refresh for different reasons.

jose's key cache lives inside `createRemoteJWKSet`, one per issuer, bound to one
`jwks_uri`. It reuses fetched keys for up to 10 minutes. When a token arrives
with a `kid` the cached set lacks, which is ordinary key rotation at a fixed
URL, jose refetches that URL at most once per 30 seconds. jose does not follow
redirects for the JWKS fetch and requires a 200.

The plugin caches the `jwks_uri` itself, and the key set bound to it, for the
life of the process. It resolves it on the first request for that issuer by
fetching `{issuer}/.well-known/openid-configuration` with a 5 second timeout.
The plugin refuses the document when:

- the answer is not HTTP 200. Redirects are not followed, so a 3xx counts;
- its `issuer` is not exactly the configured `issuer`, as OpenID Connect
  Discovery requires;
- it has no `jwks_uri`.

A configured `jwksUri` skips discovery.

A provider can also move its JWKS to a new URL, which jose's per-URL cache can't
see. So when `jwtVerify()` fails with a code that means the key couldn't be
resolved, such as `ERR_JWKS_NO_MATCHING_KEY`, `ERR_JWKS_TIMEOUT`, a non-200 JWKS
answer or a network error, the plugin re-runs discovery and retries verification
once. Codes that mean the token itself is bad are never retried: expired, wrong
claims, bad signature, disallowed `alg`, malformed. Re-discovery can't fix
those, and retrying them would let anyone spam garbage tokens to force discovery
calls.

Re-discovery is limited to once per `discoveryCooldownSeconds` per issuer,
default 30, matching jose's own cooldown. A fresh key set has no cooldown memory
of its own, and this keeps a burst of bad tokens from forcing unbounded
re-discovery. A request that fails while another request's re-discovery is still
running waits for that one and retries with its result instead of being refused
by the cooldown, so concurrent requests share one discovery.

## Algorithm selection

`SAFE_ALGS` in the code is a fixed ceiling, the full set of signature algorithms
the plugin will ever ask jose to accept, whatever a config or discovery document
says: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`,
`ES512` and `EdDSA`. All are asymmetric. A JWKS endpoint publishes public keys,
so an `HS*` token checked against it can only be the attack that reuses a public
key as an HMAC secret. `none` is out for the same reason.

For each issuer the accepted set is the first of these that applies:

1. `algorithms` in the issuer's config, checked against `SAFE_ALGS` at startup.
2. With `jwksUri` set and no `algorithms`, `[RS256]`. Discovery is never fetched
   only to learn algorithms.
3. The discovery document's `id_token_signing_alg_values_supported`, filtered
   through `SAFE_ALGS`. That list describes everything the issuer supports,
   including shared-secret algorithms for confidential clients, so it can only
   narrow the safe set and never add to it.
4. `[RS256]`, when that field is absent, malformed or has nothing safe in it.

The discovery-derived set refreshes with the JWKS lookup, since both come from
the same document. The plugin logs each distinct result once, at `debug`:
`oidc-auth: issuer ... trusted signing algorithms resolved via OIDC discovery: ...`.
That line is for an operator grepping after behavior shifts. `SAFE_ALGS` does
the enforcing whether or not anyone reads it.

## Result cache

A CI job sends the same token on many requests. `npm publish` alone fetches
metadata, uploads and runs `whoami`. The plugin caches each successful result,
keyed by a SHA-512 hash of the token, in one map shared by all issuers. The
token itself is never stored.

A hit needs no re-check beyond the clock. A JWT's payload is exactly the signed
bytes, so a byte-identical token carries the same claims and the same
already-proven signature. The only thing that changes between the first
verification and a later request is the time, so a hit compares `Date.now()`
with the entry's expiry and nothing else.

An entry never outlives the token. Its expiry is
`min(now + jwtCacheTtlSeconds, the token's exp)`, and the plugin requires `exp`
on every token so this bound always exists. `jwtCacheTtlSeconds: 0` caches
nothing.

`jwtCacheMaxEntries` caps the map. When it's full, a new entry evicts the one
that has gone longest without a hit, since a hit moves its entry to the
recently-used end. `jwtCacheMaxEntries: 0` turns the cache off.

The cache stores a copy of the identity and hands out a copy on every hit.
Verdaccio's middlewares write to `req.remote_user`, its `error` field for one,
and a write on one request must not change what later requests with the same
token get.

One tradeoff: editing `allow:` doesn't revoke a token that is already cached
until the entry expires or the process restarts. Most Verdaccio config changes
need a restart anyway, and a restart clears the cache. CI tokens live for
minutes, so the window is short, but the cache does not make it zero.

## Logging

- `info` `oidc-auth: authenticated CI identity`, with `{issuer, user}`, on each
  verification. Cache hits don't log.
- `warn` `oidc-auth: rejected token for trusted issuer`, with `{issuer, err}`,
  where `err` is the error's code, name or message.
- `debug` when the algorithm set resolves or changes, and when a failure
  triggers re-discovery.

The plugin never logs a token or a full claim set.

## Security properties and known limitations

- The plugin needs no secret. Verification uses each platform's public JWKS, so
  there is no client secret, private key or stored credential on your side.
- It fails closed. After the one self-healing retry, an unreachable provider or
  a key it stopped serving gets a 401, never anonymous access.
- There is no replay protection. OIDC ID tokens aren't single-use, so a leaked
  token works until its `exp`. The plugin keeps no `jti` record.
- Claim matching ignores case by default, so casing differences in GitHub org
  and repo names, or in Bitbucket UUIDs, don't cause mismatches. Identities
  render in lower case to match.
- The plugin buffers no request body, see [Request bodies](#request-bodies).

## Testing

`yarn test` runs both test files. Neither uses a test framework.

`test/smoke.js` starts a pool of throwaway RSA keys and a local fake OIDC
issuer, then drives `TrustedIssuer` and the middleware handler directly. Every
rejection test checks the error code or message, so a test can't pass for the
wrong reason. It covers:

- tokens: valid, expired, wrong audience, signed by an unpublished key, `HS256`;
- discovery: unreachable, an explicit `jwksUri`, an issuer mismatch, a redirect;
- algorithm config, and discovery advertising only unsafe algorithms;
- allow syntax: wildcards, `/` and `:` stops, literal metacharacters, case,
  multi-key entries with a `sub` pin, pattern lists;
- template claims that are missing, objects or numbers;
- every startup check;
- re-discovery after a JWKS move, its cooldown, and concurrent requests sharing
  one discovery;
- the result cache: hits, copies, the `exp` bound, LRU eviction and the 0
  settings;
- pause and resume around verification, and pass-through of requests that aren't
  the plugin's;
- JSON PUT and POST bodies and malformed JSON through Express, in both the 6.7.4
  and the 6.10.6 middleware order.

`test/verdaccio.js` runs the plugin inside a real Verdaccio with API tokens
signed as JWTs, as the deployed registry has them, and a fake GitHub-like
issuer. A CI token's first request is a JSON PUT publish of a 96 KiB tarball.
The test then publishes again from the cache, adds a dist-tag and reads it all
back. It checks that the install job's token, a forged token and an expired one
get 401, that Verdaccio's own publish rules still bind an allowed CI identity,
and that Verdaccio's own tokens and anonymous requests pass through.
`VERDACCIO_BIN` points it at another Verdaccio build, such as the one fm-npmjs
deploys.
