'use strict';

// Manual smoke test -- this repo has no test framework/build step for its
// plugins, but signature-verification code has no other safety net. Run with:
//   node verdaccio-oidc-auth/test/smoke.js
// Spins up a throwaway RSA keypair + a local fake OIDC issuer (discovery +
// JWKS endpoints) and exercises the accept/reject paths against it.

const http = require('node:http');
const assert = require('node:assert/strict');
const {TrustedIssuer, OidcAuthMiddleware} = require('../index.js');

const NOOP_LOGGER = {warn() {}, error() {}, info() {}, debug() {}};
const AUDIENCE = 'https://npmjs.dev.fort.blue';

async function startMockIssuer() {
  const jose = await import('jose');

  async function generateSigningKey() {
    const {publicKey, privateKey} = await jose.generateKeyPair('RS256');
    const jwk = await jose.exportJWK(publicKey);
    jwk.kid = await jose.calculateJwkThumbprint(jwk);
    jwk.alg = 'RS256';
    jwk.use = 'sig';
    return {jwk, privateKey};
  }

  // Keys are served at a version-numbered path (/jwks-v0, /jwks-v1, ...) and
  // discovery always points at whichever version is "current" -- rotate()
  // simulates a provider moving its JWKS to a new location, not just
  // rotating which keys live at a fixed URL (jose already handles that case
  // on its own; these tests are specifically for the location-change case).
  // The pool is pre-generated so rotate() is instant -- RSA keygen is slow
  // enough (often tens of ms) to blow past the short cooldowns the tests
  // below assert around if it ran inline during a timing-sensitive check.
  const keyPool = await Promise.all(
    Array.from({length: 6}, generateSigningKey),
  );
  const keysByVersion = new Map([[0, keyPool[0]]]);
  let currentVersion = 0;
  let nextPoolIndex = 1;
  let issuer;
  // undefined by default -- discovery response omits
  // id_token_signing_alg_values_supported entirely, same as a real provider
  // that doesn't publish it. Tests can override via setAdvertisedAlgs().
  let advertisedAlgs;

  function rotate() {
    currentVersion += 1;
    keysByVersion.set(currentVersion, keyPool[nextPoolIndex]);
    nextPoolIndex += 1;
  }

  function setAdvertisedAlgs(algs) {
    advertisedAlgs = algs;
  }

  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    const versionMatch = req.url.match(/^\/jwks-v(\d+)$/);
    if (req.url === '/.well-known/openid-configuration') {
      const doc = {issuer, jwks_uri: `${issuer}/jwks-v${currentVersion}`};
      if (advertisedAlgs)
        doc.id_token_signing_alg_values_supported = advertisedAlgs;
      res.end(JSON.stringify(doc));
    } else if (versionMatch) {
      const entry = keysByVersion.get(Number(versionMatch[1]));
      if (!entry) {
        res.statusCode = 404;
        return res.end('{}');
      }
      res.end(JSON.stringify({keys: [entry.jwk]}));
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  issuer = `http://127.0.0.1:${server.address().port}`;

  async function sign(
    claims,
    {alg = 'RS256', expiresIn = '5m', audience = AUDIENCE} = {},
  ) {
    const {jwk, privateKey} = keysByVersion.get(currentVersion);
    return new jose.SignJWT(claims)
      .setProtectedHeader({alg, kid: jwk.kid})
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .sign(privateKey);
  }

  return {jose, server, issuer, sign, rotate, setAdvertisedAlgs};
}

function issuerConfig(issuerUrl, overrides = {}) {
  return {
    id: 'mock-ci',
    issuer: issuerUrl,
    audience: AUDIENCE,
    usernameTemplate: 'ci:{repository}',
    groupTemplates: ['ci:{repository}'],
    matchClaim: 'repository',
    allow: [{repository: 'fortmesa/example'}],
    ...overrides,
  };
}

function makeIssuer(
  issuerUrl,
  cfgOverrides = {},
  {discoveryCooldownSeconds = 30} = {},
) {
  return new TrustedIssuer(issuerConfig(issuerUrl, cfgOverrides), {
    clockToleranceSeconds: 30,
    discoveryCooldownSeconds,
    logger: NOOP_LOGGER,
  });
}

function makeMiddleware(issuerUrl, configOverrides = {}) {
  return new OidcAuthMiddleware(
    {
      discoveryCooldownSeconds: 30,
      jwtCacheTtlSeconds: 300,
      jwtCacheMaxEntries: 1000,
      issuers: [issuerConfig(issuerUrl)],
      ...configOverrides,
    },
    {logger: NOOP_LOGGER},
  );
}

// register_middlewares() just does app.use(handler) -- capture that handler so
// tests can drive it directly without a real Express app.
function captureHandler(middleware) {
  let handler;
  middleware.register_middlewares({use: fn => (handler = fn)}, null, null);
  return handler;
}

// Same idea, but keeps every app.use() call in registration order --
// register_middlewares() now registers two: the body-buffering middleware
// (workaround for verdaccio/verdaccio#1912) first, then the existing
// auth-check one.
function captureHandlers(middleware) {
  const handlers = [];
  middleware.register_middlewares({use: fn => handlers.push(fn)}, null, null);
  return handlers;
}

// A minimal real Readable so req.on('data'/'end') behaves like an actual
// stream -- a plain object (like runHandler's fake req above) doesn't
// support that, and the body-buffering middleware needs genuine stream
// semantics to be tested meaningfully.
function makeStreamingReq({method, headers, body}) {
  const {Readable} = require('node:stream');
  const req = new Readable({
    read() {},
  });
  req.method = method;
  req.headers = headers;
  process.nextTick(() => {
    if (body !== undefined) req.push(body);
    req.push(null);
  });
  return req;
}

function runHandler(handler, token) {
  return new Promise((resolve, reject) => {
    const req = {headers: token ? {authorization: `Bearer ${token}`} : {}};
    const res = {
      locals: {},
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(body) {
        resolve({req, res: this, rejected: true, body});
      },
    };
    const next = err =>
      err ? reject(err) : resolve({req, res, rejected: false});
    handler(req, res, next);
  });
}

async function main() {
  const {jose, server, issuer, sign, rotate, setAdvertisedAlgs} =
    await startMockIssuer();
  let passed = 0;

  async function check(name, fn) {
    try {
      await fn();
      passed++;
      console.log(`PASS: ${name}`);
    } catch (err) {
      console.error(`FAIL: ${name}`);
      console.error(err);
      process.exitCode = 1;
    }
  }

  try {
    const trustedIssuer = makeIssuer(issuer);

    await check(
      'valid token is accepted and mapped to the right identity',
      async () => {
        const token = await sign({repository: 'fortmesa/example'});
        const {remoteUser} = await trustedIssuer.verify(token);
        assert.equal(remoteUser.name, 'ci:fortmesa/example');
        assert.ok(remoteUser.real_groups.includes('ci:fortmesa/example'));
        assert.ok(remoteUser.groups.includes('$authenticated'));
      },
    );

    await check('expired token is rejected', async () => {
      const token = await sign(
        {repository: 'fortmesa/example'},
        {expiresIn: '-1m'},
      );
      await assert.rejects(() => trustedIssuer.verify(token));
    });

    await check('wrong audience is rejected', async () => {
      const token = await sign(
        {repository: 'fortmesa/example'},
        {audience: 'https://someone-else.example'},
      );
      await assert.rejects(() => trustedIssuer.verify(token));
    });

    await check('claim not on the allow list is rejected', async () => {
      const token = await sign({repository: 'someone-else/not-allowed'});
      await assert.rejects(
        () => trustedIssuer.verify(token),
        err => err.code === 'OIDC_NOT_ALLOWED',
      );
    });

    await check(
      'allow: entries are real minimatch globs -- a trailing "*" matches a same-scope repo',
      async () => {
        const wildcardIssuer = makeIssuer(issuer, {
          allow: [{repository: 'fortmesa/*'}],
        });
        const token = await sign({
          repository: 'fortmesa/verdaccio-attestations',
        });
        const {remoteUser} = await wildcardIssuer.verify(token);
        assert.equal(remoteUser.name, 'ci:fortmesa/verdaccio-attestations');
      },
    );

    await check(
      'a "*" does not cross a "/" -- "fortmesa/*" does not match a nested path',
      async () => {
        const wildcardIssuer = makeIssuer(issuer, {
          allow: [{repository: 'fortmesa/*'}],
        });
        const token = await sign({repository: 'fortmesa/deep/nested'});
        await assert.rejects(
          () => wildcardIssuer.verify(token),
          err => err.code === 'OIDC_NOT_ALLOWED',
        );
      },
    );

    await check(
      'a "*" also does not cross a ":" -- claims are free-form, not always "/"-delimited',
      async () => {
        const colonIssuer = makeIssuer(issuer, {
          matchClaim: 'team',
          usernameTemplate: 'ci:{team}',
          allow: [{team: 'fortmesa:*'}],
        });
        const matching = await sign({team: 'fortmesa:platform'});
        const {remoteUser} = await colonIssuer.verify(matching);
        assert.equal(remoteUser.name, 'ci:fortmesa:platform');

        const nested = await sign({team: 'fortmesa:platform:prod'});
        await assert.rejects(
          () => colonIssuer.verify(nested),
          err => err.code === 'OIDC_NOT_ALLOWED',
        );
      },
    );

    await check(
      '"**" matches every repo, crossing both "/" and ":"',
      async () => {
        const everythingIssuer = makeIssuer(issuer, {
          allow: [{repository: '**'}],
        });
        const token = await sign({repository: 'anyone/anything'});
        const {remoteUser} = await everythingIssuer.verify(token);
        assert.equal(remoteUser.name, 'ci:anyone/anything');
      },
    );

    await check(
      'matching is case-insensitive by default, same as before minimatch',
      async () => {
        const token = await sign({repository: 'FortMesa/Example'});
        const {remoteUser} = await trustedIssuer.verify(token);
        assert.equal(remoteUser.name, 'ci:FortMesa/Example');
      },
    );

    await check(
      'matchCaseInsensitive: false makes matching case-sensitive',
      async () => {
        const caseSensitiveIssuer = makeIssuer(issuer, {
          matchCaseInsensitive: false,
        });
        const token = await sign({repository: 'FortMesa/Example'});
        await assert.rejects(
          () => caseSensitiveIssuer.verify(token),
          err => err.code === 'OIDC_NOT_ALLOWED',
        );
      },
    );

    await check(
      'a missing/non-string claim value fails closed instead of throwing',
      async () => {
        const token = await sign({});
        await assert.rejects(
          () => trustedIssuer.verify(token),
          err => err.code === 'OIDC_NOT_ALLOWED',
        );
      },
    );

    await check(
      'non-RS256 signature is rejected (alg pinned server-side)',
      async () => {
        const secret = new TextEncoder().encode('attacker-controlled-secret');
        const token = await new jose.SignJWT({repository: 'fortmesa/example'})
          .setProtectedHeader({alg: 'HS256'})
          .setIssuer(issuer)
          .setAudience(AUDIENCE)
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(secret);
        await assert.rejects(() => trustedIssuer.verify(token));
      },
    );

    await check('unreachable JWKS endpoint fails closed', async () => {
      const unreachable = makeIssuer('http://127.0.0.1:1');
      const token = await sign({repository: 'fortmesa/example'});
      await assert.rejects(() => unreachable.verify(token));
    });

    await check(
      'explicit per-issuer algorithms config rejects an unsupported algorithm at construction',
      () => {
        assert.throws(
          () => makeIssuer(issuer, {algorithms: ['HS256']}),
          /unsupported algorithm 'HS256'/,
        );
      },
    );

    await check(
      'explicit per-issuer algorithms config is enforced, not merged with the default',
      async () => {
        const esOnly = makeIssuer(issuer, {algorithms: ['ES256']});
        const token = await sign({repository: 'fortmesa/example'}); // actually signed RS256
        await assert.rejects(() => esOnly.verify(token));
      },
    );

    await check(
      'discovery-advertised algorithms are filtered through the safe list, falling back to RS256 when nothing survives',
      async () => {
        setAdvertisedAlgs(['HS256', 'none']);
        try {
          const unsafeAdvertised = makeIssuer(issuer);
          const token = await sign({repository: 'fortmesa/example'});
          const {remoteUser} = await unsafeAdvertised.verify(token); // still verifies: falls back to RS256
          assert.equal(remoteUser.name, 'ci:fortmesa/example');
        } finally {
          setAdvertisedAlgs(undefined); // restore default for subsequent checks
        }
      },
    );

    const recovering = makeIssuer(issuer, {}, {discoveryCooldownSeconds: 60});

    await check(
      're-runs discovery and recovers when the provider moves its JWKS location',
      async () => {
        const baseline = await sign({repository: 'fortmesa/example'});
        await recovering.verify(baseline); // caches the key set at the current location

        await rotate(); // provider now serves a different key at a different jwks_uri
        const afterMove = await sign({repository: 'fortmesa/example'});
        const {remoteUser} = await recovering.verify(afterMove);
        assert.equal(remoteUser.name, 'ci:fortmesa/example');
      },
    );

    await check(
      'does not re-run discovery again within the cooldown window',
      async () => {
        await rotate(); // move the location again, immediately after the last refresh
        const token = await sign({repository: 'fortmesa/example'});
        // `recovering` has a 60s cooldown and just refreshed a moment ago, so
        // this must fail -- a burst of failures can't force unbounded re-discovery.
        await assert.rejects(() => recovering.verify(token));
      },
    );

    const fastCooldown = makeIssuer(
      issuer,
      {},
      {discoveryCooldownSeconds: 0.05},
    );

    await check(
      'cooldown blocks re-discovery immediately after a refresh',
      async () => {
        const baseline = await sign({repository: 'fortmesa/example'});
        await fastCooldown.verify(baseline); // establishes the cached location, no refresh consumed yet

        await rotate();
        const afterFirstMove = await sign({repository: 'fortmesa/example'});
        await fastCooldown.verify(afterFirstMove); // triggers and consumes the one allowed refresh

        await rotate(); // move again immediately, well within the 50ms cooldown
        const afterSecondMove = await sign({repository: 'fortmesa/example'});
        await assert.rejects(() => fastCooldown.verify(afterSecondMove));
      },
    );

    await check(
      're-runs discovery again once the cooldown window has elapsed',
      async () => {
        await new Promise(resolve => setTimeout(resolve, 100)); // let the 50ms cooldown expire
        const token = await sign({repository: 'fortmesa/example'}); // still the location from the previous check
        const {remoteUser} = await fastCooldown.verify(token);
        assert.equal(remoteUser.name, 'ci:fortmesa/example');
      },
    );

    await check(
      'a second request with the same token is served from cache without re-verifying',
      async () => {
        const middleware = makeMiddleware(issuer);
        const handler = captureHandler(middleware);
        const issuerInstance = middleware.issuers[0];
        let verifyCalls = 0;
        const originalVerify = issuerInstance.verify.bind(issuerInstance);
        issuerInstance.verify = async (...args) => {
          verifyCalls += 1;
          return originalVerify(...args);
        };

        const token = await sign({repository: 'fortmesa/example'});

        const first = await runHandler(handler, token);
        assert.equal(first.req.remote_user.name, 'ci:fortmesa/example');
        assert.equal(verifyCalls, 1);

        const second = await runHandler(handler, token);
        assert.equal(second.req.remote_user.name, 'ci:fortmesa/example');
        assert.equal(
          verifyCalls,
          1,
          'verify() must not be called again on a cache hit',
        );
      },
    );

    await check(
      "a cached result never outlives the token's own expiry, even under a longer TTL",
      async () => {
        // clockToleranceSeconds: 0 so the token is genuinely rejected shortly
        // after its stated exp -- the default 30s tolerance would otherwise still
        // accept it on the re-verify below, which would make this test slow
        // (needing a 30s+ wait) without actually exercising the cache boundary.
        const middleware = makeMiddleware(issuer, {
          jwtCacheTtlSeconds: 60,
          clockToleranceSeconds: 0,
        });
        const handler = captureHandler(middleware);
        const shortLivedToken = await sign(
          {repository: 'fortmesa/example'},
          {expiresIn: '1s'},
        );

        const first = await runHandler(handler, shortLivedToken);
        assert.equal(first.req.remote_user.name, 'ci:fortmesa/example');

        await new Promise(resolve => setTimeout(resolve, 1200)); // let the token itself expire

        const second = await runHandler(handler, shortLivedToken);
        // A 60s-TTL cache entry naively honored here would wrongly still succeed --
        // this proves the cache is bounded by the token's own exp, not just the TTL.
        assert.equal(second.rejected, true);
        assert.equal(second.res.statusCode, 401);
      },
    );

    await check(
      'cache evicts the least-recently-used entry once its size limit is exceeded',
      async () => {
        const middleware = makeMiddleware(issuer, {jwtCacheMaxEntries: 2});
        const handler = captureHandler(middleware);

        const tokenA = await sign({repository: 'fortmesa/example', jti: 'a'});
        const tokenB = await sign({repository: 'fortmesa/example', jti: 'b'});
        const tokenC = await sign({repository: 'fortmesa/example', jti: 'c'});

        await runHandler(handler, tokenA);
        await runHandler(handler, tokenB);
        await runHandler(handler, tokenC); // pushes the cache over its 2-entry limit

        assert.equal(
          middleware.jwtCache.get(tokenA),
          undefined,
          'oldest/least-recently-used entry should be evicted',
        );
        assert.notEqual(middleware.jwtCache.get(tokenB), undefined);
        assert.notEqual(middleware.jwtCache.get(tokenC), undefined);
      },
    );

    // --- body-buffering middleware (workaround for verdaccio/verdaccio#1912) ---

    await check(
      'a PUT with a JSON content-type gets req.body/req._body populated by the buffering middleware, before the auth handler even runs',
      async () => {
        const middleware = makeMiddleware(issuer);
        const [bufferHandler] = captureHandlers(middleware);

        const payload = {versions: {'1.0.0': {version: '1.0.0'}}};
        const req = makeStreamingReq({
          method: 'PUT',
          headers: {'content-type': 'application/json'},
          body: JSON.stringify(payload),
        });

        await new Promise((resolve, reject) => {
          bufferHandler(req, {}, err => (err ? reject(err) : resolve()));
        });

        assert.equal(req._body, true);
        assert.deepEqual(req.body, payload);
      },
    );

    await check(
      'a non-PUT request is left alone by the buffering middleware -- no req.body, stream untouched',
      async () => {
        const middleware = makeMiddleware(issuer);
        const [bufferHandler] = captureHandlers(middleware);

        const req = makeStreamingReq({
          method: 'GET',
          headers: {'content-type': 'application/json'},
        });

        await new Promise((resolve, reject) => {
          bufferHandler(req, {}, err => (err ? reject(err) : resolve()));
        });

        assert.equal(req._body, undefined);
        assert.equal(req.body, undefined);
      },
    );

    await check(
      'a PUT with a non-JSON content-type (the tarball-only upload route) is left alone -- never treated as JSON',
      async () => {
        const middleware = makeMiddleware(issuer);
        const [bufferHandler] = captureHandlers(middleware);

        const req = makeStreamingReq({
          method: 'PUT',
          headers: {'content-type': 'application/octet-stream'},
          body: Buffer.from([0x1f, 0x8b, 0x00, 0x00]), // not JSON at all
        });

        await new Promise((resolve, reject) => {
          bufferHandler(req, {}, err => (err ? reject(err) : resolve()));
        });

        assert.equal(req._body, undefined);
        assert.equal(req.body, undefined);
      },
    );

    await check(
      'a PUT with a non-identity content-encoding is left alone -- declines rather than risk mishandling a compressed body',
      async () => {
        const middleware = makeMiddleware(issuer);
        const [bufferHandler] = captureHandlers(middleware);

        const req = makeStreamingReq({
          method: 'PUT',
          headers: {
            'content-type': 'application/json',
            'content-encoding': 'gzip',
          },
          body: Buffer.from('not actually valid json when read raw'),
        });

        await new Promise((resolve, reject) => {
          bufferHandler(req, {}, err => (err ? reject(err) : resolve()));
        });

        assert.equal(req._body, undefined);
        assert.equal(req.body, undefined);
      },
    );

    await check(
      'malformed JSON in the body propagates an error via next(err) rather than throwing',
      async () => {
        const middleware = makeMiddleware(issuer);
        const [bufferHandler] = captureHandlers(middleware);

        const req = makeStreamingReq({
          method: 'PUT',
          headers: {'content-type': 'application/json'},
          body: '{not valid json',
        });

        const err = await new Promise(resolve => {
          bufferHandler(req, {}, resolve);
        });
        assert.ok(err instanceof Error);
      },
    );

    await check(
      'end-to-end: the buffering middleware prevents the exact stream-draining race a real, unmodified Verdaccio log.js causes',
      async () => {
        // Mirrors @verdaccio/middleware's own log.js exactly (confirmed
        // directly against its real, installed source): an unconditional
        // req.on('data', ...) purely to count bytes, switching the request
        // stream into flowing mode immediately, on every request.
        function verdaccioLogMiddlewareMirror(req, res, next) {
          let bytesin = 0;
          req.on('data', chunk => {
            bytesin += chunk.length;
          });
          next();
        }

        const express = require('express');
        const bodyParser = require('body-parser');

        const middleware = makeMiddleware(issuer);
        const token = await sign({repository: 'fortmesa/example'});

        const app = express();
        app.use(verdaccioLogMiddlewareMirror);
        middleware.register_middlewares(app, null, null); // registers the buffering middleware, then the (now-instant, cache-populating) auth check
        const parseJson = bodyParser.json({strict: false, limit: '10mb'});
        app.use((req, res, next) => {
          if (req.method !== 'PUT') return next();
          parseJson(req, res, err => {
            if (err) return res.status(500).json({error: err.message});
            res.status(201).json({ok: true, versions: !!req.body?.versions});
          });
        });

        const server = await new Promise(resolve => {
          const s = app.listen(0, () => resolve(s));
        });
        try {
          const port = server.address().port;
          const payload = JSON.stringify({
            versions: {'1.0.0': {version: '1.0.0'}},
            filler: 'x'.repeat(75000), // realistic publish-with-provenance size
          });

          const result = await new Promise((resolve, reject) => {
            const req = http.request(
              {
                method: 'PUT',
                hostname: 'localhost',
                port,
                path: '/pkg',
                headers: {
                  'Content-Type': 'application/json',
                  'Content-Length': Buffer.byteLength(payload),
                  Authorization: `Bearer ${token}`,
                },
              },
              res => {
                let body = '';
                res.on('data', c => (body += c));
                res.on('end', () => resolve({status: res.statusCode, body}));
              },
            );
            req.on('error', reject);
            req.end(payload);
          });

          assert.equal(
            result.status,
            201,
            `expected the publish to succeed despite log.js's own listener; got: ${result.body}`,
          );
          assert.ok(JSON.parse(result.body).versions);
        } finally {
          server.close();
        }
      },
    );

    console.log(`\n${passed} check(s) passed.`);
  } finally {
    server.close();
  }
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
