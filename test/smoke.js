'use strict';

// Manual smoke test -- this repo has no test framework/build step for its
// plugins, but signature-verification code has no other safety net. Run with:
//   node test/smoke.js
// Spins up a throwaway RSA keypair + a local fake OIDC issuer (discovery +
// JWKS endpoints) and exercises the accept/reject paths against it.
// test/verdaccio.js runs the plugin inside a real Verdaccio.

const http = require('node:http');
const assert = require('node:assert/strict');
const {
  TrustedIssuer,
  OidcAuthMiddleware,
  JwtVerificationCache,
} = require('../index.js');

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
    Array.from({length: 8}, generateSigningKey),
  );
  // Never published at any JWKS location: a forger's key.
  const unpublishedKey = await generateSigningKey();
  const keysByVersion = new Map([[0, keyPool[0]]]);
  let currentVersion = 0;
  let nextPoolIndex = 1;
  let issuer;
  // undefined by default -- discovery response omits
  // id_token_signing_alg_values_supported entirely, same as a real provider
  // that doesn't publish it. Tests can override via setAdvertisedAlgs().
  let advertisedAlgs;
  const hits = {discovery: 0};

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
      hits.discovery += 1;
      const doc = {issuer, jwks_uri: jwksUrl()};
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

  function jwksUrl() {
    return `${issuer}/jwks-v${currentVersion}`;
  }

  async function sign(
    claims,
    {
      alg = 'RS256',
      expiresIn = '5m',
      audience = AUDIENCE,
      key = keysByVersion.get(currentVersion),
    } = {},
  ) {
    return new jose.SignJWT(claims)
      .setProtectedHeader({alg, kid: key.jwk.kid})
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .sign(key.privateKey);
  }

  const forge = claims => sign(claims, {key: unpublishedKey});

  return {
    jose,
    server,
    issuer,
    sign,
    forge,
    rotate,
    setAdvertisedAlgs,
    jwksUrl,
    hits,
  };
}

// A server that answers every request with `handler`, for discovery
// documents the mock issuer above would never serve.
async function startServer(handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {server, url: `http://127.0.0.1:${server.address().port}`};
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

// register_middlewares() does a single app.use(handler) -- capture that
// handler so tests can drive it directly without a real Express app.
function captureHandler(middleware) {
  const handlers = [];
  middleware.register_middlewares({use: fn => handlers.push(fn)}, null, null);
  assert.equal(handlers.length, 1);
  return handlers[0];
}

// Drives the handler with a fake request. `events` records, in order, every
// pause(), resume(), next() and response the handler makes.
function runHandler(handler, headers, events = []) {
  if (typeof headers === 'string') {
    headers = {authorization: `Bearer ${headers}`};
  }
  return new Promise((resolve, reject) => {
    const req = {
      headers,
      pause() {
        events.push('pause');
      },
      resume() {
        events.push('resume');
      },
    };
    const res = {
      locals: {},
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(body) {
        events.push(this.statusCode);
        resolve({req, res: this, rejected: true, body, events});
      },
    };
    const next = err => {
      events.push('next');
      if (err) reject(err);
      else resolve({req, res, rejected: false, events});
    };
    handler(req, res, next);
  });
}

// Mirrors @verdaccio/middleware's own log.js (checked against its installed
// source in both 6.7.4 and 6.10.6): an unconditional req.on('data', ...)
// purely to count bytes, which switches the request stream into flowing
// mode on every request.
function verdaccioLogMiddlewareMirror(req, res, next) {
  let bytesin = 0;
  req.on('data', chunk => {
    bytesin += chunk.length;
  });
  next();
}

// Serves `app` and sends one request through it. A request that gets no
// answer within 5s fails instead of hanging the run.
async function sendThrough(app, {method, path, headers, body}) {
  const server = await new Promise(resolve => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  try {
    return await new Promise((resolve, reject) => {
      const req = http.request(
        {
          method,
          hostname: '127.0.0.1',
          port: server.address().port,
          path,
          headers: {...headers, 'Content-Length': Buffer.byteLength(body)},
          agent: false,
        },
        res => {
          let text = '';
          res.on('data', c => (text += c));
          res.on('end', () => resolve({status: res.statusCode, body: text}));
        },
      );
      req.setTimeout(5000, () =>
        req.destroy(new Error(`${method} ${path} got no answer within 5s`)),
      );
      req.on('error', reject);
      req.end(body);
    });
  } finally {
    server.close();
  }
}

// A realistic publish-with-provenance size: well over one stream chunk.
const PUBLISH_BODY = JSON.stringify({
  versions: {'1.0.0': {version: '1.0.0'}},
  filler: 'x'.repeat(75000),
});

// The route a test app ends in: parses a JSON body the way Verdaccio's own
// endpoint router does (unless an earlier parser already has) and answers
// 201 with what it found.
function bodyEcho() {
  const bodyParser = require('body-parser');
  const parseJson = bodyParser.json({strict: false, limit: '10mb'});
  return (req, res) => {
    parseJson(req, res, err => {
      if (err) return res.status(err.status ?? 500).json({error: err.message});
      res.status(201).json({
        user: req.remote_user?.name,
        versions: Boolean(req.body?.versions),
      });
    });
  };
}

async function main() {
  const {
    jose,
    server,
    issuer,
    sign,
    forge,
    rotate,
    setAdvertisedAlgs,
    jwksUrl,
    hits,
  } = await startMockIssuer();
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

  const code = expected => err => {
    assert.equal(err?.code, expected, err?.stack);
    return true;
  };

  try {
    const trustedIssuer = makeIssuer(issuer);

    // --- token verification ---

    await check(
      'valid token is accepted and mapped to the right identity',
      async () => {
        const token = await sign({repository: 'fortmesa/example'});
        const {remoteUser} = await trustedIssuer.verify(token);
        assert.equal(remoteUser.name, 'ci:fortmesa/example');
        assert.deepEqual(remoteUser.real_groups, ['ci:fortmesa/example']);
        for (const group of [
          '$all',
          '$authenticated',
          '@all',
          '@authenticated',
          'all',
        ]) {
          assert.ok(remoteUser.groups.includes(group), group);
        }
      },
    );

    await check('expired token is rejected', async () => {
      const token = await sign(
        {repository: 'fortmesa/example'},
        {expiresIn: '-1m'},
      );
      await assert.rejects(
        () => trustedIssuer.verify(token),
        code('ERR_JWT_EXPIRED'),
      );
    });

    await check('wrong audience is rejected', async () => {
      const token = await sign(
        {repository: 'fortmesa/example'},
        {audience: 'https://someone-else.example'},
      );
      await assert.rejects(
        () => trustedIssuer.verify(token),
        err => {
          assert.equal(err.code, 'ERR_JWT_CLAIM_VALIDATION_FAILED');
          assert.equal(err.claim, 'aud');
          return true;
        },
      );
    });

    await check(
      'a token signed by a key the issuer never published is rejected, even with the right iss and aud',
      async () => {
        const isolated = makeIssuer(issuer);
        const token = await forge({repository: 'fortmesa/example'});
        await assert.rejects(
          () => isolated.verify(token),
          code('ERR_JWKS_NO_MATCHING_KEY'),
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
        await assert.rejects(
          () => trustedIssuer.verify(token),
          code('ERR_JOSE_ALG_NOT_ALLOWED'),
        );
      },
    );

    await check('unreachable discovery endpoint fails closed', async () => {
      const unreachable = makeIssuer('http://127.0.0.1:1');
      const token = await sign({repository: 'fortmesa/example'});
      await assert.rejects(() => unreachable.verify(token), /fetch failed/);
    });

    await check(
      'an explicit jwksUri is used without fetching discovery',
      async () => {
        const before = hits.discovery;
        const explicit = makeIssuer(issuer, {jwksUri: jwksUrl()});
        const token = await sign({repository: 'fortmesa/example'});
        const {remoteUser} = await explicit.verify(token);
        assert.equal(remoteUser.name, 'ci:fortmesa/example');
        assert.equal(hits.discovery, before);
      },
    );

    await check('an unreachable explicit jwksUri fails closed', async () => {
      const unreachable = makeIssuer(issuer, {
        jwksUri: 'http://127.0.0.1:1/jwks',
      });
      const token = await sign({repository: 'fortmesa/example'});
      await assert.rejects(() => unreachable.verify(token), /fetch failed/);
    });

    await check(
      'discovery is refused when the document names a different issuer',
      async () => {
        const impostor = await startServer((req, res) => {
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({issuer, jwks_uri: jwksUrl()}));
        });
        try {
          const mismatched = makeIssuer(impostor.url);
          const token = await sign({repository: 'fortmesa/example'});
          await assert.rejects(
            () => mismatched.verify(token),
            /returned issuer/,
          );
        } finally {
          impostor.server.close();
        }
      },
    );

    await check('discovery does not follow a redirect', async () => {
      const redirector = await startServer((req, res) => {
        res.writeHead(302, {location: `${issuer}${req.url}`});
        res.end();
      });
      try {
        const redirected = makeIssuer(redirector.url);
        const token = await sign({repository: 'fortmesa/example'});
        await assert.rejects(() => redirected.verify(token), /HTTP 302/);
      } finally {
        redirector.server.close();
      }
    });

    // --- algorithms ---

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
        await assert.rejects(
          () => esOnly.verify(token),
          code('ERR_JOSE_ALG_NOT_ALLOWED'),
        );
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

    // --- allow list ---

    await check('claim not on the allow list is rejected', async () => {
      const token = await sign({repository: 'someone-else/not-allowed'});
      await assert.rejects(
        () => trustedIssuer.verify(token),
        code('OIDC_NOT_ALLOWED'),
      );
    });

    await check(
      'a trailing "*" matches any repository in the same owner',
      async () => {
        const wildcardIssuer = makeIssuer(issuer, {
          allow: [{repository: 'fortmesa/*'}],
        });
        for (const repository of [
          'fortmesa/verdaccio-attestations',
          'fortmesa/.github',
        ]) {
          const token = await sign({repository});
          const {remoteUser} = await wildcardIssuer.verify(token);
          assert.equal(remoteUser.name, `ci:${repository}`);
        }
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
          code('OIDC_NOT_ALLOWED'),
        );
      },
    );

    await check(
      'a "*" also does not cross a ":" -- claims are free-form, not always "/"-delimited',
      async () => {
        const colonIssuer = makeIssuer(issuer, {
          matchClaim: 'team',
          usernameTemplate: 'ci:{team}',
          groupTemplates: ['ci:{team}'],
          allow: [{team: 'fortmesa:*'}],
        });
        const matching = await sign({team: 'fortmesa:platform'});
        const {remoteUser} = await colonIssuer.verify(matching);
        assert.equal(remoteUser.name, 'ci:fortmesa:platform');

        const nested = await sign({team: 'fortmesa:platform:prod'});
        await assert.rejects(
          () => colonIssuer.verify(nested),
          code('OIDC_NOT_ALLOWED'),
        );
      },
    );

    await check(
      '"**" matches every repo, crossing both "/" and ":"',
      async () => {
        const everythingIssuer = makeIssuer(issuer, {
          allow: [{repository: '**'}],
        });
        const token = await sign({repository: 'anyone/any:thing'});
        const {remoteUser} = await everythingIssuer.verify(token);
        assert.equal(remoteUser.name, 'ci:anyone/any:thing');
      },
    );

    await check(
      'every other character in a pattern is literal: no negation, braces, classes or "?"',
      async () => {
        const cases = [
          ['!fortmesa/blocked', 'someone-else/evil'],
          ['fortmesa/{a,b}', 'fortmesa/a'],
          ['fortmesa/[ab]', 'fortmesa/a'],
          ['fortmesa/a?c', 'fortmesa/abc'],
          ['fortmesa/a.c', 'fortmesa/abc'],
          ['fortmesa/+(a)', 'fortmesa/a'],
          ['#fortmesa', 'anything'],
        ];
        for (const [pattern, repository] of cases) {
          const literal = makeIssuer(issuer, {allow: [{repository: pattern}]});
          const token = await sign({repository});
          await assert.rejects(
            () => literal.verify(token),
            code('OIDC_NOT_ALLOWED'),
            `${pattern} must not match ${repository}`,
          );
          const exact = await sign({repository: pattern});
          const {remoteUser} = await literal.verify(exact);
          assert.equal(remoteUser.name, `ci:${pattern}`);
        }
      },
    );

    await check(
      'matching is case-insensitive by default, and the identity is rendered in lower case to match',
      async () => {
        const token = await sign({repository: 'FortMesa/Example'});
        const {remoteUser} = await trustedIssuer.verify(token);
        assert.equal(remoteUser.name, 'ci:fortmesa/example');
        assert.deepEqual(remoteUser.real_groups, ['ci:fortmesa/example']);
      },
    );

    await check(
      'matchCaseInsensitive: false makes matching case-sensitive and keeps the claim case in the identity',
      async () => {
        const caseSensitiveIssuer = makeIssuer(issuer, {
          matchCaseInsensitive: false,
          allow: [{repository: 'FortMesa/*'}],
        });
        const wrongCase = await sign({repository: 'fortmesa/example'});
        await assert.rejects(
          () => caseSensitiveIssuer.verify(wrongCase),
          code('OIDC_NOT_ALLOWED'),
        );
        const token = await sign({repository: 'FortMesa/Example'});
        const {remoteUser} = await caseSensitiveIssuer.verify(token);
        assert.equal(remoteUser.name, 'ci:FortMesa/Example');
      },
    );

    await check(
      'a missing/non-string claim value fails closed instead of throwing',
      async () => {
        for (const claims of [{}, {repository: ['fortmesa/example']}]) {
          const token = await sign(claims);
          await assert.rejects(
            () => trustedIssuer.verify(token),
            code('OIDC_NOT_ALLOWED'),
          );
        }
      },
    );

    // The install job and the publish job of one release run carry the same
    // repository claim; only the job's environment, in `sub`, differs.
    const pinned = makeIssuer(issuer, {
      allow: [
        {
          repository: 'fortmesa/example',
          sub: 'repo:fortmesa/example:environment:npmjs',
        },
        {
          repository: 'fortmesa/other',
          sub: [
            'repo:fortmesa/other:environment:npmjs',
            'repo:fortmesa/other:ref:refs/tags/v*',
          ],
        },
      ],
    });

    await check(
      'every key of an allow entry must match: a sub pin tells the publish job from the install job',
      async () => {
        const publishJob = await sign({
          repository: 'fortmesa/example',
          sub: 'repo:fortmesa/example:environment:npmjs',
        });
        const {remoteUser} = await pinned.verify(publishJob);
        assert.equal(remoteUser.name, 'ci:fortmesa/example');

        for (const sub of [
          'repo:fortmesa/example:environment:install',
          'repo:fortmesa/example:ref:refs/heads/master',
          'repo:fortmesa/example:environment:npmjs:extra',
          undefined,
        ]) {
          const token = await sign({repository: 'fortmesa/example', sub});
          await assert.rejects(
            () => pinned.verify(token),
            code('OIDC_NOT_ALLOWED'),
            String(sub),
          );
        }
      },
    );

    await check(
      'a claim may list several patterns, any one of which matches, and entries are alternatives',
      async () => {
        for (const sub of [
          'repo:fortmesa/other:environment:npmjs',
          'repo:fortmesa/other:ref:refs/tags/v1.2.3',
        ]) {
          const token = await sign({repository: 'fortmesa/other', sub});
          const {remoteUser} = await pinned.verify(token);
          assert.equal(remoteUser.name, 'ci:fortmesa/other');
        }
        // One entry's sub does not unlock another entry's repository.
        const crossed = await sign({
          repository: 'fortmesa/example',
          sub: 'repo:fortmesa/other:environment:npmjs',
        });
        await assert.rejects(
          () => pinned.verify(crossed),
          code('OIDC_NOT_ALLOWED'),
        );
      },
    );

    // --- identity templates ---

    await check(
      'a template naming a claim the token lacks fails the token instead of rendering an empty identity',
      async () => {
        const grouped = makeIssuer(issuer, {
          groupTemplates: ['ci:{repository}', 'ci-org:{repository_owner}'],
        });
        for (const repository_owner of [undefined, {name: 'fortmesa'}]) {
          const token = await sign({
            repository: 'fortmesa/example',
            repository_owner,
          });
          await assert.rejects(
            () => grouped.verify(token),
            code('OIDC_TEMPLATE_CLAIM_MISSING'),
          );
        }
        const token = await sign({
          repository: 'fortmesa/example',
          repository_owner: 'fortmesa',
        });
        const {remoteUser} = await grouped.verify(token);
        assert.deepEqual(remoteUser.real_groups, [
          'ci:fortmesa/example',
          'ci-org:fortmesa',
        ]);
      },
    );

    await check('a numeric claim renders as its digits', async () => {
      const numeric = makeIssuer(issuer, {
        usernameTemplate: 'ci:{repository}:{run}',
      });
      const token = await sign({repository: 'fortmesa/example', run: 42});
      const {remoteUser} = await numeric.verify(token);
      assert.equal(remoteUser.name, 'ci:fortmesa/example:42');
    });

    // --- config validation ---

    await check(
      'an incomplete or malformed issuer config fails at startup',
      () => {
        const cases = [
          [{id: ''}, /non-empty id/],
          [{issuer: undefined}, /absolute URL/],
          [{issuer: 'not a url'}, /absolute URL/],
          [{issuer: 'ftp://example.com'}, /http\(s\) issuer URL/],
          [{audience: undefined}, /audience/],
          [{audience: ''}, /audience/],
          [{audience: []}, /audience/],
          [{audience: [AUDIENCE, 7]}, /audience/],
          [{matchClaim: undefined}, /matchClaim/],
          [{usernameTemplate: undefined}, /usernameTemplate/],
          [{groupTemplates: 'ci:{repository}'}, /groupTemplates to be a list/],
          [{groupTemplates: ['']}, /usernameTemplate and every groupTemplates/],
          [{usernameTemplate: 'ci:{repository'}, /malformed template/],
          [{usernameTemplate: 'ci:{repo-name}'}, /malformed template/],
          [{allow: undefined}, /non-empty allow list/],
          [{allow: []}, /non-empty allow list/],
          [{allow: ['fortmesa/example']}, /not a map/],
          [
            {allow: [{sub: 'repo:fortmesa/example:*'}]},
            /without its matchClaim/,
          ],
          [{allow: [{repository: ''}]}, /'repository' is not a pattern/],
          [{allow: [{repository: []}]}, /'repository' is not a pattern/],
          [
            {allow: [{repository: 'fortmesa/x', sub: 7}]},
            /'sub' is not a pattern/,
          ],
        ];
        for (const [overrides, message] of cases) {
          assert.throws(
            () => makeIssuer(issuer, overrides),
            message,
            JSON.stringify(overrides),
          );
        }
      },
    );

    await check('a duplicate issuer URL fails at startup', () => {
      assert.throws(
        () =>
          makeMiddleware(issuer, {
            issuers: [
              issuerConfig(issuer),
              issuerConfig(issuer, {id: 'second'}),
            ],
          }),
        /duplicate issuer URL/,
      );
    });

    await check(
      'cache sizes that are negative or not whole numbers fail at startup',
      () => {
        for (const [overrides, message] of [
          [{jwtCacheMaxEntries: -1}, /jwtCacheMaxEntries/],
          [{jwtCacheMaxEntries: 1.5}, /jwtCacheMaxEntries/],
          [{jwtCacheMaxEntries: '10'}, /jwtCacheMaxEntries/],
          [{jwtCacheTtlSeconds: -1}, /jwtCacheTtlSeconds/],
          [{jwtCacheTtlSeconds: 'x'}, /jwtCacheTtlSeconds/],
        ]) {
          assert.throws(() => makeMiddleware(issuer, overrides), message);
        }
      },
    );

    // --- re-discovery ---

    const recovering = makeIssuer(issuer, {}, {discoveryCooldownSeconds: 60});

    await check(
      're-runs discovery and recovers when the provider moves its JWKS location',
      async () => {
        const baseline = await sign({repository: 'fortmesa/example'});
        await recovering.verify(baseline); // caches the key set at the current location

        rotate(); // provider now serves a different key at a different jwks_uri
        const afterMove = await sign({repository: 'fortmesa/example'});
        const {remoteUser} = await recovering.verify(afterMove);
        assert.equal(remoteUser.name, 'ci:fortmesa/example');
      },
    );

    await check(
      'does not re-run discovery again within the cooldown window',
      async () => {
        rotate(); // move the location again, immediately after the last refresh
        const token = await sign({repository: 'fortmesa/example'});
        // `recovering` has a 60s cooldown and just refreshed a moment ago, so
        // this must fail -- a burst of failures can't force unbounded re-discovery.
        await assert.rejects(
          () => recovering.verify(token),
          code('ERR_JWKS_NO_MATCHING_KEY'),
        );
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

        rotate();
        const afterFirstMove = await sign({repository: 'fortmesa/example'});
        await fastCooldown.verify(afterFirstMove); // triggers and consumes the one allowed refresh

        rotate(); // move again immediately, well within the 50ms cooldown
        const afterSecondMove = await sign({repository: 'fortmesa/example'});
        await assert.rejects(
          () => fastCooldown.verify(afterSecondMove),
          code('ERR_JWKS_NO_MATCHING_KEY'),
        );
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
      'concurrent requests that need new keys share one re-discovery instead of being refused by its cooldown',
      async () => {
        const shared = makeIssuer(issuer, {}, {discoveryCooldownSeconds: 60});
        await shared.verify(await sign({repository: 'fortmesa/example'}));

        rotate();
        const tokens = await Promise.all(
          Array.from({length: 4}, (_, i) =>
            sign({repository: 'fortmesa/example', jti: String(i)}),
          ),
        );
        const before = hits.discovery;
        const results = await Promise.all(tokens.map(t => shared.verify(t)));
        assert.equal(results.length, 4);
        assert.equal(hits.discovery - before, 1);
      },
    );

    // --- the middleware ---

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
        assert.equal(first.res.locals.remote_user.name, 'ci:fortmesa/example');
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
      'a cache hit hands out a copy, so a request that changes its remote_user does not change the next one',
      async () => {
        const handler = captureHandler(makeMiddleware(issuer));
        const token = await sign({repository: 'fortmesa/example'});

        // Both the request that filled the cache and one served from it.
        const miss = await runHandler(handler, token);
        miss.req.remote_user.error = 'set by a later middleware';
        miss.req.remote_user.groups.push('$injected-on-miss');

        const first = await runHandler(handler, token);
        first.req.remote_user.error = 'set by a later middleware';
        first.req.remote_user.groups.push('$injected');

        const second = await runHandler(handler, token);
        assert.equal(second.req.remote_user.error, undefined);
        assert.ok(!second.req.remote_user.groups.includes('$injected'));
        assert.ok(!second.req.remote_user.groups.includes('$injected-on-miss'));
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
        await runHandler(handler, tokenA); // A is now the most recently used
        await runHandler(handler, tokenC); // pushes the cache over its 2-entry limit

        assert.notEqual(middleware.jwtCache.get(tokenA), undefined);
        assert.equal(
          middleware.jwtCache.get(tokenB),
          undefined,
          'the least-recently-used entry should be evicted',
        );
        assert.notEqual(middleware.jwtCache.get(tokenC), undefined);
      },
    );

    await check('jwtCacheMaxEntries: 0 turns caching off', async () => {
      const middleware = makeMiddleware(issuer, {jwtCacheMaxEntries: 0});
      const handler = captureHandler(middleware);
      const issuerInstance = middleware.issuers[0];
      let verifyCalls = 0;
      const originalVerify = issuerInstance.verify.bind(issuerInstance);
      issuerInstance.verify = async (...args) => {
        verifyCalls += 1;
        return originalVerify(...args);
      };
      const token = await sign({repository: 'fortmesa/example'});
      await runHandler(handler, token);
      const second = await runHandler(handler, token);
      assert.equal(second.req.remote_user.name, 'ci:fortmesa/example');
      assert.equal(verifyCalls, 2);
    });

    await check('jwtCacheTtlSeconds: 0 caches nothing', () => {
      const cache = new JwtVerificationCache({ttlMs: 0, maxEntries: 10});
      cache.set('token', {name: 'x'}, Date.now() + 60000);
      assert.equal(cache.get('token'), undefined);
    });

    await check(
      'a cache miss pauses the request until verification finishes, and resumes it before next()',
      async () => {
        const handler = captureHandler(makeMiddleware(issuer));
        const token = await sign({repository: 'fortmesa/example'});
        const miss = await runHandler(handler, token);
        assert.deepEqual(miss.events, ['pause', 'resume', 'next']);

        const hit = await runHandler(handler, token);
        assert.deepEqual(hit.events, ['next']);
      },
    );

    await check(
      'a rejected token resumes the request and answers 401 with the documented body',
      async () => {
        const handler = captureHandler(makeMiddleware(issuer));
        const token = await forge({repository: 'fortmesa/example'});
        const result = await runHandler(handler, token);
        assert.deepEqual(result.events, ['pause', 'resume', 401]);
        assert.deepEqual(result.body, {
          error: 'unauthorized',
          reason: 'oidc token verification failed',
        });
        assert.equal(result.req.remote_user, undefined);
      },
    );

    await check(
      "requests without a trusted issuer's Bearer token pass through untouched",
      async () => {
        const handler = captureHandler(makeMiddleware(issuer));
        const foreignIssuer = await new jose.SignJWT({repository: 'x/y'})
          .setProtectedHeader({alg: 'HS256'})
          .setIssuer('https://someone-else.example')
          .sign(new TextEncoder().encode('k'));
        for (const headers of [
          {},
          {authorization: 'Basic dXNlcjpwYXNz'},
          {authorization: 'Bearer not-a-jwt'},
          {authorization: 'Bearer a.bm90LWpzb24.c'},
          {authorization: `Bearer ${foreignIssuer}`},
        ]) {
          const result = await runHandler(handler, headers);
          assert.deepEqual(result.events, ['next'], JSON.stringify(headers));
          assert.equal(result.req.remote_user, undefined);
        }
      },
    );

    // --- request bodies under Verdaccio's middleware order ---

    const express = require('express');
    const freshToken = () => sign({repository: 'fortmesa/example'});

    await check(
      "6.7.4 order (log, plugin, then the body parser): a JSON PUT with a token that isn't cached yet still reaches the parser whole",
      async () => {
        const app = express();
        app.use(verdaccioLogMiddlewareMirror);
        makeMiddleware(issuer).register_middlewares(app, null, null);
        app.use(bodyEcho());

        const result = await sendThrough(app, {
          method: 'PUT',
          path: '/pkg',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${await freshToken()}`,
          },
          body: PUBLISH_BODY,
        });
        assert.equal(result.status, 201, result.body);
        assert.deepEqual(JSON.parse(result.body), {
          user: 'ci:fortmesa/example',
          versions: true,
        });
      },
    );

    await check(
      '6.7.4 order: a JSON POST under a cache miss reaches the parser whole too',
      async () => {
        const app = express();
        app.use(verdaccioLogMiddlewareMirror);
        makeMiddleware(issuer).register_middlewares(app, null, null);
        app.use(bodyEcho());

        const result = await sendThrough(app, {
          method: 'POST',
          path: '/-/npm/v1/security/advisories/bulk',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${await freshToken()}`,
          },
          body: PUBLISH_BODY,
        });
        assert.equal(result.status, 201, result.body);
      },
    );

    await check(
      '6.7.4 order: malformed JSON is left to the body parser, which answers 400',
      async () => {
        const app = express();
        app.use(verdaccioLogMiddlewareMirror);
        makeMiddleware(issuer).register_middlewares(app, null, null);
        app.use(bodyEcho());

        const result = await sendThrough(app, {
          method: 'PUT',
          path: '/pkg',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${await freshToken()}`,
          },
          body: '{not valid json',
        });
        assert.equal(result.status, 400, result.body);
      },
    );

    await check(
      '6.10.6 order (log, body parser, then plugin): a JSON PUT under a cache miss completes instead of hanging',
      async () => {
        const app = express();
        app.use(verdaccioLogMiddlewareMirror);
        app.use(express.json({strict: false, limit: '10mb'}));
        makeMiddleware(issuer).register_middlewares(app, null, null);
        app.use(bodyEcho());

        const result = await sendThrough(app, {
          method: 'PUT',
          path: '/pkg',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${await freshToken()}`,
          },
          body: PUBLISH_BODY,
        });
        assert.equal(result.status, 201, result.body);
        assert.equal(JSON.parse(result.body).versions, true);
      },
    );

    await check(
      'a rejected token on a JSON PUT gets its 401 without waiting on the unread body',
      async () => {
        const app = express();
        app.use(verdaccioLogMiddlewareMirror);
        makeMiddleware(issuer).register_middlewares(app, null, null);
        app.use(bodyEcho());

        const result = await sendThrough(app, {
          method: 'PUT',
          path: '/pkg',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${await forge({repository: 'fortmesa/example'})}`,
          },
          body: PUBLISH_BODY,
        });
        assert.equal(result.status, 401, result.body);
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
