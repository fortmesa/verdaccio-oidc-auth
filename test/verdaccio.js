'use strict';

// The plugin inside a real Verdaccio, trusting a fake GitHub-like OIDC
// issuer. Proves that a CI token publishes, tags and reads through
// Verdaccio's own routes and access rules, that the request body survives
// the asynchronous first verification on this Verdaccio's middleware order,
// and that an allow entry's sub pin turns away a token from any other job.
// Run with:
//   node test/verdaccio.js
// VERDACCIO_BIN points it at another Verdaccio build, e.g. the one
// fm-npmjs deploys:
//   VERDACCIO_BIN=../fm-npmjs/node_modules/verdaccio/bin/verdaccio node test/verdaccio.js

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const {spawn} = require('node:child_process');

const PLUGIN_ROOT = path.join(__dirname, '..');
// verdaccio's package exports don't include its bin, so it's found by path.
const VERDACCIO_BIN =
  process.env.VERDACCIO_BIN ??
  path.join(PLUGIN_ROOT, 'node_modules', 'verdaccio', 'bin', 'verdaccio');

const AUDIENCE = 'https://registry.test';
const PUBLISH_SUB = 'repo:fortmesa/example:environment:npmjs';

async function startIssuer() {
  const jose = await import('jose');
  const {publicKey, privateKey} = await jose.generateKeyPair('RS256');
  const jwk = await jose.exportJWK(publicKey);
  jwk.kid = await jose.calculateJwkThumbprint(jwk);
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  const other = await jose.generateKeyPair('RS256');

  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/.well-known/openid-configuration') {
      return res.end(JSON.stringify({issuer, jwks_uri: `${issuer}/jwks`}));
    }
    if (req.url === '/jwks') return res.end(JSON.stringify({keys: [jwk]}));
    res.statusCode = 404;
    res.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const issuer = `http://127.0.0.1:${server.address().port}`;

  // Claims shaped like a GitHub Actions token from one job of the
  // fortmesa/example release workflow.
  function sign(claims = {}, {key = privateKey, expiresIn = '5m'} = {}) {
    return new jose.SignJWT({
      repository: 'fortmesa/example',
      repository_owner: 'fortmesa',
      sub: PUBLISH_SUB,
      jti: crypto.randomUUID(),
      ...claims,
    })
      .setProtectedHeader({alg: 'RS256', kid: jwk.kid})
      .setIssuer(issuer)
      .setAudience(AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .sign(key);
  }
  const forge = claims => sign(claims, {key: other.privateKey});

  return {server, issuer, sign, forge};
}

function freePort() {
  return new Promise(resolve => {
    const s = http.createServer().listen(0, '127.0.0.1', () => {
      const {port} = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function waitForUp(url, proc) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (proc.exitCode != null) break;
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      // not up yet
    }
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error(`verdaccio never came up:\n${proc.getOutput()}`);
}

// A publish document for one version, carrying a tarball large enough to
// arrive in several chunks.
function publishBody(registry, name, version) {
  const data = crypto.randomBytes(96 * 1024);
  const file = `${name.split('/').pop()}-${version}.tgz`;
  return JSON.stringify({
    _id: name,
    name,
    'dist-tags': {latest: version},
    versions: {
      [version]: {
        name,
        version,
        dist: {
          tarball: `${registry}/${name}/-/${file}`,
          shasum: crypto.createHash('sha1').update(data).digest('hex'),
        },
      },
    },
    _attachments: {
      [file]: {
        content_type: 'application/octet-stream',
        data: data.toString('base64'),
        length: data.length,
      },
    },
  });
}

async function main() {
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

  const {server: issuerServer, issuer, sign, forge} = await startIssuer();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'oidc-auth-'));
  const plugins = path.join(work, 'plugins');
  fs.mkdirSync(path.join(plugins, '@fortmesa'), {recursive: true});
  fs.symlinkSync(
    PLUGIN_ROOT,
    path.join(plugins, '@fortmesa', 'verdaccio-oidc-auth'),
    'dir',
  );
  fs.writeFileSync(path.join(work, 'htpasswd'), '');
  fs.writeFileSync(
    path.join(work, 'config.yaml'),
    `
storage: ${path.join(work, 'storage')}
plugins: ${plugins}
auth:
  htpasswd:
    file: ${path.join(work, 'htpasswd')}
    max_users: 1000
security:
  api:
    legacy: false
    jwt:
      sign:
        expiresIn: 7d
packages:
  '@fortmesa/example':
    access: $authenticated
    publish: gha:fortmesa/example
  '@fortmesa/*':
    access: $authenticated
    publish: alice
  '**':
    access: $authenticated
    publish: alice
middlewares:
  '@fortmesa/verdaccio-oidc-auth':
    issuers:
      - id: github-actions
        issuer: ${issuer}
        audience: ${AUDIENCE}
        matchClaim: repository
        usernameTemplate: 'gha:{repository}'
        groupTemplates:
          - 'gha:{repository}'
          - 'gha-org:{repository_owner}'
        allow:
          - repository: fortmesa/example
            sub: '${PUBLISH_SUB}'
log: {type: stdout, format: pretty, level: warn}
`,
  );

  const port = await freePort();
  const registry = `http://127.0.0.1:${port}`;
  const proc = spawn(
    process.execPath,
    [
      VERDACCIO_BIN,
      '--config',
      path.join(work, 'config.yaml'),
      '--listen',
      `127.0.0.1:${port}`,
    ],
    {stdio: ['ignore', 'pipe', 'pipe']},
  );
  let output = '';
  proc.stdout.on('data', d => (output += d));
  proc.stderr.on('data', d => (output += d));
  proc.getOutput = () => output;

  // Every request gets 10s; the hang this plugin once had on 6.10.6 shows
  // up here as a timeout rather than a stuck run.
  const request = (method, url, {token, headers = {}, body} = {}) =>
    fetch(`${registry}${url}`, {
      method,
      headers: {
        ...headers,
        ...(token ? {authorization: `Bearer ${token}`} : {}),
        ...(body !== undefined ? {'content-type': 'application/json'} : {}),
      },
      body,
      signal: AbortSignal.timeout(10000),
    });

  try {
    await waitForUp(`${registry}/-/ping`, proc);
    const version = JSON.parse(
      fs.readFileSync(
        path.join(path.dirname(VERDACCIO_BIN), '..', 'package.json'),
      ),
    ).version;
    console.log(`verdaccio ${version}, node ${process.version}`);

    let alice;
    await check(
      'npm adduser (a JSON PUT without a Bearer token) completes',
      async () => {
        const res = await request('PUT', '/-/user/org.couchdb.user:alice', {
          body: JSON.stringify({
            name: 'alice',
            password: crypto.randomBytes(12).toString('hex'),
          }),
        });
        assert.equal(res.status, 201);
        alice = (await res.json()).token;
        assert.ok(alice);
      },
    );

    const name = '@fortmesa/example';
    const encoded = encodeURIComponent(name);

    await check(
      "a CI token's first request, a JSON PUT publish, reaches Verdaccio whole and publishes",
      async () => {
        const res = await request('PUT', `/${encoded}`, {
          token: await sign(),
          body: publishBody(registry, name, '1.0.0'),
        });
        assert.equal(res.status, 201, await res.text());
      },
    );

    const ciToken = await sign();
    await check(
      'the same token publishes again from the cache, and reads the result back',
      async () => {
        for (const v of ['1.1.0', '1.2.0']) {
          const res = await request('PUT', `/${encoded}`, {
            token: ciToken,
            body: publishBody(registry, name, v),
          });
          assert.equal(res.status, 201, `${v}: ${await res.text()}`);
        }
        const read = await request('GET', `/${encoded}`, {token: ciToken});
        assert.equal(read.status, 200);
        const doc = await read.json();
        assert.deepEqual(Object.keys(doc.versions).sort(), [
          '1.0.0',
          '1.1.0',
          '1.2.0',
        ]);
        const tarball = await request('GET', `/${name}/-/example-1.0.0.tgz`, {
          token: ciToken,
        });
        assert.equal(tarball.status, 200);
        assert.equal((await tarball.arrayBuffer()).byteLength, 96 * 1024);
      },
    );

    await check(
      'a CI token adds a dist-tag (a JSON PUT of a bare string)',
      async () => {
        const res = await request(
          'PUT',
          `/-/package/${encoded}/dist-tags/beta`,
          {token: await sign(), body: JSON.stringify('1.1.0')},
        );
        assert.equal(res.status, 201, await res.text());
        const tags = await request('GET', `/-/package/${encoded}/dist-tags`, {
          token: ciToken,
        });
        assert.equal((await tags.json()).beta, '1.1.0');
      },
    );

    await check(
      "a token from the install job (same repository, other sub) gets the plugin's 401 and publishes nothing",
      async () => {
        const res = await request('PUT', `/${encoded}`, {
          token: await sign({
            sub: 'repo:fortmesa/example:environment:install',
          }),
          body: publishBody(registry, name, '9.0.0'),
        });
        assert.equal(res.status, 401);
        assert.deepEqual(await res.json(), {
          error: 'unauthorized',
          reason: 'oidc token verification failed',
        });
        const doc = await (
          await request('GET', `/${encoded}`, {token: ciToken})
        ).json();
        assert.equal(doc.versions['9.0.0'], undefined);
      },
    );

    await check(
      'a forged or expired token from the trusted issuer gets 401',
      async () => {
        for (const token of [
          await forge(),
          await sign({}, {expiresIn: '-1m'}),
        ]) {
          const res = await request('GET', `/${encoded}`, {token});
          assert.equal(res.status, 401);
        }
      },
    );

    await check(
      "an allowed CI identity is still bound by Verdaccio's own publish rules",
      async () => {
        const res = await request('PUT', '/@fortmesa%2fother', {
          token: ciToken,
          body: publishBody(registry, '@fortmesa/other', '1.0.0'),
        });
        assert.equal(res.status, 403, await res.text());
      },
    );

    await check(
      "Verdaccio's own tokens pass through the plugin untouched",
      async () => {
        const res = await request('PUT', '/@fortmesa%2fother', {
          token: alice,
          body: publishBody(registry, '@fortmesa/other', '1.0.0'),
        });
        assert.equal(res.status, 201, await res.text());
        const read = await request('GET', `/${encoded}`, {token: alice});
        assert.equal(read.status, 200);
      },
    );

    await check(
      "anonymous requests get Verdaccio's own 401, not the plugin's",
      async () => {
        const res = await request('GET', `/${encoded}`);
        assert.equal(res.status, 401);
        assert.notEqual(
          (await res.json()).reason,
          'oidc token verification failed',
        );
      },
    );
  } finally {
    proc.kill();
    issuerServer.close();
    if (process.exitCode) {
      console.error('\n--- verdaccio output ---\n' + proc.getOutput());
    }
    fs.rmSync(work, {recursive: true, force: true});
  }

  console.log(`\n${passed} check(s) passed.`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
