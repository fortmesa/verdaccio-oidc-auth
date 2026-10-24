# `verdaccio-oidc-auth`

A [Verdaccio](https://verdaccio.org) middleware plugin that lets CI/CD runners
authenticate with their platform's own short-lived OIDC ID token instead of a
shared static password.

**Type**: Verdaccio `middlewares` (Express) plugin. **Config key**: the literal
scoped package name, `middlewares."@fortmesa/verdaccio-oidc-auth"`. Verdaccio
never adds its `verdaccio-` prefix to a scoped plugin's key.

## What it does

The registry checks the token's signature against the issuing platform's public
JWKS, so you hold no shared secret. It then maps claims from the verified token,
such as GitHub's `repository`, to a per-repository Verdaccio identity like
`gha:your-org/your-repo`. A `packages:` ACL can then give publish rights to one
repository's CI instead of to every authenticated identity.

An `allow` entry can pin more than the repository. In GitHub Actions, every job
of a workflow run gets a token with the same `repository` claim, including a job
that only runs `yarn install`. Pinning `sub` to the publish job's environment
means a token from any other job is refused. See
[Telling the publish job apart](docs/configuration.md#telling-the-publish-job-apart).

The repo ships config for GitHub Actions and Bitbucket Pipelines. Nothing in the
code is specific to either one. Issuer, audience, discovery, claim matching and
identity templates all come from config, so GitLab CI, CircleCI, Azure DevOps,
Jenkins with the community OIDC Provider Plugin, or TeamCity 2023.11+ need only
a new config entry.

## Installation

Requires Node 22.12.0 or later.

```bash
npm install @fortmesa/verdaccio-oidc-auth
```

List it under `middlewares:` in your Verdaccio `config.yaml`, ahead of any other
middleware that reads `req.remote_user`, so those see the CI identity rather
than the anonymous one Verdaccio's auth leaves for a token it doesn't recognize.
[Why this is a `middlewares` plugin](docs/configuration.md#why-this-is-a-middlewares-plugin-not-an-auth-plugin)
explains the ordering and why it layers safely on top of `htpasswd` or other
auth.

## Quick config

```yaml
middlewares:
  '@fortmesa/verdaccio-oidc-auth':
    issuers:
      - id: github-actions
        issuer: https://token.actions.githubusercontent.com
        audience: https://your-registry.example.com
        usernameTemplate: 'gha:{repository}'
        groupTemplates:
          - 'gha:{repository}'
          - 'gha-org:{repository_owner}'
        matchClaim: repository
        allow:
          - repository: your-org/your-repo
            sub: 'repo:your-org/your-repo:environment:npmjs'
```

The plugin checks the config at startup and refuses to load a missing audience,
a malformed template, an allow entry without its `matchClaim` key, and the other
mistakes listed in [Startup checks](docs/configuration.md#startup-checks).

[`docs/configuration.md`](docs/configuration.md) is the full reference. It
covers every config field, the allow-pattern syntax, what happens on each
request, discovery and key caching, algorithm selection, the result cache and
the known limitations.

## Testing

```bash
yarn test
```

That runs two files, with no test framework:

- `test/smoke.js` starts a local fake OIDC issuer and drives the verifier and
  the middleware directly. It covers accepting and rejecting tokens, the allow
  syntax, startup checks, re-discovery, the result cache, and request bodies in
  the middleware order of both Verdaccio 6.7.4 and 6.10.6.
- `test/verdaccio.js` runs the plugin inside a real Verdaccio, which publishes,
  tags and reads packages with CI tokens. It also checks that a token from
  another job of the same repository gets a 401.

`VERDACCIO_BIN` runs `test/verdaccio.js` against another Verdaccio build:

```bash
VERDACCIO_BIN=../fm-npmjs/node_modules/verdaccio/bin/verdaccio node test/verdaccio.js
```

## Dependencies

`jose` is the plugin's only runtime dependency. It does JWKS fetching, key
selection and JWT verification. It is ESM-only, so the CommonJS `index.js` loads
it with a dynamic `import()`. Allow patterns use the plugin's own small matcher,
described in
[Matching `allow:` entries](docs/configuration.md#matching-allow-entries).

## License

MIT. See [LICENSE](LICENSE).
