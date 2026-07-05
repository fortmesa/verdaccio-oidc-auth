# `verdaccio-oidc-auth`

A [Verdaccio](https://verdaccio.org) middleware plugin: lets CI/CD runners
authenticate using their platform's own short-lived OIDC ID token instead of a
shared static password.

**Type**: Verdaccio `middlewares` (Express) plugin. **Config key**:
`middlewares.oidc-auth`.

## What it does

The registry verifies the token's signature against the issuing platform's
_public_ JWKS (no shared secret needed on your side) and maps trusted claims --
e.g. GitHub's `repository` claim -- to a synthetic, per-repository Verdaccio
identity, so `packages:` ACLs can grant publish rights to one specific repo's CI
instead of "any authenticated identity."

It ships with concrete config for **GitHub Actions** and **Bitbucket
Pipelines**, but nothing GitHub- or Bitbucket-specific is hardcoded in the code
-- the verifier is entirely config-driven (issuer, audience, JWKS/OIDC
discovery, and claim->identity templates), so GitLab CI, CircleCI, Azure DevOps,
Jenkins (with the community "OIDC Provider Plugin"), or TeamCity (2023.11+) can
be added later purely as new config entries.

## Installation

```bash
npm install @fortmesa/verdaccio-oidc-auth
```

List it under `middlewares:` in your Verdaccio `config.yaml`, **before** any
other middleware that reads `req.remote_user` (e.g. `audit`, a cache-enforcement
plugin) so those see the corrected identity rather than the anonymous fallback
Verdaccio's core auth leaves in place for a token it doesn't recognize. See
[Why this is a `middlewares` plugin, not an `auth` plugin](docs/configuration.md#why-this-is-a-middlewares-plugin-not-an-auth-plugin)
for why that ordering matters and why it's safe to layer on top of existing
`htpasswd`/other auth.

## Quick config

```yaml
middlewares:
  oidc-auth:
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
```

See [`docs/configuration.md`](docs/configuration.md) for the full reference:
every config field, how verification works per request, JWKS discovery and key
caching, algorithm selection (and why it's a hardcoded asymmetric-only
allowlist, not just whatever a config or discovery document says), the result
cache, known security limitations, and the testing approach.

## Testing

```bash
node test/smoke.js
```

No test framework/build step -- one manual, dependency-free smoke test that
spins up a throwaway RSA keypair and a local fake OIDC issuer (discovery + JWKS
endpoints) and exercises the accept/reject paths against it.

## Dependencies

`jose` -- the only JWT/JWKS/OIDC library this plugin uses. Loaded via dynamic
`import()` (it's ESM-only) rather than `require()`, so it works from this
plugin's CommonJS `index.js` on any modern Node version. `minimatch` -- `allow:`
list matching, the same convention every other plugin in this family uses -- see
[Matching `allow:` entries](docs/configuration.md#matching-allow-entries).

## License

MIT -- see [LICENSE](LICENSE).
