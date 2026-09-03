# mcp-oauth-proxy

OAuth bearer-token wrapper for HTTP-transport MCP servers. Resource-server only — bring your own OIDC provider.

**What it does:** Sits in front of any HTTP-transport [Model Context Protocol](https://modelcontextprotocol.io) server and gates traffic on bearer JWTs issued by your OIDC provider (Authentik, Auth0, Keycloak, Okta, Google, etc.). Allows MCP servers that were designed for local trust-the-socket use to be exposed publicly to clients like Claude.ai.

**What it does NOT do:** Issue tokens. That's your OIDC provider's job. This proxy validates tokens; it does not host login UIs or run an OAuth dance with end users.

## How it fits

The proxy advertises itself as **both** the resource server and the authorization server (RFC 8414). MCP clients (e.g. Claude.ai) discover the proxy's `/.well-known/oauth-authorization-server`, which the proxy serves by fetching the upstream IdP's metadata and passing it through — the `issuer` value is preserved as-is, so it still names the upstream. The `authorize` and `token` endpoints likewise still point at the upstream IdP, and clients follow those URLs directly. Token verification uses the upstream's JWKS (tokens carry `iss=upstream`; the JWT verifier is configured with the upstream issuer URL).

```
         ┌──────────────────┐         ┌──────────────────┐
         │   Claude.ai web  │ ──(2)──▶│  OIDC Provider   │
         │  (or any MCP     │         │  (Authentik etc) │
         │   client)        │         └──────────────────┘
         └────────┬─────────┘                  │
          (1) discovers proxy's                │ issues tokens
              .well-known/ docs                │ JWKS
                  │                            │
                  │ (3) Bearer <jwt>            │
                  ▼                            │
         ┌──────────────────┐                  │
         │  mcp-oauth-proxy │◀─── JWKS ────────┘
         │  - auth-server   │
         │    (rewrites      │
         │     issuer)       │
         │  - verifies JWT  │
         │  - allow-list    │
         │  - rate-limits   │
         └────────┬─────────┘
                  │ proxied (no auth headers)
                  ▼
         ┌──────────────────┐
         │   Your MCP       │
         │   (HTTP)         │
         └──────────────────┘
```

## Quick start

### As a Docker container

```bash
docker run --rm -p 8080:8080 \
  -e OIDC_ISSUER_URL=https://auth.example.com/application/o/my-mcp/ \
  -e OIDC_AUDIENCE=my-mcp \
  -e RESOURCE_URL=https://mcp.example.com \
  -e ALLOW_SUBS=your-user-uuid \
  -e MCP_SPAWN_CMD="npx -y your-mcp-server --transport http --port 8765" \
  -e MCP_SPAWN_PORT=8765 \
  ghcr.io/allardy/mcp-oauth-proxy:latest
```

### As an npm package (programmatic)

```bash
pnpm add @allardy/mcp-oauth-proxy
```

```ts
import { buildApp } from '@allardy/mcp-oauth-proxy'

const app = buildApp({
  issuerUrl: process.env.OIDC_ISSUER_URL!,
  audience: process.env.OIDC_AUDIENCE!,
  resourceUrl: process.env.RESOURCE_URL!,
  allowGroups: ['wiki-users'],
  upstreamUrl: 'http://127.0.0.1:8765',
  // ...remaining fields mirror the env vars below
})
app.listen(8080)
```

## Configuration

| Variable                  | Required     | Description                                                                                                                                                                                                                                                                       |
| ------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OIDC_ISSUER_URL`         | yes          | OIDC discovery URL (anything ending in / where /.well-known/openid-configuration resolves).                                                                                                                                                                                       |
| `OIDC_AUDIENCE`           | yes          | Expected `aud` claim.                                                                                                                                                                                                                                                             |
| `RESOURCE_URL`            | yes          | This proxy's public URL. Used in the protected-resource discovery doc.                                                                                                                                                                                                            |
| `ALLOW_SUBS`              | one of these | Comma-separated allow-list of token `sub` values.                                                                                                                                                                                                                                 |
| `ALLOW_EMAILS`            |              | Comma-separated allow-list of token `email` values. Only matches when the token also carries `email_verified: true` — an unverified address is attacker-chosen on any IdP that permits self-signup.                                                                               |
| `ALLOW_GROUPS`            |              | Comma-separated allow-list of group names. Matched against the token's `groups` claim; if the token carries no such claim, the group list is fetched from the issuer's `userinfo_endpoint` instead. See [Group membership](#group-membership).                                    |
| `MCP_UPSTREAM_URL`        | xor          | Existing HTTP MCP to proxy to.                                                                                                                                                                                                                                                    |
| `MCP_SPAWN_CMD`           | xor          | Command to spawn as a child process.                                                                                                                                                                                                                                              |
| `MCP_SPAWN_PORT`          | with cmd     | Port the spawned MCP listens on.                                                                                                                                                                                                                                                  |
| `PORT`                    | no           | Default 8080.                                                                                                                                                                                                                                                                     |
| `LOG_LEVEL`               | no           | `trace` to `fatal`. Default `info`.                                                                                                                                                                                                                                               |
| `RATE_LIMIT_RPM`          | no           | Per-`sub` rate limit. Default 60.                                                                                                                                                                                                                                                 |
| `CORS_ALLOW_ORIGINS`      | no           | Comma-separated allowed browser origins for CORS. Default: `https://claude.ai,https://claude.com`. Use `*` to allow any origin.                                                                                                                                                   |
| `STATIC_CLIENT_ID`        | no           | OIDC providers that don't support open DCR can use this pair. The proxy hosts a `/oauth/register` endpoint that always returns these credentials to any caller, and the `oauth-authorization-server` discovery doc advertises this endpoint. Useful for Authentik, etc.           |
| `STATIC_CLIENT_SECRET`    | no           | See `STATIC_CLIENT_ID`. Both must be set together or both left unset.                                                                                                                                                                                                             |
| `MCP_UPSTREAM_PATH`       | no           | Optional path on the upstream. All non-discovery, non-healthz, non-oauth-register requests are forwarded to `${MCP_UPSTREAM_URL}${MCP_UPSTREAM_PATH}` (or the spawned upstream URL). Use when the upstream MCP listens at a sub-path like `/mcp` but the proxy is exposed at `/`. |
| `SCOPES_SUPPORTED`        | no           | Comma-separated list of OAuth scopes the resource server supports. Advertised in both the protected-resource and auth-server discovery docs. Defaults to `openid,profile,email,offline_access`.                                                                                   |
| `GROUP_CACHE_TTL_SECONDS` | no           | How long a userinfo group lookup that admitted a request is reused. Bounded by the token's own `exp`. Default 300.                                                                                                                                                                |

## Working with OIDC providers that don't support DCR

Some OIDC providers (including Authentik 2025.10.x) don't advertise a `registration_endpoint` in their discovery doc and don't support open Dynamic Client Registration (RFC 7591). Claude.ai's "Add custom connector" flow requires DCR — if the discovery doc doesn't advertise `registration_endpoint`, it silently gives up.

**Workaround:** pre-create an OIDC application in your provider (Authentik: Applications → Providers → OAuth2/OpenID Connect), then configure the proxy with the resulting client_id and client_secret:

```bash
STATIC_CLIENT_ID=your-client-id
STATIC_CLIENT_SECRET=your-client-secret
```

The proxy will:

1. Host `POST /oauth/register` — returns your pre-configured credentials to any caller (no validation of the request body beyond parsing it).
2. Inject `registration_endpoint` into the proxy's `/.well-known/oauth-authorization-server` discovery doc (with `issuer` rewritten to the proxy's own URL) so clients see DCR as available.

The upstream provider's redirect_uri whitelist still governs which callbacks are accepted at `/authorize` time, so adding only the real Claude.ai callback URL to the whitelist is the primary security boundary.

> **Understand what this endpoint gives away.** It publishes your OIDC `client_secret` to anyone who can reach the proxy. The redirect_uri whitelist contains that only for the authorization-code flow, where the secret alone gets an attacker nowhere. It does **not** help if the same upstream client also permits a grant that involves no redirect — `client_credentials` or resource-owner password — because those can be driven with the secret directly against the token endpoint. If you enable static DCR, restrict the upstream client to `authorization_code` (plus `refresh_token`) and nothing else. Better still, if your provider supports a public client with PKCE and no secret at all, use that and leave `STATIC_CLIENT_SECRET` unset.

**Note on the issuer value:** The proxy serves `/.well-known/oauth-authorization-server` from its own URL but preserves the upstream IdP's `issuer` value verbatim, because tokens are signed by the upstream and carry the upstream's `iss` claim — clients that check the token's `iss` against the metadata's `issuer` need the two to match. This technically violates RFC 8414 §3.3, which requires `issuer` to match the URL the metadata was fetched from; a strict client would reject it. Claude.ai tolerates it today. See the comment in `src/discovery.ts` for what a stricter client would force (proxying the token endpoint and re-signing).

## Group membership

`ALLOW_GROUPS` matches against the access token's `groups` claim when the token has one. Many issuers do not put it there: OIDC claim mapping is commonly applied to the **ID token** only, and a resource server validates the **access token**, so the claim never arrives. Kanidm behaves this way, and so do others. `ALLOW_GROUPS` then looks supported while silently matching nothing.

When the token carries no `groups` claim at all, the proxy asks the issuer instead, calling the `userinfo_endpoint` from the issuer's discovery document with the caller's own token. Nothing about this is issuer-specific.

- **The token stays the source of identity.** The lookup is made with the verified token, and the `sub` in the response must match the `sub` in the token, per OpenID Connect Core §5.3.2.
- **No lookup happens unless it is needed.** A token that already carries `groups` is taken at its word, including an empty list. A request already admitted by `ALLOW_SUBS` or `ALLOW_EMAILS` never triggers one, and neither does any request when `ALLOW_GROUPS` is unset.
- **Results are cached**, keyed on the token rather than on the subject, for at most `GROUP_CACHE_TTL_SECONDS` and never past the token's `exp`. A lookup that did _not_ admit is cached for a few seconds only, so adding someone to a group takes effect promptly.
- **The endpoint must be on the issuer's own origin.** The proxy already reaches the issuer for discovery and JWKS; it will not follow an issuer document to any other host while carrying a live access token.

### Failure behaviour

A lookup that cannot be completed — issuer unreachable, non-2xx, timeout, malformed body, subject mismatch — is refused with **`503` and a `Retry-After` header**, never admitted, and never quietly downgraded to "member of nothing". A genuine non-member still gets `403`. The distinction matters: a `403` invites a client to treat a transient IdP blip as bad credentials and demand re-authentication.

### Issuer configuration

- The client must be granted the `openid` scope, or `userinfo` will reject the token.
- Whatever claim mapping produces `groups` must apply to userinfo, and must produce a **JSON array of strings**. A single space-joined string is rejected as malformed rather than read as one group.
- The userinfo response must be **unsigned JSON**. An issuer configured to return a signed (`application/jwt`) userinfo response will be refused as malformed.

## Security model

- **Resource-server only** — does not initiate OAuth flows or maintain user state.
- **Allow-list gating** — even after JWT verification, the request is rejected unless the token's `sub`, `email`, or one of its `groups` matches a configured list. Group membership may be resolved from the issuer's `userinfo` endpoint when the token does not carry it; that lookup fails closed. See [Group membership](#group-membership).
- **Per-`sub` rate limiting** — default 60 req/min as defense-in-depth. Tokens without a usable `sub` are rejected, so every admitted request is attributable and rate-limited.
- **Credentials stop here** — the caller's `Authorization` (and `Cookie`) header is stripped before the request is forwarded, so the upstream MCP never sees a live IdP access token. This matters most under `MCP_SPAWN_CMD`, where the upstream is arbitrary third-party code.
- **Audit log** — every request is logged at info level (method, path, status, latency), including the authenticated `sub` once auth has run.

**Suitable for:** personal deployments, small-team MCPs, internal tools.
**Not suitable for:** multi-tenant SaaS — allow-list and rate-limit are per-process; use a real authorization service for that.

## Examples

- [Samsung Health MCP behind Authentik](examples/samsung-health-with-authentik.md)
- [Any MCP behind Auth0](examples/generic-with-auth0.md)

## License

MIT
