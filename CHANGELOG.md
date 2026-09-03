# Changelog

## 0.4.1

Hardening follow-up to 0.4.0. Availability fixes around the two unauthenticated IdP-fetch paths, plus header-hygiene and audit-log corrections.

- **fix(jwt): bound and retry the OIDC-config bootstrap.** The fetch of `.well-known/openid-configuration` had no timeout and ran once at startup; an IdP that was down or hung when the proxy booted either blocked every request or poisoned the verifier permanently (all tokens 401 until restart). The fetch is now bounded to 5s, shared across concurrent requests, and retried after failure with a 30s cooldown.
- **fix(jwt): allow EdDSA.** The asymmetric-only algorithm pinning omitted EdDSA, silently locking out every user of an Ed25519-signing issuer.
- **fix(discovery): close the remaining metadata amplification.** Concurrent cold-cache hits each made their own IdP request, and failures were never cached — so during an IdP incident the endpoint reverted to one outbound request per anonymous hit. Concurrent misses now share one in-flight fetch; failures are negatively cached for 5s.
- **fix(proxy): strip `Proxy-Authorization`** alongside `Authorization` and `Cookie`, and enable `xfwd` so the real peer address is appended to `X-Forwarded-*` — a caller can no longer be the last word on its own source address to an upstream that trusts those headers.
- **fix(log): `hasAuth` was read after the proxy stripped the Authorization header**, logging every authenticated proxied request as tokenless and inverting the audit trail. It is now captured when the request enters the stack.

## 0.4.0

Security release. Anyone running 0.3.x should upgrade; the first item below is exploitable without any token.

- **fix(auth): unauthenticated requests could reach the upstream MCP.** The auth middleware skipped any path starting with `/.well-known/`, plus `/healthz` and `/oauth/register`. Those exemptions called `next()`, which continued down the stack into the catch-all proxy rather than ending the request — so `POST /healthz`, `POST /.well-known/anything`, and (when static DCR was unconfigured) `POST /oauth/register` were forwarded to the upstream with no token, no allow-list check, and no rate limit. With `MCP_UPSTREAM_PATH` set — as in the README's own example — the rewrite pointed them straight at the MCP endpoint. The exemptions were also unnecessary: the public routes are registered above the auth middleware and answer their own requests.
- **fix(proxy): stop forwarding the caller's `Authorization` header upstream.** The README already described the upstream as receiving no auth headers; it was in fact receiving the user's bearer token, which under `MCP_SPAWN_CMD` hands a live IdP access token to arbitrary third-party code. `Cookie` is stripped too.
- **fix(jwt): restore jose's JWKS refetch cooldown.** `cooldownDuration: 0` let any anonymous caller force one upstream JWKS fetch per request by presenting a JWT with an unknown `kid`, using the proxy to amplify traffic at the IdP. The cooldown is now jose's 30s default, exposed as `jwksCooldownMs` for tests.
- **fix(auth): require `email_verified` for `ALLOW_EMAILS` matches.** On an IdP permitting self-signup, an unverified `email` claim is attacker-chosen, so an allow-listed address could be claimed by anyone.
- **fix(auth): reject tokens with no usable `sub`.** Such a token could be admitted via the group or email allow-list, then bypass the rate limiter entirely (keyed on `sub`) and appear unattributed in the audit log.
- **fix(jwt): pin verification to asymmetric algorithms**, so a symmetric or malformed JWKS entry can't be used to forge an accepted token.
- **fix(discovery): cache upstream metadata (5 min) and bound the fetch (5s)** — this endpoint is unauthenticated and made one outbound request per hit.
- **fix(proxy): preserve the query string** when rewriting to `MCP_UPSTREAM_PATH`.
- **feat(logging): include the authenticated `sub`** in the per-request log line, making the documented audit trail actually attributable.
- **docs:** correct the README's description of `issuer` handling, which still described pre-0.3.1 behaviour, and spell out the exposure created by the static DCR endpoint.

## 0.3.3

- fix: scope `express.json()` to `/oauth/register` only — global body parser was draining proxied request bodies before http-proxy-3 could forward them, causing upstream MCP to see "request aborted"

## 0.3.2

- fix: accept JWT `iss` claim with or without trailing slash — Authentik appends a trailing `/` to issuer URLs; jose's exact-match rejected the stripped-slash form

## 0.3.1

- fix: preserve upstream `issuer` in proxied `/.well-known/oauth-authorization-server` metadata — previous version rewrote it to the proxy URL, which broke JWT validation because tokens are still signed by the upstream IdP with its own `iss`

## 0.3.0

- feat: proxy advertises itself as the authorization server (`authorization_servers` self-references); MCP clients fetch `/.well-known/oauth-authorization-server` from the proxy rather than going directly to the upstream IdP
- feat: RFC 6750 error params in `WWW-Authenticate` response header on 401s

## 0.2.0

- feat: static DCR shim — `POST /oauth/register` returns pre-configured `STATIC_CLIENT_ID`/`STATIC_CLIENT_SECRET` for OIDC providers that don't support open Dynamic Client Registration (e.g. Authentik); `registration_endpoint` is injected into the auth-server discovery doc when the pair is set
- feat: `MCP_UPSTREAM_PATH` — optional path suffix forwarded to the upstream MCP when it doesn't listen at root (e.g. `/mcp`)

## 0.1.2

- feat: per-request structured logging (method, path, status, latency, origin, UA) for easier debugging

## 0.1.1

- fix: CORS support — Claude.ai is a browser-context client; OPTIONS preflights were getting 401'd before this

## 0.1.0

- Initial release: JWT verification via OIDC discovery + JWKS, allow-list gating (sub / email / group), protected-resource discovery doc, per-sub rate limiting, HTTP proxy and process-spawn modes, Dockerfile, CI/release pipeline
