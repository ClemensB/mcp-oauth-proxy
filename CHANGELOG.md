# Changelog

## 0.5.0

Feature release: `ALLOW_GROUPS` now works against issuers whose access tokens carry no `groups` claim. Also raises the Node floor and brings every dependency current.

**Upgrading:** this release requires **Node 22.13 or newer** (previously 20). The published Docker image is built on `node:22-alpine`. Nothing else in the configuration changes; no new variable is required.

- **feat(auth): resolve group membership from the issuer's `userinfo` endpoint.** `ALLOW_GROUPS` matched only against the access token's `groups` claim. Many issuers apply OIDC claim mapping to the ID token alone, and a resource server validates the access token — so the claim never arrived and the option was permanently non-functional while still looking supported. When, and only when, the token carries no `groups` claim, the proxy now asks the issuer with the caller's own token. A token that already carries the claim is taken at its word (empty list included), a request already admitted by `ALLOW_SUBS` or `ALLOW_EMAILS` never triggers a lookup, and neither does anything when `ALLOW_GROUPS` is unset.
  - The userinfo `sub` must match the token's `sub` (OIDC Core §5.3.2), and the endpoint must be on the issuer's own origin — the proxy will not follow an issuer document to another host while carrying a live access token.
  - Lookups are cached keyed on a hash of the token rather than on the subject, since two tokens for one person may carry different grants. Entries never outlive the token's `exp`, are bounded by the new `GROUP_CACHE_TTL_SECONDS` (default 300), and a result that did _not_ admit is held for seconds only, so adding someone to a group takes effect promptly.
  - **A lookup that cannot be completed answers `503` with `Retry-After`, never `403` and never an empty group list.** An unreachable dependency is not the same event as a user who is not a member, and a `403` invites a client to treat a transient IdP blip as bad credentials and demand re-authentication. An absent `groups` claim in an otherwise well-formed response is not a failure: it means membership of nothing, and is a plain `403`.
- **refactor(discovery): extract the issuer-metadata fetcher.** The cache, in-flight coalescing and negative-cache window added in 0.4.1 were closure state inside `mountDiscovery`. They are now a module that the discovery endpoint and the group lookup share, so the two paths use one cache and one in-flight request between them rather than opening a second route to the IdP.
- **build: raise the pnpm floor to 11 and the Node floor to 22.** nixpkgs marks the whole pnpm 9 line insecure (seven CVEs). The published artifact was never exposed, but anyone building this fork the documented way got a vulnerable toolchain. pnpm 11 requires Node 22.13+, so the Docker base image, CI and `engines.node` move together. `pnpm-workspace.yaml` declares the one dependency whose install script pnpm 11 would otherwise treat as a hard error.
- **build(deps): everything current.** `jose` 5 → 6, `http-proxy-3` 1 → 2, `pino` 9 → 10, `zod` 4.4 → 4.5, `vitest` 2 → 4, `typescript` 6 → 7, plus lockfile-only fixes for `body-parser`, `qs` and `form-data`. `pnpm audit` goes from fourteen findings to one dev-only advisory (esbuild under tsx, which tsx still pins below the patched release); the production tree is clean. The runtime bumps landed after the feature so the full suite, not the bump itself, certified them. `@types/node` deliberately stays on the 22 line to match the runtime floor.
- **chore(nix): add a flake dev shell.** `nix develop` provides node and pnpm at the versions this package targets.

Tests: 72 → 106.

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
