import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose'

export type JwtVerifierOptions = {
  issuerUrl: string
  audience: string
  // Minimum gap between JWKS refetches triggered by an unknown `kid`. Defaults to jose's 30s.
  // Intended for tests; setting it to 0 in production restores the amplification hole described below.
  jwksCooldownMs?: number
  // Minimum gap between retries of the OIDC-config bootstrap fetch after a failure. Defaults to 30s.
  // Intended for tests.
  bootstrapRetryMs?: number
}

// Bound the bootstrap fetch so a hung IdP can't pin every request on the await, and space out retries
// so unauthenticated garbage tokens can't drive one config fetch per request while the IdP is down.
const BOOTSTRAP_TIMEOUT_MS = 5_000
const BOOTSTRAP_RETRY_MS = 30_000

export const createJwtVerifier = (opts: JwtVerifierOptions) => {
  const configUrl = new URL('.well-known/openid-configuration', ensureTrailingSlash(opts.issuerUrl))
  const retryMs = opts.bootstrapRetryMs ?? BOOTSTRAP_RETRY_MS

  // Keep jose's default 30s cooldown between JWKS refetches. Setting it to 0 to speed up key rotation
  // lets any unauthenticated caller force one upstream JWKS fetch per request just by presenting a JWT
  // with an unknown `kid`, turning this proxy into a traffic amplifier aimed at the IdP. Rotation still
  // converges within the cooldown window.
  //
  // The JWKS handle is created lazily and re-created after a failed bootstrap: if the IdP is down when
  // the proxy starts (host reboot, compose ordering), a one-shot startup promise would stay rejected
  // forever and 401 every request until a manual restart. Concurrent requests share the in-flight
  // promise, and failures fail fast until the retry window elapses.
  let remoteJwksPromise: Promise<ReturnType<typeof createRemoteJWKSet>> | undefined
  let lastBootstrapFailureAt = 0

  const getJwks = (): Promise<ReturnType<typeof createRemoteJWKSet>> => {
    if (!remoteJwksPromise) {
      if (Date.now() - lastBootstrapFailureAt < retryMs) {
        return Promise.reject(new Error(`OIDC config fetch from ${configUrl} recently failed; retry pending`))
      }
      remoteJwksPromise = fetchJwksUri(configUrl).then((uri) =>
        createRemoteJWKSet(
          new URL(uri),
          opts.jwksCooldownMs === undefined ? {} : { cooldownDuration: opts.jwksCooldownMs },
        ),
      )
      // On failure, record the time and clear the handle so a later request can retry; this also
      // suppresses unhandled-rejection noise — the error still surfaces to each caller awaiting the
      // promise, which the auth middleware turns into a 401.
      remoteJwksPromise.catch(() => {
        lastBootstrapFailureAt = Date.now()
        remoteJwksPromise = undefined
      })
    }
    return remoteJwksPromise
  }

  return async (token: string): Promise<JWTPayload> => {
    const jwks = await getJwks()
    // Accept both trailing-slash and stripped forms — Authentik issues tokens with the trailing slash,
    // older OIDC servers strip it. jose's `issuer` field accepts an array of acceptable strings.
    const { payload } = await jwtVerify(token, jwks, {
      issuer: [opts.issuerUrl, opts.issuerUrl.replace(/\/$/, '')],
      audience: opts.audience,
      algorithms: ALLOWED_ALGS,
    })
    return payload
  }
}

// Asymmetric signature algorithms only — never HMAC (`HS*`) or `none`, so a symmetric or malformed
// entry appearing in the upstream JWKS can't be used to forge a token the proxy would accept.
// EdDSA (Ed25519/Ed448) is asymmetric and offered by several IdPs (Keycloak, Authentik), so it belongs here.
const ALLOWED_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA']

const ensureTrailingSlash = (url: string): string => (url.endsWith('/') ? url : `${url}/`)

const fetchJwksUri = async (configUrl: URL): Promise<string> => {
  const res = await fetch(configUrl, { signal: AbortSignal.timeout(BOOTSTRAP_TIMEOUT_MS) })
  if (!res.ok) throw new Error(`failed to fetch OIDC config from ${configUrl}: ${res.status}`)
  const json = (await res.json()) as { jwks_uri?: string }
  if (!json.jwks_uri) throw new Error(`OIDC config at ${configUrl} missing jwks_uri`)
  return json.jwks_uri
}
