import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose'

export type JwtVerifierOptions = {
  issuerUrl: string
  audience: string
  // Minimum gap between JWKS refetches triggered by an unknown `kid`. Defaults to jose's 30s.
  // Intended for tests; setting it to 0 in production restores the amplification hole described below.
  jwksCooldownMs?: number
}

export const createJwtVerifier = (opts: JwtVerifierOptions) => {
  const configUrl = new URL('.well-known/openid-configuration', ensureTrailingSlash(opts.issuerUrl))
  // Keep jose's default 30s cooldown between JWKS refetches. Setting it to 0 to speed up key rotation
  // lets any unauthenticated caller force one upstream JWKS fetch per request just by presenting a JWT
  // with an unknown `kid`, turning this proxy into a traffic amplifier aimed at the IdP. Rotation still
  // converges within the cooldown window.
  const remoteJwksPromise = fetchJwksUri(configUrl).then((uri) =>
    createRemoteJWKSet(
      new URL(uri),
      opts.jwksCooldownMs === undefined ? {} : { cooldownDuration: opts.jwksCooldownMs },
    ),
  )
  // Suppress unhandled-rejection at construction time; the error surfaces properly
  // when `verify()` is called and `await remoteJwksPromise` re-throws inside the
  // auth middleware's try/catch, returning 401 instead of crashing the process.
  remoteJwksPromise.catch(() => undefined)

  return async (token: string): Promise<JWTPayload> => {
    const jwks = await remoteJwksPromise
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
const ALLOWED_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512']

const ensureTrailingSlash = (url: string): string => (url.endsWith('/') ? url : `${url}/`)

const fetchJwksUri = async (configUrl: URL): Promise<string> => {
  const res = await fetch(configUrl)
  if (!res.ok) throw new Error(`failed to fetch OIDC config from ${configUrl}: ${res.status}`)
  const json = (await res.json()) as { jwks_uri?: string }
  if (!json.jwks_uri) throw new Error(`OIDC config at ${configUrl} missing jwks_uri`)
  return json.jwks_uri
}
