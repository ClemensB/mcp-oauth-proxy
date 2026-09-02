import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createJwtVerifier } from '../src/jwt.js'
import { startOidcFixture, type OidcFixture } from './fixtures/oidc-server.js'

describe('createJwtVerifier', () => {
  let oidc: OidcFixture

  beforeAll(async () => {
    oidc = await startOidcFixture()
  })

  afterAll(async () => {
    await oidc.close()
  })

  it('verifies a valid token', async () => {
    const verify = createJwtVerifier({ issuerUrl: oidc.issuerUrl, audience: 'test-aud' })
    const token = await oidc.signToken({ sub: 'user-1' }, { audience: 'test-aud' })
    const claims = await verify(token)
    expect(claims.sub).toBe('user-1')
  })

  it('rejects a token with wrong audience', async () => {
    const verify = createJwtVerifier({ issuerUrl: oidc.issuerUrl, audience: 'expected-aud' })
    const token = await oidc.signToken({ sub: 'user-1' }, { audience: 'other-aud' })
    await expect(verify(token)).rejects.toThrow()
  })

  it('rejects a token with wrong issuer', async () => {
    const verify = createJwtVerifier({ issuerUrl: 'https://different.example.com', audience: 'test-aud' })
    const token = await oidc.signToken({ sub: 'user-1' }, { audience: 'test-aud' })
    await expect(verify(token)).rejects.toThrow()
  })

  it('rejects an expired token', async () => {
    const verify = createJwtVerifier({ issuerUrl: oidc.issuerUrl, audience: 'test-aud' })
    const token = await oidc.signToken({ sub: 'user-1' }, { audience: 'test-aud', expiresIn: '-1s' })
    await expect(verify(token)).rejects.toThrow()
  })

  it('refreshes JWKS after key rotation', async () => {
    // Explicit short cooldown: the production default (jose's 30s) deliberately rate-limits refetches,
    // so rotation would not converge inside a test.
    const verify = createJwtVerifier({ issuerUrl: oidc.issuerUrl, audience: 'test-aud', jwksCooldownMs: 0 })
    const before = await oidc.signToken({ sub: 'user-1' }, { audience: 'test-aud' })
    await verify(before)

    await oidc.rotateKey()
    const after = await oidc.signToken({ sub: 'user-2' }, { audience: 'test-aud' })
    const claims = await verify(after)
    expect(claims.sub).toBe('user-2')
  })

  it('accepts EdDSA (Ed25519) signed tokens', async () => {
    // The algorithm allowlist pins asymmetric algs; EdDSA is asymmetric and used by real IdPs —
    // omitting it silently locks out every user of an Ed25519-signing issuer.
    const ed = await startOidcFixture('EdDSA')
    try {
      const verify = createJwtVerifier({ issuerUrl: ed.issuerUrl, audience: 'test-aud' })
      const token = await ed.signToken({ sub: 'user-1' }, { audience: 'test-aud' })
      const claims = await verify(token)
      expect(claims.sub).toBe('user-1')
    } finally {
      await ed.close()
    }
  })

  it('rejects malformed tokens', async () => {
    const verify = createJwtVerifier({ issuerUrl: oidc.issuerUrl, audience: 'test-aud' })
    await expect(verify('not.a.jwt')).rejects.toThrow()
  })
})
