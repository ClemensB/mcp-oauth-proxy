import { describe, expect, it } from 'vitest'
import supertest from 'supertest'
import { createServer, type Server } from 'node:http'
import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose'
import { buildApp } from '../src/index.js'
import { createJwtVerifier } from '../src/jwt.js'
import { startMcpUpstream } from './fixtures/mcp-upstream.js'

describe('JWKS refetch cooldown', () => {
  it('does not refetch the IdP JWKS once per unknown-kid token', async () => {
    // Counting IdP: an anonymous caller must not be able to drive one upstream fetch per request.
    const upstream = await startMcpUpstream()
    const { privateKey, publicKey } = await generateKeyPair('RS256')
    const jwk: JWK & { kid: string } = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }
    let jwksHits = 0
    const idp: Server = createServer((req, res) => {
      const issuer = `http://127.0.0.1:${(idp.address() as { port: number }).port}`
      if (req.url?.startsWith('/.well-known/openid-configuration')) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ issuer, jwks_uri: `${issuer}/jwks` }))
        return
      }
      if (req.url === '/jwks') {
        jwksHits++
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ keys: [jwk] }))
        return
      }
      res.writeHead(404)
      res.end()
    })
    await new Promise<void>((r) => idp.listen(0, '127.0.0.1', r))
    const issuerUrl = `http://127.0.0.1:${(idp.address() as { port: number }).port}`

    try {
      const a = buildApp({
        issuerUrl,
        audience: 'test-aud',
        resourceUrl: 'https://mcp.example.com',
        allowSubs: ['allowed-user'],
        allowEmails: [],
        allowGroups: [],
        upstreamUrl: upstream.url,
        rateLimitRpm: 60,
        allowOrigins: [],
        staticClientId: undefined,
        staticClientSecret: undefined,
        upstreamPath: '/mcp',
      })
      for (let i = 0; i < 10; i++) {
        const token = await new SignJWT({ sub: 'allowed-user' })
          .setProtectedHeader({ alg: 'RS256', kid: `unknown-kid-${i}` })
          .setIssuer(issuerUrl)
          .setIssuedAt()
          .setExpirationTime('5m')
          .setAudience('test-aud')
          .sign(privateKey)
        const res = await supertest(a).post('/x').set('authorization', `Bearer ${token}`).send({})
        expect(res.status).toBe(401)
      }
      // One initial fetch plus at most one cooldown-permitted refetch — not one per request.
      expect(jwksHits).toBeLessThanOrEqual(2)
    } finally {
      await new Promise<void>((res2, rej) => idp.close((e) => (e ? rej(e) : res2())))
      await upstream.close()
    }
  })
})

describe('OIDC config bootstrap', () => {
  it('recovers once the IdP comes back after being down at first verification', async () => {
    // Reserve a port, then release it so the verifier's first bootstrap attempt hits a dead address —
    // the docker-compose/host-reboot ordering where the IdP is not up yet when the proxy starts.
    const placeholder = createServer()
    await new Promise<void>((r) => placeholder.listen(0, '127.0.0.1', r))
    const port = (placeholder.address() as { port: number }).port
    await new Promise<void>((res2, rej) => placeholder.close((e) => (e ? rej(e) : res2())))
    const issuerUrl = `http://127.0.0.1:${port}`

    const { privateKey, publicKey } = await generateKeyPair('RS256')
    const jwk: JWK & { kid: string } = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }
    const token = await new SignJWT({ sub: 'user-1' })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuer(issuerUrl)
      .setIssuedAt()
      .setExpirationTime('5m')
      .setAudience('test-aud')
      .sign(privateKey)

    const verify = createJwtVerifier({ issuerUrl, audience: 'test-aud', bootstrapRetryMs: 0 })
    await expect(verify(token)).rejects.toThrow()

    const idp: Server = createServer((req, res) => {
      if (req.url?.startsWith('/.well-known/openid-configuration')) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ issuer: issuerUrl, jwks_uri: `${issuerUrl}/jwks` }))
        return
      }
      if (req.url === '/jwks') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ keys: [jwk] }))
        return
      }
      res.writeHead(404)
      res.end()
    })
    await new Promise<void>((r) => idp.listen(port, '127.0.0.1', r))
    try {
      // Before the fix the startup promise stayed rejected forever and this second call could never succeed.
      const claims = await verify(token)
      expect(claims.sub).toBe('user-1')
    } finally {
      await new Promise<void>((res2, rej) => idp.close((e) => (e ? rej(e) : res2())))
    }
  })

  it('does not refetch the OIDC config per request while bootstrap keeps failing', async () => {
    let configHits = 0
    const idp: Server = createServer((_req, res) => {
      configHits++
      res.writeHead(500)
      res.end()
    })
    await new Promise<void>((r) => idp.listen(0, '127.0.0.1', r))
    const issuerUrl = `http://127.0.0.1:${(idp.address() as { port: number }).port}`
    try {
      // Default retry cooldown: the second verify must fail fast without another upstream fetch,
      // otherwise unauthenticated garbage tokens drive one IdP request each while the IdP is degraded.
      const verify = createJwtVerifier({ issuerUrl, audience: 'test-aud' })
      await expect(verify('not.a.jwt')).rejects.toThrow()
      await expect(verify('not.a.jwt')).rejects.toThrow()
      expect(configHits).toBe(1)
    } finally {
      await new Promise<void>((res2, rej) => idp.close((e) => (e ? rej(e) : res2())))
    }
  })
})
