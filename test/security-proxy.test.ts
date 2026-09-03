import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import supertest from 'supertest'
import { buildApp } from '../src/index.js'
import { logger } from '../src/logger.js'
import { startOidcFixture, type OidcFixture } from './fixtures/oidc-server.js'
import { startMcpUpstream, type McpUpstreamFixture } from './fixtures/mcp-upstream.js'

const appFor = (oidc: OidcFixture, upstream: McpUpstreamFixture, over: Record<string, unknown> = {}) =>
  buildApp({
    issuerUrl: oidc.issuerUrl,
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
    // Set because it is the configuration the README's own example uses, and the one in which a
    // path-based auth skip forwards straight to the upstream's MCP endpoint.
    upstreamPath: '/mcp',
    ...over,
  } as Parameters<typeof buildApp>[0])

describe('credentials are not forwarded to the upstream', () => {
  let oidc: OidcFixture
  let upstream: McpUpstreamFixture

  beforeAll(async () => {
    oidc = await startOidcFixture()
    upstream = await startMcpUpstream()
  })
  afterAll(async () => {
    await oidc.close()
    await upstream.close()
  })

  it('strips Authorization, Proxy-Authorization and Cookie before proxying', async () => {
    const token = await oidc.signToken({ sub: 'allowed-user' }, { audience: 'test-aud' })
    const res = await supertest(appFor(oidc, upstream))
      .post('/x')
      .set('authorization', `Bearer ${token}`)
      .set('proxy-authorization', 'Basic c2VjcmV0OnNlY3JldA==')
      .set('cookie', 'session=secret')
      .send({ jsonrpc: '2.0', id: 1 })
    expect(res.status).toBe(200)
    expect(upstream.lastHeaders()['authorization']).toBeUndefined()
    expect(upstream.lastHeaders()['proxy-authorization']).toBeUndefined()
    expect(upstream.lastHeaders()['cookie']).toBeUndefined()
  })

  it('appends the real peer address to X-Forwarded-For instead of letting the caller be the last word', async () => {
    const token = await oidc.signToken({ sub: 'allowed-user' }, { audience: 'test-aud' })
    const res = await supertest(appFor(oidc, upstream))
      .post('/x')
      .set('authorization', `Bearer ${token}`)
      .set('x-forwarded-for', '10.0.0.1')
      .send({})
    expect(res.status).toBe(200)
    const xff = upstream.lastHeaders()['x-forwarded-for'] as string
    // Client-supplied value stays in the chain, but the socket's address is appended after it, so an
    // upstream trusting the rightmost hop sees the real peer, not the spoofed one.
    expect(xff.startsWith('10.0.0.1,')).toBe(true)
    expect(xff).not.toBe('10.0.0.1')
  })

  it('audit log records hasAuth:true for authenticated proxied requests', async () => {
    const spy = vi.spyOn(logger, 'info')
    try {
      const token = await oidc.signToken({ sub: 'allowed-user' }, { audience: 'test-aud' })
      const res = await supertest(appFor(oidc, upstream)).post('/x').set('authorization', `Bearer ${token}`).send({})
      expect(res.status).toBe(200)
      // The 'finish' handler that writes the request log runs on the server side; yield once so it has fired.
      await new Promise((r) => setImmediate(r))
      const call = spy.mock.calls.find((c) => c[1] === 'request')
      // Before the fix, the header was read at 'finish' — after the proxy stripped it — so every
      // authenticated proxied request logged hasAuth:false.
      expect(call && (call[0] as { hasAuth?: boolean }).hasAuth).toBe(true)
    } finally {
      spy.mockRestore()
    }
  })

  it('preserves the query string when rewriting to upstreamPath', async () => {
    const token = await oidc.signToken({ sub: 'allowed-user' }, { audience: 'test-aud' })
    const res = await supertest(appFor(oidc, upstream))
      .post('/x?foo=bar')
      .set('authorization', `Bearer ${token}`)
      .send({})
    expect(res.status).toBe(200)
    expect(res.body.path).toBe('/mcp?foo=bar')
  })
})
