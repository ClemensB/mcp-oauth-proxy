import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import supertest from 'supertest'
import { buildApp } from '../src/index.js'
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

  it('strips Authorization and Cookie before proxying', async () => {
    const token = await oidc.signToken({ sub: 'allowed-user' }, { audience: 'test-aud' })
    const res = await supertest(appFor(oidc, upstream))
      .post('/x')
      .set('authorization', `Bearer ${token}`)
      .set('cookie', 'session=secret')
      .send({ jsonrpc: '2.0', id: 1 })
    expect(res.status).toBe(200)
    expect(upstream.lastHeaders()['authorization']).toBeUndefined()
    expect(upstream.lastHeaders()['cookie']).toBeUndefined()
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
