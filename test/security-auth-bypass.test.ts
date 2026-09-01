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

describe('public routes are not an unauthenticated path to the upstream', () => {
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

  // Each of these once fell through the auth middleware's path exemptions into the catch-all proxy.
  const bypasses = ['/healthz', '/.well-known/anything', '/.well-known/oauth-protected-resource', '/oauth/register']

  for (const path of bypasses) {
    it(`POST ${path} without a token does not reach the upstream`, async () => {
      const res = await supertest(appFor(oidc, upstream))
        .post(path)
        .send({ jsonrpc: '2.0', method: 'tools/list', id: 1 })
      expect(res.status).toBe(401)
      expect(res.body.ok).toBeUndefined()
    })
  }

  it('still serves the public GET routes it is meant to serve', async () => {
    const a = appFor(oidc, upstream)
    expect((await supertest(a).get('/healthz')).status).toBe(200)
    expect((await supertest(a).get('/.well-known/oauth-protected-resource')).status).toBe(200)
    expect((await supertest(a).get('/.well-known/oauth-authorization-server')).status).toBe(200)
  })

  it('rate-limits a token allow-listed by group rather than by sub', async () => {
    const a = appFor(oidc, upstream, { allowSubs: [], allowGroups: ['admins'], rateLimitRpm: 1 })
    const token = await oidc.signToken({ sub: 'group-user', groups: ['admins'] }, { audience: 'test-aud' })
    const statuses: number[] = []
    for (let i = 0; i < 5; i++) {
      statuses.push((await supertest(a).post('/x').set('authorization', `Bearer ${token}`).send({})).status)
    }
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0)
  })
})
