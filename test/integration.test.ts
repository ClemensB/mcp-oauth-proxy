import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import supertest from 'supertest'
import { buildApp } from '../src/index.js'
import { startOidcFixture, type OidcFixture } from './fixtures/oidc-server.js'
import { startMcpUpstream, type McpUpstreamFixture } from './fixtures/mcp-upstream.js'

describe('mcp-oauth-proxy integration', () => {
  let oidc: OidcFixture
  let upstream: McpUpstreamFixture
  let app: ReturnType<typeof buildApp>

  beforeAll(async () => {
    oidc = await startOidcFixture()
    upstream = await startMcpUpstream()
    app = buildApp({
      issuerUrl: oidc.issuerUrl,
      audience: 'test-aud',
      resourceUrl: 'https://mcp.example.com',
      allowSubs: ['yann'],
      allowEmails: [],
      allowGroups: [],
      upstreamUrl: upstream.url,
      rateLimitRpm: 600,
      allowOrigins: [],
      staticClientId: undefined,
      staticClientSecret: undefined,
      upstreamPath: undefined,
    })
  })

  afterAll(async () => {
    await oidc.close()
    await upstream.close()
  })

  it('serves discovery without auth', async () => {
    const res = await supertest(app).get('/.well-known/oauth-protected-resource')
    expect(res.status).toBe(200)
    expect(res.body.resource).toBe('https://mcp.example.com')
  })

  it('serves /healthz without auth', async () => {
    const res = await supertest(app).get('/healthz')
    expect(res.status).toBe(200)
  })

  it('rejects unauthenticated MCP calls', async () => {
    const res = await supertest(app).get('/mcp')
    expect(res.status).toBe(401)
  })

  it('forwards authenticated requests to upstream', async () => {
    const token = await oidc.signToken({ sub: 'yann' }, { audience: 'test-aud' })
    const res = await supertest(app).get('/mcp').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    expect(res.body).toMatchObject({ ok: true, path: '/mcp', method: 'GET' })
  })

  it('forwards identity headers the proxy sets and drops any the caller sent', async () => {
    const token = await oidc.signToken({ sub: 'yann', preferred_username: 'yann.h' }, { audience: 'test-aud' })
    const res = await supertest(app)
      .get('/mcp')
      .set('authorization', `Bearer ${token}`)
      .set('x-wiki-client', 'spoofed-client')
      .set('x-wiki-user', 'spoofed-user')
      .set('x-wiki-user-id', 'spoofed-id')
    expect(res.status).toBe(200)
    expect(upstream.lastHeaders()['x-wiki-user-id']).toBe('yann')
    expect(upstream.lastHeaders()['x-wiki-user']).toBe('yann.h')
    // No CLIENT_LABEL on this app: the header is absent, not the caller's value.
    expect(upstream.lastHeaders()['x-wiki-client']).toBeUndefined()
  })

  it('sends CLIENT_LABEL as x-wiki-client when configured', async () => {
    const labelled = buildApp({
      issuerUrl: oidc.issuerUrl,
      audience: 'test-aud',
      resourceUrl: 'https://mcp.example.com',
      allowSubs: ['yann'],
      allowEmails: [],
      allowGroups: [],
      upstreamUrl: upstream.url,
      rateLimitRpm: 600,
      allowOrigins: [],
      staticClientId: undefined,
      staticClientSecret: undefined,
      upstreamPath: undefined,
      clientLabel: 'claude.ai',
    })
    const token = await oidc.signToken({ sub: 'yann' }, { audience: 'test-aud' })
    const res = await supertest(labelled).get('/mcp').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    expect(upstream.lastHeaders()['x-wiki-client']).toBe('claude.ai')
    // No preferred_username on this token and no lookup ran: no x-wiki-user, but the id is always there.
    expect(upstream.lastHeaders()['x-wiki-user']).toBeUndefined()
    expect(upstream.lastHeaders()['x-wiki-user-id']).toBe('yann')
  })

  it('rejects authenticated requests for non-allowed users', async () => {
    const token = await oidc.signToken({ sub: 'someone-else' }, { audience: 'test-aud' })
    const res = await supertest(app).get('/mcp').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(403)
  })
})
