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

  const buildForwardingApp = () =>
    buildApp({
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
      forwardIdentity: true,
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

  it('strips caller-supplied identity headers and forwards none by default', async () => {
    const token = await oidc.signToken({ sub: 'yann', preferred_username: 'yann.h' }, { audience: 'test-aud' })
    const res = await supertest(app)
      .get('/mcp')
      .set('authorization', `Bearer ${token}`)
      .set('x-forwarded-user', 'spoofed')
      .set('x-forwarded-preferred-username', 'spoofed')
      .set('x-forwarded-email', 'spoofed@example.com')
      .set('x-forwarded-client', 'spoofed-client')
    expect(res.status).toBe(200)
    for (const h of ['x-forwarded-user', 'x-forwarded-preferred-username', 'x-forwarded-email', 'x-forwarded-client']) {
      expect(upstream.lastHeaders()[h]).toBeUndefined()
    }
  })

  it('forwards identity headers when FORWARD_IDENTITY is on, and the caller-declared label with them', async () => {
    const forwarding = buildForwardingApp()
    const token = await oidc.signToken({ sub: 'yann', preferred_username: 'yann.h' }, { audience: 'test-aud' })
    const res = await supertest(forwarding)
      .get('/mcp')
      .set('authorization', `Bearer ${token}`)
      .set('x-forwarded-user', 'spoofed')
      .set('x-forwarded-client', 'claude-code')
    expect(res.status).toBe(200)
    expect(upstream.lastHeaders()['x-forwarded-user']).toBe('yann')
    expect(upstream.lastHeaders()['x-forwarded-preferred-username']).toBe('yann.h')
    // The one header the caller *is* the source of: what it declared, not what this proxy decided.
    expect(upstream.lastHeaders()['x-forwarded-client']).toBe('claude-code')
    // No email on this token: absent rather than empty.
    expect(upstream.lastHeaders()['x-forwarded-email']).toBeUndefined()
  })

  it('sends no client label when the caller declares none', async () => {
    const forwarding = buildForwardingApp()
    const token = await oidc.signToken({ sub: 'yann' }, { audience: 'test-aud' })
    const res = await supertest(forwarding).get('/mcp').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    // Absent, not guessed: the upstream's own default for a missing header is what should apply.
    expect(upstream.lastHeaders()['x-forwarded-client']).toBeUndefined()
  })

  it('drops a malformed client label rather than cleaning it', async () => {
    const forwarding = buildForwardingApp()
    const token = await oidc.signToken({ sub: 'yann' }, { audience: 'test-aud' })
    // Each of these is recorded verbatim by the upstream (a git author line, there): a space, an
    // angle bracket, an uppercase letter outside the pattern, and one over the length cap.
    for (const bad of ['claude code', 'a <b@c>', 'Claude-Code', 'x'.repeat(33)]) {
      const res = await supertest(forwarding).get('/mcp').set('authorization', `Bearer ${token}`).set('x-forwarded-client', bad)
      expect(res.status).toBe(200)
      expect(upstream.lastHeaders()['x-forwarded-client']).toBeUndefined()
    }
  })

  it('drops the client label when the caller sends two of them', async () => {
    const forwarding = buildForwardingApp()
    const token = await oidc.signToken({ sub: 'yann' }, { audience: 'test-aud' })
    const res = await supertest(forwarding)
      .get('/mcp')
      .set('authorization', `Bearer ${token}`)
      // Node joins these with ", ", which the pattern rejects -- so the upstream sees neither value
      // rather than a concatenation of both.
      .set('x-forwarded-client', ['claude-code', 'claude.ai'])
    expect(res.status).toBe(200)
    expect(upstream.lastHeaders()['x-forwarded-client']).toBeUndefined()
  })

  it('rejects authenticated requests for non-allowed users', async () => {
    const token = await oidc.signToken({ sub: 'someone-else' }, { audience: 'test-aud' })
    const res = await supertest(app).get('/mcp').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(403)
  })
})
