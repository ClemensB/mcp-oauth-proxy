import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import supertest from 'supertest'
import { buildApp } from '../src/index.js'
import { startOidcFixture, type OidcFixture, type UserinfoMode } from './fixtures/oidc-server.js'
import { startMcpUpstream, type McpUpstreamFixture } from './fixtures/mcp-upstream.js'

// Inverted proof-of-concept for the group lookup's failure behaviour.
//
// The tempting implementation of "ask the IdP which groups this user is in" is
// `catch { return [] }` — swallow the error and carry on with an empty list. That reads as a safe
// default because it denies the request, and it is wrong twice over: it reports an outage as though
// the user had been deliberately removed from the group, and it does so with a 403 that a connector
// may take as "your credentials are bad, re-authenticate" over what was a transient blip.
//
// Every case below therefore asserts the exact status, not merely that access was denied. A lookup
// that could not be completed must be 503; only a completed lookup that found no allow-listed group
// may be 403. A `catch { return [] }` implementation passes "was it denied" and fails every one of
// these.
const appFor = (oidc: OidcFixture, upstream: McpUpstreamFixture, over: Record<string, unknown> = {}) =>
  buildApp({
    issuerUrl: oidc.issuerUrl,
    audience: 'test-aud',
    resourceUrl: 'https://mcp.example.com',
    allowSubs: [],
    allowEmails: [],
    allowGroups: ['wiki-users'],
    upstreamUrl: upstream.url,
    rateLimitRpm: 60,
    allowOrigins: [],
    staticClientId: undefined,
    staticClientSecret: undefined,
    upstreamPath: '/mcp',
    ...over,
  } as Parameters<typeof buildApp>[0])

describe('a group lookup that cannot be completed refuses, and says so as an outage', () => {
  let oidc: OidcFixture
  let upstream: McpUpstreamFixture

  beforeAll(async () => {
    oidc = await startOidcFixture()
    upstream = await startMcpUpstream()
    oidc.setGroups('member', ['wiki-users'])
    oidc.setGroups('outsider', ['some-other-group'])
  })

  afterAll(async () => {
    await oidc.close()
    await upstream.close()
  })

  beforeEach(() => {
    oidc.setUserinfoMode('ok')
    oidc.setUserinfoEndpoint(`${oidc.issuerUrl}/userinfo`)
  })

  const brokenModes: Array<[UserinfoMode, string]> = [
    ['unauthorized', 'userinfo rejects the token'],
    ['server-error', 'userinfo returns 5xx'],
    ['not-json', 'userinfo returns a signed (JWT) body rather than JSON'],
    ['not-object', 'userinfo returns JSON that is not an object'],
    ['wrong-sub', 'userinfo answers about a different subject'],
    ['groups-string', 'groups arrives space-joined rather than as an array'],
    ['groups-mixed', 'the groups array contains a non-string'],
    ['drop', 'the connection is dropped mid-request'],
  ]

  for (const [mode, description] of brokenModes) {
    it(`refuses with 503 and never reaches the upstream when ${description}`, async () => {
      oidc.setUserinfoMode(mode)
      const token = await oidc.signToken({ sub: 'member' }, { audience: 'test-aud' })
      const res = await supertest(appFor(oidc, upstream))
        .post('/anything')
        .set('authorization', `Bearer ${token}`)
        .send({ jsonrpc: '2.0', method: 'tools/list', id: 1 })
      expect(res.status).toBe(503)
      expect(res.headers['retry-after']).toBe('5')
      expect(res.body.ok).toBeUndefined()
    })
  }

  it('refuses with 503 when the issuer advertises no userinfo_endpoint', async () => {
    oidc.setUserinfoEndpoint(null)
    const token = await oidc.signToken({ sub: 'member' }, { audience: 'test-aud' })
    const res = await supertest(appFor(oidc, upstream))
      .post('/anything')
      .set('authorization', `Bearer ${token}`)
      .send({})
    expect(res.status).toBe(503)
    expect(res.body.ok).toBeUndefined()
  })

  it('refuses with 503 rather than sending the token to a userinfo_endpoint off the issuer origin', async () => {
    // The proxy already reaches the issuer for discovery and JWKS. Following an issuer document to
    // some other host would be new outbound reachability, carrying the caller's live access token.
    oidc.setUserinfoEndpoint('https://elsewhere.example.com/userinfo')
    const token = await oidc.signToken({ sub: 'member' }, { audience: 'test-aud' })
    const before = oidc.userinfoCalls()
    const res = await supertest(appFor(oidc, upstream))
      .post('/anything')
      .set('authorization', `Bearer ${token}`)
      .send({})
    expect(res.status).toBe(503)
    expect(oidc.userinfoCalls()).toBe(before)
  })

  it('keeps 403 for the case it is actually about: a completed lookup finding no allow-listed group', async () => {
    const token = await oidc.signToken({ sub: 'outsider' }, { audience: 'test-aud' })
    const res = await supertest(appFor(oidc, upstream))
      .post('/anything')
      .set('authorization', `Bearer ${token}`)
      .send({})
    expect(res.status).toBe(403)
    expect(res.headers['retry-after']).toBeUndefined()
    expect(res.body.ok).toBeUndefined()
  })

  it('admits and proxies when the lookup succeeds and the group is allow-listed', async () => {
    const token = await oidc.signToken({ sub: 'member' }, { audience: 'test-aud' })
    const res = await supertest(appFor(oidc, upstream))
      .post('/anything')
      .set('authorization', `Bearer ${token}`)
      .send({})
    expect(res.status).toBe(200)
    expect(res.body.ok).toBe(true)
    // The upstream is behind this proxy and validates nothing; it must never receive the credential.
    expect(upstream.lastHeaders()['authorization']).toBeUndefined()
  })
})
