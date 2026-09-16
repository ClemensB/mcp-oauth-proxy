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

  // A 401/403 from userinfo is not here: that is the issuer rejecting the token, not an outage — see
  // the next describe block. Other 4xx are here: they point at this proxy's configuration, and telling
  // the client to re-authenticate would only loop.
  const brokenModes: Array<[UserinfoMode, string]> = [
    ['bad-request', 'userinfo answers 400'],
    ['not-found', 'userinfo answers 404'],
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

// A token can verify locally and still be dead: the issuer ended or revoked the session behind it, and
// only an issuer endpoint can say so. Measured on Kanidm: /userinfo answers 401 ("the parent oauth2
// session associated to this token is revoked") while the JWT's signature and exp are still good.
// Answering that with 503 left a Claude.ai connector retrying the dead token for hours; it has to be
// the same 401 invalid_token a bad signature gets, because that is what makes a client sign in again.
describe('a token the issuer rejects during the group lookup is told to re-authenticate', () => {
  let oidc: OidcFixture
  let upstream: McpUpstreamFixture

  beforeAll(async () => {
    oidc = await startOidcFixture()
    upstream = await startMcpUpstream()
    oidc.setGroups('member', ['wiki-users'])
  })

  afterAll(async () => {
    await oidc.close()
    await upstream.close()
  })

  beforeEach(() => {
    oidc.setUserinfoMode('ok')
    oidc.setUserinfoEndpoint(`${oidc.issuerUrl}/userinfo`)
  })

  const rejectingModes: Array<[UserinfoMode, string]> = [
    ['unauthorized', 'userinfo answers 401 (session ended or revoked)'],
    ['forbidden', 'userinfo answers 403'],
  ]

  for (const [mode, description] of rejectingModes) {
    it(`refuses with 401 invalid_token and never reaches the upstream when ${description}`, async () => {
      oidc.setUserinfoMode(mode)
      const token = await oidc.signToken({ sub: 'member' }, { audience: 'test-aud' })
      const res = await supertest(appFor(oidc, upstream))
        .post('/anything')
        .set('authorization', `Bearer ${token}`)
        .send({ jsonrpc: '2.0', method: 'tools/list', id: 1 })
      expect(res.status).toBe(401)
      expect(res.headers['www-authenticate']).toMatch(/error="invalid_token"/)
      expect(res.headers['www-authenticate']).toMatch(
        /resource_metadata="https:\/\/mcp\.example\.com\/\.well-known\/oauth-protected-resource"/,
      )
      expect(res.headers['retry-after']).toBeUndefined()
      expect(res.body.ok).toBeUndefined()
    })
  }

  it('does not remember the rejection: the same token is looked up again, and admitted once the issuer is', async () => {
    const token = await oidc.signToken({ sub: 'member' }, { audience: 'test-aud' })
    const app = appFor(oidc, upstream)
    const before = oidc.userinfoCalls()
    oidc.setUserinfoMode('unauthorized')
    const first = await supertest(app).post('/anything').set('authorization', `Bearer ${token}`).send({})
    expect(first.status).toBe(401)
    oidc.setUserinfoMode('ok')
    const second = await supertest(app).post('/anything').set('authorization', `Bearer ${token}`).send({})
    expect(second.status).toBe(200)
    expect(oidc.userinfoCalls()).toBe(before + 2)
  })
})
