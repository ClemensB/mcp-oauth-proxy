import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import express from 'express'
import supertest from 'supertest'
import { createAuthMiddleware } from '../src/auth-middleware.js'
import { logger } from '../src/logger.js'
import { startOidcFixture, type OidcFixture } from './fixtures/oidc-server.js'

describe('createAuthMiddleware', () => {
  let oidc: OidcFixture

  beforeAll(async () => {
    oidc = await startOidcFixture()
  })

  afterAll(async () => {
    await oidc.close()
  })

  const buildApp = (overrides: Partial<Parameters<typeof createAuthMiddleware>[0]> = {}) => {
    const app = express()
    app.use(
      createAuthMiddleware({
        issuerUrl: oidc.issuerUrl,
        audience: 'test-aud',
        allowSubs: ['allowed-user'],
        allowEmails: [],
        allowGroups: [],
        resourceUrl: 'https://mcp.example.com',
        ...overrides,
      }),
    )
    app.get('/protected', (req, res) => {
      res.json({ sub: (req as express.Request & { auth?: { sub: string } }).auth?.sub })
    })
    return app
  }

  it('rejects requests without an Authorization header with 401 + WWW-Authenticate', async () => {
    const res = await supertest(buildApp()).get('/protected')
    expect(res.status).toBe(401)
    expect(res.headers['www-authenticate']).toMatch(/Bearer/)
    expect(res.headers['www-authenticate']).toMatch(
      /resource_metadata="https:\/\/mcp\.example\.com\/\.well-known\/oauth-protected-resource"/,
    )
    expect(res.headers['www-authenticate']).toMatch(/error="invalid_request"/)
    expect(res.headers['www-authenticate']).toMatch(/error_description=/)
  })

  it('rejects malformed Authorization header', async () => {
    const res = await supertest(buildApp()).get('/protected').set('authorization', 'NotBearer xyz')
    expect(res.status).toBe(401)
  })

  it('rejects an invalid token with 401', async () => {
    const res = await supertest(buildApp()).get('/protected').set('authorization', 'Bearer not.a.jwt')
    expect(res.status).toBe(401)
  })

  it('WWW-Authenticate on invalid token contains error="invalid_token" and all RFC 6750 params', async () => {
    const res = await supertest(buildApp()).get('/protected').set('authorization', 'Bearer not.a.jwt')
    expect(res.status).toBe(401)
    const header = res.headers['www-authenticate'] as string
    expect(header).toMatch(/realm=/)
    expect(header).toMatch(/error="invalid_token"/)
    expect(header).toMatch(/error_description=/)
    expect(header).toMatch(/resource_metadata=/)
  })

  it('rejects a valid token whose sub is not in allow-list with 403', async () => {
    const token = await oidc.signToken({ sub: 'not-allowed' }, { audience: 'test-aud' })
    const res = await supertest(buildApp()).get('/protected').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(403)
  })

  it('passes through a valid token with allowed sub', async () => {
    const token = await oidc.signToken({ sub: 'allowed-user' }, { audience: 'test-aud' })
    const res = await supertest(buildApp()).get('/protected').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    expect(res.body.sub).toBe('allowed-user')
  })

  it('passes through a valid token with allowed, verified email', async () => {
    const token = await oidc.signToken(
      { sub: 'x', email: 'yann@example.com', email_verified: true },
      { audience: 'test-aud' },
    )
    const res = await supertest(buildApp({ allowSubs: [], allowEmails: ['yann@example.com'] }))
      .get('/protected')
      .set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
  })

  it('rejects an allow-listed email that is not verified', async () => {
    for (const claims of [
      { sub: 'x', email: 'yann@example.com', email_verified: false },
      { sub: 'x', email: 'yann@example.com' }, // claim absent entirely
    ]) {
      const token = await oidc.signToken(claims, { audience: 'test-aud' })
      const res = await supertest(buildApp({ allowSubs: [], allowEmails: ['yann@example.com'] }))
        .get('/protected')
        .set('authorization', `Bearer ${token}`)
      expect(res.status).toBe(403)
    }
  })

  it('rejects a token with no sub claim, even when another allow-list would match', async () => {
    const token = await oidc.signToken({ groups: ['admin'] }, { audience: 'test-aud' })
    const res = await supertest(buildApp({ allowSubs: [], allowGroups: ['admin'] }))
      .get('/protected')
      .set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })

  it('passes through when any one allow-list matches (sub OR email OR group)', async () => {
    const token = await oidc.signToken(
      { sub: 'unknown', email: 'unknown@example.com', groups: ['admin'] },
      { audience: 'test-aud' },
    )
    const res = await supertest(buildApp({ allowSubs: [], allowEmails: [], allowGroups: ['admin'] }))
      .get('/protected')
      .set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
  })
})

describe('createAuthMiddleware group lookup via userinfo', () => {
  let oidc: OidcFixture

  beforeAll(async () => {
    oidc = await startOidcFixture()
    oidc.setGroups('member', ['wiki-users'])
    oidc.setGroups('outsider', ['some-other-group'])
    oidc.setGroups('allowed-user', ['wiki-users'])
  })

  afterAll(async () => {
    await oidc.close()
  })

  beforeEach(() => {
    oidc.setUserinfoMode('ok')
    oidc.setUserinfoEndpoint(`${oidc.issuerUrl}/userinfo`)
  })

  const buildApp = (overrides: Partial<Parameters<typeof createAuthMiddleware>[0]> = {}) => {
    const app = express()
    app.use(
      createAuthMiddleware({
        issuerUrl: oidc.issuerUrl,
        audience: 'test-aud',
        allowSubs: [],
        allowEmails: [],
        allowGroups: ['wiki-users'],
        resourceUrl: 'https://mcp.example.com',
        ...overrides,
      }),
    )
    app.get('/protected', (req, res) => {
      const auth = (req as express.Request & { auth?: { groups: string[] } }).auth
      res.json({ groups: auth?.groups })
    })
    return app
  }

  it('admits a token with no groups claim whose subject is in an allow-listed group', async () => {
    // The whole point: against an IdP that puts group claims only on the ID token, the access token
    // this proxy validates carries none, and ALLOW_GROUPS was previously dead config.
    const token = await oidc.signToken({ sub: 'member' }, { audience: 'test-aud' })
    const res = await supertest(buildApp()).get('/protected').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    expect(res.body.groups).toEqual(['wiki-users'])
  })

  it('refuses with 403 when the resolved groups are not allow-listed', async () => {
    const token = await oidc.signToken({ sub: 'outsider' }, { audience: 'test-aud' })
    const res = await supertest(buildApp()).get('/protected').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(403)
  })

  it('makes no lookup when the token already carries a groups claim', async () => {
    const token = await oidc.signToken({ sub: 'member', groups: ['wiki-users'] }, { audience: 'test-aud' })
    const before = oidc.userinfoCalls()
    const res = await supertest(buildApp()).get('/protected').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    expect(oidc.userinfoCalls()).toBe(before)
  })

  it('takes an empty groups claim at its word rather than second-guessing it at the IdP', async () => {
    const token = await oidc.signToken({ sub: 'member', groups: [] }, { audience: 'test-aud' })
    const before = oidc.userinfoCalls()
    const res = await supertest(buildApp()).get('/protected').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(403)
    expect(oidc.userinfoCalls()).toBe(before)
  })

  it('makes no lookup when the subject allow-list already admits the request', async () => {
    const token = await oidc.signToken({ sub: 'allowed-user' }, { audience: 'test-aud' })
    const before = oidc.userinfoCalls()
    const res = await supertest(buildApp({ allowSubs: ['allowed-user'] }))
      .get('/protected')
      .set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    expect(oidc.userinfoCalls()).toBe(before)
  })

  it('makes no lookup at all when ALLOW_GROUPS is unset', async () => {
    const token = await oidc.signToken({ sub: 'member' }, { audience: 'test-aud' })
    const before = oidc.userinfoCalls()
    const res = await supertest(buildApp({ allowGroups: [], allowSubs: ['nobody'] }))
      .get('/protected')
      .set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(403)
    expect(oidc.userinfoCalls()).toBe(before)
  })

  it('caches across requests, so a session does not pay a round-trip per MCP call', async () => {
    const token = await oidc.signToken({ sub: 'member' }, { audience: 'test-aud' })
    const app = buildApp()
    const before = oidc.userinfoCalls()
    await supertest(app).get('/protected').set('authorization', `Bearer ${token}`)
    await supertest(app).get('/protected').set('authorization', `Bearer ${token}`)
    await supertest(app).get('/protected').set('authorization', `Bearer ${token}`)
    expect(oidc.userinfoCalls()).toBe(before + 1)
  })

  it('answers 503 with Retry-After when the lookup cannot be completed', async () => {
    // Not 403: an unreachable dependency is a different event from a user who is not a member, and a
    // client that reads 403 may mark the connector unauthorized and demand re-auth over a blip.
    oidc.setUserinfoMode('server-error')
    const token = await oidc.signToken({ sub: 'member' }, { audience: 'test-aud' })
    const res = await supertest(buildApp()).get('/protected').set('authorization', `Bearer ${token}`)
    expect(res.status).toBe(503)
    expect(res.headers['retry-after']).toBe('5')
    expect(res.headers['www-authenticate']).toBeUndefined()
  })

  it('never writes the token to the log, on the failure path or the denial path', async () => {
    const token = await oidc.signToken({ sub: 'outsider' }, { audience: 'test-aud' })
    const seen: string[] = []
    const capture = (...args: unknown[]) => {
      seen.push(JSON.stringify(args))
      return logger
    }
    const warn = vi.spyOn(logger, 'warn').mockImplementation(capture as never)
    const error = vi.spyOn(logger, 'error').mockImplementation(capture as never)
    try {
      await supertest(buildApp()).get('/protected').set('authorization', `Bearer ${token}`)
      oidc.setUserinfoMode('server-error')
      await supertest(buildApp()).get('/protected').set('authorization', `Bearer ${token}`)
    } finally {
      warn.mockRestore()
      error.mockRestore()
    }
    expect(seen.length).toBeGreaterThan(0)
    for (const line of seen) expect(line).not.toContain(token)
  })
})
