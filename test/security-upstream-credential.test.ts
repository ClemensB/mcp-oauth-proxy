import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import supertest from 'supertest'
import { buildApp } from '../src/index.js'
import { loadConfig } from '../src/config.js'
import { readUpstreamBearer } from '../src/upstream-credential.js'
import { startOidcFixture, type OidcFixture } from './fixtures/oidc-server.js'
import { startMcpUpstream, type McpUpstreamFixture } from './fixtures/mcp-upstream.js'

const UPSTREAM_TOKEN = 'upstream-static-token-0123456789'

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
    upstreamPath: '/mcp',
    ...over,
  } as Parameters<typeof buildApp>[0])

describe('upstream bearer: the upstream sees the proxy credential or none, never the caller', () => {
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

  it('unset: an admitted request reaches the upstream with no Authorization at all', async () => {
    const token = await oidc.signToken({ sub: 'allowed-user' }, { audience: 'test-aud' })
    const res = await supertest(appFor(oidc, upstream)).post('/x').set('authorization', `Bearer ${token}`).send({})
    expect(res.status).toBe(200)
    expect(upstream.lastHeaders()['authorization']).toBeUndefined()
  })

  it('set: an admitted request reaches the upstream with the configured bearer', async () => {
    const token = await oidc.signToken({ sub: 'allowed-user' }, { audience: 'test-aud' })
    const res = await supertest(appFor(oidc, upstream, { upstreamBearer: UPSTREAM_TOKEN }))
      .post('/x')
      .set('authorization', `Bearer ${token}`)
      .send({})
    expect(res.status).toBe(200)
    expect(upstream.lastHeaders()['authorization']).toBe(`Bearer ${UPSTREAM_TOKEN}`)
  })

  // Inverted proof-of-concept: an implementation that set the header *before* the strip, or only when
  // the caller sent none, would forward the caller's live IdP token. It must be replaced, not kept.
  it("set: the caller's own token never reaches the upstream", async () => {
    const token = await oidc.signToken({ sub: 'allowed-user' }, { audience: 'test-aud' })
    await supertest(appFor(oidc, upstream, { upstreamBearer: UPSTREAM_TOKEN }))
      .post('/x')
      .set('authorization', `Bearer ${token}`)
      .send({})
    const seen = String(upstream.lastHeaders()['authorization'])
    expect(seen).not.toContain(token)
    expect(seen).toBe(`Bearer ${UPSTREAM_TOKEN}`)
  })

  // Inverted proof-of-concept: the credential is lent only to admitted callers. Were the header set in
  // a middleware ahead of auth, a tokenless request would still be refused here -- but a later route
  // change could let it through carrying the proxy's credential. The request must not reach at all.
  it('set: an unauthenticated request is refused and never reaches the upstream', async () => {
    const before = upstream.lastHeaders()
    const res = await supertest(appFor(oidc, upstream, { upstreamBearer: UPSTREAM_TOKEN }))
      .post('/x')
      .send({})
    expect(res.status).toBe(401)
    expect(upstream.lastHeaders()).toBe(before)
  })
})

describe('upstream bearer file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'upstream-bearer-'))
  const write = (name: string, content: string) => {
    const p = join(dir, name)
    writeFileSync(p, content)
    return p
  }

  it('is read and trimmed of the trailing newline secret files usually carry', () => {
    expect(readUpstreamBearer(write('ok', `${UPSTREAM_TOKEN}\n`))).toBe(UPSTREAM_TOKEN)
  })

  it('refuses a missing file, naming the path', () => {
    expect(() => readUpstreamBearer(join(dir, 'absent'))).toThrow(/unreadable: .*absent/)
  })

  it('refuses an empty file', () => {
    expect(() => readUpstreamBearer(write('empty', '\n'))).toThrow(/empty/)
  })

  it('refuses a file holding more than one token', () => {
    expect(() => readUpstreamBearer(write('two', 'a b\n'))).toThrow(/more than one token/)
  })

  it('never puts the contents in the error', () => {
    try {
      readUpstreamBearer(write('two-secret', `${UPSTREAM_TOKEN} extra\n`))
    } catch (err) {
      expect((err as Error).message).not.toContain(UPSTREAM_TOKEN)
    }
  })

  it('is optional in the config and carried through when set', () => {
    const base = {
      OIDC_ISSUER_URL: 'https://idp.example.com',
      OIDC_AUDIENCE: 'aud',
      RESOURCE_URL: 'https://mcp.example.com',
      ALLOW_SUBS: 'u',
      MCP_UPSTREAM_URL: 'http://upstream:3000',
    }
    expect(loadConfig(base).mcpUpstreamBearerFile).toBeUndefined()
    expect(loadConfig({ ...base, MCP_UPSTREAM_BEARER_FILE: '/run/secrets/t' }).mcpUpstreamBearerFile).toBe(
      '/run/secrets/t',
    )
  })
})
