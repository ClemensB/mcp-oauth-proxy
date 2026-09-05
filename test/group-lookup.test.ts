import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { createGroupLookup, GroupLookupError } from '../src/group-lookup.js'
import { createIssuerMetadataFetcher } from '../src/issuer-metadata.js'
import { startOidcFixture, type OidcFixture } from './fixtures/oidc-server.js'

describe('createGroupLookup', () => {
  let oidc: OidcFixture
  // Injected clock: the cache's whole contract is about time, and sleeping through a five minute TTL
  // is not a test.
  let clock = 0

  beforeAll(async () => {
    oidc = await startOidcFixture()
    oidc.setGroups('member', ['wiki-users', 'other'])
    oidc.setGroups('outsider', ['unrelated'])
  })

  afterAll(async () => {
    await oidc.close()
  })

  beforeEach(() => {
    clock = Date.now()
    oidc.setUserinfoMode('ok')
    oidc.setUserinfoEndpoint(null)
    oidc.setUserinfoEndpoint(`${oidc.issuerUrl}/userinfo`)
  })

  const build = (overrides: Partial<Parameters<typeof createGroupLookup>[0]> = {}) =>
    createGroupLookup({
      metadata: createIssuerMetadataFetcher({ issuerUrl: oidc.issuerUrl }),
      issuerUrl: oidc.issuerUrl,
      allowGroups: ['wiki-users'],
      now: () => clock,
      ...overrides,
    })

  const tokenFor = (sub: string, expiresIn = '5m') => oidc.signToken({ sub }, { audience: 'test-aud', expiresIn })

  it('reads the groups claim from userinfo, authenticating as the caller', async () => {
    const token = await tokenFor('member')
    const before = oidc.userinfoCalls()
    await expect(build().groupsFor({ token, sub: 'member' })).resolves.toMatchObject({ groups: ['wiki-users', 'other'] })
    expect(oidc.userinfoCalls()).toBe(before + 1)
    expect(oidc.lastUserinfoAuthorization()).toBe(`Bearer ${token}`)
  })

  it('caches an admitting lookup, so a session does not pay a round-trip per call', async () => {
    const token = await tokenFor('member')
    const lookup = build()
    const before = oidc.userinfoCalls()
    await lookup.groupsFor({ token, sub: 'member' })
    await lookup.groupsFor({ token, sub: 'member' })
    await lookup.groupsFor({ token, sub: 'member' })
    expect(oidc.userinfoCalls()).toBe(before + 1)
  })

  it('keys the cache on the token, not the subject', async () => {
    // Two tokens for one person may legitimately carry different grants, so the second must not
    // inherit the first's answer.
    const lookup = build()
    const first = await tokenFor('member')
    const second = await tokenFor('member', '6m')
    expect(first).not.toBe(second)
    const before = oidc.userinfoCalls()
    await lookup.groupsFor({ token: first, sub: 'member' })
    await lookup.groupsFor({ token: second, sub: 'member' })
    expect(oidc.userinfoCalls()).toBe(before + 2)
  })

  it('expires a cached answer at the configured maximum', async () => {
    const lookup = build({ maxCacheTtlMs: 60_000 })
    const token = await tokenFor('member')
    const before = oidc.userinfoCalls()
    await lookup.groupsFor({ token, sub: 'member' })
    clock += 59_000
    await lookup.groupsFor({ token, sub: 'member' })
    expect(oidc.userinfoCalls()).toBe(before + 1)
    clock += 2_000
    await lookup.groupsFor({ token, sub: 'member' })
    expect(oidc.userinfoCalls()).toBe(before + 2)
  })

  it('never caches past the token exp, even when the maximum is longer', async () => {
    const lookup = build({ maxCacheTtlMs: 300_000 })
    const token = await tokenFor('member')
    const exp = Math.floor(clock / 1000) + 30
    const before = oidc.userinfoCalls()
    await lookup.groupsFor({ token, sub: 'member', exp })
    clock += 20_000
    await lookup.groupsFor({ token, sub: 'member', exp })
    expect(oidc.userinfoCalls()).toBe(before + 1)
    // Past the token's own expiry but well inside the 5 minute maximum.
    clock += 11_000
    await lookup.groupsFor({ token, sub: 'member', exp })
    expect(oidc.userinfoCalls()).toBe(before + 2)
  })

  it('holds a non-admitting answer far more briefly than an admitting one', async () => {
    // Someone just added to a group should not have to wait out a cache to gain access.
    const lookup = build({ maxCacheTtlMs: 300_000, negativeCacheTtlMs: 5_000 })
    const token = await tokenFor('outsider')
    await expect(lookup.groupsFor({ token, sub: 'outsider' })).resolves.toMatchObject({ groups: ['unrelated'] })
    clock += 6_000
    oidc.setGroups('outsider', ['unrelated', 'wiki-users'])
    await expect(lookup.groupsFor({ token, sub: 'outsider' })).resolves.toMatchObject({ groups: ['unrelated', 'wiki-users'] })
    oidc.setGroups('outsider', ['unrelated'])
  })

  it('treats an absent groups claim as membership of nothing, not as an error', async () => {
    // An issuer whose claim mapping produces nothing simply omits the claim. Refusing with an error
    // would turn the ordinary "removed from the group" case into something that reads like an outage.
    oidc.setUserinfoMode('absent-groups')
    const token = await tokenFor('member')
    await expect(build().groupsFor({ token, sub: 'member' })).resolves.toMatchObject({ groups: [] })
  })

  it('refuses a userinfo_endpoint that is not on the issuer origin', async () => {
    oidc.setUserinfoEndpoint('https://elsewhere.example.com/userinfo')
    const token = await tokenFor('member')
    const before = oidc.userinfoCalls()
    const err = await build()
      .groupsFor({ token, sub: 'member' })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(GroupLookupError)
    expect((err as GroupLookupError).reason).toBe('endpoint')
    // The origin check runs before any request is made, so the token never went on the wire at all.
    expect(oidc.userinfoCalls()).toBe(before)
  })

  it('refuses when the issuer advertises no userinfo_endpoint', async () => {
    oidc.setUserinfoEndpoint(null)
    const token = await tokenFor('member')
    const err = await build()
      .groupsFor({ token, sub: 'member' })
      .catch((e: unknown) => e)
    expect((err as GroupLookupError).reason).toBe('endpoint')
  })

  it('refuses on a timeout rather than answering with no groups', async () => {
    oidc.setUserinfoMode('hang')
    const token = await tokenFor('member')
    const err = await build({ timeoutMs: 250 })
      .groupsFor({ token, sub: 'member' })
      .catch((e: unknown) => e)
    expect((err as GroupLookupError).reason).toBe('timeout')
  })
})
