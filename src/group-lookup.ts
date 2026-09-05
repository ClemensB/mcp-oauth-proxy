import { createHash } from 'node:crypto'
import type { IssuerMetadataFetcher } from './issuer-metadata.js'

// Resolving group membership from the IdP's `/userinfo` endpoint.
//
// Some issuers apply their claim mapping to the ID token only, so the *access* token a resource server
// validates carries no `groups` claim at all — Kanidm is one, but this is a general OIDC shape rather
// than a vendor quirk. `ALLOW_GROUPS` is then present but permanently non-functional, which is worse
// than absent because it looks supported. This closes that by asking the issuer, with the caller's own
// verified token, who they are.
//
// Everything here fails closed: any outcome that is not "the issuer answered, and the answer was
// well-formed, and it was about this token's subject" is an error, never an empty group list. An empty
// list would silently read as "not a member" and turn an IdP outage into a permanent, quiet denial.

export type GroupLookupFailure =
  | 'metadata' // the issuer's discovery document could not be fetched
  | 'endpoint' // no userinfo_endpoint, or one that is not on the issuer's own origin
  | 'timeout'
  | 'network'
  | 'status' // userinfo answered, but not with 2xx
  | 'malformed' // not JSON, or `groups` present in a shape that is not an array of strings
  | 'subject-mismatch' // the answer describes a different subject than the token

export class GroupLookupError extends Error {
  readonly reason: GroupLookupFailure

  constructor(reason: GroupLookupFailure, message: string) {
    super(message)
    this.name = 'GroupLookupError'
    this.reason = reason
  }
}

export type GroupLookupOptions = {
  // Shared with the discovery endpoint, so both paths use one cache and one in-flight fetch.
  metadata: IssuerMetadataFetcher
  // Used to constrain userinfo_endpoint to the issuer's own origin.
  issuerUrl: string
  // Consulted only to decide how long to cache: see maxCacheTtlMs.
  allowGroups: string[]
  // Upper bound on how long an admitting lookup is reused. The token's own `exp` bounds it too.
  maxCacheTtlMs?: number
  // How long a non-admitting lookup is reused. Deliberately short.
  negativeCacheTtlMs?: number
  timeoutMs?: number
  maxCacheEntries?: number
  // Injectable clock, for tests.
  now?: () => number
}

export type GroupLookupInput = {
  // The raw access token. Sent as the bearer credential, and hashed to key the cache.
  token: string
  // The verified token's subject. The issuer's answer must agree with it.
  sub: string
  // The verified token's `exp`, in seconds since the epoch, when it has one.
  exp?: number
}

export type GroupLookupResult = {
  groups: string[]
  // `preferred_username` from the same userinfo answer, when the issuer sends one. Carried to the
  // upstream as X-Wiki-User; nothing here decides admission on it.
  username?: string
}

export type GroupLookup = {
  groupsFor: (input: GroupLookupInput) => Promise<GroupLookupResult>
}

const MAX_CACHE_TTL_MS = 300_000
const NEGATIVE_CACHE_TTL_MS = 5_000
const FETCH_TIMEOUT_MS = 5_000
const MAX_CACHE_ENTRIES = 1_000

export const createGroupLookup = (opts: GroupLookupOptions): GroupLookup => {
  const maxCacheTtlMs = opts.maxCacheTtlMs ?? MAX_CACHE_TTL_MS
  const negativeCacheTtlMs = opts.negativeCacheTtlMs ?? NEGATIVE_CACHE_TTL_MS
  const timeoutMs = opts.timeoutMs ?? FETCH_TIMEOUT_MS
  const maxEntries = opts.maxCacheEntries ?? MAX_CACHE_ENTRIES
  const now = opts.now ?? Date.now
  const issuerOrigin = new URL(opts.issuerUrl).origin

  // Keyed on a hash of the token, never the token itself: two tokens for one person may carry
  // different grants, so the subject is the wrong key (a narrowly-scoped token would inherit a
  // broadly-scoped one's answer), and holding raw credentials in a long-lived map is worth avoiding.
  const cache = new Map<string, { result: GroupLookupResult; expiresAt: number }>()

  const remember = (key: string, result: GroupLookupResult, admitted: boolean, exp: number | undefined) => {
    // The cache must never outlive the token it describes. Beyond that, an admitting answer is held
    // for the full window while a non-admitting one is held barely at all: someone just added to a
    // group should not have to wait out a cache to get in, whereas someone just removed is bounded by
    // this window only in the narrow case of a still-valid token — revoking properly means disabling
    // the account at the IdP, which invalidates the token and no cache survives that.
    const ttl = admitted ? maxCacheTtlMs : negativeCacheTtlMs
    const expiresAt = exp === undefined ? now() + ttl : Math.min(now() + ttl, exp * 1000)
    if (expiresAt <= now()) return

    if (cache.size >= maxEntries) {
      for (const [k, v] of cache) if (v.expiresAt <= now()) cache.delete(k)
      // Still full of live entries: drop the oldest insertion, which Map iterates first.
      if (cache.size >= maxEntries) {
        const oldest = cache.keys().next()
        if (!oldest.done) cache.delete(oldest.value)
      }
    }
    cache.set(key, { result, expiresAt })
  }

  const userinfoUrl = async (): Promise<URL> => {
    let metadata
    try {
      metadata = await opts.metadata.get()
    } catch (err) {
      throw new GroupLookupError('metadata', `issuer metadata unavailable: ${(err as Error).message}`)
    }
    const raw = metadata['userinfo_endpoint']
    if (typeof raw !== 'string' || raw === '') {
      throw new GroupLookupError('endpoint', 'issuer metadata declares no userinfo_endpoint')
    }
    let url: URL
    try {
      url = new URL(raw)
    } catch {
      throw new GroupLookupError('endpoint', 'issuer metadata declares a malformed userinfo_endpoint')
    }
    // The proxy already reaches the issuer for discovery and JWKS; userinfo must be the same host and
    // nothing else. Without this, an issuer document — or anyone who can spoof one — could aim an
    // authenticated request carrying the caller's live token at an arbitrary origin.
    if (url.origin !== issuerOrigin) {
      throw new GroupLookupError('endpoint', `userinfo_endpoint origin ${url.origin} is not the issuer's`)
    }
    return url
  }

  const fetchGroups = async (url: URL, token: string, sub: string): Promise<GroupLookupResult> => {
    let res: Response
    try {
      res = await fetch(url, {
        headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
        signal: AbortSignal.timeout(timeoutMs),
        // A redirect would move an authenticated request off the origin we just checked.
        redirect: 'error',
      })
    } catch (err) {
      const name = err instanceof Error ? err.name : ''
      const reason = name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'network'
      // Deliberately not interpolating the error's message: it is issuer-controlled text and this
      // string reaches the log.
      throw new GroupLookupError(reason, `userinfo request failed (${name || 'error'})`)
    }
    // Status only — a body from a failed userinfo call is issuer-controlled and never logged.
    if (!res.ok) throw new GroupLookupError('status', `userinfo returned ${res.status}`)

    let body: unknown
    try {
      body = await res.json()
    } catch {
      // Also the path taken when the issuer is configured to sign the userinfo response, which arrives
      // as a JWT rather than JSON. Failing closed is right; the fix is issuer-side configuration.
      throw new GroupLookupError('malformed', 'userinfo response is not JSON')
    }
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      throw new GroupLookupError('malformed', 'userinfo response is not a JSON object')
    }

    const claims = body as Record<string, unknown>
    // OpenID Connect Core §5.3.2 requires the client to check this. It is also what keeps the token
    // the source of identity: without it, an issuer answering about somebody else would be believed.
    if (claims['sub'] !== sub) {
      throw new GroupLookupError('subject-mismatch', 'userinfo sub does not match the token sub')
    }

    const pu = claims['preferred_username']
    const username = typeof pu === 'string' && pu.trim() !== '' ? pu.trim() : undefined

    const raw = claims['groups']
    // Absent is not malformed: an issuer whose claim mapping produces nothing for a user in no mapped
    // groups simply omits the claim. Treating that as an error would turn the ordinary "removed from
    // the group" case into a 503 that reads like an outage, when it is a plain, correct refusal.
    if (raw === undefined || raw === null) return { groups: [], ...(username && { username }) }
    if (!Array.isArray(raw) || raw.some((g) => typeof g !== 'string')) {
      // A present-but-wrong shape is different: a `groups` claim joined into a single space-separated
      // string would otherwise silently read as "member of nothing".
      throw new GroupLookupError('malformed', 'userinfo groups claim is not an array of strings')
    }
    return { groups: raw as string[], ...(username && { username }) }
  }

  return {
    groupsFor: async ({ token, sub, exp }) => {
      const key = createHash('sha256').update(token).digest('hex')
      const hit = cache.get(key)
      if (hit && hit.expiresAt > now()) return hit.result
      if (hit) cache.delete(key)

      const url = await userinfoUrl()
      const result = await fetchGroups(url, token, sub)
      remember(
        key,
        result,
        result.groups.some((g) => opts.allowGroups.includes(g)),
        exp,
      )
      return result
    },
  }
}
