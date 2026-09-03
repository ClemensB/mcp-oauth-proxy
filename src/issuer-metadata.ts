// The issuer's `.well-known/openid-configuration`, fetched once and shared.
//
// Two code paths need this document: the public discovery endpoint, and — to find `userinfo_endpoint`
// — the group lookup in the auth middleware. Sharing one instance gives them one cache, one in-flight
// fetch and one negative-cache window between them, so neither can be used to amplify traffic at the
// IdP. Each fetch is bounded so a slow upstream cannot pin sockets open here, concurrent misses share
// a single request, and failures are negatively cached: without that, a cold cache or an IdP that is
// mid-incident (returning errors, so nothing gets cached) reopens the one-request-per-hit
// amplification the positive cache exists to close.

export type IssuerMetadata = Record<string, unknown>

// Why the caller gets a reason rather than a bare Error: a request refused because a *previous* fetch
// failed is not the same event as one that just failed, and only the latter is worth logging — during
// an IdP outage the cooldown path is hit once per request.
export type IssuerMetadataFailure = 'cooldown' | 'timeout' | 'status' | 'network' | 'malformed'

export class IssuerMetadataError extends Error {
  readonly reason: IssuerMetadataFailure

  constructor(reason: IssuerMetadataFailure, message: string) {
    super(message)
    this.name = 'IssuerMetadataError'
    this.reason = reason
  }
}

export type IssuerMetadataOptions = {
  issuerUrl: string
  // How long a successful fetch is reused. Intended for tests.
  metadataTtlMs?: number
  // How long after a failure every caller is refused without a new fetch. Intended for tests.
  failureTtlMs?: number
  // Per-fetch timeout. Intended for tests.
  timeoutMs?: number
}

export type IssuerMetadataFetcher = {
  // Resolves with the issuer metadata, or rejects with an IssuerMetadataError.
  get: () => Promise<IssuerMetadata>
}

const METADATA_TTL_MS = 300_000
const FAILURE_TTL_MS = 5_000
const FETCH_TIMEOUT_MS = 5_000

export const createIssuerMetadataFetcher = (opts: IssuerMetadataOptions): IssuerMetadataFetcher => {
  const url = new URL('.well-known/openid-configuration', ensureTrailingSlash(opts.issuerUrl))
  const metadataTtlMs = opts.metadataTtlMs ?? METADATA_TTL_MS
  const failureTtlMs = opts.failureTtlMs ?? FAILURE_TTL_MS
  const timeoutMs = opts.timeoutMs ?? FETCH_TIMEOUT_MS

  let cached: { at: number; body: IssuerMetadata } | undefined
  let inflight: Promise<IssuerMetadata> | undefined
  let failedAt = 0

  const fetchOnce = async (): Promise<IssuerMetadata> => {
    let res: Response
    try {
      res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
    } catch (err) {
      const name = err instanceof Error ? err.name : ''
      const reason = name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'network'
      throw new IssuerMetadataError(reason, `fetch of ${url} failed: ${(err as Error).message}`)
    }
    if (!res.ok) throw new IssuerMetadataError('status', `upstream issuer returned ${res.status}`)
    try {
      return (await res.json()) as IssuerMetadata
    } catch {
      throw new IssuerMetadataError('malformed', `issuer metadata at ${url} is not valid JSON`)
    }
  }

  return {
    get: async () => {
      const fresh = cached && Date.now() - cached.at < metadataTtlMs ? cached.body : undefined
      if (fresh) return fresh
      if (Date.now() - failedAt < failureTtlMs) {
        throw new IssuerMetadataError('cooldown', `issuer metadata fetch from ${url} recently failed; retry pending`)
      }
      inflight ??= fetchOnce().finally(() => {
        inflight = undefined
      })
      try {
        const body = await inflight
        cached = { at: Date.now(), body }
        return body
      } catch (err) {
        failedAt = Date.now()
        throw err
      }
    },
  }
}

const ensureTrailingSlash = (url: string): string => (url.endsWith('/') ? url : `${url}/`)
