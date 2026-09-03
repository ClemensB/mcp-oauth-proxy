import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { createGroupLookup, GroupLookupError, type GroupLookup } from './group-lookup.js'
import { createIssuerMetadataFetcher, type IssuerMetadataFetcher } from './issuer-metadata.js'
import { createJwtVerifier } from './jwt.js'
import { logger } from './logger.js'

export type AuthMiddlewareOptions = {
  issuerUrl: string
  audience: string
  resourceUrl: string
  allowSubs: string[]
  allowEmails: string[]
  allowGroups: string[]
  // Shared with the discovery endpoint so both use one cache and one in-flight fetch. Only consulted
  // when ALLOW_GROUPS is set; omitted, a private fetcher is created.
  metadata?: IssuerMetadataFetcher
  // Upper bound on how long a group lookup that admitted a request is reused. The token's own `exp`
  // bounds it too.
  groupCacheTtlMs?: number
  // Test seam: overrides the userinfo lookup entirely.
  groupLookup?: GroupLookup
}

type AuthedRequest = Request & {
  auth?: {
    sub: string
    email: string | undefined
    groups: string[]
  }
}

// Advertised on a failed group lookup. Matches the negative-cache window, so a client that honours it
// retries roughly when a retry could first succeed.
const RETRY_AFTER_SECONDS = 5

const wwwAuthenticateFor = (reason: 'missing' | 'invalid', resourceUrl: string) => {
  const r = resourceUrl.replace(/\/$/, '')
  const realm = `"${r}"`
  const errorCode = reason === 'missing' ? '"invalid_request"' : '"invalid_token"'
  const description = reason === 'missing' ? '"Bearer token required"' : '"The access token is invalid or expired"'
  const metadata = `"${r}/.well-known/oauth-protected-resource"`
  return `Bearer realm=${realm}, error=${errorCode}, error_description=${description}, resource_metadata=${metadata}`
}

export const createAuthMiddleware = (opts: AuthMiddlewareOptions): RequestHandler => {
  const verify = createJwtVerifier({ issuerUrl: opts.issuerUrl, audience: opts.audience })

  // Only built when ALLOW_GROUPS is configured: with no group allow-list there is nothing a lookup
  // could authorize, so no deployment that does not ask for it pays an outbound call.
  const groupLookup =
    opts.allowGroups.length > 0
      ? (opts.groupLookup ??
        createGroupLookup({
          metadata: opts.metadata ?? createIssuerMetadataFetcher({ issuerUrl: opts.issuerUrl }),
          issuerUrl: opts.issuerUrl,
          allowGroups: opts.allowGroups,
          ...(opts.groupCacheTtlMs !== undefined && { maxCacheTtlMs: opts.groupCacheTtlMs }),
        }))
      : undefined

  return async (req: AuthedRequest, res: Response, next: NextFunction) => {
    const header = req.header('authorization')
    if (!header || !header.toLowerCase().startsWith('bearer ')) {
      res.setHeader('www-authenticate', wwwAuthenticateFor('missing', opts.resourceUrl))
      res.status(401).json({ error: 'missing or malformed Authorization header' })
      return
    }
    const token = header.slice('bearer '.length).trim()
    let claims
    try {
      claims = await verify(token)
    } catch (err) {
      logger.warn({ err: (err as Error).message }, 'token verification failed')
      res.setHeader('www-authenticate', wwwAuthenticateFor('invalid', opts.resourceUrl))
      res.status(401).json({ error: 'invalid token' })
      return
    }

    const sub = typeof claims.sub === 'string' ? claims.sub.trim() : ''
    // A token with no usable `sub` is rejected outright: it can't be allow-listed by subject, can't be
    // attributed in the audit log, and can't be rate-limited (the limiter is keyed on `sub`).
    if (!sub) {
      logger.warn('token verified but carries no usable sub claim')
      res.setHeader('www-authenticate', wwwAuthenticateFor('invalid', opts.resourceUrl))
      res.status(401).json({ error: 'invalid token' })
      return
    }

    const email = typeof claims['email'] === 'string' ? (claims['email'] as string) : undefined
    // Only a verified email may satisfy the allow-list. On an IdP that permits self-signup, an
    // unverified `email` claim is attacker-chosen — anyone could claim an allow-listed address.
    const emailVerified = claims['email_verified'] === true
    const groups = Array.isArray(claims['groups']) ? claims['groups'].filter((g) => typeof g === 'string') : []

    const subOk = opts.allowSubs.length > 0 && opts.allowSubs.includes(sub)
    const emailOk = !!email && emailVerified && opts.allowEmails.length > 0 && opts.allowEmails.includes(email)
    const groupOk = opts.allowGroups.length > 0 && groups.some((g) => opts.allowGroups.includes(g))

    if (!emailVerified && !!email && opts.allowEmails.includes(email)) {
      logger.warn({ email }, 'email matches allow-list but email_verified is not true — refusing to match on it')
    }

    if (subOk || emailOk || groupOk) {
      req.auth = { sub, email, groups }
      next()
      return
    }

    // Nothing on the token itself admitted the request. If a group allow-list is configured and the
    // token carried no `groups` claim at all, the issuer may still hold the answer: some IdPs apply
    // their claim mapping only to the ID token, so a resource server validating an access token never
    // sees it. A token that *does* carry the claim is taken at its word — including an empty one —
    // so this costs nothing on issuers that populate it.
    if (groupLookup && claims['groups'] === undefined) {
      let resolved: string[]
      try {
        resolved = await groupLookup.groupsFor({
          token,
          sub,
          ...(typeof claims.exp === 'number' && { exp: claims.exp }),
        })
      } catch (err) {
        // 503, not 403. An unreachable dependency is not the same event as a user who is not a member,
        // and answering 403 risks a client marking the connector unauthorized and demanding re-auth
        // over a transient blip. The metadata this proxy already publishes names the issuer anyway, so
        // a 403 here would hide nothing and only cost a misdiagnosis.
        const reason = err instanceof GroupLookupError ? err.reason : 'unknown'
        logger.error({ sub, reason, detail: (err as Error).message }, 'group lookup failed, refusing request')
        res.setHeader('retry-after', String(RETRY_AFTER_SECONDS))
        res.status(503).json({ error: 'group membership could not be determined' })
        return
      }

      if (resolved.some((g) => opts.allowGroups.includes(g))) {
        req.auth = { sub, email, groups: resolved }
        next()
        return
      }
      logger.warn({ sub, email, groups: resolved }, 'token verified but not in allow-list')
      res.status(403).json({ error: 'not authorized' })
      return
    }

    logger.warn({ sub, email, groups }, 'token verified but not in allow-list')
    res.status(403).json({ error: 'not authorized' })
  }
}
