import express, { type Express } from 'express'
import { loadConfig } from './config.js'
import { createAuthMiddleware } from './auth-middleware.js'
import { createCorsMiddleware } from './cors.js'
import { mountDiscovery } from './discovery.js'
import { createIssuerMetadataFetcher } from './issuer-metadata.js'
import { mountProxy } from './proxy.js'
import { mountRegistration } from './registration.js'
import { createRateLimiter } from './rate-limit.js'
import { spawnMcpUpstream, type SpawnedUpstream } from './spawn.js'
import { logger } from './logger.js'

const buildApp = (opts: {
  issuerUrl: string
  audience: string
  resourceUrl: string
  allowSubs: string[]
  allowEmails: string[]
  allowGroups: string[]
  upstreamUrl: string
  rateLimitRpm: number
  allowOrigins: string[]
  staticClientId: string | undefined
  staticClientSecret: string | undefined
  upstreamPath: string | undefined
  forwardIdentity?: boolean | undefined
  clientLabel?: string | undefined
  scopesSupported?: string[]
  groupCacheTtlSeconds?: number
}): Express => {
  const app = express()
  app.disable('x-powered-by')

  // One fetcher for the whole app: the discovery endpoint and the auth middleware's group lookup
  // both read the issuer's metadata, and sharing it means one cache, one in-flight request and one
  // negative-cache window between them rather than two independent paths to the IdP.
  const metadata = createIssuerMetadataFetcher({ issuerUrl: opts.issuerUrl })

  // CORS must run before auth so OPTIONS preflights short-circuit cleanly.
  app.use(createCorsMiddleware({ allowOrigins: opts.allowOrigins }))

  // Request log — runs before auth so we can see all incoming requests including 401-bound ones.
  app.use((req, res, next) => {
    const start = Date.now()
    // Captured now, not at 'finish': the proxy strips the Authorization header before forwarding, so
    // reading it after the response would log every authenticated proxied request as tokenless.
    const hasAuth = !!req.header('authorization')
    res.on('finish', () => {
      logger.info(
        {
          method: req.method,
          path: req.path,
          status: res.statusCode,
          ms: Date.now() - start,
          origin: req.header('origin'),
          ua: req.header('user-agent'),
          contentType: req.header('content-type'),
          accept: req.header('accept'),
          hasAuth,
          // Populated by the auth middleware before this 'finish' handler runs, so authenticated
          // requests are attributable in the audit log.
          sub: (req as express.Request & { auth?: { sub: string } }).auth?.sub,
        },
        'request',
      )
    })
    next()
  })

  mountDiscovery(app, {
    issuerUrl: opts.issuerUrl,
    resourceUrl: opts.resourceUrl,
    metadata,
    injectRegistrationEndpoint: Boolean(opts.staticClientId && opts.staticClientSecret),
    ...(opts.scopesSupported !== undefined && { scopesSupported: opts.scopesSupported }),
  })

  // Body parser scoped to /oauth/register ONLY. A global express.json() would consume the request
  // body for proxied MCP calls too, leaving nothing for http-proxy-3 to forward — upstream then sees
  // "request aborted" because the body stream is already drained.
  // /oauth/register is public — needs to be reachable before any auth middleware.
  mountRegistration(app, {
    staticClientId: opts.staticClientId,
    staticClientSecret: opts.staticClientSecret,
  })

  const limiter = createRateLimiter({ rpm: opts.rateLimitRpm })
  const auth = createAuthMiddleware({
    issuerUrl: opts.issuerUrl,
    audience: opts.audience,
    resourceUrl: opts.resourceUrl,
    allowSubs: opts.allowSubs,
    allowEmails: opts.allowEmails,
    allowGroups: opts.allowGroups,
    metadata,
    ...(opts.groupCacheTtlSeconds !== undefined && { groupCacheTtlMs: opts.groupCacheTtlSeconds * 1000 }),
  })

  // No path exemptions here. The public routes (discovery, /healthz, /oauth/register) are all
  // registered ABOVE this middleware and answer their own requests, so they never reach it. Skipping
  // auth by path prefix instead would let any other method/path under those prefixes — e.g.
  // `POST /healthz` or `POST /.well-known/anything` — fall straight through to the catch-all proxy.
  app.use((req, res, next) => {
    auth(req, res, (err) => {
      if (err) return next(err)
      // The auth middleware rejects tokens without a usable `sub`, so this is always a real identity.
      const sub = (req as express.Request & { auth?: { sub: string } }).auth?.sub ?? ''
      if (!limiter.tryConsume(sub)) {
        res.status(429).json({ error: 'rate limit exceeded' })
        return
      }
      next()
    })
  })

  mountProxy(app, { upstreamUrl: opts.upstreamUrl, upstreamPath: opts.upstreamPath, forwardIdentity: opts.forwardIdentity, clientLabel: opts.clientLabel })

  return app
}

export { buildApp }

const main = async () => {
  const config = loadConfig()
  logger.info({ port: config.port, resourceUrl: config.resourceUrl }, 'starting mcp-oauth-proxy')

  let spawned: SpawnedUpstream | undefined
  let upstreamUrl: string
  if (config.mcpSpawnCmd && config.mcpSpawnPort) {
    spawned = await spawnMcpUpstream({ cmd: config.mcpSpawnCmd, port: config.mcpSpawnPort })
    upstreamUrl = spawned.url
    logger.info({ upstreamUrl }, 'spawned MCP upstream')
  } else if (config.mcpUpstreamUrl) {
    upstreamUrl = config.mcpUpstreamUrl
  } else {
    throw new Error('no MCP upstream configured')
  }

  const app = buildApp({
    issuerUrl: config.oidcIssuerUrl,
    audience: config.oidcAudience,
    resourceUrl: config.resourceUrl,
    allowSubs: config.allowSubs,
    allowEmails: config.allowEmails,
    allowGroups: config.allowGroups,
    upstreamUrl,
    rateLimitRpm: config.rateLimitRpm,
    allowOrigins: config.allowOrigins,
    staticClientId: config.staticClientId,
    staticClientSecret: config.staticClientSecret,
    upstreamPath: config.mcpUpstreamPath,
    forwardIdentity: config.forwardIdentity,
    clientLabel: config.clientLabel,
    groupCacheTtlSeconds: config.groupCacheTtlSeconds,
    ...(config.scopesSupported !== undefined && { scopesSupported: config.scopesSupported }),
  })

  const server = app.listen(config.port, () => {
    logger.info({ port: config.port }, 'mcp-oauth-proxy listening')
  })

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'shutting down')
    server.close()
    if (spawned) await spawned.shutdown()
    process.exit(0)
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'))
  process.on('SIGINT', () => shutdown('SIGINT'))
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    logger.error({ err }, 'fatal startup error')
    process.exit(1)
  })
}
