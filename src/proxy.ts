import type { Express, Request, Response } from 'express'
import httpProxy from 'http-proxy-3'

export type ProxyOptions = {
  upstreamUrl: string
  // If set, all requests are rewritten to this exact path on the upstream (e.g. `/mcp`).
  // If undefined, paths pass through unchanged.
  upstreamPath: string | undefined
  // When true, identity headers are set on every proxied request (see below). Default false.
  forwardIdentity?: boolean | undefined
  // Sent as X-Forwarded-Client when forwardIdentity is on and this is set.
  clientLabel?: string | undefined
}

type AuthedRequest = Request & { auth?: { sub: string; email?: string | undefined; username?: string | undefined } }

// The de-facto forward-auth convention (oauth2-proxy, Traefik ForwardAuth), not anything specific to
// one deployment. Always stripped from the caller; set only when the operator turned forwarding on.
const IDENTITY_HEADERS = ['x-forwarded-user', 'x-forwarded-preferred-username', 'x-forwarded-email', 'x-forwarded-client'] as const

export const mountProxy = (app: Express, opts: ProxyOptions) => {
  const proxy = httpProxy.createProxyServer({
    target: opts.upstreamUrl,
    changeOrigin: true,
    proxyTimeout: 60_000,
    timeout: 60_000,
    ws: false,
    // Append the immediate peer's address/port/proto to X-Forwarded-*. Client-supplied values still
    // pass through ahead of it (standard XFF chain semantics), but the caller is never the last word
    // on its own source address — an upstream that trusts the rightmost hop sees the real peer.
    xfwd: true,
  })

  proxy.on('error', (err, _req, res) => {
    if (res && 'writeHead' in res && !res.headersSent) {
      ;(res as Response).status(502).json({ error: 'upstream proxy error', message: err.message })
    }
  })

  // Catch-all — must be registered LAST in the Express stack.
  app.use((req: Request, res: Response) => {
    // The upstream MCP is behind this proxy and never validates the token itself; forwarding the
    // caller's bearer credential would hand a live IdP access token to it (which, under MCP_SPAWN_CMD,
    // is arbitrary third-party code). Auth has already run — the upstream needs none of this.
    delete req.headers['authorization']
    delete req.headers['proxy-authorization']
    delete req.headers['cookie']

    // The caller's own values for the identity headers are dropped whether or not forwarding is on:
    // only this proxy, having authenticated the request, gets to say who is asking.
    for (const h of IDENTITY_HEADERS) delete req.headers[h]
    if (opts.forwardIdentity) {
      const auth = (req as AuthedRequest).auth
      if (auth) {
        req.headers['x-forwarded-user'] = auth.sub
        if (auth.username) req.headers['x-forwarded-preferred-username'] = auth.username
        if (auth.email) req.headers['x-forwarded-email'] = auth.email
      }
      if (opts.clientLabel) req.headers['x-forwarded-client'] = opts.clientLabel
    }

    if (opts.upstreamPath) {
      // Rewrite the request URL so http-proxy forwards to the configured path on the upstream,
      // preserving any query string the client sent.
      const q = req.url.indexOf('?')
      req.url = q === -1 ? opts.upstreamPath : `${opts.upstreamPath}${req.url.slice(q)}`
    }
    proxy.web(req, res)
  })
}
