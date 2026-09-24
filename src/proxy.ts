import type { Express, Request, Response } from 'express'
import httpProxy from 'http-proxy-3'

export type ProxyOptions = {
  upstreamUrl: string
  // If set, all requests are rewritten to this exact path on the upstream (e.g. `/mcp`).
  // If undefined, paths pass through unchanged.
  upstreamPath: string | undefined
  // When true, identity headers are set on every proxied request (see below). Default false.
  forwardIdentity?: boolean | undefined
  // A credential of the proxy's own for the upstream, set as `Authorization: Bearer` after the
  // caller's credentials are stripped. Undefined: the upstream receives no Authorization at all.
  upstreamBearer?: string | undefined
}

type AuthedRequest = Request & { auth?: { sub: string; email?: string | undefined; username?: string | undefined } }

// The de-facto forward-auth convention (oauth2-proxy, Traefik ForwardAuth), not anything specific to
// one deployment.
//
// These three say *who*. They are always stripped from the caller and set only from the validated
// token: the caller is never a source for them.
const USER_HEADERS = ['x-forwarded-user', 'x-forwarded-preferred-username', 'x-forwarded-email'] as const

// This one says *what program*, and the proxy cannot know it -- one endpoint fronts every surface,
// and the token is identical whichever client obtained it. So the client declares it and the proxy
// forwards what it declared, rather than stamping a value from its own config.
//
// It is a label, never a credential: nothing here admits, denies or branches on it, and an upstream
// that did would be trusting the caller. A compromised session can declare anything, which costs a
// wrong provenance label and nothing else.
const CLIENT_HEADER = 'x-forwarded-client'

// Deliberately narrow, and a failure drops the header rather than repairing it. The upstream records
// this value verbatim -- in the deployment this was written for, into a git author line -- so a CR,
// an angle bracket or a space is a header-injection attempt, and a partially cleaned value is still
// a value someone else chose. `unknown` (the upstream's own default for an absent header) is the
// honest answer instead.
const CLIENT_LABEL = /^[a-z0-9][a-z0-9._-]{0,31}$/

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

    // Only after the strip, so the caller's token can never be what the upstream receives: the
    // upstream sees this proxy's credential or none. Auth has already admitted the caller -- an
    // unauthenticated request never reaches this handler, so the credential is never lent to one.
    if (opts.upstreamBearer) req.headers['authorization'] = `Bearer ${opts.upstreamBearer}`

    // The caller's own values for the *who* headers are dropped whether or not forwarding is on:
    // only this proxy, having authenticated the request, gets to say who is asking.
    for (const h of USER_HEADERS) delete req.headers[h]

    const declared = req.headers[CLIENT_HEADER]
    delete req.headers[CLIENT_HEADER]

    if (opts.forwardIdentity) {
      const auth = (req as AuthedRequest).auth
      if (auth) {
        req.headers['x-forwarded-user'] = auth.sub
        if (auth.username) req.headers['x-forwarded-preferred-username'] = auth.username
        if (auth.email) req.headers['x-forwarded-email'] = auth.email
      }
      // Node joins duplicate headers with ", ", which the pattern rejects -- so two of these is the
      // same as one malformed one, and neither reaches the upstream.
      if (typeof declared === 'string' && CLIENT_LABEL.test(declared)) req.headers[CLIENT_HEADER] = declared
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
