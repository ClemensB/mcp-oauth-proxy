import type { Express, Request, Response } from 'express'
import httpProxy from 'http-proxy-3'

export type ProxyOptions = {
  upstreamUrl: string
  // If set, all requests are rewritten to this exact path on the upstream (e.g. `/mcp`).
  // If undefined, paths pass through unchanged.
  upstreamPath: string | undefined
}

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

    if (opts.upstreamPath) {
      // Rewrite the request URL so http-proxy forwards to the configured path on the upstream,
      // preserving any query string the client sent.
      const q = req.url.indexOf('?')
      req.url = q === -1 ? opts.upstreamPath : `${opts.upstreamPath}${req.url.slice(q)}`
    }
    proxy.web(req, res)
  })
}
