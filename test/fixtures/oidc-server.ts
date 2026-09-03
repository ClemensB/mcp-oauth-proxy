import { createServer, type Server } from 'node:http'
import type { Socket } from 'node:net'
import { decodeJwt, exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose'

// How /userinfo behaves. Everything other than 'ok' and 'absent-groups' is a failure the group lookup
// must refuse on rather than read as "member of nothing".
export type UserinfoMode =
  | 'ok'
  | 'absent-groups' // 200, but no groups claim at all — a user in no mapped groups
  | 'unauthorized' // 401
  | 'server-error' // 500
  | 'not-json' // 200 with a body that is not JSON, e.g. a signed (JWT) userinfo response
  | 'not-object' // 200 with a JSON array
  | 'wrong-sub' // 200 describing a different subject
  | 'groups-string' // 200 with groups as a space-joined string rather than an array
  | 'groups-mixed' // 200 with a groups array containing a non-string
  | 'hang' // accepts the request and never answers
  | 'drop' // destroys the connection

export type OidcFixture = {
  issuerUrl: string
  jwksUrl: string
  signToken: (claims: Record<string, unknown>, opts?: { expiresIn?: string; audience?: string }) => Promise<string>
  rotateKey: () => Promise<void>
  // Groups returned by /userinfo for a given token subject.
  setGroups: (sub: string, groups: string[]) => void
  setUserinfoMode: (mode: UserinfoMode) => void
  // Overrides what the discovery document advertises. null omits the field entirely.
  setUserinfoEndpoint: (url: string | null) => void
  userinfoCalls: () => number
  lastUserinfoAuthorization: () => string | undefined
  close: () => Promise<void>
}

export const startOidcFixture = async (alg = 'RS256'): Promise<OidcFixture> => {
  let { privateKey, publicKey } = await generateKeyPair(alg)
  let jwk: JWK & { kid: string } = { ...(await exportJWK(publicKey)), kid: 'k1', alg, use: 'sig' }

  const groupsBySub = new Map<string, string[]>()
  let mode: UserinfoMode = 'ok'
  let userinfoEndpointOverride: string | null | undefined
  let calls = 0
  let lastAuthorization: string | undefined
  // 'hang' leaves requests open; without tracking them, close() would never resolve.
  const sockets = new Set<Socket>()

  const server: Server = createServer((req, res) => {
    const port = (server.address() as { port: number }).port
    const issuer = `http://127.0.0.1:${port}`

    if (req.url?.startsWith('/.well-known/openid-configuration')) {
      const doc: Record<string, unknown> = {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
      }
      const userinfo = userinfoEndpointOverride === undefined ? `${issuer}/userinfo` : userinfoEndpointOverride
      if (userinfo !== null) doc['userinfo_endpoint'] = userinfo
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(doc))
      return
    }

    if (req.url === '/jwks') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ keys: [jwk] }))
      return
    }

    if (req.url === '/userinfo') {
      calls += 1
      lastAuthorization = req.headers.authorization
      if (mode === 'hang') return
      if (mode === 'drop') {
        req.socket.destroy()
        return
      }
      const header = req.headers.authorization
      if (!header?.toLowerCase().startsWith('bearer ')) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'invalid_token' }))
        return
      }
      if (mode === 'unauthorized' || mode === 'server-error') {
        res.writeHead(mode === 'unauthorized' ? 401 : 500, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'nope' }))
        return
      }
      if (mode === 'not-json') {
        // What a signed (application/jwt) userinfo response looks like to a JSON parser.
        res.writeHead(200, { 'content-type': 'application/jwt' })
        res.end('eyJhbGciOiJSUzI1NiJ9.e30.signature')
        return
      }

      let sub: string
      try {
        sub = String(decodeJwt(header.slice('bearer '.length).trim()).sub ?? '')
      } catch {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'invalid_token' }))
        return
      }
      const groups = groupsBySub.get(sub) ?? []

      let body: unknown
      if (mode === 'not-object') body = [{ sub, groups }]
      else if (mode === 'wrong-sub') body = { sub: `${sub}-someone-else`, groups }
      else if (mode === 'groups-string') body = { sub, groups: groups.join(' ') }
      else if (mode === 'groups-mixed') body = { sub, groups: [...groups, 42] }
      else if (mode === 'absent-groups') body = { sub, email: 'user@example.com' }
      else body = { sub, email: 'user@example.com', groups }

      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(body))
      return
    }

    res.writeHead(404)
    res.end()
  })

  server.on('connection', (socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as { port: number }).port
  const issuerUrl = `http://127.0.0.1:${port}`

  return {
    issuerUrl,
    jwksUrl: `${issuerUrl}/jwks`,
    signToken: async (claims, opts = {}) => {
      const jwt = new SignJWT(claims)
        .setProtectedHeader({ alg, kid: jwk.kid })
        .setIssuer(issuerUrl)
        .setIssuedAt()
        .setExpirationTime(opts.expiresIn ?? '5m')
      if (opts.audience) jwt.setAudience(opts.audience)
      return jwt.sign(privateKey)
    },
    rotateKey: async () => {
      const next = await generateKeyPair(alg)
      privateKey = next.privateKey
      publicKey = next.publicKey
      jwk = { ...(await exportJWK(publicKey)), kid: `k${Date.now()}`, alg, use: 'sig' }
    },
    setGroups: (sub, groups) => groupsBySub.set(sub, groups),
    setUserinfoMode: (next) => {
      mode = next
    },
    setUserinfoEndpoint: (url) => {
      userinfoEndpointOverride = url
    },
    userinfoCalls: () => calls,
    lastUserinfoAuthorization: () => lastAuthorization,
    close: () =>
      new Promise<void>((resolve, reject) => {
        for (const socket of sockets) socket.destroy()
        server.close((err) => (err ? reject(err) : resolve()))
      }),
  }
}
