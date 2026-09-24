import { readFileSync } from 'node:fs'

// Read once at startup. A set-but-unusable file is a refusal to start, never a silent fallback to
// sending nothing: an upstream that expects the token would then answer every request 401, which
// looks like an auth failure on the *caller's* side and sends the operator looking in the wrong place.
//
// Error messages name the path and never the contents.
export const readUpstreamBearer = (path: string): string => {
  let raw: string
  try {
    raw = readFileSync(path, 'utf8')
  } catch (err) {
    throw new Error(
      `MCP_UPSTREAM_BEARER_FILE is set but unreadable: ${path} (${(err as NodeJS.ErrnoException).code ?? 'error'})`,
      { cause: err },
    )
  }
  // Secret files usually end in a newline; a token never contains whitespace.
  const token = raw.trim()
  if (token === '') throw new Error(`MCP_UPSTREAM_BEARER_FILE is empty: ${path}`)
  if (/\s/.test(token)) throw new Error(`MCP_UPSTREAM_BEARER_FILE holds more than one token: ${path}`)
  return token
}
