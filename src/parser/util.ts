// Shared parsing helpers ported from Tower iOS SubscriptionParser.swift.

/** URL-safe-tolerant base64 → utf8 string, or undefined. */
export function decodeBase64String(value: string): string | undefined {
  let normalized = value.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '')
  const remainder = normalized.length % 4
  if (remainder !== 0) normalized += '='.repeat(4 - remainder)
  try {
    const binary = atob(normalized)
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0))
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return undefined
  }
}

/** utf8 → standard base64. */
export function encodeBase64String(value: string): string {
  const bytes = new TextEncoder().encode(value)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary)
}

/** `a=b&c=d` → dictionary. Values are NOT percent-decoded (caller decides). */
export function queryDictionary(query: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const item of query.split('&')) {
    const eq = item.indexOf('=')
    if (eq < 0) continue
    out[item.slice(0, eq)] = item.slice(eq + 1)
  }
  return out
}

export function boolString(value: string | undefined | null): boolean {
  if (!value) return false
  return ['true', '1', 'yes', 'tls'].includes(value.toLowerCase())
}

/**
 * Share links encode the name form-style, so `+` is a space. Strictly a URI
 * fragment keeps `+` literal, but every airport writes it the other way.
 */
export function normalizedName(value: string | undefined | null, fallback: string): string {
  const spaced = (value ?? '').replace(/\+/g, ' ')
  const trimmed = spaced.trim()
  return trimmed === '' ? fallback : trimmed
}

/** Strips the brackets off an IPv6 literal. */
export function normalizedHost(value: string): string {
  const trimmed = value.trim()
  if (trimmed.startsWith('[') && trimmed.endsWith(']') && trimmed.length > 2) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

/** `host:port` with IPv6 bracket support. */
export function parseEndpoint(value: string): { host: string; port: number } | undefined {
  let host: string
  let portText: string
  if (value.startsWith('[')) {
    const close = value.indexOf(']')
    if (close < 0) return undefined
    host = value.slice(1, close)
    const rest = value.slice(close + 1)
    if (!rest.startsWith(':')) return undefined
    portText = rest.slice(1)
  } else {
    const colon = value.lastIndexOf(':')
    if (colon < 0) return undefined
    host = value.slice(0, colon)
    portText = value.slice(colon + 1)
  }
  const port = Number(portText)
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return undefined
  return { host: normalizedHost(host), port }
}

/** Comma-separated values → trimmed non-empty array. */
export function csvValues(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
}

/** Hysteria bandwidth field: bare number, "100 Mbps", "100M". */
export function mbps(value: string | undefined): number | undefined {
  if (!value) return undefined
  const m = value.trim().match(/^([\d.]+)\s*(mbps|m)?$/i)
  if (!m) return undefined
  const n = Number(m[1])
  return Number.isFinite(n) ? n : undefined
}

export function normalizedTransport(value: string | undefined | null): string | undefined {
  const v = value?.trim().toLowerCase()
  if (!v) return undefined
  switch (v) {
    case 'tcp':
    case 'none':
      return undefined
    case 'websocket':
    case 'ws':
      return 'ws'
    case 'http2':
      return 'h2'
    case 'http-upgrade':
    case 'httpupgrade':
      return 'httpupgrade'
    case 'splithttp':
      return 'xhttp'
    default:
      return v
  }
}

export function normalizedVMessTransport(value: string | undefined | null): string | undefined {
  const v = value?.trim().toLowerCase()
  if (!v) return undefined
  switch (v) {
    case 'websocket':
    case 'ws':
      return 'ws'
    case 'http2':
      return 'h2'
    case 'http-upgrade':
    case 'httpupgrade':
      return 'httpupgrade'
    case 'splithttp':
      return 'xhttp'
    case 'none':
      return undefined
    default:
      return v
  }
}

let idCounter = 0
export function nextNodeID(): string {
  return `n${Date.now().toString(36)}-${(idCounter++).toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 8)}`
}
