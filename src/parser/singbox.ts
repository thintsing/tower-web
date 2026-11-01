// sing-box `masque-client` endpoint import.
// Only CONNECT-IP endpoints are understood; ordinary outbounds are counted as
// rejected so a full config is never reported as a complete import.
import type { ProxyNode } from '../models/types'
import { nextNodeID, normalizedHost } from './util'

export interface ParsedSingBoxEndpoints {
  nodes: ProxyNode[]
  rejected: number
}

const ENDPOINT_KEYS = new Set([
  'type', 'tag', 'server', 'server_port', 'username', 'password', 'path',
  'headers', 'version', 'disable_version_fallback', 'tls', 'system', 'mtu',
])
const TLS_KEYS = new Set(['enabled', 'server_name', 'insecure', 'alpn', 'certificate'])
const BUILTIN_OUTBOUND_TYPES = new Set(['direct', 'block', 'dns', 'selector', 'urltest'])
const BAD_HOST = /[\s,/\\@?#=]/

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) return undefined
  return value as string[]
}

function stringMap(value: unknown): Record<string, string> | undefined {
  const map = record(value)
  if (!map || !Object.values(map).every((item) => typeof item === 'string')) return undefined
  return map as Record<string, string>
}

function integer(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) ? value : undefined
}

function optionalString(fields: Record<string, unknown>, key: string): string | undefined {
  const value = fields[key]
  if (value === undefined) return undefined
  return typeof value === 'string' ? value : undefined
}

/** One `masque-client` endpoint, validated field-by-field like the iOS parser. */
function parseEndpoint(raw: unknown, sourceID?: string): ProxyNode | undefined {
  const fields = record(raw)
  if (!fields || fields.type !== 'masque-client') return undefined
  if (!Object.keys(fields).every((key) => ENDPOINT_KEYS.has(key))) return undefined

  const serverValue = fields.server
  const port = integer(fields.server_port)
  if (typeof serverValue !== 'string' || !port || port < 1 || port > 65535) return undefined
  const server = normalizedHost(serverValue)
  if (!server || BAD_HOST.test(server)) return undefined
  if (fields.system !== undefined && fields.system !== false) return undefined

  for (const key of ['tag', 'username', 'password', 'path']) {
    if (fields[key] !== undefined && typeof fields[key] !== 'string') return undefined
  }
  for (const key of ['version', 'mtu']) {
    if (fields[key] !== undefined && integer(fields[key]) === undefined) return undefined
  }
  if (fields.headers !== undefined && stringMap(fields.headers) === undefined) return undefined
  if (fields.disable_version_fallback !== undefined && typeof fields.disable_version_fallback !== 'boolean') {
    return undefined
  }

  const tlsFields = fields.tls === undefined ? {} : record(fields.tls)
  if (!tlsFields || !Object.keys(tlsFields).every((key) => TLS_KEYS.has(key))) return undefined
  if (tlsFields.enabled !== undefined && typeof tlsFields.enabled !== 'boolean') return undefined
  if (tlsFields.server_name !== undefined && typeof tlsFields.server_name !== 'string') return undefined
  if (tlsFields.insecure !== undefined && typeof tlsFields.insecure !== 'boolean') return undefined
  const alpn = tlsFields.alpn === undefined ? undefined : stringArray(tlsFields.alpn)
  if (tlsFields.alpn !== undefined && !alpn) return undefined
  const certificate = tlsFields.certificate === undefined ? undefined : stringArray(tlsFields.certificate)
  if (tlsFields.certificate !== undefined && !certificate) return undefined

  const version = integer(fields.version)
  if (version !== undefined && ![1, 2, 3].includes(version)) return undefined
  const tls = tlsFields.enabled === true
  // HTTP/1.1 and HTTP/2 use TLS; HTTP/3 is QUIC and may run without it.
  if (version !== undefined && version !== 3 && !tls) return undefined
  const username = optionalString(fields, 'username')
  if (username?.includes(':')) return undefined
  const mtu = integer(fields.mtu)
  if (mtu !== undefined && (mtu < 1280 || mtu > 1500)) return undefined

  const tag = optionalString(fields, 'tag')?.trim()
  return {
    id: nextNodeID(),
    sourceID,
    kind: 'masque',
    name: tag || server,
    server,
    port,
    username,
    password: optionalString(fields, 'password'),
    path: optionalString(fields, 'path'),
    tls,
    sni: optionalString(tlsFields, 'server_name'),
    alpn: alpn?.join(','),
    skipCertificateVerification: tlsFields.insecure === true,
    rawURI: '',
    masque: {
      mode: 'basicConnectIP',
      httpVersion: version,
      mtu,
      headers: fields.headers === undefined ? undefined : stringMap(fields.headers),
      disableVersionFallback: fields.disable_version_fallback === undefined
        ? undefined
        : fields.disable_version_fallback === true,
      certificate: certificate && certificate.length > 0 ? certificate : undefined,
    },
  }
}

/**
 * Parse a sing-box config / endpoint snippet. Returns undefined when the JSON
 * is unrelated, so the caller can continue with the other import formats.
 */
export function parseSingBoxEndpoints(
  text: string,
  sourceID?: string,
): ParsedSingBoxEndpoints | undefined {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    return undefined
  }

  const root = record(value)
  const records: unknown[] = []
  if (root && Array.isArray(root.endpoints)) {
    records.push(...root.endpoints)
    // A full profile also carries ordinary outbounds. They are not imported,
    // but counting them keeps the "rejected" report honest.
    if (Array.isArray(root.outbounds)) {
      records.push(...root.outbounds.filter((item) => {
        const outbound = record(item)
        return outbound && !BUILTIN_OUTBOUND_TYPES.has(String(outbound.type))
      }))
    }
  } else if (root?.type === 'masque-client') {
    records.push(root)
  } else if (Array.isArray(value) && value.some((item) => record(item)?.type === 'masque-client')) {
    records.push(...value)
  } else {
    return undefined
  }

  const nodes: ProxyNode[] = []
  for (const item of records) {
    const node = parseEndpoint(item, sourceID)
    if (node) nodes.push(node)
  }
  return { nodes, rejected: records.length - nodes.length }
}
