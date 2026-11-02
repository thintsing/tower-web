// Surge / Loon / Quantumult X node configuration import.
//
// These clients share the same INI shape for [Proxy], but their proxy lines use
// different positional fields and option names. Keep one parser per section
// family and one internal ProxyNode model; the public subscription parser
// (`parse`) remains the only entry point.
import type { ProxyKind, ProxyNode } from '../models/types'
import { PROXY_KIND_TITLES } from '../models/types'
import { baseNode } from './uri'
import {
  boolString,
  normalizedHost,
  normalizedTransport,
  parseEndpoint,
} from './util'

export interface ClientProxyParseResult {
  nodes: ProxyNode[]
  rejected: number
}

type SectionKind = 'none' | 'proxy' | 'server-local' | 'wireguard'

interface WireGuardSection {
  name: string
  options: Record<string, string>
  peers: string[]
}

interface PeerFields {
  publicKey?: string
  allowedIPs?: string
  endpoint?: string
  preSharedKey?: string
  keepalive?: number
  reserved?: string
}

const COMMENT_PREFIX = /^(?:#|;|\/\/)/
const INVALID_HOST = /[\s,/\\@?#=]/

function cleanName(value: string): string {
  return value.replace(/[\r\n]+/g, ' ').trim()
}

function unquote(value: string): string {
  const trimmed = value.trim()
  if (trimmed.length >= 2) {
    const first = trimmed[0]
    const last = trimmed[trimmed.length - 1]
    if ((first === '"' || first === "'") && first === last) return trimmed.slice(1, -1)
  }
  return trimmed
}

/** Split on top-level commas, respecting quotes and (), [], {}. */
function splitTopLevel(value: string): string[] {
  const fields: string[] = []
  let current = ''
  let quote: string | undefined
  let escaped = false
  let depth = 0
  for (const char of value) {
    if (escaped) {
      current += char
      escaped = false
      continue
    }
    if (char === '\\') {
      current += char
      escaped = true
      continue
    }
    if (quote) {
      current += char
      if (char === quote) quote = undefined
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      current += char
      continue
    }
    if (char === '(' || char === '[' || char === '{') depth += 1
    else if (char === ')' || char === ']' || char === '}') depth = Math.max(0, depth - 1)
    if (char === ',' && depth === 0) {
      fields.push(current.trim())
      current = ''
      continue
    }
    current += char
  }
  fields.push(current.trim())
  return fields
}

function parseOptions(fields: string[], start = 0): Record<string, string> {
  const options: Record<string, string> = {}
  for (const field of fields.slice(start)) {
    const eq = field.indexOf('=')
    if (eq < 0) continue
    const key = field.slice(0, eq).trim().toLowerCase()
    if (!key) continue
    options[key] = unquote(field.slice(eq + 1))
  }
  return options
}

function positional(fields: string[], index: number): string | undefined {
  const value = fields[index]
  if (!value || value.includes('=')) return undefined
  const trimmed = unquote(value)
  return trimmed || undefined
}

function option(options: Record<string, string>, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = options[key]
    if (value !== undefined) {
      const trimmed = unquote(value)
      if (trimmed) return trimmed
    }
  }
  return undefined
}

function boolOption(options: Record<string, string>, ...keys: string[]): boolean | undefined {
  const value = option(options, ...keys)
  return value === undefined ? undefined : boolString(value)
}

function numberOption(options: Record<string, string>, ...keys: string[]): number | undefined {
  const value = option(options, ...keys)
  if (value === undefined) return undefined
  const parsed = Number(value)
  return Number.isInteger(parsed) ? parsed : undefined
}

function hostPort(fields: string[]): { host: string; port: number } | undefined {
  if (fields.length < 3) return undefined
  const host = normalizedHost(unquote(fields[1]))
  const port = Number(unquote(fields[2]))
  if (!host || INVALID_HOST.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
    return undefined
  }
  return { host, port }
}

function makeNode(
  kind: ProxyKind,
  name: string,
  host: string,
  port: number,
  raw: string,
  sourceID?: string,
): ProxyNode {
  const node = baseNode(kind, raw, sourceID)
  node.name = cleanName(name) || `${PROXY_KIND_TITLES[kind]} · ${host}`
  node.server = host
  node.port = port
  return node
}

function decodeQuanXALPN(value: string | undefined): string | undefined {
  if (!value) return undefined
  const hex = value.replace(/[^0-9a-f]/gi, '')
  if (!hex || hex.length % 2 !== 0) return undefined
  const bytes: number[] = []
  for (let index = 0; index < hex.length; index += 2) {
    bytes.push(Number.parseInt(hex.slice(index, index + 2), 16))
  }
  const protocols: string[] = []
  let cursor = 0
  while (cursor < bytes.length) {
    const length = bytes[cursor]
    if (!length || cursor + 1 + length > bytes.length) return undefined
    protocols.push(String.fromCharCode(...bytes.slice(cursor + 1, cursor + 1 + length)))
    cursor += length + 1
  }
  return protocols.join(',') || undefined
}

function headerFromWSHeaders(value: string | undefined): string | undefined {
  if (!value) return undefined
  for (const item of value.split('|')) {
    const colon = item.indexOf(':')
    if (colon < 0) continue
    const key = item.slice(0, colon).trim().toLowerCase()
    if (key === 'host') return item.slice(colon + 1).trim() || undefined
  }
  return undefined
}

/** Common TLS options shared by Surge and Loon lines. */
function applyTLS(node: ProxyNode, options: Record<string, string>): void {
  const tls = boolOption(options, 'tls', 'over-tls')
  if (tls !== undefined) node.tls = tls
  const sni = option(options, 'sni', 'tls-name', 'servername', 'server-name')
  if (sni) node.sni = sni
  if (!tls && option(options, 'tls-name')) node.tls = true
  const skip = boolOption(options, 'skip-cert-verify')
  if (skip !== undefined) node.skipCertificateVerification = skip
  if (boolOption(options, 'tls-verification') === false) node.skipCertificateVerification = true
  if (boolOption(options, 'insecure', 'allow-insecure')) node.skipCertificateVerification = true
  const alpn = option(options, 'alpn')
  if (alpn) node.alpn = alpn
  const fingerprint = option(
    options,
    'server-cert-fingerprint-sha256',
    'tls-cert-sha256',
    'tls-pubkey-sha256',
    'certificate-fingerprint',
  )
  if (fingerprint) node.certificateFingerprint = fingerprint
  const clientFingerprint = option(options, 'client-fingerprint', 'fp')
  if (clientFingerprint) node.fingerprint = clientFingerprint
}

/** Surge/Loon transport fields (`ws`, `ws-path`, `transport=ws`, `path`, `host`). */
function applyTransport(node: ProxyNode, options: Record<string, string>): void {
  let transport = normalizedTransport(option(options, 'transport', 'network'))
  if (!transport && boolOption(options, 'ws') === true) transport = 'ws'
  node.transport = transport
  if (!transport) return
  const path = option(options, 'ws-path', 'path')
  if (path) node.path = path
  const headers = option(options, 'ws-headers')
  const host = option(options, 'host', 'authority') ?? headerFromWSHeaders(headers)
  if (host) node.hostHeader = host
  if (transport === 'grpc') {
    node.path = option(options, 'grpc-service-name', 'service-name', 'servicename') ?? node.path
  }
}

function applyUDP(node: ProxyNode, options: Record<string, string>): void {
  const udp = boolOption(options, 'udp-relay', 'udp')
  if (udp !== undefined) node.udpRelayEnabled = udp
}

function applyReality(node: ProxyNode, options: Record<string, string>): void {
  const publicKey = option(options, 'reality-base64-pubkey', 'reality-public-key', 'pbk')
  if (publicKey) {
    node.realityPublicKey = publicKey
    node.tls = true
  }
  const shortID = option(options, 'reality-hex-shortid', 'reality-short-id', 'sid')
  if (shortID) node.realityShortID = shortID
}

function parseSSR(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const cipher = option(options, 'encrypt-method', 'method', 'cipher') ?? positional(fields, 3)
  const password = option(options, 'password') ?? positional(fields, 4)
  if (!cipher || !password) return undefined
  const node = makeNode('ssr', name, target.host, target.port, raw, sourceID)
  node.cipher = cipher
  node.password = password
  node.protocolName = option(options, 'protocol')
  node.protocolParam = option(options, 'protocol-param', 'protocolparam')
  node.obfs = option(options, 'obfs')
  node.obfsParam = option(options, 'obfs-param', 'obfs-host')
  applyUDP(node, options)
  return node
}

function parseShadowsocks(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const cipher = option(options, 'encrypt-method', 'method', 'cipher') ?? positional(fields, 3)
  const password = option(options, 'password') ?? positional(fields, 4)
  if (!cipher || !password) return undefined
  const node = makeNode('ss', name, target.host, target.port, raw, sourceID)
  node.cipher = cipher
  node.password = password
  node.tls = boolOption(options, 'tls', 'over-tls') ?? false
  const obfs = option(options, 'obfs-name', 'obfs')
  if (obfs) {
    node.obfs = obfs
    node.obfsParam = option(options, 'obfs-host')
    node.path = option(options, 'obfs-uri')
  }
  const shadowPassword = option(options, 'shadow-tls-password')
  if (shadowPassword) {
    const version = numberOption(options, 'shadow-tls-version')
    const host = option(options, 'shadow-tls-sni', 'shadow-tls-host')
    if (version === undefined || !host) return undefined
    node.shadowTLS = {
      version,
      host,
      password: shadowPassword,
      skipCertificateVerification: boolOption(options, 'shadow-tls-skip-verify') ?? false,
    }
    node.plugin = 'shadow-tls'
  }
  applyTLS(node, options)
  applyUDP(node, options)
  return node
}

function parseVMess(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const positionalCipher = positional(fields, 3)
  const positionalUUID = positional(fields, 4)
  const uuid = option(options, 'username', 'uuid')
    ?? positionalUUID
    ?? positional(fields, 3)
  if (!uuid) return undefined
  const cipher = option(options, 'encrypt-method', 'method', 'cipher')
    ?? (positionalUUID ? positionalCipher : undefined)
    ?? 'auto'
  const node = makeNode('vmess', name, target.host, target.port, raw, sourceID)
  node.uuid = uuid
  node.cipher = cipher
  const alterID = numberOption(options, 'alterid', 'alter-id')
  const aead = boolOption(options, 'vmess-aead', 'aead')
  node.alterID = aead === false ? (alterID && alterID > 0 ? alterID : 1) : alterID ?? 0
  applyTLS(node, options)
  applyTransport(node, options)
  node.uuid = uuid
  return node
}

function parseVLESS(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const uuid = option(options, 'username', 'uuid') ?? positional(fields, 3)
  if (!uuid) return undefined
  const node = makeNode('vless', name, target.host, target.port, raw, sourceID)
  node.uuid = uuid
  node.flow = option(options, 'flow')
  node.vlessEncryption = option(options, 'encryption')
  if (node.vlessEncryption?.toLowerCase() === 'none') node.vlessEncryption = undefined
  applyTLS(node, options)
  applyTransport(node, options)
  applyReality(node, options)
  applyUDP(node, options)
  return node
}

function parseTrojan(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const password = option(options, 'password') ?? positional(fields, 3)
  if (!password) return undefined
  const node = makeNode('trojan', name, target.host, target.port, raw, sourceID)
  node.password = password
  node.tls = true
  applyTLS(node, options)
  node.tls = true
  applyTransport(node, options)
  applyReality(node, options)
  applyUDP(node, options)
  return node
}

function parseHysteria2(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const password = option(options, 'password') ?? positional(fields, 3)
  if (!password) return undefined
  const node = makeNode('hysteria2', name, target.host, target.port, raw, sourceID)
  node.password = password
  node.tls = true
  applyTLS(node, options)
  node.tls = true
  const salamander = option(options, 'salamander-password')
  const gecko = option(options, 'gecko-password')
  const obfs = option(options, 'obfs')
  if (salamander) {
    node.obfs = 'salamander'
    node.obfsParam = salamander
  } else if (gecko) {
    node.obfs = 'gecko'
    node.obfsParam = gecko
  } else if (obfs) {
    const obfsPassword = option(options, 'obfs-password', 'obfs_password', 'obfs-pwd')
    if (!obfsPassword) return undefined
    node.obfs = obfs
    node.obfsParam = obfsPassword
  }
  const portHopping = option(options, 'port-hopping')
  if (portHopping) node.portHopping = portHopping.replace(/;/g, ',').replace(/\s+/g, '')
  const bandwidth = numberOption(options, 'download-bandwidth')
  if (bandwidth !== undefined) node.downMbps = bandwidth
  applyUDP(node, options)
  return node
}

function parseTUIC(
  name: string,
  type: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  // Surge uses tuic for v4 token auth and tuic-v5 for UUID + password. Both
  // Loon and the internal model express TUIC v5 only. Older Tower releases
  // emitted `tuic` with uuid/password; accept that as a tolerant v5 form.
  if (type !== 'tuic-v5' && type !== 'tuic') return undefined
  const target = hostPort(fields)
  if (!target) return undefined
  const uuid = option(options, 'uuid')
  const password = option(options, 'password')
  if (!uuid || !password) return undefined
  const node = makeNode('tuic', name, target.host, target.port, raw, sourceID)
  node.uuid = uuid
  node.password = password
  node.tls = true
  applyTLS(node, options)
  node.tls = true
  node.alpn = option(options, 'alpn') ?? node.alpn
  node.congestionControl = option(options, 'congestion-controller', 'congestion-control')
  node.udpRelayMode = option(options, 'udp-relay-mode')
  const portHopping = option(options, 'port-hopping')
  if (portHopping) node.portHopping = portHopping.replace(/;/g, ',').replace(/\s+/g, '')
  applyUDP(node, options)
  return node
}

function parseHTTPProxy(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
  https = false,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const username = option(options, 'username') ?? positional(fields, 3)
  const password = option(options, 'password') ?? positional(fields, 4)
  if (username && !password) return undefined
  const node = makeNode('http', name, target.host, target.port, raw, sourceID)
  node.username = username
  node.password = password
  node.tls = https
  applyTLS(node, options)
  if (https) node.tls = true
  applyUDP(node, options)
  return node
}

function parseSOCKS5(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const username = option(options, 'username') ?? positional(fields, 3)
  const password = option(options, 'password') ?? positional(fields, 4)
  if (username && !password) return undefined
  const node = makeNode('socks5', name, target.host, target.port, raw, sourceID)
  node.username = username
  node.password = password
  applyTLS(node, options)
  applyUDP(node, options)
  return node
}

function parseSnell(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const psk = option(options, 'psk', 'password')
  if (!psk) return undefined
  const node = makeNode('snell', name, target.host, target.port, raw, sourceID)
  node.password = psk
  node.version = numberOption(options, 'version')
  node.obfs = option(options, 'obfs')
  node.obfsParam = option(options, 'obfs-host')
  applyUDP(node, options)
  return node
}

function parseAnnTLS(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const password = option(options, 'password') ?? positional(fields, 3)
  if (!password) return undefined
  const node = makeNode('anytls', name, target.host, target.port, raw, sourceID)
  node.password = password
  node.tls = true
  applyTLS(node, options)
  node.tls = true
  node.idleSessionCheckInterval = numberOption(options, 'idle-session-check-interval')
  node.idleSessionTimeout = numberOption(options, 'idle-session-timeout')
  node.minIdleSession = numberOption(options, 'min-idle-session')
  applyUDP(node, options)
  return node
}

function parseTrustTunnel(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const username = option(options, 'username')
  const password = option(options, 'password')
  if (!username || !password) return undefined
  const node = makeNode('trusttunnel', name, target.host, target.port, raw, sourceID)
  node.username = username
  node.password = password
  node.tls = true
  node.trustTunnel = { quic: boolOption(options, 'h3', 'quic') ?? false }
  applyTLS(node, options)
  node.tls = true
  applyUDP(node, options)
  return node
}

function parseSSH(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const username = option(options, 'username')
  const password = option(options, 'password')
  if (!username || (!password && !option(options, 'private-key'))) return undefined
  // A Keystore reference only gives us a key name, not the key material;
  // importing it as password auth would create a node that cannot log in.
  if (!password) return undefined
  const node = makeNode('ssh', name, target.host, target.port, raw, sourceID)
  node.username = username
  node.password = password
  const hostKeys = option(options, 'server-fingerprint')
  node.ssh = { hostKeys: hostKeys ? splitTopLevel(hostKeys).map(unquote).filter(Boolean) : [] }
  return node
}

function parseMASQUE(
  name: string,
  fields: string[],
  options: Record<string, string>,
  raw: string,
  sourceID?: string,
): ProxyNode | undefined {
  const target = hostPort(fields)
  if (!target) return undefined
  const username = option(options, 'username')
  if (username?.includes(':')) return undefined
  const allowed = new Set([
    'username', 'password', 'sni', 'alpn', 'skip-cert-verify', 'server-cert-fingerprint-sha256',
  ])
  if (Object.keys(options).some((key) => !allowed.has(key))) return undefined
  const node = makeNode('masque', name, target.host, target.port, raw, sourceID)
  node.username = username
  node.password = option(options, 'password')
  node.tls = true
  node.sni = option(options, 'sni')
  node.alpn = option(options, 'alpn')
  node.certificateFingerprint = option(options, 'server-cert-fingerprint-sha256')
  node.skipCertificateVerification = boolOption(options, 'skip-cert-verify') ?? false
  return node
}

/** Parse one `[WireGuard <name>]` section into a single peer (the model has one). */
function collectWireGuardSections(lines: string[]): Map<string, WireGuardSection> {
  const sections = new Map<string, WireGuardSection>()
  let current: WireGuardSection | undefined
  for (const rawLine of lines) {
    const line = rawLine.trim()
    const header = line.match(/^\[WireGuard\s+(.+)\]$/i)
    if (header) {
      current = { name: header[1].trim(), options: {}, peers: [] }
      sections.set(current.name, current)
      continue
    }
    if (line.startsWith('[')) {
      current = undefined
      continue
    }
    if (!current || !line || COMMENT_PREFIX.test(line)) continue
    const eq = line.indexOf('=')
    if (eq < 0) continue
    const key = line.slice(0, eq).trim().toLowerCase()
    const value = line.slice(eq + 1).trim()
    if (key === 'peer') current.peers.push(value)
    else if (key) current.options[key] = unquote(value)
  }
  return sections
}

function decodeClientID(value: string | undefined): string | undefined {
  if (!value) return undefined
  const text = value.trim()
  if (/^\d{1,3}\/\d{1,3}\/\d{1,3}$/.test(text)) {
    return text.split('/').map((item) => String(Number(item))).join(',')
  }
  if (/^[0-9a-f]{6}$/i.test(text)) {
    return [0, 2, 4].map((offset) => String(Number.parseInt(text.slice(offset, offset + 2), 16))).join(',')
  }
  if (text.length === 4) {
    try {
      const decoded = atob(text)
      if (decoded.length === 3) {
        return [...decoded].map((char) => String(char.charCodeAt(0))).join(',')
      }
    } catch {
      return undefined
    }
  }
  return undefined
}

function normalizeReserved(value: string | undefined): string | undefined {
  if (!value) return undefined
  const text = value.trim().replace(/^\[|\]$/g, '')
  const bytes = splitTopLevel(text).map((item) => Number(unquote(item)))
  if (!bytes.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)) return undefined
  return bytes.join(',')
}

function parsePeerObject(value: string): PeerFields | undefined {
  let body = value.trim()
  while (
    (body.startsWith('(') && body.endsWith(')'))
    || (body.startsWith('{') && body.endsWith('}'))
  ) {
    body = body.slice(1, -1).trim()
  }
  const fields = splitTopLevel(body)
  const options: Record<string, string> = {}
  let lastKey = ''
  for (const field of fields) {
    const eq = field.indexOf('=')
    if (eq < 0) {
      // Surge permits unquoted `allowed-ips = 0.0.0.0/0, ::/0`; the second
      // CIDR is a continuation rather than a new key.
      const continuation = unquote(field)
      if (lastKey === 'allowed-ips' && /[/:]/.test(continuation)) {
        options['allowed-ips'] = `${options['allowed-ips']}, ${continuation}`
      }
      continue
    }
    const key = field.slice(0, eq).trim().toLowerCase()
    const rawValue = field.slice(eq + 1).trim()
    if (!key) continue
    options[key] = unquote(rawValue)
    lastKey = key
  }
  const endpoint = options['endpoint']
  const publicKey = options['public-key'] ?? options['publickey']
  if (!publicKey || !endpoint) return undefined
  const allowedIPs = options['allowed-ips'] ?? options['allowedips']
  if (!allowedIPs) return undefined
  const reservedRaw = options['reserved']
  const clientIDRaw = options['client-id']
  const reserved = normalizeReserved(reservedRaw)
  const clientID = decodeClientID(clientIDRaw)
  // A present but malformed reserved/client-id is critical for WARP-style
  // deployments; reject instead of silently dropping the routing bytes.
  if ((reservedRaw && !reserved) || (clientIDRaw && !clientID)) return undefined
  return {
    publicKey,
    allowedIPs,
    endpoint,
    preSharedKey: options['preshared-key'] ?? options['pre-shared-key'] ?? options['presharedkey'],
    keepalive: numberOption(options, 'keepalive', 'persistent-keepalive'),
    reserved: reserved ?? clientID,
  }
}

function peerList(value: string | undefined): PeerFields | undefined {
  if (!value) return undefined
  let body = value.trim()
  if (body.startsWith('[') && body.endsWith(']')) body = body.slice(1, -1).trim()
  const objects = splitTopLevel(body).filter((item) => item.trim())
  if (objects.length !== 1) return undefined
  return parsePeerObject(objects[0])
}

function parseWireGuard(
  name: string,
  options: Record<string, string>,
  raw: string,
  sourceID: string | undefined,
  wgSections: Map<string, WireGuardSection>,
): ProxyNode | undefined {
  // Surge: policy line points at a section. Loon: all fields are inline.
  const sectionName = option(options, 'section-name')
  const section = sectionName
    ? wgSections.get(sectionName)
      ?? [...wgSections.values()].find((item) => item.name.toLowerCase() === sectionName.toLowerCase())
    : undefined
  if (sectionName && !section) return undefined
  if (section && section.peers.length !== 1) return undefined
  const source = section?.options ?? options
  const peersRaw = section ? section.peers : [option(options, 'peers') ?? '']
  const peer = peersRaw.length === 1 ? peerList(peersRaw[0]) : undefined
  if (!peer) return undefined
  const endpoint = parseEndpoint(peer.endpoint ?? '')
  if (!endpoint || INVALID_HOST.test(endpoint.host)) return undefined
  const privateKey = option(source, 'private-key')
  const ipv4 = option(source, 'self-ip', 'interface-ip')
  const ipv6 = option(source, 'self-ip-v6', 'interface-ipv6')
  if (!privateKey || (!ipv4 && !ipv6)) return undefined
  const node = makeNode('wireguard', name, endpoint.host, endpoint.port, raw, sourceID)
  node.wireGuardPrivateKey = privateKey
  node.wireGuardPublicKey = peer.publicKey
  node.wireGuardPreSharedKey = peer.preSharedKey
  node.wireGuardIPv4 = ipv4
  node.wireGuardIPv6 = ipv6
  node.wireGuardAllowedIPs = peer.allowedIPs
  node.wireGuardReserved = peer.reserved
  node.wireGuardMTU = numberOption(source, 'mtu')
  node.wireGuardPersistentKeepalive = numberOption(source, 'keepalive', 'keeyalive') ?? peer.keepalive
  const dns = option(source, 'dns-server', 'dns')
  const dns6 = option(source, 'dns6', 'dnsv6')
  const dnsValues = [dns, dns6].filter(Boolean).join(',')
  node.wireGuardDNS = dnsValues || undefined
  node.udpRelayEnabled = true
  return node
}

function parseProxyLine(
  raw: string,
  sourceID: string | undefined,
  wgSections: Map<string, WireGuardSection>,
): ProxyNode | undefined {
  const eq = raw.indexOf('=')
  if (eq < 0) return undefined
  const name = cleanName(raw.slice(0, eq))
  const body = raw.slice(eq + 1).trim()
  const fields = splitTopLevel(body)
  const type = unquote(fields[0] ?? '').toLowerCase()
  if (!type) return undefined
  const options = parseOptions(fields, 3)

  if (type === 'wireguard' || type === 'wg') {
    return parseWireGuard(name, parseOptions(fields, 1), raw, sourceID, wgSections)
  }
  if (type === 'tuic' || type === 'tuic-v4' || type === 'tuic-v5') {
    return parseTUIC(name, type, fields, options, raw, sourceID)
  }
  if (type === 'ss') {
    return parseShadowsocks(name, fields, options, raw, sourceID)
  }
  if (type === 'shadowsocks') {
    return parseShadowsocks(name, fields, options, raw, sourceID)
  }
  if (type === 'ssr' || type === 'shadowsocksr') {
    return parseSSR(name, fields, options, raw, sourceID)
  }
  if (type === 'vmess') {
    return parseVMess(name, fields, options, raw, sourceID)
  }
  if (type === 'vless') {
    return parseVLESS(name, fields, options, raw, sourceID)
  }
  if (type === 'trojan') {
    return parseTrojan(name, fields, options, raw, sourceID)
  }
  if (type === 'hysteria2' || type === 'hy2') {
    return parseHysteria2(name, fields, options, raw, sourceID)
  }
  if (type === 'http' || type === 'https') {
    return parseHTTPProxy(name, fields, options, raw, sourceID, type === 'https')
  }
  if (type === 'socks5' || type === 'socks') {
    return parseSOCKS5(name, fields, options, raw, sourceID)
  }
  if (type === 'snell') {
    return parseSnell(name, fields, options, raw, sourceID)
  }
  if (type === 'anytls') {
    return parseAnnTLS(name, fields, options, raw, sourceID)
  }
  if (type === 'trust-tunnel' || type === 'trusttunnel') {
    return parseTrustTunnel(name, fields, options, raw, sourceID)
  }
  if (type === 'ssh') {
    return parseSSH(name, fields, options, raw, sourceID)
  }
  if (type === 'masque') {
    return parseMASQUE(name, fields, options, raw, sourceID)
  }
  // Surge accepts ssr as `ssr`; Loon uses `ShadowsocksR` (handled above).
  return undefined
}

/** Quantumult X [server_local] line: `type=host:port, key=value, …`. */
function parseQuanXLine(raw: string, sourceID?: string): ProxyNode | undefined {
  const eq = raw.indexOf('=')
  if (eq < 0) return undefined
  const type = unquote(raw.slice(0, eq)).toLowerCase()
  const fields = splitTopLevel(raw.slice(eq + 1))
  const address = parseEndpoint(unquote(fields[0] ?? ''))
  if (!address || INVALID_HOST.test(address.host)) return undefined
  const options = parseOptions(fields, 1)
  const tag = option(options, 'tag') ?? address.host
  const make = (kind: ProxyKind): ProxyNode => makeNode(kind, tag, address.host, address.port, raw, sourceID)
  const tlsParts = (node: ProxyNode): void => {
    if (boolOption(options, 'over-tls') === true) node.tls = true
    const sni = option(options, 'tls-host')
      ?? (node.tls ? option(options, 'obfs-host') : undefined)
    if (sni) node.sni = sni
    const alpn = decodeQuanXALPN(option(options, 'tls-alpn')) ?? option(options, 'alpn')
    if (alpn) node.alpn = alpn
    node.skipCertificateVerification = boolOption(options, 'tls-verification') === false
      || boolOption(options, 'insecure') === true
    const cert = option(options, 'tls-cert-sha256', 'tls-pubkey-sha256')
    if (cert) node.certificateFingerprint = cert
    applyReality(node, options)
    if (node.realityPublicKey) node.tls = true
  }
  const applyWs = (node: ProxyNode, obfs: string | undefined): void => {
    if (obfs === 'ws' || obfs === 'wss') {
      node.transport = 'ws'
      node.path = option(options, 'obfs-uri')
      node.hostHeader = option(options, 'obfs-host')
      node.tls = obfs === 'wss'
      if (obfs === 'wss' && node.hostHeader) node.sni = node.hostHeader
    } else if (obfs === 'http') {
      node.transport = 'http'
      node.path = option(options, 'obfs-uri')
      node.hostHeader = option(options, 'obfs-host')
    }
  }

  if (type === 'shadowsocks') {
    const cipher = option(options, 'method', 'cipher')
    const password = option(options, 'password')
    if (!cipher || !password) return undefined
    if (option(options, 'ssr-protocol')) {
      const node = make('ssr')
      node.cipher = cipher
      node.password = password
      node.protocolName = option(options, 'ssr-protocol')
      node.protocolParam = option(options, 'ssr-protocol-param')
      node.obfs = option(options, 'obfs')
      node.obfsParam = option(options, 'obfs-host')
      applyUDP(node, options)
      return node
    }
    const node = make('ss')
    node.cipher = cipher
    node.password = password
    const obfs = option(options, 'obfs')?.toLowerCase()
    if (obfs === 'ws' || obfs === 'wss') {
      node.plugin = 'v2ray-plugin'
      // QuanX's v2ray-plugin mode is mux=0; leave mux enabled would make the
      // export gate (and some servers) reject the node.
      node.pluginMux = false
      node.transport = 'ws'
      node.path = option(options, 'obfs-uri')
      node.hostHeader = option(options, 'obfs-host')
      node.tls = obfs === 'wss'
      if (obfs === 'wss' && node.hostHeader) node.sni = node.hostHeader
    } else if (obfs === 'over-tls') {
      node.tls = true
      node.sni = option(options, 'tls-host', 'obfs-host')
    } else if (obfs) {
      node.obfs = obfs
      node.obfsParam = option(options, 'obfs-host')
      node.path = option(options, 'obfs-uri')
    }
    tlsParts(node)
    applyUDP(node, options)
    return node
  }

  if (type === 'vmess' || type === 'vless') {
    const uuid = option(options, 'password')
    if (!uuid) return undefined
    const node = make(type === 'vmess' ? 'vmess' : 'vless')
    node.uuid = uuid
    if (type === 'vmess') {
      const method = option(options, 'method')
      node.cipher = method && method.toLowerCase() !== 'none' ? method : 'auto'
      node.alterID = boolOption(options, 'aead') === false ? 1 : 0
    }
    node.flow = option(options, 'vless-flow', 'flow')
    const obfs = option(options, 'obfs')?.toLowerCase()
    applyWs(node, obfs)
    if (obfs === 'over-tls') node.tls = true
    if (obfs === 'wss') node.tls = true
    if (boolOption(options, 'over-tls') === true) node.tls = true
    tlsParts(node)
    applyUDP(node, options)
    return node
  }

  if (type === 'trojan') {
    const password = option(options, 'password')
    if (!password) return undefined
    const node = make('trojan')
    node.password = password
    node.tls = true
    const obfs = option(options, 'obfs')?.toLowerCase()
    applyWs(node, obfs)
    if (obfs === 'wss' || obfs === 'over-tls') node.tls = true
    tlsParts(node)
    applyUDP(node, options)
    return node
  }

  if (type === 'http' || type === 'https') {
    const node = make('http')
    node.tls = type === 'https'
    node.username = option(options, 'username')
    node.password = option(options, 'password')
    tlsParts(node)
    if (type === 'https') node.tls = true
    applyUDP(node, options)
    return node
  }

  if (type === 'socks5' || type === 'socks') {
    const node = make('socks5')
    node.username = option(options, 'username')
    node.password = option(options, 'password')
    tlsParts(node)
    applyUDP(node, options)
    return node
  }

  return undefined
}

export function containsClientProxySection(text: string): boolean {
  for (const line of text.split(/\r?\n/)) {
    const normalized = line.trim().toLowerCase()
    if (normalized === '[proxy]' || normalized === '[server_local]') return true
  }
  return false
}

export function parseClientProxyConfiguration(
  text: string,
  sourceID?: string,
): ClientProxyParseResult {
  const lines = text.split(/\r?\n/)
  const wgSections = collectWireGuardSections(lines)
  const nodes: ProxyNode[] = []
  let rejected = 0
  let section: SectionKind = 'none'

  for (const rawLine of lines) {
    const line = rawLine.trim()
    if (!line || COMMENT_PREFIX.test(line)) continue
    if (line.startsWith('[') && line.endsWith(']')) {
      const header = line.match(/^\[WireGuard\s+([^\]]+)\]$/i)
      if (header) {
        section = 'wireguard'
      } else if (line.slice(1, -1).trim().toLowerCase() === 'proxy') {
        section = 'proxy'
      } else if (line.slice(1, -1).trim().toLowerCase() === 'server_local') {
        section = 'server-local'
      } else {
        section = 'none'
      }
      continue
    }
    if (section === 'proxy') {
      const node = parseProxyLine(line, sourceID, wgSections)
      if (node) nodes.push(node)
      else rejected += 1
    } else if (section === 'server-local') {
      const node = parseQuanXLine(line, sourceID)
      if (node) nodes.push(node)
      else rejected += 1
    }
  }
  return { nodes, rejected }
}
