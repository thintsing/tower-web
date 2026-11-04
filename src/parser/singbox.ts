// sing-box / Hiddify JSON config import.
// Understands both a bare `{ "outbounds": [...] }` node list and a full
// profile (inbounds / route / dns / experimental), plus WireGuard endpoints.
// Non-node outbounds (selector / urltest / direct / block / dns) are skipped
// silently; unsupported or malformed ones are counted with a readable reason.
import type { ProxyKind, ProxyNode } from '../models/types'
import { baseNode } from './uri'
import { normalizedHost } from './util'

export interface SingBoxSkipSummary {
  [reason: string]: number
}

export interface ParsedSingBoxConfig {
  nodes: ProxyNode[]
  /** Outbound records that could not become nodes (built-in groups excluded). */
  rejected: number
  /** Reason → count, used for the "0 nodes" explanation. */
  skipped: SingBoxSkipSummary
  /** Set when the JSON is a recognized sing-box profile but yielded no nodes. */
  error?: string
}

const BUILTIN_OUTBOUND_TYPES = new Set(['direct', 'block', 'dns', 'selector', 'urltest'])
const HIDDEN_TAG_PREFIX = '§hide§'
const CONFIG_ROOT_KEYS = ['outbounds', 'endpoints', 'inbounds', 'route', 'dns', 'log', 'experimental', 'ntp', 'clash_api']

const BAD_HOST = /[\s,/\\@?#=]/

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined
}

function text(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) return undefined
  return value as string[]
}

function numberArray(value: unknown): number[] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'number')) return undefined
  return value as number[]
}

function integer(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isInteger(value)) return value
  // Some panels write ports / alter_id as strings.
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) return Number(value.trim())
  return undefined
}

function booleanOption(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value
  if (typeof value === 'string') {
    const v = value.trim().toLowerCase()
    if (['1', 'true', 'yes', 'on'].includes(v)) return true
    if (['0', 'false', 'no', 'off'].includes(v)) return false
  }
  return undefined
}

function host(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  const normalized = normalizedHost(value.trim())
  if (!normalized || BAD_HOST.test(normalized)) return undefined
  return normalized
}

function durationSeconds(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.round(value)
  if (typeof value !== 'string') return undefined
  const match = value.trim().match(/^(\d+(?:\.\d+)?)(ms|s|m|h)?$/i)
  if (!match) return undefined
  const amount = Number(match[1])
  if (!Number.isFinite(amount)) return undefined
  const unit = (match[2] ?? 's').toLowerCase()
  const factor = unit === 'ms' ? 0.001 : unit === 'm' ? 60 : unit === 'h' ? 3600 : 1
  return Math.round(amount * factor)
}

/** Hiddify marks helper outbounds with `§hide§` and node tags with a trailing `/`. */
function rawTag(fields: Record<string, unknown>): string {
  return (text(fields.tag) ?? '').trim()
}

function hiddenTag(tag: string): boolean {
  return tag.startsWith(HIDDEN_TAG_PREFIX)
}

function cleanName(fields: Record<string, unknown>, fallback: string): string {
  const tag = rawTag(fields)
  if (!tag) return fallback
  // Hiddify appends a trailing `/` marker to node tags; keep internal slashes.
  const stripped = tag.replace(/\/+$/, '').trim()
  return stripped || fallback
}

/** SIP003 option string → key/value map. `tls` alone is stored as `true`. */
function sip003Options(value: string | undefined): Map<string, string | true> {
  const map = new Map<string, string | true>()
  if (!value) return map
  const parts: string[] = []
  let part = ''
  let escaped = false
  for (const ch of value) {
    if (escaped) { part += ch; escaped = false }
    else if (ch === '\\') escaped = true
    else if (ch === ';') { parts.push(part); part = '' }
    else part += ch
  }
  if (escaped) part += '\\'
  parts.push(part)
  for (const raw of parts) {
    const item = raw.trim()
    if (!item) continue
    const eq = item.indexOf('=')
    if (eq < 0) map.set(item.toLowerCase(), true)
    else map.set(item.slice(0, eq).trim().toLowerCase(), item.slice(eq + 1).trim())
  }
  return map
}

function optionText(options: Map<string, string | true>, key: string): string | undefined {
  const value = options.get(key)
  return typeof value === 'string' && value ? value : undefined
}

function mapTLS(node: ProxyNode, value: unknown): void {
  const tls = record(value)
  if (!tls) return
  if (tls.enabled === false) node.tls = false
  else if (tls.enabled === true) node.tls = true
  const serverName = text(tls.server_name)?.trim()
  if (serverName) node.sni = serverName
  if (tls.insecure === true) node.skipCertificateVerification = true
  const alpn = stringArray(tls.alpn)?.map((item) => item.trim()).filter(Boolean)
  if (alpn?.length) node.alpn = alpn.join(',')
  const reality = record(tls.reality)
  const publicKey = reality ? text(reality.public_key)?.trim() : undefined
  if (publicKey) {
    node.realityPublicKey = publicKey
    node.realityShortID = text(reality!.short_id)?.trim() || undefined
    // REALITY 是 TLS 的变体，即使配置漏写 enabled 也要按 TLS 处理。
    node.tls = true
  }
  const utls = record(tls.utls)
  const fingerprint = utls ? text(utls.fingerprint)?.trim() : undefined
  if (fingerprint) node.fingerprint = fingerprint
}

function headerHost(value: unknown): string | undefined {
  const headers = record(value)
  if (!headers) return undefined
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === 'host')
  return entry ? text(entry[1])?.trim() || undefined : undefined
}

function mapTransport(node: ProxyNode, value: unknown): void {
  const transport = record(value)
  if (!transport) return
  const type = text(transport.type)?.trim().toLowerCase()
  switch (type) {
    case 'ws':
      node.transport = 'ws'
      node.path = text(transport.path)
      node.hostHeader = headerHost(transport.headers)
      break
    case 'grpc':
      node.transport = 'grpc'
      node.path = text(transport.service_name)
      break
    case 'http':
      node.transport = 'http'
      node.path = text(transport.path)
      node.hostHeader = headerHost(transport.headers)
        ?? stringArray(transport.host)?.map((item) => item.trim()).filter(Boolean).join(',')
      break
    case 'httpupgrade':
      node.transport = 'httpupgrade'
      node.path = text(transport.path)
      node.hostHeader = headerHost(transport.headers)
        ?? stringArray(transport.host)?.map((item) => item.trim()).filter(Boolean).join(',')
      break
    case 'quic':
      node.transport = 'quic'
      break
    default:
      // `tcp` / absent keeps the model's default.
      break
  }
}

/** Hysteria `server_ports` uses `a:b`; the Tower model uses `a-b`. */
function portHopping(value: unknown): string | undefined {
  const list = stringArray(value)
  if (!list?.length) return undefined
  return list.map((item) => item.trim().replace(/:/g, '-')).filter(Boolean).join(',')
}

function wireGuardAddresses(value: unknown): { ipv4?: string; ipv6?: string } {
  const list = stringArray(value)
  if (!list) return {}
  // sing-box always writes /32 and /128; the Tower model keeps bare addresses.
  const trim = (item: string) => item.trim().replace(/\/32$/, '').replace(/\/128$/, '')
  return {
    ipv4: list.filter((item) => item.includes('.')).map(trim)[0],
    ipv6: list.filter((item) => item.includes(':')).map(trim)[0],
  }
}

// ---------- per-protocol mappers ----------

interface MapOutcome {
  node?: ProxyNode
  reason?: string
}

interface Context {
  sourceID?: string
  helpers: Map<string, Record<string, unknown>>
  usedHelpers: Set<string>
}

function withServer(
  type: string,
  fields: Record<string, unknown>,
): { server: string; port: number } | { reason: string } {
  const server = host(fields.server)
  const port = integer(fields.server_port)
  if (!server) return { reason: `${type} 缺少有效的 server` }
  if (!port || port < 1 || port > 65535) return { reason: `${type} 缺少有效的 server_port` }
  return { server, port }
}

function newNode(kind: ProxyKind, fields: Record<string, unknown>, server: string, port: number, context: Context): ProxyNode {
  const node = baseNode(kind, '', context.sourceID)
  node.name = cleanName(fields, server)
  node.server = server
  node.port = port
  return node
}

function mapShadowsocks(fields: Record<string, unknown>, context: Context): MapOutcome {
  const endpoint = withServer('shadowsocks', fields)
  if ('reason' in endpoint) return endpoint
  const method = text(fields.method)?.trim()
  if (!method) return { reason: 'shadowsocks 缺少 method' }
  const password = text(fields.password)
  if (password === undefined) return { reason: 'shadowsocks 缺少 password' }
  const node = newNode('ss', fields, endpoint.server, endpoint.port, context)
  node.cipher = method
  node.password = password

  const pluginName = text(fields.plugin)?.trim().toLowerCase()
  const options = sip003Options(text(fields.plugin_opts))
  if (pluginName === 'v2ray-plugin') {
    const mode = (optionText(options, 'mode') ?? 'websocket').toLowerCase()
    if (mode !== 'websocket' && mode !== 'ws') {
      return { reason: `shadowsocks 的 v2ray-plugin 模式不受支持：${mode}` }
    }
    node.plugin = 'v2ray-plugin'
    node.transport = 'ws'
    node.path = optionText(options, 'path')
    node.hostHeader = optionText(options, 'host')
    node.tls = booleanOption(options.get('tls')) ?? options.has('tls')
    node.pluginMux = booleanOption(options.get('mux'))
  } else if (pluginName && ['obfs-local', 'simple-obfs', 'obfs'].includes(pluginName)) {
    node.plugin = 'obfs-local'
    node.obfs = (optionText(options, 'obfs') ?? optionText(options, 'mode') ?? 'http').toLowerCase()
    node.obfsParam = optionText(options, 'obfs-host') ?? optionText(options, 'host')
  } else if (pluginName === 'shadow-tls') {
    const version = integer(options.get('version'))
    const shadowHost = optionText(options, 'host')
    if (!version || !shadowHost) return { reason: 'shadowsocks 的 shadow-tls 插件缺少 version/host' }
    const shadowPassword = optionText(options, 'password') ?? ''
    if (version !== 1 && !shadowPassword) return { reason: 'shadowsocks 的 shadow-tls 插件缺少 password' }
    node.plugin = 'shadow-tls'
    node.shadowTLS = {
      version,
      host: shadowHost,
      password: shadowPassword,
      ...(booleanOption(options.get('skip-cert-verify')) === true
        ? { skipCertificateVerification: true }
        : {}),
    }
  } else if (pluginName) {
    // Flattening an unknown plugin would silently connect to a different server.
    return { reason: `shadowsocks 使用了不支持的插件：${pluginName}` }
  }

  // ShadowTLS pairs a ShadowTLS helper outbound with an SS outbound that detours through it.
  const detour = text(fields.detour)?.trim()
  if (detour) {
    const helper = context.helpers.get(detour)
    if (!helper) {
      return { reason: 'shadowsocks 使用了无法表达的 detour 链式代理' }
    }
    const tls = record(helper.tls)
    const version = integer(helper.version)
    const shadowHost = tls ? text(tls.server_name)?.trim() : undefined
    if (!version || !shadowHost) {
      return { reason: 'ShadowTLS 辅助出站缺少 version/server_name' }
    }
    const shadowPassword = text(helper.password) ?? ''
    if (version !== 1 && !shadowPassword) {
      return { reason: 'ShadowTLS 辅助出站缺少 password' }
    }
    node.plugin = 'shadow-tls'
    node.shadowTLS = {
      version,
      host: shadowHost,
      password: shadowPassword,
      ...(tls?.insecure === true ? { skipCertificateVerification: true } : {}),
    }
    const fingerprint = record(tls?.utls) ? text(record(tls?.utls)!.fingerprint)?.trim() : undefined
    if (fingerprint) node.fingerprint = fingerprint
    context.usedHelpers.add(detour)
  }
  return { node }
}

function mapVMess(fields: Record<string, unknown>, context: Context): MapOutcome {
  const endpoint = withServer('vmess', fields)
  if ('reason' in endpoint) return endpoint
  const uuid = text(fields.uuid)?.trim()
  if (!uuid) return { reason: 'vmess 缺少 uuid' }
  const node = newNode('vmess', fields, endpoint.server, endpoint.port, context)
  node.uuid = uuid
  node.cipher = text(fields.security)?.trim() || 'auto'
  node.alterID = integer(fields.alter_id)
  mapTLS(node, fields.tls)
  mapTransport(node, fields.transport)
  return { node }
}

function mapVLESS(fields: Record<string, unknown>, context: Context): MapOutcome {
  const endpoint = withServer('vless', fields)
  if ('reason' in endpoint) return endpoint
  const uuid = text(fields.uuid)?.trim()
  if (!uuid) return { reason: 'vless 缺少 uuid' }
  const node = newNode('vless', fields, endpoint.server, endpoint.port, context)
  node.uuid = uuid
  node.flow = text(fields.flow)?.trim() || undefined
  mapTLS(node, fields.tls)
  mapTransport(node, fields.transport)
  return { node }
}

function mapTrojan(fields: Record<string, unknown>, context: Context): MapOutcome {
  const endpoint = withServer('trojan', fields)
  if ('reason' in endpoint) return endpoint
  const password = text(fields.password)
  if (password === undefined) return { reason: 'trojan 缺少 password' }
  const node = newNode('trojan', fields, endpoint.server, endpoint.port, context)
  node.password = password
  node.tls = true
  mapTLS(node, fields.tls)
  mapTransport(node, fields.transport)
  return { node }
}

function mapHysteria2(fields: Record<string, unknown>, context: Context): MapOutcome {
  const endpoint = withServer('hysteria2', fields)
  if ('reason' in endpoint) return endpoint
  const password = text(fields.password)
  if (password === undefined) return { reason: 'hysteria2 缺少 password' }
  const node = newNode('hysteria2', fields, endpoint.server, endpoint.port, context)
  node.password = password
  node.tls = true
  mapTLS(node, fields.tls)
  const obfs = record(fields.obfs)
  const obfsType = obfs ? text(obfs.type)?.trim() : undefined
  if (obfsType && obfsType.toLowerCase() !== 'none') {
    node.obfs = obfsType
    node.obfsParam = text(obfs!.password)
  }
  node.upMbps = integer(fields.up_mbps)
  node.downMbps = integer(fields.down_mbps)
  node.portHopping = portHopping(fields.server_ports)
  return { node }
}

function mapHysteria(fields: Record<string, unknown>, context: Context): MapOutcome {
  const endpoint = withServer('hysteria', fields)
  if ('reason' in endpoint) return endpoint
  const password = text(fields.auth_str) ?? text(fields.auth)
  if (password === undefined) return { reason: 'hysteria 缺少 auth_str' }
  const node = newNode('hysteria', fields, endpoint.server, endpoint.port, context)
  node.password = password
  node.tls = true
  mapTLS(node, fields.tls)
  const obfs = text(fields.obfs)?.trim()
  if (obfs && obfs.toLowerCase() !== 'none') node.obfs = obfs
  node.upMbps = integer(fields.up_mbps)
  node.downMbps = integer(fields.down_mbps)
  node.portHopping = portHopping(fields.server_ports)
  return { node }
}

function mapTUIC(fields: Record<string, unknown>, context: Context): MapOutcome {
  const endpoint = withServer('tuic', fields)
  if ('reason' in endpoint) return endpoint
  const uuid = text(fields.uuid)?.trim()
  const password = text(fields.password)
  if (!uuid) return { reason: 'tuic 缺少 uuid' }
  if (password === undefined) return { reason: 'tuic 缺少 password' }
  const node = newNode('tuic', fields, endpoint.server, endpoint.port, context)
  node.uuid = uuid
  node.password = password
  node.congestionControl = text(fields.congestion_control)?.trim() || undefined
  node.udpRelayMode = text(fields.udp_relay_mode)?.trim() || undefined
  node.tls = true
  mapTLS(node, fields.tls)
  return { node }
}

function mapAnyTLS(fields: Record<string, unknown>, context: Context): MapOutcome {
  const endpoint = withServer('anytls', fields)
  if ('reason' in endpoint) return endpoint
  const password = text(fields.password)
  if (password === undefined) return { reason: 'anytls 缺少 password' }
  const node = newNode('anytls', fields, endpoint.server, endpoint.port, context)
  node.password = password
  node.tls = true
  node.idleSessionCheckInterval = durationSeconds(fields.idle_session_check_interval)
  node.idleSessionTimeout = durationSeconds(fields.idle_session_timeout)
  node.minIdleSession = integer(fields.min_idle_session)
  mapTLS(node, fields.tls)
  return { node }
}

function mapSSH(fields: Record<string, unknown>, context: Context): MapOutcome {
  const endpoint = withServer('ssh', fields)
  if ('reason' in endpoint) return endpoint
  const user = text(fields.user)?.trim() ?? text(fields.username)?.trim()
  if (!user) return { reason: 'ssh 缺少 user' }
  const password = text(fields.password)
  const privateKey = text(fields.private_key)
  if (!password && !privateKey) return { reason: 'ssh 缺少 password 或 private_key' }
  const node = newNode('ssh', fields, endpoint.server, endpoint.port, context)
  node.username = user
  node.password = password
  const hostKeys = stringArray(fields.host_key)
  const hostKeyAlgorithms = stringArray(fields.host_key_algorithms)
  const privateKeyPassphrase = text(fields.private_key_passphrase)
  if (privateKey || privateKeyPassphrase || hostKeys?.length || hostKeyAlgorithms?.length) {
    node.ssh = {
      ...(privateKey ? { privateKey } : {}),
      ...(privateKeyPassphrase ? { privateKeyPassphrase } : {}),
      ...(hostKeys?.length ? { hostKeys } : {}),
      ...(hostKeyAlgorithms?.length ? { hostKeyAlgorithms } : {}),
    }
  }
  return { node }
}

function mapSnell(fields: Record<string, unknown>, context: Context): MapOutcome {
  const endpoint = withServer('snell', fields)
  if ('reason' in endpoint) return endpoint
  const psk = text(fields.psk) ?? text(fields.password)
  if (!psk) return { reason: 'snell 缺少 psk' }
  const node = newNode('snell', fields, endpoint.server, endpoint.port, context)
  node.password = psk
  node.version = integer(fields.version) ?? 4
  const obfsMode = text(fields.obfs_mode)?.trim()
  if (obfsMode && obfsMode.toLowerCase() !== 'none') {
    node.obfs = obfsMode
    node.obfsParam = text(fields.obfs_host)?.trim() || undefined
  }
  return { node }
}

function mapSocks(fields: Record<string, unknown>, context: Context): MapOutcome {
  const version = integer(fields.version) ?? 5
  if (version !== 5) return { reason: `不支持的 SOCKS 版本：${version}` }
  const endpoint = withServer('socks', fields)
  if ('reason' in endpoint) return endpoint
  const node = newNode('socks5', fields, endpoint.server, endpoint.port, context)
  node.username = text(fields.username)
  node.password = text(fields.password)
  return { node }
}

function mapHTTP(fields: Record<string, unknown>, context: Context): MapOutcome {
  const endpoint = withServer('http', fields)
  if ('reason' in endpoint) return endpoint
  const node = newNode('http', fields, endpoint.server, endpoint.port, context)
  node.username = text(fields.username)
  node.password = text(fields.password)
  mapTLS(node, fields.tls)
  return { node }
}

function mapWireGuard(fields: Record<string, unknown>, context: Context): MapOutcome {
  const privateKey = text(fields.private_key)?.trim()
  if (!privateKey) return { reason: 'wireguard 缺少 private_key' }
  const peers = Array.isArray(fields.peers)
    ? fields.peers.map(record).filter((item): item is Record<string, unknown> => !!item)
    : []
  const peer = peers[0]
  const server = peer ? host(peer.address) : host(fields.server)
  const port = peer ? integer(peer.port) : integer(fields.server_port)
  if (!server) return { reason: 'wireguard 缺少 peer.address（或 server）' }
  if (!port || port < 1 || port > 65535) return { reason: 'wireguard 缺少 peer.port（或 server_port）' }
  const publicKey = text(peer?.public_key)?.trim() ?? text(fields.peer_public_key)?.trim()
  if (!publicKey) return { reason: 'wireguard 缺少 peer public_key' }
  const addresses = wireGuardAddresses(fields.address ?? fields.local_address)
  if (!addresses.ipv4 && !addresses.ipv6) return { reason: 'wireguard 缺少 address/local_address' }

  const node = newNode('wireguard', fields, server, port, context)
  node.wireGuardPrivateKey = privateKey
  node.wireGuardPublicKey = publicKey
  node.wireGuardPreSharedKey = (text(peer?.pre_shared_key)?.trim()
    ?? text(fields.pre_shared_key)?.trim()) || undefined
  node.wireGuardIPv4 = addresses.ipv4
  node.wireGuardIPv6 = addresses.ipv6
  const allowed = stringArray(peer?.allowed_ips) ?? stringArray(fields.allowed_ips)
  if (allowed?.length) node.wireGuardAllowedIPs = allowed.join(',')
  const reserved = peer?.reserved ?? fields.reserved
  const reservedNumbers = numberArray(reserved)
  if (reservedNumbers?.length) node.wireGuardReserved = reservedNumbers.join(',')
  else node.wireGuardReserved = text(reserved)?.trim() || undefined
  node.wireGuardMTU = integer(fields.mtu)
  node.wireGuardPersistentKeepalive = integer(peer?.persistent_keepalive_interval ?? fields.persistent_keepalive_interval)
  return { node }
}

// ---------- MASQUE endpoint (sing-box basic CONNECT-IP) ----------

const ENDPOINT_KEYS = new Set([
  'type', 'tag', 'server', 'server_port', 'username', 'password', 'path',
  'headers', 'version', 'disable_version_fallback', 'tls', 'system', 'mtu',
])
const TLS_KEYS = new Set(['enabled', 'server_name', 'insecure', 'alpn', 'certificate'])

function stringMap(value: unknown): Record<string, string> | undefined {
  const map = record(value)
  if (!map || !Object.values(map).every((item) => typeof item === 'string')) return undefined
  return map as Record<string, string>
}

/** Same strict whitelist as the iOS parser: unknown endpoint fields mean we misread it. */
function mapMasqueEndpoint(fields: Record<string, unknown>, context: Context): MapOutcome {
  if (!Object.keys(fields).every((key) => ENDPOINT_KEYS.has(key))) {
    return { reason: 'masque-client 端点包含无法识别的字段' }
  }
  const server = host(fields.server)
  const port = integer(fields.server_port)
  if (!server) return { reason: 'masque-client 缺少有效的 server' }
  if (!port || port < 1 || port > 65535) return { reason: 'masque-client 缺少有效的 server_port' }
  if (fields.system !== undefined && fields.system !== false) {
    return { reason: 'masque-client 的 system 模式不支持导入' }
  }
  for (const key of ['tag', 'username', 'password', 'path']) {
    if (fields[key] !== undefined && typeof fields[key] !== 'string') {
      return { reason: `masque-client 的 ${key} 字段类型错误` }
    }
  }
  for (const key of ['version', 'mtu']) {
    if (fields[key] !== undefined && integer(fields[key]) === undefined) {
      return { reason: `masque-client 的 ${key} 字段类型错误` }
    }
  }
  if (fields.headers !== undefined && stringMap(fields.headers) === undefined) {
    return { reason: 'masque-client 的 headers 字段类型错误' }
  }
  const tlsFields = fields.tls === undefined ? {} : record(fields.tls)
  if (!tlsFields || !Object.keys(tlsFields).every((key) => TLS_KEYS.has(key))) {
    return { reason: 'masque-client 的 tls 字段包含无法识别的项' }
  }
  if (tlsFields.enabled !== undefined && typeof tlsFields.enabled !== 'boolean') {
    return { reason: 'masque-client 的 tls.enabled 字段类型错误' }
  }
  if (tlsFields.server_name !== undefined && typeof tlsFields.server_name !== 'string') {
    return { reason: 'masque-client 的 tls.server_name 字段类型错误' }
  }
  const alpn = tlsFields.alpn === undefined ? undefined : stringArray(tlsFields.alpn)
  if (tlsFields.alpn !== undefined && !alpn) return { reason: 'masque-client 的 tls.alpn 字段类型错误' }
  const certificate = tlsFields.certificate === undefined ? undefined : stringArray(tlsFields.certificate)
  if (tlsFields.certificate !== undefined && !certificate) {
    return { reason: 'masque-client 的 tls.certificate 字段类型错误' }
  }
  const version = integer(fields.version)
  if (version !== undefined && ![1, 2, 3].includes(version)) {
    return { reason: `masque-client 的 HTTP 版本不受支持：${version}` }
  }
  if (version !== undefined && version !== 3 && tlsFields.enabled !== true) {
    return { reason: 'masque-client 的 HTTP/1.1 与 HTTP/2 必须启用 TLS' }
  }
  const username = text(fields.username)
  if (username?.includes(':')) return { reason: 'masque-client 的 username 不能包含冒号' }
  const mtu = integer(fields.mtu)
  if (mtu !== undefined && (mtu < 1280 || mtu > 1500)) {
    return { reason: `masque-client 的 MTU 超出范围：${mtu}` }
  }

  const node = newNode('masque', fields, server, port, context)
  node.username = username
  node.password = text(fields.password)
  node.path = text(fields.path)
  node.tls = tlsFields.enabled === true
  node.sni = text(tlsFields.server_name)
  node.alpn = alpn?.join(',')
  node.skipCertificateVerification = tlsFields.insecure === true
  node.masque = {
    mode: 'basicConnectIP',
    httpVersion: version,
    mtu,
    headers: fields.headers === undefined ? undefined : stringMap(fields.headers),
    disableVersionFallback: fields.disable_version_fallback === undefined
      ? undefined
      : fields.disable_version_fallback === true,
    certificate: certificate && certificate.length > 0 ? certificate : undefined,
  }
  return { node }
}

function mapOutbound(type: string, fields: Record<string, unknown>, context: Context): MapOutcome {
  switch (type) {
    case 'shadowsocks': return mapShadowsocks(fields, context)
    case 'vmess': return mapVMess(fields, context)
    case 'vless': return mapVLESS(fields, context)
    case 'trojan': return mapTrojan(fields, context)
    case 'hysteria2': return mapHysteria2(fields, context)
    case 'hysteria': return mapHysteria(fields, context)
    case 'tuic': return mapTUIC(fields, context)
    case 'anytls': return mapAnyTLS(fields, context)
    case 'ssh': return mapSSH(fields, context)
    case 'snell': return mapSnell(fields, context)
    case 'socks': return mapSocks(fields, context)
    case 'http': return mapHTTP(fields, context)
    case 'wireguard': return mapWireGuard(fields, context)
    case 'masque-client': return mapMasqueEndpoint(fields, context)
    default: return { reason: `不支持的出站类型：${type || '(缺少 type)'}` }
  }
}

function isOutboundRecord(value: unknown): value is Record<string, unknown> {
  const fields = record(value)
  return !!fields && typeof fields.type === 'string'
}

function emptyResult(reason: string, rejected = 0): ParsedSingBoxConfig {
  return { nodes: [], rejected, skipped: {}, error: reason }
}

function skipSummary(skipped: SingBoxSkipSummary): string {
  return Object.entries(skipped)
    .filter(([, count]) => count > 0)
    .map(([reason, count]) => `${reason}×${count}`)
    .join('，')
}

/**
 * Parse a sing-box / Hiddify JSON profile. Returns undefined when the JSON is
 * unrelated to sing-box, so the caller can fall back to other importers.
 */
export function parseSingBoxConfig(
  textBody: string,
  sourceID?: string,
): ParsedSingBoxConfig | undefined {
  let value: unknown
  try {
    value = JSON.parse(textBody)
  } catch {
    return undefined
  }

  const root = record(value)
  let records: unknown[]
  if (root) {
    if (typeof root.type === 'string') {
      records = [root]
    } else if (Array.isArray(root.outbounds) || Array.isArray(root.endpoints)) {
      records = [
        ...(Array.isArray(root.endpoints) ? root.endpoints : []),
        ...(Array.isArray(root.outbounds) ? root.outbounds : []),
      ]
      if (!records.length) {
        return emptyResult('sing-box 配置的 outbounds/endpoints 为空')
      }
    } else if (CONFIG_ROOT_KEYS.some((key) => key in root)) {
      return emptyResult('sing-box 配置缺少有效的 outbounds/endpoints 数组')
    } else {
      return undefined
    }
  } else if (Array.isArray(value)) {
    if (!value.length) return emptyResult('顶层是空 JSON 数组，不是 sing-box 配置')
    if (!value.every(isOutboundRecord)) {
      return emptyResult('顶层是 JSON 数组，但元素不是 sing-box 出站对象', value.length)
    }
    records = value
  } else {
    return undefined
  }

  // ShadowTLS helpers are looked up by tag before the main pass so the pairing
  // works regardless of outbound order.
  const helpers = new Map<string, Record<string, unknown>>()
  for (const item of records) {
    const fields = record(item)
    if (fields?.type === 'shadowtls' && typeof fields.tag === 'string') {
      helpers.set(fields.tag, fields)
    }
  }
  const usedHelpers = new Set<string>()
  for (const item of records) {
    const fields = record(item)
    if (fields?.type === 'shadowsocks' && typeof fields.detour === 'string'
      && helpers.has(fields.detour)) {
      usedHelpers.add(fields.detour)
    }
  }

  const context: Context = { sourceID, helpers, usedHelpers }
  const nodes: ProxyNode[] = []
  const skipped: SingBoxSkipSummary = {}
  let rejected = 0
  const note = (reason: string, counted = true) => {
    skipped[reason] = (skipped[reason] ?? 0) + 1
    if (counted) rejected += 1
  }

  for (const item of records) {
    const fields = record(item)
    if (!fields) {
      note('出站不是 JSON 对象')
      continue
    }
    const type = text(fields.type)?.trim() ?? ''
    if (!type) {
      note('出站缺少 type 字段')
      continue
    }
    if (BUILTIN_OUTBOUND_TYPES.has(type)) {
      note('内置出站或策略组（不导入）', false)
      continue
    }
    const tag = rawTag(fields)
    if (type === 'shadowtls') {
      if (usedHelpers.has(tag)) continue // consumed by its Shadowsocks detour
      if (hiddenTag(tag)) {
        note('Hiddify 隐藏辅助出站（§hide§）', false)
        continue
      }
      note('ShadowTLS 辅助出站未与 Shadowsocks detour 配对')
      continue
    }
    if (hiddenTag(tag)) {
      note('Hiddify 隐藏辅助出站（§hide§）', false)
      continue
    }
    const outcome = mapOutbound(type, fields, context)
    if (outcome.node) nodes.push(outcome.node)
    else note(outcome.reason ?? `无法导入的出站类型：${type}`)
  }

  let error: string | undefined
  if (!nodes.length) {
    const detail = skipSummary(skipped)
    error = detail
      ? `sing-box 配置中没有可导入的节点（已跳过：${detail}）`
      : 'sing-box 配置中没有可导入的节点（outbounds 为空）'
  }
  return { nodes, rejected, skipped, error }
}
