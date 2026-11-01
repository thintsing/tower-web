// URI share-link parsers (ss/ssr/vmess/vless/trojan/hysteria/hysteria2/tuic/
// socks5/http), ported from Tower iOS SubscriptionParser.swift.
import type { ProxyKind, ProxyNode, ShadowTLSOptions } from '../models/types'
import {
  boolString,
  csvValues,
  decodeBase64String,
  mbps,
  nextNodeID,
  normalizedHost,
  normalizedName,
  normalizedTransport,
  normalizedVMessTransport,
  parseEndpoint,
  queryDictionary,
} from './util'

function baseNode(kind: ProxyKind, raw: string, sourceID?: string): ProxyNode {
  return {
    id: nextNodeID(),
    sourceID,
    kind,
    name: '',
    server: '',
    port: 0,
    tls: false,
    skipCertificateVerification: false,
    rawURI: raw,
  }
}

const AMNEZIA_WG_KEYS = new Set(['jc', 'jmin', 'jmax', 's1', 's2', 'h1', 'h2', 'h3', 'h4'])

export function parseURI(rawValue: string, sourceID?: string): ProxyNode | undefined {
  const value = rawValue.trim()
  const lower = value.toLowerCase()
  if (lower.startsWith('ss://')) return parseShadowsocks(value, sourceID)
  if (lower.startsWith('ssr://')) return parseShadowsocksR(value, sourceID)
  if (lower.startsWith('vmess://')) return parseVMess(value, sourceID)
  if (lower.startsWith('vless://'))
    return parseStandardURL(value, 'vless', sourceID) ?? parseLegacyVLESS(value, sourceID)
  if (lower.startsWith('trojan://')) return parseStandardURL(value, 'trojan', sourceID)
  if (lower.startsWith('anytls://')) return parseStandardURL(value, 'anytls', sourceID)
  if (lower.startsWith('hysteria2://') || lower.startsWith('hy2://'))
    return parseStandardURL(value, 'hysteria2', sourceID)
  // Checked after hysteria2 so `hysteria2://` never falls in here.
  if (lower.startsWith('hysteria://') || lower.startsWith('hy://'))
    return parseStandardURL(value, 'hysteria', sourceID)
  if (lower.startsWith('tuic://')) return parseStandardURL(value, 'tuic', sourceID)
  if (lower.startsWith('wireguard://') || lower.startsWith('wg://'))
    return parseWireGuardURL(value, sourceID)
  if (lower.startsWith('snell://')) return parseStandardURL(value, 'snell', sourceID)
  if (lower.startsWith('ssh://')) return parseStandardURL(value, 'ssh', sourceID)
  if (lower.startsWith('socks5://') || lower.startsWith('socks://'))
    return parseStandardURL(value, 'socks5', sourceID)
  if (lower.startsWith('http://') || lower.startsWith('https://'))
    return parseShadowrocketHTTPURL(value, sourceID) ?? parseStandardURL(value, 'http', sourceID)
  return undefined
}

// ---------- WireGuard URL ----------

function parseWireGuardURL(raw: string, sourceID?: string): ProxyNode | undefined {
  const normalized = raw.toLowerCase().startsWith('wg://')
    ? 'wireguard://' + raw.slice('wg://'.length)
    : raw
  let url: URL
  try {
    url = new URL(normalized)
  } catch {
    return undefined
  }
  const rawHost = url.hostname
  if (!rawHost) return undefined
  const port = url.port ? Number(url.port) : 51820
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined

  const query: Record<string, string> = {}
  for (const [k, v] of url.searchParams) query[k.toLowerCase()] = v

  // AmneziaWG uses extra handshake fields we cannot model.
  if (Object.keys(query).some((k) => AMNEZIA_WG_KEYS.has(k))) return undefined

  const addresses = csvValues(query['address'] ?? query['addresses'] ?? '')
  const ipv4 = addresses.find((a) => !a.includes(':'))
  const ipv6 = addresses.find((a) => a.includes(':'))
  const fragment = url.hash ? safeDecode(url.hash.slice(1)) : undefined

  const node = baseNode('wireguard', raw, sourceID)
  node.name = normalizedName(fragment ?? 'WireGuard', normalizedHost(rawHost))
  node.server = normalizedHost(rawHost)
  node.port = port
  node.wireGuardPrivateKey = url.username || undefined
  node.wireGuardPublicKey = query['publickey'] ?? query['public-key']
  node.wireGuardPreSharedKey = query['presharedkey'] ?? query['pre-shared-key'] ?? query['preshared-key']
  node.wireGuardIPv4 = ipv4
  node.wireGuardIPv6 = ipv6
  node.wireGuardAllowedIPs = (query['allowedips'] ?? query['allowed-ips'] ?? '0.0.0.0/0,::/0').replace(/[|]/g, ',')
  const reservedCsv = csvValues(query['reserved'] ?? '').join(',')
  node.wireGuardReserved = reservedCsv || undefined
  const mtu = intOrUndefined(query['mtu'])
  node.wireGuardMTU = mtu
  const keepalive = intOrUndefined(query['keepalive'] ?? query['persistent-keepalive'])
  node.wireGuardPersistentKeepalive = keepalive
  const dnsCsv = csvValues(query['dns'] ?? query['dns-server'] ?? '').join(',')
  node.wireGuardDNS = dnsCsv || undefined
  return node
}

// ---------- SIP003 plugin strings ----------

/** SIP003 escapes semicolons and backslashes inside option values. */
function sip003Fields(plugin: string): string[] | undefined {
  const parts: string[] = []
  let part = ''
  let escaped = false
  for (const ch of plugin) {
    if (escaped) {
      part += ch
      escaped = false
    } else if (ch === '\\') {
      escaped = true
    } else if (ch === ';') {
      parts.push(part)
      part = ''
    } else {
      part += ch
    }
  }
  if (escaped) return undefined
  parts.push(part)
  return parts
}

function shadowTLSOptions(
  options: Record<string, string>,
): (ShadowTLSOptions & { skipCertificateVerification?: boolean }) | undefined {
  const known = new Set(['version', 'host', 'password', 'skip-cert-verify'])
  if (!Object.keys(options).every((k) => known.has(k))) return undefined
  const version = Number(options['version'] ?? '')
  const host = options['host']
  if (!Number.isInteger(version) || !host) return undefined
  return {
    version,
    host,
    password: options['password'] ?? '',
    skipCertificateVerification: boolString(options['skip-cert-verify']),
  }
}

function shadowTLSPluginOptions(plugin: string): ReturnType<typeof shadowTLSOptions> | undefined {
  const parts = sip003Fields(plugin)
  if (!parts) return undefined
  const options: Record<string, string> = {}
  for (const field of parts.slice(1)) {
    const eq = field.indexOf('=')
    if (eq < 0) return undefined
    const key = field.slice(0, eq).toLowerCase()
    if (key in options) return undefined
    options[key] = field.slice(eq + 1)
  }
  return shadowTLSOptions(options)
}

/** `obfs-local;obfs=http;obfs-host=www.invalid.local` */
function simpleObfsOptions(
  plugin: string,
): { mode: string; host?: string } | undefined {
  const fields = sip003Fields(plugin)
  if (!fields) return undefined
  const parts = fields.map((f) => f.trim()).filter(Boolean)
  const name = parts[0]?.toLowerCase()
  if (!name || !['obfs', 'obfs-local', 'simple-obfs'].includes(name)) return undefined
  let mode = 'http'
  let host: string | undefined
  for (const part of parts.slice(1)) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    const key = part.slice(0, eq).trim().toLowerCase()
    const value = part.slice(eq + 1).trim()
    if (key === 'obfs' || key === 'mode') mode = value
    else if (key === 'obfs-host' || key === 'host') host = value
  }
  return { mode, host }
}

function v2rayPluginOptions(
  plugin: string,
): { transport: string; host?: string; path?: string; tls: boolean; mux?: boolean } | undefined {
  const fields = sip003Fields(plugin)
  if (!fields) return undefined
  const parts = fields.map((f) => f.trim())
  if (parts[0]?.toLowerCase() !== 'v2ray-plugin') return undefined
  let mode = 'websocket'
  let host: string | undefined
  let path: string | undefined
  let tls = false
  let mux: boolean | undefined
  for (const part of parts.slice(1)) {
    const eq = part.indexOf('=')
    const key = (eq < 0 ? part : part.slice(0, eq)).toLowerCase()
    if (eq < 0) {
      if (key === 'tls') tls = true
      continue
    }
    const value = part.slice(eq + 1)
    switch (key) {
      case 'mode':
      case 'obfs':
        mode = value
        break
      case 'host':
      case 'obfs-host':
        host = value
        break
      case 'path':
        path = value
        break
      case 'tls':
        tls = boolString(value)
        break
      case 'mux':
        mux = boolString(value)
        break
    }
  }
  if (!['websocket', 'ws'].includes(mode.toLowerCase())) return undefined
  return { transport: 'ws', host, path, tls, mux }
}

// ---------- Shadowsocks ----------

function parseShadowsocks(raw: string, sourceID?: string): ProxyNode | undefined {
  const hashIndex = raw.indexOf('#')
  const name =
    hashIndex >= 0 ? safeDecode(raw.slice(hashIndex + 1)) : 'Shadowsocks'
  let payload = raw
    .slice(0, hashIndex >= 0 ? hashIndex : undefined)
    .replace(/^ss:\/\//i, '')
  let obfsMode: string | undefined
  let obfsHost: string | undefined
  let sip003Plugin: string | undefined
  let pluginTransport: string | undefined
  let pluginPath: string | undefined
  let pluginTLS = false
  let pluginMux: boolean | undefined
  let shadowTLS: ShadowTLSOptions | undefined
  let shadowTLSFingerprint: string | undefined
  let udpRelayEnabled: boolean | undefined

  const queryIndex = payload.indexOf('?')
  if (queryIndex >= 0) {
    const query = payload.slice(queryIndex + 1)
    const parameters = queryDictionary(query)
    const udp = parameters['udp-relay'] ?? parameters['udp']
    if (udp !== undefined) udpRelayEnabled = boolString(udp)
    const plugin = safeDecode(parameters['plugin'])
    if (plugin) {
      if (plugin.toLowerCase().startsWith('shadow-tls;')) {
        // UDP-over-TCP is a separate server capability; refuse to model it.
        if (boolString(parameters['udp-over-tcp'])) return undefined
        const options = shadowTLSPluginOptions(plugin)
        if (!options) return undefined
        shadowTLS = options
        shadowTLSFingerprint = safeDecode(parameters['client-fingerprint'])
        sip003Plugin = 'shadow-tls'
      } else if (simpleObfsOptions(plugin)) {
        const options = simpleObfsOptions(plugin)!
        obfsMode = options.mode
        obfsHost = options.host
      } else if (v2rayPluginOptions(plugin)) {
        const options = v2rayPluginOptions(plugin)!
        sip003Plugin = 'v2ray-plugin'
        pluginTransport = options.transport
        obfsHost = options.host
        pluginPath = options.path
        pluginTLS = options.tls
        pluginMux = options.mux
      } else {
        // Unknown plugins must never turn into an ordinary SS node.
        return undefined
      }
    }
    payload = payload.slice(0, queryIndex)
  }

  let auth: string
  let endpoint: string
  const atIndex = payload.lastIndexOf('@')
  if (atIndex >= 0) {
    const encodedAuth = payload.slice(0, atIndex)
    auth = decodeBase64String(encodedAuth) ?? safeDecode(encodedAuth) ?? encodedAuth
    endpoint = payload.slice(atIndex + 1)
  } else {
    const decoded = decodeBase64String(payload)
    if (!decoded) return undefined
    const at = decoded.lastIndexOf('@')
    if (at < 0) return undefined
    auth = decoded.slice(0, at)
    endpoint = decoded.slice(at + 1)
  }

  const sep = auth.indexOf(':')
  if (sep < 0) return undefined
  const method = auth.slice(0, sep)
  const password = auth.slice(sep + 1)
  const address = parseEndpoint(endpoint)
  if (!address) return undefined

  const node = baseNode('ss', raw, sourceID)
  node.name = normalizedName(name, address.host)
  node.server = address.host
  node.port = address.port
  node.cipher = method
  node.password = password
  node.transport = pluginTransport
  node.plugin = sip003Plugin
  node.pluginMux = pluginMux
  node.shadowTLS = shadowTLS
  node.tls = pluginTLS
  node.hostHeader = obfsHost
  node.path = pluginPath
  node.fingerprint = shadowTLSFingerprint
  node.obfs = obfsMode
  node.obfsParam = sip003Plugin == null ? obfsHost : undefined
  node.udpRelayEnabled = udpRelayEnabled
  return node
}

// ---------- ShadowsocksR ----------

function parseShadowsocksR(raw: string, sourceID?: string): ProxyNode | undefined {
  const decoded = decodeBase64String(raw.slice('ssr://'.length))
  if (!decoded) return undefined
  const sections = decoded.split('/?')
  // Split from the right so a bare or bracketed IPv6 host stays one field.
  const main = sections[0].split(':')
  if (main.length < 6) return undefined
  const tail = main.splice(main.length - 5)
  const host = main.join(':')
  const [portText, protocol, cipher, obfs, passwordB64] = tail
  const port = Number(portText)
  const password = decodeBase64String(passwordB64)
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !password) return undefined

  const query = sections.length > 1 ? queryDictionary(sections[1]) : {}
  const remarks = query['remarks'] ? decodeBase64String(query['remarks']) : undefined

  const node = baseNode('ssr', raw, sourceID)
  node.name = normalizedName(remarks, host)
  node.server = normalizedHost(host)
  node.port = port
  node.cipher = cipher
  node.password = password
  node.protocolName = protocol
  node.protocolParam = query['protoparam'] ? decodeBase64String(query['protoparam']) : undefined
  node.obfs = obfs
  node.obfsParam = query['obfsparam'] ? decodeBase64String(query['obfsparam']) : undefined
  return node
}

// ---------- VMess ----------

function parseVMess(raw: string, sourceID?: string): ProxyNode | undefined {
  const encoded = raw.slice('vmess://'.length)
  const decoded = decodeBase64String(encoded.split('?')[0] ?? encoded)
  let json: Record<string, unknown> | undefined
  if (decoded) {
    try {
      json = JSON.parse(decoded)
    } catch {
      json = undefined
    }
  }
  if (!json || typeof json !== 'object') return parseLegacyVMess(raw, sourceID)
  const server = str(json['add'])
  const port = int(json['port'])
  const uuid = str(json['id'])
  if (!server || !port || !uuid) return parseLegacyVMess(raw, sourceID)

  const tlsValue = str(json['tls'])?.toLowerCase()
  const network = str(json['net']) ?? str(json['network'])
  const headerType = str(json['type'])
  let transport: string | undefined
  const netLower = network?.toLowerCase()
  const typeLower = headerType?.toLowerCase()
  // v2rayN's HTTP/1.1 header obfuscation is `net: tcp` plus `type: http`.
  if ((netLower === undefined && typeLower === 'http') ||
      (netLower === 'tcp' && typeLower === 'http') ||
      (netLower === 'raw' && typeLower === 'http')) {
    transport = 'http'
  } else if (netLower === 'http') {
    // Xray names its HTTP/2 transport `http`.
    transport = 'h2'
  } else {
    transport = normalizedVMessTransport(network ?? headerType)
  }

  const node = baseNode('vmess', raw, sourceID)
  node.name = normalizedName(str(json['ps']), server)
  node.server = server
  node.port = port
  node.cipher = str(json['scy']) ?? 'auto'
  node.uuid = uuid
  node.transport = transport ?? 'tcp'
  node.tls = tlsValue === 'tls' || tlsValue === 'true'
  node.sni = str(json['sni'])
  node.hostHeader = str(json['host'])
  node.path = str(json['path'])
  node.alpn = str(json['alpn'])
  node.skipCertificateVerification = bool(json['allowInsecure'])
  node.alterID = int(json['aid'])
  return node
}

/** `vmess://base64(method:uuid@host:port)?remarks=…&obfs=websocket…` */
function parseLegacyVMess(raw: string, sourceID?: string): ProxyNode | undefined {
  let body = raw.slice('vmess://'.length)
  const hashIndex = body.indexOf('#')
  if (hashIndex >= 0) body = body.slice(0, hashIndex)
  const qIndex = body.indexOf('?')
  const decoded = decodeBase64String(qIndex >= 0 ? body.slice(0, qIndex) : body)
  if (!decoded) return undefined
  const query: Record<string, string> = {}
  if (qIndex >= 0) {
    for (const [k, v] of Object.entries(queryDictionary(body.slice(qIndex + 1)))) {
      query[k.toLowerCase()] = v
    }
  }
  const atIndex = decoded.lastIndexOf('@')
  if (atIndex < 0) return undefined
  const auth = decoded.slice(0, atIndex)
  const address = parseEndpoint(decoded.slice(atIndex + 1))
  if (!address) return undefined

  let cipher: string
  let uuid: string
  const sep = auth.indexOf(':')
  if (sep >= 0) {
    cipher = auth.slice(0, sep)
    uuid = auth.slice(sep + 1)
  } else {
    cipher = 'auto'
    uuid = auth
  }
  if (!uuid) return undefined

  const transport = normalizedVMessTransport(safeDecode(query['obfs']))
  const nameParam =
    safeDecode(query['remarks']) ??
    (raw.includes('#') ? safeDecode(raw.slice(raw.indexOf('#') + 1)) : undefined)

  const node = baseNode('vmess', raw, sourceID)
  node.name = normalizedName(nameParam, address.host)
  node.server = address.host
  node.port = address.port
  node.cipher = cipher === '' ? 'auto' : cipher
  node.uuid = uuid
  node.transport = transport
  node.tls = ['1', 'true', 'tls'].includes((query['tls'] ?? '').toLowerCase())
  node.sni = safeDecode(query['peer']) ?? safeDecode(query['sni'])
  if (transport === 'ws') {
    const obfsParam = safeDecode(query['obfs-param'] ?? query['obfsparam'])
    node.hostHeader = obfsParam?.split(/[|@,]/)[0]
    node.path = safeDecode(query['path']) ?? '/'
  }
  node.alterID = query['alterid'] ? Number(query['alterid']) : undefined
  return node
}

// ---------- Standard URL form (vless/trojan/hysteria/hysteria2/tuic/anytls/socks5/http) ----------

function parseStandardURL(raw: string, kind: ProxyKind, sourceID?: string): ProxyNode | undefined {
  let normalized = raw
  if (normalized.toLowerCase().startsWith('hy2://'))
    normalized = 'hysteria2://' + normalized.slice('hy2://'.length)
  else if (normalized.toLowerCase().startsWith('hy://'))
    normalized = 'hysteria://' + normalized.slice('hy://'.length)
  else if (normalized.toLowerCase().startsWith('socks://'))
    normalized = 'socks5://' + normalized.slice('socks://'.length)

  // Hysteria 2 writes port hopping into the port: `host:443,5000-6000`.
  let authorityPortHopping: string | undefined
  if (kind === 'hysteria2') {
    const split = splitMultiPortAuthority(normalized)
    if (split) {
      normalized = split.link
      authorityPortHopping = split.ports
    }
  }

  let url: URL
  try {
    url = new URL(normalized)
  } catch {
    return undefined
  }
  const rawHost = url.hostname
  if (!rawHost) return undefined
  const defaultHTTPPort =
    kind === 'http' ? (url.protocol.toLowerCase() === 'https:' ? 443 : 80) : undefined
  const port = url.port ? Number(url.port) : defaultHTTPPort
  if (!port) return undefined
  const server = normalizedHost(rawHost)

  const query: Record<string, string> = {}
  for (const [k, v] of url.searchParams) query[k.toLowerCase()] = v

  const fallback = `${kind.toUpperCase()} · ${server}`
  const fragment = url.hash ? safeDecode(url.hash.slice(1)) : undefined
  const name = normalizedName(fragment ?? proxyNameQueryValue(query), fallback)

  const trojanPlugin =
    kind === 'trojan' && query['plugin']
      ? shadowrocketTrojanWebSocketOptions(query['plugin'])
      : undefined
  let transport = normalizedTransport(
    trojanPlugin?.transport ??
      query['type'] ??
      query['network'] ??
      (query['obfs']?.includes('ws') ? 'ws' : undefined),
  )
  // VLESS/Trojan: `type=http` is HTTP/2; bare headerType http is HTTP/1.1.
  if (kind === 'vless' || kind === 'trojan') {
    if (query['type']?.toLowerCase() === 'http') transport = 'h2'
    else if (!transport && query['headertype']?.toLowerCase() === 'http') transport = 'http'
  }

  const security = (query['security'] ?? query['tls'] ?? '').toLowerCase()
  const realityPublicKey = query['pbk']
  const carriesReality =
    security === 'reality' || (kind === 'vless' && !!realityPublicKey)
  const flow =
    query['flow'] ?? (kind === 'vless' && query['xtls'] === '2' ? 'xtls-rprx-vision' : undefined)

  // URL userinfo is already percent-decoded once by the URL parser. Do not
  // decode again: a literal `%41` in a secret must stay literal.
  const credential = url.username || undefined
  const passwordPart = url.password || undefined

  // TUIC v5: `tuic://uuid:password@host`; Shadowrocket dialect puts both in query.
  const tuicUUID = [credential, query['uuid']].find((v) => v)
  const tuicPassword = [passwordPart, query['password']].find((v) => v)
  if (kind === 'tuic' && (!tuicUUID || !tuicPassword)) return undefined

  // alpn=h3 or alpn[0]=h3&alpn[1]=h2
  const alpnValues: string[] = []
  for (const [k, v] of url.searchParams) {
    const key = k.toLowerCase()
    if (key === 'alpn' || key === 'alpn[]' || (key.startsWith('alpn[') && key.endsWith(']'))) {
      if (v) alpnValues.push(v)
    }
  }
  const alpn = alpnValues.length ? alpnValues.join(',') : undefined

  const node = baseNode(kind, raw, sourceID)
  node.name = name
  node.server = server
  node.port = port
  if (kind === 'tuic') {
    node.password = tuicPassword
    node.uuid = tuicUUID
  } else if (kind === 'hysteria') {
    node.password = credential ?? query['auth'] ?? query['auth_str'] ?? query['authstr']
  } else if (kind === 'trojan' || kind === 'hysteria2' || kind === 'anytls') {
    node.password = credential
  } else {
    node.password = passwordPart
  }
  if (kind === 'vmess' || kind === 'vless') node.uuid = credential
  if (kind === 'socks5' || kind === 'http') node.username = credential
  node.transport = transport
  node.transportMode = transport === 'xhttp' ? query['mode'] : undefined
  node.tls =
    ['trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls'].includes(kind) ||
    ['1', 'true', 'tls', 'reality'].includes(security) ||
    carriesReality ||
    normalized.toLowerCase().startsWith('https://')
  node.sni = query['sni'] ?? query['servername'] ?? query['peer']
  node.hostHeader =
    trojanPlugin?.host ??
    query['authority'] ??
    query['host'] ??
    (kind === 'vless' && transport === 'ws'
      ? safeDecode(query['obfsparam'])?.split(/[|@,]/)[0]
      : undefined)
  node.path =
    transport === 'grpc'
      ? query['servicename'] ?? query['service_name'] ?? query['path']
      : trojanPlugin?.path ?? query['path']
  node.alpn = alpn
  if (carriesReality) {
    node.realityPublicKey = realityPublicKey
    node.realityShortID = query['sid']
  }
  node.certificateFingerprint =
    query['pinsha256'] ??
    query['pin-sha256'] ??
    query['tls-fingerprint'] ??
    query['pcs'] ??
    (kind === 'hysteria2' ? query['fingerprint'] : undefined)
  node.fingerprint =
    query['fp'] ??
    query['client_fingerprint'] ??
    query['client-fingerprint'] ??
    (carriesReality ? query['fingerprint'] : undefined)
  node.flow = flow
  node.skipCertificateVerification = ['1', 'true'].includes(
    query['allowinsecure'] ?? query['insecure'] ?? query['allow_insecure'] ?? '',
  )
  if (kind === 'hysteria') {
    node.protocolName = query['protocol']
    node.obfs = query['obfsparam'] ?? query['obfs']
    node.upMbps = mbps(query['upmbps'] ?? query['up'])
    node.downMbps = mbps(query['downmbps'] ?? query['down'])
  }
  if (kind === 'hysteria2') {
    node.obfs = query['obfs']
    node.obfsParam = query['obfs-password'] ?? query['obfspassword'] ?? query['obfs_password']
  }
  if (kind === 'anytls') {
    node.idleSessionCheckInterval = intOrUndefined(
      query['idle-session-check-interval'] ?? query['idlesessioncheckinterval'],
    )
    node.idleSessionTimeout = intOrUndefined(
      query['idle-session-timeout'] ?? query['idlesessiontimeout'],
    )
    node.minIdleSession = intOrUndefined(query['min-idle-session'] ?? query['minidlesession'])
  }
  if (kind === 'tuic') {
    node.congestionControl = query['congestion_control'] ?? query['congestion-controller']
    node.udpRelayMode = query['udp_relay_mode'] ?? query['udp-relay-mode']
  }
  node.portHopping =
    authorityPortHopping ?? query['mport'] ?? query['ports'] ?? query['server-ports'] ?? query['port-hopping']
  if (kind === 'vless') node.vlessEncryption = vlessEncryption(query['encryption'])
  return node
}

/** VLESS encryption other than `none`. */
function vlessEncryption(value: string | undefined): string | undefined {
  const v = value?.trim()
  if (!v || v.toLowerCase() === 'none') return undefined
  return v
}

/** `scheme://auth@host:443,5000-6000/?…` → link with first port + full list. */
function splitMultiPortAuthority(link: string): { link: string; ports: string } | undefined {
  const schemeEnd = link.indexOf('://')
  if (schemeEnd < 0) return undefined
  const rest = link.slice(schemeEnd + 3)
  const authorityEndMatch = rest.match(/[/?#]/)
  const authorityEnd = authorityEndMatch?.index ?? rest.length
  const authority = rest.slice(0, authorityEnd)
  const hostStart = authority.lastIndexOf('@') + 1 // 0 when no userinfo
  const hostPort = authority.slice(hostStart)
  // For an IPv6 literal the port colon must follow the closing bracket.
  const closeBracket = hostPort.lastIndexOf(']')
  const colon = hostPort.lastIndexOf(':')
  if (colon < 0 || colon < closeBracket) return undefined
  const ports = hostPort.slice(colon + 1)
  if (!ports.includes(',') && !ports.includes('-')) return undefined
  if (!/^[\d,-]+$/.test(ports)) return undefined
  const first = ports.split(/[,-]/)[0]
  if (!first) return undefined
  const rebuilt =
    link.slice(0, schemeEnd + 3 + hostStart + colon + 1) + first + link.slice(schemeEnd + 3 + authorityEnd)
  return { link: rebuilt, ports }
}

/**
 * `vless://base64(uuid@host:port)?remarks=…&tls=1&pbk=…&xtls=2` —
 * Shadowrocket's endpoint-only Base64 dialect.
 */
function parseLegacyVLESS(raw: string, sourceID?: string): ProxyNode | undefined {
  let body = raw.slice('vless://'.length)
  let fragmentName: string | undefined
  const hashIndex = body.indexOf('#')
  if (hashIndex >= 0) {
    fragmentName = safeDecode(body.slice(hashIndex + 1))
    body = body.slice(0, hashIndex)
  }
  const qIndex = body.indexOf('?')
  const decoded = decodeBase64String(qIndex >= 0 ? body.slice(0, qIndex) : body)
  if (!decoded) return undefined
  const atIndex = decoded.lastIndexOf('@')
  if (atIndex < 0) return undefined

  let rawUUID = decoded.slice(0, atIndex)
  const lowerUUID = rawUUID.toLowerCase()
  // `none:` is Shadowrocket preserving VLESS's encryption=none marker.
  if (lowerUUID.startsWith('auto:')) rawUUID = rawUUID.slice(5)
  else if (lowerUUID.startsWith('none:')) rawUUID = rawUUID.slice(5)
  else if (rawUUID.startsWith(':')) rawUUID = rawUUID.slice(1)
  const uuid = rawUUID
  const address = parseEndpoint(decoded.slice(atIndex + 1))
  if (!uuid || !address) return undefined

  const query: Record<string, string> = {}
  if (qIndex >= 0) {
    for (const [k, v] of Object.entries(queryDictionary(body.slice(qIndex + 1)))) {
      query[k.toLowerCase()] = v
    }
  }
  const realityPublicKey = safeDecode(query['pbk'])
  const tlsValue = (query['security'] ?? query['tls'] ?? '').toLowerCase()
  const transport = normalizedTransport(safeDecode(query['type'] ?? query['network'] ?? query['obfs']))
  const flow = safeDecode(query['flow']) ?? (query['xtls'] === '2' ? 'xtls-rprx-vision' : undefined)
  const name = proxyNameQueryValue(query) ?? fragmentName

  const node = baseNode('vless', raw, sourceID)
  node.name = normalizedName(name, address.host)
  node.server = address.host
  node.port = address.port
  node.uuid = uuid
  node.transport = transport
  node.transportMode = transport === 'xhttp' ? safeDecode(query['mode']) : undefined
  node.tls = !!realityPublicKey || ['1', 'true', 'tls', 'reality'].includes(tlsValue)
  node.sni = safeDecode(query['peer'] ?? query['sni'] ?? query['servername'])
  node.hostHeader =
    safeDecode(query['authority'] ?? query['host']) ??
    (transport === 'ws' ? safeDecode(query['obfsparam'])?.split(/[|@,]/)[0] : undefined)
  node.path = safeDecode(
    transport === 'grpc' ? query['servicename'] ?? query['service_name'] : query['path'],
  )
  node.alpn = safeDecode(query['alpn'])
  node.realityPublicKey = realityPublicKey
  node.realityShortID = safeDecode(query['sid'])
  node.certificateFingerprint = safeDecode(query['pcs'] ?? query['pinsha256'] ?? query['pin-sha256'])
  // Shadowrocket's legacy REALITY URI spells the uTLS value `fingerprint`.
  node.fingerprint = safeDecode(query['fp'] ?? (realityPublicKey ? query['fingerprint'] : undefined))
  node.flow = flow
  node.skipCertificateVerification = ['1', 'true'].includes(
    (query['allowinsecure'] ?? query['insecure'] ?? '').toLowerCase(),
  )
  return node
}

/** Shadowrocket's Trojan WebSocket: `plugin=obfs-local;obfs=websocket;…` */
function shadowrocketTrojanWebSocketOptions(
  plugin: string,
): { transport: string; host?: string; path?: string } | undefined {
  const parts = plugin.split(';').map((p) => p.trim())
  const name = parts[0]?.toLowerCase()
  if (!name || !['obfs', 'obfs-local', 'simple-obfs'].includes(name)) return undefined
  let mode: string | undefined
  let host: string | undefined
  let path: string | undefined
  for (const part of parts.slice(1)) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    const key = part.slice(0, eq).trim().toLowerCase()
    const value = part.slice(eq + 1).trim()
    if (key === 'obfs' || key === 'mode') mode = value
    else if (key === 'obfs-host' || key === 'host') host = value
    else if (key === 'obfs-uri' || key === 'path') path = value
  }
  if (!mode || !['websocket', 'ws', 'wss'].includes(mode.toLowerCase())) return undefined
  return { transport: 'ws', host, path }
}

/** `https://base64(user:password@host:port)?remarks=…` (Shadowrocket dialect). */
function parseShadowrocketHTTPURL(raw: string, sourceID?: string): ProxyNode | undefined {
  const match = raw.match(/^https?:\/\/([^/?#]+)([^#]*)#?(.*)$/i)
  if (!match) return undefined
  const decoded = decodeBase64String(match[1])
  if (!decoded || !decoded.includes('@')) return undefined
  const query = queryDictionary((match[2] ?? '').replace(/^\?/, ''))
  const atIndex = decoded.lastIndexOf('@')
  const auth = decoded.slice(0, atIndex)
  const endpoint = parseEndpoint(decoded.slice(atIndex + 1))
  if (!endpoint) return undefined
  const sep = auth.indexOf(':')

  const node = baseNode('http', raw, sourceID)
  node.name = normalizedName(
    safeDecode(query['remarks']) ??
      (match[0].includes('#') ? safeDecode(raw.slice(raw.indexOf('#') + 1)) : undefined),
    endpoint.host,
  )
  node.server = endpoint.host
  node.port = endpoint.port
  if (sep >= 0) {
    node.username = auth.slice(0, sep)
    node.password = auth.slice(sep + 1)
  }
  node.tls = raw.toLowerCase().startsWith('https://')
  return node
}

function proxyNameQueryValue(query: Record<string, string>): string | undefined {
  for (const key of ['remarks', 'name', 'title']) {
    if (query[key]) return query[key]
  }
  return undefined
}

// ---------- small adapters ----------

function safeDecode(value: string | undefined | null): string | undefined {
  if (value == null) return undefined
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

function str(value: unknown): string | undefined {
  if (typeof value === 'string') return value
  if (typeof value === 'number') return String(value)
  return undefined
}

function int(value: unknown): number | undefined {
  const n = Number(str(value))
  return Number.isFinite(n) ? n : undefined
}

function intOrUndefined(value: string | undefined): number | undefined {
  if (!value) return undefined
  const n = Number(value)
  return Number.isInteger(n) ? n : undefined
}

function bool(value: unknown): boolean {
  if (typeof value === 'boolean') return value
  return boolString(str(value))
}

export { csvValues }
