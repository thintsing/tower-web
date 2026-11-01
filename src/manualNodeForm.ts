// 自有节点手动表单：把逐协议字段转换回 ProxyNode。
// 只负责表单数据与校验；不依赖 React，便于自检和后续复用。
import { PROXY_KIND_TITLES, type ProxyKind, type ProxyNode } from './models/types'
import { newID } from './util/browser'

export interface ManualNodeDraft {
  kind: ProxyKind
  name: string
  server: string
  port: string
  /** VMess / VLESS / TUIC 的 UUID，其它协议的密码或 PSK。 */
  secret: string
  /** TUIC 的密码；TrustTunnel / SSH / SOCKS / HTTP 也复用。 */
  password: string
  username: string
  cipher: string
  transport: string
  tls: boolean
  sni: string
  hostHeader: string
  path: string
  alpn: string
  fingerprint: string
  certificateFingerprint: string
  flow: string
  vlessEncryption: string
  realityPublicKey: string
  realityShortID: string
  skipCertificateVerification: boolean
  alterID: string
  protocolName: string
  protocolParam: string
  obfs: string
  obfsParam: string
  version: string
  congestionControl: string
  udpRelayMode: string
  portHopping: string
  upMbps: string
  downMbps: string
  wireGuardPrivateKey: string
  wireGuardPublicKey: string
  wireGuardPreSharedKey: string
  wireGuardIPv4: string
  wireGuardIPv6: string
  wireGuardAllowedIPs: string
  wireGuardReserved: string
  wireGuardMTU: string
  wireGuardPersistentKeepalive: string
  wireGuardDNS: string
  quic: boolean
  udpRelayEnabled: boolean
  idleSessionCheckInterval: string
  idleSessionTimeout: string
  minIdleSession: string
  sshHostKeys: string
}

export const MANUAL_FORM_KINDS: ProxyKind[] = [
  'ss', 'vmess', 'vless', 'trojan', 'hysteria2', 'tuic', 'anytls',
  'ssr', 'hysteria', 'snell', 'socks5', 'http', 'wireguard', 'ssh', 'trusttunnel',
]

const TLS_REQUIRED: ProxyKind[] = ['trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'trusttunnel']

const DEFAULTS: Partial<Record<ProxyKind, Partial<ManualNodeDraft>>> = {
  ss: { cipher: 'aes-256-gcm', udpRelayEnabled: true },
  ssr: { cipher: 'aes-256-cfb', protocolName: 'origin', obfs: 'plain' },
  vmess: { cipher: 'auto', alterID: '0', transport: 'tcp' },
  vless: { transport: 'tcp', tls: true, fingerprint: 'chrome' },
  trojan: { tls: true, transport: 'tcp' },
  hysteria: { tls: true, upMbps: '50', downMbps: '100', protocolName: 'udp' },
  hysteria2: { tls: true },
  tuic: { tls: true, udpRelayEnabled: true },
  anytls: { tls: true, idleSessionCheckInterval: '30', idleSessionTimeout: '30', minIdleSession: '0' },
  snell: { version: '4' },
  wireguard: {
    wireGuardAllowedIPs: '0.0.0.0/0,::/0',
    wireGuardMTU: '1280',
    wireGuardPersistentKeepalive: '25',
  },
  ssh: { port: '22' },
  trusttunnel: { tls: true, quic: true },
}

export function emptyManualDraft(kind: ProxyKind = 'ss'): ManualNodeDraft {
  return {
    kind,
    name: '',
    server: '',
    port: kind === 'ssh' ? '22' : '',
    secret: '',
    password: '',
    username: '',
    cipher: '',
    transport: '',
    tls: false,
    sni: '',
    hostHeader: '',
    path: '',
    alpn: '',
    fingerprint: '',
    certificateFingerprint: '',
    flow: '',
    vlessEncryption: '',
    realityPublicKey: '',
    realityShortID: '',
    skipCertificateVerification: false,
    alterID: '',
    protocolName: '',
    protocolParam: '',
    obfs: '',
    obfsParam: '',
    version: '',
    congestionControl: '',
    udpRelayMode: '',
    portHopping: '',
    upMbps: '',
    downMbps: '',
    wireGuardPrivateKey: '',
    wireGuardPublicKey: '',
    wireGuardPreSharedKey: '',
    wireGuardIPv4: '',
    wireGuardIPv6: '',
    wireGuardAllowedIPs: '',
    wireGuardReserved: '',
    wireGuardMTU: '',
    wireGuardPersistentKeepalive: '',
    wireGuardDNS: '',
    quic: false,
    udpRelayEnabled: false,
    idleSessionCheckInterval: '',
    idleSessionTimeout: '',
    minIdleSession: '',
    sshHostKeys: '',
    ...DEFAULTS[kind],
  }
}

/** 切换协议时保留名称 / 服务器 / 端口，重置协议专属字段。 */
export function applyManualKind(draft: ManualNodeDraft, kind: ProxyKind): ManualNodeDraft {
  return {
    ...emptyManualDraft(kind),
    name: draft.name,
    server: draft.server,
    port: draft.port || (kind === 'ssh' ? '22' : ''),
  }
}

export function manualDraftFromNode(node: ProxyNode): ManualNodeDraft {
  const secret = node.kind === 'vmess' || node.kind === 'vless' || node.kind === 'tuic'
    ? node.uuid ?? ''
    : node.password ?? ''
  return {
    ...emptyManualDraft(node.kind),
    name: node.name,
    server: node.server,
    port: String(node.port),
    secret,
    password: node.password ?? '',
    username: node.username ?? '',
    cipher: node.cipher ?? '',
    transport: node.transport ?? '',
    tls: node.tls,
    sni: node.sni ?? '',
    hostHeader: node.hostHeader ?? '',
    path: node.path ?? '',
    alpn: node.alpn ?? '',
    fingerprint: node.fingerprint ?? '',
    certificateFingerprint: node.certificateFingerprint ?? '',
    flow: node.flow ?? '',
    vlessEncryption: node.vlessEncryption ?? '',
    realityPublicKey: node.realityPublicKey ?? '',
    realityShortID: node.realityShortID ?? '',
    skipCertificateVerification: node.skipCertificateVerification,
    alterID: node.alterID !== undefined ? String(node.alterID) : '',
    protocolName: node.protocolName ?? '',
    protocolParam: node.protocolParam ?? '',
    obfs: node.obfs ?? '',
    obfsParam: node.obfsParam ?? '',
    version: node.version !== undefined ? String(node.version) : '',
    congestionControl: node.congestionControl ?? '',
    udpRelayMode: node.udpRelayMode ?? '',
    portHopping: node.portHopping ?? '',
    upMbps: node.upMbps !== undefined ? String(node.upMbps) : '',
    downMbps: node.downMbps !== undefined ? String(node.downMbps) : '',
    wireGuardPrivateKey: node.wireGuardPrivateKey ?? '',
    wireGuardPublicKey: node.wireGuardPublicKey ?? '',
    wireGuardPreSharedKey: node.wireGuardPreSharedKey ?? '',
    wireGuardIPv4: node.wireGuardIPv4 ?? '',
    wireGuardIPv6: node.wireGuardIPv6 ?? '',
    wireGuardAllowedIPs: node.wireGuardAllowedIPs ?? '',
    wireGuardReserved: node.wireGuardReserved ?? '',
    wireGuardMTU: node.wireGuardMTU !== undefined ? String(node.wireGuardMTU) : '',
    wireGuardPersistentKeepalive: node.wireGuardPersistentKeepalive !== undefined
      ? String(node.wireGuardPersistentKeepalive)
      : '',
    wireGuardDNS: node.wireGuardDNS ?? '',
    quic: node.trustTunnel?.quic ?? false,
    udpRelayEnabled: node.udpRelayEnabled ?? false,
    idleSessionCheckInterval: node.idleSessionCheckInterval !== undefined
      ? String(node.idleSessionCheckInterval)
      : '',
    idleSessionTimeout: node.idleSessionTimeout !== undefined ? String(node.idleSessionTimeout) : '',
    minIdleSession: node.minIdleSession !== undefined ? String(node.minIdleSession) : '',
    sshHostKeys: (node.ssh?.hostKeys ?? []).join('\n'),
  }
}

function required(value: string, label: string): string {
  const trimmed = value.trim()
  if (!trimmed) throw new Error(`请填写${label}`)
  return trimmed
}

function optional(value: string): string | undefined {
  const trimmed = value.trim()
  return trimmed || undefined
}

function numberOrUndefined(value: string, label: string, min = 0, max = Number.MAX_SAFE_INTEGER): number | undefined {
  const trimmed = value.trim()
  if (!trimmed) return undefined
  const parsed = Number(trimmed)
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${label}必须是 ${min} 到 ${max} 之间的整数`)
  }
  return parsed
}

function hostKeyList(value: string): string[] {
  return value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean)
}

export function buildManualNode(draft: ManualNodeDraft, existing?: ProxyNode): ProxyNode {
  const kind = draft.kind
  const server = required(draft.server, '服务器地址').trim()
  if (server.includes('://') || /[\s,/\\@?#=]/.test(server)) {
    throw new Error('服务器只填写主机名或 IP，不要带协议、端口、路径或空格')
  }
  const port = numberOrUndefined(draft.port, '端口', 1, 65535)
  if (!port) throw new Error('端口必须是 1 到 65535 之间的数字')
  const name = draft.name.trim() || `${PROXY_KIND_TITLES[kind]} · ${server}`

  const secret = draft.secret.trim()
  const password = draft.password.trim()
  const username = draft.username.trim()
  const cipher = draft.cipher.trim()
  const transport = optional(draft.transport)
  const tls = TLS_REQUIRED.includes(kind) || draft.tls
  const sni = optional(draft.sni)
  const hostHeader = optional(draft.hostHeader)
  const path = optional(draft.path)
  const alpn = optional(draft.alpn)
  const fingerprint = optional(draft.fingerprint)
  const flow = optional(draft.flow)
  const realityPublicKey = optional(draft.realityPublicKey)
  const realityShortID = optional(draft.realityShortID)

  if (kind === 'ss' || kind === 'ssr') {
    required(cipher, '加密方式')
    required(secret, '密码')
  }
  if (kind === 'ssr') {
    required(draft.protocolName, 'SSR 协议')
    required(draft.obfs, 'SSR 混淆')
  }
  if (kind === 'vmess' || kind === 'vless') required(secret, 'UUID')
  if (kind === 'trojan' || kind === 'hysteria' || kind === 'hysteria2' || kind === 'anytls') {
    required(secret, '密码')
  }
  if (kind === 'tuic') {
    required(secret, 'UUID')
    required(password, '密码')
  }
  if (kind === 'snell') required(secret, 'PSK')
  if (kind === 'trusttunnel') {
    required(username, '用户名')
    required(password, '密码')
  }
  if (kind === 'ssh') {
    required(username, '用户名')
    required(password, '密码')
  }
  if (kind === 'wireguard') {
    required(draft.wireGuardPrivateKey, 'WireGuard 私钥')
    required(draft.wireGuardPublicKey, 'WireGuard 公钥')
    required(draft.wireGuardAllowedIPs, '允许的网段')
    if (!draft.wireGuardIPv4.trim() && !draft.wireGuardIPv6.trim()) {
      throw new Error('WireGuard 至少需要填写一个本机 IPv4 / IPv6 地址')
    }
  }

  let upMbps: number | undefined
  let downMbps: number | undefined
  if (kind === 'hysteria') {
    upMbps = numberOrUndefined(draft.upMbps, '上行带宽', 1)
    downMbps = numberOrUndefined(draft.downMbps, '下行带宽', 1)
    if (!upMbps || !downMbps) throw new Error('Hysteria 必须填写大于 0 的上行和下行带宽')
  }

  let alterID: number | undefined
  if (kind === 'vmess' && draft.alterID.trim()) {
    alterID = numberOrUndefined(draft.alterID, 'Alter ID', 0, 65535)
  }
  let version: number | undefined
  if (kind === 'snell' && draft.version.trim()) {
    version = numberOrUndefined(draft.version, 'Snell 版本', 1, 6)
  }
  const idleSessionCheckInterval = kind === 'anytls'
    ? numberOrUndefined(draft.idleSessionCheckInterval, 'AnyTLS 会话检查间隔', 0)
    : undefined
  const idleSessionTimeout = kind === 'anytls'
    ? numberOrUndefined(draft.idleSessionTimeout, 'AnyTLS 会话超时', 0)
    : undefined
  const minIdleSession = kind === 'anytls'
    ? numberOrUndefined(draft.minIdleSession, 'AnyTLS 最小空闲会话', 0)
    : undefined
  const mtu = kind === 'wireguard' ? numberOrUndefined(draft.wireGuardMTU, 'WireGuard MTU', 1) : undefined
  const keepalive = kind === 'wireguard'
    ? numberOrUndefined(draft.wireGuardPersistentKeepalive, 'WireGuard keepalive', 0)
    : undefined

  const node: ProxyNode = {
    id: existing?.id ?? newID(),
    sourceID: undefined,
    kind,
    name,
    server,
    port,
    cipher: kind === 'ss' || kind === 'ssr'
      ? cipher
      : kind === 'vmess' ? (cipher || 'auto') : undefined,
    password: kind === 'tuic' || ['trusttunnel', 'ssh', 'socks5', 'http'].includes(kind)
      ? (password || secret || undefined)
      : ['ss', 'ssr', 'trojan', 'hysteria', 'hysteria2', 'anytls', 'snell'].includes(kind)
        ? (secret || undefined)
        : undefined,
    uuid: kind === 'vmess' || kind === 'vless' || kind === 'tuic' ? secret : undefined,
    username: ['trusttunnel', 'ssh', 'socks5', 'http'].includes(kind) ? username || undefined : undefined,
    transport: ['vmess', 'vless', 'trojan'].includes(kind) ? transport : undefined,
    transportMode: transport === 'xhttp' ? 'packet-up' : undefined,
    tls,
    sni,
    hostHeader,
    path,
    alpn,
    realityPublicKey: kind === 'vless' ? realityPublicKey : undefined,
    realityShortID: kind === 'vless' ? realityShortID : undefined,
    fingerprint: kind === 'vless' || kind === 'vmess' ? fingerprint : undefined,
    certificateFingerprint: optional(draft.certificateFingerprint),
    flow: kind === 'vless' ? flow : undefined,
    vlessEncryption: kind === 'vless' ? optional(draft.vlessEncryption) : undefined,
    skipCertificateVerification: draft.skipCertificateVerification,
    alterID,
    protocolName: kind === 'ssr' || kind === 'hysteria' ? optional(draft.protocolName) : undefined,
    protocolParam: kind === 'ssr' ? optional(draft.protocolParam) : undefined,
    obfs: ['ss', 'ssr', 'hysteria', 'hysteria2', 'snell'].includes(kind) ? optional(draft.obfs) : undefined,
    obfsParam: ['ss', 'ssr', 'hysteria2', 'snell'].includes(kind) ? optional(draft.obfsParam) : undefined,
    version,
    congestionControl: kind === 'tuic' ? optional(draft.congestionControl) : undefined,
    udpRelayMode: kind === 'tuic' ? optional(draft.udpRelayMode) : undefined,
    udpRelayEnabled: ['ss', 'trusttunnel'].includes(kind) || kind === 'tuic' ? draft.udpRelayEnabled : undefined,
    portHopping: kind === 'hysteria2' ? optional(draft.portHopping) : undefined,
    upMbps,
    downMbps,
    wireGuardPrivateKey: kind === 'wireguard' ? optional(draft.wireGuardPrivateKey) : undefined,
    wireGuardPublicKey: kind === 'wireguard' ? optional(draft.wireGuardPublicKey) : undefined,
    wireGuardPreSharedKey: kind === 'wireguard' ? optional(draft.wireGuardPreSharedKey) : undefined,
    wireGuardIPv4: kind === 'wireguard' ? optional(draft.wireGuardIPv4) : undefined,
    wireGuardIPv6: kind === 'wireguard' ? optional(draft.wireGuardIPv6) : undefined,
    wireGuardAllowedIPs: kind === 'wireguard' ? optional(draft.wireGuardAllowedIPs) : undefined,
    wireGuardReserved: kind === 'wireguard' ? optional(draft.wireGuardReserved) : undefined,
    wireGuardMTU: mtu,
    wireGuardPersistentKeepalive: keepalive,
    wireGuardDNS: kind === 'wireguard' ? optional(draft.wireGuardDNS) : undefined,
    idleSessionCheckInterval,
    idleSessionTimeout,
    minIdleSession,
    trustTunnel: kind === 'trusttunnel' ? { quic: draft.quic } : undefined,
    ssh: kind === 'ssh' ? { hostKeys: hostKeyList(draft.sshHostKeys) } : undefined,
    rawURI: '',
    isManual: true,
    isEnabled: existing?.isEnabled !== false,
    countryOverride: existing?.countryOverride,
    detectedCountry: existing?.detectedCountry,
  }
  return node
}
