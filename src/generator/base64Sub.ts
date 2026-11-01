// Node-only Base64 subscription output (Shadowrocket / V2Box / Anywhere):
// re-emit each node as a share URI, join with newlines, base64 the whole.
import type { ClientTarget, ProxyNode } from '../models/types'
import { encodeBase64String } from '../parser/util'
import type { OutputOptions } from './groups'

const enc = encodeURIComponent

const V2BOX_KINDS = new Set(['ss', 'vmess', 'vless', 'trojan', 'wireguard', 'hysteria2', 'socks5', 'http'])
const ANYWHERE_KINDS = new Set(['ss', 'vless', 'trojan', 'anytls', 'hysteria2', 'socks5'])
const ANYWHERE_CIPHERS = new Set([
  'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'chacha20-poly1305',
  '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305', 'none',
])
const ANYWHERE_FINGERPRINTS = new Map<string, string | undefined>([
  ['chrome', 'chrome_133'],
  ['firefox', 'firefox_148'],
  ['safari', 'safari_26'],
  ['ios', 'chrome_120'],
  ['edge', 'edge_106'],
  ['random', undefined],
  ['randomized', undefined],
])
const ANYWHERE_NATIVE_FINGERPRINTS = new Set([
  'chrome_133', 'chrome_120', 'chrome_106', 'firefox_148', 'firefox_120',
  'safari_26', 'edge_106', 'non_browser',
])
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function anywhereUnsupported(node: ProxyNode): boolean {
  if (!ANYWHERE_KINDS.has(node.kind)) return true
  if (node.kind === 'vless' && !UUID_RE.test(node.uuid ?? '')) return true
  if (node.skipCertificateVerification || node.certificateFingerprint) return true
  if (node.udpRelayEnabled === false) return true
  if (node.fingerprint) {
    const fingerprint = node.fingerprint.toLowerCase()
    if (!ANYWHERE_FINGERPRINTS.has(fingerprint) && !ANYWHERE_NATIVE_FINGERPRINTS.has(fingerprint)) {
      return true
    }
  }
  if ((node.portHopping ?? '').trim() || (node.plugin ?? '').trim()) return true
  const transport = (node.transport ?? 'tcp').toLowerCase()
  if ((node.realityPublicKey && node.kind !== 'vless')
    || (node.kind !== 'vless' && !['', 'tcp'].includes(transport))) {
    return true
  }
  if (node.kind === 'ss') {
    if (node.tls || (node.obfs ?? 'none').toLowerCase() !== 'none') return true
    if (!node.password || !ANYWHERE_CIPHERS.has((node.cipher ?? '').toLowerCase())) return true
  }
  if (node.kind === 'socks5' && node.tls) return true
  if (node.kind === 'hysteria2') {
    if ((node.alpn ?? '').trim()) return true
    if (![undefined, '', 'none', 'salamander', 'gecko'].includes(node.obfs?.toLowerCase())) return true
  }
  return false
}

/** Anywhere 的 URI 方言：查询参数别名与 TLS 指纹映射，均已对照上游实现。 */
function anywhereLink(uri: string, node: ProxyNode): string | undefined {
  if (node.kind === 'ss') return uri
  let url: URL
  try {
    url = new URL(uri)
  } catch {
    return undefined
  }
  const aliases: Record<string, string> = {
    'idle-session-check-interval': 'ici',
    'idle-session-timeout': 'it',
    'min-idle-session': 'mis',
  }
  const next = new URLSearchParams()
  for (const [key, value] of url.searchParams) {
    if (node.kind === 'vless' && node.transport === 'grpc' && key === 'host') {
      next.append('authority', value)
      continue
    }
    if (node.kind === 'anytls' && aliases[key]) {
      next.append(aliases[key], value)
      continue
    }
    if (key === 'fp') {
      const fingerprint = value.toLowerCase()
      if (ANYWHERE_FINGERPRINTS.has(fingerprint)) {
        const mapped = ANYWHERE_FINGERPRINTS.get(fingerprint)
        if (mapped) next.append('fp', mapped)
        continue
      }
    }
    next.append(key, value)
  }
  if (node.kind === 'vless' && node.flow && !next.has('flow')) next.append('flow', node.flow)
  if (node.kind === 'hysteria2') {
    if (node.upMbps !== undefined) next.append('upmbps', String(node.upMbps))
    if (node.downMbps !== undefined) next.append('downmbps', String(node.downMbps))
  }
  url.search = node.kind === 'socks5' ? '' : next.toString()
  return url.href
}

function b64urlSafe(value: string): string {
  return encodeBase64String(value).replace(/=+$/, '')
}

function nodeURI(node: ProxyNode, displayName: string, target?: ClientTarget): string | undefined {
  if (target === 'v2box' && !V2BOX_KINDS.has(node.kind)) return undefined
  if (target === 'anywhere' && anywhereUnsupported(node)) return undefined
  const name = enc(displayName)
  const server = node.server.includes(':') ? `[${node.server}]` : node.server
  switch (node.kind) {
    case 'ss': {
      const auth = b64urlSafe(`${node.cipher ?? 'aes-256-gcm'}:${node.password ?? ''}`)
      let plugin = ''
      if (node.shadowTLS) {
        plugin = `?plugin=${enc(`shadow-tls;host=${node.shadowTLS.host};password=${node.shadowTLS.password};version=${node.shadowTLS.version}`)}`
      } else if (node.plugin === 'v2ray-plugin') {
        const parts = ['v2ray-plugin;mode=websocket']
        if (node.tls) parts.push('tls')
        if (node.hostHeader) parts.push(`host=${node.hostHeader}`)
        if (node.path) parts.push(`path=${node.path}`)
        plugin = `?plugin=${enc(parts.join(';'))}`
      } else if (node.obfs) {
        const parts = [`obfs-local;obfs=${node.obfs}`]
        if (node.obfsParam) parts.push(`obfs-host=${node.obfsParam}`)
        plugin = `?plugin=${enc(parts.join(';'))}`
      }
      return `ss://${auth}@${server}:${node.port}${plugin}#${name}`
    }
    case 'ssr': {
      const main = `${node.server}:${node.port}:${node.protocolName ?? 'origin'}:${node.cipher ?? 'aes-256-cfb'}:${node.obfs ?? 'plain'}:${b64urlSafe(node.password ?? '')}`
      const query = [
        `remarks=${b64urlSafe(displayName)}`,
        node.protocolParam ? `protoparam=${b64urlSafe(node.protocolParam)}` : '',
        node.obfsParam ? `obfsparam=${b64urlSafe(node.obfsParam)}` : '',
      ].filter(Boolean).join('&')
      return `ssr://${b64urlSafe(`${main}/?${query}`)}`
    }
    case 'vmess': {
      const json = {
        v: '2',
        ps: displayName,
        add: node.server,
        port: String(node.port),
        id: node.uuid ?? '',
        aid: String(node.alterID ?? 0),
        scy: node.cipher ?? 'auto',
        net: node.transport ?? 'tcp',
        type: 'none',
        host: node.hostHeader ?? '',
        path: node.path ?? '',
        tls: node.tls ? 'tls' : '',
        sni: node.sni ?? '',
        alpn: node.alpn ?? '',
      }
      return `vmess://${encodeBase64String(JSON.stringify(json))}`
    }
    case 'vless': {
      const params = new URLSearchParams()
      params.set('type', node.transport ?? 'tcp')
      params.set('security', node.realityPublicKey ? 'reality' : node.tls ? 'tls' : 'none')
      if (node.sni) params.set('sni', node.sni)
      if (node.hostHeader) params.set('host', node.hostHeader)
      if (node.path) params.set('path', node.path)
      if (node.flow) params.set('flow', node.flow)
      if (node.realityPublicKey) params.set('pbk', node.realityPublicKey)
      if (node.realityShortID) params.set('sid', node.realityShortID)
      if (node.fingerprint) params.set('fp', node.fingerprint)
      if (node.skipCertificateVerification) params.set('allowInsecure', '1')
      if (node.vlessEncryption) params.set('encryption', node.vlessEncryption)
      else params.set('encryption', 'none')
      return `vless://${node.uuid ?? ''}@${server}:${node.port}?${params}#${name}`
    }
    case 'trojan': {
      const params = new URLSearchParams()
      if (node.sni) params.set('sni', node.sni)
      if (node.transport && node.transport !== 'tcp') params.set('type', node.transport)
      if (node.hostHeader) params.set('host', node.hostHeader)
      if (node.path) params.set('path', node.path)
      if (node.skipCertificateVerification) params.set('allowInsecure', '1')
      const query = params.toString()
      return `trojan://${enc(node.password ?? '')}@${server}:${node.port}${query ? `?${query}` : ''}#${name}`
    }
    case 'hysteria2': {
      const params = new URLSearchParams()
      if (node.sni) params.set('sni', node.sni)
      if (node.obfs) {
        params.set('obfs', node.obfs)
        if (node.obfsParam) params.set('obfs-password', node.obfsParam)
      }
      if (node.portHopping) params.set('mport', node.portHopping)
      if (node.skipCertificateVerification) params.set('insecure', '1')
      const query = params.toString()
      return `hy2://${enc(node.password ?? '')}@${server}:${node.port}${query ? `?${query}` : ''}#${name}`
    }
    case 'tuic': {
      const params = new URLSearchParams()
      if (node.sni) params.set('sni', node.sni)
      if (node.congestionControl) params.set('congestion_control', node.congestionControl)
      if (node.udpRelayMode) params.set('udp_relay_mode', node.udpRelayMode)
      if (node.skipCertificateVerification) params.set('allow_insecure', '1')
      const query = params.toString()
      return `tuic://${node.uuid ?? ''}:${enc(node.password ?? '')}@${server}:${node.port}${query ? `?${query}` : ''}#${name}`
    }
    case 'anytls': {
      const params = new URLSearchParams()
      if (node.sni) params.set('sni', node.sni)
      if (node.skipCertificateVerification) params.set('insecure', '1')
      if (node.idleSessionCheckInterval !== undefined) {
        params.set('idle-session-check-interval', String(node.idleSessionCheckInterval))
      }
      if (node.idleSessionTimeout !== undefined) {
        params.set('idle-session-timeout', String(node.idleSessionTimeout))
      }
      if (node.minIdleSession !== undefined) {
        params.set('min-idle-session', String(node.minIdleSession))
      }
      const query = params.toString()
      return `anytls://${enc(node.password ?? '')}@${server}:${node.port}${query ? `?${query}` : ''}#${name}`
    }
    case 'socks5': {
      const auth = node.username ? `${enc(node.username)}:${enc(node.password ?? '')}@` : ''
      return `socks5://${auth}${server}:${node.port}#${name}`
    }
    case 'http': {
      const auth = node.username ? `${enc(node.username)}:${enc(node.password ?? '')}@` : ''
      return `${node.tls ? 'https' : 'http'}://${auth}${server}:${node.port}#${name}`
    }
    case 'wireguard': {
      if (!node.wireGuardPrivateKey || !node.wireGuardPublicKey) return undefined
      const addresses = [node.wireGuardIPv4, node.wireGuardIPv6].filter(Boolean)
      if (!addresses.length) return undefined
      const params = new URLSearchParams()
      params.set('publickey', node.wireGuardPublicKey)
      params.set('address', addresses.join(','))
      params.set('allowedips', node.wireGuardAllowedIPs || '0.0.0.0/0,::/0')
      if (node.wireGuardReserved) params.set('reserved', node.wireGuardReserved)
      if (node.wireGuardPreSharedKey) params.set('presharedkey', node.wireGuardPreSharedKey)
      if (node.wireGuardMTU !== undefined) params.set('mtu', String(node.wireGuardMTU))
      if (node.wireGuardPersistentKeepalive !== undefined) {
        params.set('keepalive', String(node.wireGuardPersistentKeepalive))
      }
      if (node.wireGuardDNS) params.set('dns', node.wireGuardDNS)
      return `wireguard://${enc(node.wireGuardPrivateKey)}@${server}:${node.port}?${params.toString()}#${name}`
    }
    default:
      // snell / hysteria1 / ssh … have no portable URI form here.
      return undefined
  }
}

export function generateBase64Subscription(
  nodes: ProxyNode[],
  options: OutputOptions = {},
): { text: string; skipped: number } {
  const usable = nodes.filter((n) => !n.isSubscriptionMetadata)
  const uris: string[] = []
  let skipped = 0
  for (const node of usable) {
    let uri = nodeURI(node, options.nameForNode?.(node) ?? node.name, options.target)
    if (uri && options.target === 'anywhere') uri = anywhereLink(uri, node)
    if (uri) uris.push(uri)
    else skipped += 1
  }
  return { text: encodeBase64String(uris.join('\n')), skipped }
}
