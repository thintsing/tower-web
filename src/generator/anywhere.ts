// Anywhere AJSON 订阅：只在请求头声明 ajson/1 时返回。
// 分享链接没有逐节点 insecure 字段，跳过证书校验的 VLESS / Trojan / AnyTLS
// 节点改为结构化 proxy；其他节点仍是原来的链接字符串。
import type { ProxyNode } from '../models/types'
import { anywhereShareLink } from './base64Sub'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const FINGERPRINTS = new Map<string, string | undefined>([
  ['chrome', 'chrome_133'],
  ['firefox', 'firefox_148'],
  ['safari', 'safari_26'],
  ['ios', 'chrome_120'],
  ['edge', 'edge_106'],
  ['random', undefined],
  ['randomized', undefined],
])

const NATIVE_FINGERPRINTS = new Set([
  'chrome_133', 'chrome_120', 'chrome_106', 'firefox_148', 'firefox_120',
  'safari_26', 'edge_106', 'non_browser',
])

/** 与 base64Sub 的 Anywhere 链接共用同一套指纹映射。 */
function anywhereFingerprint(node: ProxyNode): string | undefined | false {
  const raw = (node.fingerprint ?? '').trim()
  if (!raw) return 'plain'
  const key = raw.toLowerCase()
  if (NATIVE_FINGERPRINTS.has(key)) return key
  if (!FINGERPRINTS.has(key)) return false
  return FINGERPRINTS.get(key)
}

/**
 * 跳过证书校验的节点才有 AJSON 变体。Reality 没有证书校验可跳，Hysteria 没有
 * insecure 字段，因此都不在这里；WS / gRPC / XHTTP 在 Anywhere 里重建 TLS 时
 * 不带 insecureSkipVerify，也保持跳过。
 */
export function anywhereAjsonProxy(node: ProxyNode): Record<string, unknown> | undefined {
  if (!node.skipCertificateVerification || node.certificateFingerprint) return undefined
  if ((node.portHopping ?? '').trim() || (node.plugin ?? '').trim()) return undefined
  if (node.udpRelayEnabled === false) return undefined
  if (node.realityPublicKey) return undefined
  const fingerprint = anywhereFingerprint(node)
  if (fingerprint === false) return undefined
  const tls: Record<string, unknown> = { type: 'tls', insecure: true, fingerprint }
  if (node.sni) tls.sni = node.sni
  if (node.alpn) tls.alpn = node.alpn.split(',').map((item) => item.trim()).filter(Boolean)
  const base: Record<string, unknown> = {
    name: node.name,
    server: node.server,
    port: node.port,
    security: tls,
  }

  if (node.kind === 'vless') {
    if (!node.tls || !UUID_RE.test(node.uuid ?? '')) return undefined
    const transport = (node.transport ?? 'tcp').toLowerCase()
    if (!['', 'tcp', 'raw', 'httpupgrade'].includes(transport)) return undefined
    const proxy: Record<string, unknown> = { ...base, protocol: 'vless', uuid: node.uuid }
    if (node.vlessEncryption) proxy.encryption = node.vlessEncryption
    if (node.flow) proxy.flow = node.flow
    if (transport === 'httpupgrade') {
      const layer: Record<string, unknown> = { type: 'httpupgrade' }
      if (node.hostHeader) layer.host = node.hostHeader
      if (node.path) layer.path = node.path
      proxy.transport = layer
    }
    return proxy
  }

  if (node.kind === 'trojan' || node.kind === 'anytls') {
    if (!node.password) return undefined
    const proxy: Record<string, unknown> = {
      ...base,
      protocol: node.kind,
      password: node.password,
    }
    if (node.kind === 'anytls') {
      if (node.idleSessionCheckInterval !== undefined) proxy.idleCheckInterval = node.idleSessionCheckInterval
      if (node.idleSessionTimeout !== undefined) proxy.idleTimeout = node.idleSessionTimeout
      if (node.minIdleSession !== undefined) proxy.minIdleSession = node.minIdleSession
    }
    return proxy
  }

  return undefined
}

/** 生成的 AJSON 文档；没有可保留的跳过证书节点时返回 undefined。 */
export function anywhereAjsonDocument(nodes: ProxyNode[], name: string): string | undefined {
  const proxies: unknown[] = []
  let hasAjsonProxy = false
  for (const node of nodes) {
    if (node.skipCertificateVerification) {
      const proxy = anywhereAjsonProxy(node)
      if (!proxy) return undefined
      proxies.push(proxy)
      hasAjsonProxy = true
      continue
    }
    const link = anywhereShareLink(node, node.name)
    if (link) proxies.push(link)
  }
  if (!hasAjsonProxy || proxies.length === 0) return undefined
  return `${JSON.stringify({ anywhere: 1, name, proxies }, null, 2)}\n`
}

export function anywhereAjsonCount(nodes: ProxyNode[]): number {
  return nodes.filter((node) => !!anywhereAjsonProxy(node)).length
}
