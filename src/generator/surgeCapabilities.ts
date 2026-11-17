// Surge 测试版协议能力：按请求方 User-Agent 的构建号分级。
// 正式版 App Store 构建只拿基线配置；测试版依次解锁 VLESS、
// VLESS Encryption / XHTTP、HTTPUpgrade。与上游 SurgeClientCapabilities 对齐。
import type { ProxyNode } from '../models/types'

export type SurgeTier = 1 | 2 | 3

/** 第一版支持对应能力的构建号；低于该值按更低档位处理。 */
export const SURGE_TIER_BUILDS = {
  ios: { vless: 4024, vlessExtensions: 4026, httpUpgrade: 4027 },
  mac: { vless: 12820, vlessExtensions: 12840, httpUpgrade: 12860 },
} as const

export type SurgePlatform = 'surge' | 'surge-mac'

/** 从 `Surge iOS/4027` / `Surge Mac/12860` 解析平台与档位。 */
export function surgeTierFromUserAgent(userAgent: string | undefined): { platform: SurgePlatform; tier: SurgeTier } | undefined {
  const match = String(userAgent ?? '').match(/Surge (iOS|Mac)\/(\d+)/i)
  if (!match) return undefined
  const build = Number(match[2])
  if (!Number.isFinite(build)) return undefined
  const platform: SurgePlatform = match[1].toLowerCase() === 'ios' ? 'surge' : 'surge-mac'
  const thresholds = platform === 'surge' ? SURGE_TIER_BUILDS.ios : SURGE_TIER_BUILDS.mac
  if (build >= thresholds.httpUpgrade) return { platform, tier: 3 }
  if (build >= thresholds.vlessExtensions) return { platform, tier: 2 }
  if (build >= thresholds.vless) return { platform, tier: 1 }
  return undefined
}

/** Surge 的 encryption 值是 xray vlessenc 的客户端字符串。 */
export function surgeAcceptsVLESSEncryption(value: string | undefined): boolean {
  const parts = String(value ?? '').trim().split('.')
  if (parts.length < 4 || parts[0].toLowerCase() !== 'mlkem768x25519plus') return false
  if (!['native', 'xorpub', 'random'].includes(parts[1].toLowerCase())) return false
  if (!['1rtt', '0rtt'].includes(parts[2].toLowerCase())) return false
  return parts.slice(3).every((part) => /^[A-Za-z0-9_=-]+$/.test(part))
}

/**
 * Surge 的 `vless` 策略能完整表达哪些节点。
 * tier 1：RAW / WS / gRPC（含 REALITY、Vision），不含 Encryption / XHTTP；
 * tier 2：再加 Encryption 与 XHTTP；
 * tier 3：再加 HTTPUpgrade。
 */
export function surgeAcceptsVLESS(node: ProxyNode, tier: SurgeTier): boolean {
  if (node.kind !== 'vless') return false
  const transport = (node.transport ?? 'tcp').toLowerCase()
  const encrypted = !!node.vlessEncryption
  if (tier < 2 && (encrypted || transport === 'xhttp')) return false
  if (tier < 3 && transport === 'httpupgrade') return false
  if (encrypted && !surgeAcceptsVLESSEncryption(node.vlessEncryption)) return false
  const reality = !!node.realityPublicKey
  const secured = node.tls || reality
  const raw = ['', 'tcp', 'raw'].includes(transport)
  if (reality) {
    if (!(raw || ['grpc', 'xhttp'].includes(transport))) return false
    const shortID = (node.realityShortID ?? '').trim()
    if (shortID.length > 16 || !/^[0-9a-f]*$/i.test(shortID)) return false
  }
  const flow = (node.flow ?? '').trim().toLowerCase()
  if (flow) {
    if (!['xtls-rprx-vision', 'xtls-rprx-vision-udp443'].includes(flow)) return false
    const visionCarrier = (raw && secured)
      || (encrypted && (raw || ['ws', 'httpupgrade', 'xhttp'].includes(transport)))
    if (!visionCarrier) return false
  }
  if (transport === 'xhttp') {
    const mode = (node.transportMode ?? '').trim().toLowerCase()
    return ['', 'auto', 'packet-up', 'stream-up', 'stream-one'].includes(mode)
  }
  if (raw || ['ws', 'httpupgrade'].includes(transport)) return true
  return transport === 'grpc' && secured
}

/** tier 3 下能进入 Surge 的节点数；用于发布时判断是否需要生成测试版变体。 */
export function surgeBetaNodeCount(nodes: ProxyNode[]): number {
  return nodes.filter((node) => surgeAcceptsVLESS(node, 3)
    || (['vmess', 'trojan'].includes(node.kind) && (node.transport ?? '').toLowerCase() === 'httpupgrade')).length
}
