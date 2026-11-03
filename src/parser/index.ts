// Subscription content orchestration, ported from Tower iOS
// SubscriptionParser.parse: base64 → JSON → Surge/Loon/Quantumult X node
// sections → Clash YAML → line-by-line URIs, with STATUS= lines, notice
// detection and dedupe.
import type { ProxyNode, SubscriptionUsage } from '../models/types'
import { regionForNode } from '../models/region'
import { parseClashYAML } from './clash'
import { parseSingBoxEndpoints } from './singbox'
import { parseURI } from './uri'
import { decodeBase64String } from './util'
import { containsClientProxySection, parseClientProxyConfiguration } from './clientConfigs'

export interface ParsedContent {
  nodes: ProxyNode[]
  rejectedLineCount: number
  /** Airport announcements smuggled into the node list. */
  notices: string[]
  /** Quota read from a `STATUS=` line or a notice remark. */
  status?: SubscriptionUsage
}

const NOTICE_KEYWORDS = [
  '剩余流量', '已用流量', '总流量', '流量重置', '距离下次重置', '重置剩余',
  '套餐到期', '到期时间', '过期时间', '有效期至', '账户余额',
  '官网', '续费', '客服', '邮箱', '订阅地址', '机场地址',
  'expire', 'expires', 'traffic', 'remaining', 'reset',
]

/** Hosts airports park announcement entries on. No real proxy runs there. */
const PLACEHOLDER_HOSTS = new Set([
  '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '223.5.5.5',
  '127.0.0.1', '0.0.0.0', 'localhost', 'invalid.local',
])

export function isNoticeName(name: string): boolean {
  const text = name.toLowerCase()
  return NOTICE_KEYWORDS.some((k) => text.includes(k.toLowerCase()))
}

export function isNoticeNode(node: ProxyNode): boolean {
  return isNoticeName(node.name) || PLACEHOLDER_HOSTS.has(node.server.toLowerCase())
}

export const STATUS_PREFIX = 'STATUS='

/**
 * Tolerant STATUS= / TRAFFIC= line, also accepts key=value declarations:
 * `STATUS=↑:1.2GB ↓:34GB TOT:500GB EXPIRES:2027-01-01`
 * `TRAFFIC=upload=1.2GB; download=34GB; total=500GB; expire=2027-01-01`
 */
export function parseStatusLine(line: string): SubscriptionUsage | undefined {
  let text = line.trim()
  if (/^(?:STATUS|TRAFFIC)\s*=/i.test(text)) {
    text = text.replace(/^(?:STATUS|TRAFFIC)\s*=/i, '').trim()
  }
  const usage: SubscriptionUsage = {}
  let matched = false
  const up = bytesAfter('↑:', text)
  if (up !== undefined) { usage.upload = up; matched = true }
  const down = bytesAfter('↓:', text)
  if (down !== undefined) { usage.download = down; matched = true }
  const total = bytesAfter('TOT:', text) ?? bytesAfter('TOTAL:', text)
  if (total !== undefined) { usage.total = total; matched = true }
  const expires = timeAfter('EXPIRES:', text) ?? timeAfter('EXPIRE:', text)
  if (expires !== undefined) { usage.expire = expires; matched = true }

  // `upload=…; download=…; total=…; expire=…` (with optional units / dates).
  const setKeyValue = (key: string, raw: string) => {
    const value = raw.replace(/^["']|["']$/g, '').trim()
    if (!value) return
    if (key === 'expire' || key === 'expires') {
      const expire = parseExpiryValue(value)
      if (expire !== undefined) { usage.expire = expire; matched = true }
      return
    }
    const bytes = parseBytesValue(value)
    if (bytes !== undefined) {
      if (key === 'upload') usage.upload = bytes
      else if (key === 'download') usage.download = bytes
      else if (key === 'total') usage.total = bytes
      matched = true
    }
  }
  const keyPattern = /(?:^|[\s;,|])(upload|download|total|expire|expires)\s*=\s*("[^"]*"|'[^']*'|[^\s;,|]+)/gi
  for (const match of text.matchAll(keyPattern)) setKeyValue(match[1].toLowerCase(), match[2])
  return matched ? usage : undefined
}

/** Merge quota sources field by field；后面的来源覆盖前面的同名字段。 */
export function mergeUsage(
  ...values: (SubscriptionUsage | undefined)[]
): SubscriptionUsage | undefined {
  let merged: SubscriptionUsage | undefined
  let matched = false
  for (const value of values) {
    if (!value) continue
    for (const key of ['upload', 'download', 'total', 'expire'] as const) {
      const item = value[key]
      if (typeof item !== 'number' || !Number.isFinite(item)) continue
      merged = { ...(merged ?? {}), [key]: item }
      matched = true
    }
  }
  return matched ? merged : undefined
}

/**
 * 从订阅正文里挑出配额声明行。只接受明确的 STATUS=/TRAFFIC= 行、以
 * upload/download/total/expire 开头的行，或至少含两个配额键的行；
 * 含节点 scheme 的行一律跳过，避免把节点参数当成套餐信息。
 */
export function parseUsageDeclaration(data: string): SubscriptionUsage | undefined {
  let merged: SubscriptionUsage | undefined
  for (const rawLine of data.split(/\r?\n/)) {
    const line = rawLine.replace(/\uFEFF/g, '').trim()
    if (!line || line.length > 400 || line.includes('://')) continue
    const stripped = line.replace(/^(?:#|;|\/\/)\s*/, '')
    const markerLine = /^(?:STATUS|TRAFFIC)\s*=/i.test(stripped)
    const startsWithKey = /^(?:upload|download|total|expire|expires)\s*=/i.test(stripped)
    const keyCount = (stripped.match(/\b(?:upload|download|total|expire|expires)\s*=/gi) ?? []).length
    if (!markerLine && !startsWithKey && keyCount < 2) continue
    const parsed = parseStatusLine(stripped)
    if (parsed) merged = mergeUsage(merged, parsed)
  }
  return merged
}

const UNIT_MULTIPLIERS: Record<string, number> = {
  '': 1, b: 1,
  k: 1024, kb: 1024,
  m: 1048576, mb: 1048576,
  g: 1073741824, gb: 1073741824,
  t: 1099511627776, tb: 1099511627776,
}

function toBytes(value: string, unitText: string): number | undefined {
  const amount = Number(value)
  const unit = unitText.toLowerCase().replace('i', '')
  const multiplier = UNIT_MULTIPLIERS[unit]
  if (!Number.isFinite(amount) || multiplier === undefined) return undefined
  const bytes = amount * multiplier
  // Saturate instead of overflowing (providers write nonsense).
  if (bytes <= 0) return 0
  if (bytes >= Number.MAX_SAFE_INTEGER) return Number.MAX_SAFE_INTEGER
  return Math.floor(bytes)
}

function parseBytesValue(raw: string): number | undefined {
  const m = raw.trim().match(/^([\d.]+)\s*([kmgt]?i?b?)$/i)
  return m ? toBytes(m[1], m[2]) : undefined
}

function bytesAfter(marker: string, text: string): number | undefined {
  const index = text.toUpperCase().indexOf(marker.toUpperCase())
  if (index < 0) return undefined
  // 允许后面继续跟其它 STATUS/TRAFFIC 字段，所以只匹配开头的数值。
  const m = text.slice(index + marker.length).match(/^\s*([\d.]+)\s*([kmgt]?i?b?)/i)
  return m ? toBytes(m[1], m[2]) : undefined
}

/** Unix 秒 / Unix 毫秒 / YYYY-MM-DD（按 UTC 午夜，和旧解析保持一致）。 */
function parseExpiryValue(raw: string): number | undefined {
  const text = raw.trim()
  if (/^\d+(?:\.\d+)?$/.test(text)) {
    const value = Number(text)
    if (!Number.isFinite(value) || value < 0) return undefined
    return Math.floor(value > 1e12 ? value / 1000 : value)
  }
  const m = text.replace(/[./]/g, '-').match(/^(\d{4})-(\d{1,2})-(\d{1,2})/)
  if (!m) return undefined
  const date = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]))
  return Number.isFinite(date) ? Math.floor(date / 1000) : undefined
}

function timeAfter(marker: string, text: string): number | undefined {
  const index = text.toUpperCase().indexOf(marker.toUpperCase())
  if (index < 0) return undefined
  return parseExpiryValue(text.slice(index + marker.length))
}

/** `subscription-userinfo: upload=…; download=…; total=…; expire=…` header. */
export function parseUserinfoHeader(header: string | undefined | null): SubscriptionUsage | undefined {
  if (!header) return undefined
  const usage: SubscriptionUsage = {}
  let matched = false
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    const key = part.slice(0, eq).trim().toLowerCase()
    const value = Number(part.slice(eq + 1).trim().replace(/^["']|["']$/g, ''))
    if (!Number.isFinite(value) || value < 0) continue
    if (key === 'upload') { usage.upload = Math.floor(value); matched = true }
    else if (key === 'download') { usage.download = Math.floor(value); matched = true }
    else if (key === 'total') { usage.total = Math.floor(value); matched = true }
    else if (key === 'expire') { usage.expire = Math.floor(value); matched = true }
  }
  return matched ? usage : undefined
}

const NODE_SCHEMES = [
  'ss://', 'ssr://', 'vmess://', 'vless://', 'trojan://', 'anytls://',
  'hysteria2://', 'hy2://', 'hysteria://', 'hy://', 'tuic://',
  'socks5://', 'socks://', 'http://', 'https://',
]

function containsNodeScheme(text: string): boolean {
  const lower = text.toLowerCase()
  return NODE_SCHEMES.some((s) => lower.includes(s))
}

export function parse(data: string, sourceID?: string): ParsedContent {
  let text = data.trim()

  if (!containsNodeScheme(text)) {
    const decoded = decodeBase64String(text)?.trim()
    if (decoded && (containsNodeScheme(decoded) || decoded.startsWith('{') || decoded.startsWith('['))) {
      text = decoded
    }
  }

  const declaredStatus = parseUsageDeclaration(text)

  if (text.startsWith('{') || text.startsWith('[')) {
    const endpoints = parseSingBoxEndpoints(text, sourceID)
    if (endpoints) return finish(endpoints.nodes, endpoints.rejected, declaredStatus)
  }

  if (containsClientProxySection(text)) {
    const parsed = parseClientProxyConfiguration(text, sourceID)
    return finish(parsed.nodes, parsed.rejected, declaredStatus)
  }

  if (text.includes('proxies:')) {
    const parsed = parseClashYAML(text, sourceID)
    return finish(parsed.nodes, parsed.rejected, declaredStatus)
  }

  // Line-by-line URI list. Some panels paste several links on one line.
  // A leading STATUS= quota line is never split on spaces.
  let headStatus: SubscriptionUsage | undefined
  const rawLines: string[] = []
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (trimmed.startsWith(STATUS_PREFIX)) {
      headStatus = headStatus ?? parseStatusLine(trimmed)
      continue
    }
    rawLines.push(trimmed)
  }
  const candidates = rawLines
    .flatMap((line) => {
      const trimmed = line.trim()
      // 有的面板会把多条链接写在同一行；只有确实解析出两个以上带 scheme
      // 的片段时才拆行。否则 `#My Node` 这种带空格的名字会被截断成 `#My`。
      const parts = trimmed.split(/\s+/)
      if (parts.filter((part) => containsNodeScheme(part)).length > 1) {
        return parts.filter((part) => containsNodeScheme(part))
      }
      return [trimmed]
    })
    .filter((t) => t && !t.startsWith('#'))

  const nodes: ProxyNode[] = []
  let rejected = 0
  let status: SubscriptionUsage | undefined = headStatus
  for (const candidate of candidates) {
    // Not a node and not a failure: some panels lead with the quota.
    if (candidate.startsWith(STATUS_PREFIX)) {
      status = status ?? parseStatusLine(candidate)
      continue
    }
    const node = parseURI(candidate, sourceID)
    if (node) nodes.push(node)
    else rejected += 1
  }
  return finish(nodes, rejected, mergeUsage(declaredStatus, status))
}

function finish(
  rawNodes: ProxyNode[],
  rejected: number,
  status?: SubscriptionUsage,
): ParsedContent {
  const marked = deduplicated(rawNodes.map(markingSubscriptionMetadata))
  const notices = marked.filter((n) => n.isSubscriptionMetadata).map((n) => n.name)
  const noticeStatus = notices.map(parseStatusLine).find((s) => s)
  return {
    nodes: marked,
    rejectedLineCount: rejected,
    notices,
    status: mergeUsage(noticeStatus, status),
  }
}

function markingSubscriptionMetadata(node: ProxyNode): ProxyNode {
  if (isNoticeNode(node)) return { ...node, isSubscriptionMetadata: true }
  return node
}

/** Same endpoint + same protocol credentials = the same node. */
function deduplicated(nodes: ProxyNode[]): ProxyNode[] {
  const seen = new Set<string>()
  const out: ProxyNode[] = []
  for (const node of nodes) {
    const key = [
      node.kind,
      node.server.toLowerCase(),
      node.port,
      node.cipher ?? '',
      node.password ?? '',
      node.uuid ?? '',
      node.username ?? '',
      node.transport ?? '',
      node.sni ?? '',
      node.path ?? '',
      node.hostHeader ?? '',
      node.protocolName ?? '',
      node.obfs ?? '',
      node.wireGuardPrivateKey ?? '',
      node.wireGuardPublicKey ?? '',
      node.wireGuardIPv4 ?? '',
      node.wireGuardIPv6 ?? '',
      node.masque?.privateKey ?? '',
      node.masque?.publicKey ?? '',
      node.ssh?.privateKey ?? '',
    ].join('|')
    if (seen.has(key)) continue
    seen.add(key)
    out.push(node)
  }
  return out
}

// Re-export for views that show region badges.
export { regionForNode }
