// DNS / IPv6 / latency-test settings shared by the rule-scheme UI and
// every generator. Values are normalized here so a Surge key is never copied
// verbatim into Clash or sing-box output.
import type {
  RuleSchemeDNSProtectionMode,
  RuleSchemeNetworkSettings,
} from './types'

export const DEFAULT_TEST_URL = 'http://www.gstatic.com/generate_204'

export const DEFAULT_NETWORK_SETTINGS: RuleSchemeNetworkSettings = {
  ipv6Enabled: true,
  dnsServers: ['223.5.5.5', '119.29.29.29'],
  encryptedDNSServers: [
    'https://223.5.5.5/dns-query',
    'https://doh.pub/dns-query',
  ],
  remoteDNSServers: [
    'https://8.8.8.8/dns-query',
    'https://1.1.1.1/dns-query',
  ],
  proxyTestURLString: DEFAULT_TEST_URL,
  dnsProtectionMode: 'standard',
}

export interface NetworkSettingsDraft {
  ipv6Enabled?: boolean
  dnsServers: string[]
  encryptedDNSServers: string[]
  remoteDNSServers: string[]
  proxyTestURLString: string
  dnsProtectionMode: RuleSchemeDNSProtectionMode
}

export function networkSettingsDraft(
  settings?: RuleSchemeNetworkSettings,
): NetworkSettingsDraft {
  const defaults = DEFAULT_NETWORK_SETTINGS
  return {
    ipv6Enabled: settings?.ipv6Enabled,
    dnsServers: settings?.dnsServers.length ? [...settings.dnsServers] : [...defaults.dnsServers],
    encryptedDNSServers: settings?.encryptedDNSServers.length
      ? [...settings.encryptedDNSServers]
      : [...defaults.encryptedDNSServers],
    remoteDNSServers: settings?.remoteDNSServers.length
      ? [...settings.remoteDNSServers]
      : [...defaults.remoteDNSServers],
    proxyTestURLString: settings?.proxyTestURLString ?? defaults.proxyTestURLString ?? DEFAULT_TEST_URL,
    dnsProtectionMode: settings?.dnsProtectionMode ?? defaults.dnsProtectionMode,
  }
}

/** 生成器使用；空字段回退到默认值，避免把空数组写进客户端配置。 */
export function effectiveNetworkSettings(
  settings?: RuleSchemeNetworkSettings,
): RuleSchemeNetworkSettings {
  return networkSettingsDraft(settings)
}

export function latencyTestURL(
  settings?: RuleSchemeNetworkSettings,
  fallback = DEFAULT_TEST_URL,
): string {
  return settings?.proxyTestURLString?.trim() || fallback
}

function ipv4(value: string): boolean {
  return /^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/.test(value)
}

function ipv6(value: string): boolean {
  return /^[0-9a-fA-F:]+$/.test(value) && value.includes(':')
}

export function isPlainDNSServer(value: string): boolean {
  const trimmed = value.trim()
  return ipv4(trimmed) || ipv6(trimmed)
}

const ENCRYPTED_SCHEMES = new Set(['https', 'h3', 'tls', 'quic'])

export function isEncryptedDNSServer(value: string): boolean {
  try {
    const url = new URL(value.trim())
    return ENCRYPTED_SCHEMES.has(url.protocol.replace(':', '').toLowerCase()) && !!url.hostname
  } catch {
    return false
  }
}

/** 与 Tower iOS 一致：这些解析器会尊重 EDNS Client Subnet。 */
const CLIENT_SUBNET_HOSTS = new Set([
  'dns.google', '8.8.8.8', '8.8.4.4',
  'dns11.quad9.net', '9.9.9.11', '149.112.112.11',
])

export function supportsClientSubnet(value: string): boolean {
  try {
    const host = new URL(value.trim()).hostname.toLowerCase()
    return CLIENT_SUBNET_HOSTS.has(host)
  } catch {
    return false
  }
}

/** 任何中国地址都可；解析器只需要相信客户端在中国。 */
export const CHINA_CLIENT_SUBNET = '114.114.114.0/24'

export function isHTTPTestURL(value: string): boolean {
  try {
    const url = new URL(value.trim())
    return (url.protocol === 'http:' || url.protocol === 'https:') && !!url.hostname
  } catch {
    return false
  }
}

function normalized(values: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of values) {
    const value = raw.trim()
    if (!value || seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}

export class NetworkSettingsError extends Error {}

/** 保存前校验；普通 DNS 只接受 IPv4/IPv6 字面量，避免主机名回退到系统解析器。 */
export function validateNetworkSettingsDraft(draft: NetworkSettingsDraft): RuleSchemeNetworkSettings {
  const dnsServers = normalized(draft.dnsServers)
  if (!dnsServers.length) throw new NetworkSettingsError('至少保留一个普通 DNS')
  for (const value of dnsServers) {
    if (!isPlainDNSServer(value)) {
      throw new NetworkSettingsError(`普通 DNS 必须是 IPv4 或 IPv6 地址：${value}`)
    }
  }

  const encryptedDNSServers = normalized(draft.encryptedDNSServers)
  if (!encryptedDNSServers.length) throw new NetworkSettingsError('至少保留一个国内 DNS')
  for (const value of encryptedDNSServers) {
    if (!isEncryptedDNSServer(value)) {
      throw new NetworkSettingsError(`国内 DNS 需要 https / h3 / tls / quic 地址：${value}`)
    }
  }

  const remoteDNSServers = normalized(draft.remoteDNSServers)
  if (!remoteDNSServers.length) throw new NetworkSettingsError('至少保留一个远程 DNS')
  for (const value of remoteDNSServers) {
    if (!isEncryptedDNSServer(value)) {
      throw new NetworkSettingsError(`远程 DNS 需要 https / h3 / tls / quic 地址：${value}`)
    }
  }

  const testURL = draft.proxyTestURLString.trim()
  if (!testURL || !isHTTPTestURL(testURL)) {
    throw new NetworkSettingsError('延迟测试地址需要有效的 http(s) 地址')
  }

  return {
    ipv6Enabled: draft.ipv6Enabled,
    dnsServers,
    encryptedDNSServers,
    remoteDNSServers,
    proxyTestURLString: testURL,
    dnsProtectionMode: draft.dnsProtectionMode,
  }
}

export const DNS_MODE_TITLES: Record<RuleSchemeDNSProtectionMode, string> = {
  'follow-scheme': '跟随方案',
  standard: '标准保护',
  strict: '严格保护',
}

export const DNS_MODE_SUMMARIES: Record<RuleSchemeDNSProtectionMode, string> = {
  'follow-scheme': '不强制接管 DNS，由客户端按原方案解析；域名可能在本机先解析。',
  standard: '使用 fake-ip；直连域名走国内加密 DNS，其余域名经纯节点组用远程 DNS 带中国子网（ECS）解析，减少海外 CDN 结果。',
  strict: '普通 DNS 也走代理；支持的 Clash 客户端会启用 TUN 与 strict-route；有纯节点组时直连域名也经带中国子网的远程 DNS。可能影响局域网、公共网络认证和使用域名的代理节点。',
}

export interface EncryptedDNSEntry {
  type: 'https' | 'h3' | 'tls' | 'quic'
  server: string
  port?: number
  /** https / h3 的请求路径；tls / quic 没有。 */
  path?: string
  /** 证书校验使用的名称；8.8.8.8 这类地址需要映射到 dns.google。 */
  serverName: string
  /** host 是普通 IP，不需要额外解析器。 */
  isLiteral: boolean
  url: string
}

const RESOLVER_SERVER_NAMES: Record<string, string> = {
  '8.8.8.8': 'dns.google',
  '8.8.4.4': 'dns.google',
}

/** sing-box / mihomo 用的加密 DNS URL → 结构化条目。 */
export function encryptDNServer(value: string): EncryptedDNSEntry | undefined {
  if (!isEncryptedDNSServer(value)) return undefined
  try {
    const url = new URL(value.trim())
    const type = url.protocol.replace(':', '').toLowerCase() as EncryptedDNSEntry['type']
    const host = url.hostname
    return {
      type,
      server: host,
      port: url.port ? Number(url.port) : undefined,
      path: type === 'https' || type === 'h3'
        ? (url.pathname || '/dns-query') + (url.search || '')
        : undefined,
      serverName: RESOLVER_SERVER_NAMES[host.toLowerCase()] ?? host,
      isLiteral: isPlainDNSServer(host),
      url: value.trim(),
    }
  } catch {
    return undefined
  }
}
