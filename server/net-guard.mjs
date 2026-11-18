// 订阅 / 规则集抓取的地址安全判断：拦截链路本地、云元数据、组播与保留地址。
// `/api/ruleset` / `/api/fetch` / `/api/probe` 是免密钥端点（客户端要直接拉取），
// 共用同一套判断；但这些端点在被局域网调用时默认不再放行私网 / 回环，
// 防止未授权的横向探测。本机请求和显式开启 allowPrivateNetworkFetch 仍可访问。
import { isIP } from 'node:net'

export const BLOCKED_TARGET_MESSAGE = '地址不能指向链路本地、云元数据、组播或保留地址'
export const PRIVATE_BLOCKED_MESSAGE = '地址指向私网 / 回环；局域网请求默认不允许'
const BLOCKED_HOSTS = new Set([
  '169.254.169.254',
  '100.100.100.200',
  'fd00:ec2::254',
  'metadata',
  'metadata.google.internal',
  'metadata.tencentyun.com',
])

/**
 * 判断是否属于「SSRF 高危」地址：链路本地、云元数据、组播、保留网段。
 * 这些无论本机还是局域网请求都绝对拦截。
 */
export function isBlockedRuleSetTarget(target) {
  const host = target.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  return BLOCKED_HOSTS.has(host)
    || blockedRuleSetAddress(host)
    || host.endsWith('.metadata.google.internal')
}

/** 初始地址和每一跳跳转都走这里：命中直接抛错，调用方负责带上第几跳。 */
export function assertAllowedTarget(target) {
  if (isBlockedRuleSetTarget(target)) throw new Error(BLOCKED_TARGET_MESSAGE)
}

/**
 * 私网 / 回环 / Tailscale 100.64.0.0/10 / ULA / 唯一本地地址：
 * 这些是内网地址，默认对非本机请求拦截，对本机或显式放行的请求开放。
 */
export function isPrivateAddress(address) {
  const ip = String(address).trim().toLowerCase()
  const v4 = isIP(ip) === 4 ? ip : embeddedIPv4(ip)
  if (v4) {
    const first = Number(v4.split('.')[0])
    if (first === 10) return true                           // 10.0.0.0/8
    if (first === 127) return true                          // 127.0.0.0/8 回环
    if (first === 0) return true                            // 0.0.0.0/8 本网络
    const second = Number(v4.split('.')[1])
    if (first === 172 && second >= 16 && second <= 31) return true  // 172.16.0.0/12
    if (first === 192 && second === 168) return true         // 192.168.0.0/16
    if (first === 100 && second >= 64 && second <= 127) return true  // 100.64.0.0/10 (Tailscale + Carrier NAT)
    if (first === 169 && second !== 254) return true         // 169.254.0.0/16 里除了链路本地保留的部分
  }
  if (ip === '::1') return true                              // IPv6 回环
  if (ip === 'fc00:') return true                            // IPv6 ULA 前缀本身不会出现
  if (/^fc[0-9a-f]{2}:/.test(ip)) return true                // IPv6 ULA / 唯一本地地址
  if (/^fd[0-9a-f]{2}:/.test(ip)) return true                // IPv6 ULA / 唯一本地地址
  if (/^fe80:/.test(ip)) return true                         // IPv6 链路本地（也是私网）
  return false
}

/**
 * 判断 URL 目标是否最终指向私网 / 回环地址。只看 hostname 是否是 IP，
 * 域名先放行——DNS rebinding 的防护在上游（fetchWithDoH 的解析后校验）处理。
 */
export function targetRequiresPrivateNetwork(target) {
  const host = target.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  // hostname 是字面 IP（含 IPv6），且落在私网段。
  if (isIP(host)) return isPrivateAddress(host)
  // IPv4-mapped / NAT64 写法也按私网处理
  const embedded = embeddedIPv4(host)
  if (embedded) return isPrivateAddress(embedded)
  // 域名先放过；fetchWithDoH 里解析完再调 blockedRuleSetAddress + DNS rebinding 校验。
  return false
}

/**
 * 在入口层（路由）决定是否允许访问私网。
 * @param localRequest 当前请求是否来自本机（localhost / 回环）
 * @param allowPrivate 显式的配置开关（环境变量 / 持久设置）
 */
export function allowPrivateNetworkFor(localRequest, allowPrivate) {
  return localRequest || !!allowPrivate
}

/**
 * fetchWithDoH 里每一跳解析后也要校验：先过 SSRF 高危（blockedRuleSetAddress），
 * 再过私网策略（私网对非本机 / 未放行请求拦截）。
 * @param address DNS 解析结果
 * @param options.localRequest 本机请求标志
 * @param options.allowPrivate 显式放行标志
 */
export function assertResolvedAddressAllowed(address, { localRequest, allowPrivate }) {
  if (blockedRuleSetAddress(address)) throw new Error(BLOCKED_TARGET_MESSAGE)
  if (isPrivateAddress(address) && !allowPrivateNetworkFor(localRequest, allowPrivate)) {
    throw new Error(PRIVATE_BLOCKED_MESSAGE)
  }
}

/**
 * SSRF 高危网段的纯拦截判断（不含私网策略）。保留给订阅 / 规则集 / 代理
 * 入口层和每一跳守卫共用。
 */
export function blockedRuleSetAddress(address) {
  const ip = String(address).trim().toLowerCase()
  const v4 = isIP(ip) === 4 ? ip : embeddedIPv4(ip)
  if (v4) {
    const [first, second] = v4.split('.').map(Number)
    return (first === 169 && second === 254)   // 169.254.0.0/16 链路本地
      || v4 === '100.100.100.200'              // 阿里云元数据
      || first === 0                           // 0.0.0.0/8 本网络
      || first >= 224                          // 224.0.0.0/4 组播 + 240.0.0.0/4 保留（含广播）
  }
  return /^fe80:/.test(ip)                     // IPv6 链路本地
    || ip === '::'                             // IPv6 未指定地址
    || /^ff[0-9a-f]{2}:/.test(ip)              // IPv6 组播
    || /^fd00:ec2::/.test(ip)                  // AWS 元数据
}

/**
 * IPv4-mapped（::ffff:0:0/96）和 NAT64（64:ff9b::/96）都能携带任意 IPv4。
 * URL 会把点分形式规范化成十六进制（::ffff:a9fe:a9fe），只剥前缀再判 isIP
 * 会整条跳过 IPv4 分支，云元数据地址因此可达。这里统一还原成点分四段。
 */
function embeddedIPv4(ip) {
  const match = ip.match(/^(?:::ffff:|64:ff9b::)(.+)$/)
  if (!match) return undefined
  const tail = match[1]
  if (isIP(tail) === 4) return tail
  const hex = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/)
  if (!hex) return undefined
  const high = parseInt(hex[1], 16)
  const low = parseInt(hex[2], 16)
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`
}
