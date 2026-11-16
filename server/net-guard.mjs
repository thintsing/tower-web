// 订阅 / 规则集抓取的地址安全判断：拦截链路本地、云元数据、组播与保留地址。
// `/api/ruleset` 与 `/api/fetch` 是免密钥端点（客户端要直接拉取），共用同一套判断；
// 局域网 NAS 等私网地址仍然允许。
import { isIP } from 'node:net'

export const BLOCKED_TARGET_MESSAGE = '地址不能指向链路本地、云元数据、组播或保留地址'
const BLOCKED_HOSTS = new Set([
  '169.254.169.254',
  '100.100.100.200',
  'fd00:ec2::254',
  'metadata',
  'metadata.google.internal',
  'metadata.tencentyun.com',
])

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

/**
 * 解析结果也要校验：只按域名挡，A 记录指向 169.254.169.254 的域名仍能绕过。
 * 私网（10/8、172.16/12、192.168/16）与回环地址按原有设计放行，
 * 只拦截链路本地、云元数据、组播和保留地址。
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
