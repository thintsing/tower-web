// Which rules can be compiled into binary rule sets, and which must stay inline.
// Keep this in sync with server/ruleset-binary.mjs: a rule the server silently
// drops must never be marked as covered here, or the profile would lose it.
import type { RoutingRule } from '../models/types'

export const MRS_DOMAIN_TYPES = new Set(['DOMAIN', 'DOMAIN-SUFFIX'])
export const MRS_IP_TYPES = new Set(['IP-CIDR', 'IP-CIDR6', 'IP6-CIDR'])
/** DNS 规则只能判断查询名；domain-only SRS 只收这三类。 */
export const SRS_DOMAIN_TYPES = new Set(['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'])
export const SRS_TYPES = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX',
  'IP-CIDR', 'IP-CIDR6', 'IP6-CIDR',
])

export interface MRSBinaryPlan {
  domain: RoutingRule[]
  ipcidr: RoutingRule[]
  residual: RoutingRule[]
  /** ipcidr 引用需要 no-resolve；原列表未写时也补上，与 mihomo 生态一致。 */
  ipNoResolve: boolean
}

export interface SRSBinaryPlan {
  covered: RoutingRule[]
  residual: RoutingRule[]
}

function plainValue(value: string | undefined): value is string {
  return !!value && !/\s/.test(value)
}

function optionsOnlyNoResolve(rule: RoutingRule): boolean {
  return (rule.options ?? []).every((option) => option.toLowerCase() === 'no-resolve')
}

function normalizedDomain(value: string | undefined): string | undefined {
  const domain = (value ?? '').trim().toLowerCase()
  if (!domain || domain.length > 253 || domain.startsWith('.') || domain.includes('*')) return undefined
  const labels = domain.split('.')
  if (!labels.every((label) => /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/i.test(label))) return undefined
  return domain
}

function validIPv4(value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function validIPv6(value: string): boolean {
  let text = value.toLowerCase()
  if (text.includes('.')) {
    const colon = text.lastIndexOf(':')
    if (colon < 0 || !validIPv4(text.slice(colon + 1))) return false
    text = `${text.slice(0, colon + 1)}0:0`
  }
  const halves = text.split('::')
  if (halves.length > 2) return false
  const left = halves[0] ? halves[0].split(':') : []
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const groups = halves.length === 2
    ? [...left, ...right]
    : left
  if (halves.length === 1 && groups.length !== 8) return false
  if (halves.length === 2 && groups.length >= 8) return false
  return groups.every((group) => /^[0-9a-f]{1,4}$/.test(group))
}

function validCIDR(value: string | undefined): boolean {
  if (!value) return false
  const slash = value.lastIndexOf('/')
  if (slash <= 0) return false
  const address = value.slice(0, slash)
  const prefixLength = Number(value.slice(slash + 1))
  const ipv4 = !address.includes(':')
  if (!Number.isInteger(prefixLength) || prefixLength < 0) return false
  if (ipv4) return prefixLength <= 32 && validIPv4(address)
  return prefixLength <= 128 && validIPv6(address)
}

/**
 * mihomo MRS 只能表达域名 trie 与 CIDR 集合。IP 规则如果混用带 / 不带
 * no-resolve，一条远程引用无法同时保留两种语义，整组退回逐条内联。
 */
export function mihomoBinaryPlan(rules: RoutingRule[]): MRSBinaryPlan | undefined {
  const domain: RoutingRule[] = []
  const ipcidr: RoutingRule[] = []
  const residual: RoutingRule[] = []
  let wroteNoResolve: boolean | undefined
  for (const rule of rules) {
    const type = rule.type.toUpperCase()
    if (MRS_DOMAIN_TYPES.has(type) && !rule.raw && plainValue(rule.value)
      && !(rule.options?.length) && normalizedDomain(rule.value)) {
      domain.push(rule)
      continue
    }
    if (MRS_IP_TYPES.has(type) && !rule.raw && plainValue(rule.value)
      && optionsOnlyNoResolve(rule) && validCIDR(rule.value)) {
      const noResolve = (rule.options ?? []).some((option) => option.toLowerCase() === 'no-resolve')
      if (wroteNoResolve !== undefined && wroteNoResolve !== noResolve) {
        return undefined
      }
      wroteNoResolve = noResolve
      ipcidr.push(rule)
      continue
    }
    residual.push(rule)
  }
  if (!domain.length && !ipcidr.length) return undefined
  return { domain, ipcidr, residual, ipNoResolve: true }
}

/** SRS 支持域名 / 关键字 / 正则 / CIDR；其余类型和带额外参数的规则保持内联。 */
export function singBoxBinaryPlan(rules: RoutingRule[]): SRSBinaryPlan | undefined {
  const covered: RoutingRule[] = []
  const residual: RoutingRule[] = []
  for (const rule of rules) {
    const type = rule.type.toUpperCase()
    if (!SRS_TYPES.has(type) || rule.raw || !rule.value) {
      residual.push(rule)
      continue
    }
    if (MRS_DOMAIN_TYPES.has(type)) {
      if (!plainValue(rule.value) || rule.options?.length || !normalizedDomain(rule.value)) {
        residual.push(rule)
      } else {
        covered.push(rule)
      }
      continue
    }
    if (type === 'DOMAIN-KEYWORD' || type === 'DOMAIN-REGEX') {
      if (rule.options?.length) residual.push(rule)
      else covered.push(rule)
      continue
    }
    if (!plainValue(rule.value) || !optionsOnlyNoResolve(rule) || !validCIDR(rule.value)) {
      residual.push(rule)
    } else {
      covered.push(rule)
    }
  }
  return covered.length ? { covered, residual } : undefined
}
