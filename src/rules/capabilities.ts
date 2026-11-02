// Per-client rule capability sets, mirrored from Tower iOS
// RoutingRuleCapabilities. The generators use these sets to drop rules a
// client cannot express instead of handing it a profile that fails to load.
import type { ClientTarget, PolicyGroupType, RoutingRule } from '../models/types'

const common = [
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
  'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP', 'PROCESS-NAME',
  'SRC-PORT', 'IN-PORT',
]

const logical = ['AND', 'OR', 'NOT']

const mihomo = new Set([
  ...common,
  ...logical,
  'DOMAIN-REGEX', 'GEOSITE', 'IP-SUFFIX', 'SRC-GEOIP', 'SRC-IP-ASN',
  'SRC-IP-CIDR', 'SRC-IP-SUFFIX', 'DST-PORT', 'NETWORK', 'IN-TYPE',
  'IN-USER', 'IN-NAME', 'REMATCH-NAME', 'PROCESS-PATH',
  'PROCESS-PATH-WILDCARD', 'PROCESS-PATH-REGEX', 'PROCESS-NAME-WILDCARD',
  'PROCESS-NAME-REGEX', 'DSCP', 'RULE-SET', 'FINAL', 'MATCH',
])

// Stash 的规则白名单（stash.wiki/en/rules/rule-types）。
const stash = new Set([
  ...logical,
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
  'DOMAIN-REGEX', 'GEOSITE', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP',
  'DST-PORT', 'NETWORK', 'PROTOCOL', 'PROCESS-NAME', 'PROCESS-PATH',
  'USER-AGENT', 'URL-REGEX', 'SRC-IP', 'RULE-SET', 'FINAL', 'MATCH',
])

const surge = new Set([
  ...common,
  ...logical,
  'DOMAIN-SET', 'RULE-SET', 'DEST-PORT', 'SRC-IP', 'PROTOCOL',
  'USER-AGENT', 'URL-REGEX', 'SUBNET', 'DEVICE-NAME', 'MAC-ADDRESS',
  'HOSTNAME-TYPE', 'CELLULAR-RADIO', 'CELLULAR-CARRIER',
  'FINAL', 'MATCH',
])

const loon = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6',
  'GEOIP', 'IP-ASN', 'URL-REGEX', 'USER-AGENT', 'SRC-PORT',
  'DEST-PORT', 'DST-PORT', 'PROTOCOL', 'NETWORK',
  ...logical, 'RULE-SET', 'FINAL', 'MATCH',
])

const shadowrocket = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
  'USER-AGENT', 'URL-REGEX', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN',
  'GEOIP', 'DST-PORT', 'DEST-PORT', 'PROTOCOL',
  ...logical, 'RULE-SET', 'FINAL', 'MATCH',
])

const quanx = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6',
  'GEOIP', 'USER-AGENT', 'RULE-SET', 'FINAL', 'MATCH',
])

const singbox = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX',
  'IP-CIDR', 'IP-CIDR6', 'RULE-SET', 'FINAL', 'MATCH',
])

const egern = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX',
  'DOMAIN-WILDCARD', 'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'IP-ASN',
  'URL-REGEX', 'USER-AGENT', 'DEST-PORT', 'DST-PORT',
  'PROTOCOL', 'NETWORK', 'RULE-SET', 'FINAL', 'MATCH',
])

const MIHOMO_TARGETS: ClientTarget[] = [
  'clash-apple', 'clash-verge', 'clashmac', 'flclash',
  'mihomo-party', 'clash-mi', 'karing',
]

function ruleSetFor(target?: ClientTarget): Set<string> | undefined {
  if (!target) return undefined
  if (MIHOMO_TARGETS.includes(target)) return mihomo
  switch (target) {
    case 'clash': return stash
    case 'surge':
    case 'surge-mac': return surge
    case 'loon': return loon
    case 'quanx': return quanx
    case 'shadowrocket': return shadowrocket
    case 'sing-box':
    case 'hiddify': return singbox
    case 'egern': return egern
    default: return undefined
  }
}

/** True when the client can express this rule type in a full config. */
export function targetSupportsRule(target: ClientTarget | undefined, type: string): boolean {
  const set = ruleSetFor(target)
  return set ? set.has(type.toUpperCase()) : true
}

/** Drop rules the destination cannot express. FINAL is always kept. */
export function filterRulesForTarget<T extends Pick<RoutingRule, 'type'>>(
  rules: T[],
  target: ClientTarget | undefined,
): T[] {
  const set = ruleSetFor(target)
  return set ? rules.filter((rule) => set.has(rule.type.toUpperCase())) : rules
}

export const RULE_TYPE_CAPABILITIES = {
  common: new Set(common),
  logical: new Set(logical),
  mihomo,
  stash,
  surge,
  loon,
  shadowrocket,
  quanx,
  singbox,
  egern,
}

/** 解析规则时会接受的类型并集；未知类型仍然丢弃，避免误识别节点行。 */
export const ALL_RULE_TYPES = new Set([
  ...mihomo, ...stash, ...surge, ...loon, ...shadowrocket,
  ...quanx, ...singbox, ...egern, 'FINAL', 'MATCH',
])

export type EffectiveGroupType = 'select' | 'url-test' | 'smart' | 'fallback' | 'load-balance' | 'relay' | 'conditional'

type GroupParameters = Record<string, string> | undefined

function stringArray(value: string | undefined): string[] | undefined {
  if (!value) return undefined
  try {
    const parsed = JSON.parse(value)
    return Array.isArray(parsed) && parsed.every((item) => typeof item === 'string')
      ? parsed
      : undefined
  } catch {
    return undefined
  }
}

/** Surge conditional group (`subnet`) 的设备字段；必须含 default=。 */
export function surgeConditionalFields(parameters: GroupParameters): string[] | undefined {
  const fields = stringArray(parameters?.['subnet-fields'])
  if (!fields?.length) return undefined
  if (!fields.some((field) => field.trim().startsWith('default='))) return undefined
  return fields.every((field) => field.includes('=') && !/[\r\n]/.test(field))
    ? fields
    : undefined
}

export interface EgernConditional {
  rules: string
  fallback: string
}

/** Egern conditional rules 的受限结构：ssid / bssid / cellular → match + policy。 */
export function egernConditional(parameters: GroupParameters): EgernConditional | undefined {
  const fallback = parameters?.default_policy?.trim()
  if (!fallback) return undefined
  if (!parameters?.rules) return undefined
  try {
    const rules = JSON.parse(parameters.rules)
    if (!Array.isArray(rules) || !rules.length) return undefined
    const valid = rules.every((rule) => {
      if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return false
      const entries = Object.entries(rule)
      if (entries.length !== 1) return false
      const [kind, value] = entries[0]
      if (!['ssid', 'bssid', 'cellular'].includes(kind)) return false
      if (!value || typeof value !== 'object' || Array.isArray(value)) return false
      const pairs = Object.entries(value as Record<string, unknown>)
      return pairs.length === 2
        && pairs.every(([key, item]) => ['match', 'policy'].includes(key) && typeof item === 'string')
    })
    return valid
      ? { rules: JSON.stringify(rules), fallback }
      : undefined
  } catch {
    return undefined
  }
}

export interface NativeGroupOption {
  key: string
  value: string
}

/** 条件组降级为普通选择组时使用的默认策略。 */
export function conditionalDefaultPolicy(parameters: GroupParameters): string | undefined {
  const fallback = parameters?.default_policy?.trim()
  if (fallback) return fallback
  const subnet = stringArray(parameters?.['subnet-fields'])
  for (const field of subnet ?? []) {
    const equal = field.indexOf('=')
    if (equal >= 0 && field.slice(0, equal).trim() === 'default') {
      const value = field.slice(equal + 1).trim()
      if (value) return value
    }
  }
  return stringArray(parameters?.['ssid-members'])?.[0]?.trim() || undefined
}

/** 只透传同一种方言的标量参数，单位与语义不跨客户端猜测。 */
export function nativeGroupOptions(
  parameters: GroupParameters,
  target: ClientTarget | undefined,
): NativeGroupOption[] {
  if (!parameters) return []
  const allowed = target === 'surge' || target === 'surge-mac'
    ? new Set(['timeout', 'evaluate-before-use', 'no-alert'])
    : target === 'egern'
      ? new Set(['timeout', 'flatten', 'block_quic'])
      : target === 'loon'
        ? new Set(['max-timeout'])
        : target === 'quanx'
          ? new Set(['alive-checking'])
          : new Set<string>()
  const booleanKeys = new Set(['evaluate-before-use', 'no-alert', 'flatten', 'block_quic', 'alive-checking'])
  return Object.entries(parameters)
    .filter(([key, value]) => {
      if (!allowed.has(key)) return false
      if (booleanKeys.has(key)) return ['true', 'false'].includes(value)
      if (key === 'timeout' || key === 'max-timeout') return /^\d+$/.test(value)
      return false
    })
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => ({ key, value }))
}

const FALLBACK_TARGETS: ClientTarget[] = [
  'surge', 'surge-mac', 'quanx', 'clash', 'clash-mi', 'clash-apple',
  'clash-verge', 'clashmac', 'flclash', 'mihomo-party', 'loon',
  'egern', 'shadowrocket',
]

const LOAD_BALANCE_TARGETS: ClientTarget[] = [
  'surge', 'surge-mac', 'quanx', 'clash', 'clash-mi', 'clash-apple',
  'clash-verge', 'clashmac', 'flclash', 'mihomo-party', 'loon', 'egern',
]

const RELAY_TARGETS: ClientTarget[] = [
  'clash-apple', 'clash-verge', 'clashmac', 'flclash', 'mihomo-party',
]

/**
 * 把导入方案里的策略组类型降级到目标客户端最接近的原生类型。
 * smart / relay / conditional 只在部分客户端保留。
 */
export function effectiveGroupType(
  type: PolicyGroupType,
  target?: ClientTarget,
  parameters?: Record<string, string>,
): EffectiveGroupType {
  switch (type) {
    case 'select':
    case 'url-test':
      return type
    case 'fallback':
      return !target || FALLBACK_TARGETS.includes(target) ? 'fallback' : 'url-test'
    case 'load-balance':
      return !target || LOAD_BALANCE_TARGETS.includes(target) ? 'load-balance' : 'url-test'
    case 'smart':
      return target === 'surge' || target === 'surge-mac' || target === 'egern'
        ? 'smart'
        : 'url-test'
    case 'relay':
      // 只有少数 mihomo 客户端原生支持 relay；共享 YAML 载体保持保守。
      return target && RELAY_TARGETS.includes(target) ? 'relay' : 'select'
    case 'conditional':
      if ((target === 'surge' || target === 'surge-mac') && surgeConditionalFields(parameters)) {
        return 'conditional'
      }
      if (target === 'egern' && egernConditional(parameters)) return 'conditional'
      return 'select'
    case 'unsupported':
      return 'select'
  }
}
