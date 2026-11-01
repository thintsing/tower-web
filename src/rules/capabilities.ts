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

export type EffectiveGroupType = 'select' | 'url-test' | 'smart' | 'fallback' | 'load-balance' | 'relay'

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
    case 'unsupported':
      return 'select'
  }
}
