// Remote rule-set dialects and which export targets can reference them.
import type { ClientTarget, RoutingRule, RuleSetFormat, SchemeRuleSet, SubFormat } from '../models/types'

/** 每种订阅载体能直接引用的规则集方言。 */
export const REMOTE_RULE_SET_FORMATS: Record<SubFormat, RuleSetFormat[]> = {
  // 共享 YAML 面向 mihomo / Stash；Karing / Shadowrocket 发布时各有去掉 MRS 的变体。
  yaml: ['classical', 'yaml', 'mrs'],
  surge: ['classical'],
  loon: ['classical'],
  quanx: ['quanx'],
  json: ['singbox', 'singbox-binary'],
  egern: ['egern'],
  base64: [],
}

/** 读取 MRS provider 的 mihomo 系目标；Karing / Shadowrocket 不读 MRS。 */
const MRS_TARGETS: ClientTarget[] = [
  'clash', 'clash-apple', 'clash-verge', 'clashmac',
  'flclash', 'mihomo-party', 'clash-mi',
]

const CLASH_YAML_TARGETS: ClientTarget[] = [
  ...MRS_TARGETS, 'karing', 'shadowrocket',
]

/** URL 扩展名 → 方言；无法判断时按经典文本列表处理。 */
export function inferRuleSetFormat(url: string): RuleSetFormat {
  const path = url.split(/[?#]/)[0]?.toLowerCase() ?? ''
  if (path.endsWith('.mrs')) return 'mrs'
  if (path.endsWith('.srs')) return 'singbox-binary'
  if (path.endsWith('.json')) return 'singbox'
  if (path.endsWith('.yaml') || path.endsWith('.yml')) return 'yaml'
  return 'classical'
}

export function ruleSetFormatOfRule(rule: Pick<RoutingRule, 'value' | 'ruleSetFormat'>): RuleSetFormat | undefined {
  if (!rule.value) return undefined
  return rule.ruleSetFormat ?? inferRuleSetFormat(rule.value)
}

export function ruleSetFormatOfSet(set: SchemeRuleSet, url?: string): RuleSetFormat | undefined {
  if (!url) return undefined
  return set.format ?? inferRuleSetFormat(url)
}

export function subFormatSupportsRuleSetFormat(
  format: SubFormat,
  ruleSetFormat: RuleSetFormat | undefined,
): boolean {
  if (!ruleSetFormat) return false
  return REMOTE_RULE_SET_FORMATS[format].includes(ruleSetFormat)
}

/** 目标客户端专属限制（主要是 MRS 与 Shadowrocket / Karing）。 */
export function targetSupportsRuleSetFormat(
  target: ClientTarget | undefined,
  ruleSetFormat: RuleSetFormat | undefined,
): boolean {
  if (!ruleSetFormat) return false
  switch (ruleSetFormat) {
    case 'mrs':
      return !!target && MRS_TARGETS.includes(target)
    case 'classical':
      return !target || CLASH_YAML_TARGETS.includes(target)
        || ['surge', 'surge-mac', 'loon'].includes(target)
    case 'yaml':
      return !target || CLASH_YAML_TARGETS.includes(target)
    case 'quanx':
      return !target || target === 'quanx'
    case 'egern':
      return !target || target === 'egern'
    case 'singbox':
    case 'singbox-binary':
      return !target || target === 'sing-box' || target === 'hiddify'
  }
}

export function supportsRuleSetReference(
  rule: Pick<RoutingRule, 'value' | 'ruleSetFormat' | 'ruleSetBehavior'>,
  format: SubFormat,
  target?: ClientTarget,
): boolean {
  const ruleSetFormat = ruleSetFormatOfRule(rule)
  if (!ruleSetFormat) return false
  if (ruleSetFormat === 'mrs' && !['domain', 'ipcidr'].includes(rule.ruleSetBehavior ?? '')) {
    return false
  }
  return target
    ? targetSupportsRuleSetFormat(target, ruleSetFormat)
    : subFormatSupportsRuleSetFormat(format, ruleSetFormat)
}

const LOON_REMOTE_RULE_TYPES = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6',
  'GEOIP', 'IP-ASN', 'USER-AGENT', 'URL-REGEX',
])

const SURGE_REMOTE_RULE_TYPES = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-SET', 'DOMAIN-WILDCARD',
  'IP-CIDR', 'IP-CIDR6', 'IP6-CIDR', 'IP-ASN', 'GEOIP', 'PROCESS-NAME',
  'USER-AGENT', 'URL-REGEX', 'DEST-PORT', 'SRC-IP', 'SRC-PORT', 'IN-PORT',
  'PROTOCOL', 'SUBNET', 'AND', 'OR', 'NOT',
])

const SHADOWROCKET_REMOTE_RULE_TYPES = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
  'USER-AGENT', 'URL-REGEX', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP',
  'DST-PORT', 'DEST-PORT',
])

/** Karing 接受 Clash provider，但内核不是完整的 mihomo；逻辑规则不放进远程列表。 */
const KARING_REMOTE_RULE_TYPES = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6',
  'IP-ASN', 'GEOIP', 'GEOSITE', 'SRC-IP-CIDR', 'SRC-PORT', 'DST-PORT',
  'PROCESS-NAME', 'PROCESS-PATH', 'PROCESS-PATH-REGEX', 'NETWORK',
])

/**
 * 经典文本规则集引用前确认每一行都是该客户端远程列表认识的类型。
 * 不认识的类型继续内联，避免客户端拒绝整份远程列表。
 */
export function classicalRulesFitTarget(
  rules: RoutingRule[],
  target: ClientTarget | undefined,
  format: SubFormat,
): boolean {
  let allowed: Set<string> | undefined
  if (target === 'loon') allowed = LOON_REMOTE_RULE_TYPES
  else if (target === 'surge' || target === 'surge-mac') allowed = SURGE_REMOTE_RULE_TYPES
  else if (target === 'shadowrocket') allowed = SHADOWROCKET_REMOTE_RULE_TYPES
  else if (target === 'karing') allowed = KARING_REMOTE_RULE_TYPES
  else if (!target && format === 'loon') allowed = LOON_REMOTE_RULE_TYPES
  else if (!target && format === 'surge') allowed = SURGE_REMOTE_RULE_TYPES
  if (!allowed) return true
  return rules.every((rule) => rule.type === 'FINAL' || allowed!.has(rule.type.toUpperCase()))
}

const QUANX_CONVERTIBLE_TYPES = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
  'IP-CIDR', 'IP-CIDR6', 'IP6-CIDR', 'GEOIP', 'IP-ASN', 'USER-AGENT',
])

const EGERN_CONVERTIBLE_TYPES = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX',
  'DOMAIN-WILDCARD', 'IP-CIDR', 'IP-CIDR6', 'IP6-CIDR', 'GEOIP',
  'IP-ASN', 'URL-REGEX', 'USER-AGENT',
])

const SINGBOX_CONVERTIBLE_TYPES = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX',
  'IP-CIDR', 'IP-CIDR6', 'IP6-CIDR',
])

const CONVERTIBLE_IP_TYPES = new Set(['IP-CIDR', 'IP-CIDR6', 'IP6-CIDR'])
const EGERN_IP_TYPES = new Set([...CONVERTIBLE_IP_TYPES, 'GEOIP', 'IP-ASN'])

export type HostedRuleSetDialect =
  | 'quanx'
  | 'egern'
  | 'singbox'
  | 'srs'
  | 'mrs-domain'
  | 'mrs-ipcidr'

export function hostedDialectForFormat(format: SubFormat | undefined): HostedRuleSetDialect | undefined {
  if (format === 'quanx') return 'quanx'
  if (format === 'egern') return 'egern'
  if (format === 'json') return 'singbox'
  return undefined
}

export function ruleSetFormatForDialect(dialect: HostedRuleSetDialect): RuleSetFormat {
  switch (dialect) {
    case 'srs': return 'singbox-binary'
    case 'mrs-domain':
    case 'mrs-ipcidr': return 'mrs'
    default: return dialect
  }
}

function optionsOnlyNoResolve(rule: RoutingRule): boolean {
  return (rule.options ?? []).every((option) => option.toLowerCase() === 'no-resolve')
}

/**
 * 判断规则集能否无损改写成目标方言。
 * 与 server/ruleset-convert.mjs 保持同一套类型和参数限制；
 * 宁可内联，也不生成会丢规则的远程引用。
 */
export function ruleSetRulesFitDialect(rules: RoutingRule[], dialect: HostedRuleSetDialect): boolean {
  if (!rules.length) return false
  const allowed = dialect === 'quanx'
    ? QUANX_CONVERTIBLE_TYPES
    : dialect === 'egern'
      ? EGERN_CONVERTIBLE_TYPES
      : SINGBOX_CONVERTIBLE_TYPES
  let uniformNoResolve: boolean | undefined
  for (const rule of rules) {
    const type = rule.type.toUpperCase()
    if (!allowed.has(type) || !rule.value || rule.raw) return false
    if (type === 'DOMAIN-SUFFIX' && (rule.value.startsWith('.') || rule.value.startsWith('+.'))) {
      return false
    }
    if (dialect === 'quanx' && rule.value.includes(',')) return false
    const isIP = EGERN_IP_TYPES.has(type)
    const hasNoResolve = (rule.options ?? []).some((option) => option.toLowerCase() === 'no-resolve')
    if (rule.options?.length && (!isIP || !optionsOnlyNoResolve(rule))) return false
    if (!isIP && hasNoResolve) return false
    if (dialect === 'egern' && isIP) {
      const state = hasNoResolve || type === 'GEOIP'
      if (uniformNoResolve !== undefined && state !== uniformNoResolve) return false
      uniformNoResolve = state
    }
  }
  return true
}

/** 塔台服务托管的转换产物；浏览器里用当前站点绝对地址。 */
export function hostedRuleSetURL(
  set: SchemeRuleSet,
  dialect: HostedRuleSetDialect,
): string | undefined {
  if (!set.sourceRef) return undefined
  const params = new URLSearchParams()
  if (dialect === 'mrs-domain' || dialect === 'mrs-ipcidr') {
    params.set('format', 'mrs')
    params.set('behavior', dialect === 'mrs-domain' ? 'domain' : 'ipcidr')
  } else if (dialect === 'srs') {
    params.set('format', 'srs')
  } else {
    params.set('format', dialect)
  }
  if (set.sourceKind === 'library') {
    if (!/^[A-Za-z0-9_.-]+\.list$/.test(set.sourceRef) || set.sourceRef.includes('..')) {
      return undefined
    }
    params.set('file', set.sourceRef)
  } else if (set.sourceKind === 'url') {
    if (!/^https?:\/\//i.test(set.sourceRef)) return undefined
    params.set('url', set.sourceRef)
  } else {
    return undefined
  }
  const origin = typeof location !== 'undefined' && location.origin ? location.origin : ''
  return `${origin}/api/ruleset?${params.toString()}`
}

/** 载体是否有可能引用至少一种原生规则集。 */
export function formatSupportsRemoteRuleSets(format: SubFormat): boolean {
  return REMOTE_RULE_SET_FORMATS[format].length > 0
}
