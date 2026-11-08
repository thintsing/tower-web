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
  | 'classic'
  | 'quanx'
  | 'egern'
  | 'singbox'
  | 'srs'
  | 'srs-domain'
  | 'mrs-domain'
  | 'mrs-ipcidr'

export function hostedDialectForFormat(format: SubFormat | undefined): HostedRuleSetDialect | undefined {
  // Surge / Loon 直接读经典文本列表，服务端会把 provider YAML 拍平成经典行。
  if (format === 'surge' || format === 'loon') return 'classic'
  if (format === 'quanx') return 'quanx'
  if (format === 'egern') return 'egern'
  if (format === 'json') return 'singbox'
  return undefined
}

export function ruleSetFormatForDialect(dialect: HostedRuleSetDialect): RuleSetFormat {
  switch (dialect) {
    case 'srs':
    case 'srs-domain': return 'singbox-binary'
    case 'mrs-domain':
    case 'mrs-ipcidr': return 'mrs'
    case 'classic': return 'classical'
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

/** 塔台服务托管的转换产物；baseURL 缺省时退回当前站点地址。 */
export function hostedRuleSetURL(
  set: SchemeRuleSet,
  dialect: HostedRuleSetDialect,
  baseURL?: string,
): string | undefined {
  if (!set.sourceRef) return undefined
  const params = new URLSearchParams()
  if (dialect === 'mrs-domain' || dialect === 'mrs-ipcidr') {
    params.set('format', 'mrs')
    params.set('behavior', dialect === 'mrs-domain' ? 'domain' : 'ipcidr')
  } else {
    params.set('format', dialect)
  }
  // provider 引用需要服务端先解开 YAML payload，再拍平 / 转换成目标方言。
  if (set.providerOnly) {
    params.set('provider', 'yaml')
    if (set.ruleSetBehavior) params.set('behavior', set.ruleSetBehavior)
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
  // baseURL 缺省时沿用旧行为：返回站点相对地址（浏览器里由 location.origin 补全；
  // 纯 Node 自检里就是 `/api/ruleset?...`）。显式空字符串才表示「没有对外地址」。
  const origin = baseURL !== undefined
    ? baseURL.replace(/\/+$/, '')
    : (typeof location !== 'undefined' && location.origin ? location.origin : '')
  if (baseURL !== undefined && !origin) return undefined
  return `${origin}/api/ruleset?${params.toString()}`
}

/** PROCESS-NAME 这类 classic provider 只有 Surge 的远程列表能直接读。 */
export function providerOnlyClassicalHostedSupported(target?: ClientTarget): boolean {
  return !target || target === 'surge' || target === 'surge-mac'
}

/**
 * provider-only 规则集能否在当前载体上变成一条远程引用：
 * Clash 系直接引用原 YAML provider；其余载体交给塔台服务托管转换。
 * hostedBaseURL === '' 表示调用方明确判定「没有对外地址」，此时不允许托管引用。
 */
export function providerOnlyCanReference(
  set: SchemeRuleSet,
  format: SubFormat | undefined,
  target: ClientTarget | undefined,
  hostedBaseURL: string | undefined,
): 'native' | 'hosted' | undefined {
  if (!set.ruleSetBehavior) return undefined
  if (format === 'yaml' && (!target || targetSupportsRuleSetFormat(target, 'yaml'))) {
    // Shadowrocket 的 Clash YAML 变体按经典文本口径判断规则类型（见
    // classicalRulesFitTarget），不读 classic provider 的 PROCESS-NAME 等条目；
    // 这里对 classic 引用保持同样的口径，避免同一个列表在两条导出路径上结论相反。
    // 被跳过的列表会在兼容性提示里点名，不会静默丢弃。
    if (set.ruleSetBehavior === 'classical' && target === 'shadowrocket') return undefined
    return 'native'
  }
  const dialect = hostedDialectForFormat(format)
  if (!dialect) return undefined
  if (set.ruleSetBehavior === 'classical') {
    // classic 列表按原样拍平；QuanX / Egern / sing-box 的规则集都不认识 PROCESS-NAME。
    if (dialect !== 'classic') return undefined
    if (!providerOnlyClassicalHostedSupported(target)) return undefined
  }
  if (hostedBaseURL === '') return undefined
  return 'hosted'
}

/**
 * 托管转换对对外地址的要求：托管规则集由手机或其他设备直接拉取，地址必须可达。
 * - 只有 provider-only 方案需要托管地址，其余方案返回 undefined（不参与判断）；
 * - `/api/network` 能响应就说明伴生服务（本地模式）或服务器服务存活，
 *   `/api/ruleset` 在同一服务上；serverMode 只表示是否启用服务端工作区，不能当作判据；
 * - 优先级：TOWER_PUBLIC_URL → 非回环的当前地址 → 本机打开时用局域网地址 → 置空。
 */
export function resolveHostedBaseURL(input: {
  providerOnly: boolean
  net: { publicUrl?: string; lan?: readonly string[] } | null
  loopback: boolean
  origin: string
}): string | undefined {
  if (!input.providerOnly) return undefined
  // 拿不到 /api/network 说明根本没有可用的服务端端点，给出地址也是假的。
  if (!input.net) return ''
  const trim = (value: string) => value.replace(/\/+$/, '')
  if (input.net.publicUrl) return trim(input.net.publicUrl)
  if (!input.loopback && input.origin) return trim(input.origin)
  // 本机打开时手机只能用局域网地址；`/api/network` 已过滤回环，取第一个即可。
  const lan = input.net.lan?.[0]
  return lan ? trim(lan) : ''
}

/** 载体是否有可能引用至少一种原生规则集。 */
export function formatSupportsRemoteRuleSets(format: SubFormat): boolean {
  return REMOTE_RULE_SET_FORMATS[format].length > 0
}
