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
  'DEST-PORT', 'PROTOCOL',
  ...logical, 'RULE-SET', 'FINAL', 'MATCH',
])

const shadowrocket = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
  'USER-AGENT', 'URL-REGEX', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN',
  'GEOIP', 'DST-PORT', 'PROTOCOL',
  ...logical, 'RULE-SET', 'FINAL', 'MATCH',
])

const quanx = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
  'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'IP-ASN', 'USER-AGENT',
  'RULE-SET', 'FINAL', 'MATCH',
])

const singbox = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX', 'DOMAIN-WILDCARD',
  'IP-CIDR', 'IP-CIDR6', 'SRC-IP', 'SRC-IP-CIDR', 'DST-PORT', 'DEST-PORT', 'SRC-PORT',
  'NETWORK', 'PROTOCOL', 'GEOIP',
  ...logical, 'RULE-SET', 'FINAL', 'MATCH',
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

// ---------- 客户端方言归一化 ----------
// 同一语义在不同客户端拼写不同：Surge / Loon 用 PROTOCOL，mihomo 用 NETWORK；
// Loon 用 DEST-PORT，Shadowrocket 用 DST-PORT。规则进入生成器前先归一化，
// 避免把目标客户端不认识的 TYPE 原样写进配置（见原版 RoutingRuleSyntax.convert）。

export interface RuleCondition {
  type: string
  value: string
  options: string[]
  children?: RuleCondition[]
}

type RuleLike = Pick<RoutingRule, 'type' | 'value' | 'options' | 'raw'>

const LOON_PROTOCOLS = new Set(['HTTP', 'HTTPS', 'TCP', 'QUIC', 'STUN', 'UDP'])

function splitTopLevel(text: string): string[] {
  const parts: string[] = []
  let depth = 0
  let start = 0
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]
    if (char === '(') depth += 1
    else if (char === ')') depth -= 1
    else if (char === ',' && depth === 0) {
      parts.push(text.slice(start, index))
      start = index + 1
    }
  }
  parts.push(text.slice(start))
  return parts
}

function closingParen(text: string, open: number): number {
  let depth = 0
  for (let index = open; index < text.length; index += 1) {
    if (text[index] === '(') depth += 1
    else if (text[index] === ')') {
      depth -= 1
      if (depth === 0) return index
    }
  }
  return -1
}

/** 解析 AND / OR / NOT 的原始行；无法结构化时返回 undefined。 */
export function parseRuleCondition(text: string): RuleCondition | undefined {
  const line = text.trim()
  const comma = line.indexOf(',')
  if (comma < 0) return undefined
  const type = line.slice(0, comma).trim().toUpperCase()
  const rest = line.slice(comma + 1).trim()
  if (type === 'AND' || type === 'OR' || type === 'NOT') {
    if (!rest.startsWith('(')) return undefined
    const close = closingParen(rest, 0)
    if (close < 0) return undefined
    const inner = rest.slice(1, close)
    const tail = rest.slice(close + 1).trim()
    const children = splitTopLevel(inner).map((part) => {
      const trimmed = part.trim()
      if (!trimmed.startsWith('(') || !trimmed.endsWith(')')) return undefined
      return parseRuleCondition(trimmed.slice(1, -1))
    })
    if (children.some((child) => !child)) return undefined
    if (type === 'NOT' && children.length !== 1) return undefined
    return {
      type,
      value: '',
      options: tail ? tail.split(',').map((item) => item.trim()).filter(Boolean) : [],
      children: children as RuleCondition[],
    }
  }
  const fields = splitTopLevel(rest)
  return {
    type,
    value: (fields[0] ?? '').trim(),
    options: fields.slice(1).map((item) => item.trim()).filter(Boolean),
  }
}

export function renderRuleCondition(condition: RuleCondition): string {
  if (condition.children) {
    const body = condition.children
      .map((child) => `(${renderRuleCondition(child)})`)
      .join(',')
    const tail = condition.options.length ? `,${condition.options.join(',')}` : ''
    return `${condition.type},(${body})${tail}`
  }
  const tail = condition.options.length ? `,${condition.options.join(',')}` : ''
  return `${condition.type},${condition.value}${tail}`
}

function normalizeCondition(
  condition: RuleCondition,
  target: ClientTarget,
  depth: number,
  mihomoTarget: boolean,
): RuleCondition | undefined {
  if (condition.children) {
    const children = condition.children.map((child) =>
      normalizeCondition(child, target, depth + 1, mihomoTarget))
    if (children.some((child) => !child)) return undefined
    return { ...condition, children: children as RuleCondition[] }
  }
  let type = condition.type.toUpperCase()
  let value = condition.value
  const upperValue = value.toUpperCase()
  if (type === 'IP6-CIDR') type = 'IP-CIDR6'
  if (mihomoTarget) {
    if (type === 'DEST-PORT') type = 'DST-PORT'
    else if (type === 'SRC-IP') type = 'SRC-IP-CIDR'
    else if (type === 'PROTOCOL') {
      if (!['TCP', 'UDP'].includes(upperValue)) return undefined
      type = 'NETWORK'
      value = upperValue
    }
  } else if (target === 'clash') {
    if (type === 'DEST-PORT') type = 'DST-PORT'
  } else if (target === 'surge' || target === 'surge-mac') {
    if (type === 'DST-PORT') type = 'DEST-PORT'
    else if (type === 'NETWORK') {
      if (!['TCP', 'UDP'].includes(upperValue)) return undefined
      type = 'PROTOCOL'
      value = upperValue
    }
  } else if (target === 'loon') {
    if (type === 'DST-PORT') type = 'DEST-PORT'
    else if (type === 'NETWORK' || type === 'PROTOCOL') {
      if (!LOON_PROTOCOLS.has(upperValue)) return undefined
      type = 'PROTOCOL'
      value = upperValue
    }
  } else if (target === 'shadowrocket') {
    if (type === 'DEST-PORT') type = 'DST-PORT'
    else if (type === 'NETWORK' || type === 'PROTOCOL') {
      // Shadowrocket 只在逻辑规则里接受 PROTOCOL，且只认 TCP / UDP。
      if (depth < 1 || !['TCP', 'UDP'].includes(upperValue)) return undefined
      type = 'PROTOCOL'
      value = upperValue
    }
  }
  if (!targetSupportsRule(target, type)) return undefined
  return { ...condition, type, value }
}

/**
 * 把一条规则转换成目标客户端原生拼写；无法无损表达时返回 undefined。
 * 逻辑规则的子条件会递归转换，任一子条件不支持时整条丢弃（避免语义被改）。
 */
export function normalizeRuleForTarget<T extends RuleLike>(rule: T, target?: ClientTarget): T | undefined {
  if (!target) return rule
  if (rule.raw || ['AND', 'OR', 'NOT'].includes(rule.type.toUpperCase())) {
    const parsed = parseRuleCondition(rule.raw ?? `${rule.type},${rule.value ?? ''}`)
    if (!parsed) return undefined
    const normalized = normalizeCondition(parsed, target, 0, MIHOMO_TARGETS.includes(target))
    if (!normalized || !targetSupportsRule(target, normalized.type)) return undefined
    return { ...rule, type: normalized.type, raw: renderRuleCondition(normalized) }
  }
  const normalized = normalizeCondition(
    {
      type: rule.type,
      value: rule.value ?? '',
      options: [...(rule.options ?? [])],
    },
    target,
    0,
    MIHOMO_TARGETS.includes(target),
  )
  if (!normalized) return undefined
  return { ...rule, type: normalized.type, value: normalized.value || undefined }
}

/** Drop rules the destination cannot express. FINAL is always kept. */
export function filterRulesForTarget<T extends RuleLike>(
  rules: T[],
  target?: ClientTarget,
): T[] {
  if (!target) return rules
  return rules.flatMap((rule) => {
    const normalized = normalizeRuleForTarget(rule, target)
    return normalized ? [normalized] : []
  })
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
