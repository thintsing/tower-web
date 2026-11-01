// Local rule sets can be written as a client-native inline rule set instead of
// hundreds of individual rules. Only plain TYPE,value lines are eligible; a
// single rule with an option or unsupported type flattens the whole set.
import type {
  ClientTarget,
  InlineRuleSetMeta,
  RoutingRule,
  SchemeRuleSet,
  SubFormat,
} from '../models/types'

const CIDR_TYPES = new Set(['IP-CIDR', 'IP-CIDR6'])
const INLINE_TYPES = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6',
])

const MIHOMO_TARGETS: ClientTarget[] = [
  'clash-apple', 'clash-verge', 'clashmac', 'flclash',
  'mihomo-party', 'clash-mi',
]

/** 支持目标客户端内联规则集的载体。 */
export function targetSupportsInlineRuleSets(
  format: SubFormat | undefined,
  target?: ClientTarget,
): boolean {
  if (format === 'surge') {
    return !target || target === 'surge' || target === 'surge-mac'
  }
  if (format !== 'yaml') return false
  if (!target) return true
  // Stash 3.6+ 和 mihomo 1.19.1+ 支持 type: inline；Karing / Shadowrocket 不支持。
  return target === 'clash' || MIHOMO_TARGETS.includes(target)
}

function noResolveWritten(rule: RoutingRule): boolean {
  return (rule.options ?? []).some((option) => option.toLowerCase() === 'no-resolve')
}

function plainValue(value: string | undefined): value is string {
  return !!value && !/[,\r\n"']/.test(value)
}

/**
 * 只接受可以原样写入规则集 section/provider 的本地规则。
 * 返回 undefined 时调用方继续逐条展开，保持原有语义。
 */
export function inlineRuleSetMetadata(
  set: SchemeRuleSet,
  format: SubFormat,
  target?: ClientTarget,
): InlineRuleSetMeta | undefined {
  if (set.sourceKind !== 'local' || !set.rules.length) return undefined
  if (!targetSupportsInlineRuleSets(format, target)) return undefined
  let hasDomain = false
  let hasKeyword = false
  let hasCIDR = false
  let ipNoResolve: boolean | undefined
  for (const rule of set.rules) {
    const type = rule.type.toUpperCase()
    if (!INLINE_TYPES.has(type) || !plainValue(rule.value) || rule.raw) return undefined
    const options = rule.options ?? []
    if (options.length && !CIDR_TYPES.has(type)) return undefined
    if (options.length && !options.every((option) => option.toLowerCase() === 'no-resolve')) {
      return undefined
    }
    if (CIDR_TYPES.has(type)) {
      hasCIDR = true
      const state = noResolveWritten(rule)
      if (ipNoResolve !== undefined && state !== ipNoResolve) return undefined
      ipNoResolve = state
    } else {
      if (options.length) return undefined
      hasDomain = true
      if (type === 'DOMAIN-KEYWORD') hasKeyword = true
    }
  }
  // 域名与 IP 混排时拆成多个规则集会改变源顺序；保守地继续逐条展开。
  if (hasDomain && hasCIDR) return undefined
  const behavior = hasCIDR
    ? 'ipcidr'
    : hasKeyword
      ? 'classical'
      : 'domain'
  return {
    id: set.id,
    name: set.name,
    behavior,
    noResolve: !!ipNoResolve,
  }
}

/** Clash inline provider payload 的约定格式。 */
export function clashInlinePayload(rule: RoutingRule, meta: InlineRuleSetMeta): string | undefined {
  if (!rule.value) return undefined
  if (meta.behavior === 'domain') {
    return rule.type.toUpperCase() === 'DOMAIN-SUFFIX' ? `+.${rule.value}` : rule.value
  }
  if (meta.behavior === 'ipcidr') return rule.value
  return `${rule.type.toUpperCase()},${rule.value}`
}

/** Surge `[Ruleset …]` section 同样只写 TYPE,value。 */
export function surgeInlinePayload(rule: RoutingRule): string | undefined {
  if (!rule.value) return undefined
  return `${rule.type.toUpperCase()},${rule.value}`
}

export function inlineSetReference(key: string, meta: InlineRuleSetMeta, group: string): string {
  return `RULE-SET,${key},${group}${meta.noResolve ? ',no-resolve' : ''}`
}
