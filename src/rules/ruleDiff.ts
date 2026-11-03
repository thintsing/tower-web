// 规则集版本 diff：先规范化、稳定排序，再按身份对比，避免顺序变化制造噪音。
import type { RoutingRule } from '../models/types'

export type RuleSetRuleLike = Omit<RoutingRule, 'group'>

export type DiffKind = 'added' | 'removed' | 'modified'

export interface NormalizedRule {
  identity: string
  signature: string
  text: string
  rule: RuleSetRuleLike
}

export interface DiffLine {
  kind: DiffKind
  identity: string
  text: string
  before?: RuleSetRuleLike
  after?: RuleSetRuleLike
}

export interface RuleDiffResult {
  added: DiffLine[]
  removed: DiffLine[]
  modified: DiffLine[]
  unchanged: number
  oldCount: number
  newCount: number
}

const DOMAIN_TYPES = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX',
])
const IP_TYPES = new Set(['IP-CIDR', 'IP-CIDR6', 'IP6-CIDR', 'IP-SUFFIX', 'GEOIP', 'IP-ASN'])

function normalizeValue(value: string | undefined): string {
  return (value ?? '').trim().toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '')
}

/** 正则规则的值必须保留大小写与结尾符号，客户端按原文区分大小写匹配。 */
function normalizeRuleValue(type: string, value: string | undefined): string {
  if (type === 'DOMAIN-REGEX' || type === 'URL-REGEX') return (value ?? '').trim()
  return normalizeValue(value)
}

function normalizeOptions(rule: RuleSetRuleLike): string[] {
  const options = (rule.options ?? []).map((option) => option.trim().toLowerCase()).filter(Boolean)
  if (rule.noResolve && !options.includes('no-resolve')) options.push('no-resolve')
  return options.sort()
}

/** 规则的身份：域名按值、IP 按值、逻辑规则按原文；类型变化视为同一条规则被修改。 */
export function ruleIdentity(rule: RuleSetRuleLike): string {
  const type = (rule.type ?? '').toUpperCase()
  if (type === 'FINAL' || type === 'MATCH') return 'final'
  if (rule.raw) return `raw:${(rule.raw ?? '').trim()}`
  const value = normalizeRuleValue(type, rule.value)
  if (DOMAIN_TYPES.has(type)) return `domain:${value}`
  if (IP_TYPES.has(type)) return `ip:${value}`
  return `rule:${value}`
}

/** 完整签名：类型 + 值 + 选项；用于判断是否真的修改过。 */
export function ruleSignature(rule: RuleSetRuleLike): string {
  const type = (rule.type ?? '').toUpperCase()
  if (rule.raw) return `${type}|${(rule.raw ?? '').trim()}`
  return `${type}|${normalizeRuleValue(type, rule.value)}|${normalizeOptions(rule).join(',')}`
}

export function ruleDisplayText(rule: RuleSetRuleLike): string {
  const type = (rule.type ?? '').toUpperCase()
  if (rule.raw) return rule.raw
  const options = normalizeOptions(rule)
  return `${type}${rule.value ? `,${rule.value}` : ''}${options.length ? `,${options.join(',')}` : ''}`
}

export function normalizeRule(rule: RuleSetRuleLike): NormalizedRule {
  return {
    identity: ruleIdentity(rule),
    signature: ruleSignature(rule),
    text: ruleDisplayText(rule),
    rule,
  }
}

function sortedEntries(rules: RuleSetRuleLike[]): NormalizedRule[] {
  const unique = new Map<string, NormalizedRule>()
  for (const rule of rules) {
    const entry = normalizeRule(rule)
    if (!unique.has(entry.signature)) unique.set(entry.signature, entry)
  }
  return [...unique.values()].sort((left, right) => {
    if (left.identity !== right.identity) return left.identity.localeCompare(right.identity)
    return left.signature.localeCompare(right.signature)
  })
}

/**
 * 对比两组规则。新增/删除按完整签名判断；同身份但类型或选项变化归为「修改」。
 * 输出和输入顺序都会先稳定排序，同样内容多次 diff 结果完全一致。
 */
export function diffRules(before: RuleSetRuleLike[], after: RuleSetRuleLike[]): RuleDiffResult {
  const oldEntries = sortedEntries(before)
  const newEntries = sortedEntries(after)
  const oldBySignature = new Map(oldEntries.map((entry) => [entry.signature, entry]))
  const newBySignature = new Map(newEntries.map((entry) => [entry.signature, entry]))

  const added: DiffLine[] = []
  const removed: DiffLine[] = []
  const addedBySignature = new Map<string, DiffLine>()
  const removedBySignature = new Map<string, DiffLine>()
  for (const entry of newEntries) {
    if (!oldBySignature.has(entry.signature)) {
      const line: DiffLine = { kind: 'added', identity: entry.identity, text: entry.text, after: entry.rule }
      added.push(line)
      addedBySignature.set(entry.signature, line)
    }
  }
  for (const entry of oldEntries) {
    if (!newBySignature.has(entry.signature)) {
      const line: DiffLine = { kind: 'removed', identity: entry.identity, text: entry.text, before: entry.rule }
      removed.push(line)
      removedBySignature.set(entry.signature, line)
    }
  }

  const oldByIdentity = new Map<string, NormalizedRule>()
  const newByIdentity = new Map<string, NormalizedRule>()
  for (const entry of oldEntries) if (!oldByIdentity.has(entry.identity)) oldByIdentity.set(entry.identity, entry)
  for (const entry of newEntries) if (!newByIdentity.has(entry.identity)) newByIdentity.set(entry.identity, entry)

  const modified: DiffLine[] = []
  const modifiedOld = new Set<string>()
  const modifiedNew = new Set<string>()
  for (const [identity, oldEntry] of oldByIdentity) {
    const newEntry = newByIdentity.get(identity)
    if (!newEntry || newEntry.signature === oldEntry.signature) continue
    if (!removedBySignature.has(oldEntry.signature) || !addedBySignature.has(newEntry.signature)) continue
    modified.push({
      kind: 'modified',
      identity,
      text: newEntry.text,
      before: oldEntry.rule,
      after: newEntry.rule,
    })
    modifiedOld.add(oldEntry.signature)
    modifiedNew.add(newEntry.signature)
  }

  const sortLines = (lines: DiffLine[]): DiffLine[] => lines.sort((left, right) => {
    if (left.identity !== right.identity) return left.identity.localeCompare(right.identity)
    return left.text.localeCompare(right.text)
  })
  return {
    added: sortLines(added.filter((line) => !(line.after && modifiedNew.has(ruleSignature(line.after))))),
    removed: sortLines(removed.filter((line) => !(line.before && modifiedOld.has(ruleSignature(line.before))))),
    modified: sortLines(modified),
    unchanged: oldEntries.filter((entry) => newBySignature.has(entry.signature)).length,
    oldCount: before.length,
    newCount: after.length,
  }
}

export function diffTotal(result: RuleDiffResult): number {
  return result.added.length + result.removed.length + result.modified.length
}

/** 便于 UI 只显示某一类。 */
export function filterDiff(result: RuleDiffResult, kind: DiffKind | 'all'): DiffLine[] {
  if (kind === 'all') return [...result.modified, ...result.added, ...result.removed]
  return result[kind]
}
