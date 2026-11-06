// 规则顺序移植自 Tower iOS RuleScheme：
// - 用户附加的条件按“最具体优先”排列；
// - 从规则库加入的规则集放在第一条与它冲突的模板规则之前，而不是全部压到最前；
// - FINAL / MATCH 永远留在最后，不参与拖动重排。
import type { RoutingRule, RuleScheme } from '../models/types'
import { reorderRulesByMatchingOrder } from './matchingOrder'
import { isTerminalRule, normalizedPolicyName, ruleMatchKey } from './ruleKeys'

export { isTerminalRule, normalizedPolicyName, ruleMatchKey } from './ruleKeys'

function cidrPrefixLength(value: string | undefined): number {
  const trimmed = (value ?? '').trim()
  const slash = trimmed.lastIndexOf('/')
  if (slash < 0) return trimmed.includes(':') ? 128 : 32
  const prefix = Number(trimmed.slice(slash + 1))
  if (!Number.isFinite(prefix)) return 0
  return prefix
}

/** 最具体优先；同等级保持添加顺序。 */
export function sortSupplementRules(rules: RoutingRule[]): RoutingRule[] {
  const rank = (rule: RoutingRule): [number, number] => {
    switch (rule.type.toUpperCase()) {
      case 'DOMAIN': return [0, 0]
      case 'DOMAIN-SUFFIX': return [1, -(rule.value ?? '').split('.').filter(Boolean).length]
      case 'DOMAIN-KEYWORD': return [2, -(rule.value ?? '').trim().length]
      case 'IP-CIDR':
      case 'IP-CIDR6':
      case 'IP6-CIDR': return [3, -cidrPrefixLength(rule.value)]
      default: return [4, 0]
    }
  }
  return [...rules].sort((left, right) => {
    const a = rank(left)
    const b = rank(right)
    return a[0] - b[0] || a[1] - b[1]
  })
}

export interface RuleSetBlock {
  group: string
  /** 原始规则集内容，用来寻找模板里第一条重叠规则。 */
  matchRules: RoutingRule[]
  /** 规则集来源地址；与模板里的 RULE-SET 引用比较。 */
  sourceURL?: string
  /** 真正写入配置的规则（可能是 MRS/SRS 的远程引用加残余内联规则）。 */
  rules: RoutingRule[]
  /** 规则已经在 baseRules 内联保存（固化快照），不再插入，避免同一批规则出现两份。 */
  inlined?: boolean
}

/**
 * 一条规则集应该插到模板的第几条规则之前：
 * 同组、同来源地址或同 TYPE,value 的第一条；没有冲突就放到 FINAL 之前。
 */
export function ruleSetInsertionIndex(
  baseRules: RoutingRule[],
  block: Omit<RuleSetBlock, 'rules'>,
): number {
  const group = normalizedPolicyName(block.group)
  const keys = new Set(
    block.matchRules.map(ruleMatchKey).filter((key): key is string => !!key),
  )
  const sourceURL = block.sourceURL?.trim()
  const index = baseRules.findIndex((rule) => {
    if (isTerminalRule(rule)) return false
    if (normalizedPolicyName(rule.group) === group) return true
    if (sourceURL && rule.type === 'RULE-SET' && (rule.value ?? '').trim() === sourceURL) return true
    const key = ruleMatchKey(rule)
    return !!key && keys.has(key)
  })
  return index < 0 ? baseRules.length : index
}

/**
 * 把规则集块按插入位置与模板规则交错合并。
 * 多个规则集落在同一位置时保持它们在方案里的顺序。
 */
export function insertRuleSetBlocks(
  baseRules: RoutingRule[],
  blocks: RuleSetBlock[],
): RoutingRule[] {
  const ordinary = baseRules.filter((rule) => !isTerminalRule(rule))
  const finals = baseRules.filter(isTerminalRule)
  const buckets = new Map<number, RoutingRule[]>()
  for (const block of blocks) {
    // 内联块（固化快照）的规则已经在 baseRules 里；跳过是导出逐字节一致的前提。
    if (block.inlined) continue
    const index = ruleSetInsertionIndex(ordinary, block)
    buckets.set(index, [...(buckets.get(index) ?? []), ...block.rules])
  }
  const merged: RoutingRule[] = []
  ordinary.forEach((rule, index) => {
    const bucket = buckets.get(index)
    if (bucket) merged.push(...bucket)
    merged.push(rule)
  })
  const tail = buckets.get(ordinary.length)
  if (tail) merged.push(...tail)
  merged.push(...finals)
  return merged
}

/** 规则集与模板规则合并后的顺序；不含用户自定义规则。 */
export function orderedSchemeBaseRules(scheme: RuleScheme): RoutingRule[] {
  const blocks: RuleSetBlock[] = (scheme.ruleSets ?? []).map((set) => ({
    group: set.group,
    matchRules: set.rules,
    sourceURL: set.sourceRef,
    rules: set.rules.map((rule) => ({ ...rule, group: set.group })),
    inlined: set.inlined,
  }))
  return reorderRulesByMatchingOrder(
    insertRuleSetBlocks(scheme.rules, blocks),
    scheme.matchingOrder,
  )
}

/** 界面展示用顺序：自定义规则（排序后）+ 规则集/模板规则 + FINAL。 */
export function orderedSchemeRules(scheme: RuleScheme): RoutingRule[] {
  return [
    ...sortSupplementRules(scheme.customRules ?? []),
    ...orderedSchemeBaseRules(scheme),
  ]
}
