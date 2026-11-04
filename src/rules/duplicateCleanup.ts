// 诊断结果里的「重复规则」一键清理。
//
// 准确性优先：只有「类型 + 归一化值 + 选项」完全等价、后一条与前一条同组、
// 且前一条本身确实可达（没有被更前面的规则遮蔽）时，才允许删除后一条。
// 跨组重复、只读规则集、前一条已失效的情况一律跳过，并在确认摘要里单列。
import type { RuleScheme, RoutingRule } from '../models/types'
import { reorderRulesByMatchingOrder } from './matchingOrder'
import { ruleSignature } from './ruleDiff'
import { ruleSetInsertionIndex, sortSupplementRules, type RuleSetBlock } from './ruleOrder'
import { isTerminalRule } from './ruleKeys'
import { shadowedRuleIndexes } from './schemeLint'

export type RulePlaceKind = 'custom' | 'scheme' | 'ruleSet'

export interface RulePlace {
  kind: RulePlaceKind
  /** 源数组里的原地索引。 */
  index: number
  ruleSetId?: string
  ruleSetName?: string
}

export interface DuplicateDeletion {
  place: RulePlace
  rule: RoutingRule
  ruleText: string
  group: string
  /** 保留的前一条在扁平化后的位置（从 1 开始）。 */
  duplicateOfIndex: number
  duplicateOfGroup: string
}

export type SkipReason = 'readOnly' | 'crossGroup' | 'deadPredecessor'

export interface SkippedDuplicate {
  ruleText: string
  group: string
  firstGroup: string
  /** 前一条与后一条在扁平化后的位置（从 1 开始）。 */
  firstIndex: number
  index: number
  reason: SkipReason
  source: string
}

export interface DuplicateCleanupPlan {
  /** 可以无风险删除的后一条规则。 */
  deletions: DuplicateDeletion[]
  skipped: Record<SkipReason, SkippedDuplicate[]>
  /** 删除会涉及的策略组数量。 */
  groups: number
  /** 命中的重复总数（可删 + 跳过）。 */
  total: number
}

interface TaggedRule {
  rule: RoutingRule
  place: RulePlace
  position: number
}

function ruleText(rule: RoutingRule): string {
  return rule.raw?.trim() || `${rule.type}${rule.value ? `,${rule.value}` : ''}`
}

function sameGroup(left: string | undefined, right: string | undefined): boolean {
  return (left ?? '').trim() === (right ?? '').trim()
}

function placeSource(place: RulePlace): string {
  if (place.kind === 'custom') return '自定义规则'
  if (place.kind === 'scheme') return '方案规则'
  return `规则集「${place.ruleSetName ?? '未命名'}」`
}

function placeWritable(place: RulePlace, scheme: RuleScheme): boolean {
  if (place.kind !== 'ruleSet') return true
  const set = scheme.ruleSets?.find((item) => item.id === place.ruleSetId)
  // 在线订阅与内置规则库是只读快照，不能在方案里删条目冒充修复。
  return !!set && set.sourceKind !== 'url' && set.sourceKind !== 'library'
}

/**
 * 与诊断器完全一致的扁平化顺序：自定义规则（最具体优先）+ 规则集块 +
 * 方案规则 + FINAL。每一步都保留回写到原数组所需的索引。
 */
function flattenScheme(scheme: RuleScheme): TaggedRule[] {
  const customTags: TaggedRule[] = (scheme.customRules ?? []).map((rule, index) => ({
    rule: { ...rule },
    place: { kind: 'custom', index },
    position: 0,
  }))
  const customByRule = new Map(customTags.map((tag) => [tag.rule, tag]))
  const customOrdered = sortSupplementRules(customTags.map((tag) => tag.rule))
    .map((rule) => customByRule.get(rule))
    .filter((tag): tag is TaggedRule => !!tag)

  const schemeTags: TaggedRule[] = scheme.rules.map((rule, index) => ({
    rule: { ...rule },
    place: { kind: 'scheme', index },
    position: 0,
  }))
  const blocks = (scheme.ruleSets ?? []).map((set) => {
    const tags: TaggedRule[] = set.rules.map((rule, index) => ({
      rule: { ...rule, group: set.group },
      place: { kind: 'ruleSet', index, ruleSetId: set.id, ruleSetName: set.name },
      position: 0,
    }))
    const block: RuleSetBlock = {
      group: set.group,
      matchRules: set.rules,
      sourceURL: set.sourceRef,
      rules: tags.map((tag) => tag.rule),
    }
    return { tags, block }
  })

  // 与 insertRuleSetBlocks 相同的插入算法，但带着索引一起合并。
  const ordinary = schemeTags.filter((tag) => !isTerminalRule(tag.rule))
  const finals = schemeTags.filter((tag) => isTerminalRule(tag.rule))
  const buckets = new Map<number, TaggedRule[]>()
  for (const { tags, block } of blocks) {
    const index = ruleSetInsertionIndex(ordinary.map((tag) => tag.rule), block)
    buckets.set(index, [...(buckets.get(index) ?? []), ...tags])
  }
  const merged: TaggedRule[] = []
  ordinary.forEach((tag, index) => {
    const bucket = buckets.get(index)
    if (bucket) merged.push(...bucket)
    merged.push(tag)
  })
  const tail = buckets.get(ordinary.length)
  if (tail) merged.push(...tail)
  merged.push(...finals)

  const byRule = new Map(merged.map((tag) => [tag.rule, tag]))
  const baseOrdered = reorderRulesByMatchingOrder(
    merged.map((tag) => tag.rule),
    scheme.matchingOrder,
  )
    .map((rule) => byRule.get(rule))
    .filter((tag): tag is TaggedRule => !!tag)

  return [...customOrdered, ...baseOrdered].map((tag, position) => ({ ...tag, position }))
}

/**
 * 分析重复。判定顺序：可写性 → 前一条是否失效 → 是否跨组。
 * 任何一种跳过原因都不会进入 deletions。
 */
export function analyzeDuplicateCleanup(scheme: RuleScheme): DuplicateCleanupPlan {
  const tagged = flattenScheme(scheme)
  const rules = tagged.map((tag) => tag.rule)
  const dead = shadowedRuleIndexes(rules)

  const firstBySignature = new Map<string, TaggedRule>()
  const deletions: DuplicateDeletion[] = []
  const skipped: DuplicateCleanupPlan['skipped'] = {
    readOnly: [],
    crossGroup: [],
    deadPredecessor: [],
  }
  let total = 0

  for (const tag of tagged) {
    if (isTerminalRule(tag.rule)) continue
    const signature = ruleSignature(tag.rule)
    const first = firstBySignature.get(signature)
    if (!first) {
      firstBySignature.set(signature, tag)
      continue
    }
    total += 1
    const base = {
      ruleText: ruleText(tag.rule),
      group: tag.rule.group,
      firstGroup: first.rule.group,
      firstIndex: first.position + 1,
      index: tag.position + 1,
      source: placeSource(tag.place),
    }
    if (!placeWritable(tag.place, scheme)) {
      skipped.readOnly.push({ ...base, reason: 'readOnly' })
      continue
    }
    if (dead.has(first.position)) {
      skipped.deadPredecessor.push({ ...base, reason: 'deadPredecessor' })
      continue
    }
    if (!sameGroup(first.rule.group, tag.rule.group)) {
      skipped.crossGroup.push({ ...base, reason: 'crossGroup' })
      continue
    }
    deletions.push({
      place: tag.place,
      rule: tag.rule,
      ruleText: ruleText(tag.rule),
      group: tag.rule.group,
      duplicateOfIndex: first.position + 1,
      duplicateOfGroup: first.rule.group,
    })
  }

  const groups = new Set(deletions.map((item) => item.group.trim()))
  return { deletions, skipped, groups: groups.size, total }
}

export interface DuplicateApplyResult {
  scheme: RuleScheme
  removed: number
}

/** 按原地索引删除；应用到前会核对签名，避免方案已变时误删别的规则。 */
export function applyDuplicateCleanup(
  scheme: RuleScheme,
  plan: DuplicateCleanupPlan,
): DuplicateApplyResult {
  const custom = new Set<number>()
  const base = new Set<number>()
  const bySet = new Map<string, Set<number>>()

  for (const deletion of plan.deletions) {
    const place = deletion.place
    const current = place.kind === 'custom'
      ? scheme.customRules?.[place.index]
      : place.kind === 'scheme'
        ? scheme.rules[place.index]
        : scheme.ruleSets?.find((set) => set.id === place.ruleSetId)?.rules[place.index]
    if (!current || ruleSignature(current) !== ruleSignature(deletion.rule)) continue
    if (place.kind === 'custom') custom.add(place.index)
    else if (place.kind === 'scheme') base.add(place.index)
    else if (place.ruleSetId) {
      const indexes = bySet.get(place.ruleSetId) ?? new Set<number>()
      indexes.add(place.index)
      bySet.set(place.ruleSetId, indexes)
    }
  }

  const removed = custom.size + base.size + [...bySet.values()].reduce((sum, item) => sum + item.size, 0)
  if (!removed) return { scheme, removed: 0 }

  const next: RuleScheme = {
    ...scheme,
    customRules: scheme.customRules?.filter((_, index) => !custom.has(index)),
    rules: base.size ? scheme.rules.filter((_, index) => !base.has(index)) : scheme.rules,
    ruleSets: scheme.ruleSets?.map((set) => {
      const indexes = bySet.get(set.id)
      return indexes?.size
        ? { ...set, rules: set.rules.filter((_, index) => !indexes.has(index)) }
        : set
    }),
  }
  return { scheme: next, removed }
}
