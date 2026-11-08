// 诊断结果里的「重复规则」一键清理。
//
// 准确性优先：只有「类型 + 归一化值 + 选项」完全等价、且前一条本身确实可达
//（没有被更前面的规则遮蔽）时，才允许删除后一条。
// 同组重复删掉后一条不影响命中；跨组重复删掉后一条同样不影响命中——流量本来
// 就已被前一条接住。跨组的前提是前一条可写且存活：前一条若来自在线 / 内置只读
// 规则集，刷新后可能消失，删除后一条就会改变路由，因此跳过并单列。
import type { RuleScheme, RoutingRule } from '../models/types'
import { reorderRulesByMatchingOrder } from './matchingOrder'
import { ruleSignature } from './ruleDiff'
import { applyRuleOrder, ruleSetInsertionIndex, sortSupplementRules, type RuleSetBlock } from './ruleOrder'
import { isReadOnlyRuleSet } from './ruleSetExclusions'
import { isTerminalRule } from './ruleKeys'
import { shadowedRuleIndexes } from './schemeLint'

export type RulePlaceKind = 'custom' | 'scheme' | 'ruleSet'

export interface RulePlace {
  kind: RulePlaceKind
  /** 源数组里的原地索引。 */
  index: number
  ruleSetId?: string
  ruleSetName?: string
  /** 内联在 scheme.rules 里的只读规则（固化快照）：只能屏蔽，不能删除。 */
  readOnly?: boolean
}

/** 同组重复、跨组重复，以及被前序规则遮蔽的死规则。 */
export type DuplicateKind = 'sameGroup' | 'crossGroup' | 'shadowed'

export interface DuplicateDeletion {
  place: RulePlace
  rule: RoutingRule
  ruleText: string
  group: string
  /** 保留的前一条（或后一条）在扁平化后的位置（从 1 开始）。 */
  duplicateOfIndex: number
  duplicateOfGroup: string
  kind: DuplicateKind
  /** 本次选择保留的方向；跨组且保留后一条时会改变目标策略组。 */
  keptDirection?: 'first' | 'last'
  /** shadowed 的说明。 */
  shadowedReason?: string
}

export type SkipReason = 'readOnly' | 'deadPredecessor'

export interface SkippedDuplicate {
  ruleText: string
  group: string
  firstGroup: string
  /** 前一条与后一条在扁平化后的位置（从 1 开始）。 */
  firstIndex: number
  index: number
  reason: SkipReason
  source: string
  /** 前一条所在来源；前一条不可写时用来解释为什么不能删。 */
  firstSource?: string
}

/** 跨组删除的「保留组 → 删除组」配对，供确认弹窗展示明细。 */
export interface CrossGroupPair {
  keepGroup: string
  dropGroup: string
  count: number
  /** 该配对下被删除的规则文本，按规则顺序。 */
  rules: string[]
}

/** 选择「保留后一条」时，目标策略组会从 fromGroup 改为 toGroup。 */
export interface DirectionChange {
  fromGroup: string
  toGroup: string
  count: number
  rules: string[]
}

/** 逐对处理时，每一条重复规则的可选方向。 */
export interface DuplicateChoice {
  signature: string
  ruleText: string
  /** 出现过的策略组，按规则顺序去重。 */
  groups: string[]
  occurrences: number
  direction: 'first' | 'last'
}

export interface DuplicateCleanupOptions {
  /** 默认保留前一条；last 保留最后一条。 */
  keep?: 'first' | 'last'
  /** 逐对处理：按规则签名覆盖方向。 */
  decisions?: Record<string, 'first' | 'last'>
}

export interface DuplicateCleanupPlan {
  /** 可以无风险删除的重复条目（同组 + 跨组）。 */
  deletions: DuplicateDeletion[]
  /** 被前序更宽规则遮蔽、永远不会命中的死规则；与重复走同一套删除/撤销流程。 */
  shadowed: DuplicateDeletion[]
  skipped: Record<SkipReason, SkippedDuplicate[]>
  /** 同组重复条数。 */
  sameGroupCount: number
  /** 跨组重复条数。 */
  crossGroupCount: number
  /** 被前序规则遮蔽、永远不会命中的可删条数。 */
  shadowedCount: number
  /** 跨组删除里保留的策略组数量。 */
  keptGroups: number
  /** 跨组删除里被删除条目的策略组数量。 */
  droppedGroups: number
  crossPairs: CrossGroupPair[]
  /** 保留后一条会改变去向的组配对。 */
  directionChanges: DirectionChange[]
  /** 逐对处理的可选项；每项对应一个重复签名。 */
  choices: DuplicateChoice[]
  /** 删除会涉及的策略组数量。 */
  groups: number
  /** 命中的重复总数（可删 + 跳过），不含遮蔽的死规则。 */
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
  if (place.readOnly) return false
  if (place.kind !== 'ruleSet') return true
  const set = scheme.ruleSets?.find((item) => item.id === place.ruleSetId)
  // 在线订阅与内置规则库是只读快照，不能在方案里删条目冒充修复。
  return !!set && !isReadOnlyRuleSet(set)
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

  const readOnlyBySetID = new Map(
    (scheme.ruleSets ?? [])
      .filter((set) => isReadOnlyRuleSet(set))
      .map((set) => [set.id, set.name]),
  )
  const schemeTags: TaggedRule[] = scheme.rules.map((rule, index) => {
    const sourceSet = rule.sourceSetId ? readOnlyBySetID.get(rule.sourceSetId) : undefined
    return {
      rule: { ...rule },
      place: {
        kind: 'scheme',
        index,
        // 固化快照把只读规则内联在 scheme.rules 里：位置可定位，但只能屏蔽不能删。
        ...(rule.sourceSetId && sourceSet
          ? { readOnly: true, ruleSetId: rule.sourceSetId, ruleSetName: sourceSet }
          : {}),
      },
      position: 0,
    }
  })
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
      inlined: set.inlined,
    }
    return { tags, block }
  })

  // 与 insertRuleSetBlocks 相同的插入算法，但带着索引一起合并。
  const ordinary = schemeTags.filter((tag) => !isTerminalRule(tag.rule))
  const finals = schemeTags.filter((tag) => isTerminalRule(tag.rule))
  const buckets = new Map<number, TaggedRule[]>()
  for (const { tags, block } of blocks) {
    // 固化快照的规则已在 scheme.rules 里，块只是展示 / 屏蔽入口，不能再插一遍。
    if (block.inlined) continue
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

  const baseNatural = reorderRulesByMatchingOrder(
    merged.map((tag) => tag.rule),
    scheme.matchingOrder,
  )
    .map((rule) => merged.find((tag) => tag.rule === rule))
    .filter((tag): tag is TaggedRule => !!tag)
  const allTags = [...customOrdered, ...baseNatural]
  const byRule = new Map(allTags.map((tag) => [tag.rule, tag]))
  const allOrdered = applyRuleOrder(
    allTags.map((tag) => tag.rule),
    scheme.ruleOrder,
  )
    .map((rule) => byRule.get(rule))
    .filter((tag): tag is TaggedRule => !!tag)

  return allOrdered.map((tag, position) => ({ ...tag, position }))
}

/**
 * 分析重复。判定顺序：可写性 → 前一条是否失效 → 是否跨组。
 * 前一条失效（本身被更宽的规则遮蔽）时不删后一条：无法证明后一条不会命中。
 * 跨组时还要求前一条可写：前一条来自只读规则集，刷新后可能消失。
 */
export function analyzeDuplicateCleanup(
  scheme: RuleScheme,
  options: DuplicateCleanupOptions = {},
): DuplicateCleanupPlan {
  const tagged = flattenScheme(scheme)
  const rules = tagged.map((tag) => tag.rule)
  const dead = shadowedRuleIndexes(rules)
  const keepMode: 'first' | 'last' = options.keep === 'last' ? 'last' : 'first'
  const decisions = options.decisions ?? {}

  const bySignature = new Map<string, TaggedRule[]>()
  for (const tag of tagged) {
    if (isTerminalRule(tag.rule)) continue
    const signature = ruleSignature(tag.rule)
    const list = bySignature.get(signature) ?? []
    list.push(tag)
    bySignature.set(signature, list)
  }

  const deletions: DuplicateDeletion[] = []
  const skipped: DuplicateCleanupPlan['skipped'] = {
    readOnly: [],
    deadPredecessor: [],
  }
  const choices: DuplicateChoice[] = []
  let duplicateTotal = 0

  for (const [signature, list] of bySignature) {
    if (list.length < 2) continue
    duplicateTotal += list.length - 1
    const direction = decisions[signature] ?? keepMode
    choices.push({
      signature,
      ruleText: ruleText(list[0].rule),
      groups: [...new Set(list.map((tag) => tag.rule.group.trim()))],
      occurrences: list.length,
      direction,
    })
    const kept = direction === 'last' ? list[list.length - 1] : list[0]
    const candidates = direction === 'last' ? list.slice(0, -1) : list.slice(1)

    for (const candidate of candidates) {
      const base = {
        ruleText: ruleText(candidate.rule),
        group: candidate.rule.group,
        firstGroup: kept.rule.group,
        firstIndex: kept.position + 1,
        index: candidate.position + 1,
        source: placeSource(candidate.place),
      }
      if (!placeWritable(candidate.place, scheme)) {
        skipped.readOnly.push({ ...base, reason: 'readOnly' })
        continue
      }
      const crossGroup = !sameGroup(kept.rule.group, candidate.rule.group)
      if (direction === 'first' && dead.has(kept.position)) {
        // 保留的前一条本身不会命中：此时后一条可能真的生效，不能贸然删除。
        skipped.deadPredecessor.push({ ...base, reason: 'deadPredecessor' })
        continue
      }
      // 保留的条目来自在线 / 内置只读规则集：刷新后它可能消失，删掉另一条会改变路由。
      if (crossGroup && !placeWritable(kept.place, scheme)) {
        skipped.readOnly.push({ ...base, reason: 'readOnly', firstSource: placeSource(kept.place) })
        continue
      }
      deletions.push({
        place: candidate.place,
        rule: candidate.rule,
        ruleText: ruleText(candidate.rule),
        group: candidate.rule.group,
        duplicateOfIndex: kept.position + 1,
        duplicateOfGroup: kept.rule.group,
        kind: crossGroup ? 'crossGroup' : 'sameGroup',
        keptDirection: direction,
      })
    }
  }

  // 被前序更宽规则遮蔽的死规则永远不会命中，可安全删除；只读来源仍需走屏蔽。
  const shadowed: DuplicateDeletion[] = []
  const placed = new Set(deletions.map((item) => `${item.place.kind}:${item.place.ruleSetId ?? ''}:${item.place.index}`))
  for (const tag of tagged) {
    if (!dead.has(tag.position) || isTerminalRule(tag.rule)) continue
    const key = `${tag.place.kind}:${tag.place.ruleSetId ?? ''}:${tag.place.index}`
    if (placed.has(key) || !placeWritable(tag.place, scheme)) continue
    placed.add(key)
    shadowed.push({
      place: tag.place,
      rule: tag.rule,
      ruleText: ruleText(tag.rule),
      group: tag.rule.group,
      duplicateOfIndex: 0,
      duplicateOfGroup: '',
      kind: 'shadowed',
      shadowedReason: '被前序更宽的规则遮蔽，永远不会命中',
    })
  }

  const crossDeletions = deletions.filter((item) => item.kind === 'crossGroup')
  const crossPairs: CrossGroupPair[] = []
  const pairByKey = new Map<string, CrossGroupPair>()
  const changes: DirectionChange[] = []
  const changeByKey = new Map<string, DirectionChange>()
  for (const item of crossDeletions) {
    const keepGroup = item.duplicateOfGroup.trim()
    const dropGroup = item.group.trim()
    const key = `${keepGroup}\0${dropGroup}`
    const existing = pairByKey.get(key)
    if (existing) {
      existing.count += 1
      existing.rules.push(item.ruleText)
    } else {
      const pair = { keepGroup, dropGroup, count: 1, rules: [item.ruleText] }
      pairByKey.set(key, pair)
      crossPairs.push(pair)
    }
    // 保留后一条时，原本由「前一条组」接住的流量改由「后一条组」处理。
    if (item.keptDirection === 'last') {
      const change = changeByKey.get(key)
      if (change) {
        change.count += 1
        change.rules.push(item.ruleText)
      } else {
        const entry = { fromGroup: dropGroup, toGroup: keepGroup, count: 1, rules: [item.ruleText] }
        changeByKey.set(key, entry)
        changes.push(entry)
      }
    }
  }

  const groups = new Set([...deletions, ...shadowed].map((item) => item.group.trim()))
  const shadowedCount = shadowed.length
  return {
    deletions,
    shadowed,
    skipped,
    sameGroupCount: deletions.filter((item) => item.kind === 'sameGroup').length,
    crossGroupCount: crossDeletions.length,
    shadowedCount,
    keptGroups: new Set(crossDeletions.map((item) => item.duplicateOfGroup.trim())).size,
    droppedGroups: new Set(crossDeletions.map((item) => item.group.trim())).size,
    crossPairs,
    directionChanges: changes,
    choices,
    groups: groups.size,
    total: duplicateTotal,
  }
}

export interface DuplicateApplyResult {
  scheme: RuleScheme
  removed: number
  /** 实际通过签名核对、真正被删除的条目；撤销按这些条目精确回插。 */
  applied: DuplicateDeletion[]
}

/** 按原地索引删除；应用到前会核对签名，避免方案已变时误删别的规则。 */
export function applyDuplicateCleanup(
  scheme: RuleScheme,
  plan: DuplicateCleanupPlan,
): DuplicateApplyResult {
  const custom = new Set<number>()
  const base = new Set<number>()
  const bySet = new Map<string, Set<number>>()
  const applied: DuplicateDeletion[] = []

  for (const deletion of [...plan.deletions, ...(plan.shadowed ?? [])]) {
    const place = deletion.place
    const current = place.kind === 'custom'
      ? scheme.customRules?.[place.index]
      : place.kind === 'scheme'
        ? scheme.rules[place.index]
        : scheme.ruleSets?.find((set) => set.id === place.ruleSetId)?.rules[place.index]
    if (!current || ruleSignature(current) !== ruleSignature(deletion.rule)) continue
    applied.push(deletion)
    if (place.kind === 'custom') custom.add(place.index)
    else if (place.kind === 'scheme') base.add(place.index)
    else if (place.ruleSetId) {
      const indexes = bySet.get(place.ruleSetId) ?? new Set<number>()
      indexes.add(place.index)
      bySet.set(place.ruleSetId, indexes)
    }
  }

  const removed = applied.length
  if (!removed) return { scheme, removed: 0, applied: [] }

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
  return { scheme: next, removed, applied }
}

export interface RemovedRuleRecord {
  place: RulePlace
  rule: RoutingRule
}

export interface RestoreResult {
  scheme: RuleScheme
  restored: number
  /** 规则集已被删除/替换成只读来源，或原位已经有同签名规则时跳过。 */
  skipped: number
}

function sameSignature(left: RoutingRule, right: RoutingRule): boolean {
  return ruleSignature(left) === ruleSignature(right)
}

/** 按记录的原始索引升序回插；只动被清理的那几条，不覆盖其它编辑。 */
function insertBack(rules: RoutingRule[], records: RemovedRuleRecord[]): { next: RoutingRule[]; restored: number; skipped: number } {
  const next = [...rules]
  let restored = 0
  let skipped = 0
  for (const record of [...records].sort((a, b) => a.place.index - b.place.index)) {
    const at = Math.min(Math.max(0, record.place.index), next.length)
    // 用户可能已经手工把同一条规则加回原位；此时不再重复插入，避免凭空多一条。
    if (next[at] && sameSignature(next[at], record.rule)) {
      skipped += 1
      continue
    }
    next.splice(at, 0, { ...record.rule })
    restored += 1
  }
  return { next, restored, skipped }
}

/**
 * 撤销重复规则清理：精确回插被删的条目，其它编辑原样保留。
 * 边界：同一条值被用户重新加回原位 → 跳过；规则集被删除或被替换成
 * 在线 / 内置只读来源 → 跳过并在 skipped 里计数；用户在别处又加了同签名
 * 规则 → 照原样回插，不按签名去重（撤销是“恢复原状”，不是再次清理）。
 */
export function restoreRemovedRules(
  scheme: RuleScheme,
  records: RemovedRuleRecord[],
): RestoreResult {
  const custom: RemovedRuleRecord[] = []
  const base: RemovedRuleRecord[] = []
  const bySet = new Map<string, RemovedRuleRecord[]>()
  let skipped = 0

  for (const record of records) {
    const place = record.place
    if (place.kind === 'custom') {
      custom.push(record)
      continue
    }
    if (place.kind === 'scheme') {
      base.push(record)
      continue
    }
    const set = place.ruleSetId ? scheme.ruleSets?.find((item) => item.id === place.ruleSetId) : undefined
    if (!set || set.sourceKind === 'url' || set.sourceKind === 'library') {
      skipped += 1
      continue
    }
    bySet.set(set.id, [...(bySet.get(set.id) ?? []), record])
  }

  const customResult = insertBack(scheme.customRules ?? [], custom)
  const baseResult = insertBack(scheme.rules, base)
  let restored = customResult.restored + baseResult.restored
  let skippedCount = skipped + customResult.skipped + baseResult.skipped

  const ruleSets = scheme.ruleSets?.map((set) => {
    const records = bySet.get(set.id)
    if (!records?.length) return set
    const result = insertBack(set.rules, records)
    restored += result.restored
    skippedCount += result.skipped
    return { ...set, rules: result.next }
  })

  return {
    scheme: {
      ...scheme,
      customRules: scheme.customRules ? customResult.next : scheme.customRules,
      rules: baseResult.next,
      ruleSets,
    },
    restored,
    skipped: skippedCount,
  }
}
