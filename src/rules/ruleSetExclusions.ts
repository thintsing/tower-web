// 只读规则集的本地屏蔽表：按「规则集 id + ruleSignature」记录被排除的条目。
// 与规则集快照分离，刷新来源后仍按签名生效；编译与导出都必须经过这里。
import type { RuleScheme, RuleSetExclusionTable, SchemeRuleSet } from '../models/types'
import { ruleSignature } from './ruleDiff'

/** 只读来源：刷新后方案里的快照会被替换，直接删规则属于假删除。 */
export function isReadOnlyRuleSet(set: SchemeRuleSet): boolean {
  return set.sourceKind === 'url' || set.sourceKind === 'library'
}

/**
 * 容错归一化：坏掉一条只丢一条（非字符串、空串、重复项）。
 * 备份、工作区同步和本地旧快照都走这里。
 */
export function normalizeRuleSetExclusions(value: unknown): RuleSetExclusionTable {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  const out: RuleSetExclusionTable = {}
  for (const [rawID, list] of Object.entries(value as Record<string, unknown>)) {
    const id = rawID.trim()
    if (!id || !Array.isArray(list)) continue
    const signatures = [...new Set(
      list
        .filter((item): item is string => typeof item === 'string')
        .map((item) => item.trim())
        .filter(Boolean),
    )].sort()
    if (signatures.length) out[id] = signatures
  }
  return out
}

/** 过滤掉被屏蔽的条目；没有命中任何排除项时返回原对象，避免无谓重算。 */
export function filterExcludedRuleSets(
  scheme: RuleScheme,
  exclusions: RuleSetExclusionTable | undefined,
): RuleScheme {
  if (!exclusions || !Array.isArray(scheme.ruleSets) || !scheme.ruleSets.length) return scheme
  let changed = false
  const ruleSets = scheme.ruleSets.map((set) => {
    const blocked = exclusions[set.id]
    // 内联规则集（固化快照）的规则就在 scheme.rules 里：保留 set.rules 作为快照，
    // 屏蔽直接过滤 scheme.rules，这样「解除屏蔽」和「当前快照仍存在」都还能判断。
    if (!blocked?.length || set.inlined || !Array.isArray(set.rules)) return set
    const rules = set.rules.filter((rule) => !blocked.includes(ruleSignature(rule)))
    if (rules.length === set.rules.length) return set
    changed = true
    return { ...set, rules }
  })

  const blockedBySet = new Map<string, Set<string>>()
  const ownersBySignature = new Map<string, string[]>()
  for (const set of scheme.ruleSets) {
    if (!set.inlined || !Array.isArray(set.rules)) continue
    const blocked = exclusions[set.id]
    if (blocked?.length) blockedBySet.set(set.id, new Set(blocked))
    for (const rule of set.rules) {
      const signature = ruleSignature(rule)
      const owners = ownersBySignature.get(signature)
      if (owners) owners.push(set.id)
      else ownersBySignature.set(signature, [set.id])
    }
  }
  let rulesChanged = false
  const rules = blockedBySet.size
    ? scheme.rules.filter((rule) => {
      const signature = ruleSignature(rule)
      if (rule.sourceSetId) {
        if (!blockedBySet.get(rule.sourceSetId)?.has(signature)) return true
        rulesChanged = true
        return false
      }
      // 旧快照没有 sourceSetId：按签名 + 内联规则集归属判断；同签名在多组时一并屏蔽。
      const owners = ownersBySignature.get(signature)
      if (!owners?.some((id) => blockedBySet.get(id)?.has(signature))) return true
      rulesChanged = true
      return false
    })
    : scheme.rules

  if (!changed && !rulesChanged) return scheme
  return {
    ...scheme,
    ruleSets: changed ? ruleSets : scheme.ruleSets,
    rules,
  }
}

export function addRuleSetExclusion(
  table: RuleSetExclusionTable,
  ruleSetID: string,
  signature: string,
): RuleSetExclusionTable {
  const current = table[ruleSetID] ?? []
  if (current.includes(signature)) return table
  return { ...table, [ruleSetID]: [...current, signature].sort() }
}

export function removeRuleSetExclusion(
  table: RuleSetExclusionTable,
  ruleSetID: string,
  signature: string,
): RuleSetExclusionTable {
  const current = table[ruleSetID]
  if (!current?.length) return table
  const next = current.filter((item) => item !== signature)
  if (next.length === current.length) return table
  const result = { ...table }
  if (next.length) result[ruleSetID] = next
  else delete result[ruleSetID]
  return result
}

/** 一条签名在界面上的可读写法（仅展示用，不参与匹配）。 */
export function exclusionSignatureText(signature: string): string {
  return signature.split('|').filter(Boolean).join(',')
}

/** 整张屏蔽表的签名总数（用于回滚影响文案）。 */
export function countRuleSetExclusions(table: RuleSetExclusionTable | undefined): number {
  if (!table) return 0
  return Object.values(table).reduce((sum, list) => sum + list.length, 0)
}

/**
 * 已不存在于任何方案 / 我的规则集 / 固化快照里的屏蔽表 id。
 * 移除规则集会生成新 id，旧屏蔽记录如果没清理就会永久留在这里。
 */
export function orphanRuleSetIDs(
  table: RuleSetExclusionTable | undefined,
  liveIDs: Iterable<string>,
): string[] {
  if (!table) return []
  const live = new Set(liveIDs)
  return Object.keys(table).filter((id) => !live.has(id)).sort()
}

/** 孤儿屏蔽记录的签名总数；界面用它决定是否显示清理入口。 */
export function countOrphanRuleSetExclusions(
  table: RuleSetExclusionTable | undefined,
  liveIDs: Iterable<string>,
): number {
  if (!table) return 0
  return orphanRuleSetIDs(table, liveIDs)
    .reduce((sum, id) => sum + (table[id]?.length ?? 0), 0)
}

/** 清理孤儿屏蔽记录；没有孤儿时返回原对象，避免无谓的状态更新。 */
export function removeOrphanRuleSetExclusions(
  table: RuleSetExclusionTable,
  liveIDs: Iterable<string>,
): RuleSetExclusionTable {
  const orphans = orphanRuleSetIDs(table, liveIDs)
  if (!orphans.length) return table
  const next: RuleSetExclusionTable = { ...table }
  for (const id of orphans) delete next[id]
  return next
}

/** 移除规则集确认框里必须讲清屏蔽记录的后果，不能静默丢弃。 */
export function describeRuleSetRemovalImpact(blockedCount: number): string {
  return blockedCount > 0
    ? `该规则集有 ${blockedCount} 条屏蔽记录，移除后会一并失效并从工作区删除。`
    : '该规则集没有屏蔽记录。'
}

export interface RuleSetExclusionItem {
  setId: string
  setName: string
  group: string
  signature: string
  text: string
  /** 签名在当前方案快照里仍然存在；刷新后规则消失时为 false。 */
  present: boolean
}

/** 当前方案里的屏蔽条目；用于诊断页「已屏蔽 N 条」与解除屏蔽。 */
export function listSchemeExclusions(
  scheme: RuleScheme,
  table: RuleSetExclusionTable | undefined,
): RuleSetExclusionItem[] {
  if (!table || !Array.isArray(scheme.ruleSets) || !scheme.ruleSets.length) return []
  const items: RuleSetExclusionItem[] = []
  for (const set of scheme.ruleSets) {
    const blocked = table[set.id]
    if (!blocked?.length || !Array.isArray(set.rules)) continue
    for (const signature of blocked) {
      items.push({
        setId: set.id,
        setName: set.name,
        group: set.group,
        signature,
        text: exclusionSignatureText(signature),
        present: set.rules.some((rule) => ruleSignature(rule) === signature),
      })
    }
  }
  return items
}
