// Creating and deleting node-filter policy groups. Kept outside App.tsx so the
// rules can be exercised by the self-check scripts.
import type { PolicyGroup, ProxyNode, RuleScheme, SchemeRuleSet } from '../models/types'
import { DEFAULT_TEST_URL } from '../models/networkSettings'
import { dropRuleOrderKeysForGroup } from './ruleOrder'
import { isRemoteReferenceSet } from './ruleSetReferences'

export type NodeGroupType = 'select' | 'url-test' | 'fallback'

export interface NodeGroupDraft {
  name: string
  type: NodeGroupType
  pattern: string
  /** 显式候选：方案里其他策略组的名字，或 DIRECT / REJECT。 */
  options?: string[]
}

const RESERVED_GROUP_NAMES = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS'])
const CANDIDATE_BUILTINS = new Set(['DIRECT', 'REJECT'])
const AUTO_GROUP_TYPES = new Set(['url-test', 'fallback', 'load-balance', 'smart'])
const INVALID_GROUP_NAME = /[\r\n,=`]/

/**
 * 自动组里放策略组引用时，sing-box 的 urltest 会把这些引用过滤掉。
 * 在编辑时就提示，别等导出后才发现。
 */
export function autoGroupReferenceWarning(
  type: PolicyGroup['type'],
  options: string[],
  groupNames: Iterable<string>,
): string | undefined {
  if (!AUTO_GROUP_TYPES.has(type)) return undefined
  const names = new Set(groupNames)
  const references = options.filter((option) => names.has(option))
  if (references.length === 0) return undefined
  return `候选里有 ${references.length} 个策略组引用（${references.join('、')}）：sing-box 导出会过滤掉这些组引用，只保留节点；其它客户端按原样输出。`
}

/** A name that does not collide with current groups, case-insensitively. */
export function nextGroupName(scheme: RuleScheme, base = '自定义节点'): string {
  const names = new Set(scheme.groups.map((group) => group.name.toLowerCase()))
  let candidate = base
  let suffix = 2
  while (names.has(candidate.toLowerCase())) {
    candidate = `${base} ${suffix}`
    suffix += 1
  }
  return candidate
}

/** Parse and preview a node-name regex against the enabled node pool. */
export function previewNodeMatches(
  pattern: string,
  nodes: ProxyNode[],
): { error?: string; names: string[] } {
  if (!pattern.trim()) return { names: [] }
  let regex: RegExp
  try {
    regex = new RegExp(pattern)
  } catch {
    return { error: '节点名称匹配不是有效的正则表达式', names: [] }
  }
  return { names: nodes.filter((node) => regex.test(node.name)).map((node) => node.name) }
}

/** 显式候选只能引用其他策略组或内置策略；节点走名称匹配。改名时原名字也算自己。 */
export function validateGroupCandidates(
  scheme: RuleScheme,
  groupName: string,
  options: string[],
  originalName?: string,
): string | undefined {
  if (new Set(options).size !== options.length) return '候选策略里有重复项'
  const selfNames = new Set([groupName, originalName].filter((name): name is string => !!name))
  const available = new Set(
    scheme.groups
      .filter((group) => !selfNames.has(group.name))
      .map((group) => group.name),
  )
  for (const option of options) {
    if (CANDIDATE_BUILTINS.has(option)) continue
    if (selfNames.has(option)) return '策略组不能把自己加入候选'
    if (!available.has(option)) {
      return `候选「${option}」不是当前方案里的策略组；节点请用节点名称匹配加入`
    }
  }
  return undefined
}

/**
 * 从 groupName 出发能否绕回自己；返回闭环路径（首尾同名），没有环时 undefined。
 * 内置策略和节点名不在 groups 里，天然不会成环。
 */
export function findGroupCyclePath(
  groups: PolicyGroup[],
  groupName: string,
): string[] | undefined {
  const adjacency = new Map<string, string[]>()
  for (const group of groups) adjacency.set(group.name, group.options)
  if (!adjacency.has(groupName)) return undefined
  const path: string[] = []
  const onPath = new Set<string>()
  const walk = (name: string): string[] | undefined => {
    path.push(name)
    onPath.add(name)
    for (const next of adjacency.get(name) ?? []) {
      if (!adjacency.has(next)) continue
      if (next === groupName) return [...path, next]
      if (onPath.has(next)) continue
      const hit = walk(next)
      if (hit) return hit
    }
    path.pop()
    onPath.delete(name)
    return undefined
  }
  return walk(groupName)
}

/** Validation shared by the dialog and the save path. */
export function validateNodeGroupDraft(
  scheme: RuleScheme,
  draft: NodeGroupDraft,
): string | undefined {
  const name = draft.name.trim()
  const options = draft.options ?? []
  const pattern = draft.pattern.trim()
  if (!name) return '请填写策略组名称'
  if (INVALID_GROUP_NAME.test(name)) return '名称不能包含换行、逗号、等号或反引号'
  if (RESERVED_GROUP_NAMES.has(name.toUpperCase())) return '不能使用内置策略名'
  if (scheme.groups.some((group) => group.name.toLowerCase() === name.toLowerCase())) {
    return '已经有同名策略组'
  }
  if (!pattern && options.length === 0) return '至少填写节点名称匹配，或选择候选策略'
  const candidateError = validateGroupCandidates(scheme, name, options)
  if (candidateError) return candidateError
  if (pattern && previewNodeMatches(pattern, []).error) {
    return '节点名称匹配不是有效的正则表达式'
  }
  // 保存前就把环挡掉：与 lint 的 groupCycle 使用同一套图定义。
  const draftGroups: PolicyGroup[] = scheme.groups.some((group) => group.name === name)
    ? scheme.groups.map((group) => (group.name === name ? { ...group, name, options } : group))
    : [...scheme.groups, { name, type: draft.type, options }]
  const cycle = findGroupCyclePath(draftGroups, name)
  if (cycle) return `策略组循环引用：${cycle.join(' → ')}`
  return undefined
}

/** Create a group from a node regex and/or explicit candidate references. */
export function buildNodeFilterGroup(draft: NodeGroupDraft): PolicyGroup {
  const pattern = draft.pattern.trim()
  return {
    name: draft.name.trim(),
    type: draft.type,
    options: [...(draft.options ?? [])],
    ...(pattern ? { nodeFilter: pattern } : {}),
    ...(draft.type === 'select'
      ? {}
      : { url: DEFAULT_TEST_URL, interval: 300, tolerance: 50 }),
  }
}

export interface RemovedGroupSummary {
  scheme: RuleScheme
  removedRules: number
  removedCustomRules: number
  removedRuleSets: number
  /** 被一并删除、且原本以远程引用（provider / 只读快照）写入的规则集数量。 */
  removedRemoteReferences: number
  /** 候选里引用过这个组的其他策略组；删除时它们的引用会被一并移除。 */
  referencingGroups: string[]
}

/**
 * Drop a group, its rules, its custom rules, its rule-set snapshots and any
 * references from other groups. The returned scheme is a new object.
 */
export function removePolicyGroup(source: RuleScheme, name: string): RemovedGroupSummary {
  const referencingGroups = source.groups
    .filter((group) => group.name !== name && group.options.includes(name))
    .map((group) => group.name)
  const groups = source.groups
    .filter((group) => group.name !== name)
    .map((group) => ({
      ...group,
      options: group.options.filter((option) => option !== name),
    }))
  const rules = source.rules.filter((rule) => rule.group !== name)
  const customRules = (source.customRules ?? []).filter((rule) => rule.group !== name)

  let removedRuleSets = 0
  let removedRemoteReferences = 0
  const ruleSets: SchemeRuleSet[] = []
  for (const set of source.ruleSets ?? []) {
    if (set.group === name) {
      removedRuleSets += 1
      if (isRemoteReferenceSet(set)) removedRemoteReferences += 1
      continue
    }
    const kept = set.rules.filter((rule) => rule.group !== name)
    if (kept.length === set.rules.length) {
      ruleSets.push(set)
      continue
    }
    if (kept.length > 0) ruleSets.push({ ...set, rules: kept })
    else {
      removedRuleSets += 1
      if (isRemoteReferenceSet(set)) removedRemoteReferences += 1
    }
  }

  const matchingOrder = source.matchingOrder?.filter((group) => group !== name)
  const ruleOrder = dropRuleOrderKeysForGroup(source.ruleOrder, name)
  return {
    scheme: {
      ...source,
      groups,
      rules,
      customRules,
      ruleSets,
      matchingOrder,
      ruleOrder,
      updatedAt: Date.now(),
    },
    removedRules: source.rules.length - rules.length,
    removedCustomRules: (source.customRules ?? []).length - customRules.length,
    removedRuleSets,
    removedRemoteReferences,
    referencingGroups,
  }
}
