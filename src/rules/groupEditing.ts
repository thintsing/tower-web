// Creating and deleting node-filter policy groups. Kept outside App.tsx so the
// rules can be exercised by the self-check scripts.
import type { PolicyGroup, ProxyNode, RuleScheme, SchemeRuleSet } from '../models/types'
import { DEFAULT_TEST_URL } from '../models/networkSettings'

export type NodeGroupType = 'select' | 'url-test' | 'fallback'

export interface NodeGroupDraft {
  name: string
  type: NodeGroupType
  pattern: string
}

const RESERVED_GROUP_NAMES = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS'])
const INVALID_GROUP_NAME = /[\r\n,=`]/

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

/** Validation shared by the dialog and the save path. */
export function validateNodeGroupDraft(
  scheme: RuleScheme,
  draft: NodeGroupDraft,
): string | undefined {
  const name = draft.name.trim()
  if (!name) return '请填写策略组名称'
  if (INVALID_GROUP_NAME.test(name)) return '名称不能包含换行、逗号、等号或反引号'
  if (RESERVED_GROUP_NAMES.has(name.toUpperCase())) return '不能使用内置策略名'
  if (scheme.groups.some((group) => group.name.toLowerCase() === name.toLowerCase())) {
    return '已经有同名策略组'
  }
  if (!draft.pattern.trim()) return '请填写节点名称匹配'
  if (previewNodeMatches(draft.pattern, []).error) return '节点名称匹配不是有效的正则表达式'
  return undefined
}

/** Create a group with only a node regex; candidates are resolved at export. */
export function buildNodeFilterGroup(draft: NodeGroupDraft): PolicyGroup {
  return {
    name: draft.name.trim(),
    type: draft.type,
    options: [],
    nodeFilter: draft.pattern.trim(),
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
}

/**
 * Drop a group, its rules, its custom rules, its rule-set snapshots and any
 * references from other groups. The returned scheme is a new object.
 */
export function removePolicyGroup(source: RuleScheme, name: string): RemovedGroupSummary {
  const groups = source.groups
    .filter((group) => group.name !== name)
    .map((group) => ({
      ...group,
      options: group.options.filter((option) => option !== name),
    }))
  const rules = source.rules.filter((rule) => rule.group !== name)
  const customRules = (source.customRules ?? []).filter((rule) => rule.group !== name)

  let removedRuleSets = 0
  const ruleSets: SchemeRuleSet[] = []
  for (const set of source.ruleSets ?? []) {
    if (set.group === name) {
      removedRuleSets += 1
      continue
    }
    const kept = set.rules.filter((rule) => rule.group !== name)
    if (kept.length === set.rules.length) {
      ruleSets.push(set)
      continue
    }
    if (kept.length > 0) ruleSets.push({ ...set, rules: kept })
    else removedRuleSets += 1
  }

  const matchingOrder = source.matchingOrder?.filter((group) => group !== name)
  return {
    scheme: {
      ...source,
      groups,
      rules,
      customRules,
      ruleSets,
      matchingOrder,
      updatedAt: Date.now(),
    },
    removedRules: source.rules.length - rules.length,
    removedCustomRules: (source.customRules ?? []).length - customRules.length,
    removedRuleSets,
  }
}
