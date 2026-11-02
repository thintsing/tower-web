// Preflight validation for an imported rule scheme. Mirrors the native
// RuleSchemePolicyValidator: it catches the errors that would otherwise become
// a client-side "configuration loaded, nothing connects" failure.
import type { PolicyGroup, RuleScheme } from '../models/types'

export type PolicyIssueCode =
  | 'duplicateGroupName'
  | 'unknownGroupMember'
  | 'unknownRuleTarget'
  | 'cycle'
  | 'emptyGroup'
  | 'invalidNodePattern'

export interface PolicyIssue {
  code: PolicyIssueCode
  /** Group first, then the offending member / pattern / cycle path. */
  names: string[]
}

const POLICY_ISSUE_TITLES: Record<PolicyIssueCode, string> = {
  duplicateGroupName: '策略组名称重复',
  unknownGroupMember: '候选策略不存在',
  unknownRuleTarget: '规则目标不存在',
  cycle: '策略组循环引用',
  emptyGroup: '策略组没有可用候选项',
  invalidNodePattern: '节点筛选表达式无效',
}

const BUILTIN_POLICIES = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE'])

function parameterArray(parameters: Record<string, string> | undefined, key: string): string[] {
  if (!parameters?.[key]) return []
  try {
    const value = JSON.parse(parameters[key])
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
  } catch {
    return []
  }
}

/** Conditional groups emit their real targets from parameters, not options. */
function conditionalTargets(group: PolicyGroup): string[] {
  if (group.type !== 'conditional' || !group.parameters) return []
  const targets: string[] = []
  parameterArray(group.parameters, 'ssid-members').forEach((field, index) => {
    if (index < 2) {
      targets.push(field)
      return
    }
    const colon = field.indexOf(':')
    if (colon >= 0) targets.push(field.slice(colon + 1))
  })
  for (const field of parameterArray(group.parameters, 'subnet-fields')) {
    const equal = field.indexOf('=')
    if (equal >= 0) targets.push(field.slice(equal + 1))
  }
  const fallback = group.parameters.default_policy
  if (fallback) targets.push(fallback)
  const rawRules = group.parameters.rules
  if (rawRules) {
    try {
      const rules = JSON.parse(rawRules)
      if (Array.isArray(rules)) {
        for (const wrapper of rules) {
          if (!wrapper || typeof wrapper !== 'object') continue
          for (const value of Object.values(wrapper)) {
            if (value && typeof value === 'object' && typeof (value as { policy?: unknown }).policy === 'string') {
              targets.push((value as { policy: string }).policy)
            }
          }
        }
      }
    } catch {
      // Ignore malformed conditional metadata; options still validate.
    }
  }
  return targets.map((name) => name.trim())
}

/** Detailed, de-duplicated issues for display; empty when the graph is sound. */
export function validateSchemePolicy(
  scheme: RuleScheme,
  nodeNames: Iterable<string> = [],
  allowUnresolvedPatterns = false,
): PolicyIssue[] {
  const nodes = new Set(nodeNames)
  const noNodesLoaded = nodes.size === 0
  const issues: PolicyIssue[] = []
  const seen = new Set<string>()
  const append = (code: PolicyIssueCode, names: string[]) => {
    const key = `${code}|${names.join('|')}`
    if (seen.has(key)) return
    seen.add(key)
    issues.push({ code, names })
  }

  const indexByName = new Map<string, number>()
  scheme.groups.forEach((group, index) => {
    if (indexByName.has(group.name)) {
      append('duplicateGroupName', [group.name])
    } else {
      indexByName.set(group.name, index)
    }
  })

  const edges: number[][] = scheme.groups.map(() => [])
  const reverseEdges: number[][] = scheme.groups.map(() => [])
  const reachesCandidate = scheme.groups.map(() => false)

  scheme.groups.forEach((group, index) => {
    const declared = new Set(group.options)
    const conditionMembers = conditionalTargets(group).filter((name) => !declared.has(name))
    for (const member of [...group.options, ...conditionMembers]) {
      const target = indexByName.get(member)
      if (target !== undefined) {
        edges[index].push(target)
        reverseEdges[target].push(index)
      } else if (BUILTIN_POLICIES.has(member.toUpperCase()) || nodes.has(member)) {
        reachesCandidate[index] = true
      } else if (!noNodesLoaded) {
        append('unknownGroupMember', [group.name, member])
      } else {
        // Nodes are not loaded yet; an unmatched member may still be a node.
        reachesCandidate[index] = true
      }
    }
    if (group.nodeFilter) {
      let regex: RegExp | undefined
      try {
        regex = new RegExp(group.nodeFilter)
      } catch {
        append('invalidNodePattern', [group.name, group.nodeFilter])
      }
      if (regex && (allowUnresolvedPatterns || noNodesLoaded
        || [...nodes].some((name) => regex.test(name)))) {
        reachesCandidate[index] = true
      }
    }
  })

  const ruleTargets = [
    ...scheme.rules.map((rule) => rule.group),
    ...(scheme.customRules ?? []).map((rule) => rule.group),
    ...(scheme.ruleSets ?? []).flatMap((set) => set.rules.map((rule) => rule.group)),
  ]
  for (const target of ruleTargets) {
    if (target && indexByName.has(target)) continue
    if (BUILTIN_POLICIES.has(target.toUpperCase())) continue
    if (nodes.has(target)) continue
    if (noNodesLoaded && target) continue
    append('unknownRuleTarget', [target])
  }

  // Iterative DFS: a back edge to a gray node is a cycle.
  const colors = scheme.groups.map(() => 0)
  for (let root = 0; root < scheme.groups.length; root += 1) {
    if (colors[root] !== 0) continue
    const stack: Array<{ node: number; next: number }> = [{ node: root, next: 0 }]
    const path = new Map<number, number>([[root, 0]])
    colors[root] = 1
    while (stack.length) {
      const frame = stack[stack.length - 1]
      if (frame.next >= edges[frame.node].length) {
        colors[frame.node] = 2
        path.delete(frame.node)
        stack.pop()
        continue
      }
      const next = edges[frame.node][frame.next]
      frame.next += 1
      if (colors[next] === 0) {
        colors[next] = 1
        path.set(next, stack.length)
        stack.push({ node: next, next: 0 })
      } else if (colors[next] === 1) {
        const start = path.get(next)
        if (start !== undefined) {
          append('cycle', stack.slice(start).map(({ node }) => scheme.groups[node].name))
        }
      }
    }
  }

  // Propagate concrete candidates backwards through the reference graph.
  const queue = scheme.groups.map((_, index) => index).filter((index) => reachesCandidate[index])
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const target = queue[cursor]
    for (const owner of reverseEdges[target]) {
      if (reachesCandidate[owner]) continue
      reachesCandidate[owner] = true
      queue.push(owner)
    }
  }
  scheme.groups.forEach((group, index) => {
    if (!reachesCandidate[index]) append('emptyGroup', [group.name])
  })

  return issues
}

export function policyIssueText(issue: PolicyIssue): string {
  return `${POLICY_ISSUE_TITLES[issue.code]}：${issue.names.join(' → ')}`
}
