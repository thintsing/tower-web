// 命中解释器：规则顺序、规则来源和策略组解析都走导出管线，保证解释结果与客户端收到的配置一致。
import type {
  LocalRuleSet,
  ProxyNode,
  RuleScheme,
  RuleSetExclusionTable,
  RoutingRule,
  SchemeRuleSet,
} from '../models/types'
import { prepareSchemeForExport, resolveGroups, uniqueDisplayNames } from '../generator/groups'
import { filterExcludedRuleSets } from './ruleSetExclusions'
import { evaluateRule, parseQuery } from './ruleMatcher'
import type { QueryTarget, RuleEvaluation, RuleStepStatus } from './ruleMatcher'

export type RuleOriginKind = 'custom' | 'scheme' | 'local' | 'url' | 'library'

export interface RuleOrigin {
  source: string
  kind: RuleOriginKind
  group: string
  setName?: string
}

export interface ExplainedStep {
  index: number
  rule: RoutingRule
  origin: RuleOrigin
  evaluation: RuleEvaluation
  ruleSetNote?: string
}

export interface ExplainGroupSnapshot {
  name: string
  type: string
  candidates: number
  groupRefs: number
}

export interface ExplainFinal {
  group?: string
  groupType?: string
  candidates: number
  node?: string
  note?: string
  isFallback: boolean
  steps: number
  origin?: RuleOrigin
}

export interface ExplainResult {
  target: QueryTarget
  steps: ExplainedStep[]
  match?: ExplainedStep
  final: ExplainFinal
  notes: string[]
  totalRules: number
}

export interface CompileExplainOptions {
  scheme: RuleScheme
  nodes: ProxyNode[]
  policySelections?: Record<string, string>
  latencyByNodeId?: Record<string, number | null>
  localRuleSets?: LocalRuleSet[]
  /** 只读规则集的本地屏蔽表；命中解释与导出必须用同一份。 */
  ruleSetExclusions?: RuleSetExclusionTable
}

export interface CompiledScheme {
  scheme: RuleScheme
  nodes: ProxyNode[]
  displayNameByNodeID: Map<string, string>
  nodeByDisplayName: Map<string, ProxyNode>
  resolvedMembers: Map<string, string[]>
  groupsByName: Map<string, { name: string; type: string }>
  origins: Map<string, RuleOrigin>
  ruleSets: SchemeRuleSet[]
  pausedSetNames: Set<string>
  notes: string[]
  latencyByNodeId: Record<string, number | null>
}

function ruleKey(rule: Pick<RoutingRule, 'type' | 'value' | 'group' | 'raw'>): string {
  if (rule.raw) return `${rule.type}|${rule.raw}|${rule.group}`
  return `${rule.type}|${rule.value ?? ''}|${rule.group}`
}

/** 把方案按导出顺序展开一次，供批量查询复用。 */
export function compileScheme(options: CompileExplainOptions): CompiledScheme {
  const policySelections = options.policySelections ?? {}
  const scheme = filterExcludedRuleSets(options.scheme, options.ruleSetExclusions)
  const prepared = prepareSchemeForExport(scheme, policySelections, {
    preferRuleSets: false,
    ruleSetExclusions: options.ruleSetExclusions,
  })
  const displayNameByNodeID = uniqueDisplayNames(options.nodes, (value) => value)
  const nodeByDisplayName = new Map<string, ProxyNode>()
  for (const node of options.nodes) {
    const display = displayNameByNodeID.get(node.id) ?? node.name
    nodeByDisplayName.set(display, node)
  }
  const resolved = resolveGroups(prepared, options.nodes, (node) => displayNameByNodeID.get(node.id) ?? node.name)
  const resolvedMembers = new Map(resolved.map((item) => [item.group.name, item.members]))

  const origins = new Map<string, RuleOrigin>()
  for (const rule of scheme.rules) {
    origins.set(ruleKey(rule), { source: '方案内置规则', kind: 'scheme', group: rule.group })
  }
  for (const set of scheme.ruleSets ?? []) {
    for (const rule of set.rules) {
      origins.set(ruleKey({ ...rule, group: set.group }), {
        source: set.name,
        kind: set.sourceKind,
        group: set.group,
        setName: set.name,
      })
    }
  }
  for (const rule of scheme.customRules ?? []) {
    origins.set(ruleKey(rule), { source: '自定义规则', kind: 'custom', group: rule.group })
  }

  // 规则集可能被重命名（方案内保留旧名），所以把 id / 订阅地址也作为匹配键，避免暂停状态判断失效。
  const pausedSetNames = new Set<string>()
  for (const set of options.localRuleSets ?? []) {
    if (!set.paused) continue
    pausedSetNames.add(set.name)
    pausedSetNames.add(set.id)
    if (set.sourceURL) pausedSetNames.add(set.sourceURL)
  }
  const isPaused = (set: SchemeRuleSet): boolean =>
    pausedSetNames.has(set.name) || (set.sourceRef ? pausedSetNames.has(set.sourceRef) : false)
  const notes: string[] = []
  for (const set of scheme.ruleSets ?? []) {
    if (set.rules.length === 0) notes.push(`规则集「${set.name}」当前没有生效规则，不会参与匹配。`)
    if (isPaused(set)) notes.push(`规则集「${set.name}」的来源订阅已暂停自动刷新，当前仍使用已加入方案的快照。`)
  }
  const declaredGroups = new Set(scheme.groups.map((group) => group.name))
  for (const set of scheme.ruleSets ?? []) {
    if (!declaredGroups.has(set.group)) notes.push(`规则集「${set.name}」指向的策略组「${set.group}」不存在。`)
  }

  return {
    scheme: prepared,
    nodes: options.nodes,
    displayNameByNodeID,
    nodeByDisplayName,
    resolvedMembers,
    groupsByName: new Map(prepared.groups.map((group) => [group.name, { name: group.name, type: group.type }])),
    origins,
    ruleSets: scheme.ruleSets ?? [],
    pausedSetNames,
    notes,
    latencyByNodeId: options.latencyByNodeId ?? {},
  }
}

function fallbackEvaluation(rule: RoutingRule): RuleEvaluation {
  const type = (rule.type ?? '').toUpperCase()
  return {
    status: 'match',
    matchType: '兜底规则',
    detail: type === 'MATCH' ? 'MATCH 兜底：前面的规则都没有命中' : 'FINAL 兜底：前面的规则都没有命中',
  }
}

function originFor(compiled: CompiledScheme, rule: RoutingRule): RuleOrigin {
  const known = compiled.origins.get(ruleKey(rule))
  if (known) return known
  if (rule.sourceName) {
    const set = compiled.ruleSets.find((item) => item.name === rule.sourceName)
    return {
      source: rule.sourceName,
      kind: set?.sourceKind ?? 'library',
      group: rule.group,
      setName: rule.sourceName,
    }
  }
  return { source: '方案规则', kind: 'scheme', group: rule.group }
}

function evaluateRuleSetReference(
  compiled: CompiledScheme,
  rule: RoutingRule,
  target: QueryTarget,
): { evaluation: RuleEvaluation; note?: string } {
  const value = rule.value ?? ''
  const set = compiled.ruleSets.find(
    (item) => item.name === rule.sourceName || item.sourceRef === value || item.name === value || item.id === value,
  )
  if (!set) {
    return {
      evaluation: {
        status: 'unknown',
        matchType: '规则集引用',
        reason: `找不到规则集「${rule.sourceName ?? value}」，无法展开判断`,
      },
    }
  }
  if (!set.rules.length) {
    return {
      evaluation: {
        status: 'skip',
        matchType: '规则集引用',
        reason: `规则集「${set.name}」是空的（0 条规则）`,
      },
    }
  }
  const paused = compiled.pausedSetNames.has(set.name) || (set.sourceRef ? compiled.pausedSetNames.has(set.sourceRef) : false)
  for (let index = 0; index < set.rules.length; index += 1) {
    const child = set.rules[index]
    const result = evaluateRule(child, target)
    if (result.status === 'match') {
      return {
        evaluation: {
          status: 'match',
          matchType: '规则集引用',
          detail: `展开「${set.name}」第 ${index + 1} 条 ${child.type},${child.value ?? ''}`,
        },
        note: paused ? '来源订阅已暂停自动刷新，使用方案内快照' : undefined,
      }
    }
  }
  return {
    evaluation: {
      status: 'miss',
      matchType: '规则集引用',
      detail: `展开「${set.name}」共 ${set.rules.length} 条，全部未命中`,
    },
    note: paused ? '来源订阅已暂停自动刷新，使用方案内快照' : undefined,
  }
}

interface NodeChoice {
  node?: string
  note?: string
  groupType?: string
  candidates: number
  groupRefs: number
}

function pickNodeForGroup(
  compiled: CompiledScheme,
  groupName: string,
  visited: Set<string>,
): NodeChoice {
  const group = compiled.scheme.groups.find((item) => item.name === groupName)
  if (!group) {
    return { candidates: 0, groupRefs: 0, note: `策略组「${groupName}」不存在` }
  }
  if (visited.has(group.name)) {
    return { candidates: 0, groupRefs: 0, note: `策略组「${group.name}」存在循环引用` }
  }
  visited.add(group.name)
  const members = compiled.resolvedMembers.get(group.name) ?? []
  const nodeMembers = members.filter((name) => compiled.nodeByDisplayName.has(name))
  const groupMembers = members.filter((name) => compiled.groupsByName.has(name))
  const builtin = members.find((name) => ['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE'].includes(name.toUpperCase()))
  const candidates = nodeMembers.length

  if (group.type === 'relay') {
    const chain = members.map((name) => {
      if (compiled.nodeByDisplayName.has(name)) return name
      if (compiled.groupsByName.has(name)) return `[${name}]`
      return name
    })
    return { candidates, groupRefs: groupMembers.length, groupType: group.type, note: chain.length ? `链式代理：${chain.join(' → ')}` : '链式代理没有候选' }
  }
  if (group.type === 'select') {
    const first = members[0]
    if (!first) return { candidates, groupRefs: groupMembers.length, groupType: group.type, note: '没有候选成员' }
    if (compiled.nodeByDisplayName.has(first)) {
      return { node: first, candidates, groupRefs: groupMembers.length, groupType: group.type }
    }
    if (compiled.groupsByName.has(first)) {
      const nested = pickNodeForGroup(compiled, first, visited)
      return {
        node: nested.node,
        candidates,
        groupRefs: groupMembers.length,
        groupType: group.type,
        note: nested.note ?? (nested.node ? `首选「${first}」，实际走 ${nested.node}` : `首选「${first}」没有可用节点`),
      }
    }
    if (['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE'].includes(first.toUpperCase())) {
      return { node: first.toUpperCase(), candidates, groupRefs: groupMembers.length, groupType: group.type, note: `首选内置策略 ${first.toUpperCase()}，不经过节点` }
    }
    return { candidates, groupRefs: groupMembers.length, groupType: group.type, note: `首选「${first}」既不是节点也不是策略组` }
  }
  if (group.type === 'load-balance') {
    return {
      node: undefined,
      candidates,
      groupRefs: groupMembers.length,
      groupType: group.type,
      note: candidates
        ? `按负载均衡算法在 ${candidates} 个候选间分配，单次连接无法离线确定`
        : '没有可用候选节点',
    }
  }
  if (group.type === 'fallback') {
    const first = nodeMembers[0]
    return {
      node: first,
      candidates,
      groupRefs: groupMembers.length,
      groupType: group.type,
      note: first
        ? `按候选顺序选择第一个可用节点（${first}），可用性由客户端健康检查决定`
        : candidates ? '候选暂时没有可用节点，客户端健康检查后决定' : '没有可用候选节点',
    }
  }
  if (group.type === 'url-test' || group.type === 'smart') {
    let fastest: { name: string; ms: number } | undefined
    for (const name of nodeMembers) {
      const node = compiled.nodeByDisplayName.get(name)
      const ms = node ? compiled.latencyByNodeId[node.id] : null
      if (typeof ms === 'number' && (!fastest || ms < fastest.ms)) fastest = { name, ms }
    }
    if (fastest) {
      return {
        node: fastest.name,
        candidates,
        groupRefs: groupMembers.length,
        groupType: group.type,
        note: `按当前测速结果自动选择 ${fastest.name}（${fastest.ms}ms）；客户端运行时会重新测速`,
      }
    }
    return {
      node: undefined,
      candidates,
      groupRefs: groupMembers.length,
      groupType: group.type,
      note: candidates
        ? `自动测速选择（${candidates} 个候选暂无测速结果，客户端运行时再决定）`
        : '没有可用候选节点',
    }
  }
  if (group.type === 'conditional') {
    return {
      node: undefined,
      candidates,
      groupRefs: groupMembers.length,
      groupType: group.type,
      note: '条件策略组按 Wi-Fi / 蜂窝 / 子网条件选择，需客户端运行状态',
    }
  }
  if (builtin) {
    return { node: builtin.toUpperCase(), candidates, groupRefs: groupMembers.length, groupType: group.type, note: '直接使用内置策略' }
  }
  return { node: nodeMembers[0], candidates, groupRefs: groupMembers.length, groupType: group.type }
}

/** 对一次输入执行完整链路判定。 */
export function explainWith(compiled: CompiledScheme, raw: string): ExplainResult {
  const target = parseQuery(raw)
  const steps: ExplainedStep[] = []
  let matchStep: ExplainedStep | undefined

  for (let index = 0; index < compiled.scheme.rules.length; index += 1) {
    const rule = compiled.scheme.rules[index]
    let evaluation: RuleEvaluation
    let ruleSetNote: string | undefined
    const ruleType = (rule.type ?? '').toUpperCase()
    if (ruleType === 'RULE-SET') {
      const expanded = evaluateRuleSetReference(compiled, rule, target)
      evaluation = expanded.evaluation
      ruleSetNote = expanded.note
    } else if (ruleType === 'FINAL' || ruleType === 'MATCH') {
      evaluation = fallbackEvaluation(rule)
    } else {
      evaluation = evaluateRule(rule, target)
    }
    const step: ExplainedStep = {
      index: index + 1,
      rule,
      origin: originFor(compiled, rule),
      evaluation,
      ruleSetNote,
    }
    steps.push(step)
    if (evaluation.status === 'match') {
      matchStep = step
      break
    }
  }

  const matchedRule = matchStep?.rule
  const matchedType = (matchedRule?.type ?? '').toUpperCase()
  const isFallback = !!matchedRule && (matchedType === 'FINAL' || matchedType === 'MATCH')
  const groupName = matchedRule?.group
  const group = groupName ? compiled.groupsByName.get(groupName) : undefined
  let final: ExplainFinal

  if (!matchedRule) {
    final = {
      isFallback: false,
      candidates: 0,
      steps: steps.length,
      note: target.kind === 'unknown'
        ? `输入无法解析：${target.note ?? '格式不正确'}`
        : '规则列表里没有兜底规则（FINAL / MATCH），客户端会按自身默认策略处理或拒绝连接',
    }
  } else if (!groupName) {
    final = { isFallback, candidates: 0, steps: steps.length, note: '规则没有指向策略组' }
  } else if (['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE'].includes(groupName.toUpperCase())) {
    final = {
      group: groupName,
      groupType: '内置策略',
      candidates: 0,
      node: groupName.toUpperCase(),
      note: '直接使用客户端内置策略，不经过节点',
      isFallback,
      steps: steps.length,
      origin: matchStep?.origin,
    }
  } else {
    const choice = pickNodeForGroup(compiled, groupName, new Set())
    final = {
      group: groupName,
      groupType: group?.type,
      candidates: choice.candidates,
      node: choice.node,
      note: choice.note,
      isFallback,
      steps: steps.length,
      origin: matchStep?.origin,
    }
    if (choice.groupRefs > 0) {
      final.note = `${final.note ? `${final.note}；` : ''}另有 ${choice.groupRefs} 个候选是策略组引用`
    }
  }

  if (matchStep) {
    let uncertain = 0
    for (const step of steps) {
      if (step === matchStep) break
      if (step.evaluation.status === 'skip' || step.evaluation.status === 'unknown') uncertain += 1
    }
    if (uncertain > 0) {
      final.note = `${final.note ? `${final.note}；` : ''}命中前有 ${uncertain} 条规则需要 DNS / 数据库 / 运行状态才能判定，实际客户端可能提前命中`
    }
  }

  return {
    target,
    steps,
    match: matchStep,
    final,
    notes: compiled.notes,
    totalRules: compiled.scheme.rules.length,
  }
}

export function explainQuery(options: CompileExplainOptions, raw: string): ExplainResult {
  return explainWith(compileScheme(options), raw)
}

export type { RuleStepStatus }
