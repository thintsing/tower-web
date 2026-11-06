// 方案 lint：默认只提示，不硬阻断导出。所有判断复用导出管线的规则顺序、策略组解析和客户端兼容性。
import type { ClientInfo, LocalRuleSet, PolicyGroup, ProxyNode, RuleScheme, RuleSetExclusionTable, RoutingRule } from '../models/types'
import { CLIENTS } from '../models/types'
import { prepareSchemeForExport, resolveGroups, uniqueDisplayNames } from '../generator/groups'
import { analyzeRuleCompatibility } from '../generator/compatibility'
import { validateSchemePolicy } from './policyValidation'
import { DOMAIN_TYPES } from './ruleMatcher'
import { ruleSignature } from './ruleDiff'
import { isTerminalRule } from './ruleKeys'
import { filterExcludedRuleSets, isReadOnlyRuleSet } from './ruleSetExclusions'

export type LintLevel = 'error' | 'warn' | 'info'

export type LintLocationKind = 'rule' | 'group' | 'ruleSet' | 'target'

export interface LintLocation {
  kind: LintLocationKind
  /** 规则所在的策略组，便于直接打开该组的规则页。 */
  group?: string
  /** 规则原文（TYPE,value），用于跳转后定位。 */
  rule?: string
  ruleIndex?: number
  ruleType?: string
  ruleSet?: string
  target?: string
}

export interface SchemeLintIssue {
  id: string
  level: LintLevel
  code: string
  message: string
  location: LintLocation
  /** 进一步的修正建议。 */
  hint?: string
  /** 是否允许一键删除；跨组遮蔽或前置规则已失效时为 false。 */
  deletable?: boolean
  /** 跨组重复时，保留的那条规则所在策略组。 */
  firstGroup?: string
  /** 跨组重复时，前一条来自在线 / 内置只读规则集（刷新后可能消失）。 */
  firstReadOnly?: boolean
  /** 需要处理的这一条本身来自只读规则集；删除是假删除，只能屏蔽。 */
  sourceSetId?: string
  sourceSetName?: string
  sourceReadOnly?: boolean
  /** 这一条规则的签名；用于精确屏蔽，刷新后仍能定位。 */
  ruleSignature?: string
  /** 跨组 / 同组重复时，前一条本身已失效；此时不可动。 */
  firstDead?: boolean
}

export interface SchemeLintOptions {
  scheme: RuleScheme
  nodes: ProxyNode[]
  policySelections?: Record<string, string>
  localRuleSets?: LocalRuleSet[]
  preferRuleSets?: boolean
  clients?: ClientInfo[]
  /** 只读规则集的本地屏蔽表；被屏蔽的条目不再参与检查。 */
  ruleSetExclusions?: RuleSetExclusionTable
}

export interface SchemeLintSummary {
  error: number
  warn: number
  info: number
  total: number
}

const AUTO_GROUP_TYPES = new Set(['url-test', 'fallback', 'load-balance', 'smart'])

function ruleText(rule: RoutingRule): string {
  if (rule.raw) return rule.raw
  return `${rule.type}${rule.value ? `,${rule.value}` : ''}`
}

function normalizeDomain(value: string | undefined): string {
  return (value ?? '').trim().toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '')
}

/** 与 ruleDiff 的签名一致：忽略域名大小写 / 首尾点、选项顺序与空白。 */
function ruleKey(rule: RoutingRule): string {
  return ruleSignature(rule)
}

function locationForRule(rule: RoutingRule, index: number): LintLocation {
  return {
    kind: 'rule',
    group: rule.group,
    rule: ruleText(rule),
    ruleIndex: index,
    ruleType: rule.type,
  }
}

/** 目标规则是否来自只读规则集；决定「可删除」还是「只能屏蔽」。 */
function provenanceOf(rule: RoutingRule, readOnlySetIDs: Set<string>) {
  if (!rule.sourceSetId) return {}
  return {
    sourceSetId: rule.sourceSetId,
    sourceSetName: rule.sourceName,
    sourceReadOnly: readOnlySetIDs.has(rule.sourceSetId) || undefined,
    ruleSignature: ruleKey(rule),
  }
}

function ancestorSuffixes(value: string): string[] {
  const domain = normalizeDomain(value)
  if (!domain) return []
  const parts = domain.split('.')
  const out: string[] = []
  for (let index = 0; index < parts.length; index += 1) {
    out.push(parts.slice(index).join('.'))
  }
  return out
}

/** 域名死规则检测：被更宽的域名后缀 / 关键词规则完全覆盖。 */
function findShadowedDomainRules(rules: RoutingRule[], readOnlySetIDs: Set<string>): SchemeLintIssue[] {
  const issues: SchemeLintIssue[] = []
  const firstSuffix = new Map<string, { index: number; rule: RoutingRule }>()
  const firstExact = new Map<string, { index: number; rule: RoutingRule }>()
  const keywords: Array<{ index: number; rule: RoutingRule; keyword: string }> = []
  const seenKeys = new Set<string>()

  rules.forEach((rule, index) => {
    const type = (rule.type ?? '').toUpperCase()
    const value = normalizeDomain(rule.value)
    if (!DOMAIN_TYPES.has(type) || !value) return
    // 完全相同的规则交给 findDuplicateRules 上报，避免同一行同时刷出「重复」和「死规则」。
    const duplicatedEarlier = seenKeys.has(ruleKey(rule))
    seenKeys.add(ruleKey(rule))

    let coveredBy: { index: number; rule: RoutingRule } | undefined
    let reason = ''

    if (!duplicatedEarlier && (type === 'DOMAIN' || type === 'DOMAIN-SUFFIX')) {
      for (const suffix of ancestorSuffixes(value)) {
        const existing = firstSuffix.get(suffix)
        const samePattern = existing?.rule.type === type && normalizeDomain(existing.rule.value) === value
        if (existing && !samePattern && (!coveredBy || existing.index < coveredBy.index)) {
          coveredBy = existing
          reason = `被更宽的后缀规则 ${ruleText(existing.rule)} 覆盖`
        }
      }
      const exact = firstExact.get(value)
      if (type === 'DOMAIN' && exact && (!coveredBy || exact.index < coveredBy.index)) {
        coveredBy = exact
        reason = `被前面的精确规则 ${ruleText(exact.rule)} 覆盖`
      }
      for (const item of keywords) {
        if (value.includes(item.keyword) && (!coveredBy || item.index < coveredBy.index)) {
          coveredBy = { index: item.index, rule: item.rule }
          reason = `被关键词规则 ${ruleText(item.rule)} 覆盖`
        }
      }
    } else if (type === 'DOMAIN-KEYWORD') {
      for (const item of keywords) {
        if (item.keyword !== value && value.includes(item.keyword) && (!coveredBy || item.index < coveredBy.index)) {
          coveredBy = { index: item.index, rule: item.rule }
          reason = `被更短的关键词规则 ${ruleText(item.rule)} 覆盖`
        }
      }
    }

    if (coveredBy) {
      const provenance = provenanceOf(rule, readOnlySetIDs)
      const readOnly = provenance.sourceReadOnly === true
      issues.push({
        id: `dead:${index}`,
        level: 'info',
        code: 'shadowedRule',
        message: readOnly
          ? `规则 ${ruleText(rule)} 永远不会命中：${reason}；它来自只读规则集「${rule.sourceName ?? rule.sourceSetId}」，直接删除会在刷新后恢复`
          : `规则 ${ruleText(rule)} 永远不会命中：${reason}`,
        hint: readOnly
          ? '来源是只读规则集，请用「屏蔽」把它从编译与导出中排除；屏蔽可能改变去向'
          : '前序规则已经覆盖同样的请求，可删除这一条或调整顺序',
        deletable: !readOnly,
        ...provenance,
        location: locationForRule(rule, index),
      })
    }

    if (type === 'DOMAIN-SUFFIX' && !firstSuffix.has(value)) firstSuffix.set(value, { index, rule })
    if (type === 'DOMAIN' && !firstExact.has(value)) firstExact.set(value, { index, rule })
    if (type === 'DOMAIN-KEYWORD') keywords.push({ index, rule, keyword: value })
  })
  return issues
}

function findDuplicateRules(
  rules: RoutingRule[],
  dead: Set<number> = new Set(),
  readOnlyFirst: Set<string> = new Set(),
  readOnlySetIDs: Set<string> = new Set(),
): SchemeLintIssue[] {
  const issues: SchemeLintIssue[] = []
  const seen = new Map<string, { index: number; rule: RoutingRule }>()
  rules.forEach((rule, index) => {
    if (isTerminalRule(rule)) return
    const key = ruleKey(rule)
    const existing = seen.get(key)
    if (!existing) {
      seen.set(key, { index, rule })
      return
    }
    const firstDead = dead.has(existing.index)
    const firstReadOnly = readOnlyFirst.has(`${key}\0${existing.rule.group}`)
    const provenance = provenanceOf(rule, readOnlySetIDs)
    const targetReadOnly = provenance.sourceReadOnly === true
    if (existing.rule.group === rule.group) {
      issues.push({
        id: `dup:${index}`,
        level: 'info',
        code: 'duplicateRuleSameGroup',
        message: targetReadOnly
          ? `规则 ${ruleText(rule)} 与第 ${existing.index + 1} 条完全重复（同一个策略组）；这一条来自只读规则集「${rule.sourceName ?? rule.sourceSetId}」，直接删除会在刷新后恢复`
          : firstDead
            ? `规则 ${ruleText(rule)} 与第 ${existing.index + 1} 条重复（同一个策略组）；但第 ${existing.index + 1} 条本身已被更前面的规则遮蔽，不能据此判断后一条是否命中`
            : `规则 ${ruleText(rule)} 与第 ${existing.index + 1} 条完全重复（同一个策略组）`,
        hint: targetReadOnly
          ? '只读来源不能直接删除；用「屏蔽」把它从编译与导出中排除，屏蔽可能改变去向'
          : firstDead
            ? '两条规则都已被更前面的规则遮蔽；清理前需要先确认前置规则的顺序'
            : '重复规则不会改变结果，可以删除一条保持整洁',
        deletable: !firstDead && !targetReadOnly,
        firstDead: firstDead || undefined,
        ...provenance,
        location: locationForRule(rule, index),
      })
    } else {
      issues.push({
        id: `dup:${index}`,
        level: 'info',
        code: 'duplicateRule',
        message: targetReadOnly
          ? `规则 ${ruleText(rule)} 与第 ${existing.index + 1} 条等价（策略组 ${rule.group} / ${existing.rule.group}）；这一条来自只读规则集「${rule.sourceName ?? rule.sourceSetId}」，直接删除会在刷新后恢复`
          : firstDead
            ? `规则 ${ruleText(rule)} 与第 ${existing.index + 1} 条等价，但第 ${existing.index + 1} 条本身已被更前面的规则遮蔽，不能据此判断后一条是否命中（策略组 ${rule.group} / ${existing.rule.group}）`
            : firstReadOnly
              ? `规则 ${ruleText(rule)} 与第 ${existing.index + 1} 条等价（策略组 ${rule.group} / ${existing.rule.group}）；但前一条位于在线 / 内置只读规则集，刷新后可能消失`
              : `规则 ${ruleText(rule)} 与第 ${existing.index + 1} 条完全重复，后一条永远不会命中（策略组 ${rule.group} 被前一条 ${existing.rule.group} 遮蔽）`,
        hint: targetReadOnly
          ? '只读来源不能直接删除；用「屏蔽」把它从编译与导出中排除，屏蔽可能改变去向'
          : firstDead
            ? '前一条已失效，先处理遮蔽它的规则；不要直接删除后一条'
            : firstReadOnly
              ? '前一条来自只读规则集，刷新后可能不再存在；先确认来源，别直接删后一条'
              : `保留「${existing.rule.group}」，从「${rule.group}」删除；两处命中结果相同`,
        deletable: !firstDead && !targetReadOnly && !firstReadOnly,
        firstGroup: existing.rule.group,
        firstReadOnly: firstReadOnly || undefined,
        firstDead: firstDead || undefined,
        ...provenance,
        location: locationForRule(rule, index),
      })
    }
  })
  return issues
}

/** 只读规则集里的规则签名 + 策略组；用于判断前一条是否会在刷新后消失。 */
function readOnlyRuleKeys(scheme: RuleScheme): Set<string> {
  const keys = new Set<string>()
  for (const set of scheme.ruleSets ?? []) {
    if (!isReadOnlyRuleSet(set)) continue
    for (const rule of set.rules) keys.add(`${ruleKey(rule)}\0${set.group}`)
  }
  return keys
}

/** 只读规则集 id；用于判断要处理的这一条是否只能屏蔽。 */
function readOnlySetIDsOf(scheme: RuleScheme): Set<string> {
  return new Set((scheme.ruleSets ?? []).filter(isReadOnlyRuleSet).map((set) => set.id))
}

/**
 * 本身不可达的规则下标：被更宽的域名/关键词规则遮蔽，或排在 FINAL/MATCH 之后。
 * 清理重复前必须先排除这些「前一条」，否则会把假阳性当成安全删除。
 */
export function shadowedRuleIndexes(rules: RoutingRule[]): Set<number> {
  const dead = new Set<number>()
  for (const issue of findShadowedDomainRules(rules, new Set())) {
    if (issue.location.ruleIndex !== undefined) dead.add(issue.location.ruleIndex)
  }
  const terminal = rules.findIndex((rule) => isTerminalRule(rule))
  if (terminal >= 0) {
    for (let index = terminal + 1; index < rules.length; index += 1) dead.add(index)
  }
  return dead
}

function groupNodeCount(group: PolicyGroup, nodes: ProxyNode[]): number {
  if (!group.nodeFilter) return 0
  let regex: RegExp
  try {
    regex = new RegExp(group.nodeFilter)
  } catch {
    return 0
  }
  return nodes.filter((node) => regex.test(node.name)).length
}

function findGroupIssues(options: SchemeLintOptions, prepared: RuleScheme): SchemeLintIssue[] {
  const nodes = options.nodes
  const issues: SchemeLintIssue[] = []
  const policyIssues = validateSchemePolicy(prepared, nodes.map((node) => node.name), nodes.length === 0)
  const emptyGroups = new Set(policyIssues.filter((issue) => issue.code === 'emptyGroup').map((issue) => issue.names[0]))

  for (const issue of policyIssues) {
    const group = issue.names[0]
    const location: LintLocation = { kind: 'group', group }
    if (issue.code === 'duplicateGroupName') {
      issues.push({
        id: `group:duplicate:${group}`,
        level: 'error',
        code: 'duplicateGroup',
        message: `策略组名称「${group}」重复`,
        hint: '客户端会把它当成两个组，规则可能指向错误的组',
        location,
      })
    } else if (issue.code === 'unknownGroupMember') {
      const member = issue.names[1]
      issues.push({
        id: `group:member:${group}:${member}`,
        level: 'error',
        code: 'missingGroupMember',
        message: `策略组「${group}」的候选「${member}」既不是节点也不是已定义的策略组`,
        hint: '删除该候选，或先创建同名策略组',
        location,
      })
    } else if (issue.code === 'unknownRuleTarget') {
      const target = issue.names[0]
      issues.push({
        id: `rule-target:${target}`,
        level: 'error',
        code: 'missingRuleTarget',
        message: `规则指向的策略组「${target}」不存在`,
        hint: '在规则方案里补上该策略组，或把规则改指向已有策略组',
        location: { kind: 'group', group: target },
      })
    } else if (issue.code === 'cycle') {
      issues.push({
        id: `group:cycle:${issue.names.join('>')}`,
        level: 'error',
        code: 'groupCycle',
        message: `策略组循环引用：${issue.names.join(' → ')}`,
        hint: '移除循环中的一个候选引用',
        location,
      })
    } else if (issue.code === 'invalidNodePattern') {
      issues.push({
        id: `group:pattern:${group}`,
        level: 'error',
        code: 'invalidNodePattern',
        message: `策略组「${group}」的节点名称匹配不是有效正则：${issue.names[1] ?? ''}`,
        hint: '修正正则表达式，例如「韩国|KR」',
        location,
      })
    } else if (issue.code === 'emptyGroup') {
      issues.push({
        id: `group:empty:${group}`,
        level: 'error',
        code: 'emptyGroup',
        message: `策略组「${group}」没有可用候选（候选组和节点名称匹配都没有结果）`,
        hint: '检查候选策略、节点名称匹配，或先启用节点',
        location,
      })
    }
  }

  const displayNameByNodeID = uniqueDisplayNames(nodes, (value) => value)
  const displayNames = new Set(nodes.map((node) => displayNameByNodeID.get(node.id) ?? node.name))
  const resolved = resolveGroups(prepared, nodes, (node) => displayNameByNodeID.get(node.id) ?? node.name)

  for (const group of prepared.groups) {
    const matched = groupNodeCount(group, nodes)
    if (group.nodeFilter && nodes.length > 0 && matched === 0 && !emptyGroups.has(group.name)) {
      issues.push({
        id: `group:regex-empty:${group.name}`,
        level: 'warn',
        code: 'nodeFilterMatchesNothing',
        message: `策略组「${group.name}」的节点名称匹配（${group.nodeFilter}）匹配不到任何启用节点`,
        hint: '检查正则表达式，或确认相关节点已启用',
        location: { kind: 'group', group: group.name },
      })
    }
    const members = resolved.find((item) => item.group.name === group.name)?.members ?? []
    const nodeMembers = members.filter((name) => displayNames.has(name))
    const groupMembers = members.filter((name) => prepared.groups.some((item) => item.name === name))
    if (AUTO_GROUP_TYPES.has(group.type)) {
      if (nodeMembers.length === 1) {
        issues.push({
          id: `group:type:${group.name}`,
          level: 'warn',
          code: 'groupTypeCandidateMismatch',
          message: `策略组「${group.name}」是 ${group.type}，但只有 1 个候选节点，自动选择没有意义`,
          hint: '改用 select，或让节点名称匹配包含更多节点',
          location: { kind: 'group', group: group.name },
        })
      } else if (nodeMembers.length === 0 && groupMembers.length === 0 && !emptyGroups.has(group.name)) {
        issues.push({
          id: `group:type-empty:${group.name}`,
          level: 'error',
          code: 'groupNoCandidates',
          message: `策略组「${group.name}」是 ${group.type}，但没有任何候选节点`,
          location: { kind: 'group', group: group.name },
        })
      }
    }
    if (group.type === 'select' && members.length === 0 && !emptyGroups.has(group.name)) {
      issues.push({
        id: `group:select-empty:${group.name}`,
        level: 'error',
        code: 'selectGroupEmpty',
        message: `策略组「${group.name}」没有候选成员`,
        location: { kind: 'group', group: group.name },
      })
    }
  }
  return issues
}

function findRuleSetIssues(options: SchemeLintOptions, prepared: RuleScheme): SchemeLintIssue[] {
  const issues: SchemeLintIssue[] = []
  const declared = new Set(prepared.groups.map((group) => group.name))
  const localSets = new Map((options.localRuleSets ?? []).map((set) => [set.id, set]))
  for (const set of prepared.ruleSets ?? []) {
    if (!set.rules.length) {
      issues.push({
        id: `ruleset:empty:${set.id}`,
        level: 'warn',
        code: 'emptyRuleSet',
        message: `规则集「${set.name}」当前没有生效规则（为空或已被屏蔽），加入方案不会产生任何规则`,
        hint: '刷新该规则集，或从方案中移除',
        location: { kind: 'ruleSet', ruleSet: set.name, group: set.group },
      })
    }
    if (!declared.has(set.group)) {
      issues.push({
        id: `ruleset:group:${set.id}`,
        level: 'error',
        code: 'ruleSetMissingGroup',
        message: `规则集「${set.name}」引用了不存在的策略组「${set.group}」`,
        hint: '重新选择该规则集的策略组',
        location: { kind: 'ruleSet', ruleSet: set.name, group: set.group },
      })
    }
    const source = set.sourceRef ? localSets.get(set.sourceRef) : undefined
    if (source?.paused) {
      issues.push({
        id: `ruleset:paused:${set.id}`,
        level: 'info',
        code: 'ruleSetSourcePaused',
        message: `规则集「${set.name}」的来源订阅已暂停自动刷新，当前使用方案内快照`,
        location: { kind: 'ruleSet', ruleSet: set.name, group: set.group },
      })
    }
    if (source && source.rules.length === 0) {
      issues.push({
        id: `ruleset:source-empty:${set.id}`,
        level: 'warn',
        code: 'ruleSetSourceEmpty',
        message: `规则集「${set.name}」对应的本地规则集是空的`,
        location: { kind: 'ruleSet', ruleSet: set.name, group: set.group },
      })
    }
  }
  return issues
}

function findCompatibilityIssues(options: SchemeLintOptions): SchemeLintIssue[] {
  const clients = options.clients ?? CLIENTS
  const issues: SchemeLintIssue[] = []
  for (const client of clients) {
    if (client.contentMode === 'nodes') continue
    const compatibility = analyzeRuleCompatibility(client, options.scheme, {
      preferRuleSets: options.preferRuleSets,
      ruleSetExclusions: options.ruleSetExclusions,
    })
    if (compatibility.nodeOnly || compatibility.skipped === 0) continue
    const types = compatibility.unsupportedTypes.slice(0, 4).join('、')
    issues.push({
      id: `target:${client.target}`,
      level: 'warn',
      code: 'unsupportedRuleType',
      message: `${client.name} 会忽略 ${compatibility.skipped} 条规则${types ? `（${types}${compatibility.unsupportedTypes.length > 4 ? '…' : ''}）` : ''}`,
      hint: '换成支持的客户端导出，或在规则页调整这些规则',
      location: { kind: 'target', target: client.name },
    })
  }
  return issues
}

/** 运行完整检查。返回按 error → warn → info 排序的问题列表。 */
export function lintScheme(options: SchemeLintOptions): SchemeLintIssue[] {
  const scheme = filterExcludedRuleSets(options.scheme, options.ruleSetExclusions)
  const prepared = prepareSchemeForExport(scheme, options.policySelections ?? {}, {
    preferRuleSets: false,
    ruleSetExclusions: options.ruleSetExclusions,
  })
  const rules = prepared.rules
  const dead = shadowedRuleIndexes(rules)
  const readOnlyIDs = readOnlySetIDsOf(scheme)
  const issues = [
    ...findDuplicateRules(rules, dead, readOnlyRuleKeys(scheme), readOnlyIDs),
    ...findShadowedDomainRules(rules, readOnlyIDs),
    ...findGroupIssues(options, prepared),
    ...findRuleSetIssues(options, prepared),
    ...findCompatibilityIssues(options),
  ]
  const rank: Record<LintLevel, number> = { error: 0, warn: 1, info: 2 }
  return issues.sort((left, right) => rank[left.level] - rank[right.level])
}

export function lintSummary(issues: SchemeLintIssue[]): SchemeLintSummary {
  return {
    error: issues.filter((issue) => issue.level === 'error').length,
    warn: issues.filter((issue) => issue.level === 'warn').length,
    info: issues.filter((issue) => issue.level === 'info').length,
    total: issues.length,
  }
}
