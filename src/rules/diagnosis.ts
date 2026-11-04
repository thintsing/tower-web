// 规则诊断：把「命中 → 上下文 → 风险 → 修复 → 验证」串成一条链路。
// 这里只放纯逻辑，界面负责渲染与跳转。
import type { RuleScheme, RoutingRule, SchemeRuleSet } from '../models/types'
import type { ExplainResult, ExplainedStep } from './ruleExplain'
import type { SchemeLintIssue } from './schemeLint'
import type { RuleSetHistory } from './ruleSetHistory'
import {
  diffRules,
  filterDiff,
  ruleDisplayText,
  ruleIdentity,
  type DiffLine,
} from './ruleDiff'

export interface RankedIssue {
  issue: SchemeLintIssue
  /** 与当前查询的相关度，越大越靠前。 */
  score: number
  reasons: string[]
}

// 跨组重复（duplicateRule）删除后会改变流量去向，不属于「安全删除」。
const SAFE_DELETE_CODES = new Set(['duplicateRuleSameGroup', 'shadowedRule'])

const LEVEL_WEIGHT: Record<string, number> = { error: 0, warn: 1, info: 2 }

function lower(value: string | undefined): string {
  return (value ?? '').trim().toLowerCase()
}

/** 命中规则所在方案规则集；内联展开的规则按「同组 + 同文本」回查。 */
export function findMatchedRuleSet(scheme: RuleScheme, rule?: RoutingRule): SchemeRuleSet | undefined {
  if (!rule || !scheme.ruleSets?.length) return undefined
  if (rule.type === 'RULE-SET') {
    const byName = scheme.ruleSets.find((set) =>
      set.name === rule.sourceName || set.name === rule.value)
    if (byName) return byName
  }
  const text = lower(ruleDisplayText(rule))
  return scheme.ruleSets.find((set) =>
    set.group === rule.group
    && set.rules.some((item) => lower(ruleDisplayText(item)) === text))
}

function matchIndex(step: ExplainedStep): number {
  return step.index
}

/**
 * lint 结果按与当前查询的相关性排序：
 * 命中规则本身 > 命中规则集 > 命中路径上的遮蔽/重复 > 最终策略组 > 导出兼容性 > 无关项。
 * 未命中任何规则时，只保留导出兼容性这类通用风险。
 */
export function rankLintIssues(
  issues: SchemeLintIssue[],
  explain: ExplainResult,
  scheme: RuleScheme,
): RankedIssue[] {
  const match = explain.match
  const host = lower(explain.target.host)
  const matchedText = match ? lower(ruleDisplayText(match.rule)) : ''
  const matchedSet = match ? findMatchedRuleSet(scheme, match.rule) : undefined
  const finalGroup = explain.final.group
  const matchGroup = match?.rule.group ?? match?.origin.group

  const ranked = issues.map((issue, order) => {
    let score = 0
    const reasons: string[] = []
    const loc = issue.location
    const locText = lower(loc.rule)

    if (match) {
      if (loc.ruleIndex !== undefined && loc.ruleIndex + 1 === matchIndex(match)) {
        score += 200
        reasons.push('与命中规则是同一条')
      }
      if (locText && matchedText && (locText === matchedText || matchedText.startsWith(`${locText},`))) {
        score += 160
        reasons.push('命中规则本身')
      }
      if (loc.ruleSet && matchedSet && (loc.ruleSet === matchedSet.name || loc.ruleSet === matchedSet.id)) {
        score += 130
        reasons.push('命中点所在规则集')
      }
      if (loc.kind === 'ruleSet' && !loc.ruleSet && matchedSet && loc.group === matchedSet.group) {
        score += 100
        reasons.push('命中点所在规则集')
      }
      if (loc.ruleIndex !== undefined) {
        if (loc.ruleIndex + 1 < matchIndex(match)) {
          if (SAFE_DELETE_CODES.has(issue.code)) {
            score += 90
            reasons.push('排在命中之前，可能改变判定顺序')
          } else {
            score += 20
          }
        } else if (loc.ruleIndex + 1 > matchIndex(match)) {
          score += 10
        }
      }
      if (loc.group && finalGroup && loc.group === finalGroup) {
        score += 70
        reasons.push('决定最终策略组')
      } else if (loc.group && matchGroup && loc.group === matchGroup) {
        score += 50
        reasons.push('与命中规则同组')
      }
      if (host && locText && locText.includes(host)) {
        score += 40
        reasons.push('涉及这次查询的域名')
      }
    }

    if (loc.kind === 'target') {
      score += 30
      reasons.push('导出目标兼容性')
    }
    if (issue.level === 'error') score += 8
    else if (issue.level === 'warn') score += 4

    return { issue, score, reasons, order }
  })

  return ranked.sort((a, b) =>
    b.score - a.score
    || (LEVEL_WEIGHT[a.issue.level] ?? 9) - (LEVEL_WEIGHT[b.issue.level] ?? 9)
    || a.order - b.order)
}

export function splitRanked(ranked: RankedIssue[]): { relevant: RankedIssue[]; others: RankedIssue[] } {
  return {
    relevant: ranked.filter((item) => item.score > 0),
    others: ranked.filter((item) => item.score <= 0),
  }
}

export type MatchedChange = 'added' | 'removed' | 'modified' | 'unchanged' | 'not-found' | 'no-history'

export interface RuleSetChange {
  setName: string
  hasHistory: boolean
  /** 上次只存了摘要，没有规则明细，无法逐条对比。 */
  truncated: boolean
  added: number
  removed: number
  modified: number
  matched: MatchedChange
  sample: DiffLine[]
  paused: boolean
  empty: boolean
}

/** 命中规则所在规则集的最近变更摘要；没有历史时也明确返回 no-history。 */
export function describeRuleSetChange(
  set: SchemeRuleSet | undefined,
  history: RuleSetHistory | undefined,
  matchedRule?: RoutingRule,
): RuleSetChange | undefined {
  if (!set) return undefined
  const entry = (history?.[set.sourceRef ?? ''] ?? history?.[set.id])
  const previous = entry?.previous
  const base: RuleSetChange = {
    setName: set.name,
    hasHistory: !!previous,
    truncated: false,
    added: 0,
    removed: 0,
    modified: 0,
    matched: 'no-history',
    sample: [],
    paused: false,
    empty: set.rules.length === 0,
  }
  if (!previous) return base
  if (!previous.rules?.length) return { ...base, truncated: true }
  const diff = diffRules(previous.rules, set.rules)
  const identity = matchedRule ? ruleIdentity(matchedRule) : ''
  let matched: MatchedChange = 'not-found'
  if (identity) {
    if (diff.added.some((line) => line.identity === identity)) matched = 'added'
    else if (diff.removed.some((line) => line.identity === identity)) matched = 'removed'
    else if (diff.modified.some((line) => line.identity === identity)) matched = 'modified'
    else if (set.rules.some((rule) => ruleIdentity(rule) === identity)) matched = 'unchanged'
  }
  return {
    ...base,
    hasHistory: true,
    added: diff.added.length,
    removed: diff.removed.length,
    modified: diff.modified.length,
    matched,
    sample: filterDiff(diff, 'all').slice(0, 5),
  }
}

export type FixActionKind = 'delete-rule' | 'locate-group' | 'locate-rule-set' | 'go-export' | 'manual'

export interface FixAction {
  kind: FixActionKind
  label: string
  detail: string
  /** 能安全一键执行。 */
  safe?: boolean
  ruleText?: string
  group?: string
  ruleSet?: string
  ruleIndex?: number
  target?: string
}

/** 每条 lint 发现的可执行修复动作：能安全执行的在前面，其余给出确切改法。 */
export function buildFixActions(issue: SchemeLintIssue): FixAction[] {
  const loc = issue.location
  const locateGroup: FixAction | undefined = loc.group
    ? { kind: 'locate-group', label: `定位策略组「${loc.group}」`, detail: '打开策略组设置或规则列表，手动修正。', group: loc.group }
    : undefined
  const locateSet: FixAction | undefined = loc.ruleSet
    ? { kind: 'locate-rule-set', label: `定位规则集「${loc.ruleSet}」`, detail: '打开规则集详情，查看规则或刷新来源。', ruleSet: loc.ruleSet }
    : undefined
  const goExport: FixAction = { kind: 'go-export', label: '去导出页调整客户端', detail: '在导出页选择支持这些规则的客户端，或关闭该客户端的导出。' }

  if (SAFE_DELETE_CODES.has(issue.code) && issue.deletable !== false) {
    const readOnlySetNote = '若这条规则来自在线 / 订阅规则集，删除只对当前方案快照生效，刷新规则集后会恢复。'
    return [
      {
        kind: 'delete-rule',
        label: issue.code === 'shadowedRule' ? '删除这条永远不命中的规则' : '删除重复的后一条规则',
        detail: issue.code === 'shadowedRule'
          ? `它被前面的规则完全覆盖，删除不会改变任何匹配结果。${readOnlySetNote}`
          : `保留前面那条即可，删除不会改变匹配结果。${readOnlySetNote}`,
        safe: true,
        ruleText: loc.rule,
        group: loc.group,
        ruleIndex: loc.ruleIndex,
      },
      ...(locateGroup ? [locateGroup] : []),
      ...(locateSet ? [locateSet] : []),
    ]
  }

  const actions: FixAction[] = []
  switch (issue.code) {
    case 'duplicateRule':
      actions.push({
        kind: 'manual',
        label: '需你决定：删除后一条或调整前一条策略组',
        detail: '两条规则等价但策略组不同，删除后一条会改变这些流量的去向。请确认意图后手动处理，或把它们移到前面并重排顺序。',
        group: loc.group,
        ruleText: loc.rule,
        ruleIndex: loc.ruleIndex,
      })
      break
    case 'duplicateRuleSameGroup':
      actions.push({
        kind: 'manual',
        label: '先处理遮蔽前一条的规则',
        detail: '前一条重复规则本身已被更前面的规则遮蔽，直接删后一条会让诊断结论失真；请先调整前置规则顺序。',
        group: loc.group,
        ruleText: loc.rule,
        ruleIndex: loc.ruleIndex,
      })
      break
    case 'missingRuleTarget':
      actions.push({
        kind: 'manual',
        label: '把规则改指向已有策略组',
        detail: `在规则组里找到指向「${loc.group ?? '未知组'}」的规则，改绑到一个真实存在的策略组；或先创建同名策略组。`,
        group: loc.group,
      })
      break
    case 'missingGroupMember':
      actions.push({
        kind: 'manual',
        label: '删除或补建这个候选',
        detail: '在策略组设置的候选策略里删掉不存在的名字，或先创建同名策略组再引用。',
        group: loc.group,
      })
      break
    case 'emptyGroup':
    case 'groupNoCandidates':
    case 'selectGroupEmpty':
      actions.push({
        kind: 'manual',
        label: '给策略组添加候选',
        detail: '在策略组设置里选择节点组、内置策略或填写节点名称正则，确保至少有一个候选。',
        group: loc.group,
      })
      break
    case 'nodeFilterMatchesNothing':
    case 'groupTypeCandidateMismatch':
      actions.push({
        kind: 'manual',
        label: '放宽节点名称匹配',
        detail: '把节点名称正则改得更宽（例如「香港|HK」），或换回固定候选策略。',
        group: loc.group,
      })
      break
    case 'invalidNodePattern':
      actions.push({
        kind: 'manual',
        label: '修正节点名称正则',
        detail: '改成合法正则，例如「香港|HK」；保存后重新运行检查。',
        group: loc.group,
      })
      break
    case 'duplicateGroup':
      actions.push({
        kind: 'manual',
        label: '合并或重命名重复策略组',
        detail: '保留一个组，把规则和候选统一指向它；另一个组改名或删除。',
        group: loc.group,
      })
      break
    case 'groupCycle':
      actions.push({
        kind: 'manual',
        label: '移除循环引用',
        detail: '在循环里挑一个策略组，从候选策略里删掉指向自己的那条引用。',
        group: loc.group,
      })
      break
    case 'emptyRuleSet':
      actions.push({
        kind: 'manual',
        label: '补充或移除空规则集',
        detail: '规则集里没有规则，不会命中任何流量；刷新来源，或从方案中移除它。',
        ruleSet: loc.ruleSet,
      })
      break
    case 'ruleSetMissingGroup':
      actions.push({
        kind: 'manual',
        label: '给规则集指定有效策略组',
        detail: '规则集指向的策略组不存在；在规则页改绑到一个已有策略组。',
        ruleSet: loc.ruleSet,
      })
      break
    case 'ruleSetSourcePaused':
      actions.push({
        kind: 'manual',
        label: '恢复规则集订阅',
        detail: '该在线规则集已暂停自动刷新；在规则集列表里恢复，或手动刷新一次。',
        ruleSet: loc.ruleSet,
      })
      break
    case 'ruleSetSourceEmpty':
      actions.push({
        kind: 'manual',
        label: '刷新规则集来源',
        detail: '远程规则集最近返回空内容；检查地址是否有效，刷新后重新检查。',
        ruleSet: loc.ruleSet,
      })
      break
    case 'unsupportedRuleType':
      actions.push({
        kind: 'manual',
        label: '改用目标客户端支持的规则类型',
        detail: issue.hint ?? `该客户端不支持 ${loc.ruleType ?? '这条规则'}；改成 DOMAIN-SUFFIX 等通用类型，或在导出设置里跳过该客户端。`,
        ruleText: loc.rule,
        target: loc.target,
      })
      actions.push(goExport)
      break
    default:
      actions.push({
        kind: 'manual',
        label: '查看并手动修正',
        detail: issue.hint ?? '打开对应规则组或规则集检查。',
        group: loc.group,
        ruleSet: loc.ruleSet,
      })
  }

  if (locateGroup) actions.push(locateGroup)
  if (locateSet) actions.push(locateSet)
  return actions
}

export interface ApplyFixResult {
  scheme: RuleScheme
  removedFrom: 'custom' | 'ruleset' | 'scheme'
  removedText: string
}

function sameRule(rule: RoutingRule, text: string, group?: string): boolean {
  const matchesText = lower(ruleDisplayText(rule)) === lower(text) || lower(rule.raw) === lower(text)
  if (!matchesText) return false
  return !group || rule.group === group
}

/** 一键修复：仅支持安全删除死规则/重复规则，删除最后一条匹配项。 */
export function applyFixAction(scheme: RuleScheme, action: FixAction): ApplyFixResult | null {
  if (action.kind !== 'delete-rule' || !action.ruleText) return null
  const text = action.ruleText
  const group = action.group

  const customRules = scheme.customRules ?? []
  for (let index = customRules.length - 1; index >= 0; index -= 1) {
    if (sameRule(customRules[index], text, group)) {
      const nextCustom = customRules.filter((_, i) => i !== index)
      return {
        scheme: { ...scheme, customRules: nextCustom },
        removedFrom: 'custom',
        removedText: ruleDisplayText(customRules[index]),
      }
    }
  }

  // 优先删方案规则，其次才是规则集：重复多半发生在方案内，
  // 改规则集等于改用户引用的整块规则，风险更高。
  for (let index = scheme.rules.length - 1; index >= 0; index -= 1) {
    const rule = scheme.rules[index]
    if (sameRule(rule, text, group)) {
      return {
        scheme: { ...scheme, rules: scheme.rules.filter((_, i) => i !== index) },
        removedFrom: 'scheme',
        removedText: ruleDisplayText(rule),
      }
    }
  }

  if (scheme.ruleSets?.length) {
    for (let setIndex = scheme.ruleSets.length - 1; setIndex >= 0; setIndex -= 1) {
      const set = scheme.ruleSets[setIndex]
      if (action.ruleSet && set.name !== action.ruleSet && set.id !== action.ruleSet) continue
      if (group && set.group !== group) continue
      for (let index = set.rules.length - 1; index >= 0; index -= 1) {
        const rule = set.rules[index]
        if (lower(ruleDisplayText(rule)) === lower(text)) {
          const nextSets = scheme.ruleSets.map((item, i) => i === setIndex
            ? { ...item, rules: item.rules.filter((_, j) => j !== index) }
            : item)
          return {
            scheme: { ...scheme, ruleSets: nextSets },
            removedFrom: 'ruleset',
            removedText: ruleDisplayText(rule),
          }
        }
      }
    }
  }
  return null
}
