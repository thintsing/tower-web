// 刷新在线规则集时复用固化预览的 diff：规范化后比对，结果留在规则集上供事后查看。
import type {
  RuleSetDiffSample,
  RuleSetRefreshDiff,
} from '../models/types'
import { diffRules, ruleDisplayText, type RuleSetRuleLike } from './ruleDiff'

/** 最多保留多少条具体变化；其余只留计数。 */
export const RULE_SET_DIFF_SAMPLE_LIMIT = 12

export function summarizeRuleSetRefresh(
  before: RuleSetRuleLike[],
  after: RuleSetRuleLike[],
  at = Date.now(),
): RuleSetRefreshDiff {
  const diff = diffRules(before, after)
  const samples: RuleSetDiffSample[] = []
  // 修改优先展示（能看出具体改了什么），其次新增、删除。
  for (const line of diff.modified) {
    if (samples.length >= RULE_SET_DIFF_SAMPLE_LIMIT) break
    samples.push({
      kind: 'modified',
      text: line.text,
      previous: line.before ? ruleDisplayText(line.before) : undefined,
    })
  }
  for (const line of diff.added) {
    if (samples.length >= RULE_SET_DIFF_SAMPLE_LIMIT) break
    samples.push({ kind: 'added', text: line.text })
  }
  for (const line of diff.removed) {
    if (samples.length >= RULE_SET_DIFF_SAMPLE_LIMIT) break
    samples.push({ kind: 'removed', text: line.text })
  }
  const total = diff.added.length + diff.removed.length + diff.modified.length
  return {
    added: diff.added.length,
    removed: diff.removed.length,
    modified: diff.modified.length,
    samples,
    hidden: total - samples.length,
    checkedAt: at,
  }
}

/** 把多个规则集的变化摘要汇总成一行总数（刷新全部时用）。 */
export function sumRuleSetDiffs(diffs: (RuleSetRefreshDiff | undefined)[]): {
  added: number
  removed: number
  modified: number
} {
  const total = { added: 0, removed: 0, modified: 0 }
  for (const diff of diffs) {
    if (!diff) continue
    total.added += diff.added
    total.removed += diff.removed
    total.modified += diff.modified
  }
  return total
}

/** 刷新成功：写入新规则、清空错误，并记录这次变化摘要。 */
export function ruleSetRefreshSuccess<T extends {
  rules: RuleSetRuleLike[]
  updatedAt?: number
  lastError?: string
  lastDiff?: RuleSetRefreshDiff
}>(set: T, rules: T['rules'], at = Date.now()): T {
  return {
    ...set,
    rules,
    updatedAt: at,
    lastError: undefined,
    lastDiff: summarizeRuleSetRefresh(set.rules, rules, at),
  }
}

/** 刷新失败：只记错误，刻意不动 lastDiff，保留上一次成功的摘要。 */
export function ruleSetRefreshFailure<T extends {
  lastError?: string
  lastDiff?: RuleSetRefreshDiff
}>(set: T, message: string): T {
  return { ...set, lastError: message }
}
