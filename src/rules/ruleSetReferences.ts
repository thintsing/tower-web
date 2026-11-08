// 策略组计数口径：直接规则（正文）与远程引用分开统计。
// providerOnly 规则集不保存正文，导出时只写一条 RULE-SET；不能把它算成 0 条规则，
// 也不能并进「规则数」让用户以为塔台存了正文。
import type { RuleScheme } from '../models/types'

/** 只存 provider 地址、导出时写远程引用的规则集（未内联）。 */
export function isRemoteReferenceSet(set: { providerOnly?: boolean; inlined?: boolean }): boolean {
  return !!set.providerOnly && !set.inlined
}

/** 每个策略组各有多少条远程引用。 */
export function remoteReferenceCounts(scheme: RuleScheme | undefined): Map<string, number> {
  const counts = new Map<string, number>()
  for (const set of scheme?.ruleSets ?? []) {
    if (!isRemoteReferenceSet(set)) continue
    counts.set(set.group, (counts.get(set.group) ?? 0) + 1)
  }
  return counts
}

/** 单个策略组的远程引用数；组行和组编辑器共用同一口径。 */
export function remoteReferenceCount(scheme: RuleScheme | undefined, groupName: string): number {
  return (scheme?.ruleSets ?? []).filter(
    (set) => isRemoteReferenceSet(set) && set.group === groupName,
  ).length
}

/** 组行副标题：直接规则、自定义、远程引用分开写。 */
export function groupRuleSummary(ruleCount: number, customCount: number, remoteCount: number): string {
  const parts = [`${ruleCount} 条规则`]
  if (customCount > 0) parts.push(`${customCount} 条自定义`)
  if (remoteCount > 0) parts.push(`${remoteCount} 条远程引用`)
  return parts.join(' · ')
}

/** 组编辑器顶部：明确区分「方案自带的直接规则」和「远程引用」。 */
export function groupEditorRuleSummary(
  customCount: number,
  directCount: number,
  remoteCount: number,
): string {
  const parts = [`${customCount} 条我添加的规则`, `${directCount} 条方案自带或已展开规则集规则`]
  if (remoteCount > 0) parts.push(`${remoteCount} 条远程引用（由客户端自行下载）`)
  return parts.join(' · ')
}

/** 组编辑器 / 空态里的解释句：引用会在客户端下载后生效。 */
export function describeRemoteReferences(count: number): string {
  return `该组规则来自 ${count} 个远程引用，由客户端自行下载。`
}

/**
 * 规则集卡片副标题：规则集形态 · 来源 · 格式。
 * 形态里不再写死格式名，避免和后面的格式标签重复（例如两个「Clash provider YAML」）。
 */
export function ruleSetSummary(
  set: {
    providerOnly?: boolean
    inlined?: boolean
    sourceKind?: string
    rules: readonly unknown[]
  },
  formatTitle?: string,
): string {
  const state = set.providerOnly ? '远程引用（不保存正文）' : `${set.rules.length} 条`
  const kind = set.providerOnly
    ? '导出为 RULE-SET'
    : set.inlined
      ? '固化快照（只读）'
      : set.sourceKind === 'library'
        ? '内置规则库'
        : set.sourceKind === 'url'
          ? '在线订阅'
          : '我的规则集'
  return [state, kind, formatTitle].filter(Boolean).join(' · ')
}
