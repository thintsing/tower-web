// 规则影响面：静态分析 + 历史连接口径。
// 塔台目前没有服务端连接记录，connections 恒为 null；界面必须显式说明
// 「无历史数据，仅静态影响面」，不能把未知当成 0。
import type { RoutingRule, RuleScheme } from '../models/types'
import { ruleSignature } from './ruleDiff'
import { orderedSchemeRules } from './ruleOrder'
import { remoteReferenceCount } from './ruleSetReferences'

export interface RuleImpact {
  /** 规则要落到 / 当前所属的策略组。 */
  group: string
  /** 方案里出现同一匹配值（同类型 + 值 + 选项）的策略组。 */
  affectedGroups: string[]
  /** 同值规则条数；插入预览时包含待保存的这条。 */
  matchedRules: number
  /** 排在本条之后、会被本条遮蔽的同值规则条数。 */
  shadowedRules: number
  /** 目标策略组当前承载的规则总数（静态口径）。 */
  targetGroupRules: number
  /** 目标策略组的远程引用数；与组行 / 组编辑器同口径。 */
  targetGroupRemoteReferences: number
  /** 服务端历史连接数；没有连接记录时是 null，界面不得展示为 0。 */
  connections: number | null
}

/**
 * 按导出顺序分析一条规则的影响面。
 * `includeCandidate`：待保存的新规则会排在所有自定义规则之前，预览时放在第 0 位，
 * 这样遮蔽数量与保存后的真实顺序一致。
 */
export function analyzeRuleImpact(
  scheme: RuleScheme,
  rule: RoutingRule,
  options: { includeCandidate?: boolean } = {},
): RuleImpact {
  const ordered = orderedSchemeRules(scheme)
  const rows = options.includeCandidate
    ? [{ rule, index: 0 }, ...ordered.map((item, index) => ({ rule: item, index: index + 1 }))]
    : ordered.map((item, index) => ({ rule: item, index }))
  const signature = ruleSignature(rule)
  const matches = rows.filter((row) => ruleSignature(row.rule) === signature)
  // 已被遮蔽 / 遮蔽别人都相对「这一条」的位置来算：先按对象引用找，找不到再按签名 + 目标组。
  const selfIndex = options.includeCandidate
    ? 0
    : (() => {
        const byRef = rows.findIndex((row) => row.rule === rule)
        if (byRef >= 0) return byRef
        const byShape = rows.findIndex((row) => ruleSignature(row.rule) === signature && row.rule.group === rule.group)
        return byShape >= 0 ? byShape : 0
      })()
  const affectedGroups: string[] = []
  for (const match of matches) {
    if (!affectedGroups.includes(match.rule.group)) affectedGroups.push(match.rule.group)
  }
  return {
    group: rule.group,
    affectedGroups,
    matchedRules: matches.length,
    shadowedRules: matches.filter((match) => match.index > selfIndex).length,
    targetGroupRules: rows.filter((row) => row.rule.group === rule.group).length,
    targetGroupRemoteReferences: remoteReferenceCount(scheme, rule.group),
    connections: null,
  }
}

/** 一行可读的影响面摘要；没有连接数据时明确指出只是静态分析。 */
export function ruleImpactText(impact: RuleImpact): string {
  const groups = impact.affectedGroups.length
  const names = impact.affectedGroups.slice(0, 3).join('、')
  const groupPart = groups > 3 ? `${names} 等 ${groups} 个组` : names
  const parts = [
    `命中策略组「${impact.group}」`,
    `方案中同值规则 ${impact.matchedRules} 条${groups > 1 ? `（分布在 ${groupPart}）` : ''}`,
    impact.shadowedRules > 0
      ? `其中 ${impact.shadowedRules} 条排在本条之后，会被本条遮蔽`
      : '没有同值规则会被本条遮蔽',
    `目标组现有 ${impact.targetGroupRules} 条规则${impact.targetGroupRemoteReferences > 0 ? ` + ${impact.targetGroupRemoteReferences} 条远程引用` : ''}`,
    impact.connections === null ? '无历史数据，仅静态影响面' : `历史连接 ${impact.connections} 条`,
  ]
  return parts.join('；')
}
