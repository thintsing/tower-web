// 规则比较用的轻量工具，避免 ruleOrder 与 matchingOrder 互相引用。
import type { RoutingRule } from '../models/types'

const LEADING_EMOJI = /^((?:\p{Extended_Pictographic}|\u{1F1E6}-\u{1F1FF}|\uFE0F|\u200D|\u20E3)+)\s*/u

/** 组名去掉开头 Emoji 后比较，避免“🚀 节点选择”和“节点选择”被当成两个组。 */
export function normalizedPolicyName(name: string): string {
  const trimmed = name.trim()
  const leading = trimmed.match(LEADING_EMOJI)
  const stripped = leading ? trimmed.slice(leading[0].length).trim() : trimmed
  return (stripped || trimmed).toLowerCase()
}

/** FINAL / MATCH 是兜底规则；它们不能随策略组拖动而前移。 */
export function isTerminalRule(rule: Pick<RoutingRule, 'type' | 'raw'>): boolean {
  const type = (rule.raw?.split(',')[0] ?? rule.type ?? '').trim().toUpperCase()
  return type === 'FINAL' || type === 'MATCH'
}

/**
 * 作为匹配兜底锚点、不参与手动逐条排序的规则：FINAL / MATCH 永远在最后，
 * GEOIP 是地理兜底；逐条排序不能把它们挪到普通规则前面。
 */
export function isUnmovableRule(rule: Pick<RoutingRule, 'type' | 'raw'>): boolean {
  if (isTerminalRule(rule)) return true
  const type = (rule.raw?.split(',')[0] ?? rule.type ?? '').trim().toUpperCase()
  return type === 'GEOIP'
}

/** TYPE,value 小写比较键；逻辑规则的 raw 也按前两个字段识别。 */
export function ruleMatchKey(
  rule: Pick<RoutingRule, 'type' | 'value' | 'raw'>,
): string | undefined {
  const rawFields = (rule.raw ?? '').split(',').map((field) => field.trim())
  const type = (rawFields[0] || rule.type || '').trim().toUpperCase()
  const value = (rule.value ?? rawFields[1] ?? '').trim().toLowerCase()
  if (!type || !value) return undefined
  return `${type},${value}`
}
