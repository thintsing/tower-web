// 规则顺序移植自 Tower iOS RuleScheme：
// - 用户附加的条件按“最具体优先”排列；
// - 从规则库加入的规则集在同来源 / 同值锚点之前插入，没有锚点时前置；
// - FINAL / MATCH 永远留在最后，不参与拖动重排。
import type { RoutingRule, RuleScheme, SchemeRuleSet } from '../models/types'
import { reorderRulesByMatchingOrder } from './matchingOrder'
import { ruleSignature } from './ruleDiff'
import { isTerminalRule, isUnmovableRule, normalizedPolicyName, ruleMatchKey } from './ruleKeys'

export { isTerminalRule, isUnmovableRule, normalizedPolicyName, ruleMatchKey } from './ruleKeys'

function cidrPrefixLength(value: string | undefined): number {
  const trimmed = (value ?? '').trim()
  const slash = trimmed.lastIndexOf('/')
  if (slash < 0) return trimmed.includes(':') ? 128 : 32
  const prefix = Number(trimmed.slice(slash + 1))
  if (!Number.isFinite(prefix)) return 0
  return prefix
}

/** 最具体优先；同等级保持添加顺序。 */
export function sortSupplementRules(rules: RoutingRule[]): RoutingRule[] {
  const rank = (rule: RoutingRule): [number, number] => {
    switch (rule.type.toUpperCase()) {
      case 'DOMAIN': return [0, 0]
      case 'DOMAIN-SUFFIX': return [1, -(rule.value ?? '').split('.').filter(Boolean).length]
      case 'DOMAIN-KEYWORD': return [2, -(rule.value ?? '').trim().length]
      case 'IP-CIDR':
      case 'IP-CIDR6':
      case 'IP6-CIDR': return [3, -cidrPrefixLength(rule.value)]
      default: return [4, 0]
    }
  }
  return [...rules].sort((left, right) => {
    const a = rank(left)
    const b = rank(right)
    return a[0] - b[0] || a[1] - b[1]
  })
}

export interface RuleSetBlock {
  group: string
  /** 原始规则集内容，用来寻找模板里第一条重叠规则。 */
  matchRules: RoutingRule[]
  /** 规则集来源地址；与模板里的 RULE-SET 引用比较。 */
  sourceURL?: string
  /** 真正写入配置的规则（可能是 MRS/SRS 的远程引用加残余内联规则）。 */
  rules: RoutingRule[]
  /** 规则已经在 baseRules 内联保存（固化快照），不再插入，避免同一批规则出现两份。 */
  inlined?: boolean
  /** provider-only 引用（Loyalsoldier 那类只有远程数据源的规则集）。 */
  providerOnly?: boolean
}

/** 模板里第一条与规则集重叠的规则位置；同来源或同 TYPE,value 才算锚点，没有则返回 -1。 */
function findAnchorIndex(
  baseRules: RoutingRule[],
  block: Omit<RuleSetBlock, 'rules'>,
): number {
  const keys = new Set(
    block.matchRules.map(ruleMatchKey).filter((key): key is string => !!key),
  )
  const sourceURL = block.sourceURL?.trim()
  return baseRules.findIndex((rule) => {
    if (isTerminalRule(rule)) return false
    if (sourceURL && rule.type === 'RULE-SET' && (rule.value ?? '').trim() === sourceURL) return true
    const key = ruleMatchKey(rule)
    return !!key && keys.has(key)
  })
}

/**
 * 一条规则集应该插到模板的第几条规则之前：
 * 同来源地址或同 TYPE,value 的第一条；没有这类锚点时插到普通规则最前面，
 * 即使目标组里已有别的规则——新加入的规则集默认优先匹配。
 */
export function ruleSetInsertionIndex(
  baseRules: RoutingRule[],
  block: Omit<RuleSetBlock, 'rules'>,
): number {
  const index = findAnchorIndex(baseRules, block)
  return index < 0 ? 0 : index
}

/**
 * 无锚点块的先后：用户规则集 → 有锚点的规则集 → provider 引用。
 * provider 引用同样没有锚点，但它们代表模板自带的数据源，用户新加的
 * 规则集必须排在它们之前；同一档内保持方案里的顺序。
 */
function blockPriority(block: Omit<RuleSetBlock, 'rules'>, anchored: boolean): number {
  if (anchored) return 1
  return block.providerOnly ? 2 : 0
}

/**
 * 把规则集块按插入位置与模板规则交错合并。
 * 同一插入点内保持块的最终顺序（稳定排序）。
 */
export function insertRuleSetBlocks(
  baseRules: RoutingRule[],
  blocks: RuleSetBlock[],
): RoutingRule[] {
  const ordinary = baseRules.filter((rule) => !isTerminalRule(rule))
  const finals = baseRules.filter(isTerminalRule)
  const ranked = blocks
    // 内联块（固化快照）的规则已经在 baseRules 里；跳过是导出逐字节一致的前提。
    .filter((block) => !block.inlined)
    .map((block) => {
      const anchor = findAnchorIndex(ordinary, block)
      return { block, index: anchor < 0 ? 0 : anchor, anchored: anchor >= 0 }
    })
    .sort((left, right) => blockPriority(left.block, left.anchored) - blockPriority(right.block, right.anchored))
  const buckets = new Map<number, RoutingRule[]>()
  for (const { block, index } of ranked) {
    buckets.set(index, [...(buckets.get(index) ?? []), ...block.rules])
  }
  const merged: RoutingRule[] = []
  ordinary.forEach((rule, index) => {
    const bucket = buckets.get(index)
    if (bucket) merged.push(...bucket)
    merged.push(rule)
  })
  const tail = buckets.get(ordinary.length)
  if (tail) merged.push(...tail)
  merged.push(...finals)
  return merged
}

/** 规则集与模板规则合并后的顺序；不含用户自定义规则。 */
export function orderedSchemeBaseRules(scheme: RuleScheme): RoutingRule[] {
  const blocks: RuleSetBlock[] = (scheme.ruleSets ?? []).map((set) => ({
    group: set.group,
    matchRules: set.rules,
    sourceURL: set.sourceRef,
    rules: set.rules.map((rule) => ({ ...rule, group: set.group })),
    inlined: set.inlined,
    providerOnly: set.providerOnly,
  }))
  return reorderRulesByMatchingOrder(
    insertRuleSetBlocks(scheme.rules, blocks),
    scheme.matchingOrder,
  )
}

/**
 * 逐条排序键：规则签名 + 策略组。签名区分 type/value/选项，组名区分同一规则的
 * 不同去向；分隔符用 \u0000，避免与规则文本里的逗号冲突。
 */
export function ruleOrderKey(rule: RoutingRule): string {
  return `${ruleSignature(rule)}\u0000${normalizedPolicyName(rule.group)}`
}

export function ruleOrderGroup(key: string): string {
  const at = key.lastIndexOf('\u0000')
  return at < 0 ? '' : key.slice(at + 1)
}

/** 生成“当前全部普通规则”的顺序键；兜底规则不参与。 */
export function ruleOrderKeys(rules: RoutingRule[]): string[] {
  return rules.filter((rule) => !isUnmovableRule(rule)).map(ruleOrderKey)
}

/** 组改名后同步逐条顺序键里的组名（键尾存的是 normalizedPolicyName）。 */
export function renameRuleOrderKeys(
  order: string[] | undefined,
  renames: Iterable<[string, string]>,
): string[] | undefined {
  if (!order?.length) return order
  const map = new Map<string, string>()
  for (const [oldName, newName] of renames) {
    map.set(normalizedPolicyName(oldName), normalizedPolicyName(newName))
  }
  return order.map((key) => {
    const at = key.lastIndexOf('\u0000')
    if (at < 0) return key
    const next = map.get(key.slice(at + 1))
    return next ? `${key.slice(0, at)}\u0000${next}` : key
  })
}

/** 删除策略组后清掉指向它的逐条顺序键。 */
export function dropRuleOrderKeysForGroup(
  order: string[] | undefined,
  group: string,
): string[] | undefined {
  if (!order?.length) return order
  const name = normalizedPolicyName(group)
  return order.filter((key) => ruleOrderGroup(key) !== name)
}

/**
 * 应用逐条顺序。GEOIP / FINAL / MATCH 作为锚点留在原位置，普通规则只在
 * 相邻锚点之间重排，因此不会把兜底规则挤到前面。
 * 未出现在顺序键里的规则（例如刷新规则集后新增的条目）按原来的坑位插回，
 * 避免它们被悄悄挪到末尾。
 */
export function applyRuleOrder(
  rules: RoutingRule[],
  order: string[] | undefined,
): RoutingRule[] {
  if (!order?.length || rules.length < 2) return rules
  const rank = new Map<string, number>()
  order.forEach((key, index) => {
    if (!rank.has(key)) rank.set(key, index)
  })

  const output: RoutingRule[] = []
  let segment: RoutingRule[] = []

  const flush = () => {
    if (!segment.length) return
    const tagged = segment.map((rule, index) => ({ rule, index, key: ruleOrderKey(rule) }))
    const ranked = tagged
      .filter((item) => rank.has(item.key))
      .sort((left, right) => rank.get(left.key)! - rank.get(right.key)! || left.index - right.index)
    for (const item of tagged.filter((entry) => !rank.has(entry.key))) {
      ranked.splice(Math.min(item.index, ranked.length), 0, item)
    }
    output.push(...ranked.map((item) => item.rule))
    segment = []
  }

  for (const rule of rules) {
    if (isUnmovableRule(rule)) {
      flush()
      output.push(rule)
      continue
    }
    segment.push(rule)
  }
  flush()
  return output
}

/** 界面展示用顺序：自定义规则（排序后）+ 规则集/模板规则 + FINAL，再应用逐条覆盖。 */
export function orderedSchemeRules(scheme: RuleScheme): RoutingRule[] {
  return applyRuleOrder(
    [
      ...sortSupplementRules(scheme.customRules ?? []),
      ...orderedSchemeBaseRules(scheme),
    ],
    scheme.ruleOrder,
  )
}

/**
 * 加入规则集后它是否落在方案普通规则之前（用于界面提示）。
 * 用 orderedSchemeRules 的最终顺序判断，与实际导出同源，不写死文案。
 * 方案里没有普通规则时没有“之前”可言，返回 false。
 */
export function ruleSetRanksBeforeSchemeRules(
  scheme: RuleScheme,
  set: Pick<SchemeRuleSet, 'name' | 'group'>,
): boolean {
  const ordered = orderedSchemeRules(scheme)
  const group = normalizedPolicyName(set.group)
  const firstSet = ordered.findIndex(
    (rule) => rule.sourceName === set.name && normalizedPolicyName(rule.group) === group,
  )
  const schemeOrdinary = (scheme.rules ?? []).filter((rule) => !isTerminalRule(rule))
  const firstScheme = ordered.findIndex((rule) => schemeOrdinary.includes(rule))
  return firstSet >= 0 && firstScheme >= 0 && firstSet < firstScheme
}
