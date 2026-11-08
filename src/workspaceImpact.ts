// 工作区回滚影响：只比较「方案」会让只改订阅 / 节点 / 屏蔽表的回滚显示
// 「受影响的方案：无」，用户会在不知情的情况下确认。
import { BUILTIN_SCHEMES } from './rules/scheme'
import {
  normalizeWorkspaceDataDetailed,
  type WorkspaceData,
} from './workspaceValidation'

export interface WorkspaceImpact {
  /** 方案层面的影响（自定义方案、内置固化、当前选中），以及目标版本无法读取的字段说明。 */
  schemes: string[]
  /** 订阅 / 节点 / 屏蔽 / 本地规则集 / Tailscale 内网的恢复或移除描述。 */
  data: string[]
  /** 目标版本有整块无法读取的顶层字段，未纳入比较。 */
  incomplete: boolean
}

function builtinName(id: string): string {
  return BUILTIN_SCHEMES.find((meta) => meta.id === id)?.name ?? id
}

function schemeName(scheme: { id?: unknown; name?: unknown }): string {
  const name = typeof scheme.name === 'string' ? scheme.name.trim() : ''
  if (name) return name
  return typeof scheme.id === 'string' && scheme.id ? scheme.id : '未命名方案'
}

function selectedSchemeName(data: WorkspaceData): string {
  const custom = data.customSchemes.find((scheme) => scheme.id === data.selectedSchemeID)
  return custom ? schemeName(custom) : builtinName(data.selectedSchemeID)
}

function resolvedOverride(data: WorkspaceData, id: string): string {
  const pointer = data.builtinSchemeOverrides[id]
  if (!pointer) return ''
  return JSON.stringify(data.schemeSnapshots[String(pointer.snapshotId)] ?? null)
}

function visibleNodeCount(data: WorkspaceData): number {
  return data.nodes.filter((node) => !node.isSubscriptionMetadata).length
}

function exclusionCount(data: WorkspaceData): number {
  return Object.values(data.ruleSetExclusions).reduce((sum, list) => sum + list.length, 0)
}

/** 按 id 对齐比较，纯重排不算变化；只有条目内容变化才报告。 */
function sameItems(left: unknown[], right: unknown[]): boolean {
  if (left.length !== right.length) return false
  const rightByID = new Map<string, unknown>()
  for (const item of right) {
    const id = (item as { id?: unknown }).id
    if (typeof id === 'string') rightByID.set(id, item)
  }
  return left.every((item) => {
    const id = (item as { id?: unknown }).id
    if (typeof id !== 'string') return false
    const other = rightByID.get(id)
    return other !== undefined && JSON.stringify(other) === JSON.stringify(item)
  })
}

/** 屏蔽表按「规则集 id + 签名」存；同一规则集内签名重排不算变化。 */
function sameExclusions(left: WorkspaceData['ruleSetExclusions'], right: WorkspaceData['ruleSetExclusions']): boolean {
  const leftKeys = Object.keys(left)
  const rightKeys = Object.keys(right)
  if (leftKeys.length !== rightKeys.length) return false
  for (const key of leftKeys) {
    const a = left[key]
    const b = right[key]
    if (!b || a.length !== b.length) return false
    const sortedA = [...a].sort()
    const sortedB = [...b].sort()
    for (let i = 0; i < sortedA.length; i += 1) {
      if (sortedA[i] !== sortedB[i]) return false
    }
  }
  return true
}

function describeSchemeChanges(current: WorkspaceData, target: WorkspaceData): string[] {
  const impacts: string[] = []
  const currentSchemes = new Map(current.customSchemes.map((scheme) => [scheme.id, scheme]))
  const targetSchemes = new Map(target.customSchemes.map((scheme) => [scheme.id, scheme]))
  for (const [id, scheme] of targetSchemes) {
    const before = currentSchemes.get(id)
    if (!before) impacts.push(`新增自定义方案「${schemeName(scheme)}」`)
    else if (JSON.stringify(before) !== JSON.stringify(scheme)) {
      impacts.push(`自定义方案「${schemeName(scheme)}」的规则或策略组有变化`)
    }
  }
  for (const [id, scheme] of currentSchemes) {
    if (!targetSchemes.has(id)) impacts.push(`移除自定义方案「${schemeName(scheme)}」`)
  }
  const builtinIDs = new Set([
    ...Object.keys(current.builtinSchemeOverrides),
    ...Object.keys(target.builtinSchemeOverrides),
  ])
  for (const id of builtinIDs) {
    if (resolvedOverride(current, id) !== resolvedOverride(target, id)) {
      impacts.push(`内置方案「${builtinName(id)}」的固化内容有变化`)
    }
  }
  if (current.selectedSchemeID !== target.selectedSchemeID) {
    impacts.push(`当前方案 ${selectedSchemeName(current)} → ${selectedSchemeName(target)}`)
  }
  return [...new Set(impacts)]
}

/** 一个类别的变化：目标仍非空时说明会恢复多少；目标比当前少时明确「其余 N 项会被移除」。 */
function categoryImpact(
  restoring: string[],
  removing: string[],
  currentCount: number,
  targetCount: number,
  changed: boolean,
  label: string,
  unit: string,
): void {
  if (!changed) return
  // 中文类别直接接在「个 / 条」后面；Tailscale 这类英文开头要留一个空格。
  const spaced = /^[A-Za-z]/.test(label) ? ` ${label}` : label
  if (targetCount > 0) {
    restoring.push(`${targetCount} ${unit}${spaced}`)
    if (targetCount < currentCount) removing.push(`其余 ${currentCount - targetCount} ${unit}${spaced}`)
    return
  }
  if (currentCount > 0) removing.push(`全部${spaced}（当前 ${currentCount} ${unit}）`)
}

/** 订阅 / 节点 / 屏蔽 / 本地规则集 / Tailscale 内网：数量为 0 的项不出现。 */
export function describeWorkspaceDataImpact(current: WorkspaceData, target: WorkspaceData): string[] {
  const restoring: string[] = []
  const removing: string[] = []
  categoryImpact(
    restoring, removing,
    current.sources.length, target.sources.length,
    !sameItems(current.sources, target.sources),
    '订阅', '个',
  )
  categoryImpact(
    restoring, removing,
    visibleNodeCount(current), visibleNodeCount(target),
    !sameItems(current.nodes, target.nodes),
    '节点', '个',
  )
  categoryImpact(
    restoring, removing,
    exclusionCount(current), exclusionCount(target),
    !sameExclusions(current.ruleSetExclusions, target.ruleSetExclusions),
    '屏蔽', '条',
  )
  categoryImpact(
    restoring, removing,
    current.localRuleSets.length, target.localRuleSets.length,
    !sameItems(current.localRuleSets, target.localRuleSets),
    '本地规则集', '个',
  )
  categoryImpact(
    restoring, removing,
    current.tailnets.length, target.tailnets.length,
    !sameItems(current.tailnets, target.tailnets),
    'Tailscale 内网', '个',
  )
  const lines: string[] = []
  if (restoring.length > 0) lines.push(`将恢复 ${restoring.join('、')}`)
  if (removing.length > 0) lines.push(`将移除 ${removing.join('、')}`)
  return lines
}

/**
 * 对比当前工作区与目标版本，列出会被改动的方案与工作区数据。
 * 整块读不出的顶层字段不参与比较（否则会误报「全部移除」），
 * 但其余能读的字段照常比较；单条坏记录也不算整份数据不完整。
 */
export function describeWorkspaceImpact(currentRaw: WorkspaceData, targetRaw: unknown): WorkspaceImpact {
  // 逐键容错不再抛错，必须看 dropped 明细，否则坏版本会被当成「少了很多方案」。
  const normalized = normalizeWorkspaceDataDetailed(targetRaw)
  const dropped = normalized.issues.filter((item) => item.severity === 'dropped')
  const whole = dropped.filter((item) => item.wholeKey)
  if (whole.length > 0) {
    const labels = [...new Set(whole.map((item) => item.keyLabel))]
    const target: WorkspaceData = { ...normalized.data }
    for (const issue of whole) {
      // 整块坏掉的键保留当前值：它们没有可比较的数据，不能算成「被移除」。
      (target as unknown as Record<string, unknown>)[issue.key] =
        (currentRaw as unknown as Record<string, unknown>)[issue.key]
    }
    return {
      schemes: [
        `目标版本数据不完整（${labels.join('、')}无法读取），这些字段未纳入比较`,
        ...describeSchemeChanges(currentRaw, target),
      ],
      data: describeWorkspaceDataImpact(currentRaw, target),
      incomplete: true,
    }
  }
  const target: WorkspaceData = normalized.data
  return {
    schemes: describeSchemeChanges(currentRaw, target),
    data: describeWorkspaceDataImpact(currentRaw, target),
    incomplete: false,
  }
}
