// 工作区逐字段校验 + 旧数据迁移。
// 目标：一个键坏了只影响这个键；坏数据必须可解释、可见；旧结构幂等升级；
// 客户端不认识的顶层字段原样保留，避免新版本写的数据被旧版本打开一次就丢。
import type {
  BuiltinSchemeOverrideRef,
  BuiltinSchemeSnapshot,
  LocalRuleSet,
  ProxyNode,
  RuleScheme,
  RuleSetExclusionTable,
  SubscriptionSource,
  TailnetConnection,
} from './models/types'
import {
  normalizeBuiltinSchemes,
  normalizeSource,
  schemeRejectReason,
  localRuleSetRejectReason,
  validLocalRuleSet,
  validNode,
  validScheme,
  validSource,
  validTailnet,
} from './backup'
import { normalizeRuleSetExclusions } from './rules/ruleSetExclusions'
import { BUILTIN_SCHEMES } from './rules/scheme'
import {
  isWorkspaceStateKey,
  WORKSPACE_FIELD_LABELS,
  type WorkspaceStateKey,
} from './workspaceKeys'

export interface WorkspaceData {
  sources: SubscriptionSource[]
  nodes: ProxyNode[]
  customSchemes: RuleScheme[]
  localRuleSets: LocalRuleSet[]
  builtinSchemeOverrides: Record<string, BuiltinSchemeOverrideRef>
  /** 独立固化快照；与覆盖层指针一起同步，才能解引用。 */
  schemeSnapshots: Record<string, BuiltinSchemeSnapshot>
  snapshotSeq: number
  /** 只读规则集的本地屏蔽表；必须跟工作区一起同步。 */
  ruleSetExclusions: RuleSetExclusionTable
  selectedSchemeID: string
  policySelections: Record<string, string>
  exportConfigName: string
  tailnets: TailnetConnection[]
  tailnetAuthKeys: Record<string, string>
}

export class WorkspaceDataError extends Error {}

/** 逐字段问题的性质：丢弃、回退默认值、还是旧结构升级。 */
export type WorkspaceIssueSeverity = 'dropped' | 'fallback' | 'migrated'

export interface WorkspaceIssue {
  key: WorkspaceStateKey
  keyLabel: string
  /** 具体定位，例如「订阅第 2 条」「方案 c1」；整字段问题等于键名。 */
  label: string
  reason: string
  severity: WorkspaceIssueSeverity
  /** 数组里的 1-based 位置。 */
  index?: number
  /** 整个顶层字段无法使用；调用方应保留本机原值，而不是写成空值。 */
  wholeKey?: boolean
}

export interface WorkspaceNormalizationResult {
  data: WorkspaceData
  issues: WorkspaceIssue[]
  /** 客户端不认识的顶层字段；推送时原样带回。 */
  unknown: Record<string, unknown>
  /** 本次从旧结构升级的条目数（迁移是幂等的，第二次应为 0）。 */
  migrated: number
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function typeName(value: unknown): string {
  if (Array.isArray(value)) return '数组'
  if (value === null) return 'null'
  if (typeof value === 'string') return '字符串'
  if (typeof value === 'number') return '数字'
  if (typeof value === 'boolean') return '布尔值'
  if (typeof value === 'object') return '对象'
  return typeof value
}

function fieldLabel(key: WorkspaceStateKey): string {
  return WORKSPACE_FIELD_LABELS[key]
}

function keyIssue(key: WorkspaceStateKey, reason: string): WorkspaceIssue {
  return {
    key,
    keyLabel: fieldLabel(key),
    label: fieldLabel(key),
    reason,
    severity: 'dropped',
    wholeKey: true,
  }
}

function itemIssue(
  key: WorkspaceStateKey,
  label: string,
  reason: string,
  index?: number,
): WorkspaceIssue {
  return { key, keyLabel: fieldLabel(key), label, reason, severity: 'dropped', index }
}

function fallbackIssue(
  key: WorkspaceStateKey,
  label: string,
  reason: string,
): WorkspaceIssue {
  return { key, keyLabel: fieldLabel(key), label, reason, severity: 'fallback' }
}

function migrationIssue(
  key: WorkspaceStateKey,
  label: string,
  reason: string,
): WorkspaceIssue {
  return { key, keyLabel: fieldLabel(key), label, reason, severity: 'migrated' }
}

interface MigrationNotice {
  key: WorkspaceStateKey
  label: string
  reason: string
}

function stringList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function numericString(value: unknown): number | undefined {
  if (typeof value !== 'string' || !value.trim()) return undefined
  const number = Number(value)
  return Number.isFinite(number) ? number : undefined
}

function booleanString(value: unknown): boolean | undefined {
  if (value === 'true') return true
  if (value === 'false') return false
  return undefined
}

/** 只把「看起来就是数字」的字符串转成数字；其余保持原值交给校验器判断。 */
function coerceNumbers(
  value: Record<string, unknown>,
  fields: string[],
): { patch: Record<string, number>; changed: string[] } {
  const patch: Record<string, number> = {}
  const changed: string[] = []
  for (const field of fields) {
    const number = numericString(value[field])
    if (number !== undefined) {
      patch[field] = number
      changed.push(field)
    }
  }
  return { patch, changed }
}

function coerceBooleans(
  value: Record<string, unknown>,
  fields: string[],
): { patch: Record<string, boolean>; changed: string[] } {
  const patch: Record<string, boolean> = {}
  const changed: string[] = []
  for (const field of fields) {
    const bool = booleanString(value[field])
    if (bool !== undefined) {
      patch[field] = bool
      changed.push(field)
    }
  }
  return { patch, changed }
}

/** 旧版把「按 id 索引的对象」写成数组字段时，尽量无损转回数组。 */
function recordToArray(
  value: unknown,
  valid: (item: unknown) => boolean,
): unknown[] | undefined {
  if (!isRecord(value)) return undefined
  const items = Object.entries(value).map(([id, item]) => (
    isRecord(item) && typeof item.id !== 'string' ? { ...item, id } : item
  ))
  return items.every(valid) ? items : undefined
}

function recordToArrayWithKey(
  value: unknown,
  valid: (item: unknown) => boolean,
  keyField: string,
): unknown[] | undefined {
  if (!isRecord(value)) return undefined
  const items = Object.entries(value).map(([name, item]) => (
    isRecord(item) && typeof item[keyField] !== 'string' ? { ...item, [keyField]: name } : item
  ))
  return items.every(valid) ? items : undefined
}

function migrateGroups(value: unknown): unknown[] | undefined {
  return recordToArrayWithKey(value, (item) => (
    isRecord(item)
    && typeof item.name === 'string'
    && typeof item.type === 'string'
    && Array.isArray(item.options)
  ), 'name')
}

/**
 * 旧结构升级：全部按「形状是否可识别」判断，幂等且可重入。
 * 不猜测无法证明的顶层字段改名——那会把未来版本的新字段误当旧字段，
 * 反而破坏「未知字段原样保留」；只做能明确判定且不会丢内容的转换。
 */
function migrateWorkspaceRecord(raw: Record<string, unknown>): {
  raw: Record<string, unknown>
  notices: MigrationNotice[]
} {
  const next: Record<string, unknown> = { ...raw }
  const notices: MigrationNotice[] = []
  const add = (key: WorkspaceStateKey, label: string, reason: string) => {
    notices.push({ key, label, reason })
  }

  // 旧版可能把整张数组写成按 id 索引的对象。
  const asArray = (
    key: WorkspaceStateKey,
    valid: (item: unknown) => boolean,
    label: string,
  ) => {
    const value = next[key]
    if (Array.isArray(value) || value === undefined) return
    const items = recordToArray(value, valid)
    if (!items) return
    next[key] = items
    add(key, label, `旧版 ${key} 是按 id 索引的对象，已转成数组`)
  }
  asArray('sources', validSource, '订阅')
  asArray('nodes', validNode, '节点')
  asArray('customSchemes', validScheme, '自定义方案')
  asArray('localRuleSets', validLocalRuleSet, '本地规则集')
  asArray('tailnets', validTailnet, 'Tailscale 内网')

  if (Array.isArray(next.sources)) {
    next.sources = next.sources.map((item, index) => {
      if (!isRecord(item)) return item
      let changed = false
      let source = item
      const excluded = item.excludedNodeKeys
      if (typeof excluded === 'string') {
        source = { ...source, excludedNodeKeys: stringList(excluded) }
        changed = true
        add('sources', `订阅第 ${index + 1} 条`, '旧版 excludedNodeKeys 是字符串，已转成数组')
      }
      if (typeof item.notices === 'string') {
        source = { ...source, notices: stringList(item.notices) }
        changed = true
        add('sources', `订阅第 ${index + 1} 条`, '旧版 notices 是字符串，已转成数组')
      }
      const usage = item.usage
      if (isRecord(usage)) {
        const { patch, changed: fields } = coerceNumbers(usage, ['upload', 'download', 'total', 'expire'])
        if (fields.length) {
          source = { ...source, usage: { ...usage, ...patch } }
          changed = true
          add('sources', `订阅第 ${index + 1} 条`, `用量字段 ${fields.join(' / ')} 是数字字符串，已转成数字`)
        }
      }
      const { patch, changed: fields } = coerceNumbers(item, ['expireAt', 'totalBytes', 'usedBytes', 'updatedAt'])
      if (fields.length) {
        source = { ...source, ...patch }
        changed = true
        add('sources', `订阅第 ${index + 1} 条`, `字段 ${fields.join(' / ')} 是数字字符串，已转成数字`)
      }
      return changed ? source : item
    })
  }

  if (Array.isArray(next.nodes)) {
    next.nodes = next.nodes.map((item, index) => {
      if (!isRecord(item)) return item
      let node = item
      const numbers = coerceNumbers(item, ['port'])
      const booleans = coerceBooleans(item, ['tls', 'skipCertificateVerification', 'isEnabled', 'isManual'])
      if (!numbers.changed.length && !booleans.changed.length) return item
      node = { ...node, ...numbers.patch, ...booleans.patch }
      add(
        'nodes',
        `节点第 ${index + 1} 条`,
        `字段 ${[...numbers.changed, ...booleans.changed].join(' / ')} 是字符串，已转成正确类型`,
      )
      return node
    })
  }

  if (Array.isArray(next.customSchemes)) {
    next.customSchemes = next.customSchemes.map((item, index) => {
      if (!isRecord(item)) return item
      let scheme = item
      let changed = false
      const addScheme = (reason: string) => {
        changed = true
        add('customSchemes', `方案第 ${index + 1} 条`, reason)
      }
      if (scheme.groups === undefined && Array.isArray(scheme.policyGroups)) {
        scheme = { ...scheme, groups: scheme.policyGroups }
        addScheme('旧版字段 policyGroups 已按 groups 读取')
      }
      const groups = migrateGroups(scheme.groups)
      if (groups) {
        scheme = { ...scheme, groups }
        addScheme('旧版 groups 是按名称索引的对象，已转成数组')
      }
      for (const field of ['rules', 'customRules'] as const) {
        const value = scheme[field]
        if (isRecord(value)) {
          scheme = { ...scheme, [field]: Object.values(value) }
          addScheme(`旧版 ${field} 是按序号索引的对象，已转成数组`)
        }
      }
      const ruleSets = scheme.ruleSets
      if (isRecord(ruleSets)) {
        const single = isRecord(ruleSets) && typeof ruleSets.id === 'string' && Array.isArray(ruleSets.rules)
        scheme = { ...scheme, ruleSets: single ? [ruleSets] : Object.values(ruleSets) }
        addScheme('旧版 ruleSets 不是数组，已转成数组')
      }
      return changed ? scheme : item
    })
  }

  if (Array.isArray(next.localRuleSets)) {
    next.localRuleSets = next.localRuleSets.map((item, index) => {
      if (!isRecord(item) || !isRecord(item.rules)) return item
      add('localRuleSets', `规则集第 ${index + 1} 条`, '旧版 rules 是按序号索引的对象，已转成数组')
      return { ...item, rules: Object.values(item.rules) }
    })
  }

  if (Array.isArray(next.tailnets)) {
    next.tailnets = next.tailnets.map((item, index) => {
      if (!isRecord(item)) return item
      let tailnet = item
      let changed = false
      if (typeof item.subnets === 'string') {
        tailnet = { ...tailnet, subnets: stringList(item.subnets) }
        changed = true
        add('tailnets', `内网第 ${index + 1} 条`, '旧版 subnets 是字符串，已转成数组')
      }
      const bool = booleanString(item.isEnabled)
      if (bool !== undefined) {
        tailnet = { ...tailnet, isEnabled: bool }
        changed = true
        add('tailnets', `内网第 ${index + 1} 条`, 'isEnabled 是字符串，已转成布尔值')
      }
      return changed ? tailnet : item
    })
  }

  // 0.3.3 及以前的覆盖层把整份正文内联在 builtinSchemeOverrides 里；
  // normalizeBuiltinSchemes 会把它转成快照 + 指针，这里只记录发生了升级。
  if (isRecord(next.builtinSchemeOverrides)) {
    for (const [schemeID, item] of Object.entries(next.builtinSchemeOverrides)) {
      if (!isRecord(item)) continue
      const ref = item.snapshotId
      if (typeof ref !== 'number' && isRecord(item.scheme)) {
        add('builtinSchemeOverrides', schemeID, '旧版内联固化正文，已升级为独立快照 + 指针')
      }
    }
  }
  if (Array.isArray(next.schemeSnapshots)) {
    add('schemeSnapshots', '固化快照', '旧版快照按数组保存，已转成按 id 索引的对象')
  }

  return { raw: next, notices }
}

function readRows<T>(
  raw: Record<string, unknown>,
  key: WorkspaceStateKey,
  valid: (value: unknown) => value is T,
  fallback: string,
  reason: (value: unknown) => string,
  issues: WorkspaceIssue[],
): T[] {
  const value = raw[key]
  if (value === undefined) return []
  if (!Array.isArray(value)) {
    issues.push(keyIssue(
      key,
      `字段 ${key} 应该是数组，实际是${typeName(value)}；该字段已跳过，其他字段正常加载`,
    ))
    return []
  }
  const items: T[] = []
  value.forEach((item, index) => {
    if (valid(item)) {
      items.push(item)
      return
    }
    issues.push(itemIssue(key, `${fallback}第 ${index + 1} 条`, reason(item), index + 1))
  })
  return items
}

function readStringMap(
  raw: Record<string, unknown>,
  key: WorkspaceStateKey,
  issues: WorkspaceIssue[],
): Record<string, string> {
  const value = raw[key]
  if (value === undefined) return {}
  if (!isRecord(value)) {
    issues.push(keyIssue(
      key,
      `字段 ${key} 应该是对象，实际是${typeName(value)}；该字段已跳过，其他字段正常加载`,
    ))
    return {}
  }
  const out: Record<string, string> = {}
  for (const [name, item] of Object.entries(value)) {
    if (typeof item === 'string') out[name] = item
    else issues.push(itemIssue(key, name, `值应该是字符串，实际是${typeName(item)}，已跳过这一项`))
  }
  return out
}

/** 只读屏蔽表的容错由 normalizeRuleSetExclusions 负责；这里补上可见的丢弃原因。 */
function inspectExclusions(value: unknown, issues: WorkspaceIssue[]): void {
  if (value === undefined) return
  if (!isRecord(value)) {
    issues.push(keyIssue(
      'ruleSetExclusions',
      `字段 ruleSetExclusions 应该是对象，实际是${typeName(value)}；该字段已跳过，其他字段正常加载`,
    ))
    return
  }
  for (const [id, list] of Object.entries(value)) {
    if (!Array.isArray(list)) {
      issues.push(itemIssue('ruleSetExclusions', id, `屏蔽条目应该是数组，实际是${typeName(list)}，已跳过`, undefined))
      continue
    }
    const bad = list.filter((item) => typeof item !== 'string' || !item.trim()).length
    if (bad > 0) {
      issues.push(itemIssue('ruleSetExclusions', id, `有 ${bad} 条签名不是非空字符串，已跳过`))
    }
  }
}

/** 汇总成一句给人看的提示；具体键名与理由在 issues 明细里。 */
export function describeWorkspaceIssues(issues: WorkspaceIssue[]): string {
  const dropped = issues.filter((item) => item.severity === 'dropped')
  const fallback = issues.filter((item) => item.severity === 'fallback')
  const migrated = issues.filter((item) => item.severity === 'migrated')
  if (!dropped.length && !fallback.length && !migrated.length) return ''
  const parts: string[] = []
  const whole = dropped.filter((item) => item.wholeKey).length
  if (whole) parts.push(`${whole} 个字段整块无法读取（已保留本机原值）`)
  const items = dropped.length - whole
  if (items) parts.push(`${items} 条记录被跳过`)
  if (fallback.length) parts.push(`${fallback.length} 项回退到默认值`)
  if (migrated.length) parts.push(`${migrated.length} 项从旧版本升级`)
  return `服务端工作区有 ${parts.join('、')}，明细如下。`
}

/**
 * 逐键校验并规范化。只有根不是对象时才抛错；单个键 / 单条记录坏掉只影响自身。
 * `unknown` 必须随下一次推送原样写回，否则旧版本打开新数据一次就会永久丢字段。
 */
export function normalizeWorkspaceDataDetailed(raw: unknown): WorkspaceNormalizationResult {
  if (!isRecord(raw)) throw new WorkspaceDataError('工作区数据不是对象')

  const migrated = migrateWorkspaceRecord(raw)
  const issues: WorkspaceIssue[] = migrated.notices.map((notice) =>
    migrationIssue(notice.key, notice.label, notice.reason))

  const sources = readRows(
    migrated.raw,
    'sources',
    validSource,
    '订阅',
    (value) => (isRecord(value) && typeof value.url !== 'string'
      ? '订阅缺少 url 字段'
      : '订阅字段类型或必填项不完整'),
    issues,
  ).map(normalizeSource)

  const nodes = readRows(
    migrated.raw,
    'nodes',
    validNode,
    '节点',
    (value) => {
      if (!isRecord(value)) return '不是对象'
      if (typeof value.kind !== 'string') return '节点协议 kind 无效'
      if (typeof value.server !== 'string' || typeof value.name !== 'string') return '节点缺少 name / server'
      const port = value.port
      if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
        return `端口 ${String(port)} 不是 1-65535 的整数`
      }
      return '节点字段类型不完整'
    },
    issues,
  )

  const customSchemes = readRows(
    migrated.raw,
    'customSchemes',
    validScheme,
    '方案',
    schemeRejectReason,
    issues,
  )

  const localRuleSets = readRows(
    migrated.raw,
    'localRuleSets',
    validLocalRuleSet,
    '规则集',
    localRuleSetRejectReason,
    issues,
  )

  const protectedRuleSetIDs = customSchemes.flatMap((scheme) =>
    (Array.isArray(scheme.ruleSets) ? scheme.ruleSets : [])
      .map((ruleSet) => ruleSet?.id)
      .filter((id): id is string => typeof id === 'string'))

  // 顶层容器形状坏掉时 normalizeBuiltinSchemes 只会静默跳过、不留任何线索；
  // 明确报成整键问题，与其它整块损坏字段走同一套「保留本机原值」处理。
  const overridesRaw = migrated.raw.builtinSchemeOverrides
  if (overridesRaw !== undefined && !isRecord(overridesRaw)) {
    issues.push(keyIssue(
      'builtinSchemeOverrides',
      `整块字段应该是对象，实际是${typeName(overridesRaw)}，已跳过并保留本机原值`,
    ))
  }
  const snapshotsRaw = migrated.raw.schemeSnapshots
  if (snapshotsRaw !== undefined && !isRecord(snapshotsRaw) && !Array.isArray(snapshotsRaw)) {
    issues.push(keyIssue(
      'schemeSnapshots',
      `整块字段应该是对象或数组，实际是${typeName(snapshotsRaw)}，已跳过并保留本机原值`,
    ))
  }

  // 固化数据已有逐条容错；把它自己的 BackupRejection 转成带键名的可见明细。
  const builtin = normalizeBuiltinSchemes(
    migrated.raw.builtinSchemeOverrides,
    migrated.raw.schemeSnapshots,
    migrated.raw.snapshotSeq,
    protectedRuleSetIDs,
  )
  for (const rejection of builtin.rejections) {
    const key: WorkspaceStateKey = rejection.kind === 'snapshot' ? 'schemeSnapshots' : 'builtinSchemeOverrides'
    issues.push(itemIssue(key, rejection.label, rejection.reason, rejection.index))
  }
  const rawSeq = migrated.raw.snapshotSeq
  if (rawSeq !== undefined
    && (typeof rawSeq !== 'number' || !Number.isInteger(rawSeq) || rawSeq < 0)) {
    issues.push(fallbackIssue(
      'snapshotSeq',
      '快照序号',
      `不是非负整数（实际是${typeName(rawSeq)}），已按现有快照重算为 ${builtin.snapshotSeq}`,
    ))
  }

  inspectExclusions(migrated.raw.ruleSetExclusions, issues)

  const rawSelected = migrated.raw.selectedSchemeID
  let selectedSchemeID = BUILTIN_SCHEMES[0].id
  if (typeof rawSelected === 'string' && rawSelected) {
    const known = BUILTIN_SCHEMES.some((meta) => meta.id === rawSelected)
      || customSchemes.some((scheme) => scheme.id === rawSelected)
    if (known) {
      selectedSchemeID = rawSelected
    } else {
      issues.push(fallbackIssue(
        'selectedSchemeID',
        rawSelected,
        '选中的方案不存在（可能被删除或数据损坏），已切回默认方案',
      ))
    }
  } else if (rawSelected !== undefined) {
    issues.push(fallbackIssue(
      'selectedSchemeID',
      '当前方案',
      `不是字符串（实际是${typeName(rawSelected)}），已切回默认方案`,
    ))
  }

  const policySelections = readStringMap(migrated.raw, 'policySelections', issues)
  const tailnetAuthKeys = readStringMap(migrated.raw, 'tailnetAuthKeys', issues)

  let exportConfigName = 'tower'
  const rawConfigName = migrated.raw.exportConfigName
  if (typeof rawConfigName === 'string') {
    exportConfigName = rawConfigName.replace(/[\r\n]/g, '').slice(0, 48) || 'tower'
  } else if (rawConfigName !== undefined) {
    issues.push(fallbackIssue(
      'exportConfigName',
      '配置名称',
      `不是字符串（实际是${typeName(rawConfigName)}），已回退为 tower`,
    ))
  }

  const tailnets = readRows(
    migrated.raw,
    'tailnets',
    validTailnet,
    'Tailscale 内网',
    () => 'Tailscale 内网连接字段不完整（id / name / subnets / isEnabled）',
    issues,
  )

  const unknown: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(migrated.raw)) {
    if (!isWorkspaceStateKey(key)) unknown[key] = value
  }

  const data: WorkspaceData = {
    sources,
    nodes,
    customSchemes,
    localRuleSets,
    builtinSchemeOverrides: builtin.builtinSchemeOverrides,
    schemeSnapshots: builtin.schemeSnapshots,
    snapshotSeq: builtin.snapshotSeq,
    ruleSetExclusions: normalizeRuleSetExclusions(migrated.raw.ruleSetExclusions),
    selectedSchemeID,
    policySelections,
    exportConfigName,
    tailnets,
    tailnetAuthKeys,
  }

  return {
    data,
    issues,
    unknown,
    migrated: migrated.notices.length,
  }
}

/** 兼容旧调用：失败时抛错；逐键容错版本请用 normalizeWorkspaceDataDetailed。 */
export function normalizeWorkspaceData(raw: unknown): WorkspaceData {
  return normalizeWorkspaceDataDetailed(raw).data
}
