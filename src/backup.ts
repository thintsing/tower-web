// 本机数据备份：只包含持久化快照，不包含测速结果、瞬时错误和密钥。
// 恢复前由界面再次确认；备份文件本身含订阅地址与节点凭据，不能公开分享。
import { PROXY_KIND_TITLES } from './models/types'
import type {
  BuiltinSchemeOverrideRef,
  BuiltinSchemeSnapshot,
  BuiltinSchemeSnapshotContent,
  ClientTarget,
  ExportContentMode,
  LatencyTestMode,
  LocalRuleSet,
  NodeNameFilterSettings,
  PolicyGroup,
  ProxyKind,
  ProxyNode,
  RoutingRule,
  RuleScheme,
  RuleSetExclusionTable,
  SchemeRuleSet,
  SubscriptionSource,
  SubscriptionUsage,
  TailnetConnection,
} from './models/types'
import { usageFieldsFrom } from './models/types'
import { normalizeRuleSetExclusions } from './rules/ruleSetExclusions'
import { isBuiltinSchemeSnapshotValid, pruneBuiltinSchemeSnapshots } from './rules/schemeSnapshots'

export const BACKUP_APP = 'tower-web'
export const BACKUP_VERSION = 1
export const MAX_BACKUP_BYTES = 20 * 1024 * 1024

export interface PersistedData {
  sources: SubscriptionSource[]
  nodes: ProxyNode[]
  selectedSchemeID: string
  policySelections: Record<string, string>
  customSchemes: RuleScheme[]
  localRuleSets: LocalRuleSet[]
  /** 内置方案覆盖层指针；缺失或损坏时按空处理，加载会回落原厂 / 上一版快照。 */
  builtinSchemeOverrides?: Record<string, BuiltinSchemeOverrideRef>
  /** 独立固化快照；单条损坏只丢这一条。 */
  schemeSnapshots?: Record<string, BuiltinSchemeSnapshot>
  /** 快照 id 自增序列，避免淘汰后复用 id。 */
  snapshotSeq?: number
  /** 只读规则集的本地屏蔽表；坏掉一条只丢一条。 */
  ruleSetExclusions?: RuleSetExclusionTable
  checkBuiltinSchemeUpdatesOnOpen?: boolean
  autoRefreshOnOpen: boolean
  autoRefreshRuleSetsOnOpen: boolean
  preferRuleSets: boolean
  exportContentMode: ExportContentMode
  exportContentModes: Partial<Record<ClientTarget, ExportContentMode>>
  embedRemoteSubscriptions: boolean
  exportProtocols: ProxyKind[]
  exportRegions: string[]
  exportConfigName: string
  appendSourceName: boolean
  clientOrder: ClientTarget[]
  hiddenClients: ClientTarget[]
  nodeNameFilter: NodeNameFilterSettings
  filterSubscriptionInfoNodes: boolean
  renewalRemindersEnabled: boolean
  showGroupEmoji: boolean
  ruleSetVersionHistory: boolean
  latencyTestMode: LatencyTestMode
  tailnets: TailnetConnection[]
}

export interface BackupFile {
  app: typeof BACKUP_APP
  version: number
  exportedAt: string
  data: PersistedData
}

export interface BackupCounts {
  sources: number
  nodes: number
  manualNodes: number
  schemes: number
  ruleSets: number
  tailnets: number
}

const DEFAULT_NODE_NAME_FILTER: NodeNameFilterSettings = {
  include: '',
  exclude: '',
  useRegex: false,
  caseSensitive: false,
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isString(value: unknown): value is string {
  return typeof value === 'string'
}

function booleanOr(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback
}

function stringOr(value: unknown, fallback: string): string {
  return isString(value) ? value : fallback
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined
  const values = value.filter(isString)
  return values.length === value.length ? values : undefined
}

const NODE_KINDS = new Set(Object.keys(PROXY_KIND_TITLES))

function validGroup(value: unknown): value is PolicyGroup {
  return isRecord(value)
    && isString(value.name)
    && isString(value.type)
    && Array.isArray(value.options)
    && value.options.every(isString)
    && (value.nodeFilter === undefined || isString(value.nodeFilter))
}

function validRule(value: unknown): value is RoutingRule {
  return isRecord(value)
    && isString(value.type)
    && isString(value.group)
    && (value.value === undefined || isString(value.value))
    && (value.raw === undefined || isString(value.raw))
    && (value.options === undefined || stringArray(value.options) !== undefined)
    && (value.noResolve === undefined || typeof value.noResolve === 'boolean')
}

function validRuleSet(value: unknown): value is SchemeRuleSet {
  return isRecord(value)
    && isString(value.id)
    && isString(value.name)
    && isString(value.group)
    && Array.isArray(value.rules)
    && value.rules.every(validRule)
}

function validSource(value: unknown): value is SubscriptionSource {
  return isRecord(value)
    && isString(value.id)
    && isString(value.name)
    && isString(value.url)
    && (value.isEnabled === undefined || typeof value.isEnabled === 'boolean')
    && (value.excludedNodeKeys === undefined || stringArray(value.excludedNodeKeys) !== undefined)
}

function normalizedUsage(value: unknown): SubscriptionUsage | undefined {
  if (!isRecord(value)) return undefined
  const usage: SubscriptionUsage = {}
  let matched = false
  for (const key of ['upload', 'download', 'total', 'expire'] as const) {
    const item = value[key]
    if (typeof item !== 'number' || !Number.isFinite(item) || item < 0) continue
    usage[key] = Math.floor(item)
    matched = true
  }
  return matched ? usage : undefined
}

export function normalizeSource(value: SubscriptionSource): SubscriptionSource {
  const usage = normalizedUsage(value.usage)
  const derived = usageFieldsFrom(usage)
  const totalBytes = typeof value.totalBytes === 'number' && Number.isFinite(value.totalBytes) && value.totalBytes > 0
    ? value.totalBytes
    : derived.totalBytes
  return {
    ...value,
    usage,
    // 旧快照/旧备份可能没有这两个字段；补成默认值，否则界面读取
    // excludedNodeKeys.length 会直接抛错，订阅也永远刷新失败。
    isEnabled: value.isEnabled === false ? false : true,
    excludedNodeKeys: Array.isArray(value.excludedNodeKeys) ? value.excludedNodeKeys : [],
    // 旧备份只有 usage；恢复时补出新字段，损坏字段则回退到 usage 推导。
    expireAt: typeof value.expireAt === 'number' && Number.isFinite(value.expireAt) && value.expireAt >= 0
      ? value.expireAt
      : derived.expireAt,
    totalBytes,
    // 有限总量优先；只有确实没有上限时才认不限量，避免旧字段互相矛盾。
    unlimited: totalBytes === undefined
      ? (value.unlimited === true || derived.unlimited === true ? true : undefined)
      : undefined,
    usedBytes: typeof value.usedBytes === 'number' && Number.isFinite(value.usedBytes) && value.usedBytes >= 0
      ? value.usedBytes
      : derived.usedBytes,
  }
}

function validNode(value: unknown): value is ProxyNode {
  return isRecord(value)
    && isString(value.id)
    && isString(value.kind)
    && NODE_KINDS.has(value.kind)
    && isString(value.name)
    && isString(value.server)
    && typeof value.port === 'number'
    && Number.isInteger(value.port)
    && value.port >= 1
    && value.port <= 65535
    && (value.sourceID === undefined || isString(value.sourceID))
    && (value.isManual === undefined || typeof value.isManual === 'boolean')
    && (value.isEnabled === undefined || typeof value.isEnabled === 'boolean')
    && (value.tls === undefined || typeof value.tls === 'boolean')
    && (value.skipCertificateVerification === undefined || typeof value.skipCertificateVerification === 'boolean')
}

function validScheme(value: unknown): value is RuleScheme {
  return isRecord(value)
    && isString(value.id)
    && isString(value.name)
    && Array.isArray(value.groups)
    && value.groups.every(validGroup)
    && Array.isArray(value.rules)
    && value.rules.every(validRule)
    && (value.customRules === undefined
      || (Array.isArray(value.customRules) && value.customRules.every(validRule)))
    && (value.ruleSets === undefined
      || (Array.isArray(value.ruleSets) && value.ruleSets.every(validRuleSet)))
}

/** LocalRuleSet 的规则没有 group（加入方案时才补），不能复用 validRule 的组名要求。 */
function validLocalRule(value: unknown): boolean {
  return isRecord(value)
    && isString(value.type)
    && (value.value === undefined || isString(value.value))
    && (value.raw === undefined || isString(value.raw))
    && (value.options === undefined || stringArray(value.options) !== undefined)
    && (value.noResolve === undefined || typeof value.noResolve === 'boolean')
}

function validLocalRuleSet(value: unknown): value is LocalRuleSet {
  return isRecord(value)
    && isString(value.id)
    && isString(value.name)
    && Array.isArray(value.rules)
    && value.rules.every(validLocalRule)
}

function numberOr(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback
}

/**
 * 固化数据容错 + 迁移：
 * - 新结构：`schemeSnapshots[id] = { id, schemeID, scheme, ruleSets, source, createdAt }`，
 *   覆盖层只存 `{ snapshotId }`。
 * - 旧结构（0.3.3 及以前）：覆盖层里内联 scheme + ruleSets，这里转成 1 号…N 号快照，
 *   不因为升级丢固化内容；迁移失败的单条只丢这一条，不牵连整个工作区。
 * - 指针指向缺失 / 损坏快照时，只丢指针，`loadScheme` 会回落上一版或原厂。
 */
export interface NormalizedBuiltinSchemes {
  builtinSchemeOverrides: Record<string, BuiltinSchemeOverrideRef>
  schemeSnapshots: Record<string, BuiltinSchemeSnapshot>
  snapshotSeq: number
}

function normalizeSnapshotContent(value: Record<string, unknown>): BuiltinSchemeSnapshotContent | undefined {
  if (!validScheme(value.scheme)) return undefined
  if (!Array.isArray(value.ruleSets) || !value.ruleSets.every(validLocalRuleSet)) return undefined
  const source = value.source
  if (!isRecord(source) || !isString(source.iniURL)) return undefined
  if (!isString(source.commitSha) || !/^[0-9a-f]{40}$/i.test(source.commitSha)) return undefined
  const files = (Array.isArray(source.files) ? source.files : [])
    .filter((file): file is Record<string, unknown> => isRecord(file)
      && isString(file.path)
      && isString(file.blobSha)
      && /^[0-9a-f]{40}$/i.test(file.blobSha))
    .map((file) => ({
      path: file.path as string,
      blobSha: file.blobSha as string,
      ...(isString(file.etag) ? { etag: file.etag } : {}),
    }))
  const ruleSets = value.ruleSets as LocalRuleSet[]
  return {
    scheme: value.scheme as RuleScheme,
    ruleSets,
    source: {
      iniURL: source.iniURL,
      commitSha: source.commitSha.toLowerCase(),
      files,
      fetchedAt: numberOr(source.fetchedAt, 0),
      // 条数直接从正文重算，旧记录里写错也不会把可用快照判成损坏。
      ruleCount: (value.scheme as RuleScheme).rules.length,
      ruleSetCount: ruleSets.length,
    },
  }
}

export function normalizeBuiltinSchemes(
  overridesValue: unknown,
  snapshotsValue?: unknown,
  seqValue?: unknown,
  protectedRuleSetIDs?: Iterable<string>,
): NormalizedBuiltinSchemes {
  const snapshots: Record<string, BuiltinSchemeSnapshot> = {}
  const rawSnapshots = Array.isArray(snapshotsValue)
    ? snapshotsValue.map((item, index) => [String(index), item] as const)
    : isRecord(snapshotsValue)
      ? Object.entries(snapshotsValue)
      : []
  for (const [key, item] of rawSnapshots) {
    if (!isRecord(item)) continue
    const content = normalizeSnapshotContent(item)
    if (!content) continue
    const id = typeof item.id === 'number' && Number.isInteger(item.id) && item.id > 0
      ? item.id
      : Number(key)
    if (!Number.isInteger(id) || id <= 0) continue
    if (snapshots[String(id)]) continue
    const schemeID = isString(item.schemeID) ? item.schemeID : content.scheme.id
    if (!schemeID) continue
    const candidate: BuiltinSchemeSnapshot = {
      ...content,
      id,
      schemeID,
      createdAt: typeof item.createdAt === 'number' && Number.isFinite(item.createdAt)
        ? item.createdAt
        : content.source.fetchedAt,
    }
    if (isBuiltinSchemeSnapshotValid(candidate)) snapshots[String(id)] = candidate
  }

  let seq = typeof seqValue === 'number' && Number.isFinite(seqValue) && seqValue >= 0
    ? Math.floor(seqValue)
    : 0
  for (const snapshot of Object.values(snapshots)) seq = Math.max(seq, snapshot.id)

  const overrides: Record<string, BuiltinSchemeOverrideRef> = {}
  if (isRecord(overridesValue)) {
    for (const [schemeID, item] of Object.entries(overridesValue)) {
      if (!isRecord(item)) continue
      const ref = item.snapshotId
      if (typeof ref === 'number' && Number.isInteger(ref) && ref > 0) {
        // 新结构：快照必须存在且归属一致，否则丢指针（加载回落原厂 / 上一版）。
        const snapshot = snapshots[String(ref)]
        if (snapshot && snapshot.schemeID === schemeID) overrides[schemeID] = { snapshotId: ref }
        continue
      }
      // 旧结构：内联正文 → 分配一个新 id 的快照。
      const content = normalizeSnapshotContent(item)
      if (!content) continue
      seq += 1
      const snapshot: BuiltinSchemeSnapshot = {
        ...content,
        id: seq,
        schemeID,
        createdAt: content.source.fetchedAt,
      }
      if (!isBuiltinSchemeSnapshotValid(snapshot)) continue
      snapshots[String(seq)] = snapshot
      overrides[schemeID] = { snapshotId: seq }
    }
  }

  return {
    builtinSchemeOverrides: overrides,
    schemeSnapshots: pruneBuiltinSchemeSnapshots(snapshots, overrides, protectedRuleSetIDs),
    snapshotSeq: seq,
  }
}

function validTailnet(value: unknown): value is TailnetConnection {
  return isRecord(value)
    && isString(value.id)
    && isString(value.name)
    && Array.isArray(value.subnets)
    && value.subnets.every(isString)
    && typeof value.isEnabled === 'boolean'
}

function normalizeContentModes(value: unknown): Partial<Record<ClientTarget, ExportContentMode>> {
  if (!isRecord(value)) return {}
  const modes: Partial<Record<ClientTarget, ExportContentMode>> = {}
  for (const [target, mode] of Object.entries(value)) {
    if (mode === 'full' || mode === 'nodes') modes[target as ClientTarget] = mode
  }
  return modes
}

function normalizeNodeNameFilter(value: unknown): NodeNameFilterSettings {
  if (!isRecord(value)) return { ...DEFAULT_NODE_NAME_FILTER }
  return {
    include: stringOr(value.include, ''),
    exclude: stringOr(value.exclude, ''),
    useRegex: booleanOr(value.useRegex, false),
    caseSensitive: booleanOr(value.caseSensitive, false),
  }
}

/**
 * 兼容同一版本备份里缺失的设置项：用户数据仍可恢复，设置回退到当前默认值。
 * 数组类用户数据如果损坏则直接拒绝，避免恢复出一份看似成功的空配置。
 */
export function parseBackup(text: string): BackupFile {
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch {
    throw new Error('不是有效的 JSON 文件')
  }
  if (!isRecord(raw)) throw new Error('备份文件内容不是对象')
  if (raw.app !== BACKUP_APP) throw new Error('这不是塔台 Web 的备份文件')
  if (raw.version !== BACKUP_VERSION) throw new Error(`不支持的备份版本：${String(raw.version)}`)
  if (!isRecord(raw.data)) throw new Error('备份文件缺少 data')

  const data = raw.data
  for (const key of ['sources', 'nodes', 'customSchemes', 'localRuleSets']) {
    if (!Array.isArray(data[key])) throw new Error(`备份文件缺少 ${key}`)
  }
  if (!isString(data.selectedSchemeID)) throw new Error('备份文件缺少 selectedSchemeID')

  const sourceValues = data.sources as unknown[]
  const sources = sourceValues.filter(validSource).map(normalizeSource)
  if (sources.length !== sourceValues.length) throw new Error('备份文件里的订阅数据不完整')
  const nodeValues = data.nodes as unknown[]
  const nodes = nodeValues.filter(validNode)
  if (nodes.length !== nodeValues.length) throw new Error('备份文件里的节点数据不完整')
  const schemeValues = data.customSchemes as unknown[]
  const customSchemes = schemeValues.filter(validScheme)
  if (customSchemes.length !== schemeValues.length) throw new Error('备份文件里的规则方案不完整')
  const localSetValues = data.localRuleSets as unknown[]
  const localRuleSets = localSetValues.filter(validLocalRuleSet)
  if (localRuleSets.length !== localSetValues.length) throw new Error('备份文件里的规则集不完整')
  // Tailscale 内网是较晚加入的持久化字段；旧备份没有时按空列表恢复。
  const tailnetValues = Array.isArray(data.tailnets) ? data.tailnets as unknown[] : []
  const tailnets = tailnetValues.filter(validTailnet)
  if (tailnets.length !== tailnetValues.length) throw new Error('备份文件里的 Tailscale 内网数据不完整')

  const policySelections: Record<string, string> = {}
  if (isRecord(data.policySelections)) {
    for (const [group, selection] of Object.entries(data.policySelections)) {
      if (isString(selection)) policySelections[group] = selection
    }
  }

  return {
    app: BACKUP_APP,
    version: BACKUP_VERSION,
    exportedAt: stringOr(raw.exportedAt, ''),
    data: {
      sources,
      nodes,
      selectedSchemeID: data.selectedSchemeID,
      policySelections,
      customSchemes,
      localRuleSets,
      ...normalizeBuiltinSchemes(
        data.builtinSchemeOverrides,
        data.schemeSnapshots,
        data.snapshotSeq,
        customSchemes.flatMap((scheme) => (scheme.ruleSets ?? []).map((ruleSet) => ruleSet.id)),
      ),
      ruleSetExclusions: normalizeRuleSetExclusions(data.ruleSetExclusions),
      checkBuiltinSchemeUpdatesOnOpen: booleanOr(data.checkBuiltinSchemeUpdatesOnOpen, false),
      autoRefreshOnOpen: booleanOr(data.autoRefreshOnOpen, false),
      autoRefreshRuleSetsOnOpen: booleanOr(data.autoRefreshRuleSetsOnOpen, false),
      preferRuleSets: booleanOr(data.preferRuleSets, false),
      exportContentMode: data.exportContentMode === 'nodes' ? 'nodes' : 'full',
      exportContentModes: normalizeContentModes(data.exportContentModes),
      embedRemoteSubscriptions: booleanOr(data.embedRemoteSubscriptions, false),
      exportProtocols: (stringArray(data.exportProtocols) ?? []) as ProxyKind[],
      exportRegions: (stringArray(data.exportRegions) ?? [])
        .map((code) => code.trim().toUpperCase())
        .filter((code) => /^[A-Z]{2}$/.test(code)),
      exportConfigName: stringOr(data.exportConfigName, 'tower').slice(0, 48),
      appendSourceName: booleanOr(data.appendSourceName, false),
      clientOrder: (stringArray(data.clientOrder) ?? []) as ClientTarget[],
      hiddenClients: (stringArray(data.hiddenClients) ?? []) as ClientTarget[],
      nodeNameFilter: normalizeNodeNameFilter(data.nodeNameFilter),
      filterSubscriptionInfoNodes: booleanOr(data.filterSubscriptionInfoNodes, false),
      renewalRemindersEnabled: booleanOr(data.renewalRemindersEnabled, false),
      showGroupEmoji: booleanOr(data.showGroupEmoji, false),
      ruleSetVersionHistory: booleanOr(data.ruleSetVersionHistory, true),
      latencyTestMode: data.latencyTestMode === 'icmp' || data.latencyTestMode === 'automatic'
        ? data.latencyTestMode
        : 'tcp',
      tailnets,
    },
  }
}

export function createBackup(data: PersistedData, now = Date.now()): BackupFile {
  return {
    app: BACKUP_APP,
    version: BACKUP_VERSION,
    exportedAt: new Date(now).toISOString(),
    data,
  }
}

export function backupCounts(data: PersistedData): BackupCounts {
  const activeNodes = data.nodes.filter((node) => !node.isSubscriptionMetadata)
  return {
    sources: data.sources.length,
    nodes: activeNodes.length,
    manualNodes: activeNodes.filter((node) => node.isManual).length,
    schemes: data.customSchemes.length,
    ruleSets: data.localRuleSets.length,
    tailnets: data.tailnets.length,
  }
}

export function backupFileName(now = new Date()): string {
  const pad = (value: number) => String(value).padStart(2, '0')
  return `tower-backup-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}.json`
}
