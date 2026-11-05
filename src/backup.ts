// 本机数据备份：只包含持久化快照，不包含测速结果、瞬时错误和密钥。
// 恢复前由界面再次确认；备份文件本身含订阅地址与节点凭据，不能公开分享。
import { PROXY_KIND_TITLES } from './models/types'
import type {
  BuiltinSchemeOverride,
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
  SchemeRuleSet,
  SubscriptionSource,
  SubscriptionUsage,
  TailnetConnection,
} from './models/types'
import { usageFieldsFrom } from './models/types'

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
  /** 内置方案覆盖层；缺失或损坏时按空处理，加载会回落到原厂快照。 */
  builtinSchemeOverrides?: Record<string, BuiltinSchemeOverride>
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

function validLocalRuleSet(value: unknown): value is LocalRuleSet {
  return isRecord(value)
    && isString(value.id)
    && isString(value.name)
    && Array.isArray(value.rules)
    && value.rules.every(validRule)
}

function numberOr(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback
}

/**
 * 内置方案覆盖层容错：单条记录损坏就丢弃，而不是让整个工作区 / 备份判定为损坏。
 * 丢弃后 `loadScheme` 会自动回落到原厂快照。
 */
export function normalizeBuiltinSchemeOverrides(value: unknown): Record<string, BuiltinSchemeOverride> {
  if (!isRecord(value)) return {}
  const out: Record<string, BuiltinSchemeOverride> = {}
  for (const [id, item] of Object.entries(value)) {
    if (!isRecord(item) || !validScheme(item.scheme)) continue
    if (!Array.isArray(item.ruleSets) || !item.ruleSets.every(validLocalRuleSet)) continue
    const source = item.source
    if (!isRecord(source) || !isString(source.iniURL)) continue
    if (!isString(source.commitSha) || !/^[0-9a-f]{40}$/i.test(source.commitSha)) continue
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
    out[id] = {
      scheme: item.scheme,
      ruleSets: item.ruleSets,
      source: {
        iniURL: source.iniURL,
        commitSha: source.commitSha.toLowerCase(),
        files,
        fetchedAt: numberOr(source.fetchedAt, 0),
        ruleCount: numberOr(source.ruleCount, item.scheme.rules.length),
        ruleSetCount: numberOr(source.ruleSetCount, item.ruleSets.length),
      },
    }
  }
  return out
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
      builtinSchemeOverrides: normalizeBuiltinSchemeOverrides(data.builtinSchemeOverrides),
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
