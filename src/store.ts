// App state: subscriptions, nodes, scheme selection, policy overrides.
// Persisted to localStorage; nothing leaves the machine except the
// subscription fetches the user explicitly triggers (via /api/fetch).
import { create } from 'zustand'
import { createJSONStorage, persist } from 'zustand/middleware'
import type { AppState, BuiltinSchemeOverrideRef, BuiltinSchemeSnapshot, BuiltinSchemeSnapshotContent, ClientTarget, ExportContentMode, LatencyTestMethod, LatencyTestMode, LocalRuleSet, NodeNameFilterSettings, ProxyKind, ProxyNode, RuleScheme, RuleSetExclusionTable, SubscriptionRequestOptions, SubscriptionSource, SubscriptionUsage, TailnetConnection } from './models/types'
import { usageFieldsFrom } from './models/types'
import { isBuiltinSchemeSnapshotValid, writeBuiltinSchemeSnapshot } from './rules/schemeSnapshots'
import { addRuleSetExclusion as addExclusion, normalizeRuleSetExclusions, removeRuleSetExclusion as removeExclusion } from './rules/ruleSetExclusions'
import { loadTailnetAuthKeys, persistTailnetAuthKeys, pruneTailnetAuthKeys } from './models/tailnetAuthKeys'
import type { BackupRejection, PersistedData } from './backup'
import { clearCorruptPersistence, inspectSnapshotHealth, normalizeBuiltinSchemes, normalizeSource } from './backup'
import { BUILTIN_SCHEMES } from './rules/scheme'
import { prepareManualNodes, type ManualNodeImportResult } from './manualNodes'
import { mergeUsage, parse, parseUserinfoHeader } from './parser'
import { apiFetch } from './util/apiAuth'
import { nodeTransportCapability } from './generator/nodeCapabilities'
import { newID } from './util/browser'
import { browserStorage, createSafeStorage } from './util/localStore'
import { isWorkspaceReadOnly } from './util/workspaceLock'
import { WORKSPACE_STATE_KEYS } from './workspaceKeys'

export interface Store extends AppState {
  loadingSourceIDs: string[]
  errors: Record<string, string>
  /** node.id → latency ms; null = unreachable; absent = not tested. */
  latencyByNodeId: Record<string, number | null>
  /** node.id → 本次成功测速使用的方法。 */
  latencyMethodByNodeId: Record<string, LatencyTestMethod>
  /** node.id → 失败原因（ETIMEDOUT / ECONNREFUSED / ENOTFOUND …），成功时清除。 */
  probeErrorByNodeId: Record<string, string>
  testingNodeIds: string[]
  testingGeneration: number
  /** 自动 / ICMP / TCP 测速；默认保持 TCP，避免局域网地址被 ICMP 全部判为可用。 */
  latencyTestMode: LatencyTestMode
  customSchemes: RuleScheme[]
  /** 用户保存在本机的独立规则集。 */
  localRuleSets: LocalRuleSet[]
  /** 内置方案覆盖层指针：方案 id → snapshotId；正文在 schemeSnapshots。 */
  builtinSchemeOverrides: Record<string, BuiltinSchemeOverrideRef>
  /** 独立固化快照：自增 id → 方案 + 列表 + 来源；最多保留 2 个（原厂另算一版）。 */
  schemeSnapshots: Record<string, BuiltinSchemeSnapshot>
  /** 快照 id 自增序列，保证淘汰后不复用。 */
  snapshotSeq: number
  /** 只读规则集的本地屏蔽表：规则集 id → ruleSignature[]，刷新来源后仍生效。 */
  ruleSetExclusions: RuleSetExclusionTable
  /** 打开塔台时检查内置方案是否有上游更新；默认关闭，只提示不覆盖。 */
  checkBuiltinSchemeUpdatesOnOpen: boolean
  /** 本次会话的上游更新提示（scheme.id → 文案），不落盘。 */
  builtinSchemeUpdateNotices: Record<string, string>
  /** 打开塔台时自动刷新已启用、带 URL 的订阅；默认关闭。 */
  autoRefreshOnOpen: boolean
  /** 打开塔台时刷新「我的规则集」里的在线订阅；默认关闭。 */
  autoRefreshRuleSetsOnOpen: boolean
  /** 导出时优先引用远程规则集，减少内联规则体积；默认关闭。 */
  preferRuleSets: boolean
  /** 旧版全局内容模式；未单独设置的客户端继续使用这个值。 */
  exportContentMode: ExportContentMode
  /** 每个导出客户端单独记住的内容模式。 */
  exportContentModes: Partial<Record<ClientTarget, ExportContentMode>>
  /** 把启用订阅的原始链接写进支持代理集合的客户端配置。 */
  embedRemoteSubscriptions: boolean
  /** 只导出这些协议；空数组表示全部协议。 */
  exportProtocols: ProxyKind[]
  /** 只导出这些地区代码；空数组表示全部地区。 */
  exportRegions: string[]
  /** 配置名称，同时用于下载文件名与订阅 profile 标题。 */
  exportConfigName: string
  /** 节点名称后追加来源订阅名，便于多订阅合并时区分。 */
  appendSourceName: boolean
  /** 导出页客户端自定义顺序；空数组表示内置顺序。 */
  clientOrder: ClientTarget[]
  /** 在导出页隐藏的客户端；至少保留一个可见客户端。 */
  hiddenClients: ClientTarget[]
  /** 全局节点名称筛选，作用于导出。 */
  nodeNameFilter: NodeNameFilterSettings
  /** 隐藏流量、到期、官网、客服等订阅信息节点。 */
  filterSubscriptionInfoNodes: boolean
  /** 到期 / 流量提醒；Web 只在塔台打开时提示。 */
  renewalRemindersEnabled: boolean
  /** 在策略组列表和规则标签里显示组名开头的 Emoji。 */
  showGroupEmoji: boolean
  /** 刷新在线规则集前保留上一版快照，用于版本对比；默认开启。 */
  ruleSetVersionHistory: boolean
  /** Tailscale 内网连接；Auth Key 单独存在 tailnetAuthKeys。 */
  tailnets: TailnetConnection[]
  /** 本机保存的 Auth Key；不进入持久化快照，刷新前从独立 localStorage 读取。 */
  tailnetAuthKeys: Record<string, string>
  /** 本次会话的数据体检结果：被丢弃的备份条目 / 悬空快照指针；不落盘。 */
  persistenceWarnings: BackupRejection[]
  /** 清除损坏记录：丢掉悬空指针与损坏快照，返回清理数量。 */
  clearCorruptPersistence: () => { pointers: number; snapshots: number }
  setPersistenceWarnings: (warnings: BackupRejection[]) => void
  addSourceFromURL: (url: string, options?: SubscriptionRequestOptions) => Promise<void>
  updateSource: (id: string, patch: SourcePatch) => void
  setSourceEnabled: (id: string, enabled: boolean) => void
  setSourcesEnabled: (ids: string[], enabled: boolean) => void
  setAutoRefreshOnOpen: (enabled: boolean) => void
  setAutoRefreshRuleSetsOnOpen: (enabled: boolean) => void
  setPreferRuleSets: (enabled: boolean) => void
  setExportContentMode: (mode: ExportContentMode) => void
  setExportProtocols: (kinds: ProxyKind[]) => void
  setExportRegions: (codes: string[]) => void
  setExportConfigName: (name: string) => void
  setAppendSourceName: (enabled: boolean) => void
  setClientOrder: (order: ClientTarget[]) => void
  setClientHidden: (target: ClientTarget, hidden: boolean) => void
  setExportContentModeFor: (target: ClientTarget, mode: ExportContentMode) => void
  setEmbedRemoteSubscriptions: (enabled: boolean) => void
  setNodeNameFilter: (patch: Partial<NodeNameFilterSettings>) => void
  setFilterSubscriptionInfoNodes: (enabled: boolean) => void
  setRenewalRemindersEnabled: (enabled: boolean) => void
  setShowGroupEmoji: (enabled: boolean) => void
  setRuleSetVersionHistory: (enabled: boolean) => void
  addTailnet: (connection: TailnetConnection) => void
  updateTailnet: (connection: TailnetConnection) => void
  deleteTailnet: (id: string) => void
  setTailnetEnabled: (id: string, enabled: boolean) => void
  setTailnetAuthKey: (id: string, key?: string) => void
  /** 删除已不存在的 Tailscale 连接留下的 Auth Key。 */
  pruneTailnetKeys: () => void
  setLatencyTestMode: (mode: LatencyTestMode) => void
  setNodeCountryOverride: (nodeId: string, code?: string) => void
  /** 批量写入离线 IP 识别的国家；已有手动覆盖的节点保持不变。 */
  setNodeDetectedCountries: (byHost: Record<string, string>) => void
  addSourceFromText: (name: string, text: string) => void
  refreshSource: (id: string) => Promise<void>
  removeSource: (id: string) => void
  toggleNodeExcluded: (node: ProxyNode) => void
  /** 一次性设置某个订阅的排除列表（全选 / 全不选 / 恢复默认）。 */
  setSourceExclusions: (id: string, excludedKeys: string[]) => void
  setScheme: (id: string) => void
  setPolicy: (group: string, selection: string) => void
  /** Clear a stored preferred member after its policy group is deleted. */
  removePolicy: (group: string) => void
  renamePolicySelection: (oldName: string, newName: string) => void
  startTesting: (nodeIds: string[]) => void
  stopTesting: () => void
  addCustomScheme: (scheme: RuleScheme) => void
  removeCustomScheme: (id: string) => void
  addLocalRuleSet: (set: LocalRuleSet) => void
  removeLocalRuleSet: (id: string) => void
  /** 屏蔽只读规则集里的一条规则；按签名记录，刷新后仍生效。 */
  addRuleSetExclusion: (ruleSetID: string, signature: string) => void
  /** 解除一条屏蔽。 */
  removeRuleSetExclusion: (ruleSetID: string, signature: string) => void
  /** 撤销时用：整组恢复某个规则集之前的屏蔽列表。 */
  restoreRuleSetExclusions: (ruleSetID: string, signatures: string[]) => void
  /** 固化内置方案：新建独立快照并把指针指过去，返回新快照 id。 */
  saveBuiltinSchemeOverride: (id: string, content: BuiltinSchemeSnapshotContent) => number
  /** 回退到某个历史快照；快照缺失或归属不符时返回 false。 */
  restoreBuiltinSchemeSnapshot: (id: string, snapshotId: number) => boolean
  /** 清除覆盖层，回到原厂 `public/rulesets` 快照。 */
  clearBuiltinSchemeOverride: (id: string) => void
  setCheckBuiltinSchemeUpdatesOnOpen: (enabled: boolean) => void
  setBuiltinSchemeUpdateNotice: (id: string, notice?: string) => void
  /** 从链接 / Base64 / Clash YAML / Surge 配置导入自有节点。 */
  addManualNodes: (text: string, preferredName?: string) => ManualNodeImportResult
  /** 改名或启用 / 停用一个自有节点。 */
  updateManualNode: (id: string, patch: ManualNodePatch) => void
  /** 新建或完整编辑一个自有节点；保留启用状态和地区标记。 */
  saveManualNode: (node: ProxyNode) => void
  removeManualNode: (id: string) => void
  /** 覆盖当前订阅、节点、规则与导出设置。 */
  restoreBackup: (data: PersistedData) => void
}

export interface ManualNodePatch {
  name?: string
  isEnabled?: boolean
}

/** 把「数据体检」结果转成与备份拒绝同形的提示，复用同一套展示。 */
function inspectPersistenceWarnings(
  overrides: Record<string, BuiltinSchemeOverrideRef>,
  snapshots: Record<string, BuiltinSchemeSnapshot>,
): BackupRejection[] {
  const health = inspectSnapshotHealth(overrides, snapshots)
  return [
    ...health.dangling.map((item) => ({
      kind: 'override' as const,
      label: item.schemeID,
      reason: `指针 #${item.snapshotId} 指向的快照不存在，已回落原厂 / 上一版`,
    })),
    ...health.corrupted.map((item) => ({
      kind: 'snapshot' as const,
      label: item.schemeID,
      reason: `快照 #${item.snapshotId}：${item.reason}`,
    })),
  ]
}

/**
 * 同一订阅的并发刷新以最后一次为准；旧请求即使晚返回也不能覆盖新结果。
 * 同 URL 的并发抓取共享一次请求，同 host 的不同路径仍排队，避免机场限流。
 */
const refreshGenerations = new Map<string, number>()
const inFlightFetches = new Map<string, Promise<SubscriptionFetch>>()
const hostQueues = new Map<string, Promise<void>>()
/** 已命中的配额探测变体；同一订阅后续刷新先试它，避免每次从链头开始。 */
const quotaProbeHits = new Map<string, { url: string; ua?: string }>()
/**
 * 配额探测负缓存：同一订阅 6 小时内不再重复空探测。
 * 机场没下发用量时，一次刷新会多打 6 个只取响应头的请求；没有负缓存的话，
 * 每次刷新（包括每天自动刷新）都要再打一遍，纯属浪费且容易触发限流。
 */
export const QUOTA_PROBE_MISS_TTL_MS = 6 * 60 * 60 * 1000
const QUOTA_PROBE_CACHE_LIMIT = 64
const quotaProbeMisses = new Map<string, number>()

/** 负缓存仍然有效时返回 true；过期条目顺手清掉，让下一次刷新真正重试。 */
export function quotaProbeMissFresh(
  misses: Map<string, number>,
  key: string,
  now = Date.now(),
  ttl = QUOTA_PROBE_MISS_TTL_MS,
): boolean {
  const at = misses.get(key)
  if (at === undefined) return false
  if (now - at < ttl) return true
  misses.delete(key)
  return false
}

/** 记录一次「探测链跑完仍没有用量」，按写入顺序淘汰，上限与命中缓存一致。 */
export function rememberQuotaProbeMiss(
  misses: Map<string, number>,
  key: string,
  now = Date.now(),
  limit = QUOTA_PROBE_CACHE_LIMIT,
): void {
  misses.delete(key)
  misses.set(key, now)
  while (misses.size > limit) {
    const oldest = misses.keys().next().value
    if (oldest === undefined) break
    misses.delete(oldest)
  }
}

async function withHostQueue<T>(url: string, task: () => Promise<T>): Promise<T> {
  let host = ''
  try {
    host = new URL(url).hostname.toLowerCase()
  } catch {
    return task()
  }
  const previous = hostQueues.get(host) ?? Promise.resolve()
  let release!: () => void
  const gate = new Promise<void>((resolve) => { release = resolve })
  const tail = previous.then(() => gate)
  hostQueues.set(host, tail)
  await previous.catch(() => {})
  try {
    return await task()
  } finally {
    release()
    if (hostQueues.get(host) === tail) hostQueues.delete(host)
  }
}

function fetchSubscriptionShared(
  url: string,
  userAgent?: string,
  dnsOverHTTPSURL?: string,
  headersOnly = false,
): Promise<SubscriptionFetch> {
  const key = `${url}\n${userAgent ?? ''}\n${dnsOverHTTPSURL ?? ''}\n${headersOnly ? 'headers' : 'body'}`
  const existing = inFlightFetches.get(key)
  if (existing) return existing
  const promise = withHostQueue(url, () => fetchSubscription(url, userAgent, dnsOverHTTPSURL, headersOnly))
    .finally(() => {
      if (inFlightFetches.get(key) === promise) inFlightFetches.delete(key)
    })
  inFlightFetches.set(key, promise)
  return promise
}

/** 可编辑的订阅字段；未出现的字段保持原值。 */
export interface SourcePatch {
  name?: string
  url?: string
  /** 空字符串表示清除这项设置。 */
  userAgent?: string
  dnsOverHTTPSURL?: string
}

function normalizeUserAgent(value?: string): string | undefined {
  const trimmed = String(value ?? '').replace(/[\r\n]/g, '').trim()
  return trimmed ? trimmed.slice(0, 400) : undefined
}

/** The compatibility UA airports commonly use for their Clash converter. */
const COMPATIBILITY_USER_AGENT = 'clash.meta'

interface SubscriptionFetch {
  text: string
  usage?: SubscriptionUsage
  userAgent?: string
}

/**
 * Fetch one subscription through the local proxy. A custom UA pinned by the
 * user is never silently replaced; only the default request gets the
 * compatibility retry in `refreshSource`.
 */
async function fetchSubscription(
  url: string,
  userAgent?: string,
  dnsOverHTTPSURL?: string,
  headersOnly = false,
): Promise<SubscriptionFetch> {
  const params = new URLSearchParams({ url })
  if (userAgent) params.set('ua', userAgent)
  if (dnsOverHTTPSURL) params.set('doh', dnsOverHTTPSURL)
  if (headersOnly) params.set('headers', '1')
  const res = await apiFetch(`/api/fetch?${params.toString()}`)
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error ?? `HTTP ${res.status}`)
  }
  const usage = parseUserinfoHeader(res.headers.get('x-subscription-userinfo'))
  if (headersOnly) {
    // 探测只需要响应头；服务端会提前断开上游正文，这里也不读 body。
    await res.body?.cancel().catch(() => {})
    return { text: '', usage, userAgent }
  }
  return {
    text: await res.text(),
    usage,
    userAgent,
  }
}

/**
 * Candidate URLs for reading quota headers in the panel's Clash dialect.
 * Panels disagree: most use `flag=clash`, but some `/link/<token>` links only
 * return `subscription-userinfo` for `?clash=1`; combining it with the generic
 * `?sub=1` makes such panels answer with an empty JSON body, so drop `sub`.
 */
export function quotaProbeURLs(raw: string): string[] {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return []
  }
  const keys = [...url.searchParams.keys()]
  // 通用链接上的 `sub=1` 会压过 clash / flag=clash：真实机场在这种组合下
  // 返回空正文且不带用量头，所以只要还有 sub 就必须继续探测（去掉 sub）。
  const hasSub = keys.some((key) => key.toLowerCase() === 'sub')
  const alreadyClash = !hasSub && keys.some((key) => {
    const lower = key.toLowerCase()
    if (lower === 'clash') {
      const value = (url.searchParams.get(key) ?? '').trim().toLowerCase()
      return value !== '' && value !== '0' && value !== 'false'
    }
    return lower === 'flag' && (url.searchParams.get(key) ?? '').trim().toLowerCase() === 'clash'
  })
  if (alreadyClash) return []

  const probes: string[] = []
  const push = (next: URL) => {
    if (!probes.includes(next.href)) probes.push(next.href)
  }
  // 所有候选都去掉 `sub`：它会压过 clash / flag=clash，让面板返回空响应。
  const withoutSub = (source: URL) => {
    const next = new URL(source.href)
    for (const key of [...next.searchParams.keys()]) {
      if (key.toLowerCase() === 'sub') next.searchParams.delete(key)
    }
    return next
  }
  if (hasSub) {
    const bare = withoutSub(url)
    bare.searchParams.set('clash', '1')
    push(bare)
  }
  const flag = withoutSub(url)
  const flagKey = [...flag.searchParams.keys()].find((key) => key.toLowerCase() === 'flag')
  // 通用链接常带 flag=ss / flag=v2ray，这里替换成 clash 再探测一次，
  // 否则会直接跳过探测、永远拿不到只在 Clash 方言下发的用量头。
  if (flagKey) flag.searchParams.delete(flagKey)
  flag.searchParams.set('flag', 'clash')
  push(flag)
  const clash = withoutSub(url)
  // 已有 flag 时用 clash=1 替代，避免两个方言参数同时出现让面板返回空响应。
  const clashFlagKey = [...clash.searchParams.keys()].find((key) => key.toLowerCase() === 'flag')
  if (clashFlagKey) clash.searchParams.delete(clashFlagKey)
  clash.searchParams.set('clash', '1')
  push(clash)
  return probes
}

/**
 * 探测链是否还需要继续：只要拿到任意一项真实用量（总量 / 已用 / 到期），
 * 或者机场明确表示不限量（total=0 + upload/download），就不算“缺失”。
 * 单独的 total=0 无法区分“不限量”与“没填”，仍按缺失处理。
 */
export function usageIsUsable(usage?: SubscriptionUsage): boolean {
  if (!usage) return false
  if (typeof usage.total === 'number' && usage.total > 0) return true
  if (typeof usage.expire === 'number') return true
  if (typeof usage.upload === 'number' || typeof usage.download === 'number') return true
  return false
}

/**
 * Identity keys for exclusion carry-over (constraint #22):
 * node ids are regenerated on every parse and airports rewrite remarks, so
 * exact match on the full identity first, then a remark-free loose key that
 * is only trusted when unique on BOTH sides of the refresh.
 */
function exactKey(node: ProxyNode): string {
  return [
    node.kind, node.server.toLowerCase(), node.port,
    node.cipher ?? '', node.uuid ?? '', node.password ?? '',
    node.transport ?? '', node.sni ?? '', node.name,
  ].join('|')
}

function looseKey(node: ProxyNode): string {
  return [
    node.kind, node.server.toLowerCase(), node.port,
    node.cipher ?? '', node.uuid ?? '', node.password ?? '',
    node.transport ?? '', node.sni ?? '',
  ].join('|')
}

function carriedOverExclusions(
  oldNodes: ProxyNode[],
  newNodes: ProxyNode[],
  excludedKeys: string[] = [],
): string[] {
  if (!excludedKeys.length) return []
  const excludedSet = new Set(excludedKeys)
  const oldExcluded = oldNodes.filter((n) => excludedSet.has(exactKey(n)) || excludedSet.has(looseKey(n)))
  if (!oldExcluded.length) return []

  // Uniqueness maps over both generations.
  const unique = (nodes: ProxyNode[], key: (n: ProxyNode) => string) => {
    const counts = new Map<string, number>()
    for (const n of nodes) counts.set(key(n), (counts.get(key(n)) ?? 0) + 1)
    return counts
  }
  const oldExact = unique(oldNodes, exactKey)
  const newExact = unique(newNodes, exactKey)
  const oldLoose = unique(oldNodes, looseKey)
  const newLoose = unique(newNodes, looseKey)

  const carried = new Set<string>()
  for (const old of oldExcluded) {
    const ek = exactKey(old)
    if (oldExact.get(ek) === 1 && newExact.get(ek) === 1) {
      const match = newNodes.find((n) => exactKey(n) === ek)!
      carried.add(exactKey(match))
      continue
    }
    const lk = looseKey(old)
    if (oldLoose.get(lk) === 1 && newLoose.get(lk) === 1) {
      const match = newNodes.find((n) => looseKey(n) === lk)!
      carried.add(exactKey(match))
    }
  }
  return [...carried]
}

/**
 * 本机持久化与备份共用的字段。
 * 不包含测速结果、瞬时错误、Tailscale Auth Key 和已发布订阅 token。
 */
export function persistedSnapshot(s: Store): PersistedData {
  return {
    sources: s.sources,
    nodes: s.nodes,
    selectedSchemeID: s.selectedSchemeID,
    policySelections: s.policySelections,
    customSchemes: s.customSchemes,
    localRuleSets: s.localRuleSets,
    builtinSchemeOverrides: s.builtinSchemeOverrides,
    schemeSnapshots: s.schemeSnapshots,
    snapshotSeq: s.snapshotSeq,
    ruleSetExclusions: s.ruleSetExclusions,
    checkBuiltinSchemeUpdatesOnOpen: s.checkBuiltinSchemeUpdatesOnOpen,
    autoRefreshOnOpen: s.autoRefreshOnOpen,
    autoRefreshRuleSetsOnOpen: s.autoRefreshRuleSetsOnOpen,
    preferRuleSets: s.preferRuleSets,
    exportContentMode: s.exportContentMode,
    exportContentModes: s.exportContentModes,
    embedRemoteSubscriptions: s.embedRemoteSubscriptions,
    exportProtocols: s.exportProtocols,
    exportRegions: s.exportRegions,
    exportConfigName: s.exportConfigName,
    appendSourceName: s.appendSourceName,
    clientOrder: s.clientOrder,
    hiddenClients: s.hiddenClients,
    nodeNameFilter: s.nodeNameFilter,
    filterSubscriptionInfoNodes: s.filterSubscriptionInfoNodes,
    renewalRemindersEnabled: s.renewalRemindersEnabled,
    showGroupEmoji: s.showGroupEmoji,
    ruleSetVersionHistory: s.ruleSetVersionHistory,
    latencyTestMode: s.latencyTestMode,
    tailnets: s.tailnets,
  }
}

/** 服务器版工作区里会落盘的字段；只读时只拦这些，设备偏好不受影响。 */
const WORKSPACE_STATE_KEY_SET = new Set<string>(WORKSPACE_STATE_KEYS)

export const useStore = create<Store>()(
  persist(
    (set, get): Store => {
      // 服务器版只读时只拦「会写服务端」的字段；设备偏好与测速等运行时状态
      // 仍要能用。服务端 hydrate 走 useStore.setState，不经过这里。
      const rawSet = set as (partial: unknown, replace?: unknown) => void
      const guardedSet = ((partial: unknown, replace?: unknown) => {
        if (!isWorkspaceReadOnly()) {
          rawSet(partial, replace)
          return
        }
        const resolved = typeof partial === 'function'
          ? (partial as (state: Store) => unknown)(get())
          : partial
        if (!resolved || typeof resolved !== 'object') return
        const allowed = Object.fromEntries(
          Object.entries(resolved as Record<string, unknown>)
            .filter(([key]) => !WORKSPACE_STATE_KEY_SET.has(key)),
        )
        if (Object.keys(allowed).length === 0) return
        rawSet(allowed, false)
      }) as typeof set
      set = guardedSet
      return {
      sources: [],
      nodes: [],
      selectedSchemeID: 'acl4ssr-online',
      policySelections: {},
      customSchemes: [],
      localRuleSets: [],
      builtinSchemeOverrides: {},
      schemeSnapshots: {},
      snapshotSeq: 0,
      ruleSetExclusions: {},
      checkBuiltinSchemeUpdatesOnOpen: false,
      builtinSchemeUpdateNotices: {},
      persistenceWarnings: [],
      loadingSourceIDs: [],
      errors: {},
      latencyByNodeId: {},
      latencyMethodByNodeId: {},
      probeErrorByNodeId: {},
      testingNodeIds: [],
      testingGeneration: 0,
      latencyTestMode: 'tcp',
      autoRefreshOnOpen: false,
      autoRefreshRuleSetsOnOpen: false,
      preferRuleSets: false,
      exportContentMode: 'full',
      exportContentModes: {},
      embedRemoteSubscriptions: false,
      exportProtocols: [],
      exportRegions: [],
      exportConfigName: 'tower',
      appendSourceName: false,
      clientOrder: [],
      hiddenClients: [],
      nodeNameFilter: { include: '', exclude: '', useRegex: false, caseSensitive: false },
      filterSubscriptionInfoNodes: false,
      renewalRemindersEnabled: false,
      showGroupEmoji: false,
      ruleSetVersionHistory: true,
      tailnets: [],
      tailnetAuthKeys: loadTailnetAuthKeys(),

      addSourceFromURL: async (url, options) => {
        const trimmed = url.trim()
        if (!trimmed) return
        const existing = get().sources.find((s) => s.url === trimmed)
        if (existing) {
          if (options?.userAgent !== undefined || options?.dnsOverHTTPSURL !== undefined) {
            get().updateSource(existing.id, {
              userAgent: options.userAgent ?? '',
              dnsOverHTTPSURL: options.dnsOverHTTPSURL ?? '',
            })
          }
          return get().refreshSource(existing.id)
        }
        const source: SubscriptionSource = {
          id: newID(),
          name: new URL(trimmed).hostname,
          url: trimmed,
          isEnabled: true,
          userAgent: normalizeUserAgent(options?.userAgent),
          dnsOverHTTPSURL: options?.dnsOverHTTPSURL?.trim() || undefined,
          excludedNodeKeys: [],
        }
        set((s) => ({ sources: [...s.sources, source] }))
        await get().refreshSource(source.id)
      },

      updateSource: (id, patch) =>
        set((s) => ({
          sources: s.sources.map((src) => {
            if (src.id !== id) return src
            const next: SubscriptionSource = { ...src }
            if (patch.name !== undefined) {
              const name = patch.name.trim()
              if (name) next.name = name
            }
            if (patch.url !== undefined) next.url = patch.url.trim()
            if (patch.userAgent !== undefined) next.userAgent = normalizeUserAgent(patch.userAgent)
            if (patch.dnsOverHTTPSURL !== undefined) {
              next.dnsOverHTTPSURL = patch.dnsOverHTTPSURL.trim() || undefined
            }
            return next
          }),
        })),

      setSourceEnabled: (id, enabled) =>
        set((s) => ({
          sources: s.sources.map((src) =>
            src.id === id ? { ...src, isEnabled: enabled } : src,
          ),
        })),

      setSourcesEnabled: (ids, enabled) =>
        set((s) => ({
          sources: s.sources.map((src) =>
            ids.includes(src.id) ? { ...src, isEnabled: enabled } : src,
          ),
        })),

      setAutoRefreshOnOpen: (enabled) => set({ autoRefreshOnOpen: enabled }),
      setAutoRefreshRuleSetsOnOpen: (enabled) => set({ autoRefreshRuleSetsOnOpen: enabled }),
      setPreferRuleSets: (enabled) => set({ preferRuleSets: enabled }),
      setExportContentMode: (mode) => set({ exportContentMode: mode }),
      setExportProtocols: (kinds) => set({ exportProtocols: [...new Set(kinds)] }),
      setExportRegions: (codes) => set({ exportRegions: [...new Set(codes.map((code) => code.trim().toUpperCase()).filter(Boolean))] }),
      setExportConfigName: (name) =>
        set({ exportConfigName: String(name).replace(/[\r\n]/g, '').slice(0, 48) }),
      setAppendSourceName: (enabled) => set({ appendSourceName: enabled }),
      setClientOrder: (order) => set({ clientOrder: [...new Set(order)] }),
      setClientHidden: (target, hidden) =>
        set((s) => ({
          hiddenClients: hidden
            ? [...new Set([...s.hiddenClients, target])]
            : s.hiddenClients.filter((t) => t !== target),
        })),
      setExportContentModeFor: (target, mode) =>
        set((s) => ({ exportContentModes: { ...s.exportContentModes, [target]: mode } })),
      setEmbedRemoteSubscriptions: (enabled) => set({ embedRemoteSubscriptions: enabled }),
      setNodeNameFilter: (patch) =>
        set((s) => ({ nodeNameFilter: { ...s.nodeNameFilter, ...patch } })),
      setFilterSubscriptionInfoNodes: (enabled) => set({ filterSubscriptionInfoNodes: enabled }),
      setRenewalRemindersEnabled: (enabled) => set({ renewalRemindersEnabled: enabled }),
      setShowGroupEmoji: (enabled) => set({ showGroupEmoji: enabled }),
      setRuleSetVersionHistory: (enabled) => set({ ruleSetVersionHistory: enabled }),
      addTailnet: (connection) =>
        set((s) => ({
          tailnets: [...s.tailnets.filter((item) => item.id !== connection.id), connection],
        })),
      updateTailnet: (connection) =>
        set((s) => ({
          tailnets: s.tailnets.map((item) => item.id === connection.id ? connection : item),
        })),
      deleteTailnet: (id) => {
        const authKeys = { ...get().tailnetAuthKeys }
        delete authKeys[id]
        persistTailnetAuthKeys(authKeys)
        set((s) => ({
          tailnets: s.tailnets.filter((item) => item.id !== id),
          tailnetAuthKeys: authKeys,
        }))
      },
      setTailnetEnabled: (id, enabled) =>
        set((s) => ({
          tailnets: s.tailnets.map((item) => item.id === id ? { ...item, isEnabled: enabled } : item),
        })),
      setTailnetAuthKey: (id, key) => {
        // Auth Key 另存 localStorage，不走 store 闸门；只读时必须在这里拦住，
        // 否则界面虽然灰了，本机缓存仍会被改写。
        if (isWorkspaceReadOnly()) return
        const authKeys = { ...get().tailnetAuthKeys }
        const normalized = key?.trim()
        if (normalized) authKeys[id] = normalized
        else delete authKeys[id]
        persistTailnetAuthKeys(authKeys)
        set({ tailnetAuthKeys: authKeys })
      },
      pruneTailnetKeys: () => {
        if (isWorkspaceReadOnly()) return
        const state = get()
        const validIds = new Set(state.tailnets.map((item) => item.id))
        const authKeys = pruneTailnetAuthKeys(state.tailnetAuthKeys, validIds)
        if (Object.keys(authKeys).length === Object.keys(state.tailnetAuthKeys).length) return
        persistTailnetAuthKeys(authKeys)
        set({ tailnetAuthKeys: authKeys })
      },
      setLatencyTestMode: (mode) => set({ latencyTestMode: mode }),
      setNodeCountryOverride: (nodeId, code) =>
        set((s) => ({
          nodes: s.nodes.map((node) =>
            node.id === nodeId
              ? { ...node, countryOverride: code?.toUpperCase() || undefined }
              : node,
          ),
        })),
      setNodeDetectedCountries: (byHost) =>
        set((s) => {
          if (Object.keys(byHost).length === 0) return s
          return {
            nodes: s.nodes.map((node) => {
              const code = byHost[node.server]
              if (!code || node.countryOverride || node.detectedCountry) return node
              return { ...node, detectedCountry: code.toUpperCase() }
            }),
          }
        }),

      addSourceFromText: (name, text) => {
        const source: SubscriptionSource = {
          id: newID(),
          name: name.trim() || '粘贴的订阅',
          url: '',
          isEnabled: true,
          excludedNodeKeys: [],
        }
        const parsed = parse(text, source.id)
        source.usage = parsed.status
        Object.assign(source, usageFieldsFrom(parsed.status))
        source.updatedAt = Date.now()
        const nodes = parsed.nodes
        set((s) => ({
          sources: [...s.sources, source],
          nodes: [...s.nodes.filter((n) => n.sourceID !== source.id), ...nodes],
        }))
      },

      refreshSource: async (id) => {
        const source = get().sources.find((s) => s.id === id)
        if (!source) return
        if (!source.url) return // pasted content has nothing to refresh
        const generation = (refreshGenerations.get(id) ?? 0) + 1
        refreshGenerations.set(id, generation)
        const isCurrent = () => refreshGenerations.get(id) === generation
        set((s) => ({
          loadingSourceIDs: [...s.loadingSourceIDs.filter((x) => x !== id), id],
          errors: { ...s.errors, [id]: '' },
        }))
        try {
          const customUserAgent = normalizeUserAgent(source.userAgent)
          const userAgentAttempts: (string | undefined)[] = customUserAgent
            ? [customUserAgent]
            : [undefined, COMPATIBILITY_USER_AGENT]
          let fetched: SubscriptionFetch | undefined
          let parsed: ReturnType<typeof parse> | undefined
          let lastError: unknown
          for (const attempt of userAgentAttempts) {
            try {
              const result = await fetchSubscriptionShared(
                source.url,
                attempt,
                source.dnsOverHTTPSURL?.trim(),
              )
              // 用户可能在请求途中删掉了这个订阅，或又发起了一次刷新；
              // 旧请求不能把过期节点写回来。
              if (!isCurrent() || !get().sources.some((s) => s.id === id)) return
              const candidate = parse(result.text, id)
              if (!candidate.nodes.some((n) => !n.isSubscriptionMetadata)) {
                lastError = new Error(
                  candidate.reason
                    ?? (candidate.rejectedLineCount
                      ? `没有解析到可用节点（${candidate.rejectedLineCount} 行无法识别），请检查订阅内容或地址`
                      : '没有解析到可用节点，请检查订阅内容或地址'),
                )
                continue
              }
              fetched = result
              parsed = candidate
              break
            } catch (error) {
              lastError = error
            }
          }
          if (!fetched || !parsed) throw lastError
          if (!isCurrent() || !get().sources.some((s) => s.id === id)) return
          let usage = mergeUsage(parsed.status, fetched.usage)
          const quotaKey = `${source.id}\n${source.url}\n${source.userAgent ?? ''}`
          // 只有 upload/download（没有 total）、以及 total=0 的不限量声明，
          // 都已经是真实用量，不能当成什么都没返回，否则会误判成缺失并反复探测。
          const missingQuota = () => !usageIsUsable(usage)
          if (!missingQuota()) {
            // 已经拿到用量，清掉历史空结果，未来再缺失时重新探测。
            quotaProbeMisses.delete(quotaKey)
          } else if (!quotaProbeMissFresh(quotaProbeMisses, quotaKey)) {
            const probes = quotaProbeURLs(source.url)
            if (probes.length > 0) {
              const doh = source.dnsOverHTTPSURL?.trim()
              // 先按当前 UA 逐个尝试 Clash 方言链接；只有用户没固定 UA 时才补试
              // 机场常用的转换器 UA。固定 UA 的语义是“这条订阅只以这个身份请求”，
              // 探测也不能偷偷换身份去打同一个地址。
              const plan: { url: string; ua?: string }[] = probes.map((url) => ({ url, ua: fetched.userAgent }))
              if (!fetched.userAgent) {
                const compatibilityUAs = [COMPATIBILITY_USER_AGENT, 'ClashforWindows/0.20.39']
                for (const ua of compatibilityUAs) {
                  for (const probe of probes.slice(0, 2)) plan.push({ url: probe, ua })
                }
              }
              // 上一次命中的变体排到最前，失败时仍回退到完整链。
              const cached = quotaProbeHits.get(quotaKey)
              if (cached) plan.unshift(cached)
              const seen = new Set<string>()
              const attempts = plan.filter((attempt) => {
                const key = `${attempt.url}\n${attempt.ua ?? ''}`
                if (seen.has(key)) return false
                seen.add(key)
                return true
              }).slice(0, 6)
              for (const attempt of attempts) {
                try {
                  const probeResult = await fetchSubscriptionShared(attempt.url, attempt.ua, doh, true)
                  const before = usage
                  usage = mergeUsage(usage, probeResult.usage)
                  if (usage !== before && !missingQuota()) {
                    // 命中后移到队尾（Map.set 不会改变已有键的顺序），保持活跃条目不被淘汰。
                    quotaProbeHits.delete(quotaKey)
                    if (quotaProbeHits.size >= QUOTA_PROBE_CACHE_LIMIT) {
                      const oldest = quotaProbeHits.keys().next().value
                      if (oldest !== undefined) quotaProbeHits.delete(oldest)
                    }
                    quotaProbeHits.set(quotaKey, attempt)
                  }
                } catch {
                  // Quota is optional; keep the successfully parsed node list.
                }
                if (!missingQuota()) break
              }
              if (missingQuota()) rememberQuotaProbeMiss(quotaProbeMisses, quotaKey)
            }
          }
          if (!isCurrent() || !get().sources.some((s) => s.id === id)) return
          const oldNodes = get().nodes.filter((n) => n.sourceID === id)
          const removedNodeIds = oldNodes.map((node) => node.id)
          const carried = carriedOverExclusions(oldNodes, parsed.nodes, source.excludedNodeKeys)

          set((s) => {
            // 刷新会重新生成节点 id；旧 id 的测速结果如果不清理，会一直留在
            // 内存里（每天自动刷新时尤其明显），也不会再被任何 UI 引用。
            const latencyByNodeId = { ...s.latencyByNodeId }
            const latencyMethodByNodeId = { ...s.latencyMethodByNodeId }
            const probeErrorByNodeId = { ...s.probeErrorByNodeId }
            for (const nodeID of removedNodeIds) {
              delete latencyByNodeId[nodeID]
              delete latencyMethodByNodeId[nodeID]
              delete probeErrorByNodeId[nodeID]
            }
            return {
              nodes: [...s.nodes.filter((n) => n.sourceID !== id), ...parsed.nodes],
              sources: s.sources.map((src) => {
                if (src.id !== id) return src
                // 解析失败时 usage 为 undefined，保留旧值；部分字段缺失时也逐项回退。
                const nextUsage = mergeUsage(src.usage, usage)
                const fields = usageFieldsFrom(nextUsage)
                return {
                  ...src,
                  updatedAt: Date.now(),
                  usage: nextUsage,
                  expireAt: fields.expireAt ?? src.expireAt,
                  totalBytes: fields.totalBytes ?? src.totalBytes,
                  // unlimited 跟随本次合并结果：拿到上限后必须清掉旧的不限量标记，
                  // 否则机场改套餐后界面会一直显示“不限量”。
                  unlimited: fields.unlimited,
                  usedBytes: fields.usedBytes ?? src.usedBytes,
                  notices: parsed.notices,
                  excludedNodeKeys: carried,
                }
              }),
              loadingSourceIDs: s.loadingSourceIDs.filter((x) => x !== id),
              testingNodeIds: s.testingNodeIds.filter((x) => !removedNodeIds.includes(x)),
              latencyByNodeId,
              latencyMethodByNodeId,
              probeErrorByNodeId,
              // 刷新成功后清掉上一次的错误提示
              errors: (() => {
                const next = { ...s.errors }
                delete next[id]
                return next
              })(),
            }
          })
        } catch (error) {
          // 已删除或已被更新请求取代的订阅不再挂错误提示。
          if (!isCurrent() || !get().sources.some((s) => s.id === id)) return
          set((s) => ({
            loadingSourceIDs: s.loadingSourceIDs.filter((x) => x !== id),
            errors: { ...s.errors, [id]: String((error as Error).message) },
          }))
        }
      },

      removeSource: (id) =>
        set((s) => {
          const removedNodeIds = s.nodes.filter((n) => n.sourceID === id).map((n) => n.id)
          const errors = { ...s.errors }
          delete errors[id]
          const latencyByNodeId = { ...s.latencyByNodeId }
          const latencyMethodByNodeId = { ...s.latencyMethodByNodeId }
          const probeErrorByNodeId = { ...s.probeErrorByNodeId }
          for (const nodeID of removedNodeIds) {
            delete latencyByNodeId[nodeID]
            delete latencyMethodByNodeId[nodeID]
            delete probeErrorByNodeId[nodeID]
          }
          return {
            sources: s.sources.filter((x) => x.id !== id),
            nodes: s.nodes.filter((n) => n.sourceID !== id),
            loadingSourceIDs: s.loadingSourceIDs.filter((x) => x !== id),
            testingNodeIds: s.testingNodeIds.filter((x) => !removedNodeIds.includes(x)),
            errors,
            latencyByNodeId,
            latencyMethodByNodeId,
            probeErrorByNodeId,
          }
        }),

      toggleNodeExcluded: (node) => {
        if (!node.sourceID) return
        const key = exactKey(node)
        set((s) => ({
          sources: s.sources.map((src) => {
            if (src.id !== node.sourceID) return src
            const excluded = new Set(src.excludedNodeKeys)
            if (excluded.has(key)) excluded.delete(key)
            else excluded.add(key)
            return { ...src, excludedNodeKeys: [...excluded] }
          }),
        }))
      },

      setSourceExclusions: (id, excludedKeys) =>
        set((s) => ({
          sources: s.sources.map((src) =>
            src.id === id ? { ...src, excludedNodeKeys: excludedKeys } : src,
          ),
        })),

      setScheme: (id) => set({ selectedSchemeID: id, policySelections: {} }),
      setPolicy: (group, selection) =>
        set((s) => ({ policySelections: { ...s.policySelections, [group]: selection } })),
      removePolicy: (group) =>
        set((s) => {
          if (!(group in s.policySelections)) return s
          const policySelections = { ...s.policySelections }
          delete policySelections[group]
          return { policySelections }
        }),

      renamePolicySelection: (oldName, newName) =>
        set((s) => {
          if (oldName === newName || !(oldName in s.policySelections)) return s
          const policySelections = { ...s.policySelections }
          policySelections[newName] = policySelections[oldName]
          delete policySelections[oldName]
          return { policySelections }
        }),

      startTesting: (nodeIds) => {
        const allNodes = get().nodes
        const nodes = allNodes.filter((n) => nodeIds.includes(n.id) && !n.isSubscriptionMetadata)
        const generation = get().testingGeneration + 1
        set({ testingGeneration: generation, testingNodeIds: nodeIds })

        // 5 并发与 iOS 版一致；超时交给服务端（首次 5s，可重试错误自动放宽再探一次）。
        const CONCURRENCY = 5
        const PROBE_TIMEOUT = 5000
        const testMode = get().latencyTestMode

        const probeOne = async (node: ProxyNode): Promise<{
          id: string
          latency: number | null
          method?: LatencyTestMethod
          error?: string
        }> => {
          // 自动模式按节点传输层选择：TCP 承载走握手，UDP/QUIC 只能 ICMP 近似。
          const capability = nodeTransportCapability(node)
          const udpOnly = capability.probeMethod === 'icmp'
          if (udpOnly && testMode === 'tcp') {
            return { id: node.id, latency: null, error: 'tcp_not_applicable' }
          }
          const requestMode = testMode === 'automatic' ? capability.probeMethod : testMode
          // 浏览器侧网络抖动也可能导致 fetch 失败，这里再补一次。
          for (let attempt = 0; attempt < 2; attempt++) {
            const res = await apiFetch(
              `/api/probe?host=${encodeURIComponent(node.server)}&port=${node.port}&timeout=${PROBE_TIMEOUT}&mode=${requestMode}`,
            ).catch(() => null)
            if (!res) continue
            const data = await res.json().catch(() => null)
            if (!data) continue
            if (data.ok) {
              return {
                id: node.id,
                latency: data.ms as number,
                method: data.method === 'icmp' ? 'icmp' : 'tcp',
              }
            }
            if (attempt === 0 && data.error === 'timeout') continue
            return { id: node.id, latency: null, error: String(data.error ?? 'unknown') }
          }
          return { id: node.id, latency: null, error: 'network' }
        }

        const run = async () => {
          const queue = [...nodes]
          const worker = async () => {
            while (queue.length) {
              if (get().testingGeneration !== generation) return
              const node = queue.shift()
              if (!node) return
              // 测速途中被删除的自有节点，不要再写回延迟或错误。
              if (!get().nodes.some((item) => item.id === node.id)) continue
              const result = await probeOne(node)
              if (get().testingGeneration !== generation) return
              set((s) => {
                if (s.testingGeneration !== generation) return s
                if (!s.nodes.some((item) => item.id === result.id)) return s
                const latencyByNodeId = { ...s.latencyByNodeId, [result.id]: result.latency }
                const latencyMethodByNodeId = { ...s.latencyMethodByNodeId }
                if (result.method) latencyMethodByNodeId[result.id] = result.method
                else delete latencyMethodByNodeId[result.id]
                const probeErrorByNodeId = { ...s.probeErrorByNodeId }
                if (result.error) probeErrorByNodeId[result.id] = result.error
                else delete probeErrorByNodeId[result.id]
                // 只移除已完成的那一个。不能按 queue.length 清空：队列排空时
                // 仍可能有几个探测在途，否则 UI 会提前显示「测速结束」。
                const testingNodeIds = s.testingNodeIds.filter((id) => id !== result.id)
                return { latencyByNodeId, latencyMethodByNodeId, probeErrorByNodeId, testingNodeIds }
              })
            }
          }
          await Promise.all(Array.from({ length: Math.min(CONCURRENCY, nodes.length || 1) }, worker))
          if (get().testingGeneration === generation) set({ testingNodeIds: [] })
        }
        void run()
      },

      stopTesting: () => {
        // Bump the generation so all in-flight callbacks discard their
        // writes, and clear the "currently testing" UI.
        set((s) => ({ testingGeneration: s.testingGeneration + 1, testingNodeIds: [] }))
      },

      addCustomScheme: (scheme) =>
        set((s) => ({
          customSchemes: [...s.customSchemes.filter((x) => x.id !== scheme.id), scheme],
        })),

      removeCustomScheme: (id) =>
        set((s) => ({
          customSchemes: s.customSchemes.filter((x) => x.id !== id),
          selectedSchemeID:
            s.selectedSchemeID === id ? BUILTIN_SCHEMES[0].id : s.selectedSchemeID,
          policySelections:
            s.selectedSchemeID === id ? {} : s.policySelections,
        })),

      addLocalRuleSet: (ruleSet) =>
        set((s) => {
          const index = s.localRuleSets.findIndex((x) => x.id === ruleSet.id)
          // 刷新已有规则集时原位替换，避免列表顺序跳到最后。
          if (index < 0) return { localRuleSets: [...s.localRuleSets, ruleSet] }
          const localRuleSets = s.localRuleSets.slice()
          localRuleSets[index] = ruleSet
          return { localRuleSets }
        }),

      removeLocalRuleSet: (id) =>
        set((s) => {
          const ruleSetExclusions = { ...s.ruleSetExclusions }
          delete ruleSetExclusions[id]
          return {
            localRuleSets: s.localRuleSets.filter((x) => x.id !== id),
            ruleSetExclusions,
          }
        }),

      addRuleSetExclusion: (ruleSetID, signature) =>
        set((s) => ({
          ruleSetExclusions: addExclusion(s.ruleSetExclusions, ruleSetID, signature),
        })),

      removeRuleSetExclusion: (ruleSetID, signature) =>
        set((s) => ({
          ruleSetExclusions: removeExclusion(s.ruleSetExclusions, ruleSetID, signature),
        })),

      restoreRuleSetExclusions: (ruleSetID, signatures) =>
        set((s) => {
          const exclusions: RuleSetExclusionTable = { ...s.ruleSetExclusions }
          const next = [...new Set(signatures.filter(Boolean))].sort()
          if (next.length) exclusions[ruleSetID] = next
          else delete exclusions[ruleSetID]
          return { ruleSetExclusions: exclusions }
        }),

      saveBuiltinSchemeOverride: (id, content) => {
        if (isWorkspaceReadOnly()) return 0
        const result = writeBuiltinSchemeSnapshot(
          get().schemeSnapshots,
          get().builtinSchemeOverrides,
          get().snapshotSeq,
          id,
          content,
          Date.now(),
          // 自定义方案引用到的规则集 id：这些快照不淘汰，避免方案指向旧版。
          get().customSchemes.flatMap((scheme) => (scheme.ruleSets ?? []).map((ruleSet) => ruleSet.id)),
        )
        // 写进去也必须能通过同一套校验；否则下次加载会被静默判坏，
        // 用户看到的只是「已固化」，重启后却回落到原厂。
        if (!isBuiltinSchemeSnapshotValid(result.snapshot)) return 0
        set((s) => {
          const notices = { ...s.builtinSchemeUpdateNotices }
          delete notices[id]
          return {
            schemeSnapshots: result.snapshots,
            builtinSchemeOverrides: result.overrides,
            snapshotSeq: result.snapshotSeq,
            builtinSchemeUpdateNotices: notices,
          }
        })
        return result.snapshot.id
      },

      restoreBuiltinSchemeSnapshot: (id, snapshotId) => {
        if (isWorkspaceReadOnly()) return false
        const s = get()
        const snapshot = s.schemeSnapshots[String(snapshotId)]
        // 和 loadScheme 用同一套校验：结构损坏的快照不能当成回退成功，
        // 否则界面提示已切换，实际仍停留在上一版 / 原厂。
        if (!snapshot || snapshot.schemeID !== id || !isBuiltinSchemeSnapshotValid(snapshot)) return false
        set((state) => {
          const notices = { ...state.builtinSchemeUpdateNotices }
          delete notices[id]
          return {
            builtinSchemeOverrides: { ...state.builtinSchemeOverrides, [id]: { snapshotId } },
            builtinSchemeUpdateNotices: notices,
          }
        })
        return true
      },

      clearBuiltinSchemeOverride: (id) => {
        // 与固化 / 回退保持一致：只读时不能清指针，否则 UI 会报成功但没变化。
        if (isWorkspaceReadOnly()) return
        set((s) => {
          const overrides = { ...s.builtinSchemeOverrides }
          delete overrides[id]
          const notices = { ...s.builtinSchemeUpdateNotices }
          delete notices[id]
          return { builtinSchemeOverrides: overrides, builtinSchemeUpdateNotices: notices }
        })
      },

      clearCorruptPersistence: () => {
        if (isWorkspaceReadOnly()) return { pointers: 0, snapshots: 0 }
        const state = get()
        const cleaned = clearCorruptPersistence(state.builtinSchemeOverrides, state.schemeSnapshots)
        set({
          builtinSchemeOverrides: cleaned.overrides,
          schemeSnapshots: cleaned.snapshots,
          // 清理后重新生成体检提示：仍悬空的指针会继续显示，直到被处理。
          persistenceWarnings: inspectPersistenceWarnings(cleaned.overrides, cleaned.snapshots),
        })
        return { pointers: cleaned.pointersCleared, snapshots: cleaned.snapshotsCleared }
      },

      setPersistenceWarnings: (warnings) => set({ persistenceWarnings: warnings }),

      setCheckBuiltinSchemeUpdatesOnOpen: (enabled) =>
        set({ checkBuiltinSchemeUpdatesOnOpen: enabled }),

      setBuiltinSchemeUpdateNotice: (id, notice) =>
        set((s) => {
          const notices = { ...s.builtinSchemeUpdateNotices }
          if (notice) notices[id] = notice
          else delete notices[id]
          return { builtinSchemeUpdateNotices: notices }
        }),

      addManualNodes: (text, preferredName) => {
        const result = prepareManualNodes(text, preferredName ?? '', get().nodes)
        if (result.nodes.length > 0) {
          set((s) => ({ nodes: [...s.nodes, ...result.nodes] }))
        }
        return result
      },

      updateManualNode: (id, patch) =>
        set((s) => ({
          nodes: s.nodes.map((node) => {
            if (node.id !== id || !node.isManual) return node
            const next = { ...node }
            if (patch.name !== undefined) {
              const name = patch.name.replace(/[\r\n]+/g, ' ').trim().slice(0, 120)
              if (name) next.name = name
            }
            if (patch.isEnabled !== undefined) next.isEnabled = patch.isEnabled
            return next
          }),
        })),

      saveManualNode: (node) =>
        set((s) => {
          const existing = s.nodes.find((item) => item.id === node.id && item.isManual)
          const saved: ProxyNode = {
            ...node,
            sourceID: undefined,
            isManual: true,
            isEnabled: existing ? existing.isEnabled !== false : node.isEnabled !== false,
            countryOverride: existing?.countryOverride ?? node.countryOverride,
            detectedCountry: existing?.detectedCountry ?? node.detectedCountry,
          }
          return {
            nodes: existing
              ? s.nodes.map((item) => item.id === saved.id ? saved : item)
              : [...s.nodes, saved],
          }
        }),

      removeManualNode: (id) =>
        set((s) => {
          const node = s.nodes.find((item) => item.id === id && item.isManual)
          if (!node) return s
          const latencyByNodeId = { ...s.latencyByNodeId }
          const latencyMethodByNodeId = { ...s.latencyMethodByNodeId }
          const probeErrorByNodeId = { ...s.probeErrorByNodeId }
          delete latencyByNodeId[id]
          delete latencyMethodByNodeId[id]
          delete probeErrorByNodeId[id]
          return {
            nodes: s.nodes.filter((item) => item.id !== id),
            testingNodeIds: s.testingNodeIds.filter((item) => item !== id),
            latencyByNodeId,
            latencyMethodByNodeId,
            probeErrorByNodeId,
          }
        }),

      restoreBackup: (data) => {
        // 备份覆盖包含导出设置等设备偏好；只读时整笔拒绝，避免只恢复一半。
        if (isWorkspaceReadOnly()) return
        // 备份里的方案 id 可能已被删掉（例如从别的设备导出的旧备份），
        // 直接落库会留下一份「内容有、标题空」的半空选择状态。
        const selectedSchemeID = BUILTIN_SCHEMES.some((meta) => meta.id === data.selectedSchemeID)
          || data.customSchemes.some((scheme) => scheme?.id === data.selectedSchemeID)
          ? data.selectedSchemeID
          : BUILTIN_SCHEMES[0].id
        set((s) => ({
          ...data,
          selectedSchemeID,
          // 备份不含测速结果与瞬时错误；恢复后从头开始，避免旧 ID 的结果串到新节点。
          loadingSourceIDs: [],
          errors: {},
          latencyByNodeId: {},
          latencyMethodByNodeId: {},
          probeErrorByNodeId: {},
          testingNodeIds: [],
          testingGeneration: s.testingGeneration + 1,
        }))
        // 备份不含 Tailscale Auth Key；只保留仍然存在的内网连接对应的本机 Key。
        get().pruneTailnetKeys()
      },
      }
    },
    {
      name: 'tower-web-state',
      // 配额满时只标记状态、不抛出：否则每个 set() 都会让界面操作失败。
      storage: createJSONStorage(() => createSafeStorage(browserStorage)),
      partialize: persistedSnapshot,
      // 旧版本快照可能缺少 excludedNodeKeys / isEnabled，必须在这里补齐，
      // 否则渲染和刷新会读到 undefined 直接抛错。
      merge: (persisted, current) => {
        const data = persisted as Partial<PersistedData> | undefined
        // 旧版本 localStorage 里可能是内联单版覆盖层：这里归一化成快照 + 指针。
        // 自定义方案引用到的规则集快照不能在这一步被淘汰。
        const customSchemes = Array.isArray(data?.customSchemes) ? data.customSchemes : current.customSchemes
        const builtin = normalizeBuiltinSchemes(
          (data as { builtinSchemeOverrides?: unknown } | undefined)?.builtinSchemeOverrides,
          data?.schemeSnapshots,
          data?.snapshotSeq,
          customSchemes.flatMap((scheme) => Array.isArray(scheme?.ruleSets) ? scheme.ruleSets.map((ruleSet) => ruleSet.id) : []),
        )
        // 旧的 / 被删方案的 id 会让选择器与方案卡找不到对象，出现「内容有、
        // 标题和快照面板空」的半空状态；与服务端归一化保持同一口径。
        const selectedSchemeID = typeof data?.selectedSchemeID === 'string'
          && (BUILTIN_SCHEMES.some((meta) => meta.id === data.selectedSchemeID)
            || customSchemes.some((scheme) => scheme?.id === data.selectedSchemeID))
          ? data.selectedSchemeID
          : current.selectedSchemeID
        return {
          ...current,
          ...(data ?? {}),
          ...builtin,
          // 归一化丢掉的坏快照 / 悬空指针必须可见，不能静默回落。
          persistenceWarnings: builtin.rejections,
          selectedSchemeID,
          sources: Array.isArray(data?.sources)
            ? data.sources.map(normalizeSource)
            : current.sources,
          ruleSetExclusions: normalizeRuleSetExclusions(
            data?.ruleSetExclusions ?? current.ruleSetExclusions,
          ),
        }
      },
    },
  ),
)

/** 旧快照没有 isEnabled 字段的订阅按启用处理。 */
export function isSourceEnabled(source: SubscriptionSource): boolean {
  return source.isEnabled !== false
}

/** Enabled nodes for a source = parsed nodes minus exclusions and metadata. */
export function enabledNodes(state: Pick<Store, 'sources' | 'nodes'>, sourceID?: string): ProxyNode[] {
  const source = sourceID ? state.sources.find((s) => s.id === sourceID) : undefined
  if (source && !isSourceEnabled(source)) return []
  const enabledSourceIDs = new Set(state.sources.filter(isSourceEnabled).map((s) => s.id))
  const excluded = new Set(
    state.sources.flatMap((s) => (sourceID && s.id !== sourceID ? [] : s.excludedNodeKeys)),
  )
  return state.nodes.filter(
    (n) =>
      (!sourceID || n.sourceID === sourceID) &&
      (n.sourceID === undefined
        ? n.isManual
          ? n.isEnabled !== false
          : true
        : enabledSourceIDs.has(n.sourceID)) &&
      !n.isSubscriptionMetadata &&
      // 自有节点只受自己的启用开关控制，不继承订阅里同名节点的排除状态。
      (n.isManual || !excluded.has(exactKey(n))),
  )
}

export { exactKey as nodeExactKey }
