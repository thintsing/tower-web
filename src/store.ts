// App state: subscriptions, nodes, scheme selection, policy overrides.
// Persisted to localStorage; nothing leaves the machine except the
// subscription fetches the user explicitly triggers (via /api/fetch).
import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { AppState, ClientTarget, ExportContentMode, LatencyTestMethod, LatencyTestMode, LocalRuleSet, NodeNameFilterSettings, ProxyKind, ProxyNode, RuleScheme, SubscriptionRequestOptions, SubscriptionSource, TailnetConnection } from './models/types'
import { loadTailnetAuthKeys, persistTailnetAuthKeys, pruneTailnetAuthKeys } from './models/tailnetAuthKeys'
import type { PersistedData } from './backup'
import { prepareManualNodes, type ManualNodeImportResult } from './manualNodes'
import { parse, parseUserinfoHeader } from './parser'
import { newID } from './util/browser'

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
  /** Tailscale 内网连接；Auth Key 单独存在 tailnetAuthKeys。 */
  tailnets: TailnetConnection[]
  /** 本机保存的 Auth Key；不进入持久化快照，刷新前从独立 localStorage 读取。 */
  tailnetAuthKeys: Record<string, string>
  addSourceFromURL: (url: string, options?: SubscriptionRequestOptions) => Promise<void>
  updateSource: (id: string, patch: SourcePatch) => void
  setSourceEnabled: (id: string, enabled: boolean) => void
  setSourcesEnabled: (ids: string[], enabled: boolean) => void
  setAutoRefreshOnOpen: (enabled: boolean) => void
  setAutoRefreshRuleSetsOnOpen: (enabled: boolean) => void
  setPreferRuleSets: (enabled: boolean) => void
  setExportContentMode: (mode: ExportContentMode) => void
  setExportProtocols: (kinds: ProxyKind[]) => void
  setExportConfigName: (name: string) => void
  setAppendSourceName: (enabled: boolean) => void
  setClientOrder: (order: ClientTarget[]) => void
  setClientHidden: (target: ClientTarget, hidden: boolean) => void
  setExportContentModeFor: (target: ClientTarget, mode: ExportContentMode) => void
  setEmbedRemoteSubscriptions: (enabled: boolean) => void
  setNodeNameFilter: (patch: Partial<NodeNameFilterSettings>) => void
  setFilterSubscriptionInfoNodes: (enabled: boolean) => void
  setRenewalRemindersEnabled: (enabled: boolean) => void
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
  renamePolicySelection: (oldName: string, newName: string) => void
  startTesting: (nodeIds: string[]) => void
  stopTesting: () => void
  addCustomScheme: (scheme: RuleScheme) => void
  removeCustomScheme: (id: string) => void
  addLocalRuleSet: (set: LocalRuleSet) => void
  removeLocalRuleSet: (id: string) => void
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
  excludedKeys: string[],
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
    autoRefreshOnOpen: s.autoRefreshOnOpen,
    autoRefreshRuleSetsOnOpen: s.autoRefreshRuleSetsOnOpen,
    preferRuleSets: s.preferRuleSets,
    exportContentMode: s.exportContentMode,
    exportContentModes: s.exportContentModes,
    embedRemoteSubscriptions: s.embedRemoteSubscriptions,
    exportProtocols: s.exportProtocols,
    exportConfigName: s.exportConfigName,
    appendSourceName: s.appendSourceName,
    clientOrder: s.clientOrder,
    hiddenClients: s.hiddenClients,
    nodeNameFilter: s.nodeNameFilter,
    filterSubscriptionInfoNodes: s.filterSubscriptionInfoNodes,
    renewalRemindersEnabled: s.renewalRemindersEnabled,
    latencyTestMode: s.latencyTestMode,
    tailnets: s.tailnets,
  }
}

export const useStore = create<Store>()(
  persist(
    (set, get) => ({
      sources: [],
      nodes: [],
      selectedSchemeID: 'acl4ssr-online',
      policySelections: {},
      customSchemes: [],
      localRuleSets: [],
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
      exportConfigName: 'tower',
      appendSourceName: false,
      clientOrder: [],
      hiddenClients: [],
      nodeNameFilter: { include: '', exclude: '', useRegex: false, caseSensitive: false },
      filterSubscriptionInfoNodes: false,
      renewalRemindersEnabled: false,
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
        const authKeys = { ...get().tailnetAuthKeys }
        const normalized = key?.trim()
        if (normalized) authKeys[id] = normalized
        else delete authKeys[id]
        persistTailnetAuthKeys(authKeys)
        set({ tailnetAuthKeys: authKeys })
      },
      pruneTailnetKeys: () => {
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
        set((s) => ({
          loadingSourceIDs: [...s.loadingSourceIDs.filter((x) => x !== id), id],
          errors: { ...s.errors, [id]: '' },
        }))
        try {
          const params = new URLSearchParams({ url: source.url })
          const userAgent = normalizeUserAgent(source.userAgent)
          if (userAgent) params.set('ua', userAgent)
          if (source.dnsOverHTTPSURL?.trim()) params.set('doh', source.dnsOverHTTPSURL.trim())
          const res = await fetch(`/api/fetch?${params.toString()}`)
          if (!res.ok) {
            const body = await res.json().catch(() => ({}))
            throw new Error(body.error ?? `HTTP ${res.status}`)
          }
          const text = await res.text()
          // 用户可能在请求途中删掉了这个订阅；不要把它以「无主节点」的形式写回来。
          if (!get().sources.some((s) => s.id === id)) return
          const headerUsage = parseUserinfoHeader(res.headers.get('x-subscription-userinfo'))
          const parsed = parse(text, id)
          if (!parsed.nodes.some((n) => !n.isSubscriptionMetadata)) {
            throw new Error(
              parsed.rejectedLineCount
                ? `没有解析到可用节点（${parsed.rejectedLineCount} 行无法识别），请检查订阅内容或地址`
                : '没有解析到可用节点，请检查订阅内容或地址',
            )
          }
          const oldNodes = get().nodes.filter((n) => n.sourceID === id)
          const carried = carriedOverExclusions(oldNodes, parsed.nodes, source.excludedNodeKeys)

          set((s) => ({
            nodes: [...s.nodes.filter((n) => n.sourceID !== id), ...parsed.nodes],
            sources: s.sources.map((src) =>
              src.id === id
                ? {
                    ...src,
                    updatedAt: Date.now(),
                    usage: headerUsage ?? parsed.status ?? src.usage,
                    excludedNodeKeys: carried,
                  }
                : src,
            ),
            loadingSourceIDs: s.loadingSourceIDs.filter((x) => x !== id),
            // 刷新成功后清掉上一次的错误提示
            errors: (() => {
              const next = { ...s.errors }
              delete next[id]
              return next
            })(),
          }))
        } catch (error) {
          // 已删除的订阅不再挂错误提示。
          if (!get().sources.some((s) => s.id === id)) return
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
        // 纯 UDP 协议没有 TCP 端口可握手；ICMP / 自动模式仍可测服务器可达性。
        const UDP_KINDS = new Set<ProxyNode['kind']>(['hysteria', 'hysteria2', 'tuic', 'wireguard'])

        const probeOne = async (node: ProxyNode): Promise<{
          id: string
          latency: number | null
          method?: LatencyTestMethod
          error?: string
        }> => {
          const udpOnly = UDP_KINDS.has(node.kind)
          if (udpOnly && testMode === 'tcp') {
            return { id: node.id, latency: null, error: 'tcp_not_applicable' }
          }
          const requestMode = udpOnly && testMode === 'automatic' ? 'icmp' : testMode
          // 浏览器侧网络抖动也可能导致 fetch 失败，这里再补一次。
          for (let attempt = 0; attempt < 2; attempt++) {
            const res = await fetch(
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
            s.selectedSchemeID === id ? 'acl4ssr-online' : s.selectedSchemeID,
          policySelections:
            s.selectedSchemeID === id ? {} : s.policySelections,
        })),

      addLocalRuleSet: (ruleSet) =>
        set((s) => ({
          localRuleSets: [...s.localRuleSets.filter((x) => x.id !== ruleSet.id), ruleSet],
        })),

      removeLocalRuleSet: (id) =>
        set((s) => ({
          localRuleSets: s.localRuleSets.filter((x) => x.id !== id),
        })),

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
        set((s) => ({
          ...data,
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
    }),
    {
      name: 'tower-web-state',
      partialize: persistedSnapshot,
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
