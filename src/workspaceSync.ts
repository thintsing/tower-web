// 服务器版工作区同步：拉取 / 推送 / 版本探测 / 冲突与离线处理。
// 只同步「多设备应该一致」的数据；导出目标、隐藏客户端、排序、Emoji、
// 测速模式、地图与高级区展开等设备偏好仍留在 localStorage。
import { useSyncExternalStore } from 'react'
import type { BuiltinSchemeOverrideRef, BuiltinSchemeSnapshot, LocalRuleSet, ProxyNode, RuleScheme, RuleSetExclusionTable, SubscriptionSource, TailnetConnection } from './models/types'
import { normalizeBuiltinSchemes, normalizeSource } from './backup'
import { BUILTIN_SCHEMES } from './rules/scheme'
import { normalizeRuleSetExclusions } from './rules/ruleSetExclusions'
import { persistTailnetAuthKeys } from './models/tailnetAuthKeys'
import { useStore, type Store } from './store'
import { apiFetch, getAPIKey } from './util/apiAuth'
import { isWorkspaceReadOnly, setWorkspaceReadOnly } from './util/workspaceLock'

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

export type WorkspaceState =
  | 'checking'
  | 'local'
  | 'connecting'
  | 'online'
  | 'offline'
  | 'unauthorized'
  | 'corrupt'
  /** 服务端明确拒绝（403 局域网共享关闭 / 429 认证冷却），与网络离线分开。 */
  | 'blocked'

export interface WorkspaceStatus {
  mode: 'unknown' | 'local' | 'server'
  state: WorkspaceState
  readOnly: boolean
  version: number
  message: string
}

let status: WorkspaceStatus = {
  mode: 'unknown',
  state: 'checking',
  readOnly: false,
  version: 0,
  message: '',
}
const listeners = new Set<() => void>()

export function getWorkspaceStatus(): WorkspaceStatus {
  return status
}

export function subscribeWorkspaceStatus(listener: () => void): () => void {
  listeners.add(listener)
  return () => { listeners.delete(listener) }
}

/** React 侧读取同步状态；只读时会重新渲染按钮禁用态。 */
export function useWorkspaceStatus(): WorkspaceStatus {
  return useSyncExternalStore(subscribeWorkspaceStatus, getWorkspaceStatus, getWorkspaceStatus)
}

function updateStatus(patch: Partial<WorkspaceStatus>): void {
  status = { ...status, ...patch }
  for (const listener of listeners) listener()
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function stringRecord(value: unknown, field: string): Record<string, string> {
  if (value === undefined) return {}
  if (!isRecord(value)) throw new WorkspaceDataError(`工作区字段 ${field} 不是对象`)
  const out: Record<string, string> = {}
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === 'string') out[key] = item
  }
  return out
}

function arrayField<T>(raw: Record<string, unknown>, field: string): T[] {
  const value = raw[field]
  if (value === undefined) return []
  if (!Array.isArray(value)) throw new WorkspaceDataError(`工作区字段 ${field} 不是数组`)
  return value as T[]
}

/** 校验并规范化服务端数据；缺字段按空处理，类型错误直接拒绝。 */
export function normalizeWorkspaceData(raw: unknown): WorkspaceData {
  if (!isRecord(raw)) throw new WorkspaceDataError('工作区数据不是对象')
  const sources = arrayField<SubscriptionSource>(raw, 'sources').map(normalizeSource)
  const customSchemes = arrayField<RuleScheme>(raw, 'customSchemes')
  const builtinSchemes = normalizeBuiltinSchemes(
    raw.builtinSchemeOverrides,
    raw.schemeSnapshots,
    raw.snapshotSeq,
    // 旧数据 / 手工改坏的数据里 ruleSets 可能不是数组；这里只读 id，
    // 不能因为一个方案的脏字段让整个工作区加载失败。
    customSchemes.flatMap((scheme) => Array.isArray(scheme?.ruleSets) ? scheme.ruleSets.map((ruleSet) => ruleSet.id) : []),
  )
  return {
    sources,
    nodes: arrayField<ProxyNode>(raw, 'nodes'),
    customSchemes,
    localRuleSets: arrayField<LocalRuleSet>(raw, 'localRuleSets'),
    ...builtinSchemes,
    ruleSetExclusions: normalizeRuleSetExclusions(raw.ruleSetExclusions),
    // useScheme 对未知 id 会静默显示第一个内置方案，但选择器 / 方案卡仍按未知
    // id 找不到对象，出现「内容有、标题和快照面板空」的半空状态。
    selectedSchemeID: typeof raw.selectedSchemeID === 'string'
      && (BUILTIN_SCHEMES.some((meta) => meta.id === raw.selectedSchemeID)
        || customSchemes.some((scheme) => scheme.id === raw.selectedSchemeID))
      ? raw.selectedSchemeID
      : BUILTIN_SCHEMES[0].id,
    policySelections: stringRecord(raw.policySelections, 'policySelections'),
    exportConfigName: typeof raw.exportConfigName === 'string'
      ? raw.exportConfigName.replace(/[\r\n]/g, '').slice(0, 48) || 'tower'
      : 'tower',
    tailnets: arrayField<TailnetConnection>(raw, 'tailnets'),
    tailnetAuthKeys: stringRecord(raw.tailnetAuthKeys, 'tailnetAuthKeys'),
  }
}

/** 当前内存状态里属于工作区的字段。 */
export function workspaceSnapshot(state: Store): WorkspaceData {
  return normalizeWorkspaceData({
    sources: state.sources,
    nodes: state.nodes,
    customSchemes: state.customSchemes,
    localRuleSets: state.localRuleSets,
    builtinSchemeOverrides: state.builtinSchemeOverrides,
    schemeSnapshots: state.schemeSnapshots,
    snapshotSeq: state.snapshotSeq,
    ruleSetExclusions: state.ruleSetExclusions,
    selectedSchemeID: state.selectedSchemeID,
    policySelections: state.policySelections,
    exportConfigName: state.exportConfigName,
    tailnets: state.tailnets,
    tailnetAuthKeys: state.tailnetAuthKeys,
  })
}

function hasContent(data: WorkspaceData): boolean {
  return data.sources.length > 0
    || data.nodes.length > 0
    || data.customSchemes.length > 0
    || data.localRuleSets.length > 0
    || Object.keys(data.builtinSchemeOverrides).length > 0
    || Object.keys(data.schemeSnapshots).length > 0
    || Object.keys(data.ruleSetExclusions).length > 0
    || data.tailnets.length > 0
}

/** FNV-1a + 长度：用来跳过内容没变的推送，不需要加密强度。 */
function signature(data: WorkspaceData): string {
  const text = JSON.stringify(data)
  let hash = 0x811c9dc5
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index)
    hash = Math.imul(hash, 0x01000193)
  }
  return `${(hash >>> 0).toString(16)}:${text.length}`
}

function currentSignature(): string {
  return signature(workspaceSnapshot(useStore.getState()))
}

const WATCHED_KEYS = [
  'sources',
  'nodes',
  'customSchemes',
  'localRuleSets',
  'builtinSchemeOverrides',
  'schemeSnapshots',
  'snapshotSeq',
  'ruleSetExclusions',
  'selectedSchemeID',
  'policySelections',
  'exportConfigName',
  'tailnets',
  'tailnetAuthKeys',
] as const

let serverMode = false
let ready = false
let serverVersion = 0
let lastSignature = ''
let watchedState: Store | null = null
let unsubscribeStore: (() => void) | undefined
let initialized: Promise<void> | null = null
let writing = false
let pendingWrite = false
let failureCount = 0
// 版本探针连续失败两次才判定离线：一次网络抖动不打断正在编辑的页面，
// 又能在服务端停掉后约 16 秒内进入只读，而不是等到用户真的改东西才发现。
let pollFailures = 0
let debounceTimer: number | undefined
let retryTimer: number | undefined
let pollTimer: number | undefined
let windowListenersBound = false
const POLL_INTERVAL_MS = 8000
// 上次确认过的服务端模式。服务器版偶尔先于服务端启动时，不能再把缓存当成
// 可写工作区：否则离线期间的改动会在下次连接时被服务端数据静默覆盖。
const MODE_CACHE_KEY = 'tower-web-workspace-mode'

function cachedMode(): 'server' | 'local' | '' {
  try {
    const value = localStorage.getItem(MODE_CACHE_KEY)
    return value === 'server' || value === 'local' ? value : ''
  } catch {
    return ''
  }
}

function rememberMode(mode: 'server' | 'local'): void {
  try {
    localStorage.setItem(MODE_CACHE_KEY, mode)
  } catch {
    // 存储不可用时只影响重启后的离线判定，不影响本次会话。
  }
}

/** 启动同步；重复调用返回同一个 Promise。 */
export function initWorkspaceSync(): Promise<void> {
  if (!initialized) initialized = startSync()
  return initialized
}

async function startSync(): Promise<void> {
  if (typeof window === 'undefined') return
  await detectMode()
}

/** 先看服务端是 local 还是 server；local 模式完全不改变原有行为。 */
async function detectMode(): Promise<void> {
  let auth: { mode?: unknown }
  try {
    const res = await apiFetch('/api/auth-status', { cache: 'no-store' })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    auth = await res.json() as { mode?: unknown }
  } catch {
    if (cachedMode() === 'server') {
      // 上次确认是服务器版、这次连不上：按离线只读处理，避免用户以为改动
      // 已保存，等 reconnect 成功后再拉取服务端数据。
      serverMode = true
      bindStore()
      bindWindowListeners()
      setupPolling()
      goOffline('暂时无法连接服务端')
      return
    }
    // 从未确认过模式时仍保持原来的本地可用行为，但必须让用户知道
    // 「这是一份本机缓存、还没连上服务端」，否则空白页面看起来像数据丢了。
    updateStatus({
      mode: 'unknown',
      state: 'checking',
      readOnly: false,
      message: '无法连接塔台服务端，正在重试…（当前显示本机缓存，可能不是最新的）',
    })
    scheduleRetry()
    return
  }
  if (auth.mode !== 'server') {
    goLocal()
    return
  }
  rememberMode('server')
  serverMode = true
  updateStatus({ mode: 'server', state: 'connecting', readOnly: false, message: '' })
  bindStore()
  bindWindowListeners()
  setupPolling()
  await connect()
}

async function connect(): Promise<void> {
  if (!getAPIKey()) {
    goReadOnly('unauthorized', '服务器模式需要访问密钥（TOWER_API_TOKEN），请用带 ?key=… 的地址打开一次')
    return
  }
  await fetchFull()
}

function bindStore(): void {
  if (unsubscribeStore) return
  watchedState = useStore.getState()
  unsubscribeStore = useStore.subscribe((state) => {
    const changed = !watchedState
      || WATCHED_KEYS.some((key) => state[key] !== watchedState![key])
    watchedState = state
    if (!changed || !ready || isWorkspaceReadOnly()) return
    scheduleWrite(state)
  })
}

function bindWindowListeners(): void {
  if (windowListenersBound || typeof window === 'undefined') return
  windowListenersBound = true
  window.addEventListener('focus', refreshNow)
  document.addEventListener('visibilitychange', refreshNow)
}

function setupPolling(): void {
  if (pollTimer !== undefined || typeof window === 'undefined') return
  pollTimer = window.setInterval(() => {
    if (document.visibilityState !== 'visible') return
    if (!serverMode || isWorkspaceReadOnly()) return
    void pollVersion()
  }, POLL_INTERVAL_MS)
}

function refreshNow(): void {
  if (!serverMode) return
  if (document.visibilityState !== 'visible') return
  if (isWorkspaceReadOnly()) {
    // 离线 / 密钥错误时给一次立即重连的机会。
    if (status.state !== 'unauthorized') void fetchFull()
    return
  }
  void pollVersion()
}

function scheduleWrite(state: Store): void {
  const next = signature(workspaceSnapshot(state))
  if (next === lastSignature && status.state === 'online') return
  if (debounceTimer !== undefined) window.clearTimeout(debounceTimer)
  debounceTimer = window.setTimeout(() => {
    debounceTimer = undefined
    void flushWrite()
  }, 500)
}

function scheduleRetry(): void {
  if (retryTimer !== undefined) return
  // 密钥错误不会自动恢复，只等用户重新带 key 打开，避免自己把自己
  // 触发服务端的 10 次失败冷却。
  if (status.state === 'unauthorized') return
  const delay = status.mode === 'unknown'
    ? 8_000
    : status.state === 'blocked'
      ? 30_000
      : status.state === 'corrupt'
        ? 60_000
        : Math.min(30_000, 500 * 2 ** Math.min(failureCount, 6))
  retryTimer = window.setTimeout(() => {
    retryTimer = undefined
    void reconnect()
  }, delay)
}

async function reconnect(): Promise<void> {
  if (!serverMode) {
    await detectMode()
    return
  }
  // 网络恢复后先把尚未保存的改动推一次；版本冲突会在 flushWrite 内拉最新。
  if (ready && currentSignature() !== lastSignature) {
    await flushWrite()
    if (status.state === 'online') return
  }
  await fetchFull()
}

async function pollVersion(): Promise<void> {
  if (writing || debounceTimer !== undefined) return
  let version: number
  try {
    const res = await apiFetch('/api/workspace/version', { cache: 'no-store' })
    if (res.status === 401) {
      goReadOnly('unauthorized', '访问密钥无效，无法读取服务端工作区')
      return
    }
    if (res.status === 403 || res.status === 429) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      goReadOnly('blocked', body.error ?? `服务端拒绝请求（HTTP ${res.status}）`)
      return
    }
    if (res.status === 404 && await workspaceDisabled(res)) {
      goLocal()
      return
    }
    if (!res.ok) {
      notePollFailure()
      return
    }
    const body = await res.json() as { version?: unknown }
    if (typeof body.version !== 'number' || !Number.isInteger(body.version)) {
      notePollFailure()
      return
    }
    version = body.version
  } catch {
    notePollFailure()
    return
  }
  pollFailures = 0
  // 版本请求返回前用户可能刚改了东西（已排入 500ms 防抖）：此时直接拉全量
  // 会把这段尚未推送的改动覆盖掉。重新检查后再决定。
  if (debounceTimer !== undefined || writing) return
  if (version !== serverVersion) {
    await fetchFull({ notice: '已同步其他设备的改动。' })
  }
}

function notePollFailure(): void {
  if (isWorkspaceReadOnly()) return
  pollFailures += 1
  if (pollFailures >= 2) goOffline('无法连接服务端')
}

async function fetchFull(options: { notice?: string } = {}): Promise<boolean> {
  let res: Response
  try {
    res = await apiFetch('/api/workspace', { cache: 'no-store' })
  } catch {
    goOffline()
    return false
  }
  if (res.status === 401) {
    const body = await res.json().catch(() => ({})) as { error?: string }
    goReadOnly('unauthorized', body.error ?? '访问密钥无效')
    return false
  }
  if (res.status === 403 || res.status === 429) {
    const body = await res.json().catch(() => ({})) as { error?: string }
    goReadOnly('blocked', body.error ?? `服务端拒绝请求（HTTP ${res.status}）`)
    return false
  }
  if (res.status === 500) {
    const body = await res.json().catch(() => ({})) as { error?: string }
    goReadOnly('corrupt', body.error ?? '服务端工作区文件不可用')
    return false
  }
  if (res.status === 404 && await workspaceDisabled(res)) {
    goLocal()
    return false
  }
  if (!res.ok) {
    goOffline(`服务端返回 HTTP ${res.status}`)
    return false
  }
  let payload: { version?: unknown; data?: unknown }
  try {
    payload = await res.json() as { version?: unknown; data?: unknown }
  } catch {
    goReadOnly('corrupt', '服务端工作区内容不是 JSON')
    return false
  }
  if (typeof payload.version !== 'number'
    || !Number.isInteger(payload.version) || payload.version < 0) {
    goReadOnly('corrupt', '服务端工作区版本号无效')
    return false
  }
  let data: WorkspaceData
  try {
    data = normalizeWorkspaceData(payload.data)
  } catch (error) {
    goReadOnly('corrupt', error instanceof Error ? error.message : '工作区数据不完整')
    return false
  }

  if (payload.version === 0 && !hasContent(data)) {
    // 服务端还没有工作区：首次迁移，把本机缓存推上去创建。
    const snapshot = workspaceSnapshot(useStore.getState())
    if (!hasContent(snapshot)) {
      serverVersion = 0
      lastSignature = signature(snapshot)
      // 两边都空：不能再「静默成功」，否则用户会以为配置丢了却没有任何线索。
      markOnline(0, '已连接服务端，但服务端工作区为空。若你在另一台设备配置过，请在那台设备用同一访问密钥打开一次，让它把数据上传到服务器。')
      return true
    }
    const created = await putWorkspace(0, snapshot)
    if (typeof created === 'number') {
      serverVersion = created
      lastSignature = signature(snapshot)
      watchedState = useStore.getState()
      markOnline(created, '已上传本机工作区')
      return true
    }
    if (created === 'conflict') {
      // 其他设备抢先创建：重新拉最新，不覆盖对方。
      return await fetchFull({ notice: '另一台设备已先创建工作区，已载入最新数据。' })
    }
    return false
  }

  // 本地完全没有数据、服务端有数据：多半是新设备 / 新访问地址，
  // 明确说明这是从服务端载入，避免用户把正常同步误认为数据丢失。
  const localWasEmpty = !hasContent(workspaceSnapshot(useStore.getState()))
  applyServerData(data)
  serverVersion = payload.version
  lastSignature = signature(workspaceSnapshot(useStore.getState()))
  markOnline(payload.version, options.notice
    ?? (localWasEmpty ? '这是新设备或新地址：已从服务端载入工作区。' : ''))
  return true
}

function markOnline(version: number, message: string): void {
  ready = true
  failureCount = 0
  pollFailures = 0
  setWorkspaceReadOnly(false)
  updateStatus({ mode: 'server', state: 'online', readOnly: false, version, message })
}

export function applyServerData(data: WorkspaceData): void {
  const previous = useStore.getState()
  // 服务端是这些字段的唯一事实来源；运行时测速结果按节点 id 绑定，重新拉取后清空。
  useStore.setState({
    sources: data.sources,
    nodes: data.nodes,
    customSchemes: data.customSchemes,
    localRuleSets: data.localRuleSets,
    builtinSchemeOverrides: data.builtinSchemeOverrides,
    // 快照正文必须跟指针一起落地；只同步指针会让 loadScheme 回落到
    // 上一版 / 原厂，固化内容在第二台设备上凭空消失。
    schemeSnapshots: data.schemeSnapshots,
    snapshotSeq: data.snapshotSeq,
    ruleSetExclusions: data.ruleSetExclusions,
    selectedSchemeID: data.selectedSchemeID,
    policySelections: data.policySelections,
    exportConfigName: data.exportConfigName,
    tailnets: data.tailnets,
    tailnetAuthKeys: data.tailnetAuthKeys,
    loadingSourceIDs: [],
    errors: {},
    latencyByNodeId: {},
    latencyMethodByNodeId: {},
    probeErrorByNodeId: {},
    testingNodeIds: [],
    testingGeneration: previous.testingGeneration + 1,
  })
  persistTailnetAuthKeys(data.tailnetAuthKeys)
  watchedState = useStore.getState()
}

type PutResult = number | 'conflict' | 'unauthorized' | 'offline' | 'corrupt' | 'failed'

async function putWorkspace(version: number, data: WorkspaceData): Promise<PutResult> {
  let res: Response
  try {
    res = await apiFetch('/api/workspace', {
      method: 'PUT',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ version, data }),
    })
  } catch {
    return 'offline'
  }
  if (res.status === 401) {
    const body = await res.json().catch(() => ({})) as { error?: string }
    goReadOnly('unauthorized', body.error ?? '访问密钥无效')
    return 'unauthorized'
  }
  if (res.status === 403 || res.status === 429) {
    const body = await res.json().catch(() => ({})) as { error?: string }
    goReadOnly('blocked', body.error ?? `服务端拒绝请求（HTTP ${res.status}）`)
    return 'failed'
  }
  if (res.status === 404 && await workspaceDisabled(res)) {
    goLocal()
    return 'failed'
  }
  if (res.status === 409) return 'conflict'
  if (res.status === 413) {
    updateStatus({ message: '工作区超过 16MB 上限，本次改动没有保存' })
    return 'failed'
  }
  if (res.status === 500) {
    const body = await res.json().catch(() => ({})) as { error?: string; code?: string }
    if (body.code === 'workspace_write_failed') {
      // 磁盘暂时写失败：按离线处理并退避重试，而不是当成文件损坏。
      return 'offline'
    }
    goReadOnly('corrupt', body.error ?? '服务端工作区不可用')
    return 'corrupt'
  }
  if (!res.ok) return 'failed'
  const body = await res.json().catch(() => ({})) as { version?: unknown }
  if (typeof body.version !== 'number' || !Number.isInteger(body.version)) return 'failed'
  return body.version
}

async function flushWrite(): Promise<boolean> {
  if (!ready) return false
  if (writing) {
    pendingWrite = true
    return false
  }
  if (debounceTimer !== undefined) {
    window.clearTimeout(debounceTimer)
    debounceTimer = undefined
  }
  const data = workspaceSnapshot(useStore.getState())
  const nextSignature = signature(data)
  if (nextSignature === lastSignature && status.state === 'online') return true

  writing = true
  try {
    const result = await putWorkspace(serverVersion, data)
    if (typeof result === 'number') {
      serverVersion = result
      lastSignature = nextSignature
      markOnline(result, '')
      return true
    }
    if (result === 'conflict') {
      // 不做自动合并：直接拉最新并替换，提示用户另一台设备改过。
      await fetchFull({ notice: '另一台设备刚改过工作区，已载入最新数据。' })
      return false
    }
    if (result === 'offline') {
      goOffline()
      return false
    }
    if (result === 'failed') {
      updateStatus({ message: status.message || '工作区保存失败，请稍后重试' })
      return false
    }
    return false
  } finally {
    writing = false
    if (pendingWrite) {
      pendingWrite = false
      if (!isWorkspaceReadOnly()) void flushWrite()
    }
  }
}

/** 服务端明确回答「服务器版未启用」时，退回本地模式。 */
async function workspaceDisabled(res: Response): Promise<boolean> {
  const body = await res.json().catch(() => ({})) as { code?: string }
  return body.code === 'workspace_disabled'
}

/** 停掉服务器同步，退回原有本地模式；只可能发生在服务端被改回 local 时。 */
function goLocal(): void {
  serverMode = false
  stopServerSync()
  rememberMode('local')
  setWorkspaceReadOnly(false)
  updateStatus({ mode: 'local', state: 'local', readOnly: false, version: 0, message: '' })
}

function stopServerSync(): void {
  unsubscribeStore?.()
  unsubscribeStore = undefined
  watchedState = null
  if (pollTimer !== undefined) {
    window.clearInterval(pollTimer)
    pollTimer = undefined
  }
  if (retryTimer !== undefined) {
    window.clearTimeout(retryTimer)
    retryTimer = undefined
  }
  if (debounceTimer !== undefined) {
    window.clearTimeout(debounceTimer)
    debounceTimer = undefined
  }
  ready = false
}

function goOffline(detail?: string): void {
  failureCount += 1
  setWorkspaceReadOnly(true)
  updateStatus({
    mode: 'server',
    state: 'offline',
    readOnly: true,
    version: serverVersion,
    message: detail ?? '',
  })
  scheduleRetry()
}

function goReadOnly(kind: 'unauthorized' | 'corrupt' | 'blocked', message: string): void {
  ready = false
  setWorkspaceReadOnly(true)
  updateStatus({
    mode: 'server',
    state: kind,
    readOnly: true,
    version: serverVersion,
    message,
  })
  scheduleRetry()
}

/** 恢复备份后立即推送，不等 500ms 防抖；只读或本地模式不做任何事。 */
export async function flushWorkspaceNow(): Promise<void> {
  if (!serverMode || !ready || isWorkspaceReadOnly()) return
  await flushWrite()
}

/** 服务端刚发生一次带外写入（例如历史回滚）后，强制拉取最新工作区。 */
export async function reloadWorkspaceFromServer(options: { notice?: string } = {}): Promise<boolean> {
  if (!serverMode) return false
  return await fetchFull(options)
}

/** 测试与调试用：读取当前已知的服务端版本号。 */
export function workspaceServerVersion(): number {
  return serverVersion
}
