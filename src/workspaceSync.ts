// 服务器版工作区同步：拉取 / 推送 / 版本探测 / 冲突与离线处理。
// 只同步「多设备应该一致」的数据；导出目标、隐藏客户端、排序、Emoji、
// 测速模式、地图与高级区展开等设备偏好仍留在 localStorage。
import { useSyncExternalStore } from 'react'
import { persistTailnetAuthKeys } from './models/tailnetAuthKeys'
import { useStore, type Store } from './store'
import {
  describeWorkspaceIssues,
  normalizeWorkspaceData,
  normalizeWorkspaceDataDetailed,
  WorkspaceDataError,
  type WorkspaceData,
  type WorkspaceIssue,
} from './workspaceValidation'
import { describeWorkspaceTooLarge, WORKSPACE_MAX_BYTES } from './workspaceSize'
import {
  initialSaveState,
  nextSaveFailure,
  nextSaveSuccess,
  saveRetryDelay,
} from './workspaceSaveNotice'
import { apiFetch, getAPIKey } from './util/apiAuth'
import { isWorkspaceReadOnly, setWorkspaceReadOnly } from './util/workspaceLock'

export { normalizeWorkspaceData, WorkspaceDataError }
export type { WorkspaceData, WorkspaceIssue }

export type WorkspaceState =
  | 'checking'
  | 'local'
  | 'connecting'
  | 'online'
  /** 有本地改动没能写进服务端；与离线不同，用户仍可继续编辑并自动重试。 */
  | 'unsaved'
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
  /** 本次从服务端载入时被丢弃 / 回退 / 升级的字段明细；界面必须逐条展示。 */
  issues: WorkspaceIssue[]
}

let status: WorkspaceStatus = {
  mode: 'unknown',
  state: 'checking',
  readOnly: false,
  version: 0,
  message: '',
  issues: [],
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

/** 服务端数据里客户端不认识的顶层字段；每次推送原样带回。 */
let preservedUnknownFields: Record<string, unknown> = {}

/**
 * 整块无法读取、但服务端仍持有的顶层字段原始 JSON。
 * 本机不能把它当空值推回去，否则新设备一编辑就覆盖服务端原内容。
 */
let preservedWholeKeys: Record<string, unknown> = {}

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

function rawRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

/** 有本机改动尚未得到服务端确认；首次载入前的缓存不算。 */
function hasPendingLocalChanges(): boolean {
  if (status.state === 'unsaved') return true
  return lastSignature !== '' && currentSignature() !== lastSignature
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
let saveState = initialSaveState()
let unsavedRetryTimer: number | undefined
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
  window.addEventListener('beforeunload', warnBeforeUnload)
}

/** 离开页面前仍有未推送改动时让浏览器弹确认，避免整段编辑被静默丢掉。 */
function warnBeforeUnload(event: BeforeUnloadEvent): void {
  if (!serverMode) return
  if (status.state !== 'unsaved') {
    // lastSignature 为空时页面刚载入、还没确认过服务端版本：
    // 此时本机缓存不算「本次编辑」，不能无端弹离开确认。
    if (lastSignature === '' || currentSignature() === lastSignature) return
  }
  event.preventDefault()
  // 旧浏览器要求设置 returnValue 才会弹确认。
  event.returnValue = ''
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
  // 有未保存改动时只重试保存；即使处于离线只读，也不能先拉远端覆盖本机编辑。
  if (hasPendingLocalChanges()) {
    void flushWrite(!ready)
    return
  }
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

function scheduleUnsavedRetry(): void {
  if (unsavedRetryTimer !== undefined || typeof window === 'undefined') return
  const delay = saveRetryDelay(saveState.failures)
  unsavedRetryTimer = window.setTimeout(() => {
    unsavedRetryTimer = undefined
    void retryUnsaved()
  }, delay)
}

async function retryUnsaved(): Promise<void> {
  if (!serverMode || !ready || isWorkspaceReadOnly()) return
  if (status.state !== 'unsaved') return
  await flushWrite()
}

/** 保存失败：进入持久可见的「未保存」，并按退避自动重试。 */
function markUnsaved(message: string): void {
  // 服务端已经有过响应（413 / HTTP 错误 / 创建失败），后续退避重试可以直接发请求。
  ready = true
  saveState = nextSaveFailure(saveState, message)
  updateStatus({
    mode: 'server',
    state: 'unsaved',
    readOnly: false,
    version: serverVersion,
    message: saveState.message,
    // 上一次载入的「已跳过 N 项」不能继续挂在未保存横幅上。
    issues: [],
  })
  scheduleUnsavedRetry()
}

async function reconnect(): Promise<void> {
  if (!serverMode) {
    await detectMode()
    return
  }
  // 网络恢复后先把尚未保存的改动推一次；推不进去就保持原状，
  // 绝不落到 fetchFull 用服务端数据覆盖本机编辑。
  if (hasPendingLocalChanges()) {
    await flushWrite(!ready)
    return
  }
  await fetchFull()
}

async function pollVersion(): Promise<void> {
  if (writing || debounceTimer !== undefined) return
  // 有未保存改动时先写回，避免版本探针看到远端变化后拉全量、
  // 把当前编辑静默覆盖；写回成功再继续比对版本。
  if (hasPendingLocalChanges()) {
    await flushWrite()
    if (hasPendingLocalChanges() || isWorkspaceReadOnly()) return
    if (writing) return
  }
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

async function fetchFull(options: { notice?: string; force?: boolean } = {}): Promise<boolean> {
  // 有未推送的本地改动时，非显式强制拉取一律先尝试写回；
  // 写不进去就直接返回，避免「服务端数据覆盖本机编辑 + 界面显示已同步」。
  if (!options.force && hasPendingLocalChanges()) {
    await flushWrite(!ready)
    if (hasPendingLocalChanges()) return false
  }
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
  let issues: WorkspaceIssue[]
  try {
    const normalized = normalizeWorkspaceDataDetailed(payload.data)
    data = normalized.data
    issues = normalized.issues
    // 未知顶层字段必须跟着工作区走，否则旧版本打开新数据一次就会永久丢字段。
    preservedUnknownFields = normalized.unknown
  } catch (error) {
    goReadOnly('corrupt', error instanceof Error ? error.message : '工作区数据不完整')
    return false
  }

  const dropped = issues.filter((item) => item.severity === 'dropped')
  // 整字段无法读取时保留本机原值，不能把它写成空数组后推回服务端。
  const droppedKeys = dropped.filter((item) => item.wholeKey).map((item) => item.key)
  const affectedLabels = [...new Set(dropped.map((item) => item.keyLabel))]
  // 记住服务端这些键的原始 JSON：后续任意编辑触发推送时原样带回，
  // 本机空值不会覆盖服务端原内容（单字段坏掉时也能保住数据）。
  const serverRaw = rawRecord(payload.data)
  preservedWholeKeys = {}
  for (const key of droppedKeys) preservedWholeKeys[key] = serverRaw[key]

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
    if (typeof created === 'object') {
      // 413 / 服务端明确失败：必须进入「未保存」，不能停在 connecting 且无声。
      markUnsaved(created.message)
      return false
    }
    if (created === 'conflict') {
      // 其他设备抢先创建：重新拉最新，不覆盖对方。
      return await fetchFull({ notice: '另一台设备已先创建工作区，已载入最新数据。', force: true })
    }
    if (created === 'offline') {
      goOffline()
      return false
    }
    return false
  }

  if (payload.version > 0 && !hasContent(data) && dropped.length > 0) {
    // 服务端有版本但关键内容全坏：绝不能当成「本机为空」继续，
    // 否则一刷新就把本机缓存清掉，用户看到的是空工作区而不是损坏提示。
    goReadOnly(
      'corrupt',
      `服务端工作区 v${payload.version} 存在，但${affectedLabels.join('、')}无法读取；已保留本机当前数据，没有当作空工作区覆盖。`,
      issues,
    )
    return false
  }

  // 本地完全没有数据、服务端有数据：多半是新设备 / 新访问地址，
  // 明确说明这是从服务端载入，避免用户把正常同步误认为数据丢失。
  const localWasEmpty = !hasContent(workspaceSnapshot(useStore.getState()))
  applyServerData(data, droppedKeys)
  serverVersion = payload.version
  lastSignature = signature(workspaceSnapshot(useStore.getState()))
  const summary = describeWorkspaceIssues(issues)
  const notice = options.notice
    ?? (!summary && localWasEmpty ? '这是新设备或新地址：已从服务端载入工作区。' : '')
  markOnline(payload.version, [notice, summary].filter(Boolean).join(' '), issues)
  return true
}

function markOnline(version: number, message: string, issues: WorkspaceIssue[] = []): void {
  ready = true
  failureCount = 0
  pollFailures = 0
  saveState = nextSaveSuccess()
  if (unsavedRetryTimer !== undefined) {
    window.clearTimeout(unsavedRetryTimer)
    unsavedRetryTimer = undefined
  }
  setWorkspaceReadOnly(false)
  updateStatus({ mode: 'server', state: 'online', readOnly: false, version, message, issues })
}

/**
 * 应用服务端数据。`keepKeys` 是整块损坏的顶层字段：这些键保留本机原值，
 * 其它已通过校验的键正常落地；避免一个坏字段把本地可用数据一起清空。
 */
export function applyServerData(data: WorkspaceData, keepKeys: string[] = []): void {
  const previous = useStore.getState()
  // 服务端是这些字段的唯一事实来源；运行时测速结果按节点 id 绑定，重新拉取后清空。
  const patch = {
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
  }
  for (const key of keepKeys) {
    delete (patch as Record<string, unknown>)[key]
  }
  useStore.setState(patch)
  // 密钥表整块损坏时保留本机已保存的 Key，不能顺手把 localStorage 也清空。
  if (!keepKeys.includes('tailnetAuthKeys')) persistTailnetAuthKeys(data.tailnetAuthKeys)
  watchedState = useStore.getState()
}

interface SaveFailure {
  kind: 'unsaved'
  message: string
}

type PutResult = number | SaveFailure | 'conflict' | 'unauthorized' | 'offline' | 'corrupt' | 'failed'

async function putWorkspace(version: number, data: WorkspaceData): Promise<PutResult> {
  let res: Response
  try {
    res = await apiFetch('/api/workspace', {
      method: 'PUT',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      // 整块损坏字段原样写回：必须放在最后，否则会被本机快照里的空值覆盖。
      body: JSON.stringify({ version, data: { ...preservedUnknownFields, ...data, ...preservedWholeKeys } }),
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
    const report = describeWorkspaceTooLarge(data, preservedUnknownFields, WORKSPACE_MAX_BYTES)
    return { kind: 'unsaved', message: report.message }
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
  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as { error?: string }
    return {
      kind: 'unsaved',
      message: `服务端保存失败（HTTP ${res.status}）${body.error ? `：${body.error}` : ''}；本地改动会保留并自动重试。`,
    }
  }
  const body = await res.json().catch(() => ({})) as { version?: unknown }
  if (typeof body.version !== 'number' || !Number.isInteger(body.version)) {
    return {
      kind: 'unsaved',
      message: '服务端返回了无法识别的保存结果（HTTP 200），本次改动尚未确认保存；本地改动会保留并自动重试。',
    }
  }
  return body.version
}

async function flushWrite(allowNotReady = false): Promise<boolean> {
  if (!ready && !allowNotReady) return false
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
  if (nextSignature === lastSignature) {
    // 用户把改动改回服务端已确认的版本，或者在未保存状态下重新对齐；
    // 没有内容要写，直接收回「未保存」。
    if (status.state === 'unsaved') markOnline(serverVersion, '', status.issues)
    return true
  }

  writing = true
  try {
    const result = await putWorkspace(serverVersion, data)
    if (typeof result === 'number') {
      serverVersion = result
      lastSignature = nextSignature
      // 保存成功只收「未保存」，本次载入丢字段的明细保留到下一次 fetchFull。
      markOnline(result, '', status.issues)
      return true
    }
    if (result === 'conflict') {
      // 不做自动合并：直接拉最新并替换，提示用户另一台设备改过。
      await fetchFull({ notice: '另一台设备刚改过工作区，已载入最新数据。', force: true })
      return false
    }
    if (result === 'offline') {
      goOffline()
      return false
    }
    if (typeof result === 'object') {
      markUnsaved(result.message)
      return false
    }
    if (result === 'failed') {
      // 403 / 429 / 404 已经进入只读或本地模式，不要再用「未保存」覆盖。
      if (serverMode && !isWorkspaceReadOnly()) {
        markUnsaved('工作区保存失败，本地改动尚未写入服务端。')
      }
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
  if (unsavedRetryTimer !== undefined) {
    window.clearTimeout(unsavedRetryTimer)
    unsavedRetryTimer = undefined
  }
  saveState = initialSaveState()
  preservedWholeKeys = {}
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
  ready = false
  setWorkspaceReadOnly(true)
  updateStatus({
    mode: 'server',
    state: 'offline',
    readOnly: true,
    version: serverVersion,
    message: detail ?? '',
    // 上一次载入的「已跳过 N 项」不能继续挂在离线横幅上。
    issues: [],
  })
  scheduleRetry()
}

function goReadOnly(
  kind: 'unauthorized' | 'corrupt' | 'blocked',
  message: string,
  issues: WorkspaceIssue[] = [],
): void {
  ready = false
  if (unsavedRetryTimer !== undefined) {
    window.clearTimeout(unsavedRetryTimer)
    unsavedRetryTimer = undefined
  }
  setWorkspaceReadOnly(true)
  updateStatus({
    mode: 'server',
    state: kind,
    readOnly: true,
    version: serverVersion,
    message,
    issues,
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
  // 历史回滚等显式操作：调用方已先 flushWorkspaceNow，这里强制以服务端为准。
  return await fetchFull({ ...options, force: true })
}

/** 测试与调试用：读取当前已知的服务端版本号。 */
export function workspaceServerVersion(): number {
  return serverVersion
}
