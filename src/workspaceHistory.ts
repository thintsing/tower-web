// 服务端工作区历史：列表 / 单版正文 / 回滚。
// 只在 TOWER_MODE=server 下可用；回滚遵守现有乐观锁（If-Match + version）。
import { apiFetch } from './util/apiAuth'

export interface WorkspaceCounts {
  subscriptions: number
  nodes: number
  rules: number
  schemes: number
  groups: number
}

export interface WorkspaceCountChange {
  before: number
  after: number
}

export interface WorkspaceHistoryDiff {
  rules: WorkspaceCountChange
  subscriptions: WorkspaceCountChange
  nodes: WorkspaceCountChange
  schemes: WorkspaceCountChange
  groups: WorkspaceCountChange
}

export interface WorkspaceHistorySource {
  ip: string
  ua: string
}

export interface WorkspaceHistoryEntry {
  id: string
  version: number
  updatedAt: number
  archivedAt: number
  bytes: number
  trigger: 'write' | 'restore'
  source: WorkspaceHistorySource
  counts: WorkspaceCounts
  diff: WorkspaceHistoryDiff | null
}

export interface WorkspaceHistoryList {
  current: {
    version: number
    updatedAt: number
    bytes: number
    counts: WorkspaceCounts
  }
  entries: WorkspaceHistoryEntry[]
  totalBytes: number
  limits: { entries: number; bytes: number }
}

export interface WorkspaceHistoryDetail extends WorkspaceHistoryEntry {
  data: unknown
}

export interface WorkspaceHistoryRestoreResult {
  version: number
  updatedAt: number
  restoredFrom: { id: string; version: number }
  /** 回滚前自动归档的当前版，可用于「撤销回滚」。 */
  previous: { id: string; version: number; bytes: number } | null
}

export class WorkspaceHistoryError extends Error {
  code: string
  status: number

  constructor(message: string, code = 'history_request_failed', status = 0) {
    super(message)
    this.name = 'WorkspaceHistoryError'
    this.code = code
    this.status = status
  }
}

async function historyError(res: Response): Promise<WorkspaceHistoryError> {
  const body = await res.json().catch(() => ({})) as { error?: string; code?: string }
  return new WorkspaceHistoryError(
    body.error ?? `工作区历史请求失败（HTTP ${res.status}）`,
    body.code ?? 'history_request_failed',
    res.status,
  )
}

export async function fetchWorkspaceHistory(): Promise<WorkspaceHistoryList> {
  let res: Response
  try {
    res = await apiFetch('/api/workspace/history', { cache: 'no-store' })
  } catch {
    throw new WorkspaceHistoryError('无法连接服务端，暂时读不到工作区历史', 'offline')
  }
  if (!res.ok) throw await historyError(res)
  return await res.json() as WorkspaceHistoryList
}

export async function fetchWorkspaceHistoryEntry(id: string): Promise<WorkspaceHistoryDetail> {
  let res: Response
  try {
    res = await apiFetch(`/api/workspace/history/${encodeURIComponent(id)}`, { cache: 'no-store' })
  } catch {
    throw new WorkspaceHistoryError('无法连接服务端，暂时读不到这一版', 'offline')
  }
  if (!res.ok) throw await historyError(res)
  return await res.json() as WorkspaceHistoryDetail
}

/** 回滚 = 以历史版本为基础生成新版本，版本号继续递增。 */
export async function restoreWorkspaceHistoryEntry(
  id: string,
  version: number,
): Promise<WorkspaceHistoryRestoreResult> {
  let res: Response
  try {
    res = await apiFetch(`/api/workspace/history/${encodeURIComponent(id)}/restore`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'if-match': `"v${version}"`,
      },
      body: JSON.stringify({ version }),
    })
  } catch {
    throw new WorkspaceHistoryError('无法连接服务端，回滚没有执行', 'offline')
  }
  if (!res.ok) throw await historyError(res)
  return await res.json() as WorkspaceHistoryRestoreResult
}
