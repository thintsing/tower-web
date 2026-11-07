// 「订阅设置 → 工作区历史」：服务器模式下列出每次覆盖前自动保留的版本，
// 支持回滚（以旧版为基础生成新版本），当前版单独标注。
import { useEffect, useState } from 'react'
import { BUILTIN_SCHEMES } from '../rules/scheme'
import { useStore } from '../store'
import { flushWorkspaceNow, normalizeWorkspaceData, reloadWorkspaceFromServer, useWorkspaceStatus, workspaceServerVersion, workspaceSnapshot, type WorkspaceData } from '../workspaceSync'
import {
  fetchWorkspaceHistory,
  fetchWorkspaceHistoryEntry,
  restoreWorkspaceHistoryEntry,
  WorkspaceHistoryError,
  type WorkspaceCounts,
  type WorkspaceHistoryDetail,
  type WorkspaceHistoryDiff,
  type WorkspaceHistoryEntry,
  type WorkspaceHistoryList,
} from '../workspaceHistory'

const COUNT_LABELS: Array<[keyof WorkspaceCounts, string]> = [
  ['rules', '规则'],
  ['subscriptions', '订阅'],
  ['nodes', '节点'],
  ['schemes', '方案'],
  ['groups', '策略组'],
]

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 KB'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(value: number): string {
  if (!value) return '时间未记录'
  return new Date(value).toLocaleString('zh-CN')
}

function sourceText(source: { ip: string; ua: string }): string {
  const ua = source.ua.replace(/\s+/g, ' ').slice(0, 48)
  return [source.ip, ua].filter(Boolean).join(' · ') || '来源未记录'
}

function countsText(counts: WorkspaceCounts): string {
  return COUNT_LABELS.map(([key, label]) => `${label} ${counts[key]}`).join(' · ')
}

function diffText(diff: WorkspaceHistoryDiff | null): string {
  if (!diff) return '这一版没有记录差异摘要'
  return COUNT_LABELS
    .map(([key, label]) => `${label} ${diff[key].before} → ${diff[key].after}`)
    .join(' · ')
}

function countChangeLines(before: WorkspaceCounts, after: WorkspaceCounts): string[] {
  const changed = COUNT_LABELS
    .filter(([key]) => before[key] !== after[key])
    .map(([key, label]) => {
      const delta = after[key] - before[key]
      return `${label} ${before[key]} → ${after[key]}（${delta > 0 ? '+' : ''}${delta}）`
    })
  return changed.length > 0 ? changed : ['各项数量没有变化']
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

/** 对比当前工作区与目标版本，列出会被改动的方案名。 */
export function describeSchemeImpact(currentRaw: WorkspaceData, targetRaw: unknown): string[] {
  let target: WorkspaceData
  try {
    target = normalizeWorkspaceData(targetRaw)
  } catch {
    return ['目标版本数据不完整，无法逐项列出受影响的方案']
  }
  const impacts: string[] = []
  const currentSchemes = new Map(currentRaw.customSchemes.map((scheme) => [scheme.id, scheme]))
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
    ...Object.keys(currentRaw.builtinSchemeOverrides),
    ...Object.keys(target.builtinSchemeOverrides),
  ])
  for (const id of builtinIDs) {
    if (resolvedOverride(currentRaw, id) !== resolvedOverride(target, id)) {
      impacts.push(`内置方案「${builtinName(id)}」的固化内容有变化`)
    }
  }
  if (currentRaw.selectedSchemeID !== target.selectedSchemeID) {
    impacts.push(`当前方案 ${selectedSchemeName(currentRaw)} → ${selectedSchemeName(target)}`)
  }
  return [...new Set(impacts)]
}

interface PendingRestore {
  detail: WorkspaceHistoryDetail
  impact: string[]
  undoing: boolean
}

interface UndoPoint {
  id: string
  version: number
  createdVersion: number
}

export function WorkspaceHistoryPanel({ open }: { open: boolean }) {
  const status = useWorkspaceStatus()
  const [list, setList] = useState<WorkspaceHistoryList | null>(null)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [pending, setPending] = useState<PendingRestore | null>(null)
  const [undo, setUndo] = useState<UndoPoint | null>(null)

  const load = async (silent = false) => {
    if (!silent) setLoading(true)
    setError('')
    try {
      setList(await fetchWorkspaceHistory())
    } catch (e) {
      setError(e instanceof WorkspaceHistoryError ? e.message : '无法读取工作区历史')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!open || status.mode !== 'server') {
      setPending(null)
      return
    }
    void load()
  }, [open, status.mode])

  if (status.mode !== 'server') return null

  const beginRestore = async (entry: WorkspaceHistoryEntry, undoing = false) => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const detail = await fetchWorkspaceHistoryEntry(entry.id)
      const impact = describeSchemeImpact(workspaceSnapshot(useStore.getState()), detail.data)
      setPending({ detail, impact, undoing })
    } catch (e) {
      setError(e instanceof WorkspaceHistoryError ? e.message : '无法读取这一版')
    } finally {
      setBusy(false)
    }
  }

  const executeRestore = async () => {
    if (!pending) return
    const target = pending.detail
    setBusy(true)
    setError('')
    setNotice('')
    try {
      // 先把本机尚未推送的改动写回服务端，再用最新版本号做乐观锁。
      await flushWorkspaceNow()
      const expected = workspaceServerVersion()
      const result = await restoreWorkspaceHistoryEntry(target.id, expected)
      setPending(null)
      setUndo(result.previous ? {
        id: result.previous.id,
        version: result.previous.version,
        createdVersion: result.version,
      } : null)
      await reloadWorkspaceFromServer({ notice: `已回滚到 v${target.version}。` })
      setNotice(`已回滚到 v${target.version}，服务器生成新版本 v${result.version}。回滚本身也是一次写入；如果点错了，可以撤销这次回滚。`)
      await load(true)
    } catch (e) {
      const failure = e instanceof WorkspaceHistoryError ? e : null
      setError(failure?.message ?? '回滚失败')
      if (failure?.code === 'version_conflict') {
        await reloadWorkspaceFromServer()
        await load(true)
      }
    } finally {
      setBusy(false)
    }
  }

  const restoreDisabledReason = status.readOnly
    ? '工作区当前只读，无法回滚'
    : status.state !== 'online'
      ? '服务端未连接，无法回滚'
      : busy
        ? '正在处理上一次操作'
        : ''

  return (
    <>
      <div className="settings-divider" />
      <div className="settings-data-head">
        <div>
          <strong>工作区历史</strong>
          <small>
            服务器每次覆盖工作区前自动保留上一版，最近 {list?.limits.entries ?? 10} 版、总量上限{' '}
            {formatBytes(list?.limits.bytes ?? 50 * 1024 * 1024)}。当前版的前一版不会被容量策略删除。
          </small>
        </div>
        <button type="button" className="btn ghost" disabled={loading} onClick={() => void load()}>
          {loading ? '读取中…' : '刷新'}
        </button>
      </div>
      {list && (
        <div className="workspace-history-summary">
          当前 v{list.current.version} · 历史 {list.entries.length} 版 · 占用 {formatBytes(list.totalBytes)}
          {list.current.version === 0 ? ' · 服务端工作区还没有内容' : ''}
        </div>
      )}
      {loading && !list && <div className="hint">正在读取工作区历史…</div>}
      {error && <div className="form-error" role="alert"><span>{error}</span></div>}
      {notice && <div className="inline-notice" role="status">{notice}</div>}
      {undo && (
        <div className="workspace-history-undo">
          <span>
            回滚生成的新版本是 v{undo.createdVersion}；如果点错了，可以回到回滚前的 v{undo.version}。
          </span>
          <button
            type="button"
            className="btn ghost"
            disabled={busy || status.readOnly}
            onClick={() => {
              const entry = list?.entries.find((item) => item.id === undo.id)
              if (entry) void beginRestore(entry, true)
              else setError('回滚前的版本已不在历史里')
            }}
          >撤销这次回滚</button>
        </div>
      )}
      {list && (
        <ul className="backup-history-list workspace-history-list">
          <li className="current">
            <div className="backup-history-main">
              <strong>
                v{list.current.version}
                <span className="workspace-history-current">当前版</span>
              </strong>
              <span className="hint">
                {formatTime(list.current.updatedAt)} · {formatBytes(list.current.bytes)} · {countsText(list.current.counts)}
              </span>
              <span className="hint">当前正在使用的工作区，不会出现在可回滚列表里。</span>
            </div>
          </li>
          {list.entries.map((entry) => (
            <li key={entry.id}>
              <div className="backup-history-main">
                <strong>
                  v{entry.version}
                  {entry.trigger === 'restore' && <span className="workspace-history-badge">回滚时归档</span>}
                </strong>
                <span className="hint">
                  {formatTime(entry.archivedAt || entry.updatedAt)} · {sourceText(entry.source)} · {formatBytes(entry.bytes)}
                </span>
                <span className="hint workspace-history-diff">{diffText(entry.diff)}</span>
              </div>
              <div className="row" style={{ gap: 6 }}>
                <button
                  type="button"
                  className="btn ghost"
                  disabled={busy || status.readOnly || status.state !== 'online'}
                  title={restoreDisabledReason || undefined}
                  onClick={() => void beginRestore(entry)}
                >回滚到此版</button>
              </div>
            </li>
          ))}
        </ul>
      )}
      {list && list.entries.length === 0 && (
        <div className="hint">还没有历史版本。完成一次工作区修改后，上一版会自动出现在这里。</div>
      )}
      {pending && (
        <div className="restore-confirm" role="alert">
          <div>
            <strong>{pending.undoing ? `撤销回滚：回到 v${pending.detail.version}` : `确认回滚到 v${pending.detail.version}？`}</strong>
            <small>
              这一版保存于 {formatTime(pending.detail.archivedAt || pending.detail.updatedAt)}。
              回滚会以这一版为基础生成一个新版本（当前 v{list?.current.version ?? '?'} → v{(list?.current.version ?? 0) + 1}），
              版本号不会退回去；回滚前会自动备份当前版。
            </small>
            <small className="workspace-history-change">
              {countChangeLines(list?.current.counts ?? pending.detail.counts, pending.detail.counts).join(' · ')}
            </small>
            <small className="workspace-history-change">
              受影响的方案：{pending.impact.length > 0 ? pending.impact.join('、') : '无'}
            </small>
            <small>
              已导出的客户端配置和已发布的订阅链接不会自动更新，需要重新导出或让客户端刷新。
            </small>
          </div>
          <div className="row" style={{ gap: 8 }}>
            <button type="button" className="btn danger" disabled={busy} onClick={() => void executeRestore()}>
              {busy ? '回滚中…' : '确认回滚'}
            </button>
            <button type="button" className="btn ghost" disabled={busy} onClick={() => setPending(null)}>取消</button>
          </div>
        </div>
      )}
    </>
  )
}
