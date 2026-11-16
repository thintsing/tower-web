// 订阅设置弹窗：本地偏好、订阅健康、局域网访问、备份 / 体检与重置。
import { useEffect, useMemo, useRef, useState } from 'react'
import { subscriptionUsageSummary, type LatencyTestMode } from '../models/types'
import { isSourceEnabled, persistedSnapshot, useStore } from '../store'
import {
  backupCounts,
  backupFileName,
  createBackup,
  inspectSnapshotHealth,
  MAX_BACKUP_BYTES,
  parseBackup,
  type BackupFile,
  type BackupRejection,
} from '../backup'
import {
  backupHistoryItems,
  MAX_BACKUP_HISTORY,
  readBackupHistory,
  removeBackupHistory,
  saveBackupHistory,
  BackupHistoryError,
  type BackupHistoryItem,
} from '../backupHistory'
import { clearRuleSetHistory } from '../rules/ruleSetHistory'
import { apiFetch, clearAPIKey, setAPIKey } from '../util/apiAuth'
import { copyToClipboard } from '../util/browser'
import { clearTowerStorage } from '../util/localStore'
import { READONLY_NOTE, writeGuard } from '../util/readOnlyUi'
import { flushWorkspaceNow, useWorkspaceStatus } from '../workspaceSync'
import { UsageHealthBadge } from './SourceUsage'
import { WorkspaceHistoryPanel } from './WorkspaceHistoryPanel'

/** 备份 / 体检里被拒绝条目的分类名，界面上不显示内部 kind。 */
const REJECTION_KIND_TITLES: Record<BackupRejection['kind'], string> = {
  source: '订阅',
  node: '节点',
  scheme: '自定义方案',
  ruleSet: '规则集',
  tailnet: 'Tailscale 内网',
  snapshot: '固化快照',
  override: '快照指针',
  topLevel: '顶层字段',
}

export function SubscriptionSettingsDialog({
  open,
  onClose,
  onRestored,
}: {
  open: boolean
  onClose: () => void
  onRestored?: (message: string) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const backupRef = useRef<HTMLInputElement>(null)
  const autoRefreshOnOpen = useStore((s) => s.autoRefreshOnOpen)
  const setAutoRefreshOnOpen = useStore((s) => s.setAutoRefreshOnOpen)
  const autoRefreshRuleSetsOnOpen = useStore((s) => s.autoRefreshRuleSetsOnOpen)
  const setAutoRefreshRuleSetsOnOpen = useStore((s) => s.setAutoRefreshRuleSetsOnOpen)
  const filterSubscriptionInfoNodes = useStore((s) => s.filterSubscriptionInfoNodes)
  const setFilterSubscriptionInfoNodes = useStore((s) => s.setFilterSubscriptionInfoNodes)
  const renewalRemindersEnabled = useStore((s) => s.renewalRemindersEnabled)
  const setRenewalRemindersEnabled = useStore((s) => s.setRenewalRemindersEnabled)
  const sources = useStore((s) => s.sources)
  // 订阅健康与首页订阅卡同一套判定，设置页只做汇总展示。
  const subscriptionHealthRows = useMemo(
    () => sources
      .filter(isSourceEnabled)
      .map((source) => ({ source, summary: subscriptionUsageSummary(source) })),
    [sources],
  )
  const showGroupEmoji = useStore((s) => s.showGroupEmoji)
  const setShowGroupEmoji = useStore((s) => s.setShowGroupEmoji)
  const ruleSetVersionHistory = useStore((s) => s.ruleSetVersionHistory)
  const setRuleSetVersionHistory = useStore((s) => s.setRuleSetVersionHistory)
  const latencyTestMode = useStore((s) => s.latencyTestMode)
  const setLatencyTestMode = useStore((s) => s.setLatencyTestMode)
  const restoreBackup = useStore((s) => s.restoreBackup)
  const persistenceWarnings = useStore((s) => s.persistenceWarnings)
  const setPersistenceWarnings = useStore((s) => s.setPersistenceWarnings)
  const clearCorruptPersistence = useStore((s) => s.clearCorruptPersistence)
  const builtinSchemeOverrides = useStore((s) => s.builtinSchemeOverrides)
  const schemeSnapshots = useStore((s) => s.schemeSnapshots)
  // 快照健康每次实时计算：陈旧警告可能在本次会话里已被修复，不该继续吓人。
  const snapshotHealth = useMemo(
    () => inspectSnapshotHealth(builtinSchemeOverrides, schemeSnapshots),
    [builtinSchemeOverrides, schemeSnapshots],
  )
  const readOnly = useWorkspaceStatus().readOnly
  const workspaceIssues = useWorkspaceStatus().issues
  const [pendingBackup, setPendingBackup] = useState<BackupFile | null>(null)
  const [backupBusy, setBackupBusy] = useState(false)
  const [backupError, setBackupError] = useState('')
  const [backupNotice, setBackupNotice] = useState('')
  const [history, setHistory] = useState<BackupHistoryItem[]>([])
  const [resetConfirm, setResetConfirm] = useState(false)
  const [serverAccess, setServerAccess] = useState<{
    lanSharing: boolean
    requiresAuth: boolean
    apiToken: string
    mobileURL?: string
  } | null>(null)
  const [serverAccessError, setServerAccessError] = useState('')
  const [serverAccessNotice, setServerAccessNotice] = useState('')
  const [serverAccessBusy, setServerAccessBusy] = useState(false)

  const refreshHistory = () => setHistory(backupHistoryItems(readBackupHistory()))

  const loadServerAccess = async () => {
    setServerAccessError('')
    try {
      const res = await apiFetch('/api/settings', { cache: 'no-store' })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}) as { error?: string })
        throw new Error(body.error ?? `HTTP ${res.status}`)
      }
      setServerAccess(await res.json())
    } catch (error) {
      setServerAccess(null)
      setServerAccessError(error instanceof Error ? error.message : '无法读取服务端设置')
    }
  }

  const saveLanSharing = async (enabled: boolean) => {
    setServerAccessBusy(true)
    setServerAccessError('')
    try {
      const res = await apiFetch('/api/settings', {
        method: 'PUT',
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify({ lanSharing: enabled }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}) as { error?: string })
        throw new Error(body.error ?? `HTTP ${res.status}`)
      }
      setServerAccess(await res.json())
      setServerAccessNotice(enabled ? '已开启局域网共享。' : '已关闭局域网共享；手机和其他设备将无法访问塔台。')
    } catch (error) {
      setServerAccessError(error instanceof Error ? error.message : '保存失败')
    } finally {
      setServerAccessBusy(false)
    }
  }

  const rotateAPIToken = async () => {
    setServerAccessBusy(true)
    setServerAccessError('')
    try {
      const res = await apiFetch('/api/settings/token', { method: 'POST' })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}) as { error?: string })
        throw new Error(body.error ?? `HTTP ${res.status}`)
      }
      const data = await res.json()
      setServerAccess(data)
      setAPIKey(String(data.apiToken ?? ''))
      setServerAccessNotice('已生成新的访问密钥。局域网页面需要用新密钥重新打开。')
    } catch (error) {
      setServerAccessError(error instanceof Error ? error.message : '生成失败')
    } finally {
      setServerAccessBusy(false)
    }
  }

  const disableAPIToken = async () => {
    setServerAccessBusy(true)
    setServerAccessError('')
    try {
      const res = await apiFetch('/api/settings/token', { method: 'DELETE' })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}) as { error?: string })
        throw new Error(body.error ?? `HTTP ${res.status}`)
      }
      const data = await res.json()
      setServerAccess(data)
      clearAPIKey()
      setServerAccessNotice('已关闭 API 鉴权；局域网 API 恢复为无密钥访问。')
    } catch (error) {
      setServerAccessError(error instanceof Error ? error.message : '关闭失败')
    } finally {
      setServerAccessBusy(false)
    }
  }

  const copyMobileAccess = async () => {
    if (!serverAccess?.mobileURL) return
    if (await copyToClipboard(serverAccess.mobileURL)) {
      setServerAccessNotice('已复制带访问密钥的手机地址。')
    } else {
      setServerAccessError('无法写入剪贴板，请手动复制。')
    }
  }

  useEffect(() => {
    if (open) {
      ref.current?.showModal()
      setPendingBackup(null)
      setBackupBusy(false)
      setBackupError('')
      setBackupNotice('')
      setResetConfirm(false)
      setServerAccessError('')
      setServerAccessNotice('')
      void loadServerAccess()
      refreshHistory()
    } else {
      ref.current?.close()
    }
  }, [open])

  const downloadBackup = (file: BackupFile) => {
    const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' })
    const anchor = document.createElement('a')
    anchor.href = URL.createObjectURL(blob)
    anchor.download = backupFileName(new Date(file.exportedAt))
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    window.setTimeout(() => URL.revokeObjectURL(anchor.href), 1000)
  }

  const exportBackup = () => {
    const data = persistedSnapshot(useStore.getState())
    const file = createBackup(data)
    downloadBackup(file)
    const counts = backupCounts(data)
    setBackupError('')
    setBackupNotice(`已导出 ${counts.sources} 个订阅、${counts.nodes} 个节点（含 ${counts.manualNodes} 个自有节点）、${counts.schemes} 个自定义方案和 ${counts.ruleSets} 个规则集。请妥善保管备份文件。`)
  }

  const saveHistoryVersion = () => {
    try {
      saveBackupHistory(persistedSnapshot(useStore.getState()), '手动保存')
      refreshHistory()
      setBackupError('')
      setBackupNotice('已保存当前版本到本机历史。恢复备份前也会自动保存一份。')
    } catch (e) {
      setBackupNotice('')
      setBackupError(e instanceof BackupHistoryError ? e.message : '无法保存版本历史')
    }
  }

  const deleteHistoryVersion = (id: string) => {
    try {
      removeBackupHistory(id)
      refreshHistory()
      setBackupError('')
    } catch (e) {
      setBackupError(e instanceof BackupHistoryError ? e.message : '无法删除版本')
    }
  }

  const readBackup = async (file: File | undefined) => {
    if (!file) return
    setBackupBusy(true)
    setBackupError('')
    setBackupNotice('')
    try {
      if (file.size > MAX_BACKUP_BYTES) throw new Error('备份文件大于 20 MB')
      const parsed = parseBackup(await file.text())
      setPendingBackup(parsed)
    } catch (e) {
      setPendingBackup(null)
      setBackupError((e as Error).message)
    } finally {
      setBackupBusy(false)
    }
  }

  const applyBackup = () => {
    if (!pendingBackup) return
    const counts = backupCounts(pendingBackup.data)
    // 覆盖恢复不可撤销，先把当前数据存一份到本机历史。
    try {
      saveBackupHistory(persistedSnapshot(useStore.getState()), '恢复前自动保存')
    } catch {
      // 空间不足时仍然允许恢复，历史只是额外保障。
    }
    restoreBackup(pendingBackup.data)
    // 被丢弃的条目挂在本次会话的体检列表里；恢复完成后再给一次可见的机会。
    setPersistenceWarnings(pendingBackup.rejected ?? [])
    // 服务器模式下恢复 = 推送并递增版本；服务端会在覆盖前自动留一份 .bak。
    void flushWorkspaceNow()
    // 备份不含规则集历史；恢复后旧快照的 setID 可能已不存在，直接清空避免错配。
    clearRuleSetHistory()
    setPendingBackup(null)
    refreshHistory()
    onRestored?.(`已恢复 ${counts.sources} 个订阅、${counts.nodes} 个节点（含 ${counts.manualNodes} 个自有节点）、${counts.schemes} 个自定义方案和 ${counts.ruleSets} 个规则集。`)
  }

  const pendingCounts = pendingBackup ? backupCounts(pendingBackup.data) : null
  // 快照类拒绝在「数据体检」里按实时健康展示，避免同一条坏记录出现两次。
  const backupRejections = persistenceWarnings.filter((item) => item.kind !== 'snapshot' && item.kind !== 'override')
  const snapshotIssueTotal = snapshotHealth.dangling.length + snapshotHealth.corrupted.length

  const clearDamaged = () => {
    const dismissed = backupRejections.length
    const result = clearCorruptPersistence()
    // 快照类提示由 store 按清理后的真实状态重建；本次会话的备份拒绝记录只是
    // 「导入时已经丢弃」的告知，用户确认后一并收起，避免体检区一直挂着旧记录。
    setBackupError('')
    const parts: string[] = []
    if (result.pointers) parts.push(`${result.pointers} 个悬空指针`)
    if (result.snapshots) parts.push(`${result.snapshots} 个损坏快照`)
    if (dismissed) parts.push(`${dismissed} 条本次会话的丢弃记录`)
    setBackupNotice(parts.length
      ? `已清除 ${parts.join('、')}；正常版本未受影响。`
      : '没有需要清除的损坏记录。')
  }

  return (
    <dialog ref={ref} onClose={onClose}>
      <h3>订阅设置</h3>
      <div className="settings-body">
        <label className="setting-toggle">
          <input
            type="checkbox"
            checked={autoRefreshOnOpen}
            onChange={(e) => setAutoRefreshOnOpen(e.target.checked)}
          />
          <span>
            <strong>打开塔台时刷新订阅</strong>
            <small>每次打开页面时，自动刷新所有已启用且带订阅地址的条目；关闭时只在你手动刷新时联网。</small>
          </span>
        </label>
        <label className="setting-toggle">
          <input
            type="checkbox"
            checked={autoRefreshRuleSetsOnOpen}
            onChange={(e) => setAutoRefreshRuleSetsOnOpen(e.target.checked)}
          />
          <span>
            <strong>打开塔台时刷新在线规则集</strong>
            <small>只刷新「我的规则集」里带地址且未暂停的订阅快照；方案里的远程规则集由客户端自行更新。</small>
          </span>
        </label>
        <label className="setting-toggle">
          <input
            type="checkbox"
            checked={filterSubscriptionInfoNodes}
            onChange={(e) => setFilterSubscriptionInfoNodes(e.target.checked)}
          />
          <span>
            <strong>隐藏订阅信息节点</strong>
            <small>隐藏流量、到期、官网、客服等信息节点，只保留可用节点。</small>
          </span>
        </label>
        <label className="setting-toggle">
          <input
            type="checkbox"
            checked={renewalRemindersEnabled}
            onChange={(e) => {
              const enabled = e.target.checked
              setRenewalRemindersEnabled(enabled)
              if (enabled && 'Notification' in window && Notification.permission === 'default') {
                try {
                  void Notification.requestPermission().catch(() => {})
                } catch {
                  // 浏览器禁用通知 API 时保留应用内提醒。
                }
              }
            }}
          />
          <span>
            <strong>到期与流量提醒</strong>
            <small>订阅即将到期或流量接近上限时，在订阅页提示；允许通知后，塔台打开期间还会发系统通知。</small>
          </span>
        </label>
        <div className="settings-divider" />
        <div className="settings-data-head">
          <div>
            <strong>订阅健康</strong>
            <small>
              到期 ≤7 天为注意、≤3 天为紧急；流量余量 ≤20% 为注意、≤10% 为紧急。
              已过期单独标出；机场没返回数据时保持中性，不做预警。
            </small>
          </div>
        </div>
        {subscriptionHealthRows.length === 0 ? (
          <div className="hint">还没有已启用的订阅。</div>
        ) : (
          <ul className="subscription-health-list">
            {subscriptionHealthRows.map(({ source, summary }) => (
              <li key={source.id}>
                <span className="subscription-health-name">{source.name}</span>
                <UsageHealthBadge summary={summary} />
                {summary.healthReasons.length > 0 && (
                  <span className="subscription-health-reason">{summary.healthReasons.join('；')}</span>
                )}
              </li>
            ))}
          </ul>
        )}
        <label className="setting-toggle">
          <input
            type="checkbox"
            checked={showGroupEmoji}
            onChange={(e) => setShowGroupEmoji(e.target.checked)}
          />
          <span>
            <strong>显示策略组 Emoji</strong>
            <small>在策略组列表和规则标签里显示组名开头的 Emoji；关闭时只显示文字。</small>
          </span>
        </label>
        <label className="setting-toggle">
          <input
            type="checkbox"
            checked={ruleSetVersionHistory}
            onChange={(e) => setRuleSetVersionHistory(e.target.checked)}
          />
          <span>
            <strong>保留规则集刷新历史</strong>
            <small>刷新在线规则集前保存上一版快照，用于规则页的版本对比；只保留最近一版，关闭后不再记录。</small>
          </span>
        </label>
        <div className="field">
          <label htmlFor="latency-test-mode">测速方式</label>
          <select
            id="latency-test-mode"
            className="input"
            value={latencyTestMode}
            onChange={(e) => setLatencyTestMode(e.target.value as LatencyTestMode)}
          >
            <option value="tcp">TCP 端口握手（默认）</option>
            <option value="automatic">自动：按传输层选择（TCP 握手 / ICMP 近似）</option>
            <option value="icmp">仅 ICMP（近似可达性）</option>
          </select>
          <div className="hint">
            TCP 节点用握手耗时；UDP / QUIC 节点只能发 ICMP 近似，代表服务器可达性，不是真实 UDP RTT。
            仅 TCP 模式下 UDP / QUIC 节点会显示「不适用」。
          </div>
        </div>
        <div className="local-note">
          <i aria-hidden="true" />
          自动刷新同样由本机服务发起，不会经过第三方转换服务。
        </div>

        <div className="settings-divider" />
        <div className="settings-data-head">
          <div>
            <strong>局域网与访问密钥</strong>
            <small>控制手机 / 其他设备能否访问塔台，以及管理 API 是否需要密钥。</small>
          </div>
          {serverAccessBusy && <span className="hint">保存中…</span>}
        </div>
        {serverAccessError && (
          <div className="form-error" role="alert">
            <span>{serverAccessError}</span>
          </div>
        )}
        {serverAccess ? (
          <>
            <label className="setting-toggle">
              <input
                type="checkbox"
                checked={serverAccess.lanSharing}
                disabled={serverAccessBusy}
                onChange={(e) => void saveLanSharing(e.target.checked)}
              />
              <span>
                <strong>允许局域网共享</strong>
                <small>关闭后，非本机设备无法打开塔台页面，也无法更新订阅或下载规则集；本机访问不受影响。</small>
              </span>
            </label>
            <div className="field">
              <label>管理 API 访问密钥</label>
              {serverAccess.requiresAuth ? (
                <div className="api-key-row">
                  <input
                    readOnly
                    className="input mono"
                    value={serverAccess.apiToken}
                    aria-label="API 访问密钥"
                    onFocus={(e) => e.currentTarget.select()}
                  />
                  <button type="button" className="btn ghost" onClick={() => void copyToClipboard(serverAccess.apiToken)}>
                    复制
                  </button>
                  <button type="button" className="btn ghost" disabled={serverAccessBusy} onClick={() => void rotateAPIToken()}>
                    重新生成
                  </button>
                  <button type="button" className="btn ghost" disabled={serverAccessBusy} onClick={() => void disableAPIToken()}>
                    关闭鉴权
                  </button>
                </div>
              ) : (
                <div className="api-key-row">
                  <button type="button" className="btn ghost" disabled={serverAccessBusy} onClick={() => void rotateAPIToken()}>
                    生成访问密钥
                  </button>
                  <span className="hint">生成后，局域网设备调用管理 API 时需要带密钥；订阅链接、一次性分享链接和托管规则集本身就是独立凭证，不受影响。</span>
                </div>
              )}
              {serverAccess.mobileURL && serverAccess.requiresAuth && (
                <div className="api-key-row" style={{ marginTop: 8 }}>
                  <input
                    readOnly
                    className="input mono"
                    value={serverAccess.mobileURL}
                    aria-label="带访问密钥的手机地址"
                    onFocus={(e) => e.currentTarget.select()}
                  />
                  <button type="button" className="btn ghost" onClick={() => void copyMobileAccess()}>
                    复制手机地址
                  </button>
                </div>
              )}
              <div className="hint">
                密钥保存在服务端 <span className="mono">settings.json</span>，不会进入浏览器备份。
                轮换密钥后，局域网里的塔台页面需要用新密钥重新打开；已发布订阅和托管规则集链接不受影响。
              </div>
            </div>
          </>
        ) : (
          !serverAccessError && <div className="hint">正在读取服务端设置…</div>
        )}
        {serverAccessNotice && <div className="inline-notice" role="status">{serverAccessNotice}</div>}

        <div className="settings-divider" />
        <div className="settings-data-head">
          <div>
            <strong>数据备份</strong>
            <small>导出或恢复订阅、自有节点、自定义规则方案、规则集和导出设置。</small>
          </div>
          <div className="row" style={{ gap: 6 }}>
            <button type="button" className="btn ghost" disabled={backupBusy} onClick={exportBackup}>
              导出备份
            </button>
            <button type="button" className="btn ghost" disabled={backupBusy || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={() => backupRef.current?.click()}>
              {backupBusy ? '读取中…' : '恢复备份'}
            </button>
          </div>
        </div>
        <input
          ref={backupRef}
          type="file"
          accept=".json,application/json"
          style={{ display: 'none' }}
          onChange={(e) => {
            const file = e.target.files?.[0]
            e.target.value = ''
            void readBackup(file)
          }}
        />
        <div className="hint">
          备份文件包含订阅地址、节点凭据和规则，请妥善保管；不包含 Tailscale Auth Key、测速结果和已发布的订阅 token。
          恢复后请回导出页重新同步已发布的订阅链接，旧链接仍会返回恢复前的内容。
        </div>
        <div className="settings-data-head backup-history-head">
          <div>
            <strong>版本历史</strong>
            <small>本机保留最近 {MAX_BACKUP_HISTORY} 份快照；覆盖恢复前会自动保存当前数据。</small>
          </div>
          <button type="button" className="btn ghost" onClick={saveHistoryVersion}>保存当前版本</button>
        </div>
        {history.length > 0 ? (
          <ul className="backup-history-list">
            {history.map((item) => (
              <li key={item.id}>
                <div className="backup-history-main">
                  <strong>{item.label}</strong>
                  <span className="hint">
                    {new Date(item.createdAt).toLocaleString('zh-CN')} · {item.counts.sources} 个订阅 · {item.counts.nodes} 个节点 · {Math.max(1, Math.round(item.bytes / 1024))} KB
                  </span>
                </div>
                <div className="row" style={{ gap: 6 }}>
                  <button
                    type="button"
                    className="btn ghost"
                    {...writeGuard(readOnly)}
                    onClick={() => {
                      const entry = readBackupHistory().find((value) => value.id === item.id)
                      if (entry) setPendingBackup(entry.file)
                    }}
                  >恢复</button>
                  <button
                    type="button"
                    className="icon-btn"
                    title="下载这份快照"
                    aria-label={`下载版本 ${item.label}`}
                    onClick={() => {
                      const entry = readBackupHistory().find((value) => value.id === item.id)
                      if (entry) downloadBackup(entry.file)
                    }}
                  >↓</button>
                  <button
                    type="button"
                    className="icon-btn"
                    title="删除这份快照"
                    aria-label={`删除版本 ${item.label}`}
                    onClick={() => deleteHistoryVersion(item.id)}
                  >×</button>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div className="hint">还没有本机版本。导出前或恢复前可以先保存一份当前数据。</div>
        )}
        {backupError && <div className="form-error" role="alert"><span>{backupError}</span></div>}
        {backupNotice && <div className="inline-notice" role="status">{backupNotice}</div>}
        <WorkspaceHistoryPanel open={open} />
        <div className="settings-divider" />
        <div className="settings-data-head">
          <div>
            <strong>数据体检</strong>
            <small>
              列出恢复或加载时被拒绝的条目，以及指向不存在快照的悬空指针。塔台宁可拒绝也不静默丢弃；
              确认已经看过明细后，可以清除损坏的固化快照记录，并收起本次会话的丢弃记录。
            </small>
          </div>
          <button
            type="button"
            className="btn ghost"
            {...writeGuard(readOnly)}
            disabled={snapshotIssueTotal === 0 && backupRejections.length === 0}
            title={snapshotIssueTotal === 0 && backupRejections.length === 0 ? '没有可清理的损坏记录' : undefined}
            onClick={clearDamaged}
          >清除损坏记录</button>
        </div>
        <div className="persistence-health">
          {workspaceIssues.length > 0 && (
            <div className="persistence-group">
              <strong>服务端工作区字段问题（本次加载）</strong>
              <ul>
                {workspaceIssues.map((item, index) => (
                  <li key={`${item.key}-${item.label}-${index}`}>
                    <span className="backup-rejection-kind">
                      {item.severity === 'dropped' ? '已跳过' : item.severity === 'fallback' ? '已回退' : '已升级'}
                      {' · '}{item.keyLabel}
                    </span>
                    <span className="backup-rejection-label">{item.label}</span>
                    <small>{item.reason}</small>
                  </li>
                ))}
              </ul>
              <small className="hint">
                整块损坏的字段会保留本机原值；被丢弃的条目可尝试在「工作区历史」恢复上一版，
                服务端整体无法解析时会保留 .broken-* 原始文件。
              </small>
            </div>
          )}
          {backupRejections.length > 0 && (
            <div className="persistence-group">
              <strong>恢复 / 加载时被丢弃的条目（本次会话）</strong>
              <ul>
                {backupRejections.map((item, index) => (
                  <li key={`${item.kind}-${index}`}>
                    <span className="backup-rejection-kind">
                      {REJECTION_KIND_TITLES[item.kind]}{item.index ? ` #${item.index}` : ''}
                    </span>
                    <span className="backup-rejection-label">{item.label}</span>
                    <small>{item.reason}</small>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {snapshotIssueTotal > 0 && (
            <div className="persistence-group">
              <strong>固化快照：{snapshotHealth.dangling.length} 个悬空指针 / {snapshotHealth.corrupted.length} 个损坏快照</strong>
              <ul>
                {snapshotHealth.dangling.map((item) => (
                  <li key={`dangling-${item.schemeID}`}>
                    <span className="backup-rejection-kind">快照指针</span>
                    <span className="backup-rejection-label">{item.schemeID}</span>
                    <small>指针 #{item.snapshotId} 指向的快照不存在，加载时会回落原厂 / 上一版</small>
                  </li>
                ))}
                {snapshotHealth.corrupted.map((item) => (
                  <li key={`corrupted-${item.schemeID}-${item.snapshotId}`}>
                    <span className="backup-rejection-kind">固化快照</span>
                    <span className="backup-rejection-label">{item.schemeID} #{item.snapshotId}</span>
                    <small>{item.reason}</small>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {backupRejections.length === 0 && snapshotIssueTotal === 0 && workspaceIssues.length === 0 && (
            <div className="hint">未发现被丢弃的数据、服务端工作区字段问题或损坏的快照记录。</div>
          )}
        </div>
        <div className="settings-divider" />
        <div className="settings-data-head">
          <div>
            <strong className="danger-text">重置所有配置</strong>
            <small>删除本机的订阅、节点、方案、规则集、导出设置、版本历史和 Tailscale Auth Key，然后重新加载页面。</small>
          </div>
          <button type="button" className="btn danger" {...writeGuard(readOnly)} onClick={() => setResetConfirm(true)}>重置所有配置</button>
        </div>
        {resetConfirm && (
          <div className="restore-confirm" role="alert">
            <div>
              <strong>确认清空本机数据？</strong>
              <small>此操作不可撤销。服务器上已发布的订阅 token 不会被删除；如需让旧链接失效，请在导出页重新发布或清理服务器数据。</small>
            </div>
            <div className="row" style={{ gap: 8 }}>
              <button
                type="button"
                className="btn danger"
                {...writeGuard(readOnly)}
                onClick={() => {
                  clearTowerStorage()
                  window.location.reload()
                }}
              >确认重置</button>
              <button type="button" className="btn ghost" onClick={() => setResetConfirm(false)}>取消</button>
            </div>
          </div>
        )}
        {pendingBackup && pendingCounts && (
          <div className="restore-confirm" role="alert">
            <div>
              <strong>确认覆盖当前数据？</strong>
              <small>
                备份导出时间：{pendingBackup.exportedAt
                  ? new Date(pendingBackup.exportedAt).toLocaleString('zh-CN')
                  : '未记录'}。
                将恢复 {pendingCounts.sources} 个订阅、{pendingCounts.nodes} 个节点（含 {pendingCounts.manualNodes} 个自有节点）、
                {pendingCounts.schemes} 个自定义方案和 {pendingCounts.ruleSets} 个规则集。当前数据会被覆盖，且不可撤销。
              </small>
            </div>
            {pendingBackup.rejected?.length ? (
              <div className="backup-rejections">
                <strong>以下 {pendingBackup.rejected.length} 条记录无法识别，恢复时会被丢弃</strong>
                <ul>
                  {pendingBackup.rejected.map((item, index) => (
                    <li key={`${item.kind}-${index}`}>
                      <span className="backup-rejection-kind">
                        {REJECTION_KIND_TITLES[item.kind]}{item.index ? ` #${item.index}` : ''}
                      </span>
                      <span className="backup-rejection-label">{item.label}</span>
                      <small>{item.reason}</small>
                    </li>
                  ))}
                </ul>
                <small>建议先取消，修好备份文件后重新导入；直接恢复只会丢掉上面列出的条目，其余数据不受影响。</small>
              </div>
            ) : null}
            <div className="row" style={{ gap: 8 }}>
              <button type="button" className="btn danger" {...writeGuard(readOnly)} onClick={applyBackup}>覆盖恢复</button>
              <button type="button" className="btn ghost" onClick={() => setPendingBackup(null)}>取消</button>
            </div>
          </div>
        )}
      </div>
      <div className="actions">
        <button className="btn primary" onClick={onClose}>完成</button>
      </div>
    </dialog>
  )
}
