// 当前方案卡片：切换方案、来源与固化历史、上游更新与维护操作。
import type { BuiltinSchemeOverrideRef, BuiltinSchemeSnapshot, RuleScheme } from '../../models/types'
import type { SchemeMeta } from '../../rules/scheme'
import type { BuiltinSchemeFreezePlan, SnapshotResolution } from '../../rules/schemeSnapshots'
import type { UpstreamStatusPayload } from '../../upstreamStatus'
import type { WorkspaceStatus } from '../../workspaceSync'
import { DNS_MODE_TITLES } from '../../models/networkSettings'
import { RULE_SCHEME_FORMAT_TITLES } from '../../rules/importers'
import { stripSchemeCustomSuffix } from '../../rules/schemeCopy'
import { schemeDisplayName } from '../../util/exportSelection'
import { formatDate } from '../../util/formatDate'
import { READONLY_NOTE, writeGuard } from '../../util/readOnlyUi'
import { FreezePreviewDialog } from '../FreezePreviewDialog'
import { SchemeDriftNotice } from '../SchemeDriftNotice'

/** 上游检查时间只显示到分钟；无记录时返回空串。 */
export function formatUpstreamTime(value: number | null): string {
  if (!value) return ''
  return new Date(value).toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function SchemeCard({
  scheme,
  selectedMeta,
  customScheme,
  builtinForCustom,
  allMetas,
  selectedSchemeID,
  customSchemes,
  readOnly,
  refreshingScheme,
  schemeRules,
  remoteRefTotal,
  enabledNodeCount,
  selectedBuiltinOverride,
  selectedSnapshotHistory,
  selectedBuiltinResolution,
  snapshotFallbackNotice,
  workspaceMode,
  serverUpstream,
  serverUpstreamError,
  upstreamChecking,
  updatingBuiltinScheme,
  builtinSchemeOverrides,
  schemeSnapshots,
  checkBuiltinSchemeUpdatesOnOpen,
  setCheckBuiltinSchemeUpdatesOnOpen,
  builtinSchemeUpdateNotices,
  setBuiltinSchemeUpdateNotice,
  schemeError,
  importingScheme,
  pendingFreeze,
  setPendingFreeze,
  setScheme,
  setRestoreInitialConfirm,
  setTextEditorScheme,
  setImportingScheme,
  setPendingSchemeDelete,
  beginEditScheme,
  autoFillGroupEmoji,
  refreshImportedScheme,
  beginEditNetwork,
  requestSnapshotRollback,
  checkUpstreamNow,
  freezeBuiltinScheme,
  copyBuiltinSchemeFromUpstream,
  restoreBuiltinSnapshot,
  confirmFreeze,
}: {
  scheme: RuleScheme | undefined
  selectedMeta: SchemeMeta | undefined
  customScheme: RuleScheme | undefined
  builtinForCustom: SchemeMeta | undefined
  allMetas: SchemeMeta[]
  selectedSchemeID: string
  customSchemes: RuleScheme[]
  readOnly: boolean
  refreshingScheme: boolean
  schemeRules: unknown[]
  remoteRefTotal: number
  enabledNodeCount: number
  selectedBuiltinOverride: BuiltinSchemeSnapshot | undefined
  selectedSnapshotHistory: BuiltinSchemeSnapshot[]
  selectedBuiltinResolution: SnapshotResolution | undefined
  snapshotFallbackNotice: string | undefined
  workspaceMode: WorkspaceStatus['mode']
  serverUpstream: UpstreamStatusPayload | null
  serverUpstreamError: string
  upstreamChecking: boolean
  updatingBuiltinScheme: boolean
  builtinSchemeOverrides: Record<string, BuiltinSchemeOverrideRef>
  schemeSnapshots: Record<string, BuiltinSchemeSnapshot>
  checkBuiltinSchemeUpdatesOnOpen: boolean
  setCheckBuiltinSchemeUpdatesOnOpen: (value: boolean) => void
  builtinSchemeUpdateNotices: Record<string, string | undefined>
  setBuiltinSchemeUpdateNotice: (schemeID: string, notice?: string) => void
  schemeError: string | null
  importingScheme: boolean
  pendingFreeze: { meta: SchemeMeta; plan: BuiltinSchemeFreezePlan } | null
  setPendingFreeze: (value: null) => void
  setScheme: (value: string) => void
  setRestoreInitialConfirm: (value: boolean) => void
  setTextEditorScheme: (value: RuleScheme) => void
  setImportingScheme: (value: boolean) => void
  setPendingSchemeDelete: (value: RuleScheme) => void
  beginEditScheme: () => void
  autoFillGroupEmoji: () => void
  refreshImportedScheme: () => void
  beginEditNetwork: () => void
  requestSnapshotRollback: (meta: SchemeMeta, snapshotID: number) => void
  checkUpstreamNow: () => void
  freezeBuiltinScheme: (meta: SchemeMeta) => void
  copyBuiltinSchemeFromUpstream: (meta: SchemeMeta) => void
  restoreBuiltinSnapshot: (meta: SchemeMeta) => void
  confirmFreeze: () => void
}) {
  return (
      <div className="card scheme-card">
        <div className="card-head scheme-card-head">
          <div className="scheme-title-wrap">
            <div className="scheme-kicker">当前方案</div>
            <h3>{selectedMeta ? schemeDisplayName(selectedMeta.name, 'custom' in selectedMeta) : '规则方案'}</h3>
          </div>
          <div className="row wrap scheme-actions">
            {scheme && (
              <button className="btn ghost" onClick={beginEditScheme}>
                {customScheme ? '编辑方案' : '复制并编辑'}
              </button>
            )}
            {builtinForCustom && (
              <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setRestoreInitialConfirm(true)}>恢复初始规则</button>
            )}
            {scheme && (
              <button className="btn ghost" {...writeGuard(readOnly)} onClick={autoFillGroupEmoji}>补全 Emoji</button>
            )}
            {customScheme?.rawConfigurationText && (
              <button className="btn ghost" onClick={() => setTextEditorScheme(customScheme)}>编辑全文</button>
            )}
            {customScheme?.sourceURL && (
              <button className="btn ghost" disabled={refreshingScheme || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={() => void refreshImportedScheme()}>
                {refreshingScheme ? '刷新中…' : '刷新方案'}
              </button>
            )}
            {scheme && (
              <button className="btn ghost" onClick={beginEditNetwork}>DNS 与网络</button>
            )}
            <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setImportingScheme(true)}>+ 导入方案</button>
          </div>
        </div>
        {pendingFreeze && (
          <FreezePreviewDialog
            open
            schemeName={pendingFreeze.meta.name}
            plan={pendingFreeze.plan}
            confirmDisabled={readOnly}
            onConfirm={confirmFreeze}
            onCancel={() => setPendingFreeze(null)}
          />
        )}
        <div className="scheme-select-row">
          <span className="scheme-select-label">切换方案</span>
          <select className="input" value={selectedSchemeID} disabled={readOnly} title={readOnly ? READONLY_NOTE : undefined} onChange={(e) => setScheme(e.target.value)}>
            {allMetas.map((m) => <option key={m.id} value={m.id}>{schemeDisplayName(m.name, 'custom' in m)}</option>)}
          </select>
        </div>
        <div className="scheme-facts">
          <span><b>{scheme?.groups.length ?? 0}</b> 策略组</span>
          <span><b>{schemeRules.length}</b> 规则</span>
          {remoteRefTotal > 0 && (
            <span title="只保存 provider 地址，不保存正文；导出时写成 RULE-SET，由客户端自行下载">
              <b>{remoteRefTotal}</b> 远程引用
            </span>
          )}
          <span><b>{enabledNodeCount}</b> 节点</span>
        </div>
        <p className="scheme-desc">{selectedMeta?.description}</p>
        <details className="scheme-details">
          <summary>来源与说明</summary>
          <div className="scheme-source">
            {selectedMeta?.sourceKind === 'url'
              ? `${selectedMeta.sourceFormat ? `${RULE_SCHEME_FORMAT_TITLES[selectedMeta.sourceFormat]} · ` : ''}来源：URL 导入${selectedMeta.updatedAt ? ` · 更新于 ${formatDate(selectedMeta.updatedAt)}` : ''}`
              : selectedMeta?.sourceKind === 'file'
                ? `${selectedMeta.sourceFormat ? `${RULE_SCHEME_FORMAT_TITLES[selectedMeta.sourceFormat]} · ` : ''}来源：文件导入${selectedMeta.updatedAt ? ` · 更新于 ${formatDate(selectedMeta.updatedAt)}` : ''}`
                : selectedMeta?.sourceKind === 'paste'
                  ? `${selectedMeta.sourceFormat ? `${RULE_SCHEME_FORMAT_TITLES[selectedMeta.sourceFormat]} · ` : ''}来源：粘贴导入${selectedMeta.updatedAt ? ` · 更新于 ${formatDate(selectedMeta.updatedAt)}` : ''}`
                  : selectedMeta?.sourceKind === 'copy'
                    ? '来源：基于内置方案复制的自定义方案'
                    : selectedMeta && 'custom' in selectedMeta
                      ? '自定义方案 · 保存在本机'
                      : selectedBuiltinOverride
                        ? `内置方案 · 已固化 · commit ${selectedBuiltinOverride.source.commitSha.slice(0, 7)} · 更新于 ${formatDate(selectedBuiltinOverride.source.fetchedAt)} · ${selectedBuiltinOverride.source.ruleCount} 条规则`
                        : '内置方案 · 原厂快照 · 离线可用'}
          </div>
          {snapshotFallbackNotice && (
            <div className="hint scheme-snapshot-warning">{snapshotFallbackNotice}</div>
          )}
          {selectedMeta && !('custom' in selectedMeta) && selectedSnapshotHistory.length > 0 && (
            <div className="scheme-snapshot-history">
              <div className="hint">固化历史（原厂 + 最近 2 版；回退后正在用的旧版会额外保留）。回退只改本机与同步工作区，不影响已导出的客户端配置。</div>
              <ul>
                {selectedSnapshotHistory.map((snapshot) => {
                  // 指针损坏时会回落到上一版，此时「当前」应标在实际生效的那一版，
                  // 否则历史列表里一行「当前」都没有，跟上方回落提示自相矛盾。
                  const isCurrent = snapshot.id === selectedBuiltinOverride?.id
                  return (
                    <li key={snapshot.id} className={isCurrent ? 'snapshot-current' : undefined}>
                      <span className="snapshot-label">
                        快照 #{snapshot.id}{isCurrent ? ' · 当前' : ''} · commit {snapshot.source.commitSha.slice(0, 7)} · {snapshot.source.ruleCount} 条规则 · {formatDate(snapshot.createdAt)}
                      </span>
                      {!isCurrent && (
                        <button
                          type="button"
                          className="btn ghost"
                          disabled={readOnly || updatingBuiltinScheme}
                          title={readOnly ? READONLY_NOTE : undefined}
                          onClick={() => requestSnapshotRollback(selectedMeta, snapshot.id)}
                        >回退至此版</button>
                      )}
                    </li>
                  )
                })}
                <li>
                  <span className="snapshot-label">原厂快照 · 离线可用{selectedBuiltinResolution?.fallback === 'factory' ? ' · 当前' : ''}</span>
                </li>
              </ul>
            </div>
          )}
          <div className="scheme-source scheme-network-summary">
            DNS：{DNS_MODE_TITLES[scheme?.networkSettings?.dnsProtectionMode ?? 'standard']}
            {scheme?.networkSettings?.proxyTestURLString
              ? ` · 测试 ${scheme.networkSettings.proxyTestURLString}`
              : ' · 使用默认测试地址'}
          </div>
          {selectedMeta && !customScheme && (
            <div className="hint">编辑、排序或添加规则会先生成一份自定义副本。</div>
          )}
        </details>
        {workspaceMode === 'server' && (serverUpstream || serverUpstreamError) && (
          <div className="upstream-status">
            <div className="upstream-status-head">
              <span className="upstream-status-title">上游更新检查</span>
              <span className="hint">
                {serverUpstream
                  ? !serverUpstream.enabled
                    ? '服务端定时检查已关闭（TOWER_UPSTREAM_CHECK=off）'
                    : serverUpstream.checking || upstreamChecking
                      ? '正在检查上游…'
                      : serverUpstream.checkedAt
                        ? `上次检查 ${formatUpstreamTime(serverUpstream.checkedAt)}`
                        : '尚未检查（服务端会在启动几分钟后自动检查）'
                  : '读取失败'}
              </span>
              {serverUpstream?.enabled && (
                <button
                  type="button"
                  className="btn ghost"
                  disabled={upstreamChecking || serverUpstream.checking}
                  onClick={() => void checkUpstreamNow()}
                >
                  {upstreamChecking || serverUpstream.checking ? '正在检查…' : '立即检查一次'}
                </button>
              )}
            </div>
            {serverUpstream?.enabled && (
              <div className="upstream-status-lines">
                {serverUpstream.schemes.map((item) => {
                  if (item.status === 'update') {
                    const meta = allMetas.find((m) => m.id === item.id && !('custom' in m))
                    return (
                      <div key={item.id} className="upstream-status-block">
                        <div className="upstream-status-line update">
                          <span>
                            「{item.name}」上游有新版本（commit {item.commitShort}
                            {item.behindBy ? `，落后 ${item.behindBy} 个提交` : ''}）
                          </span>
                        </div>
                        {meta && (
                          <SchemeDriftNotice
                            meta={meta}
                            version={item.commit || item.commitShort || ''}
                            overrides={builtinSchemeOverrides}
                            snapshots={schemeSnapshots}
                            readOnly={readOnly}
                            busy={updatingBuiltinScheme}
                            onAbsorb={() => void freezeBuiltinScheme(meta)}
                          />
                        )}
                      </div>
                    )
                  }
                  if (item.status === 'error') {
                    return (
                      <div key={item.id} className="upstream-status-line error">
                        查不到「{item.name}」的上游状态：{item.error || '请求失败'}（这不等于「没有更新」）
                      </div>
                    )
                  }
                  if (item.status === 'current') {
                    return (
                      <div key={item.id} className="upstream-status-line">
                        「{item.name}」已是最新（commit {item.commitShort}）
                      </div>
                    )
                  }
                  return (
                    <div key={item.id} className="upstream-status-line muted">
                      「{item.name}」尚未检查
                    </div>
                  )
                })}
              </div>
            )}
            {serverUpstreamError && (
              <div className="error" style={{ marginTop: 4 }}>
                读取服务端上游状态失败：{serverUpstreamError}
              </div>
            )}
            {serverUpstream?.lastError && !serverUpstreamError && (
              <div className="hint" style={{ marginTop: 4 }}>{serverUpstream.lastError}</div>
            )}
          </div>
        )}
        {selectedMeta && !('custom' in selectedMeta) && !selectedMeta.programmatic && (
          <div className="row wrap" style={{ gap: 8, marginTop: 8 }}>
            <button
              type="button"
              className="btn"
              {...writeGuard(readOnly)}
              disabled={updatingBuiltinScheme}
              onClick={() => void freezeBuiltinScheme(selectedMeta)}
            >
              {updatingBuiltinScheme ? '正在更新…' : selectedBuiltinOverride ? '重新更新并固化' : '更新并固化'}
            </button>
            <button
              type="button"
              className="btn ghost"
              {...writeGuard(readOnly)}
              disabled={updatingBuiltinScheme}
              onClick={() => void copyBuiltinSchemeFromUpstream(selectedMeta)}
            >
              生成自定义副本
            </button>
            {selectedBuiltinOverride && (
              <button
                type="button"
                className="btn ghost"
                {...writeGuard(readOnly)}
                disabled={updatingBuiltinScheme}
                onClick={() => void restoreBuiltinSnapshot(selectedMeta)}
              >
                恢复原厂快照
              </button>
            )}
          </div>
        )}
        {selectedMeta && !('custom' in selectedMeta) && !selectedMeta.programmatic && (
          <div style={{ marginTop: 8 }}>
            <div className="hint">
              「更新并固化」拉取 ACL4SSR 最新 INI 与全部列表，直接替换这条内置方案（多设备同步）；任一列表失败整次放弃，原厂快照始终保留可恢复。
              「生成自定义副本」另存一份可编辑方案，不改内置方案。
            </div>
            {workspaceMode === 'server' ? (
              <div className="hint" style={{ marginTop: 4 }}>
                服务器版由服务端每天自动检查上游，结果显示在上方；为避免重复提示，本地打开时的检查在服务器模式已关闭。
              </div>
            ) : (
              <div className="hint" style={{ marginTop: 4 }}>
                <label className="row" style={{ gap: 6 }}>
                  <input
                    type="checkbox"
                    checked={checkBuiltinSchemeUpdatesOnOpen}
                    onChange={(e) => setCheckBuiltinSchemeUpdatesOnOpen(e.target.checked)}
                  />
                  打开塔台时检查内置方案是否有上游更新（只提示，不自动覆盖）
                </label>
              </div>
            )}
            {workspaceMode !== 'server' && builtinSchemeUpdateNotices[selectedMeta.id] && (
              <div className="row wrap" style={{ gap: 8, marginTop: 6 }}>
                <span className="scheme-source">{builtinSchemeUpdateNotices[selectedMeta.id]}</span>
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() => setBuiltinSchemeUpdateNotice(selectedMeta.id, undefined)}
                >
                  知道了
                </button>
              </div>
            )}
          </div>
        )}
        {customSchemes.length > 0 && (
          <div className="row wrap custom-scheme-chips">
            {customSchemes.map((s) => (
              <button
                key={s.id}
                type="button"
                className="btn ghost"
                {...writeGuard(readOnly)}
                onClick={() => setPendingSchemeDelete(s)}
              >× {stripSchemeCustomSuffix(s.name)}</button>
            ))}
          </div>
        )}
        {schemeError && !importingScheme && <div className="error">{schemeError}</div>}
        {(scheme?.policyWarnings?.length ?? 0) > 0 && !importingScheme && (
          <details className="scheme-warnings">
            <summary>方案校验提示 · {scheme!.policyWarnings!.length}</summary>
            <ul>
              {scheme!.policyWarnings!.map((warning, index) => (
                <li key={`${warning}-${index}`}>{warning}</li>
              ))}
            </ul>
          </details>
        )}
      </div>

  )
}
