import { useEffect, useMemo, useRef, useState, lazy, Suspense, type ReactNode, type SyntheticEvent } from 'react'
import { renderSVG } from 'uqr'
import { CLIENTS, PROXY_KIND_TITLES, clientSupportsImport, subFormatFor, subscriptionUsageSummary, type ClientInfo, type ClientTarget, type ExportContentMode, type LatencyTestMode, type LocalRuleSet, type NodeNameFilterSettings, type PolicyGroup, type ProxyKind, type ProxyNode, type RemoteSubscriptionEntry, type RoutingRule, type RuleScheme, type RuleSetFormat, type RuleSetRefreshDiff, type SchemeRuleSet, type SubFormat, type SubscriptionSource, type TailnetConnection, type TailnetExport } from './models/types'
import { allRegions, filterNodesByRegionCodes, regionForName, regionForNode } from './models/region'
import { defaultTailnetConnection, normalizeTailnetAuthKey, normalizeTailnetControlURL, normalizeTailnetDeviceName, normalizeTailnetMagicDNSSuffix, normalizeTailnetSubnets, tailnetPolicyName, TailnetValidationError } from './models/tailnet'
import {
  DNS_MODE_SUMMARIES,
  DNS_MODE_TITLES,
  NetworkSettingsError,
  networkSettingsDraft,
  validateNetworkSettingsDraft,
  type NetworkSettingsDraft,
} from './models/networkSettings'
import { enabledNodes, isSourceEnabled, nodeExactKey, persistedSnapshot, useStore } from './store'
import { backupCounts, backupFileName, createBackup, inspectSnapshotHealth, MAX_BACKUP_BYTES, parseBackup, type BackupFile, type BackupRejection } from './backup'
import {
  backupHistoryItems,
  MAX_BACKUP_HISTORY,
  readBackupHistory,
  removeBackupHistory,
  saveBackupHistory,
  BackupHistoryError,
  type BackupHistoryItem,
} from './backupHistory'
import { BUILTIN_SCHEMES, allSchemeMetas, loadScheme, parseRuleList, type SchemeMeta } from './rules/scheme'
import { planBuiltinSchemeFreeze, planSnapshotRollback, resolveBuiltinSchemeSnapshot, snapshotsForScheme, type BuiltinSchemeFreezePlan, type SnapshotRollbackPlan } from './rules/schemeSnapshots'
import { fetchUpstreamScheme, type UpstreamSchemeResult } from './rules/upstreamScheme'
import { runBuiltinUpdateCheckOnOpen } from './rules/upstreamOnOpen'
import { ruleSetRefreshFailure, ruleSetRefreshSuccess, sumRuleSetDiffs } from './rules/ruleSetRefresh'
import { detectRuleSchemeFormat, parseRuleSchemeText, RULE_SCHEME_FORMAT_TITLES } from './rules/importers'
import { describeRuleSetParse, fetchRuleSet, parseRuleSetText, RULE_SET_FORMAT_TITLES, type RuleSetRule } from './rules/ruleSets'
import { matchingGroupNames, matchingOrderAfterDragging } from './rules/matchingOrder'
import { findRuleOrderConflicts, type RuleOrderConflict } from './rules/orderConflicts'
import { policyIssueText, validateSchemePolicy } from './rules/policyValidation'
import { orderedSchemeBaseRules, orderedSchemeRules, isUnmovableRule, renameRuleOrderKeys, ruleOrderKeys } from './rules/ruleOrder'
import { analyzeRuleImpact, ruleImpactText } from './rules/ruleImpact'
import { autoGroupReferenceWarning, buildNodeFilterGroup, findGroupCyclePath, nextGroupName, previewNodeMatches, removePolicyGroup, validateGroupCandidates, validateNodeGroupDraft, type NodeGroupDraft } from './rules/groupEditing'
import { ONLINE_RULE_CATALOG } from './rules/ruleCatalog'
import type { ManualNodeImportResult } from './manualNodes'
import { MAX_BATCH_SUBSCRIPTIONS, splitSubscriptionURLs, subscriptionLabel } from './batchSubscriptions'
import { generateConfig, generateSubscriptionFormats } from './generator'
import { nodeShareText } from './generator/shareLink'
import { nodeTransportCapability } from './generator/nodeCapabilities'
import { analyzeRuleCompatibility } from './generator/compatibility'
import { formatSupportsProxyCollections, prepareSchemeForExport } from './generator/groups'
import { autoFillGroupEmojis } from './generator/groupIcons'
import { maskTailnetAuthKeys, tailnetSupports } from './generator/tailnet'
import { copyToClipboard, newID } from './util/browser'
import { browserStorage, clearTowerStorage, createSafeStorage, isStorageFull, onStorageFullChange } from './util/localStore'
import { placeDetailsPanel, placeOpenDetailsPanels } from './util/menuPlacement'
import { apiFetch, clearAPIKey, getAPIKey, setAPIKey } from './util/apiAuth'
import { MAX_REMOTE_RULE_SET_URLS, normalizeRemoteTextURL, remoteRuleSetNameFromURL, splitRemoteTextURLs } from './util/remoteURL'
import { GITHUB_REPO_URL } from './config'
import { RouteIllustration } from './components/RouteIllustration'
import { GroupIcon, groupDisplayName } from './components/GroupIcon'
import { TailnetIllustration } from './components/TailnetIllustration'
import { ManualNodeEditorDialog } from './components/ManualNodeEditorDialog'
import { SourceUsage, UsageHealthBadge, shouldShowSourceUsage } from './components/SourceUsage'
import { UserAgentField } from './components/UserAgentField'
import { RulesToolsCard } from './components/RulesToolsCard'
import { SchemeDriftNotice } from './components/SchemeDriftNotice'
import { DiagnosisPanel, type FixOutcome } from './components/DiagnosisPanel'
import { FlowRail } from './components/FlowRail'
import { AdvancedSection } from './components/AdvancedSection'
import { WorkspaceStatusBanner } from './components/WorkspaceStatusBanner'
import { WorkspaceHistoryPanel } from './components/WorkspaceHistoryPanel'
import { flushWorkspaceNow, useWorkspaceStatus } from './workspaceSync'
import { fetchUpstreamStatus, triggerUpstreamStatusCheck, type UpstreamStatusPayload } from './upstreamStatus'
import { READONLY_NOTE, writeGuard } from './util/readOnlyUi'
import { buildFlow, explainNodePool, type FlowStepKey } from './flow/flow'
import { markExported, readExportedAt } from './flow/prefs'
import { applyFixAction, type FixAction } from './rules/diagnosis'
import { applyDuplicateCleanup, restoreRemovedRules, type DuplicateCleanupPlan, type RemovedRuleRecord } from './rules/duplicateCleanup'
import { clearRuleSetHistory, digestRules, recordRuleSetSnapshot } from './rules/ruleSetHistory'
import { lintScheme, lintSummary, type SchemeLintIssue } from './rules/schemeLint'
import { createEditableSchemeCopy, stripSchemeCustomSuffix, undoEditableSchemeCopy } from './rules/schemeCopy'
import { isReadOnlyRuleSet } from './rules/ruleSetExclusions'

const SELF_CONFIGURATION_NAME = 'Self-Configuration'
const SELF_CONFIGURATION_URL = 'https://raw.githubusercontent.com/ClashConnectRules/Self-Configuration/main/Clash.yaml'

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

/** 发布 token / 地址是设备偏好；隐私模式或配额满时不能把导出页一起拖崩。 */
const localPrefs = createSafeStorage(browserStorage)

// 地图与扫码只在对应面板出现时才加载，避免把 d3/map 和 jsQR 塞进首屏。
const WorldMapSVG = lazy(() => import('./worldmap/WorldMapSVG').then((mod) => ({ default: mod.WorldMapSVG })))
const QrScanner = lazy(() => import('./components/QrScanner').then((mod) => ({ default: mod.QrScanner })))

/** 顶部工作区。跨页面跳转（上手流程 / 导出补救）需要它。 */
type TabKey = 'sub' | 'rules' | 'check' | 'tailnet' | 'export'

/** details 菜单打开/关闭后按视口可用空间决定向上或向下展开。 */
function updateDetailsPlacement(event: SyntheticEvent<HTMLDetailsElement>): void {
  const details = event.currentTarget
  requestAnimationFrame(() => placeDetailsPanel(details))
}

function formatDate(ts?: number): string {
  if (!ts) return ''
  return new Date(ts).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

/** 高级请求设置：只影响这一条订阅的抓取请求。 */
function requestOptionsFrom(userAgent: string, doh: string) {
  const ua = userAgent.replace(/[\r\n]/g, '').trim()
  const rawDoH = doh.trim()
  if (rawDoH) {
    let endpoint: URL
    try {
      endpoint = new URL(rawDoH)
    } catch {
      throw new Error('DoH 地址无效，应填写 https://…/dns-query 形式的地址')
    }
    if (endpoint.protocol !== 'https:' || !endpoint.hostname) {
      throw new Error('DoH 地址必须使用 https://')
    }
  }
  return {
    userAgent: ua || undefined,
    dnsOverHTTPSURL: rawDoH || undefined,
  }
}

function useScheme(): RuleScheme | undefined {
  const selectedSchemeID = useStore((s) => s.selectedSchemeID)
  const customSchemes = useStore((s) => s.customSchemes)
  const builtinSchemeOverrides = useStore((s) => s.builtinSchemeOverrides)
  const schemeSnapshots = useStore((s) => s.schemeSnapshots)
  const [scheme, setScheme] = useState<RuleScheme | undefined>()
  useEffect(() => {
    const custom = customSchemes.find((c) => c.id === selectedSchemeID)
    if (custom) { setScheme(custom); return }
    // 切换方案时先清空，避免旧方案的预览继续显示。
    setScheme(undefined)
    const meta = BUILTIN_SCHEMES.find((m) => m.id === selectedSchemeID) ?? BUILTIN_SCHEMES[0]
    let cancelled = false
    // 覆盖层优先（固化后的版本），没有再读 public/rulesets 原厂快照。
    loadScheme(meta, builtinSchemeOverrides, schemeSnapshots)
      .then((s) => { if (!cancelled) setScheme(s) })
      .catch(() => { if (!cancelled) setScheme(undefined) })
    return () => { cancelled = true }
  }, [selectedSchemeID, customSchemes, builtinSchemeOverrides, schemeSnapshots])
  return scheme
}

// ---------------- 通用小组件 ----------------

/** 搜索结果高亮：命中片段用浅色底标出，其余文字不变。 */
function Highlight({ text, needle }: { text: string; needle: string }) {
  if (!needle) return <>{text}</>
  const at = text.toLowerCase().indexOf(needle.toLowerCase())
  if (at < 0) return <>{text}</>
  return (
    <>
      {text.slice(0, at)}
      <mark>{text.slice(at, at + needle.length)}</mark>
      {text.slice(at + needle.length)}
    </>
  )
}

/** 统一的确认弹窗，替代 window.confirm（可用键盘与读屏器操作）。 */
function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel = '确认',
  danger = false,
  confirmDisabled = false,
  onConfirm,
  onCancel,
}: {
  open: boolean
  title: string
  body: ReactNode
  confirmLabel?: string
  danger?: boolean
  /** 只读模式下由调用方传入，写操作的确认按钮不可点。 */
  confirmDisabled?: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    if (open) ref.current?.showModal()
    else ref.current?.close()
  }, [open])
  return (
    <dialog ref={ref} onClose={onCancel} className="confirm">
      <h3>{title}</h3>
      <p className="confirm-body">{body}</p>
      <div className="actions">
        <button
          className={`btn ${danger ? 'danger' : 'primary'}`}
          disabled={confirmDisabled}
          title={confirmDisabled ? READONLY_NOTE : undefined}
          onClick={onConfirm}
        >{confirmLabel}</button>
        <button className="btn ghost" autoFocus onClick={onCancel}>取消</button>
      </div>
    </dialog>
  )
}

/** 固化前的变更预览：先看 +N / -M / ~K 与受影响策略组，确认后才写快照。 */
function FreezePreviewDialog({
  open,
  schemeName,
  plan,
  confirmDisabled,
  onConfirm,
  onCancel,
}: {
  open: boolean
  schemeName: string
  plan: BuiltinSchemeFreezePlan
  confirmDisabled: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    if (open) ref.current?.showModal()
    else ref.current?.close()
  }, [open])
  const changed = plan.added + plan.removed + plan.modified
  return (
    <dialog ref={ref} onClose={onCancel} className="freeze-dialog">
      <h3>更新并固化「{schemeName}」前的变更预览</h3>
      <div className="freeze-stats">
        <span className="pill positive">+{plan.added}</span>
        <span className="pill negative">−{plan.removed}</span>
        <span className="pill">~{plan.modified}</span>
        <span className="hint">未变 {plan.unchanged} · 规则数 {plan.oldCount} → {plan.newCount}</span>
      </div>
      <p className="confirm-body">
        {changed
          ? `上游内容与当前快照有 ${changed} 条差异；确认后才会写入新快照。`
          : '上游内容与当前快照逐条一致，确认后仍会写入一条新快照（指针切换到这一版）。'}
      </p>
      <div className="freeze-section">
        <h4>受影响的策略组（{plan.groups.length}）</h4>
        {plan.groups.length ? (
          <ul className="freeze-groups">
            {plan.groups.map((group) => (
              <li key={group.group}>
                <span className="pill">{group.group}</span>
                <span className="hint">
                  {group.added ? `+${group.added} ` : ''}
                  {group.removed ? `−${group.removed} ` : ''}
                  {group.modified ? `~${group.modified}` : ''}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="hint">没有规则归属发生变化的策略组。</div>
        )}
      </div>
      <div className="freeze-section">
        <h4>引用了旧规则集的自定义方案（{plan.affectedSchemes.length}）</h4>
        {plan.affectedSchemes.length ? (
          <div className="hint">{plan.affectedSchemes.join('、')}。更新后请检查它们的规则集引用是否仍然可用。</div>
        ) : (
          <div className="hint">没有自定义方案引用当前快照的规则集 id / 源地址。</div>
        )}
      </div>
      <div className="hint">
        确认后才写入快照；原厂快照保留，固化仍保留最近 3 版环形，可随时回退。
        已导出的客户端配置不会自动回滚，需要重新导出或让客户端刷新订阅。
      </div>
      <div className="actions">
        <button
          type="button"
          className="btn primary"
          disabled={confirmDisabled}
          title={confirmDisabled ? READONLY_NOTE : undefined}
          onClick={onConfirm}
        >确认更新并固化</button>
        <button type="button" className="btn ghost" autoFocus onClick={onCancel}>取消</button>
      </div>
    </dialog>
  )
}

/** 订阅链接二维码：完全在本机生成，不请求第三方二维码服务。 */
function QRCodeDialog({
  open,
  url,
  title,
  hint,
  onClose,
}: {
  open: boolean
  url: string
  title: string
  hint: string
  onClose: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (open) ref.current?.showModal()
    else ref.current?.close()
  }, [open])
  useEffect(() => {
    if (!open) setCopied(false)
  }, [open])
  const svg = useMemo(() => {
    if (!open || !url) return ''
    try {
      return renderSVG(url, {
        ecc: 'M',
        border: 2,
        pixelSize: 4,
        blackColor: '#141815',
        whiteColor: '#ffffff',
      })
    } catch {
      return ''
    }
  }, [open, url])
  const copy = async () => {
    if (await copyToClipboard(url)) {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    }
  }
  return (
    <dialog ref={ref} className="qr-dialog" onClose={onClose}>
      <h3>{title} · 扫码导入</h3>
      {svg ? (
        <div className="qr-code" dangerouslySetInnerHTML={{ __html: svg }} />
      ) : (
        <div className="hint">二维码生成失败，请直接复制订阅地址。</div>
      )}
      <div className="qr-hint">{hint}</div>
      <input
        readOnly
        className="input qr-url"
        value={url}
        aria-label="二维码对应的订阅地址"
        onFocus={(e) => e.currentTarget.select()}
      />
      <div className="actions">
        <button className="btn primary" onClick={copy}>{copied ? '已复制' : '复制链接'}</button>
        <button className="btn ghost" onClick={onClose}>关闭</button>
      </div>
    </dialog>
  )
}

/**
 * 局域网访问门：服务端关闭共享或要求密钥时，先挡住页面。
 * 本机访问、无鉴权或已带有效密钥时完全不渲染。
 */
function LANAccessGate() {
  const [status, setStatus] = useState<{
    mode?: 'local' | 'server'
    lanSharing: boolean
    requiresAuth: boolean
    local: boolean
    valid: boolean
    dataWritable?: boolean
  } | null>(null)
  const [key, setKey] = useState(() => getAPIKey())
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/auth-status', { cache: 'no-store' })
      .then(async (res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        if (!cancelled) setStatus(data)
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : '无法读取访问状态')
      })
    return () => { cancelled = true }
  }, [])

  if (!status) return null
  const serverMode = status.mode === 'server'
  // 服务器模式的数据目录不可写时，所有设备都存不了工作区；这比密钥问题更根本，
  // 先挡住并给出宿主机修复命令，避免用户只看到一份空白工作区。
  if (serverMode && status.dataWritable === false) {
    return (
      <div className="lan-gate" role="dialog" aria-modal="true" aria-labelledby="lan-gate-title">
        <div className="lan-gate-card">
          <strong id="lan-gate-title">服务端数据目录不可写</strong>
          <p>
            容器内的 node 用户（UID 1000）无法写入挂载目录，工作区改动会全部失败，页面会一直是空的。
            在 VPS 上执行下面的命令后重启容器：
          </p>
          <pre className="mono" style={{ whiteSpace: 'pre-wrap' }}>
            sudo chown -R 1000:1000 /opt/tower/app/data{'\n'}docker compose restart tower-web
          </pre>
          <div className="hint">
            若挂载路径不是 /opt/tower/app/data，请换成实际路径（docker-compose 里的 volumes 那一行）。
          </div>
        </div>
      </div>
    )
  }
  // 服务器模式连本机也要密钥，因此不再按 local 放行；其它行为保持原样。
  if (!serverMode && status.local) return null
  if (status.lanSharing && (!status.requiresAuth || status.valid)) return null
  const needsKey = status.lanSharing && status.requiresAuth && !status.valid

  return (
    <div className="lan-gate" role="dialog" aria-modal="true" aria-labelledby="lan-gate-title">
      <div className="lan-gate-card">
        <strong id="lan-gate-title">{needsKey ? '需要访问密钥' : '局域网共享已关闭'}</strong>
        <p>
          {needsKey
            ? '这台设备正在通过局域网访问塔台。请输入服务端本机「订阅设置 → 局域网与访问密钥」里显示的访问密钥。'
            : '服务端已关闭局域网共享。请在运行塔台服务的电脑上打开「订阅设置 → 局域网与访问密钥」重新开启。'}
        </p>
        {needsKey && (
          <form
            onSubmit={(event) => {
              event.preventDefault()
              const trimmed = key.trim()
              if (!trimmed) { setError('请输入访问密钥'); return }
              setAPIKey(trimmed)
              window.location.reload()
            }}
          >
            <input
              className="input mono"
              value={key}
              onChange={(event) => { setKey(event.target.value); setError('') }}
              placeholder="访问密钥"
              aria-label="访问密钥"
              autoFocus
            />
            <div className="actions">
              <button className="btn primary" type="submit">保存并重新加载</button>
            </div>
          </form>
        )}
        {error && <div className="form-error" role="alert"><span>{error}</span></div>}
        <div className="hint">
          {serverMode
            ? '服务器模式下所有设备（包括本机）都需要访问密钥；密钥由 TOWER_API_TOKEN 决定。'
            : '本机打开塔台无需密钥；关闭共享或轮换密钥请在服务端本机操作。'}
        </div>
      </div>
    </div>
  )
}

/** 手动标记节点地区；自动识别会回到“节点名 > 离线 IP”的顺序。 */
function NodeCountryDialog({
  node,
  onClose,
}: {
  node: ProxyNode | null
  onClose: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const setNodeCountryOverride = useStore((s) => s.setNodeCountryOverride)
  const readOnly = useWorkspaceStatus().readOnly
  const [search, setSearch] = useState('')
  useEffect(() => {
    if (node) {
      setSearch('')
      ref.current?.showModal()
    } else {
      ref.current?.close()
    }
  }, [node])
  const regions = useMemo(() => {
    const needle = search.trim().toLowerCase()
    const all = allRegions()
    if (!needle) return all
    return all.filter((region) =>
      region.name.toLowerCase().includes(needle)
      || region.code.toLowerCase().includes(needle)
      || region.flag.includes(search.trim()),
    )
  }, [search])
  const current = node ? regionForNode(node) : undefined
  const sourceLabel = node?.countryOverride
    ? '手动标记'
    : node?.detectedCountry && !regionForName(node.name)
      ? '离线 IP 识别'
      : '节点名称识别'
  return (
    <dialog ref={ref} onClose={onClose} className="country-dialog">
      <h3>设置节点地区</h3>
      {node && (
        <div className="country-current">
          <span className="flag">{current?.flag ?? '·'}</span>
          <div>
            <strong>{node.name}</strong>
            <small>{current?.name ?? '未识别'} · {sourceLabel}</small>
          </div>
        </div>
      )}
      <div className="search-wrap country-search">
        <input
          className="input"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="搜索国家、地区或代码…"
          aria-label="搜索国家或地区"
        />
        {search && (
          <button className="search-clear" aria-label="清空地区搜索" onClick={() => setSearch('')}>×</button>
        )}
      </div>
      <div className="country-list">
        <button
          type="button"
          className={`country-option${node?.countryOverride ? '' : ' active'}`}
          {...writeGuard(readOnly)}
          onClick={() => {
            if (node) setNodeCountryOverride(node.id, undefined)
            onClose()
          }}
        >
          <span className="country-auto">自动</span>
          <span>按节点名优先，其次使用离线 IP 识别</span>
        </button>
        {regions.map((region) => (
          <button
            type="button"
            key={region.code}
            className={`country-option${node?.countryOverride === region.code ? ' active' : ''}`}
            {...writeGuard(readOnly)}
            onClick={() => {
              if (node) setNodeCountryOverride(node.id, region.code)
              onClose()
            }}
          >
            <span className="flag">{region.flag}</span>
            <span>{region.name}</span>
            <span className="country-code">{region.code}</span>
          </button>
        ))}
        {regions.length === 0 && <div className="hint">没有匹配的国家或地区。</div>}
      </div>
      <div className="actions">
        <button className="btn ghost" onClick={onClose}>取消</button>
      </div>
    </dialog>
  )
}

/** 配置文件名：去掉 Windows / macOS 不允许的路径字符。 */
function configFileStem(name: string): string {
  const cleaned = name.trim().replace(/[\\/:*?"<>|]/g, '_').replace(/\s+/g, ' ')
  return cleaned || 'tower'
}

function schemeDisplayName(name: string, custom?: boolean): string {
  const base = stripSchemeCustomSuffix(name)
  return custom ? `${base} · 自定义` : base
}

/** 全局节点名称筛选：关键词按行，或切换为正则。 */
function filterNodesByName(
  nodes: ProxyNode[],
  settings: NodeNameFilterSettings,
): { nodes: ProxyNode[]; error?: string } {
  const compile = (text: string) => {
    const lines = text.split('\n').map((line) => line.trim()).filter(Boolean)
    const regexes: RegExp[] = []
    for (const line of lines) {
      try {
        regexes.push(new RegExp(
          settings.useRegex ? line : line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
          settings.caseSensitive ? '' : 'i',
        ))
      } catch {
        return { error: `筛选表达式无效：${line}` }
      }
    }
    return { regexes }
  }
  const included = compile(settings.include)
  if (included.error) return { nodes: [], error: included.error }
  const excluded = compile(settings.exclude)
  if (excluded.error) return { nodes: [], error: excluded.error }
  const include = included.regexes ?? []
  const exclude = excluded.regexes ?? []
  return {
    nodes: nodes.filter((node) => {
      if (exclude.some((regex) => regex.test(node.name))) return false
      return include.length === 0 || include.some((regex) => regex.test(node.name))
    }),
  }
}

function effectiveContentMode(
  client: ClientInfo,
  modes: Partial<Record<ClientTarget, ExportContentMode>>,
  fallback: ExportContentMode,
): ExportContentMode {
  if (client.contentMode === 'nodes') return 'nodes'
  return modes[client.target] ?? fallback
}

/** 客户端顺序：保留用户排序，新版本新增的客户端自动排在末尾。 */
function clientsInOrder(order: ClientTarget[]): ClientInfo[] {
  const known = new Map(CLIENTS.map((client) => [client.target, client]))
  const result: ClientInfo[] = []
  const seen = new Set<ClientTarget>()
  for (const target of order) {
    const client = known.get(target)
    if (!client || seen.has(target)) continue
    seen.add(target)
    result.push(client)
  }
  for (const client of CLIENTS) {
    if (!seen.has(client.target)) result.push(client)
  }
  return result
}

// SVG icons (inline — no external icon lib)
const Icon = {
  Subscriptions: () => (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" className="icn">
      <rect x="2" y="3" width="12" height="10" rx="1.5" />
      <path d="M5 7h6M5 10h4" />
    </svg>
  ),
  Rules: () => (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" className="icn">
      <path d="M3 4h10M3 8h10M3 12h10" />
      <circle cx="5" cy="4" r="1" fill="currentColor" stroke="none" />
      <circle cx="5" cy="8" r="1" fill="currentColor" stroke="none" />
      <circle cx="5" cy="12" r="1" fill="currentColor" stroke="none" />
    </svg>
  ),
  Export: () => (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" className="icn">
      <path d="M8 2v7M5.5 6.5 8 9l2.5-2.5M3 13h10" />
    </svg>
  ),
  Check: () => (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" className="icn">
      <circle cx="7" cy="7" r="4.5" />
      <path d="M10.3 10.3 14 14M5.2 7.2l1.4 1.4 2.5-2.6" />
    </svg>
  ),
  Network: () => (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" className="icn">
      <circle cx="4" cy="4" r="1.7" />
      <circle cx="12" cy="4" r="1.7" />
      <circle cx="8" cy="12" r="1.7" />
      <path d="M5.3 4.9 7 10.3M10.7 4.9 9 10.3M5.7 4h4.6" />
    </svg>
  ),
  Menu: () => (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <path d="M3.5 4h9M3.5 8h9M3.5 12h9" />
    </svg>
  ),
  Close: () => (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <path d="M4 4l8 8M12 4l-8 8" />
    </svg>
  ),
  Github: () => (
    <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" className="icn">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  ),
}

// ---------------- 订阅 Tab ----------------

interface SourceAddFailure {
  label: string
  message: string
}

interface SourceAddResult {
  /** 本批实际解析到的节点总数。 */
  count: number
  /** 用于提示的成功摘要，例如「2 个订阅」。 */
  name: string
  /** 批量添加时失败的订阅；成功的仍会保留。 */
  failures?: SourceAddFailure[]
}

function AddSourceDialog({
  open,
  onClose,
  onAdded,
}: {
  open: boolean
  onClose: () => void
  /** 添加 / 刷新成功后把结果反馈到订阅页，避免弹窗关掉就“什么都没发生”。 */
  onAdded?: (result: SourceAddResult) => void
}) {
  const [url, setURL] = useState('')
  const [mode, setMode] = useState<'url' | 'text' | 'uri' | 'scan'>('url')
  const [name, setName] = useState('')
  const [text, setText] = useState('')
  const [userAgent, setUserAgent] = useState('')
  const [doh, setDoh] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [scanNotice, setScanNotice] = useState('')
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null)
  const ref = useRef<HTMLDialogElement>(null)
  const addSourceFromURL = useStore((s) => s.addSourceFromURL)
  const addSourceFromText = useStore((s) => s.addSourceFromText)
  const readOnly = useWorkspaceStatus().readOnly
  const urlBatch = useMemo(() => splitSubscriptionURLs(url), [url])

  useEffect(() => {
    if (open) {
      ref.current?.showModal()
      setURL(''); setText(''); setName(''); setError(''); setScanNotice(''); setUserAgent(''); setDoh(''); setProgress(null); setMode('url')
      navigator.clipboard?.readText?.().then((clip) => {
        const c = clip.trim()
        // 多行订阅链接也直接填入 URL 模式；只有全部行都是订阅地址时才这样判断。
        const clipBatch = splitSubscriptionURLs(c)
        const clipLines = c.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'))
        if (clipBatch.urls.length > 0 && clipBatch.urls.length === clipLines.length) {
          setURL((v) => v || c); setMode('url')
        } else if (/^(ss|ssr|vmess|vless|trojan|hysteria2?|hy2?|tuic|wireguard|wg|snell|ssh|anytls|socks5?|http|https):\/\/\S+/i.test(c)) {
          // 名称用函数式更新：读剪贴板是异步的，闭包里的 name 已经不是最新值。
          setText((v) => v || c); setMode('uri'); setName((v) => v || '单节点')
        }
      }).catch(() => {})
    } else {
      ref.current?.close()
    }
  }, [open])

  /** 新订阅必须真的解析出节点；否则回滚，避免留下一张空卡片。 */
  const requireNodes = (sourceID: string) => {
    const state = useStore.getState()
    const real = state.nodes.filter((n) => n.sourceID === sourceID && !n.isSubscriptionMetadata)
    if (real.length === 0) {
      state.removeSource(sourceID)
      throw new Error('没有解析到可用节点，请检查订阅内容或地址')
    }
  }

  const handleScan = (value: string) => {
    const trimmed = value.trim()
    if (!trimmed) {
      setError('二维码内容为空')
      return
    }
    setError('')
    if (/^https?:\/\//i.test(trimmed)) {
      // http(s) 同时是订阅和 HTTP 代理节点的 scheme；带用户信息或空路径端口的按节点处理。
      const batch = splitSubscriptionURLs(trimmed)
      if (batch.urls.length === 0 && batch.proxyCount > 0) {
        setText(trimmed)
        setName('扫码节点')
        setMode('uri')
        setScanNotice('已识别 HTTP(S) 节点链接，并填入单节点 URI。请检查后点击添加。')
        return
      }
      setURL(trimmed)
      setMode('url')
      setScanNotice('已识别扫码内容，并填入订阅地址。请检查后点击添加。')
      return
    }
    if (/^(ss|ssr|vmess|vless|trojan|anytls|hysteria2?|hy2?|tuic|wireguard|wg|snell|ssh|socks5?|http|https):\/\/\S+/i.test(trimmed)) {
      setText(trimmed)
      setName('扫码节点')
      setMode('uri')
      setScanNotice('已识别节点链接，并填入单节点 URI。请检查后点击添加。')
      return
    }
    setText(trimmed)
    setName('扫码导入')
    setMode('text')
    setScanNotice('已识别扫码内容，并填入粘贴内容。请检查后点击添加。')
  }

  const submit = async () => {
    setBusy(true); setError(''); setProgress(null)
    let addedCount = 0
    let addedName = ''
    try {
      if (mode === 'url') {
        const batch = urlBatch
        if (batch.truncated > 0) {
          throw new Error(`一次最多添加 ${MAX_BATCH_SUBSCRIPTIONS} 个订阅链接，请分批导入`)
        }
        if (batch.urls.length === 0) {
          if (batch.proxyCount > 0) {
            throw new Error('这些地址更像 HTTP 代理节点，请改用「单节点 URI」或「粘贴内容」')
          }
          throw new Error('请输入有效的 http(s) 订阅地址，每行一条')
        }
        const requestOptions = requestOptionsFrom(userAgent, doh)
        const collectedFailures: SourceAddFailure[] = []
        const successNames: string[] = []
        let successSources = 0
        for (let index = 0; index < batch.urls.length; index += 1) {
          const targetURL = batch.urls[index]
          setProgress({ done: index + 1, total: batch.urls.length })
          const beforeIDs = new Set(useStore.getState().sources.map((item) => item.id))
          await addSourceFromURL(targetURL, requestOptions)
          const state = useStore.getState()
          const source = state.sources.find((item) => item.url === targetURL)
          if (!source) {
            collectedFailures.push({ label: subscriptionLabel(targetURL), message: '添加失败，订阅没有保存' })
            continue
          }
          const isNew = !beforeIDs.has(source.id)
          const sourceError = state.errors[source.id]
          if (sourceError) {
            // 新建订阅拉取失败就回滚；已有的订阅保留下来，错误显示在卡片上。
            if (isNew) state.removeSource(source.id)
            collectedFailures.push({ label: subscriptionLabel(targetURL), message: sourceError })
            continue
          }
          const real = state.nodes.filter((node) => node.sourceID === source.id && !node.isSubscriptionMetadata)
          if (real.length === 0) {
            if (isNew) state.removeSource(source.id)
            collectedFailures.push({ label: subscriptionLabel(targetURL), message: '没有解析到可用节点' })
            continue
          }

          successSources += 1
          addedCount += real.length
          const preferredName = name.replace(/[\r\n]+/g, ' ').trim()
          let finalName = source.name
          if (isNew) {
            finalName = preferredName
              ? (batch.urls.length === 1 ? preferredName : `${preferredName} ${successSources}`)
              : (batch.urls.length === 1 ? source.name : subscriptionLabel(targetURL))
            state.updateSource(source.id, { name: finalName })
          }
          successNames.push(finalName)
        }

        if (batch.invalid > 0) {
          collectedFailures.push({ label: '未识别行', message: `${batch.invalid} 行不是 http(s) 订阅地址` })
        }
        if (batch.proxyCount > 0) {
          collectedFailures.push({ label: '未识别行', message: `${batch.proxyCount} 行更像 HTTP 代理节点，未按订阅添加` })
        }
        if (successSources === 0) {
          throw new Error(collectedFailures.map((failure) => `${failure.label}：${failure.message}`).join('；'))
        }
        addedName = successSources === 1 ? successNames[0] : `${successSources} 个订阅`
        if (collectedFailures.length > 0) {
          onAdded?.({ count: addedCount, name: addedName, failures: collectedFailures })
          onClose()
          return
        }
      } else if (mode === 'uri') {
        if (!/^(ss|ssr|vmess|vless|trojan|hysteria2?|hy2?|tuic|wireguard|wg|snell|ssh|anytls|socks5?|http|https):\/\/\S+/i.test(text.trim()))
          throw new Error('请输入有效的节点 URI（如 ss://、vless:// 等）')
        addSourceFromText(name.trim() || '单节点', text.trim())
        const state = useStore.getState()
        const source = state.sources.at(-1)!
        requireNodes(source.id)
        addedCount = state.nodes.filter((n) => n.sourceID === source.id && !n.isSubscriptionMetadata).length
        addedName = source.name
      } else {
        if (!text.trim()) throw new Error('请粘贴订阅内容')
        addSourceFromText(name, text)
        const state = useStore.getState()
        const source = state.sources.at(-1)!
        requireNodes(source.id)
        addedCount = state.nodes.filter((n) => n.sourceID === source.id && !n.isSubscriptionMetadata).length
        addedName = source.name
      }
      onAdded?.({ count: addedCount, name: addedName })
      onClose()
    } catch (e) {
      setError(String((e as Error).message))
    } finally {
      setBusy(false)
      setProgress(null)
    }
  }

  return (
    <dialog ref={ref} onClose={onClose}>
      <h3>添加订阅</h3>
      <form
        className="dialog-form"
        onSubmit={(e) => {
          e.preventDefault()
          if (!busy) void submit()
        }}
      >
        <div className="row" style={{ gap: 14, marginTop: 8, marginBottom: 16 }}>
          <label style={{ fontSize: 13, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <input type="radio" disabled={busy} checked={mode === 'url'} onChange={() => { setMode('url'); setScanNotice('') }} /> 订阅地址
          </label>
          <label style={{ fontSize: 13, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <input type="radio" disabled={busy} checked={mode === 'uri'} onChange={() => { setMode('uri'); setScanNotice('') }} /> 单节点 URI
          </label>
          <label style={{ fontSize: 13, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <input type="radio" disabled={busy} checked={mode === 'text'} onChange={() => { setMode('text'); setScanNotice('') }} /> 粘贴内容
          </label>
          <label style={{ fontSize: 13, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <input type="radio" disabled={busy} checked={mode === 'scan'} onChange={() => { setMode('scan'); setScanNotice('') }} /> 扫码
          </label>
        </div>
        {mode === 'url' ? (
          <>
            <div className="field">
              <label>名称（可选）</label>
              <input
                type="text"
                className="field"
                disabled={busy}
                placeholder="多个订阅会自动追加序号"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="field">
              <label>订阅 URL（每行一条）</label>
              <textarea
                className="field"
                rows={4}
                disabled={busy}
                placeholder={'https://…\nhttps://…'}
                value={url}
                onChange={(e) => setURL(e.target.value)}
                autoFocus
                style={{ fontFamily: '"IBM Plex Mono", ui-monospace, monospace', fontSize: 12 }}
              />
              <div className="hint">
                {url.trim()
                  ? (urlBatch.urls.length > 0
                    ? `已识别 ${urlBatch.urls.length} 个订阅链接`
                    : '等待有效的 http(s) 订阅地址')
                  : '可一次粘贴多条链接，每行一条；空行和 # 注释会被忽略。'}
                {urlBatch.duplicates > 0 ? ` · 跳过 ${urlBatch.duplicates} 行重复` : ''}
                {urlBatch.invalid > 0 ? ` · ${urlBatch.invalid} 行格式无效` : ''}
                {urlBatch.proxyCount > 0 ? ` · ${urlBatch.proxyCount} 行像 HTTP 代理节点` : ''}
                {urlBatch.truncated > 0 ? ` · 超过 ${MAX_BATCH_SUBSCRIPTIONS} 个上限` : ''}
              </div>
              <div className="hint">
                机场通常同时提供通用链接和 Clash 链接；流量与到期响应头多只在 Clash 版（形如
                <code>?flag=clash</code>、<code>?clash=1</code> 或含 <code>/clash</code>）下发。塔台会自动尝试
                几种 Clash 方言链接，直接粘贴 Clash 链接最稳。
              </div>
            </div>
            <details className="advanced-request">
              <summary>高级请求设置（可选）</summary>
              <UserAgentField value={userAgent} onChange={setUserAgent} disabled={busy} />
              <div className="field">
                <label>DNS-over-HTTPS 地址</label>
                <input
                  type="url"
                  className="field"
                  disabled={busy}
                  placeholder="https://…/dns-query"
                  value={doh}
                  onChange={(e) => setDoh(e.target.value)}
                />
                <div className="hint">对这一批订阅生效，仅接受 https 地址，且 DoH 服务需支持 JSON 接口。</div>
              </div>
            </details>
          </>
        ) : mode === 'scan' ? (
          <Suspense fallback={<div className="hint">扫码组件加载中…</div>}>
            <QrScanner onDecoded={handleScan} />
          </Suspense>
        ) : mode === 'uri' ? (
          <>
            <div className="field">
              <label>名称（可选）</label>
              <input type="text" className="field" disabled={busy} placeholder="单节点" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="field">
              <label>节点 URI（ss://, vless://, vmess://, trojan://, hysteria2://, tuic://, wireguard:// …）</label>
              <input type="text" className="field" disabled={busy} placeholder="ss://YWVzLTI1Ni1nY206…#我的节点" value={text} onChange={(e) => setText(e.target.value)} style={{ fontFamily: '"IBM Plex Mono", ui-monospace, monospace', fontSize: 12 }} />
            </div>
          </>
        ) : (
          <>
            <div className="field">
              <label>名称（可选）</label>
              <input type="text" className="field" disabled={busy} value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="field">
              <label>Base64 / URI 列表 / Clash YAML</label>
              <textarea className="field" disabled={busy} value={text} onChange={(e) => setText(e.target.value)} />
            </div>
          </>
        )}
        {scanNotice && <div className="inline-notice" role="status">{scanNotice}</div>}
        <div className="local-note">
          <i aria-hidden="true" />
          {mode === 'url'
            ? '订阅由本机服务抓取并解析；地址、节点和凭据不会上传到第三方。'
            : mode === 'scan'
              ? '二维码图片或相机画面只在本机解码，不会上传到第三方。'
              : '节点内容只在本机解析，不会上传到第三方。'}
        </div>
        {busy && (
          <div className="form-progress" role="status" aria-live="polite">
            <span className="spinner" aria-hidden="true" />
            {mode === 'url'
              ? progress && progress.total > 1
                ? `正在读取订阅 ${progress.done}/${progress.total}…`
                : '正在拉取并解析订阅…'
              : '正在解析节点…'}
          </div>
        )}
        {error && (
          <div className="form-error" role="alert">
            <strong>添加失败</strong>
            <span>{error}</span>
            <small>检查订阅地址或内容后重试。</small>
          </div>
        )}
        <div className="actions">
          {mode !== 'scan' && (
            <button type="submit" className="btn primary" disabled={busy || readOnly} title={readOnly ? READONLY_NOTE : undefined}>
              {busy
                ? '处理中…'
                : mode === 'url' && urlBatch.urls.length > 1
                  ? `添加 ${urlBatch.urls.length} 个订阅`
                  : '添加订阅'}
            </button>
          )}
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>
            {mode === 'scan' ? '关闭' : '取消'}
          </button>
        </div>
      </form>
    </dialog>
  )
}

/** 自有节点：链接 / Base64 / Clash YAML / Surge 配置片段，一次可导入多个。 */
function AddManualNodesDialog({
  open,
  onClose,
  onAdded,
  onManualCreate,
}: {
  open: boolean
  onClose: () => void
  onAdded?: (result: ManualNodeImportResult) => void
  onManualCreate?: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const addManualNodes = useStore((s) => s.addManualNodes)
  const readOnly = useWorkspaceStatus().readOnly
  const [name, setName] = useState('')
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (open) {
      ref.current?.showModal()
      setName('')
      setText('')
      setBusy(false)
      setError('')
    } else {
      ref.current?.close()
    }
  }, [open])

  const importFile = async (file: File | undefined) => {
    if (!file) return
    setBusy(true)
    setError('')
    try {
      if (file.size > 8 * 1024 * 1024) throw new Error('文件大于 8 MB')
      const body = await file.text()
      setText(body)
      if (!name.trim()) setName(file.name.replace(/\.[^.]+$/, ''))
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const submit = () => {
    setError('')
    if (!text.trim()) {
      setError('请粘贴节点链接或配置内容')
      return
    }
    const result = addManualNodes(text, name)
    if (result.nodes.length === 0) {
      setError(result.duplicates > 0
        ? '这些节点已经在「自有节点」里了'
        : result.reason ?? '没有解析到可用节点，请检查链接或配置内容')
      return
    }
    onAdded?.(result)
    onClose()
  }

  return (
    <dialog ref={ref} onClose={onClose} className="manual-node-dialog">
      <h3>添加自有节点</h3>
      <form
        className="dialog-form"
        onSubmit={(e) => {
          e.preventDefault()
          if (!busy) submit()
        }}
      >
        <div className="field">
          <label>名称（可选）</label>
          <input
            type="text"
            className="field"
            disabled={busy}
            placeholder="只导入一个节点时生效；留空则使用节点自带名称"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="field">
          <div className="row between" style={{ marginBottom: 6 }}>
            <label>节点内容</label>
            <button type="button" className="btn ghost" disabled={busy} onClick={() => fileRef.current?.click()}>
              从文件导入
            </button>
          </div>
          <textarea
            className="field"
            rows={8}
            disabled={busy}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={'ss://…\n或粘贴 Base64 / Clash YAML / Surge [Proxy] 段落'}
            style={{ fontFamily: '"IBM Plex Mono", ui-monospace, monospace', fontSize: 12 }}
          />
          <input
            ref={fileRef}
            type="file"
            accept=".txt,.yaml,.yml,.conf,.json,.list"
            style={{ display: 'none' }}
            onChange={(e) => {
              const file = e.target.files?.[0]
              e.target.value = ''
              void importFile(file)
            }}
          />
        </div>
        <div className="hint">
          自有节点不随订阅刷新，删除订阅也不会移除；支持一次粘贴多条节点链接。导入后可在「自有节点」里改名、停用或删除。
        </div>
        {busy && (
          <div className="form-progress" role="status" aria-live="polite">
            <span className="spinner" aria-hidden="true" />
            正在读取文件…
          </div>
        )}
        {error && (
          <div className="form-error" role="alert">
            <strong>添加失败</strong>
            <span>{error}</span>
          </div>
        )}
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy || readOnly} title={readOnly ? READONLY_NOTE : undefined}>添加节点</button>
          {onManualCreate && (
            <button
              type="button"
              className="btn ghost"
              disabled={busy || readOnly}
              onClick={() => {
                onClose()
                onManualCreate()
              }}
            >手动填写</button>
          )}
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

/** 只改显示名称；不会重新解析节点，也不影响已有的订阅节点。 */
function RenameManualNodeDialog({
  node,
  onClose,
  onSaved,
}: {
  node: ProxyNode
  onClose: () => void
  onSaved?: (message: string) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const updateManualNode = useStore((s) => s.updateManualNode)
  const readOnly = useWorkspaceStatus().readOnly
  const [name, setName] = useState(node.name)
  const [error, setError] = useState('')

  useEffect(() => {
    ref.current?.showModal()
  }, [])

  const submit = () => {
    const clean = name.replace(/[\r\n]+/g, ' ').trim()
    if (!clean) {
      setError('名称不能为空')
      return
    }
    updateManualNode(node.id, { name: clean })
    onSaved?.(`已重命名为「${clean}」。`)
    onClose()
  }

  return (
    <dialog ref={ref} onClose={onClose} className="manual-node-dialog">
      <h3>重命名自有节点</h3>
      <form
        className="dialog-form"
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <div className="field">
          <label>节点名称</label>
          <input
            type="text"
            className="field"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        {error && <div className="form-error" role="alert"><span>{error}</span></div>}
        <div className="actions">
          <button type="submit" className="btn primary" {...writeGuard(readOnly)}>保存名称</button>
          <button type="button" className="btn ghost" onClick={onClose}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

// ---------------- 编辑订阅 ----------------

function EditSourceDialog({
  source,
  onClose,
  onSaved,
}: {
  source: SubscriptionSource
  onClose: () => void
  onSaved?: (message: string) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const updateSource = useStore((s) => s.updateSource)
  const refreshSource = useStore((s) => s.refreshSource)
  const readOnly = useWorkspaceStatus().readOnly
  const [name, setName] = useState(source.name)
  const [url, setURL] = useState(source.url)
  const [userAgent, setUserAgent] = useState(source.userAgent ?? '')
  const [doh, setDoh] = useState(source.dnsOverHTTPSURL ?? '')
  const [error, setError] = useState('')

  useEffect(() => {
    ref.current?.showModal()
  }, [])

  const submit = () => {
    const trimmedName = name.trim()
    if (!trimmedName) {
      setError('请填写订阅名称')
      return
    }

    let nextURL = source.url
    let nextUA = source.userAgent ?? ''
    let nextDoH = source.dnsOverHTTPSURL ?? ''
    if (source.url) {
      nextURL = url.trim()
      let parsed: URL
      try {
        parsed = new URL(nextURL)
      } catch {
        setError('请输入有效的 http(s) 订阅地址')
        return
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        setError('只支持 http(s) 订阅地址')
        return
      }
      try {
        const options = requestOptionsFrom(userAgent, doh)
        nextUA = options.userAgent ?? ''
        nextDoH = options.dnsOverHTTPSURL ?? ''
      } catch (e) {
        setError((e as Error).message)
        return
      }
    }

    updateSource(source.id, {
      name: trimmedName,
      ...(source.url
        ? {
            url: nextURL,
            // 空字符串表示清除旧设置。
            userAgent: nextUA,
            dnsOverHTTPSURL: nextDoH,
          }
        : {}),
    })

    const requestsChanged = source.url
      && (nextURL !== source.url
        || nextUA !== (source.userAgent ?? '')
        || nextDoH !== (source.dnsOverHTTPSURL ?? ''))
    if (requestsChanged) {
      void refreshSource(source.id)
      onSaved?.(`「${trimmedName}」已保存，正在按新设置重新拉取订阅…`)
    } else {
      onSaved?.(`订阅「${trimmedName}」的修改已保存。`)
    }
    ref.current?.close()
  }

  return (
    <dialog ref={ref} onClose={onClose}>
      <h3>编辑订阅</h3>
      <form
        className="dialog-form"
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <div className="field">
          <label>名称</label>
          <input
            type="text"
            className="field"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
          />
        </div>

        {source.url ? (
          <>
            <div className="field">
              <label>订阅 URL</label>
              <input
                type="url"
                className="field"
                value={url}
                onChange={(e) => setURL(e.target.value)}
              />
              <div className="hint">
                如果机场给了多个地址，优先用 Clash 版（形如 <code>?flag=clash</code>、<code>?clash=1</code>
                或含 <code>/clash</code>）；通用链接通常不带流量与到期响应头。
              </div>
            </div>
            <div className="advanced-request is-open">
              <div className="advanced-request-title">
                高级请求设置
                <span>只对这一条订阅生效</span>
              </div>
              <UserAgentField value={userAgent} onChange={setUserAgent} />
              <div className="field">
                <label>DNS-over-HTTPS 地址</label>
                <input
                  type="url"
                  className="field"
                  placeholder="https://…/dns-query"
                  value={doh}
                  onChange={(e) => setDoh(e.target.value)}
                />
                <div className="hint">仅接受 https 地址，且 DoH 服务需支持 JSON 接口；留空则使用系统 DNS。</div>
              </div>
            </div>
          </>
        ) : (
          <div className="hint">这条订阅来自粘贴内容，没有订阅地址，只能修改名称。</div>
        )}

        <div className="local-note">
          <i aria-hidden="true" />
          请求仍由本机服务发起；地址、节点和凭据不会上传到第三方。
        </div>
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          <button type="submit" className="btn primary" {...writeGuard(readOnly)}>保存</button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

function SubscriptionSettingsDialog({
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
          {backupRejections.length === 0 && snapshotIssueTotal === 0 && (
            <div className="hint">未发现被丢弃的数据或损坏的快照记录。</div>
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

function TailnetRow({
  connection,
  onEdit,
}: {
  connection: TailnetConnection
  onEdit: () => void
}) {
  const tailnetAuthKeys = useStore((s) => s.tailnetAuthKeys)
  const setTailnetEnabled = useStore((s) => s.setTailnetEnabled)
  const readOnly = useWorkspaceStatus().readOnly
  const detail = [
    connection.magicDNSSuffix ?? (connection.controlURLString ? '自建控制服务器' : '官方 Tailscale'),
    connection.subnets.length > 0 ? `${connection.subnets.length} 个子网` : '',
    tailnetAuthKeys[connection.id] ? '已保存 Auth Key' : '',
  ].filter(Boolean).join(' · ')

  return (
    <div className={`tailnet-row${connection.isEnabled ? '' : ' is-off'}`}>
      <span className="tailnet-mark" aria-hidden="true"><Icon.Network /></span>
      <div className="tailnet-main">
        <div className="tailnet-name">{tailnetPolicyName(connection)}</div>
        <div className="tailnet-detail">{detail}</div>
      </div>
      <button type="button" className="btn ghost" {...writeGuard(readOnly)} onClick={onEdit}>编辑</button>
      <label className="tailnet-switch">
        <input
          type="checkbox"
          checked={connection.isEnabled}
          {...writeGuard(readOnly)}
          onChange={(e) => setTailnetEnabled(connection.id, e.target.checked)}
          aria-label={`启用 ${tailnetPolicyName(connection)}`}
        />
        <span>{connection.isEnabled ? '已启用' : '已停用'}</span>
      </label>
    </div>
  )
}

function TailnetEditorDialog({
  item,
  onClose,
}: {
  item: { connection: TailnetConnection; isNew: boolean }
  onClose: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const tailnets = useStore((s) => s.tailnets)
  const tailnetAuthKeys = useStore((s) => s.tailnetAuthKeys)
  const addTailnet = useStore((s) => s.addTailnet)
  const updateTailnet = useStore((s) => s.updateTailnet)
  const deleteTailnet = useStore((s) => s.deleteTailnet)
  const setTailnetAuthKey = useStore((s) => s.setTailnetAuthKey)
  const readOnly = useWorkspaceStatus().readOnly
  const savedAuthKey = tailnetAuthKeys[item.connection.id] ?? ''
  const [name, setName] = useState(item.connection.name)
  const [controlURL, setControlURL] = useState(item.connection.controlURLString ?? '')
  const [authKey, setAuthKey] = useState(savedAuthKey)
  const [revealKey, setRevealKey] = useState(false)
  const [subnets, setSubnets] = useState(item.connection.subnets.join('\n'))
  const [magicDNS, setMagicDNS] = useState(item.connection.magicDNSSuffix ?? '')
  const [deviceName, setDeviceName] = useState(item.connection.deviceName ?? '')
  const [error, setError] = useState('')
  const [confirmDelete, setConfirmDelete] = useState(false)

  useEffect(() => {
    ref.current?.showModal()
    return () => ref.current?.close()
  }, [])

  const save = () => {
    setError('')
    try {
      const connection: TailnetConnection = {
        ...item.connection,
        name: (name.trim() || 'Tailscale').slice(0, 80),
        controlURLString: normalizeTailnetControlURL(controlURL),
        subnets: normalizeTailnetSubnets(subnets),
        magicDNSSuffix: normalizeTailnetMagicDNSSuffix(magicDNS),
        deviceName: normalizeTailnetDeviceName(deviceName),
      }
      const key = normalizeTailnetAuthKey(authKey)
      if (item.isNew) addTailnet(connection)
      else updateTailnet(connection)
      if (key !== (savedAuthKey || undefined)) setTailnetAuthKey(connection.id, key)
      onClose()
    } catch (e) {
      const message = e instanceof TailnetValidationError
        ? e.field === 'controlURL'
          ? '控制服务器必须是 HTTPS 地址。'
          : e.field === 'subnet'
            ? `无法识别的子网“${e.value}”，请用 192.168.1.0/24 这样的格式。`
            : e.field === 'magicDNSSuffix'
              ? 'MagicDNS 后缀格式不对，例如 tail1234.ts.net。'
              : 'Auth Key 不能包含空格、引号或逗号。'
        : '保存失败，请重试。'
      setError(message)
    }
  }

  const rows = tailnets.filter((connection) => connection.id !== item.connection.id).map((connection) => connection.name).join('、')

  return (
    <dialog ref={ref} onClose={onClose} className="tailnet-dialog">
      <h3>{item.isNew ? '添加 Tailscale 内网' : '编辑 Tailscale 内网'}</h3>
      <div className="settings-body">
        <div className="tailnet-field-grid">
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label htmlFor="tailnet-name">名称</label>
            <input
              id="tailnet-name"
              className="input"
              value={name}
              maxLength={80}
              onChange={(e) => setName(e.target.value)}
              placeholder="例如 家里"
            />
            <div className="hint">导出后在客户端里显示的策略名；不会加入任何策略组。</div>
          </div>
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label htmlFor="tailnet-control">控制服务器（留空为官方 Tailscale）</label>
            <input
              id="tailnet-control"
              className="input"
              value={controlURL}
              maxLength={2048}
              onChange={(e) => setControlURL(e.target.value)}
              placeholder="https://headscale.example.com"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <div className="hint">自建 Headscale 时填写它的 HTTPS 地址。</div>
          </div>
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label htmlFor="tailnet-auth-key">Auth Key（可选）</label>
            <div className="secret-row">
              <input
                id="tailnet-auth-key"
                className="input"
                type={revealKey ? 'text' : 'password'}
                value={authKey}
                maxLength={512}
                onChange={(e) => setAuthKey(e.target.value)}
                placeholder="tskey-auth-…"
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
              />
              {authKey && (
                <button type="button" className="btn ghost" onClick={() => setRevealKey((v) => !v)}>
                  {revealKey ? '隐藏' : '显示'}
                </button>
              )}
            </div>
            <div className="hint">
              Stash、Clash / mihomo 和 sing-box MT 需要它；Surge 在客户端里登录，不写 Key。
              生成时打开 Reusable，设备加入后关闭 Key Expiry；只保存本机，不同步。
            </div>
          </div>
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label htmlFor="tailnet-subnets">家里子网（可选）</label>
            <textarea
              id="tailnet-subnets"
              className="input"
              rows={3}
              value={subnets}
              onChange={(e) => setSubnets(e.target.value)}
              placeholder={'例如 192.168.1.0/24\nfd00:1::/64'}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <div className="hint">每行一个 CIDR；需家里设备在 Tailscale 发布并批准该子网。</div>
          </div>
          <div className="field">
            <label htmlFor="tailnet-magic-dns">MagicDNS 后缀</label>
            <input
              id="tailnet-magic-dns"
              className="input"
              value={magicDNS}
              maxLength={253}
              onChange={(e) => setMagicDNS(e.target.value)}
              placeholder="tail1234.ts.net"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <div className="hint">在 Tailscale DNS 页面查看；Stash 必填。</div>
          </div>
          <div className="field">
            <label htmlFor="tailnet-device-name">设备名</label>
            <input
              id="tailnet-device-name"
              className="input"
              value={deviceName}
              maxLength={40}
              onChange={(e) => setDeviceName(e.target.value)}
              placeholder="tower"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <div className="hint">每个客户端会注册成单独设备，例如 tower-stash。</div>
          </div>
        </div>
        <div className="local-note">
          <i aria-hidden="true" />
          Auth Key 只存本机，会写入配置（预览打码）。修改或删除后请回导出页同步订阅。
        </div>
        {rows && <div className="hint">其他内网：{rows}。每份各写一条策略。</div>}
        {error && <div className="form-error" role="alert">{error}</div>}
        {!item.isNew && (
          <div className="tailnet-delete">
            {confirmDelete ? (
              <>
                <span>删除后这份内网与本机 Auth Key 都会移除；已发布订阅需回导出页同步，才会去掉旧 Key。</span>
                <button
                  type="button"
                  className="btn danger"
                  {...writeGuard(readOnly)}
                  onClick={() => {
                    deleteTailnet(item.connection.id)
                    onClose()
                  }}
                >
                  确认删除
                </button>
                <button type="button" className="btn ghost" onClick={() => setConfirmDelete(false)}>取消删除</button>
              </>
            ) : (
              <button type="button" className="btn ghost" {...writeGuard(readOnly)} onClick={() => setConfirmDelete(true)}>删除这个内网</button>
            )}
          </div>
        )}
      </div>
      <div className="actions">
        <button type="button" className="btn primary" {...writeGuard(readOnly)} onClick={save}>保存</button>
        <button type="button" className="btn ghost" onClick={onClose}>取消</button>
      </div>
    </dialog>
  )
}

function TailnetTab() {
  const tailnets = useStore((s) => s.tailnets)
  const tailnetAuthKeys = useStore((s) => s.tailnetAuthKeys)
  const readOnly = useWorkspaceStatus().readOnly
  const [editing, setEditing] = useState<{ connection: TailnetConnection; isNew: boolean } | null>(null)
  const enabledCount = tailnets.filter((connection) => connection.isEnabled).length
  const keyCount = tailnets.filter((connection) => tailnetAuthKeys[connection.id]).length

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">内网连接 · 02</div>
          <h1>Tailscale 内网</h1>
          <div className="sub">开着代理时，也能按规则访问家里设备和子网。</div>
        </div>
        <div className="row page-actions" style={{ gap: 8 }}>
          <button className="btn primary" {...writeGuard(readOnly)} onClick={() => setEditing({ connection: defaultTailnetConnection(), isNew: true })}>
            + 添加内网
          </button>
        </div>
      </div>

      <div className="card tailnet-intro">
        <div className="card-head">
          <h3>它是什么</h3>
          <span className="meta">不是节点 · 不加入策略组</span>
        </div>
        <div className="tailnet-intro-body">
          <div className="tailnet-copy">
            <p className="tailnet-lead">把 Tailscale 当成一条独立出口。</p>
            <ul className="tailnet-points">
              <li><b>独立策略</b>：不进入节点选择、自动选择或测速。</li>
              <li><b>只走内网</b>：置顶写 Tailscale 地址段、MagicDNS 与家里子网规则。</li>
              <li><b>不回退直连</b>：不在内网的目标直接失败，不会绕回普通节点。</li>
            </ul>
            <details className="tailnet-details">
              <summary>支持的客户端与注意事项</summary>
              <ul>
                <li>支持 Surge（iOS 5.21 / Mac 6.8 起）、Stash 3.4 起、Clash / mihomo（内核 1.19.25 起）和 sing-box MT。</li>
                <li>其余客户端（Shadowrocket、Loon、QuanX、Egern、Hiddify、Karing）会跳过并提示。</li>
                <li>只写「完整配置」，「仅节点」不含它。</li>
              </ul>
            </details>
          </div>
          <div className="tailnet-visual">
            <TailnetIllustration />
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>已添加的内网</h3>
          <span className="meta">
            {tailnets.length === 0 ? '尚未添加' : `${enabledCount} 个已启用 · ${keyCount} 个已保存 Auth Key`}
          </span>
        </div>
        {tailnets.length === 0 ? (
          <div className="preview-empty tailnet-empty">
            <strong>还没有 Tailscale 内网</strong>
            <span>添加后只在「完整配置」中写入受支持的客户端。</span>
          </div>
        ) : (
          <div className="tailnet-list">
            {tailnets.map((connection) => (
              <TailnetRow
                key={connection.id}
                connection={connection}
                onEdit={() => setEditing({ connection, isNew: false })}
              />
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <h3>导出规则</h3>
          <span className="meta">置顶写入</span>
        </div>
        <div className="tailnet-routes">
          <span><b>DOMAIN-SUFFIX</b> MagicDNS 后缀，填了才写</span>
          <span><b>IP-CIDR</b> 100.64.0.0/10</span>
          <span><b>IP-CIDR6</b> fd7a:115c:a1e0::/48</span>
          <span><b>IP-CIDR</b> 你填写的家里子网</span>
        </div>
        <p className="tailnet-lead">只写完整配置，排在其他规则之前；不进节点组或测速。</p>
        <details className="tailnet-details">
          <summary>自动路由与 Stash 注意事项</summary>
          <p>
            Surge 5.21+ / Stash 3.6+ 会自动路由，重复规则无害；Stash 3.4、mihomo 和 sing-box 仍依赖它们。
            Stash 默认跳过 Tailscale 与局域网网段，建议用 MagicDNS 设备名访问。
          </p>
        </details>
      </div>

      {editing && (
        <TailnetEditorDialog
          key={`${editing.connection.id}-${editing.isNew ? 'new' : 'edit'}`}
          item={editing}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  )
}


interface NetworkOrganization {
  asn?: number
  organization?: string
}

const networkOrgCache = new Map<string, Promise<NetworkOrganization | null>>()

/** 服务器 IP 的网络组织；只查本机离线库，失败时静默返回 null。 */
function networkOrganizationForHost(host: string): Promise<NetworkOrganization | null> {
  const cached = networkOrgCache.get(host)
  if (cached) return cached
  const controller = new AbortController()
  const timer = window.setTimeout(() => controller.abort(), 5000)
  const request = apiFetch(`/api/ip-country?host=${encodeURIComponent(host)}`, { signal: controller.signal })
    .then(async (res) => {
      if (!res.ok) return null
      const data = await res.json() as { asn?: number; organization?: string }
      return data.organization ? { asn: data.asn, organization: data.organization } : null
    })
    .catch(() => null)
    .finally(() => window.clearTimeout(timer))
  networkOrgCache.set(host, request)
  return request
}

/** 订阅页与自有节点的统一搜索条件；公告 / 配额伪节点永远不命中。 */
function nodeMatchesKeyword(node: ProxyNode, needle: string): boolean {
  if (node.isSubscriptionMetadata) return false
  const region = regionForNode(node)
  return [
    node.name,
    node.server,
    node.kind,
    PROXY_KIND_TITLES[node.kind] ?? '',
    region?.name ?? '',
    region?.code ?? '',
  ].join(' ').toLowerCase().includes(needle)
}

function NodeRow({
  node,
  onCountryClick,
  onEditCountry,
  keyword = '',
  showKind = true,
  onRenameManual,
  onEditManual,
  onDeleteManual,
}: {
  node: ProxyNode
  onCountryClick?: (code: string | null) => void
  onEditCountry?: (node: ProxyNode) => void
  keyword?: string
  /** 订阅里所有节点同一协议时隐藏协议列，减少噪声。 */
  showKind?: boolean
  onRenameManual?: (node: ProxyNode) => void
  onEditManual?: (node: ProxyNode) => void
  onDeleteManual?: (node: ProxyNode) => void
}) {
  const toggle = useStore((s) => s.toggleNodeExcluded)
  const updateManualNode = useStore((s) => s.updateManualNode)
  const sources = useStore((s) => s.sources)
  const latencyMap = useStore((s) => s.latencyByNodeId)
  const latencyMethodMap = useStore((s) => s.latencyMethodByNodeId)
  const probeErrors = useStore((s) => s.probeErrorByNodeId)
  const testingIds = useStore((s) => s.testingNodeIds)
  const readOnly = useWorkspaceStatus().readOnly

  const excluded = useMemo(() => {
    if (node.isManual) return node.isEnabled === false
    const src = sources.find((s) => s.id === node.sourceID)
    if (!src || src.excludedNodeKeys.length === 0) return false
    return src.excludedNodeKeys.includes(nodeExactKey(node))
  }, [sources, node])
  const latency = latencyMap[node.id]
  const probeError = probeErrors[node.id]
  const testing = testingIds.includes(node.id)
  const region = regionForNode(node)
  const [expanded, setExpanded] = useState(false)
  const [copiedURI, setCopiedURI] = useState(false)
  const [qrOpen, setQrOpen] = useState(false)
  const [networkOrg, setNetworkOrg] = useState<NetworkOrganization | null | undefined>(undefined)

  useEffect(() => {
    if (!expanded || !node.server) return
    let cancelled = false
    setNetworkOrg(undefined)
    void networkOrganizationForHost(node.server).then((result) => {
      if (!cancelled) setNetworkOrg(result)
    })
    return () => { cancelled = true }
  }, [expanded, node.server])

  if (node.isSubscriptionMetadata) {
    return <div className="notice">{node.name}</div>
  }

  const sourceName = node.sourceID
    ? sources.find((source) => source.id === node.sourceID)?.name
    : node.isManual ? '自有节点' : '本地节点'
  const regionSource = node.countryOverride
    ? '手动标记'
    : regionForName(node.name)
      ? '节点名称'
      : node.detectedCountry ? '离线 IP' : '未知'
  const shareURI = nodeShareText(node)
  const capability = nodeTransportCapability(node)
  const method = latencyMethodMap[node.id]
  const methodText = method === 'icmp'
    ? 'ICMP 近似（服务器可达性，非 UDP RTT）'
    : 'TCP 握手'
  const latencyText = latency === undefined
    ? (testing ? '测速中' : '未测')
    : latency === null
      ? `不可达（${probeError ?? 'unknown'}）`
      : `${latency} ms · ${methodText}`
  const udpForwardingText = capability.udpForwarding === 'supported'
    ? '支持'
    : capability.udpForwarding === 'unsupported' ? '不支持' : '未知'
  const copyShareURI = async () => {
    if (!shareURI) return
    if (await copyToClipboard(shareURI)) {
      setCopiedURI(true)
      window.setTimeout(() => setCopiedURI(false), 1600)
    }
  }

  const needle = keyword.trim().toLowerCase()
  const nameMatches = !!(needle && node.name.toLowerCase().includes(needle))
  // 搜索命中不在名称里时，用一行灰字告诉用户命中的是哪个字段。
  const matchHint = (() => {
    if (!needle || nameMatches) return ''
    if (node.server.toLowerCase().includes(needle)) return `服务器 ${node.server}`
    if ((region?.name ?? '').toLowerCase().includes(needle) || (region?.code ?? '').toLowerCase().includes(needle)) {
      return `地区 ${region?.name ?? ''}`
    }
    if (node.kind.toLowerCase().includes(needle) || (PROXY_KIND_TITLES[node.kind] ?? '').toLowerCase().includes(needle)) {
      return `协议 ${PROXY_KIND_TITLES[node.kind] ?? node.kind}`
    }
    return ''
  })()

  // 三档语义色：良好 / 需关注 / 失败；悬停给出具体等级与握手耗时。
  const latencyBadge = (() => {
    if (latency === undefined) {
      return testing
        ? <span className="latency testing" title="正在测速">测速中</span>
        : <span className="latency untested" title="尚未测速">未测</span>
    }
    if (latency === null) {
      if (probeError === 'tcp_not_applicable') {
        return (
          <span className="latency untested" title="UDP/QUIC 承载节点无法用 TCP 握手测速，请改用自动或 ICMP">
            不适用
          </span>
        )
      }
      return (
        <span className="latency" style={{ color: 'var(--negative)' }} title={`失败 · 不可达（${probeError ?? 'unknown'}）`}>
          —
        </span>
      )
    }
    const measured = latencyMethodMap[node.id]
    // ICMP 只是服务器可达性参考，不套用 TCP 延迟的三档色阶。
    if (measured === 'icmp') {
      return (
        <span className="latency approx" title={`可达性参考 · ICMP 近似 ${latency}ms（非 UDP RTT）`}>
          ≈{latency}<span className="unit">ms</span>
        </span>
      )
    }
    const grade = latency < 100 ? '良好' : latency < 300 ? '一般' : '较差'
    const color = grade === '良好' ? 'var(--positive)' : grade === '一般' ? 'var(--warning)' : 'var(--negative)'
    return (
      <span className="latency" style={{ color }} title={`${grade} · TCP 握手 ${latency}ms`}>
        {latency}<span className="unit">ms</span>
      </span>
    )
  })()

  return (
    <>
      <div
        className={`node-row ${excluded ? 'off' : ''} ${onCountryClick ? 'clickable' : ''} ${testing ? 'is-testing' : ''}`}
        onClick={() => onCountryClick?.(region?.code ?? null)}
      >
      <input
        type="checkbox"
        checked={!excluded}
        onClick={(e) => e.stopPropagation()}
        onChange={() => {
          if (node.isManual) {
            updateManualNode(node.id, { isEnabled: node.isEnabled === false })
          } else {
            toggle(node)
          }
        }}
        title={readOnly ? READONLY_NOTE : '包含在生成的配置中'}
        aria-label={`包含在生成的配置中：${node.name}`}
        {...writeGuard(readOnly)}
      />
      {onEditCountry ? (
        <button
          type="button"
          className={`flag flag-button${node.countryOverride ? ' is-manual' : ''}`}
          onClick={(e) => {
            e.stopPropagation()
            onEditCountry(node)
          }}
          aria-label={`设置地区：${node.name}`}
          title={readOnly ? READONLY_NOTE : region ? `${region.name} · 点击修改地区` : '点击设置地区'}
          {...writeGuard(readOnly)}
        >
          {region?.flag ?? '·'}
        </button>
      ) : (
        <span className="flag">{region?.flag ?? '·'}</span>
      )}
      <button
        type="button"
        className="name node-name-toggle"
        title={expanded ? '收起节点详情' : '展开节点详情'}
        aria-expanded={expanded}
        onClick={(event) => {
          event.stopPropagation()
          setExpanded((value) => !value)
        }}
      >
        <span className="node-name-text"><Highlight text={node.name} needle={needle} /></span>
        <span className="node-disclosure" aria-hidden="true">{expanded ? '▾' : '▸'}</span>
      </button>
      {matchHint && <span className="node-match" title={matchHint}>{matchHint}</span>}
      <span
        className={`transport-badge transport-${capability.transport}`}
        title={`${capability.transport.toUpperCase()} 承载 · UDP 转发：${udpForwardingText}`}
      >
        {capability.transport.toUpperCase()}
      </span>
      {latencyBadge}
      {showKind && <span className="kind">{PROXY_KIND_TITLES[node.kind] ?? node.kind}</span>}
      {node.isManual && (onRenameManual || onEditManual || onDeleteManual) && (
        <details className="menu node-row-menu" onClick={(event) => event.stopPropagation()} onToggle={updateDetailsPlacement}>
          <summary className="icon-btn" aria-label={`自有节点操作：${node.name}`} title="自有节点操作">⋯</summary>
          <div className="menu-panel">
            {onEditManual && (
              <button {...writeGuard(readOnly)} onClick={(event) => {
                event.currentTarget.closest('details')?.removeAttribute('open')
                onEditManual(node)
              }}>编辑节点</button>
            )}
            {onRenameManual && (
              <button {...writeGuard(readOnly)} onClick={(event) => {
                event.currentTarget.closest('details')?.removeAttribute('open')
                onRenameManual(node)
              }}>重命名</button>
            )}
            <button {...writeGuard(readOnly)} onClick={(event) => {
              event.currentTarget.closest('details')?.removeAttribute('open')
              updateManualNode(node.id, { isEnabled: node.isEnabled === false })
            }}>
              {node.isEnabled === false ? '启用节点' : '停用节点'}
            </button>
            {onDeleteManual && (
              <button className="danger" {...writeGuard(readOnly)} onClick={(event) => {
                event.currentTarget.closest('details')?.removeAttribute('open')
                onDeleteManual(node)
              }}>删除节点</button>
            )}
          </div>
        </details>
      )}
      </div>
      {expanded && (
        <div className="node-detail">
          <div className="node-detail-grid">
            <span>服务器</span>
            <code>{node.server.includes(':') ? `[${node.server}]` : node.server}:{node.port}</code>
            <span>协议</span>
            <span>{PROXY_KIND_TITLES[node.kind] ?? node.kind}</span>
            <span>来源</span>
            <span>{sourceName ?? '未知'}</span>
            <span>地区</span>
            <span>{region ? `${region.flag} ${region.name}` : '未识别'} · {regionSource}</span>
            <span>网络组织</span>
            <span>
              {networkOrg === undefined
                ? '查询本机离线库…'
                : networkOrg?.organization
                  ? `AS${networkOrg.asn} · ${networkOrg.organization}`
                  : '未知'}
            </span>
            <span>延迟</span>
            <span>{latencyText}</span>
            <span>传输层</span>
            <span>{capability.transport.toUpperCase()} · UDP 转发{udpForwardingText}</span>
            {node.transport && node.transport !== 'tcp' && (
              <>
                <span>传输</span>
                <span>{node.transport}{node.hostHeader ? ` · ${node.hostHeader}` : ''}{node.path ? ` · ${node.path}` : ''}</span>
              </>
            )}
            {node.tls && (
              <>
                <span>TLS</span>
                <span>开启{node.sni ? ` · SNI ${node.sni}` : ''}{node.skipCertificateVerification ? ' · 跳过证书校验' : ''}</span>
              </>
            )}
            {node.alpn && (
              <>
                <span>ALPN</span>
                <span>{node.alpn}</span>
              </>
            )}
            {(node.realityPublicKey || node.fingerprint) && (
              <>
                <span>指纹 / REALITY</span>
                <span>{node.fingerprint ?? '未设置指纹'}{node.realityPublicKey ? ' · REALITY' : ''}</span>
              </>
            )}
            {node.flow && (
              <>
                <span>VLESS Flow</span>
                <span>{node.flow}</span>
              </>
            )}
            {node.trustTunnel && (
              <>
                <span>TrustTunnel</span>
                <span>{node.trustTunnel.quic ? 'HTTP/3 · QUIC' : 'HTTP/2 + TLS'}</span>
              </>
            )}
            {node.kind === 'masque' && (
              <>
                <span>MASQUE</span>
                <span>
                  {node.masque?.mode === 'basicConnectIP' ? (
                    <>
                      basic-connect-IP · HTTP/{node.masque.httpVersion ?? 3}
                      {node.username ? ` · ${node.username}` : ''}
                      {node.path ? ` · ${node.path}` : ''}
                      {node.masque.mtu ? ` · MTU ${node.masque.mtu}` : ''}
                    </>
                  ) : node.masque?.mode === 'keyConnectIP' ? (
                    <>
                      CONNECT-IP 密钥模式
                      {node.masque.network ? ` · ${node.masque.network}` : ''}
                      {node.masque.ipv4 ? ` · ${node.masque.ipv4}` : node.masque.ipv6 ? ` · ${node.masque.ipv6}` : ''}
                      {node.masque.mtu ? ` · MTU ${node.masque.mtu}` : ''}
                    </>
                  ) : (
                    <>
                      Surge Basic-auth CONNECT
                      {node.username ? ` · ${node.username}` : ''}
                    </>
                  )}
                </span>
              </>
            )}
            {node.ssh && (node.ssh.hostKeys?.length ?? 0) > 0 && (
              <>
                <span>SSH Host Key</span>
                <span>已固定 {node.ssh.hostKeys!.length} 个</span>
              </>
            )}
          </div>
          {shareURI ? (
            <div className="node-detail-link">
              <input
                readOnly
                className="input"
                value={shareURI}
                aria-label={`${node.name} 的分享链接`}
                onFocus={(event) => event.currentTarget.select()}
              />
              <button className="btn ghost" onClick={() => void copyShareURI()}>
                {copiedURI ? '已复制' : '复制链接'}
              </button>
              <button className="btn ghost" onClick={() => setQrOpen(true)}>二维码</button>
            </div>
          ) : (
            <div className="hint">这个节点来自 Clash 配置，没有原始分享链接；它仍会正常写入导出配置。</div>
          )}
          <div className="node-detail-actions">
            {onEditCountry && (
              <button className="btn ghost" onClick={() => onEditCountry(node)}>设置地区</button>
            )}
            <span className="hint">IP 地区与网络组织来自服务器地址，不代表实际出口。</span>
          </div>
        </div>
      )}
      {qrOpen && shareURI && (
        <QRCodeDialog
          open={qrOpen}
          url={shareURI}
          title={node.name}
          hint="扫码可在其他设备导入这个节点；链接包含节点凭据，请只在可信设备使用。"
          onClose={() => setQrOpen(false)}
        />
      )}
    </>
  )
}

function ManualNodesCard({
  nodes,
  keyword,
  onCountryClick,
  onEditCountry,
  onAdd,
  onCreate,
  onEditNode,
  onRename,
  onRequestDelete,
}: {
  nodes: ProxyNode[]
  keyword: string
  onCountryClick?: (code: string | null) => void
  onEditCountry?: (node: ProxyNode) => void
  onAdd: () => void
  onCreate: () => void
  onEditNode: (node: ProxyNode) => void
  onRename: (node: ProxyNode) => void
  onRequestDelete: (node: ProxyNode) => void
}) {
  const needle = keyword.trim().toLowerCase()
  const readOnly = useWorkspaceStatus().readOnly
  const visible = useMemo(
    () => needle ? nodes.filter((node) => nodeMatchesKeyword(node, needle)) : nodes,
    [nodes, needle],
  )
  const enabledCount = nodes.filter((node) => node.isEnabled !== false).length
  if (needle && visible.length === 0) return null

  return (
    <div className="card source-card manual-card">
      <div className="row between">
        <div className="row" style={{ gap: 12 }}>
          <div>
            <div className="source-title-row">
              <h3 style={{ margin: 0 }}>自有节点</h3>
              <span className="pill">手动</span>
            </div>
            <div className="meta" style={{ marginTop: 2 }}>
              <span className="num">{nodes.length}</span> 个节点 · <span className="num">{enabledCount}</span> 个启用
              {needle ? ` · 匹配 ${visible.length}/${nodes.length}` : ''}
            </div>
          </div>
        </div>
        <div className="row card-actions">
          <button className="btn ghost" {...writeGuard(readOnly)} onClick={onAdd}>+ 添加节点</button>
          <button className="btn ghost" {...writeGuard(readOnly)} onClick={onCreate}>+ 新建节点</button>
        </div>
      </div>
      <div className="hint manual-node-hint">
        只保存在本机；不随订阅刷新，删除订阅也不会移除。取消勾选后不会进入导出配置。
      </div>
      <div className={`node-list${visible.length >= 12 ? ' dense' : ''}`} style={{ marginTop: 10 }}>
        {visible.map((node) => (
          <NodeRow
            key={node.id}
            node={node}
            onCountryClick={onCountryClick}
            onEditCountry={onEditCountry}
            keyword={needle}
            onRenameManual={onRename}
            onEditManual={onEditNode}
            onDeleteManual={onRequestDelete}
          />
        ))}
      </div>
    </div>
  )
}

function SourceCard({
  id,
  onCountryClick,
  onEditCountry,
  manageMode = false,
  checked = false,
  onToggleChecked,
  keyword = '',
  onRequestDelete,
  onEdit,
}: {
  id: string
  onCountryClick?: (code: string | null) => void
  onEditCountry?: (node: ProxyNode) => void
  manageMode?: boolean
  checked?: boolean
  onToggleChecked?: () => void
  /** 订阅页的搜索词，用于过滤本卡片里的节点行。 */
  keyword?: string
  /** 低频操作（删除订阅）交给页面统一弹确认框。 */
  onRequestDelete?: (id: string, name: string) => void
  /** 修改名称、地址和请求设置。 */
  onEdit?: () => void
}) {
  const source = useStore((s) => s.sources.find((x) => x.id === id))
  const allNodes = useStore((s) => s.nodes)
  const nodes = useMemo(() => allNodes.filter((n) => n.sourceID === id), [allNodes, id])
  const loading = useStore((s) => s.loadingSourceIDs.includes(id))
  const error = useStore((s) => s.errors[id])
  const latencyMap = useStore((s) => s.latencyByNodeId)
  const testingIds = useStore((s) => s.testingNodeIds)
  const refresh = useStore((s) => s.refreshSource)
  const setExclusions = useStore((s) => s.setSourceExclusions)
  const setSourceEnabled = useStore((s) => s.setSourceEnabled)
  const startTesting = useStore((s) => s.startTesting)
  const stopTesting = useStore((s) => s.stopTesting)
  const filterInfoNodes = useStore((s) => s.filterSubscriptionInfoNodes)
  const readOnly = useWorkspaceStatus().readOnly
  // 订阅卡片默认收起；搜索时自动展开，方便直接看到命中的节点行。
  const [expanded, setExpanded] = useState(false)
  const [sortByLatency, setSortByLatency] = useState(false)
  const menuRef = useRef<HTMLDetailsElement>(null)
  const legendRef = useRef<HTMLDetailsElement>(null)
  const selectAllRef = useRef<HTMLInputElement>(null)

  // 点击菜单 / 图例外时收起（details 默认不会自动关闭）
  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      const target = e.target as Node
      for (const ref of [menuRef, legendRef]) {
        const el = ref.current
        if (el?.open && !el.contains(target)) el.open = false
      }
    }
    document.addEventListener('click', onDocClick)
    return () => document.removeEventListener('click', onDocClick)
  }, [])

  const needle = keyword.trim().toLowerCase()
  useEffect(() => {
    if (needle) setExpanded(true)
  }, [needle])
  // 搜索词命中订阅名时展示全部节点（否则只保留命中的节点行）。
  const sourceNameMatches = !!source && needle.length > 0 && source.name.toLowerCase().includes(needle)
  const visibleNodes = useMemo(() => {
    let list = filterInfoNodes ? nodes.filter((node) => !node.isSubscriptionMetadata) : nodes
    if (needle && !sourceNameMatches) {
      list = list.filter((n) => nodeMatchesKeyword(n, needle))
    }
    if (sortByLatency) {
      const rank = (n: ProxyNode) => {
        const v = latencyMap[n.id]
        return v === undefined || v === null ? Number.POSITIVE_INFINITY : v
      }
      list = [...list].sort((a, b) => rank(a) - rank(b))
    }
    return list
  }, [nodes, needle, sourceNameMatches, sortByLatency, latencyMap, filterInfoNodes])
  const visibleRealCount = visibleNodes.filter((n) => !n.isSubscriptionMetadata).length

  // 节点启用状态（排除列表）与“全选”三态复选框
  const excludedKeys = new Set(source?.excludedNodeKeys ?? [])
  const realAll = nodes.filter((n) => !n.isSubscriptionMetadata)
  const includedAll = realAll.filter((n) => !excludedKeys.has(nodeExactKey(n)))
  const allIncluded = realAll.length > 0 && includedAll.length === realAll.length
  const someIncluded = includedAll.length > 0 && !allIncluded
  useEffect(() => {
    if (selectAllRef.current) selectAllRef.current.indeterminate = someIncluded
    // 卡片默认收起时 ref 还是 null；展开 / 搜索自动展开后才挂载复选框，需要再同步一次。
  }, [someIncluded, expanded])

  if (!source) return null
  const sourceEnabled = isSourceEnabled(source)
  const real = realAll
  const usage = subscriptionUsageSummary(source)
  const thisSourceIds = real.map((n) => n.id)
  const testingThisSource = testingIds.some((tid) => thisSourceIds.includes(tid))
  const testedCount = thisSourceIds.filter((id) => latencyMap[id] !== undefined).length
  // 本轮已完成数 = 总数 - 队列里剩余数（比「累计已测」更能反映进度）
  const remainingThisSource = thisSourceIds.filter((id) => testingIds.includes(id)).length
  const doneThisRun = real.length - remainingThisSource
  // 同一订阅里协议都相同时不显示协议列（例如整份都是 SSR）。
  const showKind = new Set(real.map((n) => n.kind)).size > 1
  const currentTestingId = testingIds.find((tid) => thisSourceIds.includes(tid) && latencyMap[tid] === undefined)
  const currentTestingNode = currentTestingId ? real.find((n) => n.id === currentTestingId) : undefined

  const closeMenu = () => { if (menuRef.current) menuRef.current.open = false }
  const toggleAllNodes = () => setExclusions(id, allIncluded ? real.map(nodeExactKey) : [])

  return (
    <div className={`card source-card${sourceEnabled ? '' : ' is-disabled'}`}>
      <div className="row between">
        <div className="row" style={{ gap: 12 }}>
          {manageMode && (
            <input
              type="checkbox"
              checked={checked}
              onChange={() => onToggleChecked?.()}
              aria-label={`选择订阅「${source.name}」`}
              style={{ width: 18, height: 18 }}
            />
          )}
          <div>
            <div className="source-title-row">
              <h3 style={{ margin: 0 }}>{source.name}</h3>
              {!sourceEnabled && <span className="pill source-status">已停用</span>}
            </div>
            <div className="meta" style={{ marginTop: 2 }}>
              <span className="num">{real.length}</span> 个节点{source.updatedAt ? ` · 更新于 ${formatDate(source.updatedAt)}` : ''}
              {testedCount > 0 ? ` · 已测 ${testedCount}/${real.length}` : ''}
              {testingThisSource ? ' · 测速中' : ''}
              {source.userAgent ? ' · 自定义 UA' : ''}
              {source.dnsOverHTTPSURL ? ' · DoH' : ''}
              {needle && !sourceNameMatches ? ` · 匹配 ${visibleRealCount}/${real.length}` : ''}
            </div>
            {shouldShowSourceUsage(source) && <SourceUsage summary={usage} />}
            {(source.notices?.length ?? 0) > 0 && (
              <details className="source-notices">
                <summary>订阅公告 · {source.notices!.length}</summary>
                {source.notices!.map((notice, index) => <div key={`${notice}-${index}`}>{notice}</div>)}
              </details>
            )}
          </div>
        </div>
        {!manageMode && (
          <div className="row card-actions">
            <button
              type="button"
              role="switch"
              aria-checked={sourceEnabled}
              aria-label={sourceEnabled ? `停用订阅「${source.name}」` : `启用订阅「${source.name}」`}
              title={sourceEnabled ? '停用后，节点不会进入生成的配置' : '启用后，节点会重新进入生成的配置'}
              className={`source-switch${sourceEnabled ? ' is-on' : ''}`}
              {...writeGuard(readOnly)}
              onClick={() => setSourceEnabled(id, !sourceEnabled)}
            >
              <span className="switch-track" aria-hidden="true"><span className="switch-thumb" /></span>
              <span className="switch-label">{sourceEnabled ? '已启用' : '已停用'}</span>
            </button>
            {sourceEnabled && (
              <button className="btn" disabled={testingThisSource} onClick={() => startTesting(thisSourceIds)}>
                {testingThisSource ? `测速中 ${doneThisRun}/${real.length}` : '全部测速'}
              </button>
            )}
            {sourceEnabled && testingThisSource && <button className="btn ghost" onClick={() => stopTesting()}>取消</button>}
            {source.url && (
              <button className="btn ghost" disabled={loading || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={() => refresh(id)}>
                {loading ? '刷新中…' : '刷新'}
              </button>
            )}
            <button className="btn ghost" aria-expanded={expanded} aria-controls={`nodes-${id}`} onClick={() => setExpanded(!expanded)}>
              {expanded ? '收起' : '展开'}
            </button>
            <details className="menu" ref={menuRef} onToggle={updateDetailsPlacement}>
              <summary className="icon-btn" aria-label="更多操作" title="更多操作">⋯</summary>
              <div className="menu-panel">
                <button {...writeGuard(readOnly)} onClick={() => { closeMenu(); onEdit?.() }}>编辑订阅</button>
                <button {...writeGuard(readOnly)} onClick={() => { setSourceEnabled(id, !sourceEnabled); closeMenu() }}>
                  {sourceEnabled ? '停用订阅' : '启用订阅'}
                </button>
                <button onClick={() => { setSortByLatency((v) => !v); closeMenu() }}>
                  延迟排序{sortByLatency ? '（已开启）' : ''}
                </button>
                <button {...writeGuard(readOnly)} onClick={() => { setExclusions(id, []); closeMenu() }}>恢复默认（全部启用）</button>
                <button className="danger" {...writeGuard(readOnly)} onClick={() => { closeMenu(); onRequestDelete?.(id, source.name) }}>删除订阅</button>
              </div>
            </details>
          </div>
        )}
      </div>
      {!sourceEnabled && (
        <div className="source-off-note" role="status">
          已停用：这 {real.length} 个节点不会进入配置，也不会计入健康统计。刷新仍可更新节点，需要时再启用。
        </div>
      )}
      {sourceEnabled && testingThisSource && real.length > 0 && (
        <div className="test-block">
          <div
            className="test-progress"
            role="progressbar"
            aria-label="测速进度"
            aria-valuemin={0}
            aria-valuemax={real.length}
            aria-valuenow={doneThisRun}
          >
            <span style={{ width: `${Math.round((doneThisRun / real.length) * 100)}%` }} />
          </div>
          <div className="test-caption">
            {currentTestingNode ? `正在测：${currentTestingNode.name}` : '正在测速'}
            {' · 可随时取消，已完成的结果会保留'}
          </div>
        </div>
      )}
      {loading && (
        <div className="source-progress" role="status" aria-live="polite">
          <span className="spinner" aria-hidden="true" />
          正在拉取并解析订阅…
        </div>
      )}
      {error && (
        <div className="source-error" role="alert">
          <span>{error}</span>
          {source.url && (
            <button className="btn ghost" disabled={loading || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={() => void refresh(id)}>重试</button>
          )}
        </div>
      )}
      {expanded && !manageMode && (
        <div id={`nodes-${id}`} className={`node-list${real.length >= 12 ? ' dense' : ''}`} style={{ marginTop: 10 }}>
          {real.length > 0 && (
            <div className="node-toolbar">
              <label className="node-select">
                <input
                  ref={selectAllRef}
                  type="checkbox"
                  checked={allIncluded}
                  onChange={toggleAllNodes}
                  aria-label="全选或全不选：节点是否包含在生成的配置中"
                  title={readOnly ? READONLY_NOTE : undefined}
                  {...writeGuard(readOnly)}
                />
                <span>
                  包含在配置 <span className="num">{includedAll.length}</span>/<span className="num">{real.length}</span>
                </span>
              </label>
              <details className="legend" ref={legendRef} onToggle={updateDetailsPlacement}>
                <summary className="legend-trigger">图例</summary>
                <div className="legend-body">
                  <div className="legend-row">
                    <span className="legend-label">延迟</span>
                    <span><i style={{ background: 'var(--positive)' }} />良好 &lt;100ms</span>
                    <span><i style={{ background: 'var(--warning)' }} />一般 100–299ms</span>
                    <span><i style={{ background: 'var(--negative)' }} />较差 ≥300ms</span>
                  </div>
                  <div className="legend-row">
                    <span className="legend-label">状态</span>
                    <span><i className="swatch-untested" />未测</span>
                    <span><i className="swatch-testing" />测速中</span>
                    <span><i style={{ background: 'var(--negative)' }} />失败</span>
                    <span><i className="swatch-off" />已排除</span>
                  </div>
                  <div className="legend-row">
                    <span className="legend-label">测速</span>
                    <span><b className="num">TCP</b> 握手</span>
                    <span><b className="num">≈ ICMP</b> 近似，仅用于 UDP / QUIC，不参与延迟色阶</span>
                  </div>
                </div>
              </details>
            </div>
          )}
          {visibleNodes.some((n) => !n.isSubscriptionMetadata) && (
            <div className="node-head" aria-hidden="true">
              <span className="cb-space" />
              <span className="flag" />
              <span className="name">节点</span>
              <span className="transport">传输</span>
              <span className="latency">延迟</span>
              {showKind && <span className="kind">协议</span>}
            </div>
          )}
          {visibleNodes.map((n) => (
            <NodeRow
              key={n.id}
              node={n}
              onCountryClick={onCountryClick}
              onEditCountry={onEditCountry}
              keyword={needle}
              showKind={showKind}
            />
          ))}
          {visibleNodes.length === 0 && needle && !sourceNameMatches && (
            <div className="node-empty">该订阅里没有匹配「{keyword.trim()}」的节点</div>
          )}
        </div>
      )}
    </div>
  )
}

function SubscriptionTab({ onGo }: { onGo?: (tab: TabKey) => void }) {
  const sources = useStore((s) => s.sources)
  const loadingSourceIDs = useStore((s) => s.loadingSourceIDs)
  const refreshSource = useStore((s) => s.refreshSource)
  const setSourcesEnabled = useStore((s) => s.setSourcesEnabled)
  const allNodes = useStore((s) => s.nodes)
  const errors = useStore((s) => s.errors)
  const latencyRecord = useStore((s) => s.latencyByNodeId)
  const latencyMap = useMemo(() => new Map(Object.entries(latencyRecord)) as Map<string, number | null>, [latencyRecord])
  const probeErrors = useStore((s) => s.probeErrorByNodeId)
  const testingIds = useStore((s) => s.testingNodeIds)
  const startTesting = useStore((s) => s.startTesting)
  const stopTesting = useStore((s) => s.stopTesting)
  const renewalRemindersEnabled = useStore((s) => s.renewalRemindersEnabled)
  const setNodeDetectedCountries = useStore((s) => s.setNodeDetectedCountries)
  const readOnly = useWorkspaceStatus().readOnly
  const [adding, setAdding] = useState(false)
  const [selectedCode, setSelectedCode] = useState<string | null>(null)
  const [searchText, setSearchText] = useState('')
  const [manageMode, setManageMode] = useState(false)
  const [checkedSources, setCheckedSources] = useState<Set<string>>(new Set())
  const [pendingDelete, setPendingDelete] = useState<{ ids: string[]; label: string } | null>(null)
  const [issuesOpen, setIssuesOpen] = useState(false)
  const [flash, setFlash] = useState('')
  const [editingSource, setEditingSource] = useState<SubscriptionSource | null>(null)
  const [editingCountryNode, setEditingCountryNode] = useState<ProxyNode | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [addingManual, setAddingManual] = useState(false)
  const [manualEditor, setManualEditor] = useState<{ node?: ProxyNode } | null>(null)
  const [renamingManualNode, setRenamingManualNode] = useState<ProxyNode | null>(null)
  const [pendingManualDelete, setPendingManualDelete] = useState<ProxyNode | null>(null)
  const [batchFailures, setBatchFailures] = useState<SourceAddFailure[] | null>(null)
  const [refreshProgress, setRefreshProgress] = useState<{ done: number; total: number } | null>(null)
  const removeManualNode = useStore((s) => s.removeManualNode)

  // 视口尺寸变化后，已打开的菜单需要重新判断向下 / 向上展开。
  useEffect(() => {
    const onResize = () => placeOpenDetailsPanels()
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  // 手动「刷新全部」和打开时自动刷新都只处理启用中的 URL 订阅。
  const refreshableSources = useMemo(
    () => sources.filter((s) => s.url && isSourceEnabled(s)),
    [sources],
  )
  const refreshing = refreshableSources.some((s) => loadingSourceIDs.includes(s.id))
  const refreshAll = async () => {
    if (refreshProgress) return
    const targets = refreshableSources
    if (!targets.length) return
    let done = 0
    setRefreshProgress({ done, total: targets.length })
    await Promise.all(targets.map(async (source) => {
      try {
        await refreshSource(source.id)
      } finally {
        done += 1
        setRefreshProgress({ done, total: targets.length })
      }
    }))
    setRefreshProgress(null)
  }
  const selectedSources = sources.filter((s) => checkedSources.has(s.id))
  const selectedAllEnabled = selectedSources.length > 0 && selectedSources.every(isSourceEnabled)
  const selectedAllDisabled = selectedSources.length > 0 && selectedSources.every((s) => !isSourceEnabled(s))

  const keyword = searchText.trim().toLowerCase()
  const filteredSources = useMemo(() => {
    if (!keyword) return sources
    return sources.filter((s) => {
      if (s.name.toLowerCase().includes(keyword)) return true
      const srcNodes = allNodes.filter((n) => n.sourceID === s.id)
      return srcNodes.some((n) => nodeMatchesKeyword(n, keyword))
    })
  }, [sources, allNodes, keyword])

  const manualNodes = useMemo(
    () => allNodes.filter((node) => node.isManual),
    [allNodes],
  )
  const matchingManualNodes = useMemo(
    () => keyword ? manualNodes.filter((node) => nodeMatchesKeyword(node, keyword)) : manualNodes,
    [manualNodes, keyword],
  )
  const hasContent = sources.length > 0 || manualNodes.length > 0

  const toggleSource = (id: string) => {
    setCheckedSources((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }
  const exitManageMode = () => {
    setManageMode(false)
    setCheckedSources(new Set())
  }

  /** 只统计会进入配置的节点；排除项不参与可用数、地区和状态汇总。 */
  const enabled = useMemo(() => enabledNodes({ sources, nodes: allNodes }), [sources, allNodes])
  const poolReason = useMemo(() => {
    const sourceErrors = sources.map((source) => errors[source.id]?.trim()).filter((value): value is string => !!value)
    const excludedKeys = new Set(sources.flatMap((source) => source.excludedNodeKeys))
    const excluded = allNodes.filter((node) =>
      !node.isSubscriptionMetadata
      && (excludedKeys.has(nodeExactKey(node)) || node.isEnabled === false)).length
    return explainNodePool({
      sourceCount: sources.length,
      manualNodeCount: manualNodes.length,
      nodeCount: allNodes.filter((node) => !node.isSubscriptionMetadata).length,
      enabledNodeCount: enabled.length,
      excludedNodeCount: excluded,
      sourceErrors,
    })
  }, [sources, allNodes, enabled.length, manualNodes.length, errors])
  const enabledIds = useMemo(() => enabled.map((n) => n.id), [enabled])
  const nodeCountries = useMemo(() => {
    const set = new Set<string>()
    for (const n of enabled) {
      const r = regionForNode(n)
      if (r?.code) set.add(r.code)
    }
    return set.size
  }, [enabled])

  const health = useMemo(() => {
    const ok: ProxyNode[] = []
    const failed: ProxyNode[] = []
    const untested: ProxyNode[] = []
    const failedRegions = new Map<string, { code: string; name: string; flag: string; count: number }>()
    for (const n of enabled) {
      const latency = latencyRecord[n.id]
      if (latency === undefined) { untested.push(n); continue }
      if (latency === null) {
        failed.push(n)
        const region = regionForNode(n)
        const code = region?.code ?? '—'
        const rec = failedRegions.get(code) ?? {
          code,
          name: region?.name ?? '未知地区',
          flag: region?.flag ?? '·',
          count: 0,
        }
        rec.count++
        failedRegions.set(code, rec)
      } else {
        ok.push(n)
      }
    }
    return {
      ok,
      failed,
      untested,
      failedIds: failed.map((n) => n.id),
      failedRegions: [...failedRegions.values()].sort((a, b) => b.count - a.count),
    }
  }, [enabled, latencyRecord, probeErrors])

  const needsTest = health.untested.length > 0
  const testingAny = testingIds.length > 0
  const allHealthy = health.failed.length === 0 && health.untested.length === 0

  useEffect(() => {
    if (health.failed.length === 0) setIssuesOpen(false)
  }, [health.failed.length])

  useEffect(() => {
    if (!flash) return
    const timer = window.setTimeout(() => setFlash(''), 4200)
    return () => window.clearTimeout(timer)
  }, [flash])

  // 节点名称没有给出地区时，用本机离线 IP 库补全；按服务器缓存，刷新节点后直接复用。
  const countryByHostRef = useRef<Record<string, string>>({})
  const pendingCountryHosts = useRef<Set<string>>(new Set())
  useEffect(() => {
    const cachedByHost: Record<string, string> = {}
    const hosts = new Set<string>()
    for (const node of allNodes) {
      if (node.isSubscriptionMetadata || node.countryOverride || node.detectedCountry) continue
      if (regionForName(node.name) || !node.server) continue
      const cached = countryByHostRef.current[node.server]
      if (cached) {
        cachedByHost[node.server] = cached
        continue
      }
      if (pendingCountryHosts.current.has(node.server)) continue
      hosts.add(node.server)
    }
    if (Object.keys(cachedByHost).length > 0) setNodeDetectedCountries(cachedByHost)
    if (hosts.size === 0) return
    for (const host of hosts) pendingCountryHosts.current.add(host)
    void Promise.all([...hosts].map(async (host) => {
      try {
        const res = await apiFetch(`/api/ip-country?host=${encodeURIComponent(host)}`)
        if (!res.ok) return [host, ''] as const
        const data = await res.json() as { country?: string }
        return [host, data.country ?? ''] as const
      } catch {
        return [host, ''] as const
      }
    })).then((results) => {
      const byHost: Record<string, string> = {}
      for (const [host, country] of results) {
        if (!country) continue
        countryByHostRef.current[host] = country
        byHost[host] = country
      }
      if (Object.keys(byHost).length > 0) setNodeDetectedCountries(byHost)
    })
  }, [allNodes, setNodeDetectedCountries])

  const renewalAlerts = useMemo(() => {
    if (!renewalRemindersEnabled) return []
    const now = Date.now()
    return sources.flatMap((source) => {
      if (!isSourceEnabled(source)) return []
      const summary = subscriptionUsageSummary(source, now)
      const alerts: { id: string; name: string; text: string; tone: 'warning' | 'error' }[] = []
      if (summary.expireAt !== undefined && !summary.longTerm) {
        const days = summary.daysUntilExpiry ?? Math.ceil((summary.expireAt - now) / 86_400_000)
        if (days <= 7) {
          alerts.push({
            id: `${source.id}-expire`,
            name: source.name,
            text: days <= 0 ? '订阅已到期' : `将在 ${days} 天后到期`,
            tone: days <= 0 ? 'error' : 'warning',
          })
        }
      }
      if (summary.lowTraffic && summary.remainingRatio !== undefined) {
        const remaining = Math.round(Math.max(0, summary.remainingRatio) * 100)
        alerts.push({
          id: `${source.id}-usage`,
          name: source.name,
          text: remaining <= 0 ? '流量已用尽' : `剩余流量 ${remaining}%`,
          tone: remaining <= 0 ? 'error' : 'warning',
        })
      }
      return alerts
    })
  }, [renewalRemindersEnabled, sources])

  // 系统通知只在页面打开时能发送；同一天同一项只提醒一次。
  useEffect(() => {
    if (renewalAlerts.length === 0) return
    if (!('Notification' in window) || Notification.permission !== 'granted') return
    // 用本地日期而不是 UTC：UTC 跨日会让同一条提醒在本地同一天内重复两次。
    const day = new Date().toLocaleDateString('en-CA')
    for (const alert of renewalAlerts) {
      const key = `tower-renewal-notified:${alert.id}:${day}`
      if (localPrefs.getItem(key)) continue
      try {
        new Notification(`塔台 · ${alert.name}`, { body: alert.text, tag: alert.id })
        localPrefs.setItem(key, '1')
      } catch {
        // 浏览器不允许构造通知时保留应用内提示即可。
      }
    }
  }, [renewalAlerts])

  // 全局测速时显示「正在测哪一个」，让进度有上下文。
  const testingNode = useMemo(() => {
    if (!testingIds.length) return undefined
    const inFlight = testingIds.find((id) => latencyRecord[id] === undefined)
    return allNodes.find((n) => n.id === (inFlight ?? testingIds[0]))
  }, [testingIds, latencyRecord, allNodes])

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">订阅与节点 · 01</div>
          <h1>管理订阅与节点</h1>
          <div className="sub">添加订阅或自有节点、测速，并决定哪些节点进入配置</div>
        </div>
        <div className="row page-actions" style={{ gap: 8 }}>
          {sources.length > 0 && !manageMode && (
            <button className="btn ghost" onClick={() => setSettingsOpen(true)}>订阅设置</button>
          )}
          {sources.length > 0 && !manageMode && (
            <button className="btn ghost" onClick={() => setManageMode(true)}>管理</button>
          )}
          {manageMode && (
            <>
              <button
                className="btn ghost"
                onClick={() => {
                  setCheckedSources(
                    checkedSources.size === sources.length
                      ? new Set()
                      : new Set(sources.map((s) => s.id)),
                  )
                }}
              >
                {checkedSources.size === sources.length && sources.length > 0 ? '取消全选' : '全选'}
              </button>
              {checkedSources.size > 0 && <span className="select-count">已选 <b>{checkedSources.size}</b></span>}
              {checkedSources.size > 0 && (
                <button
                  className="btn"
                  disabled={selectedAllEnabled || readOnly}
                  title={readOnly ? READONLY_NOTE : undefined}
                  onClick={() => {
                    setSourcesEnabled([...checkedSources], true)
                    setFlash(`已启用 ${checkedSources.size} 个订阅。`)
                  }}
                >启用选中</button>
              )}
              {checkedSources.size > 0 && (
                <button
                  className="btn"
                  disabled={selectedAllDisabled || readOnly}
                  title={readOnly ? READONLY_NOTE : undefined}
                  onClick={() => {
                    setSourcesEnabled([...checkedSources], false)
                    setFlash(`已停用 ${checkedSources.size} 个订阅，节点不会再进入配置。`)
                  }}
                >停用选中</button>
              )}
              {checkedSources.size > 0 && (
                <button
                  className="btn danger"
                  {...writeGuard(readOnly)}
                  onClick={() => setPendingDelete({ ids: [...checkedSources], label: `${checkedSources.size} 个订阅` })}
                >删除选中</button>
              )}
              <button className="btn ghost" onClick={exitManageMode}>取消</button>
            </>
          )}
          {!manageMode && (
            <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setAddingManual(true)}>+ 自有节点</button>
          )}
          {!manageMode && hasContent && (
            <button className="btn primary" {...writeGuard(readOnly)} onClick={() => setAdding(true)}>+ 添加订阅</button>
          )}
        </div>
      </div>

      {flash && <div className="flash" role="status" aria-live="polite">{flash}</div>}

      {batchFailures && (
        <div className="batch-report" role="alert">
          <div className="batch-report-head">
            <strong>部分内容未添加</strong>
            <button className="btn ghost" onClick={() => setBatchFailures(null)}>关闭</button>
          </div>
          <ul>
            {batchFailures.map((failure, index) => (
              <li key={`${failure.label}-${index}`}>
                <span>{failure.label}</span>
                <small>{failure.message}</small>
              </li>
            ))}
          </ul>
        </div>
      )}

      {hasContent && poolReason.code !== 'ready' && (
        <div className={`pool-reason${poolReason.code === 'source-error' ? ' is-error' : ''}`}>
          <div className="pool-reason-body">
            <strong>{poolReason.title}</strong>
            <span>{poolReason.detail}</span>
            <div className="pool-reason-actions">
              {poolReason.action === 'retry-source' && (
                <button
                  className="btn"
                  {...writeGuard(readOnly)}
                  onClick={() => {
                    const ids = sources.filter((source) => isSourceEnabled(source)).map((source) => source.id)
                    if (ids.length) void Promise.all(ids.map((id) => refreshSource(id)))
                  }}
                >刷新全部订阅</button>
              )}
              {poolReason.action === 'enable-nodes' && (
                <button className="btn" onClick={() => setManageMode(true)}>管理订阅与节点</button>
              )}
              {poolReason.action === 'add-source' && (
                <button className="btn" {...writeGuard(readOnly)} onClick={() => setAdding(true)}>+ 添加订阅</button>
              )}
              <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setAddingManual(true)}>+ 自有节点</button>
            </div>
          </div>
        </div>
      )}

      {renewalAlerts.length > 0 && (
        <div className="renewal-alert" role="status">
          <div className="renewal-alert-title">订阅提醒</div>
          <div className="renewal-alert-list">
            {renewalAlerts.map((alert) => (
              <span key={alert.id} className={`renewal-alert-item ${alert.tone}`}>
                <b>{alert.name}</b> {alert.text}
              </span>
            ))}
          </div>
          <button className="btn ghost" onClick={() => setSettingsOpen(true)}>订阅设置</button>
        </div>
      )}

      {hasContent && (
        <div className="stat-strip" role="list">
          <div className="stat-cell" role="listitem">
            <span className="stat-label">订阅</span>
            <span className="stat-value num">{sources.length}</span>
          </div>
          {manualNodes.length > 0 && (
            <div className="stat-cell" role="listitem">
              <span className="stat-label">自有节点</span>
              <span className="stat-value num">{manualNodes.length}</span>
            </div>
          )}
          <div className="stat-cell" role="listitem">
            <span className="stat-label">可用节点</span>
            <span className="stat-value num">{enabled.length}</span>
          </div>
          <div className="stat-cell" role="listitem">
            <span className="stat-label">地区</span>
            <span className="stat-value num">{nodeCountries}</span>
          </div>
        </div>
      )}

      {enabled.length > 0 && (
        <section className={`health-bar${testingAny ? ' is-testing' : ''}`} aria-label="节点健康状态">
          <div className="health-main">
            <div className="health-kicker">节点健康</div>
            <div className="health-title">
              <strong>{enabled.length}</strong>
              <span>个节点已启用</span>
            </div>
            <div className="health-counts" aria-live="polite">
              <span className="health-status ok"><i aria-hidden="true" />正常 <b>{health.ok.length}</b></span>
              <span className="health-status bad"><i aria-hidden="true" />异常 <b>{health.failed.length}</b></span>
              <span className="health-status unknown"><i aria-hidden="true" />未测 <b>{health.untested.length}</b></span>
            </div>
            {health.failedRegions.length > 0 && (
              <div className="health-regions">
                <span className="health-regions-label">异常地区</span>
                {health.failedRegions.map((r) => (
                  <span className="region-chip" key={r.code}>
                    <span aria-hidden="true">{r.flag}</span>
                    {r.name} <b>{r.count}</b>
                  </span>
                ))}
              </div>
            )}
            {testingAny && (
              <div className="health-testing">
                <span className="spinner" aria-hidden="true" />
                {testingNode ? `正在测：${testingNode.name}` : '正在测速'}
                <span> · 剩余 {testingIds.length} 个</span>
              </div>
            )}
            {!testingAny && allHealthy && (
              <div className="health-message ok">全部节点正常，可以导出配置。</div>
            )}
            {!testingAny && !allHealthy && health.failed.length > 0 && (
              <div className="health-message bad">有节点不可达，查看异常或重测失败节点。</div>
            )}
          </div>
          <div className="health-actions">
            <button
              className={`btn ${testingAny || needsTest ? 'primary' : ''}`}
              onClick={() => {
                if (testingAny) stopTesting()
                else startTesting(enabledIds)
              }}
            >
              {testingAny ? '取消测速' : needsTest ? '全部测速' : '重新测速'}
            </button>
            {health.failed.length > 0 && (
              <button
                className="btn"
                aria-expanded={issuesOpen}
                aria-controls="health-issues"
                onClick={() => setIssuesOpen((v) => !v)}
              >
                {issuesOpen ? '收起异常' : `查看异常 (${health.failed.length})`}
              </button>
            )}
            <button
              className={`btn ${!testingAny && !needsTest ? 'primary' : 'ghost'}`}
              onClick={() => onGo?.('export')}
            >
              去导出
            </button>
          </div>
          {issuesOpen && health.failed.length > 0 && (
            <div className="health-issues" id="health-issues">
              <div className="health-issue-head">
                <span>异常节点</span>
                <button
                  className="btn ghost"
                  disabled={testingAny}
                  onClick={() => startTesting(health.failedIds)}
                >
                  重测失败节点
                </button>
              </div>
              <ul>
                {health.failed.slice(0, 8).map((n) => (
                  <li key={n.id}>
                    <span className="issue-name">{n.name}</span>
                    <code>{probeErrors[n.id] ?? '不可达'}</code>
                  </li>
                ))}
              </ul>
              {health.failed.length > 8 && (
                <div className="health-issues-more">还有 {health.failed.length - 8} 个异常节点，已在地图和订阅列表中标记。</div>
              )}
            </div>
          )}
        </section>
      )}

      {hasContent && enabled.length === 0 && (
        <div className="source-off-note global" role="status">
          当前没有会进入配置的节点：请启用订阅或自有节点，或在订阅里勾选至少一个节点。
        </div>
      )}

      {hasContent && (
        <div className="list-tools">
          <div className="search-wrap">
            <input
              className="input"
              aria-label="搜索订阅与节点"
              placeholder="搜索订阅、节点名称、服务器或协议…"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
            />
            {searchText && (
              <button className="search-clear" aria-label="清空搜索" onClick={() => setSearchText('')}>×</button>
            )}
          </div>
          {refreshableSources.length > 0 && (
            <button
              className="btn ghost refresh-all"
              onClick={() => void refreshAll()}
              disabled={refreshing || !!refreshProgress || readOnly}
              title={readOnly ? READONLY_NOTE : undefined}
            >
              {refreshProgress
                ? `刷新中… ${refreshProgress.done}/${refreshProgress.total}`
                : refreshing ? '刷新中…' : `刷新全部（${refreshableSources.length}）`}
            </button>
          )}
        </div>
      )}

      {!hasContent && (
        <section className="first-run" aria-labelledby="first-run-title">
          <div className="first-run-copy">
            <div className="first-run-kicker">第一次使用</div>
            <h2 id="first-run-title">从一条订阅开始</h2>
            <p className="first-run-lead-p">
              粘贴订阅地址、节点内容或一条 <span className="mono">ss://</span> 链接。
              塔台在本机完成拉取、解析、测速与配置生成。
            </p>
            <div className="first-run-action">
              <button className="btn primary first-run-cta" {...writeGuard(readOnly)} onClick={() => setAdding(true)}>
                + 添加订阅
              </button>
              <span className="first-run-hint">只需要这一步</span>
            </div>
            <p className="local-note">
              <i aria-hidden="true" />
              订阅和节点只在本机处理，不上传第三方服务。
            </p>
            <div className="first-run-later" aria-label="订阅后的后续步骤">
              <span className="later-label">订阅之后</span>
              <span className="later-step"><b>02</b> 规则方案 <em>可选</em></span>
              <span className="later-arrow">→</span>
              <span className="later-step"><b>03</b> 导出 / 发布</span>
            </div>
          </div>
          <div className="first-run-visual">
            <RouteIllustration />
            <div className="route-legend">
              <span>示意图</span><span>·</span><span>订阅源</span><span>→</span><span>本地解析</span><span>→</span><span>节点</span><span>→</span><span>导出</span>
            </div>
          </div>
          <div className="first-run-foot">
            <span>支持 {CLIENTS.length} 种客户端</span>
            <span>·</span>
            <span>无需账号</span>
            <span>·</span>
            <span>本机处理</span>
          </div>
        </section>
      )}

      {filteredSources.length === 0 && matchingManualNodes.length === 0 && hasContent && (
        <div className="empty">
          没有匹配「{searchText}」的订阅或节点
          <button className="btn ghost" style={{ marginLeft: 10 }} onClick={() => setSearchText('')}>清空搜索</button>
        </div>
      )}

      {filteredSources.map((s) => (
        <SourceCard
          key={s.id}
          id={s.id}
          keyword={searchText}
          onCountryClick={setSelectedCode}
          onEditCountry={setEditingCountryNode}
          manageMode={manageMode}
          checked={checkedSources.has(s.id)}
          onToggleChecked={() => toggleSource(s.id)}
          onRequestDelete={(id, name) => setPendingDelete({ ids: [id], label: `「${name}」` })}
          onEdit={() => setEditingSource(s)}
        />
      ))}
      {manualNodes.length > 0 && (
        <ManualNodesCard
          nodes={manualNodes}
          keyword={searchText}
          onCountryClick={setSelectedCode}
          onEditCountry={setEditingCountryNode}
          onAdd={() => setAddingManual(true)}
          onCreate={() => setManualEditor({})}
          onEditNode={(node) => setManualEditor({ node })}
          onRename={setRenamingManualNode}
          onRequestDelete={setPendingManualDelete}
        />
      )}
      <AddSourceDialog
        open={adding}
        onClose={() => setAdding(false)}
        onAdded={(result) => {
          setFlash(`${result.name || '订阅'}：解析到 ${result.count} 个节点，已加入配置池。`)
          setBatchFailures(result.failures?.length ? result.failures : null)
        }}
      />
      <AddManualNodesDialog
        open={addingManual}
        onClose={() => setAddingManual(false)}
        onManualCreate={() => setManualEditor({})}
        onAdded={(result) => {
          const parts = [`已添加 ${result.nodes.length} 个自有节点`]
          if (result.duplicates > 0) parts.push(`跳过 ${result.duplicates} 个重复节点`)
          if (result.rejected > 0) parts.push(`${result.rejected} 行无法识别`)
          setFlash(`${parts.join('；')}。`)
        }}
      />
      {manualEditor && (
        <ManualNodeEditorDialog
          key={manualEditor.node?.id ?? 'new-manual-node'}
          node={manualEditor.node}
          onClose={() => setManualEditor(null)}
          onSaved={setFlash}
        />
      )}
      {renamingManualNode && (
        <RenameManualNodeDialog
          key={renamingManualNode.id}
          node={renamingManualNode}
          onClose={() => setRenamingManualNode(null)}
          onSaved={setFlash}
        />
      )}
      {editingSource && (
        <EditSourceDialog
          key={editingSource.id}
          source={editingSource}
          onClose={() => setEditingSource(null)}
          onSaved={setFlash}
        />
      )}
      <SubscriptionSettingsDialog
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        onRestored={(message) => {
          setSettingsOpen(false)
          setFlash(message)
        }}
      />
      <NodeCountryDialog
        node={editingCountryNode}
        onClose={() => setEditingCountryNode(null)}
      />

      {/* 地图只展示会进入配置的节点；所有节点被排除时不占用首屏 */}
      {enabled.length > 0 && (
        <div className="card">
          <div className="card-head">
            <h3>全球节点分布</h3>
            <div className="meta">
              {selectedCode ? `选中：${selectedCode} · 点击空白取消` : '缩放 / 拖动 / 点击地区查看节点'}
            </div>
          </div>
          <Suspense fallback={<div className="hint">地图加载中…</div>}>
            <WorldMapSVG
              nodes={enabled}
              latencyByNodeId={latencyMap}
              selectedCode={selectedCode}
              onSelect={setSelectedCode}
              testing={testingAny}
              onTest={() => {
                if (testingAny) stopTesting()
                else startTesting(enabledIds)
              }}
            />
          </Suspense>
        </div>
      )}

      <ConfirmDialog
        open={!!pendingDelete}
        title="删除订阅？"
        body={<>将删除 <b>{pendingDelete?.label}</b> 及其全部节点，生成的配置会立即少掉这些节点。该操作不可撤销。</>}
        confirmLabel="删除"
        danger
        confirmDisabled={readOnly}
        onCancel={() => setPendingDelete(null)}
        onConfirm={() => {
          const ids = pendingDelete?.ids ?? []
          setPendingDelete(null)
          ids.forEach((id) => useStore.getState().removeSource(id))
          exitManageMode()
        }}
      />

      <ConfirmDialog
        open={!!pendingManualDelete}
        title="删除自有节点？"
        body={<>将从导出配置中移除 <b>{pendingManualDelete?.name}</b>。订阅里的同名节点不受影响，该操作不可撤销。</>}
        confirmLabel="删除"
        danger
        confirmDisabled={readOnly}
        onCancel={() => setPendingManualDelete(null)}
        onConfirm={() => {
          const node = pendingManualDelete
          setPendingManualDelete(null)
          if (!node) return
          removeManualNode(node.id)
          setFlash(`已删除自有节点「${node.name}」。`)
        }}
      />
    </div>
  )
}

// ---------------- 规则 Tab ----------------

// ---------------- 规则管理弹窗 ----------------

const RULE_TYPE_OPTIONS: { value: string; label: string; placeholder: string; ip?: boolean }[] = [
  { value: 'DOMAIN', label: '完整域名', placeholder: 'example.com' },
  { value: 'DOMAIN-SUFFIX', label: '域名后缀', placeholder: 'example.com' },
  { value: 'DOMAIN-KEYWORD', label: '域名关键词', placeholder: 'youtube' },
  { value: 'IP-CIDR', label: 'IPv4 网段', placeholder: '192.168.1.0/24', ip: true },
  { value: 'IP-CIDR6', label: 'IPv6 网段', placeholder: '2001:db8::/32', ip: true },
  { value: 'GEOIP', label: '国家 / 地区代码', placeholder: 'CN' },
]

function policyTypeLabel(type: PolicyGroup['type']): string {
  switch (type) {
    case 'select': return '手动选择'
    case 'url-test': return '自动测速'
    case 'smart': return '智能选择'
    case 'fallback': return '故障转移'
    case 'load-balance': return '负载均衡'
    case 'conditional': return '按网络选择'
    case 'relay': return '链式代理'
    case 'unsupported': return '未知策略'
    default: return type
  }
}

interface RuleLibraryEntry {
  id: string
  file?: string
  title: string
  category: string
  provider: string
  online: boolean
  sourceURL?: string
  aliases?: string[]
}

/** ACL4SSR 规则快照目录；规则文件随塔台打包，离线可用。 */
const BUNDLED_RULE_LIBRARY: { file: string; title: string; category: string }[] = [
  { file: 'ACL4SSR_BanAD.list', title: '广告拦截', category: '广告与净化' },
  { file: 'ACL4SSR_BanProgramAD.list', title: '应用内广告', category: '广告与净化' },
  { file: 'ACL4SSR_UnBan.list', title: '误杀放行', category: '广告与净化' },
  { file: 'ACL4SSR_ProxyGFWlist.list', title: 'GFW 代理列表', category: '代理分流' },
  { file: 'ACL4SSR_ProxyLite.list', title: '代理精简列表', category: '代理分流' },
  { file: 'ACL4SSR_ProxyMedia.list', title: '媒体代理列表', category: '代理分流' },
  { file: 'ACL4SSR_ChinaDomain.list', title: '国内域名', category: '国内与直连' },
  { file: 'ACL4SSR_ChinaCompanyIp.list', title: '国内公司 IP', category: '国内与直连' },
  { file: 'ACL4SSR_LocalAreaNetwork.list', title: '局域网地址', category: '国内与直连' },
  { file: 'ACL4SSR_Apple.list', title: 'Apple 服务', category: '厂商服务' },
  { file: 'ACL4SSR_Microsoft.list', title: 'Microsoft 服务', category: '厂商服务' },
  { file: 'ACL4SSR_GoogleCN.list', title: 'Google 中国', category: '厂商服务' },
  { file: 'ACL4SSR_OneDrive.list', title: 'OneDrive', category: '厂商服务' },
  { file: 'ACL4SSR_Bing.list', title: 'Bing', category: '厂商服务' },
  { file: 'ACL4SSR_Download.list', title: '下载服务', category: '厂商服务' },
  { file: 'ACL4SSR_Telegram.list', title: 'Telegram', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_GoogleFCM.list', title: 'Google FCM', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_AI.list', title: 'AI 服务', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_OpenAi.list', title: 'OpenAI', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_Netflix.list', title: 'Netflix', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_YouTube.list', title: 'YouTube', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_Bilibili.list', title: '哔哩哔哩', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_BilibiliHMT.list', title: '哔哩哔哩港澳台', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_Steam.list', title: 'Steam', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_SteamCN.list', title: 'Steam 国区', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_Epic.list', title: 'Epic Games', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_Nintendo.list', title: 'Nintendo', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_Sony.list', title: 'Sony', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_Bahamut.list', title: '巴哈姆特', category: '媒体与服务' },
  { file: 'ACL4SSR_Ruleset_NetEaseMusic.list', title: '网易云音乐', category: '媒体与服务' },
]

const RULE_LIBRARY: RuleLibraryEntry[] = [
  ...BUNDLED_RULE_LIBRARY.map((entry) => ({
    id: entry.file,
    file: entry.file,
    title: entry.title,
    category: entry.category,
    provider: '内置快照',
    online: false,
  })),
  ...ONLINE_RULE_CATALOG.map((entry) => ({
    id: entry.id,
    title: entry.title,
    category: entry.category,
    provider: entry.provider,
    online: true,
    sourceURL: entry.sourceURL,
    aliases: entry.aliases,
  })),
]

const ruleLibraryRules = new Map<string, RuleSetRule[]>()
const ruleLibraryRequests = new Map<string, Promise<RuleSetRule[]>>()

async function loadBundledRuleSet(file: string): Promise<RuleSetRule[]> {
  const cached = ruleLibraryRules.get(file)
  if (cached) return cached
  const pending = ruleLibraryRequests.get(file)
  if (pending) return pending
  const request = fetch(`/rulesets/${encodeURIComponent(file)}`).then(async (res) => {
    if (!res.ok) throw new Error(`规则集加载失败：HTTP ${res.status}`)
    const rules = parseRuleList(await res.text())
    ruleLibraryRules.set(file, rules)
    ruleLibraryRequests.delete(file)
    return rules
  }).catch((error) => {
    ruleLibraryRequests.delete(file)
    throw error
  })
  ruleLibraryRequests.set(file, request)
  return request
}

function ruleSetLine(rule: RuleSetRule): string {
  if (rule.type === 'FINAL') return 'FINAL'
  if (rule.raw) return rule.raw
  const options = rule.options?.length
    ? [...rule.options]
    : rule.noResolve ? ['no-resolve'] : []
  return [rule.type, rule.value ?? '', ...options].join(',')
}

function SchemeEditDialog({
  scheme,
  onClose,
  onSave,
}: {
  scheme: RuleScheme
  onClose: () => void
  onSave: (next: RuleScheme) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const readOnly = useWorkspaceStatus().readOnly
  const [name, setName] = useState(scheme.name)
  const [description, setDescription] = useState(scheme.description)
  const [error, setError] = useState('')

  useEffect(() => { ref.current?.showModal() }, [])

  const save = () => {
    if (!name.trim()) {
      setError('请填写方案名称')
      return
    }
    onSave({ ...scheme, name: name.trim(), description: description.trim() })
    ref.current?.close()
  }

  return (
    <dialog ref={ref} onClose={onClose}>
      <h3>编辑规则方案</h3>
      <form className="dialog-form" onSubmit={(e) => { e.preventDefault(); save() }}>
        <div className="field">
          <label>方案名称</label>
          <input type="text" className="field" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </div>
        <div className="field">
          <label>说明</label>
          <textarea className="field" rows={3} value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        {scheme.sourceURL && (
          <div className="hint">来源地址：<span className="mono">{scheme.sourceURL}</span></div>
        )}
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          <button type="submit" className="btn primary" {...writeGuard(readOnly)}>保存</button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

function SchemeTextDialog({
  scheme,
  onClose,
  onSave,
}: {
  scheme: RuleScheme
  onClose: () => void
  onSave: (text: string) => Promise<string | undefined>
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const readOnly = useWorkspaceStatus().readOnly
  const [text, setText] = useState(scheme.rawConfigurationText ?? '')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => { ref.current?.showModal() }, [])

  const save = async () => {
    setBusy(true)
    setError('')
    const message = await onSave(text)
    setBusy(false)
    if (message) setError(message)
    else ref.current?.close()
  }

  return (
    <dialog ref={ref} className="scheme-text-dialog" onClose={onClose}>
      <h3>编辑方案全文</h3>
      <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); void save() }}>
        <div className="hint">
          文本来自最近一次导入或刷新。保存会按文本重建策略组和方案规则，自定义规则与已加入的规则集会尽量保留。
          如果之后在表单里改过策略组，文本可能尚未同步。
        </div>
        <textarea
          className="field mono scheme-text-area"
          rows={18}
          value={text}
          onChange={(event) => { setText(event.target.value); setError('') }}
          spellCheck={false}
        />
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy || !text.trim() || readOnly} title={readOnly ? READONLY_NOTE : undefined}>
            {busy ? '解析中…' : '保存全文'}
          </button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

function AddCustomRuleDialog({
  scheme,
  initialGroup,
  onClose,
  onSave,
}: {
  scheme: RuleScheme
  initialGroup?: string
  onClose: () => void
  onSave: (rule: RoutingRule) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const firstGroup = scheme.groups.find((g) => g.name === initialGroup)?.name ?? scheme.groups[0]?.name ?? ''
  const [group, setGroup] = useState(firstGroup)
  const [type, setType] = useState('DOMAIN-SUFFIX')
  const [value, setValue] = useState('')
  const [noResolve, setNoResolve] = useState(false)
  const [error, setError] = useState('')
  const readOnly = useWorkspaceStatus().readOnly
  const typeInfo = RULE_TYPE_OPTIONS.find((t) => t.value === type) ?? RULE_TYPE_OPTIONS[0]
  const impactPreview = value.trim()
    ? analyzeRuleImpact(
        scheme,
        { type, value: value.trim(), group, ...(typeInfo.ip && noResolve ? { noResolve: true } : {}) },
        { includeCandidate: true },
      )
    : null

  useEffect(() => { ref.current?.showModal() }, [])

  const save = () => {
    if (!group) { setError('方案里没有可用的策略组'); return }
    let normalized = value.trim()
    if (!normalized) { setError('请填写规则内容'); return }

    if (/^https?:\/\//i.test(normalized)) {
      try { normalized = new URL(normalized).hostname } catch { /* 保留原文本，让下面的格式校验给出错误 */ }
    }
    if (type === 'DOMAIN' || type === 'DOMAIN-SUFFIX') {
      normalized = normalized.toLowerCase()
      if (!/^[a-z0-9._-]+$/.test(normalized)) {
        setError('域名只能包含字母、数字、点、下划线和连字符')
        return
      }
    } else if (type === 'GEOIP') {
      normalized = normalized.toUpperCase()
      if (!/^[A-Z]{2}$/.test(normalized)) {
        setError('GEOIP 需要两位国家或地区代码，例如 CN')
        return
      }
    } else if (type === 'IP-CIDR' || type === 'IP-CIDR6') {
      const v4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
      const v6 = /^[0-9a-f:]+(\/\d{1,3})?$/i
      const octetsValid = type === 'IP-CIDR'
        ? normalized.split('/')[0].split('.').map(Number).every((n) => n >= 0 && n <= 255)
        : true
      if (type === 'IP-CIDR' ? (!v4.test(normalized) || !octetsValid) : (!v6.test(normalized) || !normalized.includes(':'))) {
        setError(type === 'IP-CIDR' ? '请输入有效的 IPv4 地址或 CIDR 网段' : '请输入有效的 IPv6 地址或 CIDR 网段')
        return
      }
      const prefix = normalized.includes('/') ? Number(normalized.split('/')[1]) : (type === 'IP-CIDR' ? 32 : 128)
      if ((type === 'IP-CIDR' && prefix > 32) || (type === 'IP-CIDR6' && prefix > 128)) {
        setError('CIDR 前缀长度超出范围')
        return
      }
    }

    const duplicate = (scheme.customRules ?? []).some(
      (r) => r.group === group && r.type === type && (r.value ?? '').toLowerCase() === normalized.toLowerCase(),
    )
    if (duplicate) {
      setError('这个策略组里已经有相同的自定义规则')
      return
    }

    onSave({
      type,
      value: normalized,
      group,
      ...(typeInfo.ip && noResolve ? { noResolve: true } : {}),
    })
    ref.current?.close()
  }

  return (
    <dialog ref={ref} onClose={onClose}>
      <h3>添加自定义规则</h3>
      <form className="dialog-form" onSubmit={(e) => { e.preventDefault(); save() }}>
        <div className="field">
          <label>策略组</label>
          <select className="input" value={group} onChange={(e) => setGroup(e.target.value)}>
            {scheme.groups.map((g) => <option key={g.name} value={g.name}>{groupDisplayName(g.name)}</option>)}
          </select>
        </div>
        <div className="field">
          <label>匹配方式</label>
          <select className="input" value={type} onChange={(e) => { setType(e.target.value); setNoResolve(false) }}>
            {RULE_TYPE_OPTIONS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        </div>
        <div className="field">
          <label>规则内容</label>
          <input
            type="text"
            className="field mono"
            value={value}
            placeholder={typeInfo.placeholder}
            onChange={(e) => setValue(e.target.value)}
            autoFocus
          />
          {(type === 'DOMAIN' || type === 'DOMAIN-SUFFIX') && <div className="hint">可以直接粘贴网址，会自动取出域名。</div>}
        </div>
        {typeInfo.ip && (
          <label className="check-line">
            <input type="checkbox" checked={noResolve} onChange={(e) => setNoResolve(e.target.checked)} />
            不解析 DNS（no-resolve）
          </label>
        )}
        <div className="local-note">
          <i aria-hidden="true" />
          自定义规则会排在方案自带规则最前，优先匹配。
        </div>
        {impactPreview && (
          <div className="rule-impact" role="status">
            <strong>影响面预览（保存后）</strong>
            <small>{ruleImpactText(impactPreview)}</small>
          </div>
        )}
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          <button type="submit" className="btn primary" {...writeGuard(readOnly)}>添加规则</button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

/** 显式候选选择区：策略组 / 内置策略 / 节点三块，共用给新建与编辑对话框。 */
function GroupCandidatePicker({
  scheme,
  groupName,
  originalName,
  type,
  selected,
  matchedNodeNames,
  readOnly,
  onChange,
}: {
  scheme: RuleScheme
  groupName: string
  /** 编辑时正在改名的组原名；候选里要排除它，避免把自己加进去。 */
  originalName?: string
  type: PolicyGroup['type']
  selected: string[]
  matchedNodeNames: string[]
  readOnly: boolean
  onChange: (next: string[]) => void
}) {
  const referenceGroups = scheme.groups
    .filter((group) => group.name !== groupName && group.name !== originalName)
    .map((group) => group.name)
  const autoWarning = autoGroupReferenceWarning(type, selected, referenceGroups)
  const label = (name: string) => groupDisplayName(name, true)
  const toggle = (name: string) => {
    if (readOnly) return
    onChange(selected.includes(name)
      ? selected.filter((option) => option !== name)
      : [...selected, name])
  }
  const move = (index: number, delta: number) => {
    if (readOnly) return
    const to = index + delta
    if (to < 0 || to >= selected.length) return
    const next = [...selected]
    const [item] = next.splice(index, 1)
    next.splice(to, 0, item)
    onChange(next)
  }
  return (
    <div className="candidate-picker">
      <div className="candidate-list">
        {selected.length === 0 && <span className="hint">还没有显式候选；节点可通过名称匹配进入。</span>}
        {selected.map((option, index) => (
          <span className="candidate-chip" key={option}>
            {type === 'select' && <span className="candidate-order">{index + 1}</span>}
            {label(option)}
            <button
              type="button"
              aria-label={`上移候选 ${option}`}
              disabled={readOnly || index === 0}
              title={index === 0 ? '已经是第一项' : readOnly ? READONLY_NOTE : '上移'}
              onClick={() => move(index, -1)}
            >↑</button>
            <button
              type="button"
              aria-label={`下移候选 ${option}`}
              disabled={readOnly || index === selected.length - 1}
              title={readOnly ? READONLY_NOTE : '下移'}
              onClick={() => move(index, 1)}
            >↓</button>
            <button
              type="button"
              aria-label={`移除候选 ${option}`}
              {...writeGuard(readOnly)}
              onClick={() => toggle(option)}
            >×</button>
          </span>
        ))}
      </div>
      {type === 'select' && selected.length > 0 && (
        <div className="hint">第一项「{label(selected[0])}」是默认选中；顺序会影响客户端里的默认策略。</div>
      )}
      {autoWarning && (
        <div className="hint is-error">{autoWarning}</div>
      )}
      <div className="candidate-section">
        <div className="candidate-section-title">策略组</div>
        <div className="candidate-list">
          {referenceGroups.length === 0 && <span className="hint">当前方案还没有其他策略组。</span>}
          {referenceGroups.map((name) => (
            <button
              type="button"
              key={name}
              className={`candidate-pick${selected.includes(name) ? ' is-on' : ''}`}
              aria-pressed={selected.includes(name)}
              {...writeGuard(readOnly)}
              onClick={() => toggle(name)}
            >{selected.includes(name) ? '✓ ' : '+ '}{label(name)}</button>
          ))}
        </div>
      </div>
      <div className="candidate-section">
        <div className="candidate-section-title">内置直连与拦截</div>
        <div className="candidate-list">
          {['DIRECT', 'REJECT'].map((name) => (
            <button
              type="button"
              key={name}
              className={`candidate-pick${selected.includes(name) ? ' is-on' : ''}`}
              aria-pressed={selected.includes(name)}
              {...writeGuard(readOnly)}
              onClick={() => toggle(name)}
            >{selected.includes(name) ? '✓ ' : '+ '}{name}</button>
          ))}
        </div>
      </div>
      <div className="candidate-section">
        <div className="candidate-section-title">节点（由名称匹配进入）</div>
        <div className="candidate-list">
          {matchedNodeNames.slice(0, 8).map((name) => (
            <span className="candidate-chip" key={name}>{name}</span>
          ))}
          {matchedNodeNames.length > 8 && <span className="hint">另有 {matchedNodeNames.length - 8} 个</span>}
          {matchedNodeNames.length === 0 && <span className="hint">当前名称匹配没有命中节点。</span>}
        </div>
      </div>
    </div>
  )
}

function GroupEditorDialog({
  scheme,
  group,
  nodes,
  rules,
  customRules,
  initialTab = 'settings',
  initialRuleQuery = '',
  onClose,
  onSave,
  onAddRule,
}: {
  scheme: RuleScheme
  group: PolicyGroup
  nodes: ProxyNode[]
  rules: RoutingRule[]
  customRules: RoutingRule[]
  initialTab?: 'settings' | 'rules'
  initialRuleQuery?: string
  onClose: () => void
  onSave: (updated: PolicyGroup) => void
  onAddRule: (rule: RoutingRule) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const readOnly = useWorkspaceStatus().readOnly
  const [name, setName] = useState(group.name)
  const [type, setType] = useState<PolicyGroup['type']>(group.type)
  const [options, setOptions] = useState<string[]>(group.options)
  const [nodeFilter, setNodeFilter] = useState(group.nodeFilter ?? '')
  const [url, setURL] = useState(group.url ?? '')
  const [algorithm, setAlgorithm] = useState(group.algorithm ?? '')
  const [interval, setInterval] = useState(group.interval ? String(group.interval) : '')
  const [tolerance, setTolerance] = useState(group.tolerance ? String(group.tolerance) : '')
  const [error, setError] = useState('')
  const [tab, setTab] = useState<'settings' | 'rules'>(initialTab)
  const [ruleSearch, setRuleSearch] = useState(initialRuleQuery)
  const [newDomain, setNewDomain] = useState('')
  const [ruleNotice, setRuleNotice] = useState('')
  const [addedRules, setAddedRules] = useState<RoutingRule[]>([])

  useEffect(() => { ref.current?.showModal() }, [])

  const trimmedFilter = nodeFilter.trim()
  let filterError = ''
  let matchedNodeNames: string[] = []
  if (trimmedFilter) {
    try {
      const regex = new RegExp(trimmedFilter)
      matchedNodeNames = nodes.filter((node) => regex.test(node.name)).map((node) => node.name)
    } catch {
      filterError = '节点名称匹配不是有效的正则表达式'
    }
  }

  const groupRules = rules.filter((rule) => rule.group === group.name)
  const groupCustomRules = [
    ...customRules.filter((rule) => rule.group === group.name),
    ...addedRules,
  ]
  const ruleQuery = ruleSearch.trim().toLowerCase()
  const visibleCustomRules = groupCustomRules.filter(
    (rule) => !ruleQuery || `${rule.type} ${rule.value ?? ''} ${rule.sourceName ?? ''}`.toLowerCase().includes(ruleQuery),
  )
  const visibleRules = groupRules.filter(
    (rule) => !ruleQuery || `${rule.type} ${rule.value ?? ''} ${rule.sourceName ?? ''}`.toLowerCase().includes(ruleQuery),
  )
  const totalGroupRules = groupCustomRules.length + groupRules.length
  const visibleGroupRules = [...visibleCustomRules.map((rule) => ({ rule, custom: true })), ...visibleRules.map((rule) => ({ rule, custom: false }))]
    .slice(0, 200)

  const addDomainRule = () => {
    if (readOnly) return
    let value = newDomain.trim()
    if (!value) { setRuleNotice('请填写要加入这个组的域名'); return }
    if (/^https?:\/\//i.test(value)) {
      try { value = new URL(value).hostname } catch { /* 保留原文本，交给格式校验 */ }
    }
    value = value.toLowerCase()
    if (!/^[a-z0-9._-]+$/.test(value)) {
      setRuleNotice('域名只能包含字母、数字、点、下划线和连字符')
      return
    }
    const duplicate = [...groupCustomRules, ...groupRules].some(
      (rule) => rule.type === 'DOMAIN-SUFFIX' && (rule.value ?? '').toLowerCase() === value,
    )
    if (duplicate) {
      setRuleNotice('这个组里已经有相同的域名规则')
      return
    }
    const rule: RoutingRule = { type: 'DOMAIN-SUFFIX', value, group: group.name }
    const impact = analyzeRuleImpact(scheme, rule, { includeCandidate: true })
    onAddRule(rule)
    setAddedRules((current) => [...current, rule])
    setNewDomain('')
    setRuleNotice(`已添加，会排在所有规则最前。${ruleImpactText(impact)}`)
  }

  const save = () => {
    const trimmedName = name.trim()
    if (!trimmedName) { setError('请填写策略组名称'); return }
    // 与新建（groupEditing）保持同一口径：组名大小写不敏感，否则能改出一个
    // 只差大小写的同名组，引用与匹配顺序按名字对不上。
    if (scheme.groups.some((g) => g.name !== group.name && g.name.toLowerCase() === trimmedName.toLowerCase())) {
      setError('已经有同名策略组')
      return
    }
    if (filterError) { setError(filterError); return }
    const candidateError = validateGroupCandidates(scheme, trimmedName, options, group.name)
    if (candidateError) { setError(candidateError); return }
    // 改名后其他组的引用会同步改到新名字，成环检测也按改名后的图来算。
    const draftGroups = scheme.groups.map((item) => (
      item.name === group.name
        ? { ...item, name: trimmedName, options }
        : {
            ...item,
            options: item.options.map((option) => (option === group.name ? trimmedName : option)),
          }
    ))
    const cycle = findGroupCyclePath(draftGroups, trimmedName)
    if (cycle) {
      setError(`策略组循环引用：${cycle.join(' → ')}`)
      return
    }
    if (options.length === 0 && !trimmedFilter) {
      setError('至少保留一个候选策略，或填写节点名称匹配')
      return
    }
    const intervalValue = interval.trim() ? Number(interval) : undefined
    const toleranceValue = tolerance.trim() ? Number(tolerance) : undefined
    if (intervalValue !== undefined && (!Number.isFinite(intervalValue) || intervalValue <= 0)) {
      setError('测速间隔需要大于 0 的数字')
      return
    }
    if (toleranceValue !== undefined && (!Number.isFinite(toleranceValue) || toleranceValue < 0)) {
      setError('容差需要是 0 或正数')
      return
    }
    onSave({
      ...group,
      name: trimmedName,
      type,
      options,
      nodeFilter: trimmedFilter || undefined,
      algorithm: type === 'load-balance' ? algorithm.trim() || undefined : undefined,
      ...(type !== 'select'
        ? {
            url: url.trim() || undefined,
            interval: intervalValue,
            tolerance: toleranceValue,
          }
        : { url: undefined, interval: undefined, tolerance: undefined }),
    })
    ref.current?.close()
  }

  return (
    <dialog ref={ref} onClose={onClose} className="group-detail-dialog">
      <h3>策略组详情</h3>
      <form className="dialog-form" onSubmit={(e) => { e.preventDefault(); save() }}>
        <div className="detail-tabs" role="tablist" aria-label="策略组详情">
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'settings'}
            className={`detail-tab${tab === 'settings' ? ' active' : ''}`}
            onClick={() => setTab('settings')}
          >设置</button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'rules'}
            className={`detail-tab${tab === 'rules' ? ' active' : ''}`}
            onClick={() => setTab('rules')}
          >规则 {totalGroupRules}</button>
        </div>
        {tab === 'settings' && (
        <>
        <div className="field">
          <label>名称</label>
          <input type="text" className="field" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          <div className="hint">改名会同步更新规则绑定和其他策略组里的引用。</div>
        </div>
        <div className="field">
          <label>策略类型</label>
          <select className="input" value={type} onChange={(e) => setType(e.target.value as PolicyGroup['type'])}>
            <option value="select">手动选择</option>
            <option value="url-test">自动测速</option>
            <option value="smart">智能选择</option>
            <option value="fallback">故障转移</option>
            <option value="load-balance">负载均衡</option>
            <option value="conditional">按网络选择</option>
            <option value="relay">链式代理</option>
          </select>
          {type === 'load-balance' && (
            <input
              type="text"
              className="field mono"
              value={algorithm}
              placeholder="算法，留空由客户端决定"
              onChange={(e) => setAlgorithm(e.target.value)}
            />
          )}
          {(type === 'smart' || type === 'conditional' || type === 'relay') && (
            <div className="hint">该类型只在部分客户端原样支持，其余客户端会按最接近的类型导出。</div>
          )}
        </div>
        <div className="field">
          <label>候选策略</label>
          <GroupCandidatePicker
            scheme={scheme}
            groupName={name.trim() || group.name}
            originalName={group.name}
            type={type}
            selected={options}
            matchedNodeNames={matchedNodeNames}
            readOnly={readOnly}
            onChange={setOptions}
          />
        </div>
        <div className="field">
          <label>节点名称匹配（正则，可选）</label>
          <input
            type="text"
            className="field mono"
            value={nodeFilter}
            placeholder=".* 或 香港|HK"
            onChange={(e) => setNodeFilter(e.target.value)}
          />
          <div className={`hint${filterError ? ' is-error' : ''}`}>
            {filterError || (trimmedFilter ? `当前匹配 ${matchedNodeNames.length} 个已启用节点` : '留空表示不按名称自动加入节点')}
          </div>
        </div>
        {type !== 'select' && (
          <div className="group-auto-fields">
            <div className="field">
              <label>测速地址</label>
              <input type="text" className="field mono" value={url} placeholder="留空使用客户端默认" onChange={(e) => setURL(e.target.value)} />
            </div>
            <div className="field">
              <label>测速间隔（秒）</label>
              <input type="number" className="field" value={interval} placeholder="300" onChange={(e) => setInterval(e.target.value)} />
            </div>
            <div className="field">
              <label>容差（毫秒）</label>
              <input type="number" className="field" value={tolerance} placeholder="50" onChange={(e) => setTolerance(e.target.value)} />
            </div>
          </div>
        )}
        </>
        )}
        {tab === 'rules' && (
          <div className="group-rules-panel">
            <div className="hint">
              {groupCustomRules.length} 条我添加的规则 · {groupRules.length} 条方案自带或规则集规则。
              新添加的域名会排在所有规则最前，优先于其他组。
            </div>
            <input
              type="search"
              className="input"
              aria-label="搜索这个组的规则"
              placeholder="搜索域名、关键词或 IP…"
              value={ruleSearch}
              onChange={(e) => setRuleSearch(e.target.value)}
            />
            <div className="row candidate-add">
              <input
                className="input mono"
                aria-label="添加域名到这个组"
                placeholder="example.com"
                value={newDomain}
                onChange={(e) => { setNewDomain(e.target.value); setRuleNotice('') }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    addDomainRule()
                  }
                }}
              />
              <button type="button" className="btn" {...writeGuard(readOnly)} onClick={addDomainRule}>添加网站</button>
            </div>
            {ruleNotice && <div className="hint" role="status">{ruleNotice}</div>}
            {visibleGroupRules.length > 0 ? (
              <ul className="rule-list group-rule-list">
                {visibleGroupRules.map(({ rule, custom }, index) => (
                  <li key={`${rule.type}-${rule.value ?? ''}-${index}`}>
                    {custom && <span className="pill">自定义</span>}
                    {rule.sourceName && <span className="pill rule-source">{rule.sourceName}</span>}
                    <span className="mono rule-type">{rule.type}</span>
                    <span className="mono rule-value">{rule.value ?? '—'}</span>
                    {rule.noResolve && <span className="hint">no-resolve</span>}
                  </li>
                ))}
              </ul>
            ) : (
              <div className="hint">
                {ruleQuery ? '没有匹配的规则' : '方案里没有直接指向这个组的规则；它通常作为其他策略组的候选使用。'}
              </div>
            )}
            {totalGroupRules > visibleGroupRules.length && (
              <div className="hint">仅显示前 {visibleGroupRules.length} 条，请用搜索缩小范围。</div>
            )}
          </div>
        )}
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          {tab === 'settings' ? (
            <>
              <button type="submit" className="btn primary" {...writeGuard(readOnly)}>保存</button>
              <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
            </>
          ) : (
            <button type="button" className="btn primary" onClick={() => ref.current?.close()}>关闭</button>
          )}
        </div>
      </form>
    </dialog>
  )
}

function GroupCreateDialog({
  scheme,
  nodes,
  onClose,
  onCreate,
}: {
  scheme: RuleScheme
  nodes: ProxyNode[]
  onClose: () => void
  onCreate: (group: PolicyGroup) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const [name, setName] = useState(() => nextGroupName(scheme))
  const [type, setType] = useState<NodeGroupDraft['type']>('select')
  const [pattern, setPattern] = useState('')
  const [options, setOptions] = useState<string[]>([])
  const [error, setError] = useState('')
  const readOnly = useWorkspaceStatus().readOnly

  useEffect(() => { ref.current?.showModal() }, [])

  const preview = useMemo(() => previewNodeMatches(pattern, nodes), [pattern, nodes])

  const save = () => {
    const validation = validateNodeGroupDraft(scheme, { name, type, pattern, options })
    if (validation) {
      setError(validation)
      return
    }
    onCreate(buildNodeFilterGroup({ name, type, pattern, options }))
    ref.current?.close()
  }

  return (
    <dialog ref={ref} className="group-detail-dialog" onClose={onClose}>
      <h3>新建策略组</h3>
      <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); save() }}>
        <div className="field">
          <label>名称</label>
          <input
            className="field"
            value={name}
            onChange={(event) => { setName(event.target.value); setError('') }}
            autoFocus
          />
          <div className="hint">名称会出现在客户端策略组列表里。</div>
        </div>
        <div className="field">
          <label>策略类型</label>
          <select className="input" value={type} onChange={(event) => setType(event.target.value as NodeGroupDraft['type'])}>
            <option value="select">手动选择</option>
            <option value="url-test">自动测速</option>
            <option value="fallback">故障转移</option>
          </select>
        </div>
        <div className="field">
          <label>候选策略</label>
          <GroupCandidatePicker
            scheme={scheme}
            groupName={name.trim()}
            type={type}
            selected={options}
            matchedNodeNames={preview.names}
            readOnly={readOnly}
            onChange={setOptions}
          />
        </div>
        <div className="field">
          <label>节点名称匹配（正则，可选）</label>
          <input
            className="field mono"
            value={pattern}
            placeholder="韩国|KR|首尔 或 台湾|TW 或 .*"
            onChange={(event) => { setPattern(event.target.value); setError('') }}
          />
          <div className={`hint${preview.error ? ' is-error' : ''}`}>
            {preview.error ?? (pattern.trim()
              ? `当前匹配 ${preview.names.length} 个已启用节点`
              : '留空则只使用上面选中的候选；区分大小写。')}
          </div>
        </div>
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          <button type="submit" className="btn primary" {...writeGuard(readOnly)}>创建策略组</button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

function NetworkSettingsDialog({
  scheme,
  onClose,
  onSave,
}: {
  scheme: RuleScheme
  onClose: () => void
  onSave: (next: RuleScheme) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const readOnly = useWorkspaceStatus().readOnly
  const [draft, setDraft] = useState<NetworkSettingsDraft>(() => networkSettingsDraft(scheme.networkSettings))
  const [error, setError] = useState('')
  useEffect(() => { ref.current?.showModal() }, [])

  const save = () => {
    try {
      const networkSettings = validateNetworkSettingsDraft(draft)
      onSave({ ...scheme, networkSettings })
      ref.current?.close()
    } catch (e) {
      setError(e instanceof NetworkSettingsError ? e.message : 'DNS 设置无法保存')
    }
  }

  const text = (values: string[]) => values.join('\n')
  const lines = (value: string) => value.split('\n')

  return (
    <dialog ref={ref} className="dns-dialog" onClose={onClose}>
      <h3>DNS 与网络</h3>
      <form className="dialog-form" onSubmit={(e) => { e.preventDefault(); save() }}>
        <div className="field">
          <label>DNS 保护模式</label>
          <select
            className="input"
            value={draft.dnsProtectionMode}
            onChange={(e) => setDraft({ ...draft, dnsProtectionMode: e.target.value as NetworkSettingsDraft['dnsProtectionMode'] })}
          >
            {Object.entries(DNS_MODE_TITLES).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
          <div className="hint">{DNS_MODE_SUMMARIES[draft.dnsProtectionMode]}</div>
          {draft.dnsProtectionMode === 'strict' && (
            <div className="dns-warning">严格保护可能影响局域网、公共网络认证和使用域名的代理节点。</div>
          )}
        </div>

        <div className="field">
          <label>IPv6</label>
          <select
            className="input"
            value={draft.ipv6Enabled === undefined ? 'default' : draft.ipv6Enabled ? 'on' : 'off'}
            onChange={(e) => setDraft({
              ...draft,
              ipv6Enabled: e.target.value === 'default' ? undefined : e.target.value === 'on',
            })}
          >
            <option value="default">跟随客户端默认</option>
            <option value="on">开启</option>
            <option value="off">关闭</option>
          </select>
        </div>

        <div className="dns-grid">
          <div className="field">
            <label>普通 DNS（每行一个 IP）</label>
            <textarea
              className="field mono"
              rows={3}
              value={text(draft.dnsServers)}
              onChange={(e) => setDraft({ ...draft, dnsServers: lines(e.target.value) })}
              placeholder={'223.5.5.5\n119.29.29.29'}
            />
            <div className="hint">只接受 IPv4 / IPv6 字面量，用于解析加密 DNS 和代理节点域名。</div>
          </div>
          <div className="field">
            <label>国内 DNS（直连）</label>
            <textarea
              className="field mono"
              rows={3}
              value={text(draft.encryptedDNSServers)}
              onChange={(e) => setDraft({ ...draft, encryptedDNSServers: lines(e.target.value) })}
              placeholder={'https://223.5.5.5/dns-query\nhttps://doh.pub/dns-query'}
            />
            <div className="hint">支持 https / h3 / tls / quic 地址，用于国内和直连解析。</div>
          </div>
          <div className="field">
            <label>远程 DNS（经代理）</label>
            <textarea
              className="field mono"
              rows={3}
              value={text(draft.remoteDNSServers)}
              onChange={(e) => setDraft({ ...draft, remoteDNSServers: lines(e.target.value) })}
              placeholder={'https://8.8.8.8/dns-query\nhttps://1.1.1.1/dns-query'}
            />
            <div className="hint">只经代理访问，用于 sing-box 和 mihomo 系客户端。</div>
          </div>
        </div>

        <div className="field">
          <label>延迟测试地址</label>
          <input
            className="input mono"
            value={draft.proxyTestURLString}
            onChange={(e) => setDraft({ ...draft, proxyTestURLString: e.target.value })}
            placeholder="http://www.gstatic.com/generate_204"
          />
          <div className="hint">URL 测速组未单独填写地址时使用；支持 http / https。</div>
        </div>

        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions dns-actions">
          <button type="submit" className="btn primary" {...writeGuard(readOnly)}>保存</button>
          <button type="button" className="btn" onClick={() => setDraft(networkSettingsDraft(undefined))}>
            填入默认值
          </button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

interface RuleSetPayload {
  name: string
  group: string
  rules: RuleSetRule[]
  sourceKind: 'library' | 'local' | 'url'
  sourceRef?: string
  format?: RuleSetFormat
}

function RuleLibraryDialog({
  scheme,
  onClose,
  onAdd,
}: {
  scheme: RuleScheme
  onClose: () => void
  onAdd: (payload: RuleSetPayload) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const [group, setGroup] = useState(scheme.groups[0]?.name ?? '')
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState('全部')
  const [counts, setCounts] = useState<Record<string, number>>({})
  const [busyFile, setBusyFile] = useState('')
  const [error, setError] = useState('')
  const [remoteURL, setRemoteURL] = useState('')
  const [remoteName, setRemoteName] = useState('')
  const [remoteBusy, setRemoteBusy] = useState(false)
  const readOnly = useWorkspaceStatus().readOnly

  useEffect(() => {
    ref.current?.showModal()
    let cancelled = false
    Promise.all(BUNDLED_RULE_LIBRARY.map(async (entry) => {
      try {
        const rules = await loadBundledRuleSet(entry.file)
        return [entry.file, rules.length] as const
      } catch {
        return [entry.file, -1] as const
      }
    })).then((rows) => {
      if (!cancelled) setCounts(Object.fromEntries(rows))
    })
    return () => { cancelled = true }
  }, [])

  const LIBRARY_RENDER_LIMIT = 240
  const categories = ['全部', ...new Set(RULE_LIBRARY.map((entry) => entry.category))]
  const q = query.trim().toLowerCase()
  const matching = RULE_LIBRARY.filter((entry) => {
    if (category !== '全部' && entry.category !== category) return false
    if (!q) return true
    return `${entry.title} ${entry.file ?? ''} ${entry.category} ${entry.provider} ${entry.sourceURL ?? ''} ${(entry.aliases ?? []).join(' ')}`
      .toLowerCase()
      .includes(q)
  })
  const visible = matching.slice(0, LIBRARY_RENDER_LIMIT)
  const hiddenCount = matching.length - visible.length

  const addEntry = async (entry: RuleLibraryEntry) => {
    if (!group) { setError('方案里没有可用的策略组'); return }
    setBusyFile(entry.id); setError('')
    try {
      let rules: RuleSetRule[]
      let format: RuleSetFormat = 'classical'
      if (entry.sourceURL) {
        const parsed = await fetchRuleSet(entry.sourceURL)
        rules = parsed.rules
        format = parsed.format
      } else if (entry.file) {
        rules = await loadBundledRuleSet(entry.file)
      } else {
        throw new Error('这个规则集没有可用的来源')
      }
      if (rules.length === 0) throw new Error('这个规则集没有可用的规则')
      onAdd({
        name: entry.title,
        group,
        rules,
        sourceKind: entry.sourceURL ? 'url' : 'library',
        sourceRef: entry.sourceURL ?? entry.file ?? entry.id,
        format,
      })
      onClose()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusyFile('')
    }
  }

  const addRemote = async () => {
    const url = normalizeRemoteTextURL(remoteURL)
    if (!group) { setError('方案里没有可用的策略组'); return }
    if (!/^https?:\/\//i.test(url)) { setError('请输入有效的 http(s) 规则列表地址'); return }
    setRemoteBusy(true); setError('')
    try {
      const parsedRuleSet = await fetchRuleSet(url)
      const fallbackName = (() => {
        try {
          const parsed = new URL(url)
          return parsed.pathname.split('/').filter(Boolean).at(-1)?.replace(/\.[^.]+$/, '') || parsed.hostname
        } catch {
          return '在线规则列表'
        }
      })()
      onAdd({
        name: remoteName.trim() || fallbackName,
        group,
        rules: parsedRuleSet.rules,
        sourceKind: 'url',
        sourceRef: url,
        format: parsedRuleSet.format,
      })
      onClose()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setRemoteBusy(false)
    }
  }

  return (
    <dialog ref={ref} onClose={onClose} className="library-dialog">
      <h3>规则库</h3>
      <div className="meta">
        内置 ACL4SSR 快照离线可用；在线目录收录 ACL4SSR 与 blackmatrix7 的 {ONLINE_RULE_CATALOG.length} 个列表，添加时从上游读取。
      </div>
      <div className="field">
        <label>加入策略组</label>
        <select className="input" value={group} onChange={(e) => setGroup(e.target.value)}>
          {scheme.groups.map((g) => <option key={g.name} value={g.name}>{groupDisplayName(g.name)}</option>)}
        </select>
      </div>
      <div className="library-toolbar">
        <input
          className="input"
          type="search"
          aria-label="搜索规则库"
          placeholder="搜索规则库…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <div className="library-categories">
          {categories.map((item) => (
            <button
              key={item}
              className={`library-category${category === item ? ' active' : ''}`}
              onClick={() => setCategory(item)}
            >{item}</button>
          ))}
        </div>
      </div>
      <ul className="library-list">
        {visible.map((entry) => {
          const count = entry.file ? counts[entry.file] : undefined
          return (
            <li key={entry.id}>
              <div>
                <strong>{entry.title}</strong>
                <span className="pill">{entry.provider}</span>
                <span className="pill">{entry.category}</span>
                <span className="hint">
                  {entry.online
                    ? '在线目录 · 添加时读取'
                    : count === undefined ? '读取中…' : count < 0 ? '读取失败' : `${count} 条规则`}
                  {!entry.online && count !== undefined && count > 1000 ? ' · 配置会明显变大' : ''}
                </span>
              </div>
              <button
                className="btn ghost"
                disabled={!!busyFile || remoteBusy || readOnly}
                onClick={() => void addEntry(entry)}
              >{busyFile === entry.id ? '添加中…' : '添加'}</button>
            </li>
          )
        })}
        {visible.length === 0 && <li className="hint">没有匹配的规则集</li>}
        {hiddenCount > 0 && (
          <li className="hint">还有 {hiddenCount} 条未显示，输入关键词或选择分类缩小范围。</li>
        )}
      </ul>
      <div className="library-remote">
        <div className="field">
          <label>从在线地址添加</label>
          <div className="row candidate-add">
            <input className="input" type="url" placeholder="https://…/rules.list" value={remoteURL} onChange={(e) => setRemoteURL(e.target.value)} />
            <input className="input" type="text" placeholder="名称（可选）" value={remoteName} onChange={(e) => setRemoteName(e.target.value)} />
            <button className="btn" disabled={remoteBusy || !!busyFile || readOnly} onClick={() => void addRemote()}>
              {remoteBusy ? '读取中…' : '读取并添加'}
            </button>
          </div>
          <div className="hint">通过本机 /api/fetch 读取；自动识别 Clash 列表 / provider YAML、QuanX filter、Egern YAML 和 sing-box source JSON。需要长期刷新可改用「+ 在线规则集」保存为订阅。</div>
        </div>
      </div>
      {error && <div className="form-error" role="alert">{error}</div>}
      <div className="actions">
        <button className="btn ghost" onClick={onClose}>取消</button>
      </div>
    </dialog>
  )
}

function RuleSetEditorDialog({
  ruleSet,
  onClose,
  onSave,
}: {
  ruleSet?: LocalRuleSet
  onClose: () => void
  onSave: (set: LocalRuleSet) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const [name, setName] = useState(ruleSet?.name ?? '')
  const [text, setText] = useState(ruleSet ? ruleSet.rules.map(ruleSetLine).join('\n') : '')
  const [format, setFormat] = useState<RuleSetFormat | undefined>(ruleSet?.format)
  const [error, setError] = useState('')
  const readOnly = useWorkspaceStatus().readOnly

  useEffect(() => { ref.current?.showModal() }, [])
  const parsed = parseRuleList(text)

  const readFile = async (file?: File) => {
    if (!file) return
    setError('')
    try {
      const textBody = await file.text()
      const imported = parseRuleSetText(textBody)
      setText(imported.rules.map(ruleSetLine).join('\n'))
      setFormat(imported.format)
      if (!name.trim()) setName(file.name.replace(/\.([^.]+)$/, ''))
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const save = () => {
    if (!name.trim()) { setError('请填写规则集名称'); return }
    if (parsed.length === 0) { setError('没有解析到有效规则，请每行填写一条规则'); return }
    onSave({
      id: ruleSet?.id ?? newID(),
      name: name.trim(),
      rules: parsed,
      updatedAt: Date.now(),
      format,
    })
    ref.current?.close()
  }

  return (
    <dialog ref={ref} onClose={onClose} className="rule-set-dialog">
      <h3>{ruleSet ? '编辑规则集' : '新建规则集'}</h3>
      <form className="dialog-form" onSubmit={(e) => { e.preventDefault(); save() }}>
        <div className="field">
          <label>名称</label>
          <input type="text" className="field" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </div>
        <div className="field">
          <label>规则内容</label>
          <textarea
            className="field mono"
            rows={8}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={'DOMAIN-SUFFIX,example.com\nIP-CIDR,10.0.0.0/8\nDOMAIN-KEYWORD,keyword'}
          />
          <div className="row rs-import-row">
            <button type="button" className="btn ghost" onClick={() => fileRef.current?.click()}>导入规则文件</button>
            <input
              ref={fileRef}
              type="file"
              accept=".list,.txt,.conf,.yaml,.yml,.json"
              style={{ display: 'none' }}
              onChange={(e) => void readFile(e.target.files?.[0])}
            />
            {format && (
              <span className="hint">已识别：{RULE_SET_FORMAT_TITLES[format]}，保存时转为通用规则行</span>
            )}
          </div>
          <div className="hint">每行一条 Clash 经典规则；当前解析到 {parsed.length} 条。支持 Clash 列表 / provider YAML、QuanX filter、Egern YAML 和 sing-box source JSON。</div>
        </div>
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          <button type="submit" className="btn primary" {...writeGuard(readOnly)}>保存</button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

function RemoteRuleSetDialog({
  scheme,
  onClose,
  onSave,
}: {
  scheme: RuleScheme
  onClose: () => void
  onSave: (sets: LocalRuleSet[], joinGroup?: string, notice?: string) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const [url, setUrl] = useState('')
  const [name, setName] = useState('')
  const [group, setGroup] = useState(scheme.groups[0]?.name ?? '')
  const [join, setJoin] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const readOnly = useWorkspaceStatus().readOnly
  const targets = splitRemoteTextURLs(url)

  useEffect(() => { ref.current?.showModal() }, [])

  const save = async () => {
    if (!targets.length) {
      setError('请输入有效的 http(s) 规则集地址，每行一个，也可用空格或逗号分隔')
      return
    }
    if (targets.length > MAX_REMOTE_RULE_SET_URLS) {
      setError(`一次最多添加 ${MAX_REMOTE_RULE_SET_URLS} 个地址（当前 ${targets.length} 个），请分批提交`)
      return
    }
    setBusy(true); setError('')
    try {
      const created: { set: LocalRuleSet; notice: string }[] = []
      const failures: string[] = []
      for (const target of targets) {
        try {
          const parsed = await fetchRuleSet(target)
          created.push({
            set: {
              id: newID(),
              name: targets.length === 1 && name.trim() ? name.trim() : remoteRuleSetNameFromURL(target),
              rules: parsed.rules,
              updatedAt: Date.now(),
              sourceURL: target,
              format: parsed.format,
            },
            notice: describeRuleSetParse(parsed),
          })
        } catch (e) {
          failures.push(`${target}：${(e as Error).message}`)
        }
      }
      // 一次填多个地址时要么全部保存、要么一个都不保存，避免只更新一半。
      if (failures.length) {
        setError(`以下地址读取失败，本次没有保存任何规则集：${failures.join('；')}`)
        return
      }
      onSave(
        created.map((item) => item.set),
        join && group ? group : undefined,
        created.length === 1 ? created[0].notice : undefined,
      )
      ref.current?.close()
    } finally {
      setBusy(false)
    }
  }

  return (
    <dialog ref={ref} className="rule-set-dialog" onClose={onClose}>
      <h3>添加在线规则集</h3>
      <form className="dialog-form" onSubmit={(e) => { e.preventDefault(); void save() }}>
        <div className="field">
          <label>规则集地址（可填多个）</label>
          <textarea
            className="field mono"
            rows={3}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={'https://…/Blizzard.yaml\nhttps://…/Game.yaml'}
            autoFocus
          />
          <div className="hint">每行一个地址，也可用空格或逗号分隔；每个地址会分别保存为独立规则集。自动识别 Clash 经典列表 / provider YAML、QuanX filter、Egern YAML 和 sing-box source JSON；GitHub / Gitee 网页文件地址会转换为 raw 地址。</div>
          {targets.length > 0 && (
            <div className="hint">已识别 {targets.length} 个地址{targets.length > 1 ? '，保存时按地址文件名命名' : ''}。</div>
          )}
        </div>
        <div className="field">
          <label>名称（可选{targets.length > 1 ? '，多个地址时忽略' : ''}）</label>
          <input className="field" type="text" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        {scheme.groups.length > 0 && (
          <>
            <div className="field">
              <label>加入策略组</label>
              <select className="input" value={group} onChange={(e) => setGroup(e.target.value)}>
                {scheme.groups.map((g) => <option key={g.name} value={g.name}>{groupDisplayName(g.name)}</option>)}
              </select>
            </div>
            <label className="setting-toggle">
              <input type="checkbox" checked={join} onChange={(e) => setJoin(e.target.checked)} />
              <span>保存后同时加入当前方案</span>
            </label>
          </>
        )}
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy || readOnly} title={readOnly ? READONLY_NOTE : undefined}>
            {busy ? '读取中…' : '添加'}
          </button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

function RuleSetDiffView({ diff, stale = false }: { diff: RuleSetRefreshDiff; stale?: boolean }) {
  const total = diff.added + diff.removed + diff.modified
  const totalSamples = diff.samples.length + diff.hidden
  const renderLine = (sample: RuleSetRefreshDiff['samples'][number], index: number) => (
    <div key={`${sample.kind}-${index}`} className={`rs-diff-line ${sample.kind}`}>
      <span className="rs-diff-mark">{sample.kind === 'added' ? '+' : sample.kind === 'removed' ? '−' : '~'}</span>
      {' '}
      {sample.kind === 'modified' && sample.previous
        ? `${sample.previous} → ${sample.text}`
        : sample.text}
    </div>
  )
  return (
    <div className="rs-diff">
      <div className="rs-diff-head">
        <span className="hint">{stale ? '最近一次成功刷新：' : '上次刷新：'}</span>
        <span className="rs-diff-stat added">+{diff.added}</span>
        <span className="rs-diff-stat removed">−{diff.removed}</span>
        <span className="rs-diff-stat modified">~{diff.modified}</span>
        <span className="hint"> · {formatDate(diff.checkedAt)}</span>
        {total === 0 && <span className="hint"> · 没有变化</span>}
      </div>
      {diff.samples.length > 0 && (
        <div className="rs-diff-lines">
          {diff.samples.slice(0, 3).map(renderLine)}
          {totalSamples > 3 && (
            <details>
              <summary className="hint">展开其余 {totalSamples - 3} 条</summary>
              {diff.samples.slice(3).map((sample, index) => renderLine(sample, index + 3))}
              {diff.hidden > 0 && <div className="hint">另有 {diff.hidden} 条变化未列出。</div>}
            </details>
          )}
        </div>
      )}
      {total > 0 && diff.samples.length === 0 && (
        <div className="hint">共 {total} 条变化，未保留具体条目。</div>
      )}
    </div>
  )
}

function RenameRuleSetDialog({
  set,
  onClose,
  onSave,
}: {
  set: LocalRuleSet
  onClose: () => void
  onSave: (name: string) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const [name, setName] = useState(set.name)
  const [error, setError] = useState('')
  const readOnly = useWorkspaceStatus().readOnly

  useEffect(() => { ref.current?.showModal() }, [])

  const save = () => {
    if (!name.trim()) { setError('请填写规则集名称'); return }
    onSave(name.trim())
    ref.current?.close()
  }

  return (
    <dialog ref={ref} className="rule-set-dialog" onClose={onClose}>
      <h3>重命名规则集</h3>
      <div className="dialog-form">
        <div className="field">
          <label>名称</label>
          <input
            className="field"
            type="text"
            value={name}
            autoFocus
            onChange={(e) => setName(e.target.value)}
          />
          {set.sourceURL && <div className="hint">重命名不会改动已加入方案的快照名称。</div>}
        </div>
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          <button type="button" className="btn primary" {...writeGuard(readOnly)} onClick={save}>保存</button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </div>
    </dialog>
  )
}

function AddRuleSetToSchemeDialog({
  ruleSet,
  scheme,
  onClose,
  onAdd,
}: {
  ruleSet: LocalRuleSet
  scheme: RuleScheme
  onClose: () => void
  onAdd: (group: string) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const [group, setGroup] = useState(scheme.groups[0]?.name ?? '')
  const readOnly = useWorkspaceStatus().readOnly
  useEffect(() => { ref.current?.showModal() }, [])

  return (
    <dialog ref={ref} onClose={onClose}>
      <h3>加入规则集</h3>
      <div className="meta">「{ruleSet.name}」共 {ruleSet.rules.length} 条规则。</div>
      <div className="field">
        <label>加入策略组</label>
        <select className="input" value={group} onChange={(e) => setGroup(e.target.value)}>
          {scheme.groups.map((g) => <option key={g.name} value={g.name}>{groupDisplayName(g.name)}</option>)}
        </select>
      </div>
      <div className="hint">加入的是当前规则内容的快照；之后编辑本地规则集不会自动改动已加入的方案。</div>
      <div className="actions">
        <button className="btn primary" disabled={!group || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={() => { onAdd(group); ref.current?.close() }}>加入</button>
        <button className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
      </div>
    </dialog>
  )
}

/** 规则逐条排序的撤销记录。RulesTab 切到别的页签会卸载，撤销入口需要跨页保留最后一次操作。 */
type RuleOrderUndoRecord = { schemeID: string; ruleOrder?: string[]; label: string }
let ruleOrderUndoSlot: RuleOrderUndoRecord | null = null

function formatUpstreamTime(value: number | null): string {
  if (!value) return ''
  return new Date(value).toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function RulesTab({
  onGo,
  locateIssue,
  onLocateConsumed,
}: {
  onGo?: (tab: TabKey) => void
  /** 从诊断页跳过来时待定位的检查项。 */
  locateIssue?: SchemeLintIssue | null
  onLocateConsumed?: () => void
}) {
  const selectedSchemeID = useStore((s) => s.selectedSchemeID)
  const workspaceStatus = useWorkspaceStatus()
  const readOnly = workspaceStatus.readOnly
  const workspaceMode = workspaceStatus.mode
  const setScheme = useStore((s) => s.setScheme)
  const policySelections = useStore((s) => s.policySelections)
  const setPolicy = useStore((s) => s.setPolicy)
  const removePolicy = useStore((s) => s.removePolicy)
  const showGroupEmoji = useStore((s) => s.showGroupEmoji)
  const setShowGroupEmoji = useStore((s) => s.setShowGroupEmoji)
  const preferRuleSets = useStore((s) => s.preferRuleSets)
  const latencyByNodeId = useStore((s) => s.latencyByNodeId)
  const ruleSetVersionHistory = useStore((s) => s.ruleSetVersionHistory)
  const scheme = useScheme()
  const nodes = useStore((s) => s.nodes)
  const sources = useStore((s) => s.sources)
  const customSchemes = useStore((s) => s.customSchemes)
  const addCustomScheme = useStore((s) => s.addCustomScheme)
  const removeCustomScheme = useStore((s) => s.removeCustomScheme)
  const localRuleSets = useStore((s) => s.localRuleSets)
  const ruleSetExclusions = useStore((s) => s.ruleSetExclusions)
  const addLocalRuleSet = useStore((s) => s.addLocalRuleSet)
  const removeLocalRuleSet = useStore((s) => s.removeLocalRuleSet)
  const builtinSchemeOverrides = useStore((s) => s.builtinSchemeOverrides)
  const schemeSnapshots = useStore((s) => s.schemeSnapshots)
  const saveBuiltinSchemeOverride = useStore((s) => s.saveBuiltinSchemeOverride)
  const restoreBuiltinSchemeSnapshot = useStore((s) => s.restoreBuiltinSchemeSnapshot)
  const clearBuiltinSchemeOverride = useStore((s) => s.clearBuiltinSchemeOverride)
  const checkBuiltinSchemeUpdatesOnOpen = useStore((s) => s.checkBuiltinSchemeUpdatesOnOpen)
  const setCheckBuiltinSchemeUpdatesOnOpen = useStore((s) => s.setCheckBuiltinSchemeUpdatesOnOpen)
  const builtinSchemeUpdateNotices = useStore((s) => s.builtinSchemeUpdateNotices)
  const setBuiltinSchemeUpdateNotice = useStore((s) => s.setBuiltinSchemeUpdateNotice)
  const [serverUpstream, setServerUpstream] = useState<UpstreamStatusPayload | null>(null)
  const [serverUpstreamError, setServerUpstreamError] = useState('')
  const [upstreamChecking, setUpstreamChecking] = useState(false)
  const [importingScheme, setImportingScheme] = useState(false)
  const [updatingBuiltinScheme, setUpdatingBuiltinScheme] = useState(false)
  const [pendingFreeze, setPendingFreeze] = useState<{
    meta: SchemeMeta
    result: UpstreamSchemeResult
    plan: BuiltinSchemeFreezePlan
  } | null>(null)
  const [schemeName, setSchemeName] = useState('')
  const [schemeURL, setSchemeURL] = useState('')
  const [schemeText, setSchemeText] = useState('')
  const [schemeError, setSchemeError] = useState<string | null>(null)
  const [schemeLoading, setSchemeLoading] = useState(false)
  const [pendingSchemeDelete, setPendingSchemeDelete] = useState<RuleScheme | null>(null)
  const [editingScheme, setEditingScheme] = useState<RuleScheme | null>(null)
  const [textEditorScheme, setTextEditorScheme] = useState<RuleScheme | null>(null)
  const [restoreInitialConfirm, setRestoreInitialConfirm] = useState(false)
  const [pendingSnapshotRollback, setPendingSnapshotRollback] = useState<SnapshotRollbackPlan | null>(null)
  const [creatingGroup, setCreatingGroup] = useState<RuleScheme | null>(null)
  const [pendingGroupDelete, setPendingGroupDelete] = useState<PolicyGroup | null>(null)
  const [customRuleTarget, setCustomRuleTarget] = useState<RuleScheme | null>(null)
  const [customRuleGroup, setCustomRuleGroup] = useState<string | undefined>()
  const [groupEditor, setGroupEditor] = useState<{
    scheme: RuleScheme
    group: PolicyGroup
    tab?: 'settings' | 'rules'
    query?: string
  } | null>(null)
  const [networkEditor, setNetworkEditor] = useState<RuleScheme | null>(null)
  const [dragFromIndex, setDragFromIndex] = useState<number | null>(null)
  const [dragOverIndex, setDragOverIndex] = useState<number | null>(null)
  const [reorderUndo, setReorderUndo] = useState<{
    schemeID: string
    groups: PolicyGroup[]
    matchingOrder?: string[]
    ruleOrder?: string[]
    conflicts: RuleOrderConflict[]
  } | null>(null)
  const [ruleOrderUndo, setRuleOrderUndoState] = useState<RuleOrderUndoRecord | null>(ruleOrderUndoSlot)
  const setRuleOrderUndo = (next: RuleOrderUndoRecord | null) => {
    ruleOrderUndoSlot = next
    setRuleOrderUndoState(next)
  }
  const [ruleOrderSearch, setRuleOrderSearch] = useState('')
  const [libraryOpen, setLibraryOpen] = useState(false)
  const [localSetEditor, setLocalSetEditor] = useState<{ set?: LocalRuleSet } | null>(null)
  const [localSetAddTarget, setLocalSetAddTarget] = useState<LocalRuleSet | null>(null)
  const [pendingLocalSetDelete, setPendingLocalSetDelete] = useState<LocalRuleSet | null>(null)
  const [remoteSetOpen, setRemoteSetOpen] = useState(false)
  const [renamingLocalSet, setRenamingLocalSet] = useState<LocalRuleSet | null>(null)
  const [localSetSearch, setLocalSetSearch] = useState('')
  const localSetImportRef = useRef<HTMLInputElement>(null)
  const [refreshingRuleSetID, setRefreshingRuleSetID] = useState<string | null>(null)
  const [ruleSetError, setRuleSetError] = useState<string | null>(null)
  const [flash, setFlash] = useState('')
  const [refreshingScheme, setRefreshingScheme] = useState(false)
  const [schemeFileName, setSchemeFileName] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  // 服务端定时检查的结果只读展示；非服务器模式完全不请求、不轮询。
  useEffect(() => {
    if (workspaceMode !== 'server') {
      setServerUpstream(null)
      setServerUpstreamError('')
      return
    }
    let cancelled = false
    const load = async () => {
      try {
        const next = await fetchUpstreamStatus()
        if (cancelled) return
        setServerUpstream(next)
        setServerUpstreamError('')
      } catch (error) {
        if (!cancelled) setServerUpstreamError((error as Error).message)
      }
    }
    void load()
    const timer = window.setInterval(() => { void load() }, 5 * 60 * 1000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [workspaceMode])

  const checkUpstreamNow = async () => {
    if (upstreamChecking) return
    setUpstreamChecking(true)
    setServerUpstreamError('')
    try {
      await triggerUpstreamStatusCheck()
      // 手动检查在服务端异步执行；这里轮询到 checking 结束，避免“点了没反应”。
      // 服务端要串行比对 3 个内置方案（trees 失败还会退回逐文件 HEAD），
      // 最坏可能超过 90 秒，所以上限给到 180 秒，避免按钮一直停在“检查中”。
      const deadline = Date.now() + 180_000
      while (Date.now() < deadline) {
        await new Promise((resolve) => window.setTimeout(resolve, 1500))
        const next = await fetchUpstreamStatus()
        setServerUpstream(next)
        if (!next.checking) break
      }
    } catch (error) {
      setServerUpstreamError((error as Error).message)
    } finally {
      setUpstreamChecking(false)
    }
  }

  const allMetas = allSchemeMetas(customSchemes)
  const selectedMeta = allMetas.find((m) => m.id === selectedSchemeID)
  // 覆盖层只存指针；这里解引用成快照。损坏时自动回落并在下方逐级提示。
  const selectedBuiltinResolution = selectedMeta && !('custom' in selectedMeta)
    ? resolveBuiltinSchemeSnapshot(selectedMeta.id, builtinSchemeOverrides, schemeSnapshots)
    : undefined
  const selectedBuiltinOverride = selectedBuiltinResolution?.snapshot
  const selectedSnapshotHistory = useMemo(
    () => selectedMeta && !('custom' in selectedMeta)
      ? snapshotsForScheme(schemeSnapshots, selectedMeta.id)
      : [],
    [selectedMeta, schemeSnapshots],
  )
  const snapshotFallbackNotice = selectedBuiltinResolution?.missingId !== undefined
    ? selectedBuiltinResolution.fallback === 'previous' && selectedBuiltinResolution.snapshot
      ? `固化快照 #${selectedBuiltinResolution.missingId} 损坏或缺失，已自动回落到上一版 #${selectedBuiltinResolution.snapshot.id}。`
      : `固化快照 #${selectedBuiltinResolution.missingId} 损坏或缺失，已自动回落到原厂快照。`
    : undefined
  const customScheme = customSchemes.find((c) => c.id === scheme?.id)
  const schemeRules = useMemo(
    () => scheme ? orderedSchemeRules(scheme) : [],
    [scheme],
  )
  // 逐条顺序卡片：大方案只渲染前 300 条，搜索用来定位；顺序本身仍按全量计算。
  const ruleOrderRows = useMemo(() => {
    const query = ruleOrderSearch.trim().toLowerCase()
    const rows = schemeRules
      .map((rule, index) => ({ rule, index }))
      .filter(({ rule }) => !query
        || `${rule.type} ${rule.value ?? ''} ${rule.group} ${rule.sourceName ?? ''}`.toLowerCase().includes(query))
    return { total: rows.length, rows: rows.slice(0, 300) }
  }, [schemeRules, ruleOrderSearch])
  const enabledForRules = useMemo(() => enabledNodes({ sources, nodes }), [sources, nodes])
  // 方案卡已经显示总数；策略组卡片只补充不重复的信息。
  const groupCardMeta = useMemo(() => {
    if (!scheme) return ''
    const parts: string[] = []
    const customRules = scheme.customRules?.length ?? 0
    if (customRules > 0) parts.push(`自定义规则 ${customRules} 条`)
    const matchingGroups = scheme.groups.filter((group) => group.nodeFilter?.trim()).length
    if (matchingGroups > 0) parts.push(`${matchingGroups} 个策略组按名称匹配节点`)
    return parts.join(' · ') || '可调整顺序'
  }, [scheme])

  useEffect(() => {
    if (!flash) return
    const timer = window.setTimeout(() => setFlash(''), 4200)
    return () => window.clearTimeout(timer)
  }, [flash])

  /** 空的策略组 / 规则会让导出的配置不可用；策略组图问题作为可修正提示展示。 */
  const validateScheme = (parsed: RuleScheme) => {
    if (!parsed.groups.length || !parsed.rules.length) {
      throw new Error('没有解析到策略组或规则，请检查方案内容或规则列表地址')
    }
    const available = enabledNodes(useStore.getState())
    const issues = validateSchemePolicy(
      parsed,
      available.map((node) => node.name),
      available.length === 0,
    )
    parsed.policyWarnings = issues.length ? issues.map(policyIssueText) : undefined
    return parsed
  }

  const importSchemeFromRemote = async (name: string, rawURL: string) => {
    if (!name.trim()) { setSchemeError('请先填写方案名称'); return }
    if (!rawURL.trim()) { setSchemeError('请填写方案地址'); return }
    const sourceURL = normalizeRemoteTextURL(rawURL)
    setSchemeLoading(true); setSchemeError(null)
    try {
      const res = await apiFetch(`/api/fetch?url=${encodeURIComponent(sourceURL)}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const text = await res.text()
      const format = detectRuleSchemeFormat(text)
      const parsed = validateScheme(await parseRuleSchemeText(
        `custom-${Date.now()}`, name.trim(), '从 URL 导入', text, format,
      ))
      addCustomScheme({
        ...parsed,
        sourceKind: 'url',
        sourceFormat: format,
        sourceURL,
        rawConfigurationText: text,
        updatedAt: Date.now(),
        customRules: [],
      })
      setScheme(parsed.id)
      setImportingScheme(false); setSchemeName(''); setSchemeURL(''); setSchemeText(''); setSchemeFileName('')
    } catch (e: any) {
      setSchemeError(e.message ?? '导入失败')
    } finally { setSchemeLoading(false) }
  }

  const importSchemeFromURL = () => importSchemeFromRemote(schemeName, schemeURL)

  const importSelfConfiguration = () => importSchemeFromRemote(SELF_CONFIGURATION_NAME, SELF_CONFIGURATION_URL)

  const importSchemeFromText = async () => {
    if (!schemeName.trim()) { setSchemeError('请先填写方案名称'); return }
    if (!schemeText.trim()) { setSchemeError('请粘贴方案内容'); return }
    setSchemeLoading(true); setSchemeError(null)
    try {
      const description = schemeFileName ? `从文件导入：${schemeFileName}` : '粘贴导入'
      const format = detectRuleSchemeFormat(schemeText)
      const parsed = validateScheme(await parseRuleSchemeText(
        `custom-${Date.now()}`, schemeName.trim(), description, schemeText, format,
      ))
      addCustomScheme({
        ...parsed,
        sourceKind: schemeFileName ? 'file' : 'paste',
        sourceFormat: format,
        rawConfigurationText: schemeText,
        updatedAt: Date.now(),
        customRules: [],
      })
      // 与 URL 导入保持一致：导入成功后立即启用新方案。
      setScheme(parsed.id)
      setImportingScheme(false); setSchemeName(''); setSchemeURL(''); setSchemeText(''); setSchemeFileName('')
    } catch (e: any) {
      setSchemeError(e.message ?? '解析失败')
    } finally { setSchemeLoading(false) }
  }

  const readSchemeFile = async (file?: File) => {
    if (!file) return
    setSchemeError(null)
    try {
      const text = await file.text()
      if (!text.trim()) throw new Error('文件内容为空')
      setSchemeText(text)
      setSchemeFileName(file.name)
      if (!schemeName.trim()) setSchemeName(file.name.replace(/\.[^.]+$/, ''))
    } catch (e: any) {
      setSchemeError(e.message ?? '无法读取文件')
    }
  }

  /** 修改内置方案前先复制，保留用户原来的策略组选择。 */
  const makeEditableScheme = (source: RuleScheme): RuleScheme => {
    const existing = customSchemes.find((c) => c.id === source.id)
    if (existing) return existing
    const copy = createEditableSchemeCopy(source, { id: `custom-${Date.now()}` })
    const previousSelections = useStore.getState().policySelections
    addCustomScheme(copy)
    setScheme(copy.id)
    for (const [group, selection] of Object.entries(previousSelections)) {
      useStore.getState().setPolicy(group, selection)
    }
    setFlash(`已创建副本「${copy.name}」，后续修改只作用于副本，原内置方案「${source.name}」不变。`)
    return copy
  }

  // 从 ACL4SSR 上游拉最新 INI + 全部列表；先算差异预览，用户确认后才写覆盖层。
  // 全有或全无：失败时只报错，不写覆盖层，原厂快照继续兜底。
  const freezeBuiltinScheme = async (meta: SchemeMeta) => {
    setUpdatingBuiltinScheme(true)
    setSchemeError(null)
    try {
      const result = await fetchUpstreamScheme(meta)
      const current = await loadScheme(meta, builtinSchemeOverrides, schemeSnapshots)
      const plan = planBuiltinSchemeFreeze({
        currentScheme: current,
        content: result.override,
        customSchemes,
      })
      setPendingFreeze({ meta, result, plan })
    } catch (e) {
      setSchemeError((e as Error).message)
    } finally {
      setUpdatingBuiltinScheme(false)
    }
  }

  /** 预览确认后的实际写入；与旧流程相同的覆盖层 + 3 版环形语义。 */
  const confirmFreeze = async () => {
    if (!pendingFreeze) return
    const { meta, result } = pendingFreeze
    setPendingFreeze(null)
    const snapshotId = saveBuiltinSchemeOverride(meta.id, result.override)
    // 0 表示写保护生效（等待期间切到只读）或内容未通过快照校验。
    if (snapshotId === 0) {
      setSchemeError('未能保存固化快照：当前工作区处于只读状态，或快照内容校验失败。')
      return
    }
    setScheme(meta.id)
    setFlash(`已更新并固化「${meta.name}」：${result.override.source.ruleCount} 条规则、${result.ruleSets.length} 个列表（快照 #${snapshotId}）；已导出的客户端配置不会自动回滚。原厂快照保留，可随时恢复或回退。`)
    if (workspaceMode === 'server') {
      // 固化写入工作区后，服务端状态文件里的结果已过期；等工作区落盘后
      // 再检查一次，让提示从「有新版本」及时回到「已是最新」。
      await flushWorkspaceNow()
      void checkUpstreamNow()
    }
  }

  // 「生成自定义副本」：分支修改用；只写自定义方案与「我的规则集」，不碰覆盖层。
  const copyBuiltinSchemeFromUpstream = async (meta: SchemeMeta) => {
    setUpdatingBuiltinScheme(true)
    setSchemeError(null)
    try {
      const result = await fetchUpstreamScheme(meta)
      for (const set of result.ruleSets) {
        const existing = localRuleSets.find((item) => item.sourceURL === set.sourceURL)
        addLocalRuleSet(existing ? { ...set, id: existing.id, paused: existing.paused } : set)
      }
      // fetchUpstreamScheme 返回的 scheme.id 仍是内置方案 id（它要用来写覆盖层）。
      // 直接塞进 customSchemes 会跟内置方案同 id：列表里显示内置方案，
      // 内容却来自副本，恢复原厂 / 固化都会被副本遮住。
      // 名称补上「· 自定义」，与按钮和提示里的「自定义副本」一致；
      // 上游日期保留，便于在方案列表里区分不同批次。
      const copy = {
        ...result.scheme,
        id: `custom-${Date.now()}`,
        name: `${result.scheme.name} · 自定义`,
        sourceKind: 'copy' as const,
      }
      addCustomScheme(copy)
      setScheme(copy.id)
      setFlash(`已生成自定义副本「${copy.name}」；内置方案未改动。`)
    } catch (e) {
      setSchemeError((e as Error).message)
    } finally {
      setUpdatingBuiltinScheme(false)
    }
  }

  // 清掉覆盖层，立刻回到 public/rulesets 原厂快照；按钮回到初始态。
  const restoreBuiltinSnapshot = async (meta: SchemeMeta) => {
    setUpdatingBuiltinScheme(true)
    setSchemeError(null)
    try {
      clearBuiltinSchemeOverride(meta.id)
      // 覆盖层变化会触发 useScheme 重新 loadScheme；这里只确保仍选中这条内置方案。
      setScheme(meta.id)
      setFlash(`已恢复「${meta.name}」的原厂快照。`)
    } catch (e) {
      setSchemeError(`恢复原厂快照失败：${(e as Error).message}`)
    } finally {
      setUpdatingBuiltinScheme(false)
    }
  }

  // 回退前先算清数字与受影响方案：规则数变化、自定义方案、已导出配置提示。
  const requestSnapshotRollback = (meta: SchemeMeta, snapshotId: number) => {
    const plan = planSnapshotRollback({
      snapshots: schemeSnapshots,
      overrides: builtinSchemeOverrides,
      customSchemes,
      schemeID: meta.id,
      targetID: snapshotId,
      factoryRuleCount: scheme?.rules.length,
    })
    if (!plan) {
      setSchemeError(`快照 #${snapshotId} 不可用，无法回退。`)
      return
    }
    setPendingSnapshotRollback(plan)
  }

  const confirmSnapshotRollback = () => {
    const plan = pendingSnapshotRollback
    setPendingSnapshotRollback(null)
    if (!plan) return
    // 以计划里的 schemeID 为准：弹窗打开期间别的设备同步可能切换当前方案，
    // 用 selectedMeta 会把回退落到错误的内置方案上。
    const targetSchemeID = plan.target.schemeID
    if (!restoreBuiltinSchemeSnapshot(targetSchemeID, plan.target.id)) {
      setSchemeError(`回退失败：快照 #${plan.target.id} 不可用。`)
      return
    }
    const targetMeta = BUILTIN_SCHEMES.find((meta) => meta.id === targetSchemeID)
    setScheme(targetSchemeID)
    setFlash(`已回退「${targetMeta?.name ?? targetSchemeID}」到快照 #${plan.target.id}：规则 ${plan.fromCount} → ${plan.toCount} 条。已导出的客户端配置不会自动回滚，需要重新导出或让客户端刷新订阅。`)
  }

  const beginEditScheme = () => {
    if (!scheme) return
    const editable = customScheme ?? makeEditableScheme(scheme)
    setEditingScheme(editable)
  }

  const saveSchemeMeta = (next: RuleScheme) => {
    addCustomScheme({ ...next, updatedAt: Date.now() })
    setFlash(`已保存方案「${next.name}」。`)
  }

  const builtinForCustom = customScheme?.sourceKind === 'copy'
    ? BUILTIN_SCHEMES.find((meta) => meta.name === stripSchemeCustomSuffix(customScheme.name))
    : undefined

  const restoreInitialRules = async () => {
    if (!customScheme || !builtinForCustom) return
    setRestoreInitialConfirm(false)
    try {
      const original = await loadScheme(builtinForCustom, builtinSchemeOverrides, schemeSnapshots)
      addCustomScheme({
        ...original,
        id: customScheme.id,
        name: customScheme.name,
        description: customScheme.description,
        sourceKind: 'copy',
        rawConfigurationText: undefined,
        customRules: [],
        // 恢复初始规则时用快照重新挂回的只读规则集（inlined）；用户自己加的规则集清空。
        ruleSets: original.ruleSets ?? [],
        matchingOrder: undefined,
        ruleOrder: undefined,
        updatedAt: Date.now(),
      })
      setScheme(customScheme.id)
      setFlash(`已恢复「${builtinForCustom.name}」的初始策略组和规则。`)
    } catch (error) {
      setFlash(`恢复初始规则失败：${error instanceof Error ? error.message : String(error)}`)
    }
  }

  const autoFillGroupEmoji = () => {
    if (!scheme) return
    const editable = customScheme ?? makeEditableScheme(scheme)
    const result = autoFillGroupEmojis(editable)
    if (!result.renamed.length) {
      setFlash('所有策略组都已经带 Emoji。')
      return
    }
    addCustomScheme(result.scheme)
    for (const [oldName, newName] of result.renamed) {
      useStore.getState().renamePolicySelection(oldName, newName)
    }
    setShowGroupEmoji(true)
    setFlash(`已为 ${result.renamed.length} 个策略组补全 Emoji，并同步更新规则引用。`)
  }

  const createNodeGroup = (source: RuleScheme, group: PolicyGroup) => {
    const editable = makeEditableScheme(source)
    addCustomScheme({
      ...editable,
      groups: [...editable.groups, group],
      updatedAt: Date.now(),
    })
    setCreatingGroup(null)
    setFlash(`已新建策略组「${group.name}」。它现在还没有规则，可在「自定义规则」里把域名或 IP 加进来。`)
  }

  const deleteNodeGroup = (source: RuleScheme, group: PolicyGroup) => {
    if (source.groups.length <= 1) {
      setPendingGroupDelete(null)
      setFlash('至少保留一个策略组，不能删除最后一个组。')
      return
    }
    const editable = makeEditableScheme(source)
    const result = removePolicyGroup(editable, group.name)
    addCustomScheme(result.scheme)
    removePolicy(group.name)
    setPendingGroupDelete(null)
    const details: string[] = []
    if (result.removedRules > 0) details.push(`${result.removedRules} 条规则`)
    if (result.removedCustomRules > 0) details.push(`${result.removedCustomRules} 条自定义规则`)
    if (result.removedRuleSets > 0) details.push(`${result.removedRuleSets} 组规则集`)
    if (result.referencingGroups.length > 0) {
      details.push(`${result.referencingGroups.length} 个组引用（${result.referencingGroups.map((name) => groupDisplayName(name, true)).join('、')}）`)
    }
    setFlash(`已删除策略组「${group.name}」${details.length ? `，同时移除了 ${details.join('、')}` : ''}。`)
  }

  const beginEditNetwork = () => {
    if (!scheme) return
    setNetworkEditor(customScheme ?? makeEditableScheme(scheme))
  }

  const saveNetworkSettings = (next: RuleScheme) => {
    addCustomScheme({ ...next, updatedAt: Date.now() })
    setNetworkEditor(null)
    setFlash('DNS 与网络设置已保存。')
  }

  /** 拖动 / 上下移：同时调整策略组顺序和该组规则的匹配位置。 */
  const reorderGroups = (source: RuleScheme, from: number, to: number) => {
    const editable = makeEditableScheme(source)
    if (from < 0 || from >= editable.groups.length || to < 0 || to >= editable.groups.length || from === to) {
      return
    }
    const beforeNames = editable.groups.map((group) => group.name)
    const groups = [...editable.groups]
    const [moved] = groups.splice(from, 1)
    groups.splice(to, 0, moved)
    const names = groups.map((group) => group.name)
    const knownGroups = new Set(names)
    const matchingRules = orderedSchemeBaseRules(editable)
    const currentMatching = matchingGroupNames(matchingRules, knownGroups)
    const nextMatching = matchingOrderAfterDragging(moved.name, beforeNames, names, currentMatching)
    const changed = nextMatching.join('\n') !== currentMatching.join('\n')
    const conflicts = findRuleOrderConflicts(editable, currentMatching, nextMatching)
    setReorderUndo({
      schemeID: editable.id,
      groups: editable.groups,
      matchingOrder: editable.matchingOrder,
      ruleOrder: editable.ruleOrder,
      conflicts,
    })
    const hadRuleOrder = (editable.ruleOrder?.length ?? 0) > 0
    // 逐条顺序被清空后，旧的撤销槽已经失效；留着会让「撤销」把旧顺序重新盖回组排序之上。
    if (hadRuleOrder) setRuleOrderUndo(null)
    addCustomScheme({
      ...editable,
      groups,
      ...(changed ? { matchingOrder: nextMatching } : {}),
      // 组级拖动优先：它改写的是整组位置，旧的逐条顺序会与新的组顺序打架，清空避免静默覆盖。
      ruleOrder: undefined,
      updatedAt: Date.now(),
    })
    setFlash(changed
      ? `已调整「${moved.name}」的顺序，并把它的规则移到对应匹配位置${hadRuleOrder ? '；逐条手动排序已重置（组排序优先）' : ''}。`
      : `已调整「${moved.name}」的策略组顺序${hadRuleOrder ? '；逐条手动排序已重置' : ''}。`)
  }

  const moveGroup = (source: RuleScheme, index: number, delta: -1 | 1) => {
    reorderGroups(source, index, index + delta)
  }

  const undoGroupReorder = () => {
    if (!reorderUndo) return
    const fresh = useStore.getState().customSchemes.find((scheme) => scheme.id === reorderUndo.schemeID)
    if (fresh) {
      addCustomScheme({
        ...fresh,
        groups: reorderUndo.groups,
        matchingOrder: reorderUndo.matchingOrder,
        ruleOrder: reorderUndo.ruleOrder,
        updatedAt: Date.now(),
      })
      setFlash('已撤销策略组排序和匹配顺序。')
    }
    setReorderUndo(null)
  }

  /**
   * 逐条上移 / 下移。只在相邻兜底锚点之间交换，写回 ruleOrder；
   * 展示（orderedSchemeRules）与导出（prepareSchemeForExport）都走同一份顺序。
   */
  const moveRule = (source: RuleScheme, index: number, delta: -1 | 1) => {
    if (readOnly) return
    const editable = makeEditableScheme(source)
    const ordered = orderedSchemeRules(editable)
    const target = index + delta
    if (index < 0 || index >= ordered.length || target < 0 || target >= ordered.length) return
    if (isUnmovableRule(ordered[index]) || isUnmovableRule(ordered[target])) return
    const next = [...ordered]
    const [moved] = next.splice(index, 1)
    next.splice(target, 0, moved)
    const ruleOrder = ruleOrderKeys(next)
    setRuleOrderUndo({
      schemeID: editable.id,
      ruleOrder: editable.ruleOrder,
      label: `${moved.type} ${moved.value ?? ''}`.trim(),
    })
    addCustomScheme({ ...editable, ruleOrder, updatedAt: Date.now() })
    setFlash(`${delta < 0 ? '已上移' : '已下移'}规则「${moved.type} ${moved.value ?? ''}」。`)
  }

  const undoRuleOrder = () => {
    if (!ruleOrderUndo) return
    const fresh = useStore.getState().customSchemes.find((scheme) => scheme.id === ruleOrderUndo.schemeID)
    if (fresh) {
      addCustomScheme({ ...fresh, ruleOrder: ruleOrderUndo.ruleOrder, updatedAt: Date.now() })
      setFlash('已撤销逐条规则排序。')
    }
    setRuleOrderUndo(null)
  }

  /** 策略组名称匹配到的节点，供首选策略下拉使用。 */
  const nodeChoicesFor = (group: PolicyGroup): string[] => {
    if (!group.nodeFilter) return []
    try {
      const regex = new RegExp(group.nodeFilter)
      return enabledForRules.filter((node) => regex.test(node.name)).map((node) => node.name)
    } catch {
      return []
    }
  }

  const beginEditGroup = (
    source: RuleScheme,
    group: PolicyGroup,
    tab: 'settings' | 'rules' = 'settings',
    query?: string,
  ) => {
    const editable = makeEditableScheme(source)
    const target = editable.groups.find((g) => g.name === group.name) ?? group
    setGroupEditor({ scheme: editable, group: target, tab, query })
  }

  const locateLintIssue = (issue: SchemeLintIssue) => {
    if (issue.location.kind === 'target') {
      onGo?.('export')
      return
    }
    let groupName = issue.location.group
    // 规则集问题可能只带规则集名；回查它绑定的策略组，仍能落到具体规则。
    if (!groupName && issue.location.ruleSet && scheme) {
      const set = scheme.ruleSets?.find((item) =>
        item.name === issue.location.ruleSet || item.id === issue.location.ruleSet)
      groupName = set?.group
    }
    if (!groupName) return
    const group = scheme?.groups.find((item) => item.name === groupName)
    if (!group) {
      window.alert(`策略组「${groupName}」当前不存在，无法定位。请先在方案里补充该策略组。`)
      return
    }
    if (scheme) {
      beginEditGroup(scheme, group, issue.location.kind === 'rule' || issue.location.kind === 'ruleSet' ? 'rules' : 'settings', issue.location.rule)
    }
  }

  // 诊断页点「定位」后跳到本页：挂载后消费一次，避免重复弹窗。
  useEffect(() => {
    if (!locateIssue) return
    locateLintIssue(locateIssue)
    onLocateConsumed?.()
    // locateLintIssue 依赖当前方案，方案切换时不应重放旧定位。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [locateIssue])

  const saveGroupEdit = (target: { scheme: RuleScheme; group: PolicyGroup }, updated: PolicyGroup) => {
    const fresh = useStore.getState().customSchemes.find((c) => c.id === target.scheme.id) ?? target.scheme
    const oldName = target.group.name
    const newName = updated.name
    const groups = fresh.groups.map((group) => {
      if (group.name === oldName) return updated
      if (!group.options.includes(oldName)) return group
      return {
        ...group,
        options: group.options.map((option) => option === oldName ? newName : option),
      }
    })
    const rules = fresh.rules.map((rule) =>
      rule.group === oldName ? { ...rule, group: newName } : rule,
    )
    const customRules = (fresh.customRules ?? []).map((rule) =>
      rule.group === oldName ? { ...rule, group: newName } : rule,
    )
    const ruleSets = (fresh.ruleSets ?? []).map((set) => ({
      ...set,
      group: set.group === oldName ? newName : set.group,
      rules: set.rules.map((rule) =>
        rule.group === oldName ? { ...rule, group: newName } : rule,
      ),
    }))
    // 拖拽排序记录的是组名；改名后不改这里，规则会悄悄丢掉用户排好的匹配顺序。
    const matchingOrder = (fresh.matchingOrder ?? []).map((name) => name === oldName ? newName : name)
    const ruleOrder = oldName === newName
      ? fresh.ruleOrder
      : renameRuleOrderKeys(fresh.ruleOrder, [[oldName, newName]])
    addCustomScheme({ ...fresh, groups, rules, customRules, ruleSets, matchingOrder, ruleOrder, updatedAt: Date.now() })
    if (oldName !== newName) {
      useStore.getState().renamePolicySelection(oldName, newName)
      setFlash(`策略组已改名为「${newName}」，规则和候选引用已同步更新。`)
    } else {
      setFlash(`已保存策略组「${newName}」。`)
    }
  }

  const saveSchemeText = async (text: string): Promise<string | undefined> => {
    const editable = customScheme
    if (!editable) return '请先选择一个自定义方案'
    if (!text.trim()) return '配置内容不能为空'
    try {
      const format = detectRuleSchemeFormat(text)
      const parsed = validateScheme(await parseRuleSchemeText(
        editable.id, editable.name, editable.description, text, format,
      ))
      const validGroups = new Set(parsed.groups.map((group) => group.name))
      const customRules = (editable.customRules ?? []).filter((rule) => validGroups.has(rule.group))
      const ruleSets = (editable.ruleSets ?? [])
        .filter((set) => validGroups.has(set.group))
        .map((set) => ({
          ...set,
          rules: set.rules.filter((rule) => validGroups.has(rule.group)),
        }))
        .filter((set) => set.rules.length > 0)
      addCustomScheme({
        ...parsed,
        id: editable.id,
        name: editable.name,
        description: editable.description,
        sourceKind: editable.sourceKind ?? 'paste',
        sourceURL: editable.sourceURL,
        sourceFormat: format,
        rawConfigurationText: text,
        networkSettings: parsed.networkSettings ?? editable.networkSettings,
        customRules,
        ruleSets,
        matchingOrder: editable.matchingOrder?.filter((group) => validGroups.has(group)),
        // 全文重建后规则身份可能全变，逐条顺序按新内容重新开始。
        ruleOrder: undefined,
        updatedAt: Date.now(),
      })
      setFlash('已按全文重建方案；自定义规则和规则集快照已尽量保留。')
      return undefined
    } catch (e: any) {
      return e.message ?? '解析失败'
    }
  }

  const refreshImportedScheme = async () => {
    const editable = customScheme
    if (!editable?.sourceURL) return
    const sourceURL = normalizeRemoteTextURL(editable.sourceURL)
    setRefreshingScheme(true); setSchemeError(null)
    try {
      const res = await apiFetch(`/api/fetch?url=${encodeURIComponent(sourceURL)}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const text = await res.text()
      const format = detectRuleSchemeFormat(text)
      const parsed = validateScheme(await parseRuleSchemeText(
        editable.id, editable.name, editable.description, text, format,
      ))
      // 保留用户调整过的组顺序；新增组追加到末尾。
      const previousOrder = editable.groups.map((g) => g.name)
      const rank = (name: string) => {
        const index = previousOrder.indexOf(name)
        return index < 0 ? Number.MAX_SAFE_INTEGER : index
      }
      const groups = [...parsed.groups].sort((a, b) => rank(a.name) - rank(b.name))
      const validGroups = new Set(groups.map((g) => g.name))
      const customRules = (editable.customRules ?? []).filter((r) => validGroups.has(r.group))
      const ruleSets = (editable.ruleSets ?? [])
        .filter((set) => validGroups.has(set.group))
        .map((set) => ({
          ...set,
          rules: set.rules.filter((rule) => validGroups.has(rule.group)),
        }))
        .filter((set) => set.rules.length > 0)
      const removed = (editable.customRules ?? []).length - customRules.length
      addCustomScheme({
        ...parsed,
        id: editable.id,
        name: editable.name,
        description: editable.description,
        sourceKind: 'url',
        sourceFormat: format,
        sourceURL,
        rawConfigurationText: text,
        networkSettings: editable.networkSettings ?? parsed.networkSettings,
        updatedAt: Date.now(),
        groups,
        customRules,
        ruleSets,
      })
      setFlash(removed
        ? `方案已刷新；移除了 ${removed} 条指向已删除策略组的自定义规则。`
        : '方案已从来源刷新。')
    } catch (e: any) {
      setSchemeError(e.message ?? '刷新失败')
    } finally { setRefreshingScheme(false) }
  }

  const beginAddCustomRule = (source: RuleScheme, group?: string) => {
    const editable = makeEditableScheme(source)
    setCustomRuleTarget(editable)
    setCustomRuleGroup(group)
  }

  const saveCustomRule = (target: RuleScheme, rule: RoutingRule) => {
    const fresh = useStore.getState().customSchemes.find((c) => c.id === target.id) ?? target
    addCustomScheme({
      ...fresh,
      customRules: [...(fresh.customRules ?? []), rule],
      updatedAt: Date.now(),
    })
    setFlash(`已添加自定义规则，它会排在方案规则最前。${ruleImpactText(analyzeRuleImpact(fresh, rule, { includeCandidate: true }))}`)
  }

  const removeCustomRule = (target: RuleScheme, rule: RoutingRule) => {
    const fresh = useStore.getState().customSchemes.find((c) => c.id === target.id) ?? target
    addCustomScheme({
      ...fresh,
      customRules: (fresh.customRules ?? []).filter((r) => !(
        r.group === rule.group && r.type === rule.type && (r.value ?? '') === (rule.value ?? '')
      )),
      updatedAt: Date.now(),
    })
    setFlash('已删除自定义规则。')
  }

  const applyRuleSet = (source: RuleScheme, payload: RuleSetPayload) => {
    if (payload.rules.length === 0) return
    const editable = makeEditableScheme(source)
    const rules: RoutingRule[] = payload.rules.map((rule) => ({
      ...rule,
      group: payload.group,
      sourceName: payload.name,
    }))
    const existing = editable.ruleSets ?? []
    const existingIndex = payload.sourceRef
      ? existing.findIndex((set) => set.sourceRef === payload.sourceRef && set.group === payload.group)
      : -1
    const snapshot: SchemeRuleSet = {
      id: existingIndex >= 0 ? existing[existingIndex].id : newID(),
      name: payload.name,
      group: payload.group,
      rules,
      sourceKind: payload.sourceKind,
      sourceRef: payload.sourceRef,
      format: payload.format,
      updatedAt: Date.now(),
    }
    const ruleSets = existingIndex >= 0
      ? existing.map((set, index) => index === existingIndex ? snapshot : set)
      : [...existing, snapshot]
    addCustomScheme({ ...editable, ruleSets, updatedAt: Date.now() })
    setFlash(existingIndex >= 0
      ? `已更新「${payload.name}」：${rules.length} 条规则仍然加入「${payload.group}」。`
      : `已把「${payload.name}」的 ${rules.length} 条规则加入「${payload.group}」。`)
  }

  const addLocalSetToScheme = (source: RuleScheme, set: LocalRuleSet, group: string) => {
    applyRuleSet(source, {
      name: set.name,
      group,
      rules: set.rules,
      sourceKind: set.sourceURL ? 'url' : 'local',
      sourceRef: set.sourceURL ?? set.id,
      format: set.sourceURL ? set.format : undefined,
    })
  }

  const saveRemoteRuleSets = (incoming: LocalRuleSet[], joinGroup?: string, notice?: string) => {
    // 同一地址只保留一条订阅，重复添加时更新快照。
    const saved: LocalRuleSet[] = []
    for (const set of incoming) {
      const fresh = useStore.getState()
      const existing = fresh.localRuleSets.find((item) => item.sourceURL === set.sourceURL)
      if (existing && digestRules(existing.rules) !== digestRules(set.rules)) {
        recordRuleSetSnapshot(existing.id, existing.rules, fresh.ruleSetVersionHistory)
      }
      const savedSet = existing ? { ...set, id: existing.id, paused: existing.paused } : set
      addLocalRuleSet(savedSet)
      saved.push(savedSet)
    }
    if (joinGroup && scheme) {
      // 多个规则集依次加入同一个方案；每次读取最新方案，避免后一次覆盖前一次。
      for (const savedSet of saved) {
        const freshScheme = useStore.getState().customSchemes.find((item) => item.id === scheme.id) ?? scheme
        addLocalSetToScheme(freshScheme, savedSet, joinGroup)
      }
    }
    const total = saved.reduce((sum, item) => sum + item.rules.length, 0)
    const detail = notice ? `；${notice}` : ''
    const prefix = joinGroup && scheme ? '已保存并加入' : '已保存'
    setFlash(saved.length === 1
      ? `${prefix}在线规则集「${saved[0].name}」：${total} 条规则${detail}。`
      : `${prefix} ${saved.length} 个在线规则集：共 ${total} 条规则${detail}。`)
  }

  const refreshLocalRuleSet = async (set: LocalRuleSet) => {
    if (!set.sourceURL) return
    setRefreshingRuleSetID(set.id)
    setRuleSetError(null)
    try {
      const parsed = await fetchRuleSet(set.sourceURL)
      // 只有内容真的变了才写快照：刷新成功但内容不变时不覆盖已有历史。
      if (digestRules(parsed.rules) !== digestRules(set.rules)) {
        recordRuleSetSnapshot(set.id, set.rules, useStore.getState().ruleSetVersionHistory)
      }
      const updated = ruleSetRefreshSuccess(set, parsed.rules)
      addLocalRuleSet({ ...updated, format: parsed.format })
      const diff = updated.lastDiff
      setFlash(`已刷新「${set.name}」：${parsed.rules.length} 条规则（+${diff?.added ?? 0} −${diff?.removed ?? 0} ~${diff?.modified ?? 0}）；${describeRuleSetParse(parsed)}。`)
    } catch (e) {
      const message = (e as Error).message
      addLocalRuleSet(ruleSetRefreshFailure(set, message))
      setRuleSetError(`「${set.name}」刷新失败：${message}`)
    } finally {
      setRefreshingRuleSetID(null)
    }
  }

  const refreshAllLocalRuleSets = async () => {
    const sets = localRuleSets.filter((set) => set.sourceURL && !set.paused)
    if (!sets.length) return
    setRefreshingRuleSetID('all')
    setRuleSetError(null)
    let ok = 0
    let skippedTotal = 0
    const diffs: (RuleSetRefreshDiff | undefined)[] = []
    const errors: string[] = []
    for (const set of sets) {
      try {
        const parsed = await fetchRuleSet(set.sourceURL!)
        skippedTotal += parsed.skippedLines ?? 0
        if (digestRules(parsed.rules) !== digestRules(set.rules)) {
          recordRuleSetSnapshot(set.id, set.rules, useStore.getState().ruleSetVersionHistory)
        }
        const updated = ruleSetRefreshSuccess(set, parsed.rules)
        addLocalRuleSet({ ...updated, format: parsed.format })
        diffs.push(updated.lastDiff)
        ok += 1
      } catch (error) {
        const message = (error as Error).message
        addLocalRuleSet(ruleSetRefreshFailure(set, message))
        errors.push(`「${set.name}」${message}`)
      }
    }
    setRefreshingRuleSetID(null)
    const changed = sumRuleSetDiffs(diffs)
    const totals = ok ? `：+${changed.added} −${changed.removed} ~${changed.modified}` : ''
    setFlash(`已刷新 ${ok} 个在线规则集${totals}${errors.length ? `，${errors.length} 个失败` : ''}${skippedTotal ? `，跳过 ${skippedTotal} 行` : ''}。`)
    if (errors.length) setRuleSetError(errors.join('；'))
  }

  const toggleLocalRuleSetPaused = (set: LocalRuleSet) => {
    addLocalRuleSet({ ...set, paused: !set.paused })
    setFlash(set.paused ? `已恢复「${set.name}」的自动刷新。` : `已暂停「${set.name}」的自动刷新；仍可手动刷新。`)
  }

  const renameLocalRuleSet = (set: LocalRuleSet, name: string) => {
    addLocalRuleSet({ ...set, name: name.trim() })
    setFlash(`已重命名为「${name.trim()}」。已加入方案的条目保持原名称。`)
  }

  const importLocalRuleSetFiles = async (files: File[] | null) => {
    if (!files?.length) return
    if (files.length > 20) {
      setRuleSetError('一次最多导入 20 个规则文件')
      return
    }
    setRuleSetError(null)
    const taken = new Set(localRuleSets.map((set) => set.name.trim()))
    const created: LocalRuleSet[] = []
    const errors: string[] = []
    let skippedTotal = 0
    for (const file of files) {
      try {
        if (file.size > 8 * 1024 * 1024) throw new Error('文件大于 8 MB')
        const textBody = await file.text()
        const parsed = parseRuleSetText(textBody)
        skippedTotal += parsed.skippedLines ?? 0
        const base = file.name.replace(/\.[^.]+$/, '').trim() || '导入规则集'
        let name = base
        let suffix = 2
        while (taken.has(name)) {
          name = `${base} ${suffix}`
          suffix += 1
        }
        taken.add(name)
        created.push({
          id: newID(),
          name,
          rules: parsed.rules,
          updatedAt: Date.now(),
          format: parsed.format,
        })
      } catch (error) {
        errors.push(`${file.name}：${(error as Error).message}`)
      }
    }
    for (const set of created) addLocalRuleSet(set)
    if (created.length) setFlash(`已导入 ${created.length} 个规则集${skippedTotal ? `，跳过 ${skippedTotal} 行` : ''}。`)
    if (errors.length) setRuleSetError(errors.join('；'))
  }

  const localSetNeedle = localSetSearch.trim().toLowerCase()
  const visibleLocalRuleSets = localSetNeedle
    ? localRuleSets.filter((set) => {
        const formatLabel = set.format ? RULE_SET_FORMAT_TITLES[set.format] : ''
        return [set.name, set.sourceURL ?? '', formatLabel]
          .some((text) => text.toLowerCase().includes(localSetNeedle))
      })
    : localRuleSets

  const refreshSchemeRuleSet = async (set: SchemeRuleSet) => {
    const fresh = customScheme
    if (!fresh || set.sourceKind !== 'url' || !set.sourceRef) return
    setRefreshingRuleSetID(set.id)
    setRuleSetError(null)
    try {
      const parsed = await fetchRuleSet(set.sourceRef)
      const rules = parsed.rules.map((rule) => ({
        ...rule,
        group: set.group,
        sourceName: set.name,
      }))
      const updated = { ...ruleSetRefreshSuccess(set, rules), format: parsed.format }
      addCustomScheme({
        ...fresh,
        ruleSets: (fresh.ruleSets ?? []).map((item) => item.id === set.id ? updated : item),
        updatedAt: Date.now(),
      })
      const diff = updated.lastDiff
      setFlash(`已刷新「${set.name}」：${parsed.rules.length} 条规则（+${diff?.added ?? 0} −${diff?.removed ?? 0} ~${diff?.modified ?? 0}）；${describeRuleSetParse(parsed)}。`)
    } catch (e) {
      setRuleSetError(`「${set.name}」刷新失败：${(e as Error).message}`)
    } finally {
      setRefreshingRuleSetID(null)
    }
  }

  const removeSchemeRuleSet = (id: string) => {
    const fresh = customScheme
    if (!fresh?.ruleSets) return
    addCustomScheme({
      ...fresh,
      ruleSets: fresh.ruleSets.filter((set) => set.id !== id),
      updatedAt: Date.now(),
    })
    setFlash('已从当前方案移除规则集。')
  }


  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">分流规则 · 03</div>
          <h1>配置分流规则</h1>
          <div className="sub">选择规则方案、调整策略组顺序，或添加自定义规则</div>
        </div>
      </div>

      {flash && <div className="flash" role="status" aria-live="polite">{flash}</div>}

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
          <span><b>{enabledForRules.length}</b> 节点</span>
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
        {selectedMeta && !('custom' in selectedMeta) && (
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
        {selectedMeta && !('custom' in selectedMeta) && (
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

      {importingScheme && (
        <div className="card">
          <h3 style={{ marginBottom: 14 }}>导入规则方案</h3>
          <div className="field">
            <label>方案名称</label>
            <input className="input" value={schemeName} onChange={(e) => setSchemeName(e.target.value)} placeholder="例如：ACL4SSR 精简自定义" />
          </div>
          <div className="field">
            <label>URL（方案地址）</label>
            <input className="input" value={schemeURL} onChange={(e) => setSchemeURL(e.target.value)} placeholder="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ACL4SSR_Online.ini" />
            <div className="hint">自动识别 subconverter INI、Clash / mihomo YAML、Surge、Egern YAML 和 sing-box JSON；也可以直接粘贴内容到下方。</div>
          </div>
          <div className="field">
            <label>粘贴方案内容（可选）</label>
            <textarea className="field" value={schemeText} onChange={(e) => setSchemeText(e.target.value)} rows={6} placeholder="ruleset=广告,https://...&#10;custom_proxy_group=节点选择`select`[]DIRECT&#10;或粘贴 proxy-groups / policy_groups / route.rules / [Proxy Group]" />
            <div className="row scheme-file-row">
              <button type="button" className="btn ghost" onClick={() => fileInputRef.current?.click()}>选择方案文件</button>
              {schemeFileName && <span className="hint">已读取：{schemeFileName}</span>}
              <input
                ref={fileInputRef}
                type="file"
                accept=".ini,.txt,.conf,.yaml,.yml,.json"
                style={{ display: 'none' }}
                onChange={(e) => void readSchemeFile(e.target.files?.[0])}
              />
            </div>
            <div className="hint">支持的格式：{Object.values(RULE_SCHEME_FORMAT_TITLES).join(' · ')}</div>
          </div>
          {schemeError && <div className="error">{schemeError}</div>}
          <div className="row" style={{ gap: 8, marginTop: 8 }}>
            <button className="btn primary" disabled={schemeLoading || !schemeURL.trim() || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={importSchemeFromURL}>
              {schemeLoading ? '处理中…' : '从 URL 导入'}
            </button>
            <button className="btn" disabled={schemeLoading || !schemeText.trim() || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={importSchemeFromText}>
              {schemeLoading ? '处理中…' : schemeFileName ? '导入文件内容' : '粘贴导入'}
            </button>
            <button className="btn ghost" disabled={schemeLoading || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={() => void importSelfConfiguration()}>
              Self-Configuration 预设
            </button>
            <button className="btn ghost" onClick={() => { setImportingScheme(false); setSchemeError(null); }}>取消</button>
          </div>
        </div>
      )}

      {scheme && (
        <div className="card">
          <div className="card-head">
            <h3>策略组</h3>
            <div className="row wrap" style={{ gap: 8, alignItems: 'center' }}>
              <span className="meta">{groupCardMeta}</span>
              <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setCreatingGroup(scheme)}>+ 新建策略组</button>
            </div>
          </div>
          <div className="group-list" tabIndex={0} aria-label="策略组列表">
          {scheme.groups.map((g, index) => {
            const nodeChoices = g.type === 'select' ? nodeChoicesFor(g) : []
            const choices = [...g.options, ...nodeChoices]
            const selectedValue = policySelections[g.name]
            const current = choices.includes(selectedValue ?? '') ? selectedValue : (choices[0] ?? '')
            const ruleCount = schemeRules.filter((r) => r.group === g.name).length
            const customCount = (scheme.customRules ?? []).filter((r) => r.group === g.name).length
            return (
              <div
                className={`group-row${dragFromIndex === index ? ' dragging' : ''}${dragOverIndex === index ? ' drop-target' : ''}`}
                key={g.name}
                onDragOver={(e) => {
                  if (readOnly || dragFromIndex === null) return
                  e.preventDefault()
                  e.dataTransfer.dropEffect = 'move'
                  if (dragOverIndex !== index) setDragOverIndex(index)
                }}
                onDragLeave={() => {
                  if (dragOverIndex === index) setDragOverIndex(null)
                }}
                onDrop={(e) => {
                  e.preventDefault()
                  if (readOnly) return
                  const from = dragFromIndex ?? Number(e.dataTransfer.getData('text/plain'))
                  setDragFromIndex(null)
                  setDragOverIndex(null)
                  if (Number.isInteger(from) && from >= 0 && from !== index) {
                    reorderGroups(scheme, from, index)
                  }
                }}
              >
                <div className="group-main">
                  <div className="group-title">
                    <span
                      className="drag-handle"
                      draggable={!readOnly}
                      aria-hidden="true"
                      title={readOnly ? READONLY_NOTE : '拖动调整策略组顺序和匹配优先级'}
                      onDragStart={(e) => {
                        if (readOnly) { e.preventDefault(); return }
                        setDragFromIndex(index)
                        e.dataTransfer.effectAllowed = 'move'
                        e.dataTransfer.setData('text/plain', String(index))
                      }}
                      onDragEnd={() => {
                        setDragFromIndex(null)
                        setDragOverIndex(null)
                      }}
                    >⠿</span>
                    <GroupIcon name={g.name} />
                    <span className="gname">{groupDisplayName(g.name, showGroupEmoji)}</span>
                    <span className="gtype">{policyTypeLabel(g.type)}</span>
                  </div>
                  <div className="group-sub">
                    {ruleCount} 条规则{customCount > 0 ? ` · ${customCount} 条自定义` : ''}
                    {g.nodeFilter ? ` · 节点匹配 ${g.nodeFilter}` : ''}
                  </div>
                </div>
                <div className="group-controls">
                  {g.type === 'select' && choices.length > 0 && (
                    <select
                      className="input"
                      aria-label={`${g.name} 的首选策略`}
                      value={current}
                      disabled={readOnly}
                      title={readOnly ? READONLY_NOTE : undefined}
                      onChange={(e) => setPolicy(g.name, e.target.value)}
                    >
                      {g.options.length > 0 && (
                        <optgroup label="策略组 / 内置">
                          {g.options.map((c) => <option key={c} value={c}>{groupDisplayName(c, showGroupEmoji)}</option>)}
                        </optgroup>
                      )}
                      {nodeChoices.length > 0 && (
                        <optgroup label="节点">
                          {nodeChoices.map((c, i) => <option key={`${c}-${i}`} value={c}>{c}</option>)}
                        </optgroup>
                      )}
                    </select>
                  )}
                  {g.type !== 'select' && <span className="pill">{policyTypeLabel(g.type)}</span>}
                  {g.type === 'select' && choices.length === 0 && <span className="hint">没有候选策略</span>}
                  <button className="btn ghost group-rule-btn" onClick={() => beginEditGroup(scheme, g, 'rules')}>
                    规则 {ruleCount}
                  </button>
                  <button
                    className="icon-btn"
                    aria-label={`编辑策略组「${g.name}」`}
                    title="编辑策略组"
                    onClick={() => beginEditGroup(scheme, g)}
                  >✎</button>
                  <button
                    className="icon-btn"
                    disabled={index === 0 || readOnly}
                    aria-label={`上移策略组「${g.name}」`}
                    title={readOnly ? READONLY_NOTE : '上移'}
                    onClick={() => moveGroup(scheme, index, -1)}
                  >↑</button>
                  <button
                    className="icon-btn"
                    disabled={index === scheme.groups.length - 1 || readOnly}
                    aria-label={`下移策略组「${g.name}」`}
                    title={readOnly ? READONLY_NOTE : '下移'}
                    onClick={() => moveGroup(scheme, index, 1)}
                  >↓</button>
                  <button
                    className="icon-btn"
                    disabled={scheme.groups.length <= 1 || readOnly}
                    aria-label={`删除策略组「${g.name}」`}
                    title={readOnly ? READONLY_NOTE : scheme.groups.length <= 1 ? '至少保留一个策略组' : '删除策略组'}
                    onClick={() => setPendingGroupDelete(g)}
                  >×</button>
                </div>
              </div>
            )
          })}
          </div>
          {reorderUndo && scheme && reorderUndo.schemeID === scheme.id && (
            <div className="inline-notice group-order-undo" role="status">
              <div className="group-order-conflict-list">
                {reorderUndo.conflicts.length > 0 ? (
                  <>
                    <strong>有网站的归属改变了：</strong>
                    {reorderUndo.conflicts.slice(0, 3).map((conflict) => (
                      <div key={`${conflict.from}-${conflict.to}`}>
                        「{groupDisplayName(conflict.from, showGroupEmoji)}」中 {conflict.domains.length} 个域名改走
                        「{groupDisplayName(conflict.to, showGroupEmoji)}」，如 {conflict.domains.slice(0, 2).join('、')}
                      </div>
                    ))}
                    {reorderUndo.conflicts.length > 3 && <div>…</div>}
                    <div className="hint">规则从上到下匹配，同一个域名只会命中排在前面的组。</div>
                  </>
                ) : '已调整策略组顺序和匹配优先级。'}
              </div>
              <button type="button" className="btn ghost" {...writeGuard(readOnly)} onClick={undoGroupReorder}>撤销</button>
            </div>
          )}
          <div className="hint group-order-hint">
            拖动或上下移会写入客户端的策略组顺序，并把该组规则移到对应的匹配位置；排在前面的组先匹配。
          </div>
        </div>
      )}

      {scheme && (
        <div className="card">
          <div className="card-head">
            <h3>自定义规则</h3>
            <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => beginAddCustomRule(scheme)}>+ 添加规则</button>
          </div>
          {(scheme.customRules?.length ?? 0) > 0 ? (
            <ul className="custom-rule-list">
              {scheme.customRules!.map((rule) => (
                <li key={`${rule.group}-${rule.type}-${rule.value ?? ''}`}>
                  <span className="pill">{groupDisplayName(rule.group, showGroupEmoji)}</span>
                  <span className="mono rule-type">{rule.type}</span>
                  <span className="mono rule-value">{rule.value ?? '—'}</span>
                  {rule.noResolve && <span className="hint">no-resolve</span>}
                  <button
                    className="icon-btn"
                    aria-label={`删除规则 ${rule.type} ${rule.value ?? ''}`}
                    title={readOnly ? READONLY_NOTE : '删除这条自定义规则'}
                    {...writeGuard(readOnly)}
                    onClick={() => removeCustomRule(scheme, rule)}
                  >×</button>
                </li>
              ))}
            </ul>
          ) : (
            <div className="hint">还没有自定义规则。添加的规则会排在方案规则最前；内置方案会先复制一份再修改。</div>
          )}
        </div>
      )}

      {scheme && (
        <div className="card">
          <div className="card-head">
            <h3>规则顺序（逐条）</h3>
            <span className="meta">{schemeRules.length} 条 · 导出按这里的顺序匹配</span>
          </div>
          {schemeRules.length > 30 && (
            <div className="search-wrap rs-search">
              <input
                className="input"
                value={ruleOrderSearch}
                onChange={(e) => setRuleOrderSearch(e.target.value)}
                placeholder="搜索类型、域名、策略组或规则集…"
                aria-label="搜索规则顺序"
              />
              {ruleOrderSearch && (
                <button className="search-clear" aria-label="清空规则搜索" onClick={() => setRuleOrderSearch('')}>×</button>
              )}
            </div>
          )}
          {ruleOrderRows.rows.length > 0 ? (
            <ul className="rule-list rule-order-list">
              {ruleOrderRows.rows.map(({ rule, index }) => {
                const movable = !isUnmovableRule(rule)
                const previous = schemeRules[index - 1]
                const nextRule = schemeRules[index + 1]
                const canUp = movable && !!previous && !isUnmovableRule(previous)
                const canDown = movable && !!nextRule && !isUnmovableRule(nextRule)
                const disabledNote = !movable
                  ? 'GEOIP / FINAL / MATCH 是兜底锚点，不能手动移动'
                  : readOnly ? READONLY_NOTE : undefined
                const upNote = disabledNote ?? (canUp ? '上移这条规则' : '上方是兜底锚点或已经是第一条')
                const downNote = disabledNote ?? (canDown ? '下移这条规则' : '下方是兜底锚点或已经是最后一条')
                return (
                  <li key={`${index}-${rule.type}-${rule.value ?? ''}-${rule.group}`}>
                    <span className="hint rule-order-position">{index + 1}</span>
                    <span className="pill">{groupDisplayName(rule.group, showGroupEmoji)}</span>
                    {rule.sourceName && <span className="pill rule-source">{rule.sourceName}</span>}
                    <span className="mono rule-type">{rule.type}</span>
                    <span className="mono rule-value">{rule.value ?? '—'}</span>
                    {rule.noResolve && <span className="hint">no-resolve</span>}
                    <span className="rule-order-actions">
                      <button
                        type="button"
                        className="icon-btn"
                        disabled={!canUp || readOnly}
                        aria-label={`上移规则 ${rule.type} ${rule.value ?? ''}`}
                        title={upNote}
                        onClick={() => moveRule(scheme, index, -1)}
                      >↑</button>
                      <button
                        type="button"
                        className="icon-btn"
                        disabled={!canDown || readOnly}
                        aria-label={`下移规则 ${rule.type} ${rule.value ?? ''}`}
                        title={downNote}
                        onClick={() => moveRule(scheme, index, 1)}
                      >↓</button>
                    </span>
                  </li>
                )
              })}
            </ul>
          ) : (
            <div className="hint">{ruleOrderSearch ? '没有匹配的规则' : '当前方案没有可调整的规则。'}</div>
          )}
          {ruleOrderRows.total > ruleOrderRows.rows.length && (
            <div className="hint">共 {ruleOrderRows.total} 条匹配，仅显示前 {ruleOrderRows.rows.length} 条；用搜索缩小范围后再调整。</div>
          )}
          {ruleOrderUndo && ruleOrderUndo.schemeID === scheme.id && (
            <div className="inline-notice" role="status">
              <span>已调整规则「{ruleOrderUndo.label}」顺序。</span>
              <button type="button" className="btn ghost" {...writeGuard(readOnly)} onClick={undoRuleOrder}>撤销</button>
            </div>
          )}
          <div className="hint rule-order-hint">
            这里调整的是导出配置里真正从上到下的匹配顺序。自定义规则默认仍排在最前（最具体优先），手动移动后以这里的顺序为准；
            调整策略组顺序会重置这里的逐条顺序（组排序优先）。GEOIP / FINAL / MATCH 是兜底锚点，按钮会明确禁用。
          </div>
        </div>
      )}

      {scheme && (
        <div className="card">
          <div className="card-head">
            <h3>规则库与规则集</h3>
            <div className="row wrap" style={{ gap: 6 }}>
              <button className="btn ghost" onClick={() => setLibraryOpen(true)}>浏览规则库</button>
              <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setRemoteSetOpen(true)}>+ 在线规则集</button>
              <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setLocalSetEditor({})}>+ 新建规则集</button>
              <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => localSetImportRef.current?.click()}>导入文件</button>
              <input
                ref={localSetImportRef}
                type="file"
                multiple
                accept=".list,.txt,.conf,.yaml,.yml,.json"
                style={{ display: 'none' }}
                onChange={(e) => {
                  const files = e.target.files ? Array.from(e.target.files) : []
                  e.target.value = ''
                  void importLocalRuleSetFiles(files)
                }}
              />
            </div>
          </div>
          {ruleSetError && <div className="error" role="alert">{ruleSetError}</div>}

          <div className="rs-section">
            <div className="rs-section-title">
              已加入当前方案
              <span className="meta">{scheme.ruleSets?.length ?? 0} 组</span>
            </div>
            {(scheme.ruleSets?.length ?? 0) > 0 ? (
              <ul className="rs-list">
                {scheme.ruleSets!.map((set) => {
                  const blockedCount = ruleSetExclusions[set.id]?.length ?? 0
                  return (
                    <li key={set.id}>
                      <div>
                        <strong>{set.name}</strong>
                        <span className="pill">{groupDisplayName(set.group, showGroupEmoji)}</span>
                        {set.inlined && <span className="pill" title="来自固化快照，不能删除或刷新；可按签名逐条屏蔽">只读</span>}
                        {blockedCount > 0 && (
                          <span className="pill warn" title="原始规则集与快照不变；只在编译与导出时排除">
                            已屏蔽 {blockedCount} 条 · 仅编译期生效
                          </span>
                        )}
                        <span className="hint">
                          {set.rules.length} 条 · {set.inlined ? '固化快照（只读）' : set.sourceKind === 'library' ? '内置规则库' : set.sourceKind === 'url' ? '在线订阅' : '我的规则集'}
                          {set.format ? ` · ${RULE_SET_FORMAT_TITLES[set.format]}` : ''}
                          {set.updatedAt ? ` · 更新于 ${formatDate(set.updatedAt)}` : ''}
                        </span>
                        {set.lastDiff && <RuleSetDiffView diff={set.lastDiff} />}
                      </div>
                      <div className="rs-actions">
                        {!set.inlined && set.sourceKind === 'url' && (
                          <button
                            className="btn ghost"
                            disabled={refreshingRuleSetID !== null}
                            onClick={() => void refreshSchemeRuleSet(set)}
                          >
                            {refreshingRuleSetID === set.id ? '刷新中…' : '刷新'}
                          </button>
                        )}
                        {!set.inlined && (
                          <button
                            className="icon-btn"
                            aria-label={`从当前方案移除规则集「${set.name}」`}
                            title="移除整组规则"
                            onClick={() => removeSchemeRuleSet(set.id)}
                          >×</button>
                        )}
                      </div>
                    </li>
                  )
                })}
              </ul>
            ) : (
              <div className="hint">还没有加入规则集。规则集会排在自定义规则之后、方案规则之前。</div>
            )}
          </div>

          <div className="rs-section">
            <div className="rs-section-title">
              <span>我的规则集 <span className="meta">{localRuleSets.length} 个</span></span>
              {localRuleSets.some((set) => set.sourceURL && !set.paused) && (
                <button
                  className="btn ghost"
                  disabled={refreshingRuleSetID !== null}
                  onClick={() => void refreshAllLocalRuleSets()}
                >
                  {refreshingRuleSetID === 'all' ? '刷新中…' : '刷新全部'}
                </button>
              )}
            </div>
            {localRuleSets.length > 2 && (
              <div className="search-wrap rs-search">
                <input
                  className="input"
                  value={localSetSearch}
                  onChange={(e) => setLocalSetSearch(e.target.value)}
                  placeholder="搜索名称、地址或格式…"
                  aria-label="搜索我的规则集"
                />
                {localSetSearch && (
                  <button className="search-clear" aria-label="清空规则集搜索" onClick={() => setLocalSetSearch('')}>×</button>
                )}
              </div>
            )}
            {visibleLocalRuleSets.length > 0 ? (
              <ul className="rs-list">
                {visibleLocalRuleSets.map((set) => (
                  <li key={set.id}>
                    <div>
                      <strong>{set.name}</strong>
                      {set.sourceURL && <span className="pill">在线订阅</span>}
                      <span className="hint">
                        {set.rules.length} 条规则
                        {` · ${set.sourceURL ? '在线订阅' : set.format ? `${RULE_SET_FORMAT_TITLES[set.format]} 导入` : '手动规则集'}`}
                        {` · 更新于 ${formatDate(set.updatedAt)}`}
                        {set.paused ? ' · 已暂停自动刷新' : ''}
                      </span>
                      {set.lastError && (
                        <span className="hint rule-set-error">上次刷新失败：{set.lastError}</span>
                      )}
                      {set.lastDiff && <RuleSetDiffView diff={set.lastDiff} stale={!!set.lastError} />}
                    </div>
                    <div className="rs-actions">
                      {set.sourceURL && (
                        <>
                          <button
                            className="btn ghost"
                            disabled={refreshingRuleSetID !== null || readOnly}
                            title={readOnly ? READONLY_NOTE : undefined}
                            onClick={() => void refreshLocalRuleSet(set)}
                          >
                            {refreshingRuleSetID === set.id ? '刷新中…' : '刷新'}
                          </button>
                          <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => toggleLocalRuleSetPaused(set)}>
                            {set.paused ? '恢复刷新' : '暂停刷新'}
                          </button>
                          <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setRenamingLocalSet(set)}>重命名</button>
                        </>
                      )}
                      <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setLocalSetAddTarget(set)}>加入方案</button>
                      {!set.sourceURL && (
                        <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setLocalSetEditor({ set })}>编辑</button>
                      )}
                      <button className="btn ghost danger-text" {...writeGuard(readOnly)} onClick={() => setPendingLocalSetDelete(set)}>删除</button>
                    </div>
                  </li>
                ))}
              </ul>
            ) : localRuleSets.length === 0 ? (
              <div className="hint">可以新建、导入多个规则文件，或添加在线规则集订阅；之后重复加入不同方案。</div>
            ) : (
              <div className="hint">没有匹配「{localSetSearch}」的规则集。</div>
            )}
            {localRuleSets.length > 0 && (
              <div className="hint">加入方案使用当前快照；在线订阅加入后会保留远程地址，可在方案里单独刷新。</div>
            )}
          </div>
        </div>
      )}

      <AdvancedSection
        scope="rules-tools"
        title="规则工具与历史"
        summary="全量检查 · 命中解释 · 规则集版本对比；默认收起，展开状态按设备记住"
      >
        <RulesToolsCard
          scheme={scheme}
          nodes={enabledForRules}
          policySelections={policySelections}
          latencyByNodeId={latencyByNodeId}
          localRuleSets={localRuleSets}
          preferRuleSets={preferRuleSets}
          showGroupEmoji={showGroupEmoji}
          versionHistoryEnabled={ruleSetVersionHistory}
          onLocate={locateLintIssue}
          onGoExport={() => onGo?.('export')}
        />
      </AdvancedSection>

      <ConfirmDialog
        open={!!pendingSchemeDelete}
        title="删除自定义方案？"
        body={<>将删除规则方案 <b>「{pendingSchemeDelete?.name}」</b>。如果它正被使用，会切回内置 ACL4SSR 方案。</>}
        confirmLabel="删除"
        danger
        confirmDisabled={readOnly}
        onCancel={() => setPendingSchemeDelete(null)}
        onConfirm={() => {
          const target = pendingSchemeDelete
          setPendingSchemeDelete(null)
          if (target) removeCustomScheme(target.id)
        }}
      />

      {networkEditor && (
        <NetworkSettingsDialog
          scheme={networkEditor}
          onClose={() => setNetworkEditor(null)}
          onSave={saveNetworkSettings}
        />
      )}

      {editingScheme && (
        <SchemeEditDialog
          key={editingScheme.id}
          scheme={editingScheme}
          onClose={() => setEditingScheme(null)}
          onSave={saveSchemeMeta}
        />
      )}
      {textEditorScheme && (
        <SchemeTextDialog
          key={textEditorScheme.id}
          scheme={textEditorScheme}
          onClose={() => setTextEditorScheme(null)}
          onSave={saveSchemeText}
        />
      )}
      {customRuleTarget && (
        <AddCustomRuleDialog
          key={`${customRuleTarget.id}-${customRuleGroup ?? ''}`}
          scheme={customRuleTarget}
          initialGroup={customRuleGroup}
          onClose={() => setCustomRuleTarget(null)}
          onSave={(rule) => saveCustomRule(customRuleTarget, rule)}
        />
      )}
      {groupEditor && (
        <GroupEditorDialog
          key={`${groupEditor.scheme.id}-${groupEditor.group.name}-${groupEditor.tab ?? 'settings'}`}
          scheme={groupEditor.scheme}
          group={groupEditor.group}
          nodes={enabledForRules}
          rules={orderedSchemeBaseRules(groupEditor.scheme)}
          customRules={groupEditor.scheme.customRules ?? []}
          initialTab={groupEditor.tab}
          initialRuleQuery={groupEditor.query}
          onClose={() => setGroupEditor(null)}
          onSave={(updated) => saveGroupEdit(groupEditor, updated)}
          onAddRule={(rule) => saveCustomRule(groupEditor.scheme, rule)}
        />
      )}
      {creatingGroup && (
        <GroupCreateDialog
          key={`${creatingGroup.id}-create-group`}
          scheme={creatingGroup}
          nodes={enabledForRules}
          onClose={() => setCreatingGroup(null)}
          onCreate={(group) => createNodeGroup(creatingGroup, group)}
        />
      )}
      {libraryOpen && scheme && (
        <RuleLibraryDialog
          scheme={scheme}
          onClose={() => setLibraryOpen(false)}
          onAdd={(payload) => applyRuleSet(scheme, payload)}
        />
      )}
      {remoteSetOpen && scheme && (
        <RemoteRuleSetDialog
          key={scheme.id}
          scheme={scheme}
          onClose={() => setRemoteSetOpen(false)}
          onSave={(sets, group, notice) => {
            saveRemoteRuleSets(sets, group, notice)
            setRemoteSetOpen(false)
          }}
        />
      )}
      {renamingLocalSet && (
        <RenameRuleSetDialog
          key={renamingLocalSet.id}
          set={renamingLocalSet}
          onClose={() => setRenamingLocalSet(null)}
          onSave={(name) => {
            renameLocalRuleSet(renamingLocalSet, name)
            setRenamingLocalSet(null)
          }}
        />
      )}
      {localSetEditor && (
        <RuleSetEditorDialog
          key={localSetEditor.set?.id ?? 'new'}
          ruleSet={localSetEditor.set}
          onClose={() => setLocalSetEditor(null)}
          onSave={(set) => {
            addLocalRuleSet(set)
            setFlash(`已保存规则集「${set.name}」，共 ${set.rules.length} 条规则。`)
          }}
        />
      )}
      {localSetAddTarget && scheme && (
        <AddRuleSetToSchemeDialog
          key={`${localSetAddTarget.id}-${scheme.id}`}
          ruleSet={localSetAddTarget}
          scheme={scheme}
          onClose={() => setLocalSetAddTarget(null)}
          onAdd={(group) => addLocalSetToScheme(scheme, localSetAddTarget, group)}
        />
      )}
      {restoreInitialConfirm && customScheme && builtinForCustom && (
        <ConfirmDialog
          open
          title="恢复初始规则？"
          body={(
            <>
              将把「{customScheme.name}」恢复为「{builtinForCustom.name}」的初始策略组和规则。
              当前自定义规则、规则集快照、Emoji 补全和匹配顺序都会被清空，此操作不可撤销。
            </>
          )}
          confirmLabel="恢复初始规则"
          danger
          confirmDisabled={readOnly}
          onCancel={() => setRestoreInitialConfirm(false)}
          onConfirm={() => void restoreInitialRules()}
        />
      )}
      {pendingSnapshotRollback && selectedMeta && !('custom' in selectedMeta) && (
        <ConfirmDialog
          open
          title={`回退「${selectedMeta.name}」到快照 #${pendingSnapshotRollback.target.id}？`}
          body={(
            <>
              <span>{pendingSnapshotRollback.message}</span>
              {pendingSnapshotRollback.affectedSchemes.length > 0 && (
                <span className="hint" style={{ display: 'block', marginTop: 6 }}>
                  受影响的自定义方案会改成引用这份旧版规则集，导出结果随之变化。
                </span>
              )}
            </>
          )}
          confirmLabel="回退至此版"
          danger
          confirmDisabled={readOnly}
          onCancel={() => setPendingSnapshotRollback(null)}
          onConfirm={confirmSnapshotRollback}
        />
      )}
      {pendingGroupDelete && scheme && (
        <ConfirmDialog
          open
          title="删除策略组？"
          body={(
            <>
              将删除 <b>「{pendingGroupDelete.name}」</b>，并移除 {schemeRules.filter((rule) => rule.group === pendingGroupDelete.name).length} 条规则。
              {(() => {
                const referencing = scheme.groups
                  .filter((g) => g.name !== pendingGroupDelete.name && g.options.includes(pendingGroupDelete.name))
                  .map((g) => groupDisplayName(g.name, true))
                if (referencing.length === 0) return '其他策略组里的引用也会一并移除。'
                return <>候选里引用它的策略组：{referencing.join('、')}，这些候选会一并移除。</>
              })()}
              此操作会先复制为自定义方案，内置方案本身不受影响。
            </>
          )}
          confirmLabel="删除策略组"
          danger
          confirmDisabled={readOnly}
          onCancel={() => setPendingGroupDelete(null)}
          onConfirm={() => deleteNodeGroup(scheme, pendingGroupDelete)}
        />
      )}
      <ConfirmDialog
        open={!!pendingLocalSetDelete}
        title="删除本地规则集？"
        body={<>将删除 <b>「{pendingLocalSetDelete?.name}」</b>。已加入方案的规则集快照不会被移除。</>}
        confirmLabel="删除"
        danger
        confirmDisabled={readOnly}
        onCancel={() => setPendingLocalSetDelete(null)}
        onConfirm={() => {
          const target = pendingLocalSetDelete
          setPendingLocalSetDelete(null)
          if (target) {
            removeLocalRuleSet(target.id)
            clearRuleSetHistory(target.id)
            setFlash(`已删除本地规则集「${target.name}」；已加入方案的快照保持不变。`)
          }
        }}
      />
    </div>
  )
}

// ---------------- 规则诊断 Tab ----------------

// 规则诊断页的「撤销本次清理」只在本机这次会话内有效。
// 放在模块级而不是组件 state：诊断结果刷新会让子组件重渲染，
// 组件内快照容易被重置，撤销按钮就会无声消失。
// 只记录“被删掉的条目 + 原始位置”，撤销时精确回插；不再保存整份方案快照，
// 否则清理之后用户在同一方案里做的其它编辑会被一起回滚。
let cleanupUndoRecord: { schemeID: string; records: RemovedRuleRecord[] } | null = null
/** 本次自动复制出的方案；撤销时删掉副本并回到原内置方案。 */
let copyUndoRecord: { copyID: string; sourceID: string; sourceName: string } | null = null
/** 屏蔽 / 解除屏蔽的撤销槽（只保留最近一次），记录某个规则集完整的屏蔽列表。 */
let exclusionUndoRecord: { setId: string; before: string[]; label: string } | null = null

function CheckTab({
  onGo,
  onLocate,
}: {
  onGo?: (tab: TabKey) => void
  onLocate?: (issue: SchemeLintIssue) => void
}) {
  const scheme = useScheme()
  const nodes = useStore((s) => s.nodes)
  const sources = useStore((s) => s.sources)
  const errors = useStore((s) => s.errors)
  const policySelections = useStore((s) => s.policySelections)
  const latencyByNodeId = useStore((s) => s.latencyByNodeId)
  const localRuleSets = useStore((s) => s.localRuleSets)
  const preferRuleSets = useStore((s) => s.preferRuleSets)
  const showGroupEmoji = useStore((s) => s.showGroupEmoji)
  const ruleSetVersionHistory = useStore((s) => s.ruleSetVersionHistory)
  const ruleSetExclusions = useStore((s) => s.ruleSetExclusions)
  const customSchemes = useStore((s) => s.customSchemes)
  const readOnly = useWorkspaceStatus().readOnly
  const enabledForRules = useMemo(() => enabledNodes({ sources, nodes }), [sources, nodes])
  const sourceErrors = useMemo(
    () => sources.map((source) => errors[source.id]?.trim()).filter((value): value is string => !!value),
    [sources, errors],
  )
  const manualCount = useMemo(
    () => nodes.filter((node) => node.isManual).length,
    [nodes],
  )
  const excludedCount = useMemo(() => {
    const excludedKeys = new Set(sources.flatMap((source) => source.excludedNodeKeys))
    return nodes.filter((node) =>
      !node.isSubscriptionMetadata
      && (excludedKeys.has(nodeExactKey(node)) || node.isEnabled === false)).length
  }, [nodes, sources])
  const pool = explainNodePool({
    sourceCount: sources.length,
    manualNodeCount: manualCount,
    nodeCount: nodes.filter((node) => !node.isSubscriptionMetadata).length,
    enabledNodeCount: enabledForRules.length,
    excludedNodeCount: excludedCount,
    sourceErrors,
  })

  const canUndoCleanup = cleanupUndoRecord !== null
  const canUndoCopy = copyUndoRecord !== null
  const canUndoExclusion = exclusionUndoRecord !== null
  /** 当前方案是不是内置只读方案：删除前必须显式告知会创建副本。 */
  const requiresCopy = scheme ? !customSchemes.some((item) => item.id === scheme.id) : false

  /** 选中内置方案时，先把当前内容复制成可编辑方案。保留已有 customRules，避免索引错位。 */
  const ensureEditable = (): RuleScheme | null => {
    if (!scheme) return null
    const state = useStore.getState()
    const existing = state.customSchemes.find((item) => item.id === scheme.id)
    if (existing) return existing
    const previousSelections = { ...state.policySelections }
    const editable = createEditableSchemeCopy(scheme, { id: `custom-${Date.now()}` })
    state.addCustomScheme(editable)
    state.setScheme(editable.id)
    for (const [group, selection] of Object.entries(previousSelections)) {
      useStore.getState().setPolicy(group, selection)
    }
    return editable
  }

  const applyFix = (action: FixAction): FixOutcome => {
    if (!scheme) return { ok: false, message: '规则方案还没加载完成。' }
    if (readOnly) return { ok: false, message: '当前工作区只读，无法修改规则。' }

    // 只读规则集的条目：不删快照，改为按签名屏蔽。它不复制方案，改动立即作用于编译与导出。
    if (action.kind === 'block-rule') {
      const setId = action.ruleSetId
      const signature = action.ruleSignature
      const set = scheme.ruleSets?.find((item) => item.id === setId)
      if (!setId || !set || !signature || !isReadOnlyRuleSet(set)) {
        return { ok: false, message: '这条规则不在只读规则集里，请刷新诊断后重试。' }
      }
      const state = useStore.getState()
      exclusionUndoRecord = {
        setId,
        before: [...(state.ruleSetExclusions[setId] ?? [])],
        label: action.ruleText ?? signature,
      }
      state.addRuleSetExclusion(setId, signature)
      return {
        ok: true,
        message: `已屏蔽「${action.ruleText ?? signature}」（来源：${set.name}）。它不会再参与编译与导出，命中可能落到下一条规则；可撤销本次屏蔽。`,
      }
    }

    // 先在当前方案上试算：规则不在了就不要复制出一个多余的「自定义」方案。
    if (!applyFixAction(scheme, action)) return { ok: false, message: '没有找到这条规则，可能已被修改。' }
    const wasReadOnly = requiresCopy
    const editable = ensureEditable()
    if (!editable) return { ok: false, message: '规则方案还没加载完成。' }
    const next = applyFixAction(editable, action)
    if (!next) return { ok: false, message: '没有找到这条规则，可能已被修改。' }
    useStore.getState().addCustomScheme({ ...next.scheme, updatedAt: Date.now() })
    // 单条删除也写入同一条撤销记录：撤销按原位置回插，不会覆盖之后做的其它编辑。
    if (next.removed) {
      cleanupUndoRecord = {
        schemeID: editable.id,
        records: [{ place: next.removed.place, rule: { ...next.removed.rule } }],
      }
    }
    if (wasReadOnly) {
      copyUndoRecord = { copyID: editable.id, sourceID: scheme.id, sourceName: scheme.name }
    } else {
      copyUndoRecord = null
    }
    const where = next.removedFrom === 'custom' ? '自定义规则' : next.removedFrom === 'ruleset' ? '规则集' : '方案规则'
    const copyNote = wasReadOnly
      ? `已创建副本「${editable.name}」，后续修改只作用于副本，原内置方案「${scheme.name}」不变；可撤销本次复制回到原方案。`
      : ''
    return {
      ok: true,
      message: `已从${where}删除「${next.removedText}」，方案已保存${copyNote ? `；${copyNote}` : `；可撤销这次删除。`}`,
    }
  }

  const cleanDuplicates = (plan: DuplicateCleanupPlan): FixOutcome => {
    if (!plan.deletions.length && !plan.shadowed.length) return { ok: false, message: '没有可安全删除的重复规则。' }
    if (!scheme) return { ok: false, message: '规则方案还没加载完成。' }
    // 同上：先确认计划在当前方案上仍然成立，再决定要不要复制方案。
    if (!applyDuplicateCleanup(scheme, plan).removed) {
      return { ok: false, message: '规则已经变化，请重新运行诊断后再清理。' }
    }
    const wasReadOnly = requiresCopy
    const editable = ensureEditable()
    if (!editable) return { ok: false, message: '规则方案还没加载完成。' }
    const result = applyDuplicateCleanup(editable, plan)
    if (!result.removed) return { ok: false, message: '规则已经变化，请重新运行诊断后再清理。' }
    cleanupUndoRecord = {
      schemeID: editable.id,
      records: result.applied.map((item) => ({ place: item.place, rule: { ...item.rule } })),
    }
    if (wasReadOnly) {
      copyUndoRecord = { copyID: editable.id, sourceID: scheme.id, sourceName: scheme.name }
    } else {
      copyUndoRecord = null
    }
    useStore.getState().addCustomScheme({ ...result.scheme, updatedAt: Date.now() })
    const copyNote = wasReadOnly
      ? `已创建副本「${editable.name}」，原内置方案「${scheme.name}」不变；可撤销本次复制回到原方案。`
      : ''
    const directionNote = plan.directionChanges.length
      ? `；保留后一条把 ${plan.directionChanges.map((change) => `「${change.fromGroup}」→「${change.toGroup}」`).join('、')}`
      : ''
    const shadowedNote = plan.shadowedCount ? `，其中遮蔽死规则 ${plan.shadowedCount} 条` : ''
    return {
      ok: true,
      message: `已删除 ${result.removed} 条重复 / 遮蔽规则（同组 ${plan.sameGroupCount} 条 / 跨组 ${plan.crossGroupCount} 条${shadowedNote}），方案已保存${directionNote}${copyNote ? `；${copyNote}` : `；可撤销本次清理（只恢复这几条，不影响其它修改）。`}`,
    }
  }

  const undoCopy = (): FixOutcome => {
    const record = copyUndoRecord
    if (!record) return { ok: false, message: '没有可撤销的复制。' }
    if (readOnly) return { ok: false, message: '当前工作区只读，无法撤销。' }
    const state = useStore.getState()
    const plan = undoEditableSchemeCopy(state.customSchemes, record.sourceID, record.copyID)
    copyUndoRecord = null
    if (!plan.removed) {
      useStore.setState({ selectedSchemeID: record.sourceID })
      return { ok: false, message: '副本已经不在了，已切回原方案。' }
    }
    cleanupUndoRecord = null
    useStore.setState({
      customSchemes: plan.customSchemes,
      selectedSchemeID: plan.selectedSchemeID,
    })
    return { ok: true, message: `已撤销本次复制，删除副本并回到原方案「${record.sourceName}」。` }
  }

  const unblockRule = (ruleSetID: string, signature: string, label: string): FixOutcome => {
    if (readOnly) return { ok: false, message: '当前工作区只读，无法解除屏蔽。' }
    const state = useStore.getState()
    const set = scheme?.ruleSets?.find((item) => item.id === ruleSetID)
    if (!set || !isReadOnlyRuleSet(set)) return { ok: false, message: '找不到这个只读规则集。' }
    const before = [...(state.ruleSetExclusions[ruleSetID] ?? [])]
    if (!before.includes(signature)) return { ok: false, message: '这条规则没有被屏蔽。' }
    exclusionUndoRecord = { setId: ruleSetID, before, label }
    state.removeRuleSetExclusion(ruleSetID, signature)
    return {
      ok: true,
      message: `已解除屏蔽「${label}」，它会重新参与编译与导出；可撤销本次解除。`,
    }
  }

  const undoExclusion = (): FixOutcome => {
    const record = exclusionUndoRecord
    if (!record) return { ok: false, message: '没有可撤销的屏蔽操作。' }
    if (readOnly) return { ok: false, message: '当前工作区只读，无法撤销。' }
    exclusionUndoRecord = null
    useStore.getState().restoreRuleSetExclusions(record.setId, record.before)
    return {
      ok: true,
      message: `已撤销上次屏蔽 / 解除，恢复「${record.label}」之前的屏蔽状态。`,
    }
  }

  const undoCleanup = (): FixOutcome => {
    const record = cleanupUndoRecord
    if (!record) return { ok: false, message: '没有可撤销的清理。' }
    // undoCopy / undoExclusion 都拦了只读；这里漏拦会让 addCustomScheme 被
    // 静默过滤，界面却提示「已恢复」。
    if (readOnly) return { ok: false, message: '当前工作区只读，无法撤销。' }
    const state = useStore.getState()
    const target = state.customSchemes.find((item) => item.id === record.schemeID)
    if (!target) {
      cleanupUndoRecord = null
      return { ok: false, message: '被清理的方案已经被删除，无法撤销这次清理。' }
    }
    const result = restoreRemovedRules(target, record.records)
    cleanupUndoRecord = null
    if (!result.restored) {
      return { ok: false, message: '没有可恢复的条目：规则集可能已被删除或替换。' }
    }
    state.addCustomScheme({ ...result.scheme, updatedAt: Date.now() })
    state.setScheme(record.schemeID)
    const skippedNote = result.skipped
      ? `；${result.skipped} 条因原位置已有同条规则或规则集已被替换而跳过`
      : ''
    return {
      ok: true,
      message: `已恢复 ${result.restored} 条被清理的规则，清理之后的其它修改保持不变${skippedNote}。`,
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">STEP 03 · 检查结果</div>
          <h1>规则诊断</h1>
          <p className="sub">一条流量为什么走这里、规则集最近变过什么、导出时会不会丢语义。</p>
        </div>
        <div className="page-actions">
          <button className="btn ghost" onClick={() => onGo?.('rules')}>调整规则方案</button>
          <button className="btn" onClick={() => onGo?.('export')}>去导出</button>
        </div>
      </div>

      {pool.code !== 'ready' ? (
        <div className={`pool-reason${pool.code === 'source-error' ? ' is-error' : ''}`}>
          <div className="pool-reason-body">
            <strong>{pool.title}</strong>
            <span>{pool.detail}</span>
            <div className="pool-reason-actions">
              <button className="btn" onClick={() => onGo?.('sub')}>去添加或修复订阅</button>
              {pool.code === 'source-error' && <button className="btn ghost" onClick={() => onGo?.('sub')}>查看订阅错误</button>}
            </div>
          </div>
        </div>
      ) : (
        <DiagnosisPanel
          scheme={scheme}
          nodes={enabledForRules}
          policySelections={policySelections}
          latencyByNodeId={latencyByNodeId}
          localRuleSets={localRuleSets}
          ruleSetExclusions={ruleSetExclusions}
          preferRuleSets={preferRuleSets}
          showGroupEmoji={showGroupEmoji}
          versionHistoryEnabled={ruleSetVersionHistory}
          historyRevision={ruleSetVersionHistory ? 1 : 0}
          requiresCopy={requiresCopy}
          onLocate={(issue) => onLocate?.(issue)}
          onApplyFix={applyFix}
          onCleanDuplicates={cleanDuplicates}
          onUndoCleanup={undoCleanup}
          canUndoCleanup={canUndoCleanup}
          canUndoCopy={canUndoCopy}
          onUndoCopy={undoCopy}
          copySourceName={copyUndoRecord?.sourceName}
          canUndoExclusion={canUndoExclusion}
          onUnblockRule={unblockRule}
          onUndoExclusion={undoExclusion}
          onGo={(key) => onGo?.(key)}
        />
      )}
    </div>
  )
}

// ---------------- 导出 Tab ----------------

/** 导出页客户端按订阅载体分组，新增客户端会自动落到对应分组。 */
type ClientGroupKey = 'yaml' | 'egern' | 'surge' | 'loon-quanx' | 'json' | 'base64'
const CLIENT_GROUPS: { key: ClientGroupKey; label: string }[] = [
  { key: 'yaml', label: 'Clash / YAML 系' },
  { key: 'egern', label: 'Egern' },
  { key: 'surge', label: 'Surge' },
  { key: 'loon-quanx', label: 'Loon / Quantumult X' },
  { key: 'json', label: 'sing-box / JSON' },
  { key: 'base64', label: '手机订阅 / Base64' },
]

function clientGroupKey(client: ClientInfo): ClientGroupKey {
  switch (subFormatFor(client)) {
    case 'yaml': return 'yaml'
    case 'egern': return 'egern'
    case 'surge': return 'surge'
    case 'json': return 'json'
    case 'base64': return 'base64'
    default: return 'loon-quanx'
  }
}

const FORMAT_LABELS = {
  yaml: 'Clash YAML',
  egern: 'Egern YAML',
  surge: 'Surge',
  loon: 'Loon',
  quanx: 'Quantumult X',
  json: 'sing-box JSON',
  base64: '节点订阅',
} satisfies Record<string, string>

/** 发布订阅时，这些客户端的 Tailscale 写法需要独立变体。 */
const TAILNET_TARGET_VARIANTS: ClientTarget[] = [
  'clash',
  'clash-apple',
  'clash-verge',
  'clashmac',
  'flclash',
  'mihomo-party',
  'clash-mi',
  'surge-mac',
  'karing',
  'egern',
  'hiddify',
]

function ExportTab({ onGo }: { onGo?: (tab: TabKey) => void }) {
  const readOnly = useWorkspaceStatus().readOnly
  const scheme = useScheme()
  const policySelections = useStore((s) => s.policySelections)
  const preferRuleSets = useStore((s) => s.preferRuleSets)
  const setPreferRuleSets = useStore((s) => s.setPreferRuleSets)
  const ruleSetExclusions = useStore((s) => s.ruleSetExclusions)
  const exportContentMode = useStore((s) => s.exportContentMode)
  const exportContentModes = useStore((s) => s.exportContentModes)
  const setExportContentModeFor = useStore((s) => s.setExportContentModeFor)
  const embedRemoteSubscriptions = useStore((s) => s.embedRemoteSubscriptions)
  const setEmbedRemoteSubscriptions = useStore((s) => s.setEmbedRemoteSubscriptions)
  const nodeNameFilter = useStore((s) => s.nodeNameFilter)
  const setNodeNameFilter = useStore((s) => s.setNodeNameFilter)
  const exportProtocols = useStore((s) => s.exportProtocols)
  const setExportProtocols = useStore((s) => s.setExportProtocols)
  const exportRegions = useStore((s) => s.exportRegions)
  const setExportRegions = useStore((s) => s.setExportRegions)
  const exportConfigName = useStore((s) => s.exportConfigName)
  const setExportConfigName = useStore((s) => s.setExportConfigName)
  const appendSourceName = useStore((s) => s.appendSourceName)
  const setAppendSourceName = useStore((s) => s.setAppendSourceName)
  const clientOrder = useStore((s) => s.clientOrder)
  const setClientOrder = useStore((s) => s.setClientOrder)
  const hiddenClients = useStore((s) => s.hiddenClients)
  const setClientHidden = useStore((s) => s.setClientHidden)
  const sources = useStore((s) => s.sources)
  const nodes = useStore((s) => s.nodes)
  const localRuleSets = useStore((s) => s.localRuleSets)
  const tailnets = useStore((s) => s.tailnets)
  const tailnetAuthKeys = useStore((s) => s.tailnetAuthKeys)
  const [target, setTarget] = useState<ClientInfo>(CLIENTS[0])
  const targetFormat = subFormatFor(target)
  const contentMode = effectiveContentMode(target, exportContentModes, exportContentMode)
  const canImport = clientSupportsImport(target, contentMode)
  const orderedClients = useMemo(() => clientsInOrder(clientOrder), [clientOrder])
  const visibleClients = useMemo(() => {
    const shown = orderedClients.filter((client) => !hiddenClients.includes(client.target))
    // 旧数据若把所有客户端都隐藏了，退回显示全部，避免导出页没有可选客户端。
    return shown.length ? shown : orderedClients
  }, [orderedClients, hiddenClients])
  // 预览与下载按当前客户端载体准备方案；发布时由 generateSubscriptionFormats
  // 再按各载体分别准备，避免这里提前合并导致规则重复。
  const exportScheme = useMemo(
    () => scheme ? prepareSchemeForExport(scheme, policySelections, {
      preferRuleSets,
      format: targetFormat,
      target: target.target,
      ruleSetExclusions,
    }) : undefined,
    [scheme, policySelections, preferRuleSets, targetFormat, target.target, ruleSetExclusions],
  )
  const compatibility = useMemo(
    () => scheme ? analyzeRuleCompatibility(target, scheme, { preferRuleSets, contentMode, ruleSetExclusions }) : undefined,
    [target, scheme, preferRuleSets, contentMode, ruleSetExclusions],
  )
  const [clientQuery, setClientQuery] = useState('')
  const [manageClients, setManageClients] = useState(false)
  const pickerRef = useRef<HTMLDetailsElement>(null)
  const [generated, setGenerated] = useState('')
  const [skipped, setSkipped] = useState(0)
  const [exportedNodeCount, setExportedNodeCount] = useState(0)
  const [remoteSourceCount, setRemoteSourceCount] = useState(0)
  const [tailnetNotes, setTailnetNotes] = useState<string[]>([])
  const [previewQuery, setPreviewQuery] = useState('')
  const [qrOpen, setQrOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const [downloaded, setDownloaded] = useState(false)
  const [pendingRevoke, setPendingRevoke] = useState(false)
  const [importing, setImporting] = useState(false)
  const [subToken, setSubToken] = useState<string>(() => localPrefs.getItem('tower-sub-token') ?? '')
  const [subURL, setSubURL] = useState(() => {
    const raw = localPrefs.getItem('tower-sub-url') ?? ''
    if (!raw) return ''
    // 旧版本 / 手工改坏的地址：不要让它带着整个导出页一起崩。
    try {
      return new URL(raw, window.location.origin).href
    } catch {
      return ''
    }
  })
  const [subRefreshing, setSubRefreshing] = useState(false)
  const [subUpdatedAt, setSubUpdatedAt] = useState<number | null>(() => {
    const v = Number(localPrefs.getItem('tower-sub-updated-at'))
    return Number.isFinite(v) && v > 0 ? v : null
  })
  const [checking, setChecking] = useState(false)
  const [checkResult, setCheckResult] = useState<{ ok: boolean; text: string } | null>(null)
  /** 撤销链接失败时保留 token 与地址，显示原因并提供重试。 */
  const [revokeError, setRevokeError] = useState('')
  const [copiedField, setCopiedField] = useState<'sub' | 'import' | 'lan' | null>(null)
  const [importNotice, setImportNotice] = useState('')
  const [net, setNet] = useState<{ host: string; lan: string[] } | null>(null)
  const localHost = ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(window.location.hostname)

  useEffect(() => {
    apiFetch('/api/network')
      .then((r) => r.json())
      .then((d) => setNet({ host: String(d?.host ?? ''), lan: Array.isArray(d?.lan) ? d.lan : [] }))
      .catch(() => {})
  }, [])

  // 换客户端后，上一份格式的检查结果 / 导入提示不再适用。
  useEffect(() => {
    setCheckResult(null)
    setImportNotice('')
    setCopiedField(null)
  }, [target])

  // 客户端选择面板：点面板外收起。
  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      const el = pickerRef.current
      if (el?.open && !el.contains(e.target as Node)) el.open = false
    }
    document.addEventListener('click', onDocClick)
    return () => document.removeEventListener('click', onDocClick)
  }, [])

  // 本机打开的页面，手机端要用局域网地址而不是 127.0.0.1。
  const copyText = async (field: 'sub' | 'import' | 'lan', value: string) => {
    const ok = await copyToClipboard(value)
    if (!ok) {
      setCheckResult({ ok: false, text: '这台机器不允许网页写剪贴板，请点输入框手动全选复制' })
      return
    }
    setCopiedField(field)
    window.setTimeout(() => setCopiedField((v) => (v === field ? null : v)), 1600)
  }

  const enabled = useMemo(() => enabledNodes({ sources, nodes }), [sources, nodes])
  const lintIssues = useMemo(
    () => (scheme ? lintScheme({ scheme, nodes: enabled, policySelections, localRuleSets, preferRuleSets, clients: [target] }) : []),
    [scheme, enabled, policySelections, localRuleSets, preferRuleSets, target],
  )
  const lintState = lintSummary(lintIssues)
  // key 里带上具体 error 的 id：同样数量的 error 换成另一批问题时，不能沿用上一次的「继续导出」确认。
  const lintErrorKey = lintIssues
    .filter((issue) => issue.level === 'error')
    .map((issue) => issue.id)
    .sort()
    .join(',')
  const lintKey = `${scheme?.id ?? ''}|${target}|${lintErrorKey}|${enabled.map((node) => node.id).join(',')}`
  const [lintAck, setLintAck] = useState('')
  const [pendingExport, setPendingExport] = useState<{ run: () => void; errors: number } | null>(null)
  const guardExport = (run: () => void) => {
    if (lintState.error > 0 && lintAck !== lintKey) {
      setPendingExport({ run, errors: lintState.error })
      return
    }
    run()
  }
  const nameFilterResult = useMemo(
    () => filterNodesByName(enabled, nodeNameFilter),
    [enabled, nodeNameFilter],
  )
  // 地区多选：空数组表示全部；未识别地区的节点只在“全部”时导出。
  const regionOptions = useMemo(() => {
    const counts = new Map<string, { code: string; name: string; flag: string; count: number }>()
    for (const node of nameFilterResult.nodes) {
      const region = regionForNode(node)
      if (!region) continue
      const current = counts.get(region.code)
      if (current) current.count += 1
      else counts.set(region.code, { ...region, count: 1 })
    }
    return [...counts.values()].sort(
      (left, right) => right.count - left.count || left.name.localeCompare(right.name, 'zh-CN'),
    )
  }, [nameFilterResult.nodes])
  const regionFilteredNodes = useMemo(
    () => filterNodesByRegionCodes(nameFilterResult.nodes, exportRegions),
    [exportRegions, nameFilterResult.nodes],
  )
  const protocolCounts = useMemo(() => {
    const counts = new Map<ProxyKind, number>()
    for (const node of regionFilteredNodes) counts.set(node.kind, (counts.get(node.kind) ?? 0) + 1)
    return [...counts.entries()].sort(
      (a, b) => b[1] - a[1] || PROXY_KIND_TITLES[a[0]].localeCompare(PROXY_KIND_TITLES[b[0]], 'zh-CN'),
    )
  }, [regionFilteredNodes])
  const usable = useMemo(() => {
    if (exportProtocols.length === 0) return regionFilteredNodes
    return regionFilteredNodes.filter((node) => exportProtocols.includes(node.kind))
  }, [regionFilteredNodes, exportProtocols])
  const remoteSubscriptions = useMemo<RemoteSubscriptionEntry[]>(() => {
    if (!embedRemoteSubscriptions) return []
    return sources
      .filter((source) => isSourceEnabled(source) && /^https?:\/\//i.test(source.url))
      .map((source) => ({
        id: source.id,
        name: source.name,
        url: source.url,
        userAgent: source.userAgent,
      }))
  }, [embedRemoteSubscriptions, sources])
  const activeTailnets = useMemo<TailnetExport[]>(
    () => tailnets
      .filter((connection) => connection.isEnabled)
      .map((connection) => ({ connection, authKey: tailnetAuthKeys[connection.id] })),
    [tailnets, tailnetAuthKeys],
  )
  // Shadowrocket consumes Clash YAML but has no proxy-provider support.
  const supportsProxyCollections = target.target !== 'shadowrocket'
    && formatSupportsProxyCollections(targetFormat)
    && contentMode === 'full'
  const previewRemoteSubscriptions = supportsProxyCollections ? remoteSubscriptions : []
  const contentModeByFormat = useMemo(() => {
    const modes: Partial<Record<SubFormat, ExportContentMode>> = {}
    for (const format of ['yaml', 'egern', 'surge', 'loon', 'quanx', 'json'] as SubFormat[]) {
      const representative = targetFormat === format
        ? target
        : orderedClients.find((client) => subFormatFor(client) === format)
      modes[format] = representative
        ? effectiveContentMode(representative, exportContentModes, exportContentMode)
        : 'full'
    }
    modes.base64 = 'nodes'
    return modes
  }, [target, targetFormat, orderedClients, exportContentModes, exportContentMode])
  const exportableCount = generated
    ? exportedNodeCount
    : Math.max(0, usable.length - skipped)
  const hasRemoteExportable = remoteSourceCount > 0
  const hasExportable = exportableCount > 0 || hasRemoteExportable
  const noEnabledNodes = enabled.length === 0
  const nameFilterEmpty = !noEnabledNodes && nameFilterResult.nodes.length === 0
  const filterEmpty = !noEnabledNodes && !nameFilterEmpty && usable.length === 0
  const emptyReason = noEnabledNodes
    ? '当前没有启用的节点：请先在「订阅管理」添加订阅、自有节点或启用节点。'
    : nameFilterResult.error
      ? nameFilterResult.error
      : nameFilterEmpty
        ? '节点名称筛选没有匹配节点：调整关键词或清除筛选。'
        : filterEmpty
          ? '当前协议筛选没有匹配节点：清除筛选或选择其他协议。'
          : `当前客户端不支持这 ${usable.length} 个节点的协议：请换一个客户端，或排除不兼容节点。`

  const sourceNameByID = useMemo(() => new Map(sources.map((source) => [source.id, source.name])), [sources])
  const nameForNode = useMemo(() => {
    if (!appendSourceName) return undefined
    return (node: ProxyNode) => {
      const sourceName = node.sourceID ? sourceNameByID.get(node.sourceID) : undefined
      return sourceName ? `${node.name} · ${sourceName}` : node.name
    }
  }, [appendSourceName, sourceNameByID])
  // ------- 客户端专属订阅链接（跟随 target 实时变化）-------
  // 同一 token 下按客户端 format 取对应载体：
  //   yaml → Clash Verge / Mihomo / Stash …  ini → Surge / Loon / QuanX
  //   json → sing-box MT / Hiddify           base64 → V2Box / Anywhere
  //   yaml → Shadowrocket 也使用 Clash YAML；egern 使用独立 Egern 载体。
  const clientSubURL = useMemo(() => {
    if (!subURL) return ''
    try {
      // 用当前页面的 origin 重建：从 127.0.0.1 发布、之后用局域网地址打开时，
      // 链接也会自动变成局域网地址，不会把 127.0.0.1 发给手机。
      const u = new URL(new URL(subURL, window.location.origin).pathname, window.location.origin)
      u.searchParams.set('format', subFormatFor(target))
      // target 让服务端在存在客户端专属变体（如 Stash / Surge Mac）时选对写法。
      u.searchParams.set('target', target.target)
      return u.href
    } catch {
      // localStorage 里的旧地址被改坏时，别让整个导出页白屏。
      return ''
    }
  }, [target, subURL])

  const outputOptions = useMemo(
    () => ({
      contentMode,
      nameForNode,
      remoteSubscriptions: previewRemoteSubscriptions,
      tailnets: contentMode === 'full' ? activeTailnets : [],
      // Surge 自更新首行只指向已发布的链接；尚未发布（subURL 为空）时不写，
      // 避免生成一个指向不存在地址的 #!MANAGED-CONFIG。
      managedConfigURL: targetFormat === 'surge' && contentMode === 'full' ? clientSubURL : '',
    }),
    [contentMode, nameForNode, previewRemoteSubscriptions, activeTailnets, targetFormat, clientSubURL],
  )

  const configName = exportConfigName.trim() || 'tower'
  const fileStem = configFileStem(configName)

  const clientGroups = useMemo(() => {
    const q = clientQuery.trim().toLowerCase()
    return CLIENT_GROUPS.map((group) => ({
      ...group,
      clients: visibleClients.filter((client) => {
        if (clientGroupKey(client) !== group.key) return false
        if (!q) return true
        return [client.name, client.subtitle, client.target].join(' ').toLowerCase().includes(q)
      }),
    })).filter((group) => group.clients.length > 0)
  }, [clientQuery, visibleClients])

  // 当前客户端被隐藏时，自动落到第一个可见客户端，避免选择面板里没有当前项。
  useEffect(() => {
    if (visibleClients.some((client) => client.target === target.target)) return
    const next = visibleClients[0]
    if (next) setTarget(next)
  }, [visibleClients, target])

  useEffect(() => {
    if (!exportScheme) {
      setGenerated('')
      setSkipped(0)
      setExportedNodeCount(0)
      setRemoteSourceCount(0)
      setTailnetNotes([])
      return
    }
    const out = generateConfig(target, usable, exportScheme, outputOptions)
    setGenerated(out.text)
    setSkipped(out.skipped)
    setExportedNodeCount(out.exportedNodeCount)
    setRemoteSourceCount(out.remoteSourceCount)
    setTailnetNotes(out.notes)
  }, [target, usable, exportScheme, outputOptions])

  // importScheme 可用时包装成客户端 deep link，否则直接给订阅地址。
  const clientImportURL = useMemo(() => {
    if (!clientSubURL) return ''
    if (!canImport) return ''
    return target.importScheme?.(clientSubURL, configName, contentMode) ?? ''
  }, [target, clientSubURL, configName, contentMode, canImport])

  // 本机打开的页面，手机端要用局域网地址而不是 127.0.0.1。
  const clientLanSubURL = useMemo(() => {
    if (!localHost || !net?.lan[0] || !clientSubURL) return ''
    return clientSubURL.replace(window.location.origin, net.lan[0])
  }, [localHost, net, clientSubURL])

  // 通用局域网地址不带 format，由服务端按客户端 User-Agent / target 自动识别。
  const lanSubURL = useMemo(() => {
    if (!localHost || !net?.lan[0] || !subURL) return ''
    try {
      const path = new URL(subURL, window.location.origin).pathname
      return new URL(path, window.location.origin).href.replace(window.location.origin, net.lan[0])
    } catch {
      return ''
    }
  }, [localHost, net, subURL])

  const previewText = useMemo(
    () => maskTailnetAuthKeys(generated, activeTailnets.map((item) => item.authKey)),
    [generated, activeTailnets],
  )
  const previewMatches = useMemo(() => {
    const needle = previewQuery.trim()
    if (!needle) return null
    const lower = needle.toLowerCase()
    const rows: { number: number; line: string }[] = []
    let count = 0
    for (const [index, line] of previewText.split('\n').entries()) {
      if (!line.toLowerCase().includes(lower)) continue
      count += 1
      if (rows.length < 500) rows.push({ number: index + 1, line })
    }
    return { needle, count, rows, truncated: count > rows.length }
  }, [previewText, previewQuery])

  const downloadNow = () => {
    if (!exportScheme) {
      setCheckResult({ ok: false, text: '规则方案还没加载完成，稍后再试或到规则页重新选择方案' })
      return
    }
    if (!hasExportable) {
      setCheckResult({ ok: false, text: emptyReason })
      return
    }
    const out = generateConfig(target, usable, exportScheme, outputOptions)
    const blob = new Blob([out.text], { type: out.mime })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${fileStem}.${out.extension}`
    // 部分浏览器要求链接在 DOM 里才触发下载；URL 延后释放，避免抢在下载前回收。
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.setTimeout(() => URL.revokeObjectURL(a.href), 1000)
    markExported()
    setDownloaded(true)
    setTimeout(() => setDownloaded(false), 1600)
  }

  const download = () => guardExport(downloadNow)

  const copyNow = async () => {
    if (!hasExportable) {
      setCheckResult({ ok: false, text: emptyReason })
      return
    }
    if (!generated) {
      setCheckResult({ ok: false, text: '配置还在生成，稍后再试' })
      return
    }
    const ok = await copyToClipboard(generated)
    if (!ok) {
      setCheckResult({ ok: false, text: '这台机器不允许网页写剪贴板，请在预览框里手动全选复制' })
      return
    }
    setCopied(true)
    markExported()
    setTimeout(() => setCopied(false), 1500)
  }

  const copy = () => guardExport(() => void copyNow())

  const importNow = async () => {
    if (!canImport) return
    if (!exportScheme) {
      setCheckResult({ ok: false, text: '规则方案还没加载完成，稍后再试' })
      return
    }
    if (!hasExportable) {
      setCheckResult({ ok: false, text: emptyReason })
      return
    }
    setImporting(true)
    try {
      // 旧订阅快照可能还是修复前的产物（例如含 mihomo 不支持的 URL-REGEX）。
      // 导入前先按当前设置重新发布，避免客户端拿到一份早已过期的配置。
      const fresh = await publishNow()
      let abs = ''
      if (fresh) {
        const u = new URL(fresh, window.location.origin)
        u.searchParams.set('format', subFormatFor(target))
        u.searchParams.set('target', target.target)
        abs = u.href
      } else {
        const out = generateConfig(target, usable, exportScheme, outputOptions)
        const res = await apiFetch(`/api/share?name=${encodeURIComponent(configName)}`, {
          method: 'POST',
          headers: { 'content-type': out.mime },
          body: out.text,
        })
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const { url } = await res.json()
        if (!url) throw new Error('服务端没有返回导入链接')
        abs = new URL(url, window.location.origin).href
      }
      const scheme = target.importScheme?.(abs, configName, contentMode)
      if (!scheme) throw new Error('当前内容模式没有一键导入链接')
      window.location.href = scheme
      setImportNotice(`已同步最新配置并尝试唤起 ${target.name}；若没有反应，复制下面的订阅地址，在客户端里手动添加。`)
    } catch {
      setImportNotice(`唤起 ${target.name} 失败，请复制订阅地址手动添加。`)
    } finally {
      setImporting(false)
    }
  }

  const importIntoClient = () => guardExport(() => void importNow())

  /** 请求一个订阅地址，取回真实响应内容。 */
  const probeSubscription = async (u: string) => {
    const res = await apiFetch(u, { cache: 'no-store' })
    const text = await res.text()
    const firstLine = (text.split('\n').find((l) => l.trim()) ?? '').trim().slice(0, 80)
    const ctype = res.headers.get('content-type') ?? '—'
    if (!res.ok) {
      return { ok: false, status: res.status, text: `HTTP ${res.status} · ${text.slice(0, 120)}` }
    }
    if (!text.trim()) {
      return { ok: false, status: res.status, text: `HTTP ${res.status} 但内容为空（${ctype}）` }
    }
    return {
      ok: true,
      status: res.status,
      text: `HTTP ${res.status} · ${ctype} · ${text.length} 字节 · 首行「${firstLine}」`,
    }
  }

  /** 发布当前节点到订阅地址；返回可用的绝对地址（不含 format 参数）。 */
  const publishNow = async (): Promise<string | null> => {
    if (usable.length === 0) {
      setCheckResult({ ok: false, text: '没有可导出的节点：请先在「订阅管理」添加订阅或自有节点，并启用节点' })
      return null
    }
    if (!scheme) {
      setCheckResult({ ok: false, text: '规则方案尚未加载完成，请稍后重试' })
      return null
    }
    if (!hasExportable) {
      setCheckResult({ ok: false, text: emptyReason })
      return null
    }
    setSubRefreshing(true)
    try {
      // 一次生成全部载体，服务端按 format 参数分发，保证每个客户端拿到自己的格式。
      // 传原始方案而不是 exportScheme：内部会按各载体再次准备规则，避免规则重复。
      const formats = generateSubscriptionFormats(usable, scheme, {
        policySelections,
        preferRuleSets,
        ruleSetExclusions,
        contentMode,
        contentModeByFormat,
        nameForNode,
        remoteSubscriptions,
        tailnets: activeTailnets,
      })
      if (!formats.base64) throw new Error('节点列表为空或无法转换')
      // Stash / Surge Mac 的 Tailscale 写法与同格式其他客户端不同；Karing、
      // Egern、Hiddify 不支持，需要不带 Tailscale 的变体。
      const targets: Partial<Record<ClientTarget, string>> = {}
      // Shadowrocket 与 Clash 共用 YAML 载体，但它不支持 proxy-providers。
      // 始终提供目标变体，避免发布链接把代理集合写进 Shadowrocket 配置。
      const shadowrocket = CLIENTS.find((client) => client.target === 'shadowrocket')
      if (shadowrocket) {
        const prepared = prepareSchemeForExport(scheme, policySelections, {
          preferRuleSets,
          format: 'yaml',
          target: 'shadowrocket',
          ruleSetExclusions,
        })
        const mode = effectiveContentMode(shadowrocket, exportContentModes, exportContentMode)
        targets.shadowrocket = generateConfig(shadowrocket, usable, prepared, {
          contentMode: mode,
          nameForNode,
          remoteSubscriptions: [],
          tailnets: [],
        }).text
      }
      // Karing 与 Clash 共用 YAML，但核心不读 MRS；发布时单独去掉。
      const karing = CLIENTS.find((client) => client.target === 'karing')
      if (karing) {
        const prepared = prepareSchemeForExport(scheme, policySelections, {
          preferRuleSets,
          format: 'yaml',
          target: 'karing',
          ruleSetExclusions,
        })
        const mode = effectiveContentMode(karing, exportContentModes, exportContentMode)
        targets.karing = generateConfig(karing, usable, prepared, {
          contentMode: mode,
          nameForNode,
          remoteSubscriptions,
          tailnets: [],
        }).text
      }
      // sing-box 1.14 的远程规则集需要 http_clients，Hiddify 内嵌 1.13 不接受；
      // 发布时给两个 JSON 客户端各自一份目标变体。
      for (const targetKey of ['sing-box', 'hiddify'] as const) {
        const client = CLIENTS.find((item) => item.target === targetKey)
        if (!client) continue
        const mode = effectiveContentMode(client, exportContentModes, exportContentMode)
        const prepared = prepareSchemeForExport(scheme, policySelections, {
          preferRuleSets,
          format: 'json',
          target: targetKey,
          ruleSetExclusions,
        })
        targets[targetKey] = generateConfig(client, usable, prepared, {
          contentMode: mode,
          nameForNode,
          remoteSubscriptions,
          tailnets: [],
        }).text
      }
      if (activeTailnets.length > 0) {
        for (const targetKey of TAILNET_TARGET_VARIANTS) {
          const client = CLIENTS.find((item) => item.target === targetKey)
          if (!client) continue
          const format = subFormatFor(client)
          if (format !== 'yaml' && format !== 'surge' && format !== 'json') continue
          const mode = effectiveContentMode(client, exportContentModes, exportContentMode)
          const prepared = prepareSchemeForExport(scheme, policySelections, {
            preferRuleSets,
            format,
            target: targetKey,
            ruleSetExclusions,
          })
          targets[targetKey] = generateConfig(client, usable, prepared, {
            contentMode: mode,
            nameForNode,
            remoteSubscriptions,
            tailnets: mode === 'full' ? activeTailnets : [],
          }).text
        }
      }
      const query = new URLSearchParams({ title: configName })
      if (subToken) query.set('token', subToken)
      const res = await apiFetch(`/api/subscribe?${query.toString()}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify({ title: configName, formats, targets }),
      })
      if (!res.ok) {
        const detail = await res.text().catch(() => '')
        throw new Error(`HTTP ${res.status} ${detail.slice(0, 80)}`)
      }
      const json = await res.json()
      setSubToken(json.token)
      setRevokeError('')
      localPrefs.setItem('tower-sub-token', json.token)
      const abs = new URL(json.url, window.location.origin).href
      setSubURL(abs)
      localPrefs.setItem('tower-sub-url', abs)
      const now = Date.now()
      setSubUpdatedAt(now)
      localPrefs.setItem('tower-sub-updated-at', String(now))
      markExported()
      return abs
    } catch (e: unknown) {
      setCheckResult({ ok: false, text: `发布失败：${e instanceof Error ? e.message : String(e)}` })
      return null
    } finally {
      setSubRefreshing(false)
    }
  }

  const publishNowSubscription = async () => {
    const url = await publishNow()
    if (url) {
      const remoteLabel = remoteSubscriptions.length > 0 ? ` · ${remoteSubscriptions.length} 个代理集合` : ''
      const tailnetLabel = activeTailnets.length > 0 ? ` · ${activeTailnets.length} 个 Tailscale 内网` : ''
      setCheckResult({
        ok: true,
        text: `已发布 · ${exportableCount} 个本地节点${remoteLabel}${tailnetLabel} · 各载体按对应客户端设置生成`,
      })
    }
  }

  const publishSubscription = () => guardExport(() => void publishNowSubscription())

  // 之前发布过的 token 里存的是旧内容（例如修好 DNS 之前的 YAML）。
  // 进入导出页时静默同步一次，地址不变，用户 Clash 刷新订阅就能拿到修复后的配置。
  const autoSyncedRef = useRef(false)
  useEffect(() => {
    if (autoSyncedRef.current) return
    if (!subToken || !scheme || usable.length === 0) return
    autoSyncedRef.current = true
    void publishNow()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subToken, scheme, usable.length])

  /**
   * 检查链接：先探当前地址；若 404（多半是服务端重启前的旧 token），
   * 自动重新发布再探一次，避免用户被一个死链困住。
   */
  const checkSubscription = async () => {
    if (!clientSubURL) {
      setCheckResult({ ok: false, text: '还没有订阅地址，请先点「生成订阅链接」' })
      return
    }
    if (!hasExportable) {
      setCheckResult({ ok: false, text: emptyReason })
      return
    }
    setChecking(true)
    setCheckResult(null)
    try {
      let result = await probeSubscription(clientSubURL)
      if (!result.ok && result.status === 404) {
        const fresh = await publishNow()
        if (fresh) {
          const u = new URL(fresh, window.location.origin)
          u.searchParams.set('format', subFormatFor(target))
          result = await probeSubscription(u.href)
          result = { ...result, text: `已自动重新发布 · ${result.text}` }
        } else {
          result = { ...result, text: '旧链接已失效，且当前没有可发布的节点' }
        }
      }
      setCheckResult({ ok: result.ok, text: result.text })
    } catch (err) {
      setCheckResult({ ok: false, text: `请求失败：${err instanceof Error ? err.message : String(err)}` })
    } finally {
      setChecking(false)
    }
  }

  const chooseClient = (client: ClientInfo) => {
    setTarget(client)
    setClientQuery('')
    if (pickerRef.current) pickerRef.current.open = false
  }

  const revokeSubscription = async () => {
    if (!subToken) return
    setRevokeError('')
    try {
      const response = await apiFetch(`/api/sub/${encodeURIComponent(subToken)}`, { method: 'DELETE' })
      // 404 说明服务端已经没有这个 token，本地清掉即可；其它失败必须如实报错，
      // 否则界面显示“已撤销”，但服务端 token 仍然有效、旧链接还能继续更新。
      if (!response.ok && response.status !== 404) {
        let detail = `HTTP ${response.status}`
        try {
          const body = await response.json() as { error?: unknown }
          if (typeof body.error === 'string' && body.error.trim()) detail = body.error.trim()
        } catch { /* 非 JSON 错误体，保留状态码 */ }
        throw new Error(detail)
      }
    } catch (err) {
      setRevokeError(`撤销失败：${err instanceof Error ? err.message : String(err)}。链接仍然有效，请重试。`)
      return
    }
    setSubToken(''); setSubURL(''); setSubUpdatedAt(null)
    localPrefs.removeItem('tower-sub-token')
    localPrefs.removeItem('tower-sub-url')
    localPrefs.removeItem('tower-sub-updated-at')
  }

  const toggleProtocol = (kind: ProxyKind) => {
    if (exportProtocols.includes(kind)) {
      setExportProtocols(exportProtocols.filter((item) => item !== kind))
    } else {
      setExportProtocols([...exportProtocols, kind])
    }
  }
  const toggleRegion = (code: string) => {
    if (exportRegions.includes(code)) {
      setExportRegions(exportRegions.filter((item) => item !== code))
    } else {
      setExportRegions([...exportRegions, code])
    }
  }

  const moveClient = (client: ClientInfo, delta: number) => {
    const order = orderedClients.map((item) => item.target)
    const index = order.indexOf(client.target)
    const next = index + delta
    if (index < 0 || next < 0 || next >= order.length) return
    const swapped = [...order]
    ;[swapped[index], swapped[next]] = [swapped[next], swapped[index]]
    setClientOrder(swapped)
  }

  const toggleClientVisible = (client: ClientInfo) => {
    if (hiddenClients.includes(client.target)) {
      setClientHidden(client.target, false)
      return
    }
    // 至少保留一个可见客户端，避免一次隐藏后整个导出页无处落脚。
    if (visibleClients.length <= 1) return
    setClientHidden(client.target, true)
    if (client.target === target.target) {
      const next = visibleClients.find((item) => item.target !== client.target)
      if (next) setTarget(next)
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">导出与发布 · 04</div>
          <h1>导出与发布</h1>
          <div className="sub">为 <span className="num">{visibleClients.length}</span> 种客户端生成配置，或发布订阅链接到手机</div>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>客户端</h3>
          <div className="row client-head-actions">
            <span className="meta">
              <span className="num">{visibleClients.length}</span> 个 · 按格式分组
              {hiddenClients.length > 0 ? ` · 已隐藏 ${hiddenClients.length}` : ''}
            </span>
            <button className="btn ghost" onClick={() => setManageClients((v) => !v)}>
              {manageClients ? '完成' : '排序 / 隐藏'}
            </button>
          </div>
        </div>

        {manageClients ? (
          <div className="client-manage">
            <div className="client-manage-head">
              <span className="hint">排序影响选择面板；隐藏不会删除客户端或已生成的配置。</span>
              <button className="btn ghost" onClick={() => setClientOrder([])}>恢复默认顺序</button>
            </div>
            <ul className="client-manage-list">
              {orderedClients.map((client, index) => {
                const hidden = hiddenClients.includes(client.target)
                const active = client.target === target.target
                return (
                  <li key={client.target} className={`${hidden ? 'is-hidden' : ''}${active ? ' is-active' : ''}`}>
                    <span className="opt-icon">
                      <img
                        src={`/client-icons/${client.icon}`}
                        alt=""
                        loading="lazy"
                        onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }}
                      />
                    </span>
                    <span className="cm-info">
                      <span className="cm-name">
                        {client.name}
                        {active && <span className="pill positive">当前</span>}
                      </span>
                      <span className="cm-sub">{FORMAT_LABELS[subFormatFor(client)]} · {client.subtitle}</span>
                    </span>
                    {hidden && <span className="pill">已隐藏</span>}
                    <div className="cm-actions">
                      <button
                        className="icon-btn"
                        aria-label={`上移 ${client.name}`}
                        title="上移"
                        disabled={index === 0}
                        onClick={() => moveClient(client, -1)}
                      >↑</button>
                      <button
                        className="icon-btn"
                        aria-label={`下移 ${client.name}`}
                        title="下移"
                        disabled={index === orderedClients.length - 1}
                        onClick={() => moveClient(client, 1)}
                      >↓</button>
                      <button
                        className="btn ghost"
                        disabled={!hidden && visibleClients.length <= 1}
                        title={!hidden && visibleClients.length <= 1 ? '至少保留一个可见客户端' : undefined}
                        onClick={() => toggleClientVisible(client)}
                      >{hidden ? '显示' : '隐藏'}</button>
                    </div>
                  </li>
                )
              })}
            </ul>
          </div>
        ) : (
        /* 只展示当前客户端；其余收进可按格式分组、可搜索的选择面板，避免图标墙越堆越长。 */
        <details className="client-picker" ref={pickerRef}>
          <summary className="client-card active client-current" aria-label={`当前客户端：${target.name}，点击更换`}>
            <span className="ctile">
              <img
                className="cicon"
                src={`/client-icons/${target.icon}`}
                alt={target.name}
                onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }}
              />
            </span>
            <span className="cinfo">
              <span className="cname">{target.name}</span>
              <span className="csub">{target.subtitle}</span>
            </span>
            <span className="client-change">更换客户端 <span aria-hidden="true">▾</span></span>
          </summary>

          <div className="client-picker-panel">
            <input
              className="input client-search"
              value={clientQuery}
              onChange={(e) => setClientQuery(e.target.value)}
              placeholder="搜索客户端、平台或格式…"
              aria-label="搜索客户端"
            />
            {clientGroups.map((group) => (
              <div className="client-group" key={group.key}>
                <div className="client-group-head">
                  <span>{group.label}</span>
                  <span className="num">{group.clients.length}</span>
                </div>
                <div className="client-options">
                  {group.clients.map((client) => (
                    <button
                      key={client.target}
                      className={`client-option${client.target === target.target ? ' active' : ''}`}
                      aria-pressed={client.target === target.target}
                      onClick={() => chooseClient(client)}
                    >
                      <span className="opt-icon">
                        <img
                          src={`/client-icons/${client.icon}`}
                          alt=""
                          loading="lazy"
                          onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }}
                        />
                      </span>
                      <span className="opt-text">
                        <span className="opt-name">{client.name}</span>
                        <span className="opt-sub">{client.subtitle}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            ))}
            {clientGroups.length === 0 && <div className="hint">没有匹配的客户端</div>}
          </div>
        </details>
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <h3>导出设置</h3>
          <span className="meta">{configName}</span>
        </div>
        <div className="export-fields">
          <div className="export-field">
            <div className="export-field-head">
              <span>内容模式</span>
              <span className="hint">{contentMode === 'full' ? '节点 + 策略组 + 规则' : '仅节点内容'}</span>
            </div>
            {target.contentMode === 'nodes' ? (
              <div className="segmented is-disabled" aria-label="导出内容模式">
                <button type="button" disabled>完整配置</button>
                <button type="button" className="active" aria-pressed="true" disabled>仅节点</button>
              </div>
            ) : (
              <div className="segmented" role="group" aria-label="导出内容模式">
                <button
                  type="button"
                  className={contentMode === 'full' ? 'active' : ''}
                  aria-pressed={contentMode === 'full'}
                  onClick={() => setExportContentModeFor(target.target, 'full')}
                >完整配置</button>
                <button
                  type="button"
                  className={contentMode === 'nodes' ? 'active' : ''}
                  aria-pressed={contentMode === 'nodes'}
                  onClick={() => setExportContentModeFor(target.target, 'nodes')}
                >仅节点</button>
              </div>
            )}
            <div className="hint">
              {contentMode === 'full'
                ? '写入策略组与规则，客户端导入后即可分流。'
                : '只输出节点，省略策略组与规则，适合合并进已有配置。'}
              {target.contentMode === 'nodes' ? ` ${target.name} 本身只接收节点订阅。` : ' 每个客户端会单独记住这个模式。'}
            </div>
            {contentMode === 'nodes' && (target.target === 'surge' || target.target === 'surge-mac') && (
              <div className="hint">Surge 仅节点内容用于外部策略 policy-path：复制下面的订阅地址，在 Surge 的策略组里粘贴到 URL / 本地路径。</div>
            )}
            {contentMode === 'nodes' && target.target === 'quanx' && (
              <div className="hint">Quantumult X 仅节点内容会作为 server_remote 资源导入；也可以复制订阅地址手动添加。</div>
            )}
            {contentMode === 'nodes' && target.target === 'loon' && (
              <div className="hint">Loon 仅节点内容用于 nodelist 导入。</div>
            )}
          </div>

          <div className="export-field">
            <div className="export-field-head">
              <label htmlFor="export-config-name">配置名称</label>
              <span className="hint">用于文件名与订阅标题</span>
            </div>
            <input
              id="export-config-name"
              className="input"
              value={exportConfigName}
              maxLength={48}
              placeholder="tower"
              disabled={readOnly}
              title={readOnly ? READONLY_NOTE : undefined}
              onChange={(e) => setExportConfigName(e.target.value)}
            />
            <div className="hint">
              下载为 <span className="mono">{fileStem}.{targetFormat === 'json' ? 'json' : targetFormat === 'base64' || (contentMode === 'nodes' && ['surge', 'loon', 'quanx'].includes(targetFormat)) ? 'txt' : targetFormat === 'yaml' ? 'yaml' : 'conf'}</span>
            </div>
          </div>
        </div>

        <AdvancedSection
          scope="export-prefs"
          title="导出偏好与筛选"
          summary={[
            exportRegions.length ? `${exportRegions.length} 个地区` : '',
            exportProtocols.length ? `${exportProtocols.length} 种协议` : '',
            (nodeNameFilter.include || nodeNameFilter.exclude) ? '名称筛选' : '',
            embedRemoteSubscriptions ? '代理集合' : '',
            appendSourceName ? '追加订阅名' : '',
          ].filter(Boolean).join(' · ') || '地区 / 协议 / 名称筛选 · 代理集合 · 订阅名后缀；默认收起'}
        >
        <div className="export-field protocol-field">
          <div className="export-field-head">
            <span>地区筛选</span>
            <span className="hint">
              {exportRegions.length === 0
                ? `全部 ${nameFilterResult.nodes.length} 个命中节点`
                : `已选 ${exportRegions.length} 个地区 · ${regionFilteredNodes.length} 个节点`}
            </span>
          </div>
          {regionOptions.length === 0 ? (
            <div className="hint">还没有识别到地区的节点。</div>
          ) : (
            <div className="protocol-chips" role="group" aria-label="按地区筛选节点">
              <button
                type="button"
                className={`protocol-chip${exportRegions.length === 0 ? ' active' : ''}`}
                aria-pressed={exportRegions.length === 0}
                onClick={() => setExportRegions([])}
              >
                全部 <span className="num">{nameFilterResult.nodes.length}</span>
              </button>
              {regionOptions.map((region) => {
                const active = exportRegions.includes(region.code)
                return (
                  <button
                    key={region.code}
                    type="button"
                    className={`protocol-chip${active ? ' active' : ''}`}
                    aria-pressed={active}
                    onClick={() => toggleRegion(region.code)}
                  >
                    <span aria-hidden="true">{region.flag}</span> {region.name} <span className="num">{region.count}</span>
                  </button>
                )
              })}
            </div>
          )}
        </div>

        <div className="export-field protocol-field">
          <div className="export-field-head">
            <span>协议筛选</span>
            <span className="hint">
              {exportProtocols.length === 0
                ? `全部 ${regionFilteredNodes.length} 个命中节点`
                : `已选 ${exportProtocols.length} 种协议 · ${usable.length} 个节点`}
            </span>
          </div>
          {protocolCounts.length === 0 ? (
            <div className="hint">还没有可导出的节点。</div>
          ) : (
            <div className="protocol-chips" role="group" aria-label="按协议筛选节点">
              <button
                type="button"
                className={`protocol-chip${exportProtocols.length === 0 ? ' active' : ''}`}
                aria-pressed={exportProtocols.length === 0}
                onClick={() => setExportProtocols([])}
              >
                全部 <span className="num">{regionFilteredNodes.length}</span>
              </button>
              {protocolCounts.map(([kind, count]) => {
                const active = exportProtocols.includes(kind)
                return (
                  <button
                    key={kind}
                    type="button"
                    className={`protocol-chip${active ? ' active' : ''}`}
                    aria-pressed={active}
                    onClick={() => toggleProtocol(kind)}
                  >
                    {PROXY_KIND_TITLES[kind]} <span className="num">{count}</span>
                  </button>
                )
              })}
            </div>
          )}
        </div>

        <details className="export-advanced">
          <summary>
            <span>节点名称筛选</span>
            <span className="hint">
              {nodeNameFilter.include || nodeNameFilter.exclude
                ? `${nameFilterResult.nodes.length} / ${enabled.length} 个节点匹配`
                : '包含 / 排除关键词，可选正则'}
            </span>
          </summary>
          <div className="name-filter-fields">
            <div className="export-field">
              <label htmlFor="node-filter-include">只保留包含这些关键词的节点</label>
              <textarea
                id="node-filter-include"
                className="field"
                rows={2}
                value={nodeNameFilter.include}
                placeholder="每行一个，例如：香港&#10;JP"
                onChange={(e) => setNodeNameFilter({ include: e.target.value })}
              />
            </div>
            <div className="export-field">
              <label htmlFor="node-filter-exclude">排除包含这些关键词的节点</label>
              <textarea
                id="node-filter-exclude"
                className="field"
                rows={2}
                value={nodeNameFilter.exclude}
                placeholder="每行一个，例如：到期&#10;官网"
                onChange={(e) => setNodeNameFilter({ exclude: e.target.value })}
              />
            </div>
          </div>
          <div className="name-filter-options">
            <label className="filter-check">
              <input
                type="checkbox"
                checked={nodeNameFilter.useRegex}
                onChange={(e) => setNodeNameFilter({ useRegex: e.target.checked })}
              />
              使用正则
            </label>
            <label className="filter-check">
              <input
                type="checkbox"
                checked={nodeNameFilter.caseSensitive}
                onChange={(e) => setNodeNameFilter({ caseSensitive: e.target.checked })}
              />
              区分大小写
            </label>
            {(nodeNameFilter.include || nodeNameFilter.exclude) && (
              <button
                className="btn ghost"
                onClick={() => setNodeNameFilter({ include: '', exclude: '' })}
              >清除名称筛选</button>
            )}
          </div>
          {nameFilterResult.error ? (
            <div className="error">{nameFilterResult.error}</div>
          ) : (
            <div className="hint">条件会用于所有客户端导出；订阅刷新后新增的节点也会自动匹配。</div>
          )}
        </details>

        <label className={`setting-toggle${contentMode === 'nodes' ? ' is-disabled' : ''}`}>
          <input
            type="checkbox"
            checked={embedRemoteSubscriptions}
            disabled={contentMode === 'nodes'}
            onChange={(e) => setEmbedRemoteSubscriptions(e.target.checked)}
          />
          <span>
            <strong>代理集合（嵌入原始订阅链接）</strong>
            <small>
              {contentMode === 'nodes'
                ? '仅节点模式不会写入代理集合。'
                : `把已启用订阅的原始地址写入配置，节点由客户端更新。当前载体${supportsProxyCollections ? '支持' : '暂不支持，会回退为内联节点'}；Clash / mihomo、Stash、Karing、Surge、Loon、Quantumult X 和 Egern 可写入代理集合，Shadowrocket 与 sing-box 系回退为内联节点。${embedRemoteSubscriptions ? ` 已启用 ${remoteSubscriptions.length} 个代理集合，其节点不受名称/协议筛选和追加订阅名影响。` : ''}`}
            </small>
          </span>
        </label>

        <label className="setting-toggle">
          <input
            type="checkbox"
            checked={appendSourceName}
            onChange={(e) => setAppendSourceName(e.target.checked)}
          />
          <span>
            <strong>节点名追加订阅名</strong>
            <small>例如「香港 01 · 机场 A」，多订阅合并时更容易区分；本地节点不追加。</small>
          </span>
        </label>
        <div className="hint export-settings-note">
          这些设置同时影响预览、下载和订阅链接；修改后请点「同步节点到链接」更新已发布订阅。
        </div>
        </AdvancedSection>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>规则导出</h3>
          <span className="meta">{target.name} · {FORMAT_LABELS[targetFormat]}</span>
        </div>
        <label className="setting-toggle rule-export-toggle">
          <input
            type="checkbox"
            checked={preferRuleSets}
            onChange={(e) => setPreferRuleSets(e.target.checked)}
          />
          <span>
            <strong>优先引用远程规则集</strong>
            <small>
              客户端能读取规则集原始格式时直接写远程引用：Clash / mihomo、Stash、Shadowrocket、
              Surge 和 Loon 可读经典列表；经典列表还会由塔台服务无损转换并托管为
              QuanX / Egern / sing-box 方言。托管地址跟随当前访问的塔台地址，手机导入请使用局域网地址或局域网订阅链接；
              无法转换的格式和「我的规则集」会展开写入；节点订阅客户端不包含规则。
            </small>
          </span>
        </label>
        {compatibility ? (
          <>
            <div className="rule-export-facts">
              <div className="rule-export-fact">
                <span>自定义规则</span>
                <strong className="num">{scheme?.customRules?.length ?? 0}</strong>
              </div>
              <div className="rule-export-fact">
                <span>规则集</span>
                <strong className="num">{compatibility.ruleSetCount}</strong>
              </div>
              <div className="rule-export-fact">
                <span>远程引用</span>
                <strong className="num">{compatibility.remoteRuleSets}</strong>
              </div>
              <div className="rule-export-fact">
                <span>跳过规则</span>
                <strong className="num">{compatibility.skipped}</strong>
              </div>
            </div>
            {compatibility.nodeOnly ? (
              <div className="inline-notice">
                <span>{compatibility.note}</span>
              </div>
            ) : (
              <div className="hint rule-export-note">
                {compatibility.supportsRemoteRuleSets
                  ? preferRuleSets
                    ? compatibility.ruleSetCount === 0
                      ? '当前方案没有加入规则集，自定义规则与方案规则会直接写入配置。'
                      : compatibility.remoteRuleSets > 0
                        ? `当前会把 ${compatibility.remoteRuleSets} 组规则集写成远程引用${compatibility.inlineRuleSets > 0 ? `，${compatibility.inlineRuleSets} 组规则集继续展开` : ''}。客户端需要能访问规则集的远程地址。`
                        : compatibility.ruleSetNote ?? '这些规则集当前会展开写入。'
                    : compatibility.ruleSetCount > 0
                      ? `已加入 ${compatibility.ruleSetCount} 组规则集；开启后会优先写成 ${target.name} 能直接读取的远程格式，其余继续展开。`
                      : '当前方案没有加入规则集，自定义规则与方案规则会直接写入配置。'
                  : compatibility.ruleSetCount > 0
                    ? `${target.name} 不能直接引用远程规则集，${compatibility.ruleSetCount} 组规则集会展开为单条规则写入。`
                    : `${target.name} 不能直接引用远程规则集，规则会逐条写入。`}
              </div>
            )}
            {compatibility.skipped > 0 && (
              <div className="inline-notice">
                <span>{compatibility.note}</span>
              </div>
            )}
          </>
        ) : (
          <div className="hint rule-export-note">规则方案加载中，稍后显示兼容性。</div>
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <h3>配置预览</h3>
          <span className="meta">
            <span className="num">{exportableCount}</span> 本地可用
            {hasRemoteExportable ? ` · ${remoteSourceCount} 个代理集合` : ''}
            {noEnabledNodes
              ? ' · 没有启用的节点'
              : nameFilterEmpty
                ? ' · 名称筛选没有匹配节点'
                : filterEmpty
                  ? ' · 协议筛选没有匹配节点'
                  : exportableCount === 0 && !hasRemoteExportable
                    ? ` · ${target.name} 不支持当前节点的协议`
                    : skipped
                      ? ` · ${skipped} 个协议不被 ${target.name} 支持`
                      : ` · 共 ${usable.length} 节点`}
            {exportProtocols.length > 0 && !filterEmpty ? ` · 已筛选 ${enabled.length - usable.length} 个` : ''}
          </span>
        </div>
        {!hasExportable && (
          <div className="inline-notice error">
            <span>{emptyReason}</span>
            <div className="row" style={{ gap: 6 }}>
              {(nameFilterEmpty || nameFilterResult.error) && (
                <button className="btn ghost" onClick={() => setNodeNameFilter({ include: '', exclude: '' })}>清除名称筛选</button>
              )}
              {(filterEmpty || exportProtocols.length > 0) && (
                <button className="btn ghost" onClick={() => setExportProtocols([])}>清除协议筛选</button>
              )}
              {usable.length > 0 && (
                <button
                  className="btn ghost"
                  onClick={() => {
                    const picker = pickerRef.current
                    if (picker) {
                      picker.open = true
                      picker.scrollIntoView({ block: 'center', behavior: 'smooth' })
                    }
                  }}
                >
                  换客户端
                </button>
              )}
              <button className="btn ghost" onClick={() => onGo?.('sub')}>去订阅管理</button>
            </div>
          </div>
        )}
        {scheme && (
          <div className={`inline-notice${lintState.error ? ' error' : ''}`}>
            <span>
              导出前检查：{lintState.error} error · {lintState.warn} warn · {lintState.info} info。
              {lintState.error > 0 ? ' 默认只提示，导出时会再次确认。' : ' 不影响导出。'}
            </span>
            <button className="btn ghost" onClick={() => onGo?.('check')}>查看检查结果</button>
          </div>
        )}
        <div className="row" style={{ gap: 8, marginBottom: 14 }}>
          <button className="btn" disabled={!scheme || !hasExportable} onClick={download}>{downloaded ? '已下载' : '下载文件'}</button>
          <button className="btn ghost" disabled={!hasExportable || !generated} onClick={copy}>{copied ? '已复制' : '复制'}</button>
          {canImport && (
            <button className="btn ghost" disabled={importing || !hasExportable || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={importIntoClient}>
              {importing ? '生成链接…' : `导入到 ${target.name}`}
            </button>
          )}
        </div>
        {importNotice && <div className="hint" style={{ marginBottom: 10 }}>{importNotice}</div>}
        {skipped > 0 && hasExportable && (
          <div className="inline-notice">
            <span>
              {skipped} 个节点因 {target.name} 不支持其协议，不会写入这份配置。
            </span>
            <button className="btn ghost" onClick={() => onGo?.('sub')}>去订阅管理排除</button>
          </div>
        )}
        {tailnetNotes.map((note) => (
          <div className="inline-notice tailnet-note" key={note}>
            <span>{note}</span>
            <button className="btn ghost" onClick={() => onGo?.('tailnet')}>内网设置</button>
          </div>
        ))}
        {contentMode === 'full' && activeTailnets.length > 0 && tailnetSupports(target.target) && (
          <div className="hint tailnet-applied">
            已写入 {activeTailnets.length} 个 Tailscale 内网：
            {activeTailnets.map((item) => tailnetPolicyName(item.connection)).join('、')}
            {targetFormat === 'surge' ? '。Surge 的 [Tailscale …] 段位于配置末尾（预览只显示前 40000 字符，下载后可完整查看）' : ''}。
          </div>
        )}
        {hasExportable && generated && (
          <div className="preview-tools">
            <div className="search-wrap preview-search">
              <input
                className="input"
                value={previewQuery}
                onChange={(e) => setPreviewQuery(e.target.value)}
                placeholder="搜索配置内容：域名、规则类型、节点名…"
                aria-label="搜索配置预览"
              />
              {previewQuery && (
                <button className="search-clear" aria-label="清空预览搜索" onClick={() => setPreviewQuery('')}>×</button>
              )}
            </div>
            {previewMatches && (
              <span className={`preview-hit${previewMatches.count === 0 ? ' is-empty' : ''}`}>
                {previewMatches.count === 0 ? '没有匹配行' : `${previewMatches.count} 行命中`}
              </span>
            )}
          </div>
        )}
        {hasExportable ? (
          previewMatches ? (
            previewMatches.rows.length > 0 ? (
              <pre className="preview preview-filtered">
                {previewMatches.rows.map((row) => (
                  <span className="preview-line" key={row.number}>
                    <span className="preview-line-no">{String(row.number).padStart(4, ' ')}</span>
                    {'  '}
                    <Highlight text={row.line} needle={previewMatches.needle} />
                  </span>
                ))}
                {previewMatches.truncated && <span className="preview-line-more">…仅显示前 500 行匹配，缩小关键词可继续定位</span>}
              </pre>
            ) : (
              <div className="preview-empty preview-no-match">
                <strong>没有匹配的配置行</strong>
                <span>换一个域名、规则类型或节点名再试。</span>
              </div>
            )
          ) : (
            <pre className="preview">{previewText.slice(0, 40000)}{previewText.length > 40000 ? '\n…（预览截断）' : ''}</pre>
          )
        ) : (
          <div className="preview-empty">
            <strong>当前配置不含可用节点</strong>
            <span>{noEnabledNodes ? '添加订阅或启用节点后，这里会显示生成的配置。' : nameFilterEmpty ? '清除名称筛选，或换一组关键词后再导出。' : filterEmpty ? '清除协议筛选，或选择其他协议后再导出。' : '换一个支持这些协议的客户端，或排除不兼容节点后再导出。'}</span>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <h3 style={{ margin: 0 }}>服务端订阅链接</h3>
          <div className="meta" style={{ margin: 0 }}>按客户端自动分发格式</div>
        </div>
        <div className="field" style={{ marginTop: 14 }}>
          {subURL ? (
            <>
              {/* 客户端专属 URL（跟随 target 实时变化） */}
              <div className="sub-url-wrap">
                <div className="sub-url-label">{target.name} 订阅地址（{subFormatFor(target)}）</div>
                <input readOnly className="input" value={clientSubURL} style={{ fontFamily: '"IBM Plex Mono", ui-monospace, monospace', fontSize: 12 }} />
              </div>
              {canImport && (
                <div className="sub-url-wrap" style={{ marginTop: 10 }}>
                  <div className="sub-url-label">一键导入链接（deep link）</div>
                  <input readOnly className="input" value={clientImportURL} style={{ fontFamily: '"IBM Plex Mono", ui-monospace, monospace', fontSize: 12, color: 'var(--muted)' }} />
                </div>
              )}
              {lanSubURL && (
                <div className="sub-url-wrap" style={{ marginTop: 10 }}>
                  <div className="sub-url-label">手机 / 局域网订阅地址（同一 Wi-Fi 可导入）</div>
                  <input readOnly className="input" value={lanSubURL} style={{ fontFamily: '"IBM Plex Mono", ui-monospace, monospace', fontSize: 12 }} />
                  <div className="hint" style={{ marginTop: 6 }}>
                    通用地址会按客户端 User-Agent 自动选择格式；上方客户端专属地址始终返回当前格式。
                  </div>
                </div>
              )}
              {net && net.host !== '0.0.0.0' && (
                <div className="hint" style={{ marginTop: 8 }}>
                  服务端当前只监听本机，手机无法访问；用 <span className="mono">HOST=0.0.0.0</span> 重启后才可用。
                </div>
              )}
              {subUpdatedAt && (
                <div className="hint">
                  上次同步 {new Date(subUpdatedAt).toLocaleString('zh-CN')} · 本地节点 <span className="num">{exportableCount}</span> 个
                  {remoteSourceCount > 0 ? ` · ${remoteSourceCount} 个代理集合` : ''}
                  {exportProtocols.length > 0 ? ` · ${exportProtocols.length} 种协议` : ''}
                </div>
              )}
              <div className="row sub-actions" style={{ gap: 8, marginTop: 10 }}>
                <button className="btn primary" disabled={subRefreshing || !hasExportable || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={publishSubscription}>
                  {subRefreshing ? '同步中…' : '同步节点到链接'}
                </button>
                <button className="btn ghost" disabled={checking || !hasExportable} onClick={checkSubscription}>
                  {checking ? '检查中…' : '检查链接'}
                </button>
                <button className="btn ghost" onClick={() => copyText('sub', clientSubURL)}>
                  {copiedField === 'sub' ? '已复制订阅地址' : '复制订阅地址'}
                </button>
                {canImport && (
                  <button className="btn ghost" onClick={() => copyText('import', clientImportURL)}>
                    {copiedField === 'import' ? '已复制导入链接' : '复制导入链接'}
                  </button>
                )}
                {lanSubURL && (
                  <button className="btn ghost" onClick={() => copyText('lan', lanSubURL)}>
                    {copiedField === 'lan' ? '已复制局域网地址' : '复制局域网地址'}
                  </button>
                )}
                <button className="btn ghost" onClick={() => setQrOpen(true)}>二维码</button>
                <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setPendingRevoke(true)}>撤销</button>
              </div>
              {revokeError && (
                <div className="error" style={{ marginTop: 8 }}>
                  {revokeError}
                  <button
                    className="btn ghost"
                    style={{ marginLeft: 8 }}
                    {...writeGuard(readOnly)}
                    onClick={() => void revokeSubscription()}
                  >
                    重试撤销
                  </button>
                </div>
              )}
              {checkResult && (
                <div className={checkResult.ok ? 'hint' : 'error'} style={{ marginTop: 8 }}>
                  {checkResult.ok ? '可用 · ' : '异常 · '}
                  {checkResult.text}
                  {!checkResult.ok && hasExportable && (
                    <button className="btn ghost" style={{ marginLeft: 8 }} {...writeGuard(readOnly)} onClick={publishSubscription}>
                      重新生成链接
                    </button>
                  )}
                </div>
              )}
              <div className="next-steps">
                <div className="next-steps-title">下一步</div>
                <ol>
                  {canImport && (
                    <li>点「导入到 {target.name}」直接唤起客户端；没反应就复制下面的订阅地址手动添加。</li>
                  )}
                  <li>
                    复制{lanSubURL ? '「手机 / 局域网」' : ''}订阅地址，在 {target.name} 的「订阅 / 配置」里粘贴。
                  </li>
                  <li>在客户端里更新一次订阅，确认节点数量与测速正常。</li>
                </ol>
                {skipped > 0 && (
                  <div className="next-steps-note">
                    {target.name} 不支持 {skipped} 个节点的协议，这些节点不会出现在订阅里。
                  </div>
                )}
              </div>
            </>
          ) : (
            <>
              <button className="btn primary sub-publish-start" disabled={subRefreshing || !hasExportable || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={publishSubscription}>
                {subRefreshing ? '生成中…' : '生成订阅链接'}
              </button>
              {!hasExportable && <div className="error" style={{ marginTop: 8 }}>{emptyReason}</div>}
              <div className="next-steps">
                <div className="next-steps-title">生成后会得到什么</div>
                <ol>
                  <li>一条订阅地址：同一 token 下按客户端自动分发 6 种格式。</li>
                  <li>{canImport ? `复制地址或点「导入到 ${target.name}」把它交给客户端。` : `复制地址，在 ${target.name} 里添加订阅或粘贴节点。`}</li>
                  <li>在客户端更新一次订阅，节点与规则随即生效。</li>
                </ol>
              </div>
            </>
          )}
        </div>
        <details className="link-note">
          <summary>链接存储与有效期</summary>
          <div className="link-note-body">
            链接保存在本机 <span className="mono">server/subscriptions.json</span>，塔台重启后仍然有效；
            server 关闭期间客户端更新会失败，重新启动即可恢复。撤销或删除订阅会让对应链接立即失效。
          </div>
        </details>
      </div>

      <ConfirmDialog
        open={!!pendingExport}
        title={`导出前检查发现 ${pendingExport?.errors ?? 0} 个错误`}
        body={(
          <>
            这些问题不会阻止导出，但可能让规则或策略组在客户端里不生效：
            <ul style={{ margin: '8px 0 0', paddingLeft: 18 }}>
              {lintIssues.filter((issue) => issue.level === 'error').slice(0, 5).map((issue) => (
                <li key={issue.id}>{issue.message}</li>
              ))}
            </ul>
            {pendingExport && pendingExport.errors > 5 && <div className="hint">还有 {pendingExport.errors - 5} 个错误，可在规则诊断页查看。</div>}
          </>
        )}
        confirmLabel="仍然导出"
        onCancel={() => { setPendingExport(null); onGo?.('check') }}
        onConfirm={() => {
          const pending = pendingExport
          setPendingExport(null)
          setLintAck(lintKey)
          pending?.run()
        }}
      />
      <ConfirmDialog
        open={pendingRevoke}
        title="撤销订阅链接？"
        body={<>撤销后 <b>已经导入该链接的客户端</b> 将无法再更新订阅，需要重新生成。节点本身不会删除。</>}
        confirmLabel="撤销链接"
        danger
        confirmDisabled={readOnly}
        onCancel={() => setPendingRevoke(false)}
        onConfirm={() => { setPendingRevoke(false); void revokeSubscription() }}
      />
      <QRCodeDialog
        open={qrOpen}
        url={clientLanSubURL || clientSubURL}
        title={configName}
        hint={lanSubURL
          ? '手机与电脑需在同一 Wi-Fi；扫码后把订阅地址添加到客户端。'
          : localHost
            ? '当前二维码指向本机地址，手机扫描可能无法访问；请改用局域网地址打开塔台后再生成。'
            : '扫码后把订阅地址添加到客户端。'}
        onClose={() => setQrOpen(false)}
      />
    </div>
  )
}

// ---------------- App ----------------

const TABS: { key: TabKey; label: string; short: string; Icon: () => ReactNode }[] = [
  { key: 'sub', label: '订阅管理', short: '订阅', Icon: Icon.Subscriptions },
  { key: 'rules', label: '规则配置', short: '规则', Icon: Icon.Rules },
  { key: 'check', label: '规则诊断', short: '检查', Icon: Icon.Check },
  { key: 'export', label: '导出', short: '导出', Icon: Icon.Export },
  { key: 'tailnet', label: 'Tailscale', short: '内网', Icon: Icon.Network },
]

export function App() {
  const [tab, setTab] = useState<TabKey>('sub')
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [pendingLocate, setPendingLocate] = useState<SchemeLintIssue | null>(null)
  const [exportTick, setExportTick] = useState(0)
  const autoRefreshStarted = useRef(false)
  const ruleSetAutoRefreshStarted = useRef(false)
  const builtinUpdateCheckStarted = useRef(false)
  const keysPruned = useRef(false)
  const [storageFull, setStorageFull] = useState(isStorageFull)
  const workspaceMode = useWorkspaceStatus().mode

  useEffect(() => onStorageFullChange(setStorageFull), [])

  // 四步主线需要跨页读取同一份数据；方案本身仍然走缓存加载。
  const scheme = useScheme()
  const sources = useStore((s) => s.sources)
  const nodes = useStore((s) => s.nodes)
  const errors = useStore((s) => s.errors)
  const policySelections = useStore((s) => s.policySelections)
  const localRuleSets = useStore((s) => s.localRuleSets)
  const preferRuleSets = useStore((s) => s.preferRuleSets)
  const customSchemes = useStore((s) => s.customSchemes)
  const enabled = useMemo(() => enabledNodes({ sources, nodes }), [sources, nodes])

  const flowLint = useMemo(() => {
    if (!scheme) return { error: 0, warn: 0 }
    try {
      const issues = lintScheme({ scheme, nodes: enabled, policySelections, localRuleSets, preferRuleSets })
      return lintSummary(issues)
    } catch {
      return { error: 0, warn: 0 }
    }
  }, [scheme, enabled, policySelections, localRuleSets, preferRuleSets])

  const sourceErrors = useMemo(
    () => sources.map((source) => errors[source.id]?.trim()).filter((value): value is string => !!value),
    [sources, errors],
  )
  const manualNodeCount = useMemo(
    () => nodes.filter((node) => node.isManual).length,
    [nodes],
  )
  const excludedNodeCount = useMemo(() => {
    const excludedKeys = new Set(sources.flatMap((source) => source.excludedNodeKeys))
    return nodes.filter((node) =>
      !node.isSubscriptionMetadata
      && (excludedKeys.has(nodeExactKey(node)) || node.isEnabled === false)).length
  }, [nodes, sources])
  const nodeCount = nodes.filter((node) => !node.isSubscriptionMetadata).length

  const published = (() => {
    try { return !!window.localStorage.getItem('tower-sub-token') } catch { return false }
  })()
  const exportedAt = useMemo(() => readExportedAt(), [exportTick])

  useEffect(() => {
    const handler = () => setExportTick((value) => value + 1)
    window.addEventListener('tower:exported', handler)
    return () => window.removeEventListener('tower:exported', handler)
  }, [])

  const flowSteps = buildFlow({
    sourceCount: sources.length,
    manualNodeCount,
    nodeCount,
    enabledNodeCount: enabled.length,
    excludedNodeCount,
    sourceErrors,
    hasExportable: enabled.length > 0,
    schemeReady: !!scheme,
    schemeName: scheme?.name,
    schemeCustomized: !!customSchemes.find((item) => item.id === scheme?.id),
    lintErrors: flowLint.error,
    lintWarnings: flowLint.warn,
    published,
    exportedAt,
  })
  const flowCurrent: FlowStepKey = tab === 'sub' ? 'import' : tab === 'rules' ? 'scheme' : tab === 'check' ? 'check' : 'export'
  const showFlow = tab !== 'tailnet'

  const goFlowStep = (key: FlowStepKey) => {
    if (key === 'import') switchTab('sub')
    else if (key === 'scheme') switchTab('rules')
    else if (key === 'check') switchTab('check')
    else switchTab('export')
  }

  // 快照恢复后删除已删除连接留下的 Auth Key。
  useEffect(() => {
    const run = () => {
      if (keysPruned.current) return
      keysPruned.current = true
      useStore.getState().pruneTailnetKeys()
    }
    if (useStore.persist.hasHydrated()) {
      run()
      return
    }
    return useStore.persist.onFinishHydration(run)
  }, [])

  // 只在页面打开时尝试一次；未启用/没有地址的订阅不联网。
  useEffect(() => {
    if (autoRefreshStarted.current) return
    autoRefreshStarted.current = true
    const run = () => {
      const state = useStore.getState()
      if (!state.autoRefreshOnOpen) return
      const ids = state.sources
        .filter((s) => s.url && isSourceEnabled(s) && !state.loadingSourceIDs.includes(s.id))
        .map((s) => s.id)
      if (!ids.length) return
      void Promise.all(ids.map((id) => state.refreshSource(id)))
    }
    if (useStore.persist.hasHydrated()) {
      run()
      return
    }
    return useStore.persist.onFinishHydration(run)
  }, [])

  // 打开时只比对内置方案的上游响应头，发现变化写一条提示；绝不自动覆盖。
  // 服务器版由服务端定时检查，这里只等模式确定后执行，server 模式直接跳过且不发请求。
  useEffect(() => {
    if (builtinUpdateCheckStarted.current) return
    if (workspaceMode === 'unknown') return
    builtinUpdateCheckStarted.current = true
    const run = () => {
      const state = useStore.getState()
      void runBuiltinUpdateCheckOnOpen(
        {
          mode: workspaceMode,
          enabled: state.checkBuiltinSchemeUpdatesOnOpen,
          selectedSchemeID: state.selectedSchemeID,
          schemes: BUILTIN_SCHEMES,
          overrides: state.builtinSchemeOverrides,
          snapshots: state.schemeSnapshots,
        },
        { notify: (schemeID, message) => useStore.getState().setBuiltinSchemeUpdateNotice(schemeID, message) },
      )
    }
    if (useStore.persist.hasHydrated()) {
      run()
      return
    }
    return useStore.persist.onFinishHydration(run)
  }, [workspaceMode])

  // 在线规则集订阅的打开时刷新；只更新「我的规则集」快照，不改方案快照。
  useEffect(() => {
    if (ruleSetAutoRefreshStarted.current) return
    ruleSetAutoRefreshStarted.current = true
    const run = () => {
      const state = useStore.getState()
      if (!state.autoRefreshRuleSetsOnOpen) return
      const sets = state.localRuleSets.filter((set) => set.sourceURL && !set.paused)
      if (!sets.length) return
      void Promise.all(sets.map(async (set) => {
        try {
          const parsed = await fetchRuleSet(set.sourceURL!)
          const current = useStore.getState().localRuleSets.find((item) => item.id === set.id)
          if (!current) return
          if (digestRules(parsed.rules) !== digestRules(set.rules)) {
            recordRuleSetSnapshot(set.id, set.rules, useStore.getState().ruleSetVersionHistory)
          }
          const updated = ruleSetRefreshSuccess(current, parsed.rules)
          useStore.getState().addLocalRuleSet({ ...updated, format: parsed.format })
        } catch (error) {
          const current = useStore.getState().localRuleSets.find((item) => item.id === set.id)
          if (!current) return
          useStore.getState().addLocalRuleSet(ruleSetRefreshFailure(current, (error as Error).message))
        }
      }))
    }
    if (useStore.persist.hasHydrated()) {
      run()
      return
    }
    return useStore.persist.onFinishHydration(run)
  }, [])

  // Close drawer on desktop resize
  useEffect(() => {
    const mq = window.matchMedia('(min-width: 861px)')
    const handler = (e: MediaQueryListEvent | MediaQueryList) => {
      if ((e as any).matches !== undefined ? (e as MediaQueryListEvent).matches : (e as MediaQueryList).matches) {
        setSidebarOpen(false)
      }
    }
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [])

  // Lock body scroll while drawer open
  useEffect(() => {
    if (sidebarOpen) document.body.classList.add('no-scroll')
    else document.body.classList.remove('no-scroll')
    return () => document.body.classList.remove('no-scroll')
  }, [sidebarOpen])

  // Esc 关闭抽屉
  useEffect(() => {
    if (!sidebarOpen) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setSidebarOpen(false) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [sidebarOpen])

  // 抽屉关闭后不要把键盘焦点留在已隐藏的侧栏里；落到当前移动端页签。
  useEffect(() => {
    if (sidebarOpen || !window.matchMedia('(max-width: 860px)').matches) return
    const active = document.activeElement as HTMLElement | null
    if (!active?.closest('.sidebar')) return
    const currentTab = TABS.find((t) => t.key === tab)
    let mobileTarget: HTMLElement | null = currentTab
      ? (document.querySelector(`.mobile-tab[aria-label="${currentTab.label}"]`) as HTMLElement | null)
      : null
    if (!mobileTarget) mobileTarget = document.querySelector('.menu-toggle') as HTMLElement | null
    mobileTarget?.focus()
  }, [sidebarOpen, tab])

  const switchTab = (key: TabKey) => {
    setTab(key)
    setSidebarOpen(false)
  }

  return (
    <div className="app-shell">
      <LANAccessGate />
      <WorkspaceStatusBanner />
      {storageFull && (
        <div className="storage-alert" role="alert">
          <strong>浏览器存储已满</strong>
          <span>当前修改只保留在内存中，刷新后会丢失。请到「导出」页保存备份，再清理不需要的订阅或规则方案。</span>
          <button className="storage-alert-close" type="button" onClick={() => setStorageFull(false)}>
            知道了
          </button>
        </div>
      )}
      <aside
        className={`sidebar${sidebarOpen ? ' open' : ''}`}
      >
        <div className="brand">
          <div className="logo">
            <img src="/logo.png" alt="塔台 Tower" />
          </div>
          <div className="brand-text">
            <div className="name">塔台</div>
            <div className="sub">Tower Web · 本地代理管理</div>
          </div>
          <button className="sidebar-close" onClick={() => setSidebarOpen(false)} aria-label="关闭菜单">
            <Icon.Close />
          </button>
        </div>
        <nav className="nav">
          {TABS.map((t) => (
            <button
              key={t.key}
              className={`nav-item${tab === t.key ? ' active' : ''}`}
              onClick={() => switchTab(t.key)}
              aria-current={tab === t.key ? 'page' : undefined}
            >
              <t.Icon />
              <span>{t.label}</span>
            </button>
          ))}
        </nav>
        <div className="bottom">
          {GITHUB_REPO_URL ? (
            <a
              className="gh-link"
              href={GITHUB_REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              aria-label="在 GitHub 打开 thintsing 的主页"
              title="GitHub · thintsing"
            >
              <Icon.Github />
              <span className="gh-text">GitHub</span>
            </a>
          ) : (
            <span
              className="gh-link is-placeholder"
              role="img"
              aria-label="GitHub 仓库地址待配置"
              title="GitHub 仓库地址待配置"
            >
              <Icon.Github />
              <span className="gh-text">GitHub</span>
            </span>
          )}
          <div className="meta">
            所有订阅解析、节点生成、配置导出<br />均在本机完成，不上传任何第三方服务
          </div>
        </div>
      </aside>

      {/* mobile overlay behind drawer */}
      <div
        className={`drawer-overlay${sidebarOpen ? ' visible' : ''}`}
        onClick={() => setSidebarOpen(false)}
        aria-hidden="true"
      />

      <main className="right-col">
        {/* 窄屏导航条：桌面端由侧栏导航，这里不重复页名。 */}
        <div className="topbar">
          <button
            className="menu-toggle"
            onClick={() => setSidebarOpen((v) => !v)}
            aria-label={sidebarOpen ? '关闭菜单' : '打开菜单'}
            aria-expanded={sidebarOpen}
          >
            {sidebarOpen ? <Icon.Close /> : <Icon.Menu />}
          </button>
          <nav className="mobile-tabs" aria-label="工作区切换">
            {TABS.map((t) => (
              <button
                key={t.key}
                type="button"
                className={`mobile-tab${tab === t.key ? ' active' : ''}`}
                onClick={() => switchTab(t.key)}
                aria-label={t.label}
                aria-current={tab === t.key ? 'page' : undefined}
                title={t.label}
              >
                <t.Icon />
                <span>{t.short}</span>
              </button>
            ))}
          </nav>
        </div>
        <div className="sheet">
          {showFlow && <FlowRail steps={flowSteps} current={flowCurrent} onGo={goFlowStep} />}
          {tab === 'sub' && <SubscriptionTab onGo={switchTab} />}
          {tab === 'rules' && (
            <RulesTab
              onGo={switchTab}
              locateIssue={pendingLocate}
              onLocateConsumed={() => setPendingLocate(null)}
            />
          )}
          {tab === 'check' && (
            <CheckTab
              onGo={switchTab}
              onLocate={(issue) => { setPendingLocate(issue); switchTab('rules') }}
            />
          )}
          {tab === 'export' && <ExportTab onGo={switchTab} />}
          {tab === 'tailnet' && <TailnetTab />}
        </div>
      </main>
    </div>
  )
}
