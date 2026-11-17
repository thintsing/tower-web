// 导出页：客户端目标、内容模式、发布订阅与二维码。
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  CLIENTS,
  PROXY_KIND_TITLES,
  clientSupportsImport,
  subFormatFor,
  type ClientInfo,
  type ClientTarget,
  type ExportContentMode,
  type ProxyKind,
  type ProxyNode,
  type RemoteSubscriptionEntry,
  type SubFormat,
  type TailnetExport,
} from '../models/types'
import type { TabKey } from '../models/navigation'
import { enabledNodes, isSourceEnabled, useStore } from '../store'
import { useWorkspaceStatus } from '../workspaceSync'
import { useScheme } from '../rules/useScheme'
import { resolveHostedBaseURL } from '../rules/remoteFormats'
import { formatSupportsProxyCollections, prepareSchemeForExport } from '../generator/groups'
import { analyzeRuleCompatibility } from '../generator/compatibility'
import { describeSubscriptionFormatFailures, generateConfig, generateSubscriptionFormatsDetailed, SUBSCRIPTION_FORMAT_TITLES } from '../generator'
import { generateRuleFile, type RuleFileFormat } from '../generator/ruleFiles'
import { anywhereAjsonCount, anywhereAjsonDocument } from '../generator/anywhere'
import { surgeBetaNodeCount } from '../generator/surgeCapabilities'
import { maskTailnetAuthKeys, tailnetSupports } from '../generator/tailnet'
import { tailnetPolicyName } from '../models/tailnet'
import { clientsInOrder, configFileStem, effectiveContentMode, filterNodesByName } from '../util/exportSelection'
import { clientSubscriptionLink } from '../util/subscriptionLinks'
import { lintScheme, lintSummary } from '../rules/schemeLint'
import { filterNodesByRegionCodes, regionForNode } from '../models/region'
import { apiFetch } from '../util/apiAuth'
import { copyToClipboard } from '../util/browser'
import { browserStorage, createSafeStorage } from '../util/localStore'
import { DEMO_MODE, DEMO_PUBLISH_NOTE, SUB_TOKEN_KEY, SUB_UPDATED_AT_KEY, SUB_URL_KEY, demoBlocksServerWrites } from '../demo/demoMode'
import { markExported } from '../flow/prefs'
import { READONLY_NOTE, writeGuard } from '../util/readOnlyUi'
import { AdvancedSection } from '../components/AdvancedSection'
import { ClientRuleDiagnostics } from '../components/ClientRuleDiagnostics'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { Highlight } from '../components/Highlight'
import { QRCodeDialog } from '../components/QRCodeDialog'

const localPrefs = createSafeStorage(browserStorage)

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

interface VariantPreview {
  formats: { format: SubFormat; bytes: number }[]
  failures: { format: SubFormat; reason: string }[]
  surgeTiers: { platform: 'surge' | 'surge-mac'; tier: string; bytes: number }[]
  surgeNodeTiers: { platform: 'surge' | 'surge-mac'; tier: string; bytes: number }[]
  nodeFormatCount: number
  nodeTargetCount: number
  anywhere: { bytes: number; count: number } | null
  totalBytes: number
}

type SurgeTierMap = Partial<Record<'surge' | 'surge-mac', Record<string, string>>>

function utf8Bytes(text: string): number {
  return new TextEncoder().encode(text).length
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function surgeTierRows(tiers: SurgeTierMap): VariantPreview['surgeTiers'] {
  const rows: VariantPreview['surgeTiers'] = []
  for (const platform of ['surge', 'surge-mac'] as const) {
    for (const tier of ['1', '2', '3']) {
      const text = tiers[platform]?.[tier]
      if (text) rows.push({ platform, tier, bytes: utf8Bytes(text) })
    }
  }
  return rows
}

function VariantPreviewPanel({ preview }: { preview: VariantPreview }) {
  return (
    <div style={{ marginTop: 14 }}>
      <div className="row between" style={{ marginBottom: 8 }}>
        <strong>发布变体预检</strong>
        <span className="meta">总大小 {formatBytes(preview.totalBytes)}</span>
      </div>
      <div className="rule-export-facts">
        <div className="rule-export-fact">
          <span>基线载体</span>
          <strong className="num">{preview.formats.length}</strong>
        </div>
        <div className="rule-export-fact">
          <span>Surge 档位</span>
          <strong className="num">{preview.surgeTiers.length}</strong>
        </div>
        <div className="rule-export-fact">
          <span>仅节点载体</span>
          <strong className="num">{preview.nodeFormatCount}</strong>
        </div>
        <div className="rule-export-fact">
          <span>仅节点目标</span>
          <strong className="num">{preview.nodeTargetCount}</strong>
        </div>
      </div>
      {preview.failures.length > 0 ? (
        <div className="error" style={{ marginTop: 8 }}>
          失败载体：{preview.failures
            .map((failure) => `${SUBSCRIPTION_FORMAT_TITLES[failure.format]}（${failure.reason}）`)
            .join('；')}
        </div>
      ) : (
        <div className="hint" style={{ marginTop: 8 }}>所有基线载体已生成成功，可以发布。</div>
      )}
      <div className="hint" style={{ marginTop: 6 }}>
        {preview.formats
          .map((row) => `${SUBSCRIPTION_FORMAT_TITLES[row.format]} ${formatBytes(row.bytes)}`)
          .join(' · ')}
      </div>
      {preview.surgeTiers.length > 0 && (
        <div className="hint" style={{ marginTop: 6 }}>
          Surge 测试版：{preview.surgeTiers
            .map((row) => `${row.platform === 'surge' ? 'iOS' : 'Mac'} tier${row.tier} ${formatBytes(row.bytes)}`)
            .join(' · ')}（按请求 UA 返回）
        </div>
      )}
      {preview.anywhere && (
        <div className="hint" style={{ marginTop: 6 }}>
          Anywhere AJSON：{preview.anywhere.count} 个节点 · {formatBytes(preview.anywhere.bytes)}
        </div>
      )}
      <div className="hint" style={{ marginTop: 6 }}>
        仅节点变体：{preview.nodeFormatCount} 种载体、{preview.nodeTargetCount} 个客户端目标
        {preview.surgeNodeTiers.length > 0 ? `、${preview.surgeNodeTiers.length} 个 Surge 档位` : ''}。
      </div>
    </div>
  )
}

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

export function ExportTab({ onGo }: { onGo?: (tab: TabKey) => void }) {
  const workspaceStatus = useWorkspaceStatus()
  const readOnly = workspaceStatus.readOnly
  // 服务器模式的订阅地址由服务端固定；本地模式仍跟随当前访问地址。
  const serverMode = workspaceStatus.mode === 'server'
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
  const [net, setNet] = useState<{
    host: string
    lan: string[]
    publicUrl: string
    publicUrlError: string
  } | null>(null)
  const localHost = ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(window.location.hostname)
  // provider 引用 / 托管转换地址必须是对手机可达的绝对地址。
  // 判据不是 serverMode（它只表示是否启用服务端工作区），而是 /api/network
  // 是否可用；本地伴生服务同样提供 /api/ruleset。取不到局域网地址时才置空，
  // 由导出侧硬阻断，而不是退回 localhost 产出不可达配置。
  const hostedBaseURL = useMemo(
    () => resolveHostedBaseURL({
      providerOnly: (scheme?.ruleSets ?? []).some((set) => set.providerOnly && !set.inlined),
      net,
      loopback: localHost,
      origin: window.location.origin,
    }),
    [scheme, net, localHost],
  )
  // 预览与下载按当前客户端载体准备方案；发布时由 generateSubscriptionFormats
  // 再按各载体分别准备，避免这里提前合并导致规则重复。
  const exportScheme = useMemo(
    () => scheme ? prepareSchemeForExport(scheme, policySelections, {
      preferRuleSets,
      format: targetFormat,
      target: target.target,
      ruleSetExclusions,
      hostedBaseURL,
    }) : undefined,
    [scheme, policySelections, preferRuleSets, targetFormat, target.target, ruleSetExclusions, hostedBaseURL],
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
  const [subToken, setSubToken] = useState<string>(() => localPrefs.getItem(SUB_TOKEN_KEY) ?? '')
  const [subURL, setSubURL] = useState(() => {
    const raw = localPrefs.getItem(SUB_URL_KEY) ?? ''
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
    const v = Number(localPrefs.getItem(SUB_UPDATED_AT_KEY))
    return Number.isFinite(v) && v > 0 ? v : null
  })
  const [checking, setChecking] = useState(false)
  const [checkResult, setCheckResult] = useState<{ ok: boolean; text: string } | null>(null)
  const [ruleFileNotice, setRuleFileNotice] = useState<{ ok: boolean; text: string } | null>(null)
  const [variantPreview, setVariantPreview] = useState<VariantPreview | null>(null)
  /** 撤销链接失败时保留 token 与地址，显示原因并提供重试。 */
  const [revokeError, setRevokeError] = useState('')
  const [copiedField, setCopiedField] = useState<'sub' | 'nodes' | 'import' | 'lan' | null>(null)
  const [copiedClientLink, setCopiedClientLink] = useState<string | null>(null)
  const [importNotice, setImportNotice] = useState('')

  useEffect(() => {
    // 示例工作区不读取服务端网络信息，也不会发布可分享的订阅地址。
    if (DEMO_MODE) return
    apiFetch('/api/network')
      .then((r) => r.json())
      .then((d) => setNet({
        host: String(d?.host ?? ''),
        lan: Array.isArray(d?.lan) ? d.lan : [],
        publicUrl: String(d?.publicUrl ?? ''),
        publicUrlError: String(d?.publicUrlError ?? ''),
      }))
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
  const copyText = async (field: 'sub' | 'nodes' | 'import' | 'lan', value: string) => {
    const ok = await copyToClipboard(value)
    if (!ok) {
      setCheckResult({ ok: false, text: '这台机器不允许网页写剪贴板，请点输入框手动全选复制' })
      return
    }
    setCopiedField(field)
    window.setTimeout(() => setCopiedField((v) => (v === field ? null : v)), 1600)
  }

  const copyClientLink = async (key: string, value: string) => {
    const ok = await copyToClipboard(value)
    if (!ok) {
      setCheckResult({ ok: false, text: '这台机器不允许网页写剪贴板，请点输入框手动全选复制' })
      return
    }
    setCopiedClientLink(key)
    window.setTimeout(() => setCopiedClientLink((v) => (v === key ? null : v)), 1600)
  }

  const enabled = useMemo(() => enabledNodes({ sources, nodes }), [sources, nodes])
  const lintIssues = useMemo(
    () => (scheme ? lintScheme({ scheme, nodes: enabled, policySelections, localRuleSets, preferRuleSets, ruleSetExclusions, clients: [target], hostedBaseURL }) : []),
    [scheme, enabled, policySelections, localRuleSets, preferRuleSets, ruleSetExclusions, target, hostedBaseURL],
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
  // 与导出使用同一批节点判断空策略组：零节点时 ♻️ 自动选择会写成空 proxies，
  // mihomo 会直接拒绝加载。这里统一算一次阻断，供下面的预览和各导出按钮共用。
  const compatibility = useMemo(
    () => scheme ? analyzeRuleCompatibility(target, scheme, {
      preferRuleSets, contentMode, ruleSetExclusions, hostedBaseURL, nodes: usable,
    }) : undefined,
    [target, scheme, preferRuleSets, contentMode, ruleSetExclusions, hostedBaseURL, usable],
  )
  const exportBlockNote = compatibility?.providerOnlyBlocked
    ? compatibility.providerOnlyNote
    : compatibility?.emptyGroupsBlocked
      ? compatibility.emptyGroupsNote
      : undefined
  const exportBlocked = !!exportBlockNote
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
  // Surge 测试版 / Anywhere AJSON 的节点不在基线配置里，但仍可通过一键导入使用。
  const surgeOneTapCount = target.target === 'surge' || target.target === 'surge-mac'
    ? surgeBetaNodeCount(usable)
    : 0
  const anywhereOneTapCount = target.target === 'anywhere' ? anywhereAjsonCount(usable) : 0
  const hasOneTapOnly = surgeOneTapCount > 0 || anywhereOneTapCount > 0
  const baselineExportable = exportableCount > 0 || hasRemoteExportable
  const hasExportable = baselineExportable || hasOneTapOnly
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
  const clientSubscriptionURL = useCallback((client: ClientInfo, nodesOnly = false) => clientSubscriptionLink(subURL, client, {
    serverMode,
    origin: window.location.origin,
    nodesOnly,
  }), [serverMode, subURL])

  const clientSubURL = useMemo(
    () => clientSubscriptionURL(target),
    [clientSubscriptionURL, target],
  )

  /** 同一订阅的仅节点地址：服务端按 content=nodes 返回只含节点的载体。 */
  const clientNodeSubURL = useMemo(
    () => clientSubscriptionURL(target, true),
    [clientSubscriptionURL, target],
  )

  const outputOptions = useMemo(
    () => ({
      contentMode,
      nameForNode,
      remoteSubscriptions: previewRemoteSubscriptions,
      tailnets: contentMode === 'full' ? activeTailnets : [],
      // Surge 自更新首行只指向已发布的链接；尚未发布（subURL 为空）时不写，
      // 避免生成一个指向不存在地址的 #!MANAGED-CONFIG。
      managedConfigURL: targetFormat === 'surge' && contentMode === 'full' ? clientSubURL : '',
      hostedBaseURL,
    }),
    [contentMode, nameForNode, previewRemoteSubscriptions, activeTailnets, targetFormat, clientSubURL, hostedBaseURL],
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
    if (!exportScheme || exportBlocked) {
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
  }, [target, usable, exportScheme, outputOptions, exportBlocked])

  // importScheme 可用时包装成客户端 deep link，否则直接给订阅地址。
  const clientImportURL = useMemo(() => {
    if (!clientSubURL) return ''
    if (!canImport) return ''
    return target.importScheme?.(clientSubURL, configName, contentMode) ?? ''
  }, [target, clientSubURL, configName, contentMode, canImport])

  // 本机打开的页面，手机端要用局域网地址而不是 127.0.0.1。
  // 服务器模式的规范地址已经由 TOWER_PUBLIC_URL 决定，不能再另造一条局域网地址。
  const clientLanSubURL = useMemo(() => {
    if (serverMode || !localHost || !net?.lan[0] || !clientSubURL) return ''
    return clientSubURL.replace(window.location.origin, net.lan[0])
  }, [serverMode, localHost, net, clientSubURL])

  // 通用局域网地址不带 format，由服务端按客户端 User-Agent / target 自动识别。
  const lanSubURL = useMemo(() => {
    if (serverMode || !localHost || !net?.lan[0] || !subURL) return ''
    try {
      const path = new URL(subURL, window.location.origin).pathname
      return new URL(path, window.location.origin).href.replace(window.location.origin, net.lan[0])
    } catch {
      return ''
    }
  }, [serverMode, localHost, net, subURL])

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

  /** 独立规则文件只含规则行，不含客户端配置、策略列与 FINAL。 */
  const downloadRuleFile = (format: RuleFileFormat) => {
    if (!scheme) {
      setRuleFileNotice({ ok: false, text: '规则方案还没加载完成，稍后再试' })
      return
    }
    const result = generateRuleFile(scheme, {
      target: target.target,
      format,
      name: configName,
      ruleSetExclusions,
    })
    if (result.ruleCount === 0) {
      setRuleFileNotice({ ok: false, text: '当前方案没有可导出的规则。' })
      return
    }
    const blob = new Blob([result.text], { type: result.mime })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${fileStem}-rules.${result.extension}`
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.setTimeout(() => URL.revokeObjectURL(a.href), 1000)
    setRuleFileNotice({
      ok: true,
      text: `已导出 ${result.ruleCount} 条规则${result.skipped ? `，跳过 ${result.skipped} 条` : ''}${result.referencedRuleSets ? `，保留 ${result.referencedRuleSets} 个规则集引用` : ''}。`,
    })
  }

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
    if (demoBlocksServerWrites(DEMO_MODE)) {
      setImportNotice(DEMO_PUBLISH_NOTE)
      return
    }
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

  /** 发布当前节点到订阅地址；dryRun 只生成并展示变体，不写服务端。 */
  const publishNow = async (dryRun = false): Promise<string | null> => {
    // 预检只生成文本、不写服务端，示例工作区也可以使用。
    if (!dryRun && demoBlocksServerWrites(DEMO_MODE)) {
      setCheckResult({ ok: false, text: DEMO_PUBLISH_NOTE })
      return null
    }
    if (usable.length === 0) {
      setCheckResult({ ok: false, text: '没有可导出的节点：请先在「订阅管理」添加订阅或自有节点，并启用节点' })
      return null
    }
    if (!scheme) {
      setCheckResult({ ok: false, text: '规则方案尚未加载完成，请稍后重试' })
      return null
    }
    // 发布链接会同时生成 Surge / Loon / QuanX / Egern / sing-box 载体；
    // 只存 provider 引用的方案需要服务端托管转换，且托管地址必须对手机可达。
    const providerOnlyCount = (scheme.ruleSets ?? []).filter((set) => set.providerOnly && !set.inlined).length
    if (providerOnlyCount > 0 && hostedBaseURL === '') {
      setCheckResult({
        ok: false,
        text: '当前方案使用 Clash provider 引用，其他客户端依赖塔台服务托管转换；未能获取手机可达的托管地址（塔台服务未响应，或没有可用局域网地址）。请启动塔台服务 / 配置 TOWER_PUBLIC_URL 后重试。',
      })
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
      const generated = generateSubscriptionFormatsDetailed(usable, scheme, {
        policySelections,
        preferRuleSets,
        ruleSetExclusions,
        contentMode,
        contentModeByFormat,
        nameForNode,
        remoteSubscriptions,
        tailnets: activeTailnets,
        hostedBaseURL,
      })
      const formats = generated.formats
      // Anywhere 的 AJSON 变体只在有跳过证书校验节点时生成；它不替代基线
      // 链接列表，旧版 Anywhere 仍按原格式读取。
      const anywhereAjson = anywhereAjsonDocument(usable, configName)
      // 仅节点变体与发布时的内容模式无关：content=nodes 链接单独取这一份。
      const nodeGenerated = generateSubscriptionFormatsDetailed(usable, scheme, {
        policySelections,
        preferRuleSets,
        ruleSetExclusions,
        contentMode: 'nodes',
        nameForNode,
        remoteSubscriptions: [],
        tailnets: [],
        hostedBaseURL,
      })
      const nodeFormats: Partial<Record<SubFormat, string>> = {}
      for (const [format, text] of Object.entries(nodeGenerated.formats)) {
        if (text.trim()) nodeFormats[format as SubFormat] = text
      }
      const failures = generated.failures.filter(
        (failure) => !(failure.format === 'base64' && anywhereAjson),
      )
      // 订阅链接对所有客户端共用；任何目标载体缺失都意味着对应客户端会收到
      // 406，不能把半成品地址发出去。失败原因必须逐条展示，不能只报「发布失败」。
      if (failures.length > 0 && !dryRun) {
        throw new Error(
          `以下 ${failures.length} 个载体没有生成成功，已停止发布：`
          + `${describeSubscriptionFormatFailures(failures)}。`
          + '请检查节点 / 规则方案后重试；缺失载体的客户端会收到 406。',
        )
      }
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
          hostedBaseURL,
        })
        const mode = effectiveContentMode(shadowrocket, exportContentModes, exportContentMode)
        targets.shadowrocket = generateConfig(shadowrocket, usable, prepared, {
          contentMode: mode,
          nameForNode,
          remoteSubscriptions: [],
          tailnets: [],
          hostedBaseURL,
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
          hostedBaseURL,
        })
        const mode = effectiveContentMode(karing, exportContentModes, exportContentMode)
        targets.karing = generateConfig(karing, usable, prepared, {
          contentMode: mode,
          nameForNode,
          remoteSubscriptions,
          tailnets: [],
          hostedBaseURL,
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
          hostedBaseURL,
        })
        targets[targetKey] = generateConfig(client, usable, prepared, {
          contentMode: mode,
          nameForNode,
          remoteSubscriptions,
          tailnets: [],
          hostedBaseURL,
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
            hostedBaseURL,
          })
          targets[targetKey] = generateConfig(client, usable, prepared, {
            contentMode: mode,
            nameForNode,
            remoteSubscriptions,
            tailnets: mode === 'full' ? activeTailnets : [],
            hostedBaseURL,
          }).text
        }
      }
      // 仅节点目标变体：Surge / Shadowrocket / Karing / sing-box 系的节点写法
      // 与通用载体不同；content=nodes 链接按 target 取这里的一份。
      const nodeTargets: Partial<Record<ClientTarget, string>> = {}
      for (const targetKey of ['surge', 'surge-mac', 'shadowrocket', 'karing', 'sing-box', 'hiddify'] as const) {
        const client = CLIENTS.find((item) => item.target === targetKey)
        if (!client) continue
        try {
          // 仅节点模式不读规则；不准备方案，provider-only 方案也能生成。
          const text = generateConfig(client, usable, scheme, {
            contentMode: 'nodes',
            nameForNode,
            remoteSubscriptions: [],
            tailnets: [],
            hostedBaseURL,
          }).text
          if (text.trim()) nodeTargets[targetKey] = text
        } catch {
          // 单个目标生成失败不影响其他客户端；缺失时服务端会回退通用载体。
        }
      }
      // Surge 测试版变体：按构建号分档，服务端根据请求 UA 返回。
      // 正式版仍拿基线载体，不会被未知参数破坏。
      const surgeTiers: Partial<Record<'surge' | 'surge-mac', Record<string, string>>> = {}
      const surgeNodeTiers: Partial<Record<'surge' | 'surge-mac', Record<string, string>>> = {}
      if (surgeBetaNodeCount(usable) > 0) {
        for (const targetKey of ['surge', 'surge-mac'] as const) {
          const client = CLIENTS.find((item) => item.target === targetKey)
          if (!client) continue
          for (const tier of [1, 2, 3] as const) {
            try {
              const prepared = prepareSchemeForExport(scheme, policySelections, {
                preferRuleSets,
                format: 'surge',
                target: targetKey,
                ruleSetExclusions,
                hostedBaseURL,
              })
              const mode = effectiveContentMode(client, exportContentModes, exportContentMode)
              const text = generateConfig(client, usable, prepared, {
                contentMode: mode,
                nameForNode,
                remoteSubscriptions,
                tailnets: mode === 'full' ? activeTailnets : [],
                hostedBaseURL,
                surgeTier: tier,
              }).text
              if (text.trim()) {
                surgeTiers[targetKey] ??= {}
                surgeTiers[targetKey]![String(tier)] = text
              }
              const nodeText = generateConfig(client, usable, scheme, {
                contentMode: 'nodes',
                nameForNode,
                remoteSubscriptions: [],
                tailnets: [],
                hostedBaseURL,
                surgeTier: tier,
              }).text
              if (nodeText.trim()) {
                surgeNodeTiers[targetKey] ??= {}
                surgeNodeTiers[targetKey]![String(tier)] = nodeText
              }
            } catch {
              // 单个档位生成失败不影响基线发布。
            }
          }
        }
      }
      if (dryRun) {
        const formatRows = (Object.entries(formats) as [SubFormat, string][])
          .filter(([, text]) => text.trim())
          .map(([format, text]) => ({ format, bytes: utf8Bytes(text) }))
        const surgeRows = surgeTierRows(surgeTiers)
        const surgeNodeRows = surgeTierRows(surgeNodeTiers)
        const anywhereCount = anywhereAjsonCount(usable)
        const totalBytes = [
          ...formatRows.map((row) => row.bytes),
          ...Object.values(targets).map((text) => utf8Bytes(text ?? '')),
          ...Object.values(nodeFormats).map((text) => utf8Bytes(text ?? '')),
          ...Object.values(nodeTargets).map((text) => utf8Bytes(text ?? '')),
          ...surgeRows.map((row) => row.bytes),
          ...surgeNodeRows.map((row) => row.bytes),
          ...(anywhereAjson ? [utf8Bytes(anywhereAjson)] : []),
        ].reduce((sum, bytes) => sum + bytes, 0)
        setVariantPreview({
          formats: formatRows,
          failures,
          surgeTiers: surgeRows,
          surgeNodeTiers: surgeNodeRows,
          nodeFormatCount: Object.keys(nodeFormats).length,
          nodeTargetCount: Object.keys(nodeTargets).length,
          anywhere: anywhereAjson ? { bytes: utf8Bytes(anywhereAjson), count: anywhereCount } : null,
          totalBytes,
        })
        setCheckResult({
          ok: failures.length === 0,
          text: failures.length
            ? `预检发现 ${failures.length} 个载体失败：${describeSubscriptionFormatFailures(failures)}`
            : `预检通过：${formatRows.length} 种基线载体、${surgeRows.length} 个 Surge 档位`
              + `${anywhereAjson ? `、Anywhere AJSON（${anywhereCount} 个节点）` : ''}`
              + `、${Object.keys(nodeFormats).length} 种仅节点载体。`,
        })
        return null
      }
      const query = new URLSearchParams({ title: configName })
      if (subToken) query.set('token', subToken)
      const res = await apiFetch(`/api/subscribe?${query.toString()}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify({
          title: configName,
          formats,
          targets,
          ...(Object.keys(nodeFormats).length ? { nodeFormats } : {}),
          ...(Object.keys(nodeTargets).length ? { nodeTargets } : {}),
          ...(Object.keys(surgeTiers).length ? { surgeTiers } : {}),
          ...(Object.keys(surgeNodeTiers).length ? { surgeNodeTiers } : {}),
          ...(anywhereAjson ? { anywhereAjson } : {}),
        }),
      })
      if (!res.ok) {
        const detail = await res.text().catch(() => '')
        throw new Error(`HTTP ${res.status} ${detail.slice(0, 80)}`)
      }
      const json = await res.json()
      setSubToken(json.token)
      setRevokeError('')
      localPrefs.setItem(SUB_TOKEN_KEY, json.token)
      // 服务器模式优先用服务端返回的规范前缀；未配置 TOWER_PUBLIC_URL 时才
      // 回退到当前 origin（导出页会同时显示配置提示）。
      const abs = new URL(json.url, serverMode && json.publicUrl ? json.publicUrl : window.location.origin).href
      setSubURL(abs)
      localPrefs.setItem(SUB_URL_KEY, abs)
      const now = Date.now()
      setSubUpdatedAt(now)
      localPrefs.setItem(SUB_UPDATED_AT_KEY, String(now))
      markExported()
      return abs
    } catch (e: unknown) {
      setCheckResult({ ok: false, text: `${dryRun ? '预检' : '发布'}失败：${e instanceof Error ? e.message : String(e)}` })
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
      const oneTap = surgeOneTapCount || anywhereOneTapCount
      setCheckResult({
        ok: true,
        text: `已发布 · ${exportableCount} 个本地节点${oneTap ? ` · ${oneTap} 个仅一键导入` : ''}${remoteLabel}${tailnetLabel} · 各载体按对应客户端设置生成`,
      })
    }
  }

  const publishSubscription = () => guardExport(() => void publishNowSubscription())

  // 之前发布过的 token 里存的是旧内容（例如修好 DNS 之前的 YAML）。
  // 进入导出页时静默同步一次，地址不变，用户 Clash 刷新订阅就能拿到修复后的配置。
  const autoSyncedRef = useRef(false)
  useEffect(() => {
    if (autoSyncedRef.current || DEMO_MODE) return
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
    if (demoBlocksServerWrites(DEMO_MODE)) {
      setRevokeError(DEMO_PUBLISH_NOTE)
      return
    }
    setRevokeError('')
    let payload: { reset?: unknown; token?: unknown; url?: unknown; publicUrl?: unknown } = {}
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
      if (response.ok) {
        try {
          payload = await response.json() as typeof payload
        } catch {
          // 旧服务端可能返回空响应；本地模式仍然清空即可。
        }
      }
    } catch (err) {
      const action = serverMode ? '重置' : '撤销'
      setRevokeError(`${action}失败：${err instanceof Error ? err.message : String(err)}。链接仍然有效，请重试。`)
      return
    }
    // 服务器模式的重置会直接返回新 canonical；立即换成新链接，避免界面先空一片。
    if (serverMode
      && payload.reset === true
      && typeof payload.token === 'string'
      && typeof payload.url === 'string') {
      const token = payload.token
      const base = typeof payload.publicUrl === 'string' && payload.publicUrl
        ? payload.publicUrl
        : window.location.origin
      const abs = new URL(payload.url, base).href
      setSubToken(token)
      localPrefs.setItem(SUB_TOKEN_KEY, token)
      setSubURL(abs)
      localPrefs.setItem(SUB_URL_KEY, abs)
      const now = Date.now()
      setSubUpdatedAt(now)
      localPrefs.setItem(SUB_UPDATED_AT_KEY, String(now))
      setCheckResult({ ok: true, text: '已重置工作区订阅链接；旧链接已失效，其他设备下次同步会使用新链接。' })
      return
    }
    setSubToken(''); setSubURL(''); setSubUpdatedAt(null)
    localPrefs.removeItem(SUB_TOKEN_KEY)
    localPrefs.removeItem(SUB_URL_KEY)
    localPrefs.removeItem(SUB_UPDATED_AT_KEY)
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
              Surge 和 Loon 可读经典列表；经典列表还会由塔台服务托管转换并转成
              QuanX / Egern / sing-box 方言。转换只做格式映射：QuanX / sing-box 的远程列表
              没有 no-resolve 参数，带该参数的 IP 规则会退化成普通 IP 规则（可能触发解析）；
              Loon 的托管正文与 Surge 共用，按 Surge 口径也不带参数，同样退化为普通 IP 规则
              （Surge 把 no-resolve 写在 RULE-SET 行）。托管地址优先使用服务端
              <span className="mono">TOWER_PUBLIC_URL</span>，其次当前访问地址；本机
              <span className="mono">localhost</span> 打开时退回局域网地址，都拿不到则停止导出。
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
              <div className={`hint rule-export-note${exportBlocked ? ' warn' : ''}`}>
                {exportBlocked
                  ? compatibility.emptyGroupsBlocked
                    ? '导出已阻断：有策略组解析后没有任何成员，原因与修复方式见下方。'
                    : exportBlockNote
                  : compatibility.providerOnlyCount > 0
                    ? compatibility.providerOnlyNote ?? (targetFormat === 'yaml'
                      ? `这个方案只保存 ${compatibility.providerOnlyCount} 组 Clash provider 引用（不保存正文），会直接写成 rule-providers + RULE-SET，不受「优先引用」开关影响；客户端需要能访问这些地址。`
                      : `这个方案只保存 ${compatibility.providerOnlyCount} 组 Clash provider 引用（不保存正文），会由塔台服务托管转换并写成 ${target.name} 的远程规则集；客户端需要能访问塔台的对外地址。`)
                    : compatibility.supportsRemoteRuleSets
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
        {scheme && (
          <AdvancedSection
            scope="export-client-rule-diagnostics"
            title="按客户端规则诊断"
            summary={`${visibleClients.length} 个客户端 · 规则白名单与跳过原因`}
          >
            <ClientRuleDiagnostics
              clients={visibleClients}
              scheme={scheme}
              nodes={usable}
              preferRuleSets={preferRuleSets}
              exportContentMode={exportContentMode}
              exportContentModes={exportContentModes}
              ruleSetExclusions={ruleSetExclusions}
              hostedBaseURL={hostedBaseURL}
            />
          </AdvancedSection>
        )}
        <div className="row" style={{ gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
          <button className="btn ghost" onClick={() => downloadRuleFile('list')}>导出规则 .list</button>
          <button className="btn ghost" onClick={() => downloadRuleFile('yaml')}>导出规则 .yaml</button>
          <button className="btn ghost" onClick={() => downloadRuleFile('json')}>导出规则 .json</button>
        </div>
        {ruleFileNotice && (
          <div className={ruleFileNotice.ok ? 'hint' : 'error'} style={{ marginTop: 8 }} role="status">
            {ruleFileNotice.text}
          </div>
        )}
        <div className="hint" style={{ marginTop: 8 }}>
          独立规则文件只含规则行，不含客户端配置、策略列和 FINAL；按 {target.name} 的规则能力过滤。
          .yaml 为 Clash classical provider 的 payload 写法，无法展开的远程规则集会跳过并计入提示。
        </div>
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
          <button className="btn" disabled={!scheme || !baselineExportable || !generated || exportBlocked} onClick={download}>{downloaded ? '已下载' : '下载文件'}</button>
          <button className="btn ghost" disabled={!baselineExportable || !generated || exportBlocked} onClick={copy}>{copied ? '已复制' : '复制'}</button>
          {canImport && !DEMO_MODE && (
            <button className="btn ghost" disabled={importing || !hasExportable || readOnly || exportBlocked} title={readOnly ? READONLY_NOTE : undefined} onClick={importIntoClient}>
              {importing ? '生成链接…' : `导入到 ${target.name}`}
            </button>
          )}
        </div>
        {surgeOneTapCount > 0 && (
          <div className="inline-notice" style={{ marginBottom: 10 }}>
            <span>
              其中 {surgeOneTapCount} 个节点仅 Surge 测试版可用。下载文件和复制文本不包含它们；
              一键导入 / 订阅链接会按请求方 Surge 构建号自动返回测试版档位。
            </span>
          </div>
        )}
        {anywhereOneTapCount > 0 && (
          <div className="inline-notice" style={{ marginBottom: 10 }}>
            <span>
              其中 {anywhereOneTapCount} 个跳过证书校验的节点仅 Anywhere 一键导入（AJSON）可用；
              复制的文本和下载文件不包含它们。
            </span>
          </div>
        )}
        {exportBlocked && (
          <div className="inline-notice error" style={{ marginBottom: 10 }}>
            <span>{exportBlockNote}</span>
            <button className="btn ghost" onClick={() => onGo?.('check')}>查看检查结果</button>
          </div>
        )}
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
            <strong>{surgeOneTapCount > 0 ? '仅 Surge 测试版可用' : anywhereOneTapCount > 0 ? '仅 Anywhere 一键导入可用' : '当前配置不含可用节点'}</strong>
            <span>{surgeOneTapCount > 0
              ? '这些节点无法写入正式版 Surge 文件；请使用一键导入或订阅链接，Surge 测试版会自动拿到对应档位。'
              : anywhereOneTapCount > 0
                ? '这些节点只在 Anywhere 声明 AJSON 时通过订阅链接返回；下载文件与复制文本不包含它们。'
                : noEnabledNodes ? '添加订阅或启用节点后，这里会显示生成的配置。' : nameFilterEmpty ? '清除名称筛选，或换一组关键词后再导出。' : filterEmpty ? '清除协议筛选，或选择其他协议后再导出。' : '换一个支持这些协议的客户端，或排除不兼容节点后再导出。'}</span>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <h3 style={{ margin: 0 }}>服务端订阅链接</h3>
          <div className="meta" style={{ margin: 0 }}>按客户端自动分发格式</div>
        </div>
        <div className="field" style={{ marginTop: 14 }}>
          {DEMO_MODE ? (
            <>
              <div className="hint">{DEMO_PUBLISH_NOTE}</div>
              <button className="btn ghost" style={{ marginTop: 8 }} disabled={subRefreshing || !hasExportable} onClick={() => void publishNow(true)}>
                {subRefreshing ? '预检中…' : '预检发布变体'}
              </button>
              {variantPreview && <VariantPreviewPanel preview={variantPreview} />}
            </>
          ) : (
            <>
          {serverMode && net && !net.publicUrl && (
            <div className="error" role="alert" style={{ marginBottom: 10 }}>
              跨设备使用同一条订阅地址需要给服务端配置 <span className="mono">TOWER_PUBLIC_URL</span>。
              {net.publicUrlError
                ? ` 当前配置无效：${net.publicUrlError}`
                : ' 当前已回退为访问塔台的地址，不同设备仍可能得到不同地址。'}
            </div>
          )}
          {subURL ? (
            <>
              {/* 客户端专属 URL（跟随 target 实时变化） */}
              <div className="sub-url-wrap">
                <div className="sub-url-label">{target.name} 订阅地址（{subFormatFor(target)}）</div>
                <input readOnly className="input" value={clientSubURL} style={{ fontFamily: '"IBM Plex Mono", ui-monospace, monospace', fontSize: 12 }} />
              </div>
              {clientNodeSubURL && (
                <div className="sub-url-wrap" style={{ marginTop: 10 }}>
                  <div className="sub-url-label">仅节点订阅地址（content=nodes）</div>
                  <input readOnly className="input" value={clientNodeSubURL} style={{ fontFamily: '"IBM Plex Mono", ui-monospace, monospace', fontSize: 12 }} />
                  <div className="hint" style={{ marginTop: 6 }}>
                    只下发节点、不写规则；Surge 测试版会按请求 UA 返回带 VLESS / HTTPUpgrade 的仅节点列表。
                    旧链接若提示没有该变体，点「同步节点到链接」重新发布即可。
                  </div>
                </div>
              )}
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
                <button className="btn ghost" disabled={subRefreshing || !hasExportable} onClick={() => void publishNow(true)}>
                  {subRefreshing ? '预检中…' : '预检发布变体'}
                </button>
                <button className="btn ghost" disabled={checking || !hasExportable} onClick={checkSubscription}>
                  {checking ? '检查中…' : '检查链接'}
                </button>
                <button className="btn ghost" onClick={() => copyText('sub', clientSubURL)}>
                  {copiedField === 'sub' ? '已复制订阅地址' : '复制订阅地址'}
                </button>
                {clientNodeSubURL && (
                  <button className="btn ghost" onClick={() => copyText('nodes', clientNodeSubURL)}>
                    {copiedField === 'nodes' ? '已复制仅节点地址' : '复制仅节点地址'}
                  </button>
                )}
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
                <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => setPendingRevoke(true)}>
                  {serverMode ? '重置链接' : '撤销'}
                </button>
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
                    {serverMode ? '重试重置' : '重试撤销'}
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
              <AdvancedSection
                scope="export-all-client-links"
                title="所有客户端链接"
                summary={`${visibleClients.length} 个客户端 · 完整配置 / 仅节点`}
              >
                {visibleClients.map((client) => {
                  const fullURL = clientSubscriptionURL(client)
                  const nodesURL = clientSubscriptionURL(client, true)
                  const surgeBeta = client.target === 'surge' || client.target === 'surge-mac'
                  return (
                    <div key={client.target} className="sub-url-wrap" style={{ marginTop: 12 }}>
                      <div className="sub-url-label">
                        {client.name} · {FORMAT_LABELS[subFormatFor(client)]}
                        {surgeBeta ? ' · 测试版按 UA 分档' : ''}
                      </div>
                      <div className="row" style={{ gap: 6, alignItems: 'center', marginTop: 6 }}>
                        <span className="hint" style={{ minWidth: 56 }}>完整配置</span>
                        <input
                          readOnly
                          className="input"
                          value={fullURL}
                          style={{ flex: 1, minWidth: 0, fontFamily: '"IBM Plex Mono", ui-monospace, monospace', fontSize: 12 }}
                        />
                        <button className="btn ghost" onClick={() => void copyClientLink(`${client.target}:full`, fullURL)}>
                          {copiedClientLink === `${client.target}:full` ? '已复制' : '复制'}
                        </button>
                      </div>
                      <div className="row" style={{ gap: 6, alignItems: 'center', marginTop: 6 }}>
                        <span className="hint" style={{ minWidth: 56 }}>仅节点</span>
                        <input
                          readOnly
                          className="input"
                          value={nodesURL}
                          style={{ flex: 1, minWidth: 0, fontFamily: '"IBM Plex Mono", ui-monospace, monospace', fontSize: 12 }}
                        />
                        <button className="btn ghost" onClick={() => void copyClientLink(`${client.target}:nodes`, nodesURL)}>
                          {copiedClientLink === `${client.target}:nodes` ? '已复制' : '复制'}
                        </button>
                      </div>
                    </div>
                  )
                })}
              </AdvancedSection>
            </>
          ) : (
            <>
              <button className="btn primary sub-publish-start" disabled={subRefreshing || !hasExportable || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={publishSubscription}>
                {subRefreshing ? '生成中…' : '生成订阅链接'}
              </button>
              <button className="btn ghost" style={{ marginTop: 8 }} disabled={subRefreshing || !hasExportable} onClick={() => void publishNow(true)}>
                {subRefreshing ? '预检中…' : '预检发布变体'}
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
          {variantPreview && <VariantPreviewPanel preview={variantPreview} />}
            </>
          )}
        </div>
        {!DEMO_MODE && (
        <details className="link-note">
          <summary>链接存储与有效期</summary>
          <div className="link-note-body">
            {serverMode
              ? <>链接保存在服务端数据目录的 <span className="mono">subscriptions.json</span>，塔台重启后仍然有效；
                  服务器模式下所有设备共用一条固定链接，重置会立即换新 token 并让旧链接失效。</>
              : <>链接保存在本机 <span className="mono">server/subscriptions.json</span>，塔台重启后仍然有效；
                  server 关闭期间客户端更新会失败，重新启动即可恢复。撤销或删除订阅会让对应链接立即失效。</>}
          </div>
        </details>
        )}
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
        title={serverMode ? '重置工作区订阅链接？' : '撤销订阅链接？'}
        body={serverMode
          ? <>重置后会立即生成新的固定链接，<b>旧链接对所有设备立即失效</b>；已导入旧链接的客户端需要重新导入。节点本身不会删除。</>
          : <>撤销后 <b>已经导入该链接的客户端</b> 将无法再更新订阅，需要重新生成。节点本身不会删除。</>}
        confirmLabel={serverMode ? '重置链接' : '撤销链接'}
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
          : serverMode && net && !net.publicUrl
            ? '尚未配置 TOWER_PUBLIC_URL；当前二维码可能指向本机或某台设备的访问地址，跨设备未必可用。'
            : localHost
              ? '当前二维码指向本机地址，手机扫描可能无法访问；请改用局域网地址打开塔台后再生成。'
              : '扫码后把订阅地址添加到客户端。'}
        onClose={() => setQrOpen(false)}
      />
    </div>
  )
}
