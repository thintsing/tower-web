import { useEffect, useMemo, useRef, useState, lazy, Suspense, memo, useCallback, type ReactNode, type SyntheticEvent } from 'react'
import { CLIENTS, PROXY_KIND_TITLES, subscriptionUsageSummary, type ProxyNode, type SubscriptionSource } from './models/types'
import { allRegions, regionForName, regionForNode } from './models/region'
import type { TabKey } from './models/navigation'
import { enabledNodes, isSourceEnabled, nodeExactKey, useStore } from './store'
import { BUILTIN_SCHEMES } from './rules/scheme'
import { runBuiltinUpdateCheckOnOpen } from './rules/upstreamOnOpen'
import { ruleSetRefreshFailure, ruleSetRefreshSuccess } from './rules/ruleSetRefresh'
import { fetchRuleSet, inferRuleSetBehavior } from './rules/ruleSets'
import type { ManualNodeImportResult } from './manualNodes'
import { MAX_BATCH_SUBSCRIPTIONS, splitSubscriptionURLs, subscriptionLabel } from './batchSubscriptions'
import { nodeShareText } from './generator/shareLink'
import { nodeTransportCapability } from './generator/nodeCapabilities'
import { resolveHostedBaseURL } from './rules/remoteFormats'
import { copyToClipboard } from './util/browser'
import { formatDate } from './util/formatDate'
import { browserStorage, createSafeStorage, describeStorageFull, getStorageFullSerial, isStorageFull, measureStorage, onStorageFullChange } from './util/localStore'
import { placeDetailsPanel, placeOpenDetailsPanels } from './util/menuPlacement'
import { apiFetch, getAPIKey, setAPIKey } from './util/apiAuth'
import { isLoopbackHost, useNetworkInfo } from './util/networkInfo'
import { GITHUB_REPO_URL } from './config'
import { RouteIllustration } from './components/RouteIllustration'
import { Highlight } from './components/Highlight'
import { Icon } from './components/Icon'
import { ConfirmDialog } from './components/ConfirmDialog'
import { QRCodeDialog } from './components/QRCodeDialog'
import { TailnetTab } from './pages/TailnetTab'
import { CheckTab } from './pages/CheckTab'
import { RulesTab } from './pages/RulesTab'
import { ExportTab } from './pages/ExportTab'
import { ManualNodeEditorDialog } from './components/ManualNodeEditorDialog'
import { SourceUsage, shouldShowSourceUsage } from './components/SourceUsage'
import { UserAgentField } from './components/UserAgentField'
import { FlowRail } from './components/FlowRail'
import { WorkspaceStatusBanner } from './components/WorkspaceStatusBanner'
import { SubscriptionSettingsDialog } from './components/SubscriptionSettingsDialog'
import { useWorkspaceStatus } from './workspaceSync'
import { autoRefreshReady, buildRefreshReport, describeRefreshReport, dismissRefreshReport, publishRefreshReport, refreshFailureText, selectRefreshTargets, useRefreshReport, type RefreshOutcome } from './subscriptionRefreshReport'
import { READONLY_NOTE, writeGuard } from './util/readOnlyUi'
import { buildFlow, explainNodePool, type FlowStepKey } from './flow/flow'
import { useScheme } from './rules/useScheme'
import { DEMO_MODE, SUB_TOKEN_KEY } from './demo/demoMode'
import { readExportedAt } from './flow/prefs'
import { digestRules, recordRuleSetSnapshot } from './rules/ruleSetHistory'
import { lintScheme, lintSummary, type SchemeLintIssue } from './rules/schemeLint'

/** 发布 token / 地址是设备偏好；隐私模式或配额满时不能把导出页一起拖崩。 */
const localPrefs = createSafeStorage(browserStorage)

// 地图与扫码只在对应面板出现时才加载，避免把 d3/map 和 jsQR 塞进首屏。
const WorldMapSVG = lazy(() => import('./worldmap/WorldMapSVG').then((mod) => ({ default: mod.WorldMapSVG })))
const QrScanner = lazy(() => import('./components/QrScanner').then((mod) => ({ default: mod.QrScanner })))

/** details 菜单打开/关闭后按视口可用空间决定向上或向下展开。 */
function updateDetailsPlacement(event: SyntheticEvent<HTMLDetailsElement>): void {
  const details = event.currentTarget
  requestAnimationFrame(() => placeDetailsPanel(details))
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

// ---------------- 通用小组件 ----------------

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

const NodeRow = memo(function NodeRow({
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
  // 只订阅本节点自己的切片。订阅整张 latency / probeError 表会让任一节点测速
  // 完成时所有 NodeRow 一起重渲染，千节点订阅在测速期间会明显卡顿。
  const latency = useStore((s) => s.latencyByNodeId[node.id])
  const method = useStore((s) => s.latencyMethodByNodeId[node.id])
  const probeError = useStore((s) => s.probeErrorByNodeId[node.id])
  const testing = useStore((s) => s.testingNodeIds.includes(node.id))
  const subscribedSourceName = useStore((s) => s.sources.find((src) => src.id === node.sourceID)?.name)
  const excluded = useStore((s) => {
    if (node.isManual) return node.isEnabled === false
    const src = s.sources.find((item) => item.id === node.sourceID)
    if (!src || src.excludedNodeKeys.length === 0) return false
    return src.excludedNodeKeys.includes(nodeExactKey(node))
  })
  const readOnly = useWorkspaceStatus().readOnly
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
    ? subscribedSourceName
    : node.isManual ? '自有节点' : '本地节点'
  const regionSource = node.countryOverride
    ? '手动标记'
    : regionForName(node.name)
      ? '节点名称'
      : node.detectedCountry ? '离线 IP' : '未知'
  const shareURI = nodeShareText(node)
  const capability = nodeTransportCapability(node)
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
    const measured = method
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
})

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
  const handleEditManualNode = useCallback((node: ProxyNode) => setManualEditor({ node }), [])
  const [batchFailures, setBatchFailures] = useState<SourceAddFailure[] | null>(null)
  const [refreshProgress, setRefreshProgress] = useState<{ done: number; total: number } | null>(null)
  const refreshReport = useRefreshReport()
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
    // 已经在刷新中的订阅不再重复请求，避免同一条并发两次。
    const targets = selectRefreshTargets(refreshableSources, loadingSourceIDs)
    if (!targets.length) return
    let done = 0
    setRefreshProgress({ done, total: targets.length })
    const outcomes: RefreshOutcome[] = []
    await Promise.all(targets.map(async (source) => {
      let error = ''
      try {
        await refreshSource(source.id)
        error = useStore.getState().errors[source.id] ?? ''
      } catch (e) {
        error = e instanceof Error ? e.message : String(e)
      } finally {
        outcomes.push({ id: source.id, name: source.name, error })
        done += 1
        setRefreshProgress({ done, total: targets.length })
      }
    }))
    setRefreshProgress(null)
    // 汇总留在列表上方；失败原因在各自卡片里也有，但不该让用户自己去找。
    publishRefreshReport(buildRefreshReport('manual', outcomes))
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

      {refreshReport && (
        <div
          className={`refresh-report${refreshReport.failures.length ? ' has-failures' : ''}`}
          role="status"
          aria-live="polite"
        >
          <div className="refresh-report-head">
            <span>{describeRefreshReport(refreshReport)}</span>
            {refreshReport.failures.length > 0 && (
              <details className="refresh-report-details">
                <summary>查看失败明细</summary>
                <ul>
                  {refreshReport.failures.map((item) => (
                    <li key={item.id}>{refreshFailureText(item)}</li>
                  ))}
                </ul>
              </details>
            )}
            <button className="btn ghost refresh-report-close" onClick={dismissRefreshReport}>知道了</button>
          </div>
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
          onEditNode={handleEditManualNode}
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
  const [storageState, setStorageState] = useState(() => ({
    full: isStorageFull(),
    serial: getStorageFullSerial(),
  }))
  const [storageDismissedSerial, setStorageDismissedSerial] = useState(0)
  const workspaceStatus = useWorkspaceStatus()
  const workspaceMode = workspaceStatus.mode

  useEffect(() => onStorageFullChange((full) => {
    // 每次容量失败都会带上新的 serial；用户点掉上一次提示后，下一次失败仍会重新出现。
    setStorageState({ full, serial: getStorageFullSerial() })
  }), [])

  const showStorageFull = storageState.full && storageState.serial > storageDismissedSerial
  const storageNotice = useMemo(
    () => (showStorageFull
      ? describeStorageFull(
          { mode: workspaceStatus.mode, state: workspaceStatus.state },
          measureStorage(),
        )
      : ''),
    [showStorageFull, workspaceStatus.mode, workspaceStatus.state, storageState.serial],
  )

  // 四步主线需要跨页读取同一份数据；方案本身仍然走缓存加载。
  const scheme = useScheme()
  const sources = useStore((s) => s.sources)
  const nodes = useStore((s) => s.nodes)
  const errors = useStore((s) => s.errors)
  const policySelections = useStore((s) => s.policySelections)
  const localRuleSets = useStore((s) => s.localRuleSets)
  const preferRuleSets = useStore((s) => s.preferRuleSets)
  const customSchemes = useStore((s) => s.customSchemes)
  const ruleSetExclusions = useStore((s) => s.ruleSetExclusions)
  const enabled = useMemo(() => enabledNodes({ sources, nodes }), [sources, nodes])
  const net = useNetworkInfo()
  // 主线检查与导出页共用同一份托管地址；undefined 代表载体未知，不能当可托管。
  const flowHostedBaseURL = useMemo(
    () => resolveHostedBaseURL({
      providerOnly: (scheme?.ruleSets ?? []).some((set) => set.providerOnly),
      net,
      loopback: isLoopbackHost(),
      origin: window.location.origin,
    }),
    [net, scheme],
  )

  const flowLint = useMemo(() => {
    if (!scheme) return { error: 0, warn: 0 }
    try {
      const issues = lintScheme({ scheme, nodes: enabled, policySelections, localRuleSets, preferRuleSets, ruleSetExclusions, hostedBaseURL: flowHostedBaseURL })
      return lintSummary(issues)
    } catch {
      return { error: 0, warn: 0 }
    }
  }, [scheme, enabled, policySelections, localRuleSets, preferRuleSets, ruleSetExclusions, flowHostedBaseURL])

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
    try { return !!window.localStorage.getItem(SUB_TOKEN_KEY) } catch { return false }
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
  // 服务器模式必须等工作区在线后再跑，避免按本地旧缓存刷新远程订阅、报出不存在的失败。
  useEffect(() => {
    if (autoRefreshStarted.current) return
    if (!autoRefreshReady(workspaceStatus.mode, workspaceStatus.state)) return
    autoRefreshStarted.current = true
    const run = () => {
      const state = useStore.getState()
      if (!state.autoRefreshOnOpen) return
      const targets = selectRefreshTargets(
        state.sources.filter((s) => s.url && isSourceEnabled(s)),
        state.loadingSourceIDs,
      )
      if (!targets.length) return
      // 自动刷新不弹窗，但必须把结果留在订阅页；否则失败完全静默。
      const outcomes: RefreshOutcome[] = []
      void Promise.all(targets.map(async (source) => {
        let error = ''
        try {
          await state.refreshSource(source.id)
          error = useStore.getState().errors[source.id] ?? ''
        } catch (e) {
          error = e instanceof Error ? e.message : String(e)
        }
        outcomes.push({ id: source.id, name: source.name, error })
      })).then(() => {
        publishRefreshReport(buildRefreshReport('auto', outcomes))
      })
    }
    if (useStore.persist.hasHydrated()) {
      run()
      return
    }
    return useStore.persist.onFinishHydration(run)
  }, [workspaceStatus.mode, workspaceStatus.state])

  // 打开时只比对内置方案的上游响应头，发现变化写一条提示；绝不自动覆盖。
  // 服务器版由服务端定时检查，这里只等模式确定后执行，server 模式直接跳过且不发请求。
  useEffect(() => {
    // 示例工作区保持完全离线，不因检查上游更新向外发请求。
    if (DEMO_MODE) return
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
    // 服务器模式必须等工作区在线后再跑：首连前刷新会改写 localRuleSets，
    // 既可能被服务端数据静默覆盖，也可能被误判成用户编辑而进入冲突。
    if (!autoRefreshReady(workspaceStatus.mode, workspaceStatus.state)) return
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
          useStore.getState().addLocalRuleSet({
            ...updated,
            format: parsed.format,
            ruleSetBehavior: parsed.format === 'yaml' ? inferRuleSetBehavior(parsed.rules) : undefined,
          })
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
  }, [workspaceStatus.mode, workspaceStatus.state])

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
      {showStorageFull && (
        <div className="storage-alert" role="alert">
          <strong>浏览器存储已满</strong>
          <span>{storageNotice}</span>
          <button
            className="storage-alert-close"
            type="button"
            onClick={() => setStorageDismissedSerial(storageState.serial)}
          >
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
        {DEMO_MODE && (
          <div className="demo-banner" role="status">
            <span><b>示例工作区</b> · 虚构节点与用量，不会写入真实工作区</span>
            <a href={window.location.pathname}>退出示例</a>
          </div>
        )}
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
