// 规则库弹窗：内置 ACL4SSR 快照与在线目录；添加时读取为方案内快照。
import { useEffect, useRef, useState } from 'react'
import type { RuleScheme, RuleSetFormat } from '../../models/types'
import { ONLINE_RULE_CATALOG } from '../../rules/ruleCatalog'
import { parseRuleList } from '../../rules/scheme'
import { fetchRuleSet, inferRuleSetBehavior, type RuleSetRule } from '../../rules/ruleSets'
import { normalizeRemoteTextURL } from '../../util/remoteURL'
import { useWorkspaceStatus } from '../../workspaceSync'
import { groupDisplayName } from '../GroupIcon'

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

export interface RuleSetPayload {
  name: string
  group: string
  rules: RuleSetRule[]
  sourceKind: 'library' | 'local' | 'url'
  sourceRef?: string
  format?: RuleSetFormat
  /** provider YAML 的 behavior；按内容推断，避免导出时退化成 classical。 */
  ruleSetBehavior?: string
}

export function RuleLibraryDialog({
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
        ruleSetBehavior: format === 'yaml' ? inferRuleSetBehavior(rules) : undefined,
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

