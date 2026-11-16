// 规则配置页：方案切换、策略组、自定义规则、逐条顺序与规则集。
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  type LocalRuleSet,
  type PolicyGroup,
  type ProxyNode,
  type RoutingRule,
  type RuleScheme,
  type RuleSetFormat,
  type RuleSetRefreshDiff,
  type SchemeRuleSet,
} from '../models/types'
import type { TabKey } from '../models/navigation'
import {
  DNS_MODE_SUMMARIES,
  DNS_MODE_TITLES,
  NetworkSettingsError,
  networkSettingsDraft,
  validateNetworkSettingsDraft,
  type NetworkSettingsDraft,
} from '../models/networkSettings'
import { enabledNodes, useStore } from '../store'
import { flushWorkspaceNow, useWorkspaceStatus } from '../workspaceSync'
import { useScheme } from '../rules/useScheme'
import { isLoopbackHost, useNetworkInfo } from '../util/networkInfo'
import { resolveHostedBaseURL } from '../rules/remoteFormats'
import { apiFetch } from '../util/apiAuth'
import { newID } from '../util/browser'
import { formatDate } from '../util/formatDate'
import { schemeDisplayName } from '../util/exportSelection'
import {
  MAX_REMOTE_RULE_SET_URLS,
  normalizeRemoteTextURL,
  remoteRuleSetNameFromURL,
  splitRemoteTextURLs,
} from '../util/remoteURL'
import { READONLY_NOTE, writeGuard } from '../util/readOnlyUi'
import { fetchUpstreamStatus, triggerUpstreamStatusCheck, type UpstreamStatusPayload } from '../upstreamStatus'
import { BUILTIN_SCHEMES, allSchemeMetas, loadScheme, parseRuleList, type SchemeMeta } from '../rules/scheme'
import {
  planBuiltinSchemeFreeze,
  planSnapshotRollback,
  resolveBuiltinSchemeSnapshot,
  snapshotsForScheme,
  type BuiltinSchemeFreezePlan,
  type SnapshotRollbackPlan,
} from '../rules/schemeSnapshots'
import { fetchUpstreamScheme, type UpstreamSchemeResult } from '../rules/upstreamScheme'
import { ruleSetRefreshFailure, ruleSetRefreshSuccess, sumRuleSetDiffs } from '../rules/ruleSetRefresh'
import { detectRuleSchemeFormat, parseRuleSchemeText, RULE_SCHEME_FORMAT_TITLES } from '../rules/importers'
import {
  describeRuleSetParse,
  fetchRuleSet,
  inferRuleSetBehavior,
  parseRuleSetText,
  RULE_SET_FORMAT_TITLES,
  type RuleSetRule,
} from '../rules/ruleSets'
import { matchingGroupNames, matchingOrderAfterDragging } from '../rules/matchingOrder'
import { findRuleOrderConflicts, type RuleOrderConflict } from '../rules/orderConflicts'
import { policyIssueText, validateSchemePolicy } from '../rules/policyValidation'
import {
  orderedSchemeBaseRules,
  orderedSchemeRules,
  isUnmovableRule,
  renameRuleOrderKeys,
  ruleOrderKeys,
  ruleSetRanksBeforeSchemeRules,
} from '../rules/ruleOrder'
import { analyzeRuleImpact, ruleImpactText } from '../rules/ruleImpact'
import {
  autoGroupReferenceWarning,
  buildNodeFilterGroup,
  findGroupCyclePath,
  nextGroupName,
  previewNodeMatches,
  removePolicyGroup,
  validateGroupCandidates,
  validateNodeGroupDraft,
  type NodeGroupDraft,
} from '../rules/groupEditing'
import { ONLINE_RULE_CATALOG } from '../rules/ruleCatalog'
import {
  describeRemoteReferences,
  groupEditorRuleSummary,
  groupRuleSummary,
  remoteReferenceCount,
  remoteReferenceCounts,
  ruleSetSummary,
} from '../rules/ruleSetReferences'
import { countOrphanRuleSetExclusions, describeRuleSetRemovalImpact } from '../rules/ruleSetExclusions'
import { createEditableSchemeCopy, stripSchemeCustomSuffix } from '../rules/schemeCopy'
import type { SchemeLintIssue } from '../rules/schemeLint'
import { clearRuleSetHistory, digestRules, recordRuleSetSnapshot } from '../rules/ruleSetHistory'
import { autoFillGroupEmojis } from '../generator/groupIcons'
import { SELF_CONFIGURATION_NAME, SELF_CONFIGURATION_URL } from '../rules/selfConfiguration'
import { GroupIcon, groupDisplayName } from '../components/GroupIcon'
import { RuleOrderCard } from '../components/RuleOrderCard'
import { AdvancedSection } from '../components/AdvancedSection'
import { RulesToolsCard } from '../components/RulesToolsCard'
import { SchemeDriftNotice } from '../components/SchemeDriftNotice'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { FreezePreviewDialog } from '../components/FreezePreviewDialog'

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
  // providerOnly 规则集不在 rules 里；单独统计，避免组编辑器显示成 0。
  const groupRemoteRefCount = remoteReferenceCount(scheme, group.name)
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
    setRuleNotice(`已添加，默认排在方案规则之前；若同组已有更具体的规则，仍按具体度排序。${ruleImpactText(impact)}`)
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
          >规则 {totalGroupRules}{groupRemoteRefCount > 0 ? ` · 引用 ${groupRemoteRefCount}` : ''}</button>
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
              {groupEditorRuleSummary(groupCustomRules.length, groupRules.length, groupRemoteRefCount)}
              {groupRemoteRefCount > 0 ? ` ${describeRemoteReferences(groupRemoteRefCount)}` : ''}
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
                {ruleQuery
                  ? '没有匹配的规则'
                  : groupRemoteRefCount > 0
                    ? `方案没有直接写给这个组的规则；${describeRemoteReferences(groupRemoteRefCount)}`
                    : '方案里没有直接指向这个组的规则；它通常作为其他策略组的候选使用。'}
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
  /** provider YAML 的 behavior；按内容推断，避免导出时退化成 classical。 */
  ruleSetBehavior?: string
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
              ruleSetBehavior: parsed.format === 'yaml' ? inferRuleSetBehavior(parsed.rules) : undefined,
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

export function RulesTab({
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
  const net = useNetworkInfo()
  const hostedBaseURL = useMemo(
    () => resolveHostedBaseURL({
      providerOnly: (scheme?.ruleSets ?? []).some((set) => set.providerOnly),
      net,
      loopback: isLoopbackHost(),
      origin: window.location.origin,
    }),
    [net, scheme],
  )
  const nodes = useStore((s) => s.nodes)
  const sources = useStore((s) => s.sources)
  const customSchemes = useStore((s) => s.customSchemes)
  const addCustomScheme = useStore((s) => s.addCustomScheme)
  const removeCustomScheme = useStore((s) => s.removeCustomScheme)
  const localRuleSets = useStore((s) => s.localRuleSets)
  const ruleSetExclusions = useStore((s) => s.ruleSetExclusions)
  const addLocalRuleSet = useStore((s) => s.addLocalRuleSet)
  const removeLocalRuleSet = useStore((s) => s.removeLocalRuleSet)
  const clearOrphanRuleSetExclusions = useStore((s) => s.clearOrphanRuleSetExclusions)
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
  const [libraryOpen, setLibraryOpen] = useState(false)
  const [localSetEditor, setLocalSetEditor] = useState<{ set?: LocalRuleSet } | null>(null)
  const [localSetAddTarget, setLocalSetAddTarget] = useState<LocalRuleSet | null>(null)
  const [pendingLocalSetDelete, setPendingLocalSetDelete] = useState<LocalRuleSet | null>(null)
  const [pendingRuleSetRemove, setPendingRuleSetRemove] = useState<SchemeRuleSet | null>(null)
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
  // 屏蔽表按规则集 id 存；规则集被移除 / 方案被删后，旧记录会留在工作区。
  const orphanExclusionCount = useMemo(() => {
    const live = new Set<string>()
    for (const item of customSchemes) {
      for (const set of item.ruleSets ?? []) live.add(set.id)
    }
    for (const set of localRuleSets) live.add(set.id)
    for (const snapshot of Object.values(schemeSnapshots)) {
      for (const set of snapshot.ruleSets ?? []) live.add(set.id)
    }
    return countOrphanRuleSetExclusions(ruleSetExclusions, live)
  }, [customSchemes, localRuleSets, schemeSnapshots, ruleSetExclusions])
  const schemeRules = useMemo(
    () => scheme ? orderedSchemeRules(scheme) : [],
    [scheme],
  )
  // providerOnly 规则集不保存正文；按组统计远程引用，避免组行显示成 0 条规则。
  const remoteRefsByGroup = useMemo(() => remoteReferenceCounts(scheme), [scheme])
  const remoteRefTotal = useMemo(
    () => [...remoteRefsByGroup.values()].reduce((sum, count) => sum + count, 0),
    [remoteRefsByGroup],
  )
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
    if (result.removedRemoteReferences > 0) details.push(`${result.removedRemoteReferences} 条远程引用`)
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
   * 写入整份逐条顺序（上移 / 下移 / 置顶共用）；撤销槽按动作记录。
   */
  const commitRuleOrder = (editable: RuleScheme, next: RoutingRule[], moved: RoutingRule, action: string) => {
    setRuleOrderUndo({
      schemeID: editable.id,
      ruleOrder: editable.ruleOrder,
      label: `${moved.type} ${moved.value ?? ''}`.trim(),
    })
    addCustomScheme({ ...editable, ruleOrder: ruleOrderKeys(next), updatedAt: Date.now() })
    setFlash(`已${action}规则「${moved.type} ${moved.value ?? ''}」。`)
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
    commitRuleOrder(editable, next, moved, delta < 0 ? '上移' : '下移')
  }

  /** 置顶：移到当前兜底锚点之后的第一条，不越过 GEOIP / FINAL / MATCH。 */
  const pinRule = (source: RuleScheme, index: number) => {
    if (readOnly) return
    const editable = makeEditableScheme(source)
    const ordered = orderedSchemeRules(editable)
    if (index < 0 || index >= ordered.length || isUnmovableRule(ordered[index])) return
    // 目标位置是同一段（相邻兜底锚点之间）的第一条；跨不过锚点。
    let target = index
    for (let cursor = index - 1; cursor >= 0; cursor -= 1) {
      target = cursor
      if (isUnmovableRule(ordered[cursor])) {
        target = cursor + 1
        break
      }
    }
    if (target >= index) return
    const next = [...ordered]
    const [moved] = next.splice(index, 1)
    next.splice(target, 0, moved)
    commitRuleOrder(editable, next, moved, '置顶')
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
      ruleSetBehavior: payload.ruleSetBehavior
        ?? (payload.format === 'yaml' ? inferRuleSetBehavior(payload.rules) : undefined),
      updatedAt: Date.now(),
    }
    const ruleSets = existingIndex >= 0
      ? existing.map((set, index) => index === existingIndex ? snapshot : set)
      : [...existing, snapshot]
    const nextScheme = { ...editable, ruleSets, updatedAt: Date.now() }
    addCustomScheme(nextScheme)
    // 提示与真实顺序同源：用加入后的方案算出它是否真的排在方案规则之前。
    const preposed = ruleSetRanksBeforeSchemeRules(nextScheme, snapshot)
    const summary = existingIndex >= 0
      ? `已更新「${payload.name}」：${rules.length} 条规则仍然加入「${payload.group}」。`
      : `已把「${payload.name}」的 ${rules.length} 条规则加入「${payload.group}」。`
    setFlash(`${summary}${preposed ? '该规则集已排在方案规则之前，导出时优先匹配。' : ''}`)
  }

  const addLocalSetToScheme = (source: RuleScheme, set: LocalRuleSet, group: string) => {
    applyRuleSet(source, {
      name: set.name,
      group,
      rules: set.rules,
      sourceKind: set.sourceURL ? 'url' : 'local',
      sourceRef: set.sourceURL ?? set.id,
      format: set.sourceURL ? set.format : undefined,
      // 透传 provider behavior：漏掉会让 YAML 规则集在导出时退回 classical。
      ruleSetBehavior: set.ruleSetBehavior
        ?? (set.format === 'yaml' ? inferRuleSetBehavior(set.rules) : undefined),
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
      addLocalRuleSet({
        ...updated,
        format: parsed.format,
        ruleSetBehavior: parsed.format === 'yaml' ? inferRuleSetBehavior(parsed.rules) : undefined,
      })
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
        addLocalRuleSet({
          ...updated,
          format: parsed.format,
          ruleSetBehavior: parsed.format === 'yaml' ? inferRuleSetBehavior(parsed.rules) : undefined,
        })
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
          ruleSetBehavior: parsed.format === 'yaml' ? inferRuleSetBehavior(parsed.rules) : undefined,
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
      const updated = {
        ...ruleSetRefreshSuccess(set, rules),
        format: parsed.format,
        ruleSetBehavior: parsed.format === 'yaml' ? inferRuleSetBehavior(rules) : undefined,
      }
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
    const target = fresh?.ruleSets?.find((set) => set.id === id)
    if (target) setPendingRuleSetRemove(target)
  }

  const confirmRemoveSchemeRuleSet = () => {
    const target = pendingRuleSetRemove
    const fresh = customScheme
    setPendingRuleSetRemove(null)
    if (!target || !fresh?.ruleSets) return
    const blocked = ruleSetExclusions[target.id]?.length ?? 0
    addCustomScheme({
      ...fresh,
      ruleSets: fresh.ruleSets.filter((set) => set.id !== target.id),
      updatedAt: Date.now(),
    })
    // 屏蔽记录没有迁移目标；移除时一并删掉，避免旧 id 记录变成永久孤儿。
    if (blocked) useStore.getState().restoreRuleSetExclusions(target.id, [])
    setFlash(blocked
      ? `已从当前方案移除「${target.name}」；${blocked} 条屏蔽记录已一并失效。`
      : '已从当前方案移除规则集。')
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
          {remoteRefTotal > 0 && (
            <span title="只保存 provider 地址，不保存正文；导出时写成 RULE-SET，由客户端自行下载">
              <b>{remoteRefTotal}</b> 远程引用
            </span>
          )}
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
            const remoteRefCount = remoteRefsByGroup.get(g.name) ?? 0
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
                    {groupRuleSummary(ruleCount, customCount, remoteRefCount)}
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
                    查看规则
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
        <RuleOrderCard
          scheme={scheme}
          rules={schemeRules}
          readOnly={readOnly}
          showGroupEmoji={showGroupEmoji}
          undoLabel={ruleOrderUndo?.schemeID === scheme.id ? ruleOrderUndo.label : undefined}
          onPin={pinRule}
          onMove={moveRule}
          onUndo={undoRuleOrder}
        />
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
              {orphanExclusionCount > 0 && (
                <button
                  className="btn ghost"
                  title="所属规则集已不存在，这些屏蔽记录不会再影响任何配置"
                  {...writeGuard(readOnly)}
                  onClick={() => {
                    const removed = clearOrphanRuleSetExclusions()
                    setFlash(`已清理 ${removed} 条孤儿屏蔽记录（所属规则集已不存在）。`)
                  }}
                >
                  清理 {orphanExclusionCount} 条孤儿屏蔽
                </button>
              )}
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
                        {set.providerOnly && (
                          <span className="pill" title="只保存 provider 地址 / behavior / 间隔，不保存正文；导出 Clash 时写成 rule-providers + RULE-SET">
                            远程引用
                          </span>
                        )}
                        {blockedCount > 0 && (
                          <span className="pill warn" title="原始规则集与快照不变；只在编译与导出时排除">
                            已屏蔽 {blockedCount} 条 · 仅编译期生效
                          </span>
                        )}
                        <span className="hint">
                          {ruleSetSummary(set, set.format ? RULE_SET_FORMAT_TITLES[set.format] : undefined)}
                          {set.updatedAt ? ` · 更新于 ${formatDate(set.updatedAt)}` : ''}
                        </span>
                        {set.lastDiff && <RuleSetDiffView diff={set.lastDiff} />}
                      </div>
                      <div className="rs-actions">
                        {!set.inlined && !set.providerOnly && set.sourceKind === 'url' && (
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
          hostedBaseURL={hostedBaseURL}
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
              {(() => {
                // 与 removePolicyGroup 返回字段同源，避免确认框只数直接规则、
                // 把 providerOnly 远程引用显示成「移除 0 条」。
                const summary = removePolicyGroup(scheme, pendingGroupDelete.name)
                const details: string[] = []
                if (summary.removedRules > 0) details.push(`${summary.removedRules} 条规则`)
                if (summary.removedCustomRules > 0) details.push(`${summary.removedCustomRules} 条自定义规则`)
                if (summary.removedRuleSets > 0) details.push(`${summary.removedRuleSets} 组规则集`)
                if (summary.removedRemoteReferences > 0) details.push(`${summary.removedRemoteReferences} 条远程引用`)
                const referenced = summary.referencingGroups.map((name) => groupDisplayName(name, true))
                return (
                  <>
                    将删除 <b>「{pendingGroupDelete.name}」</b>
                    {details.length > 0 ? `，同时移除 ${details.join('、')}。` : '。'}
                    {referenced.length === 0
                      ? '其他策略组里的引用也会一并移除。'
                      : `候选里引用它的策略组：${referenced.join('、')}，这些候选会一并移除。`}
                  </>
                )
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
        open={!!pendingRuleSetRemove}
        title="从当前方案移除规则集？"
        body={(
          <>
            {pendingRuleSetRemove?.providerOnly ? (
              <>
                将移除 <b>「{pendingRuleSetRemove.name}」</b>的远程 provider 引用（不保存正文），
                方案里引用它的 RULE-SET 会一并删除。
              </>
            ) : (
              <>将移除 <b>「{pendingRuleSetRemove?.name}」</b>的 {pendingRuleSetRemove?.rules.length ?? 0} 条规则。</>
            )}
            {describeRuleSetRemovalImpact(pendingRuleSetRemove
              ? ruleSetExclusions[pendingRuleSetRemove.id]?.length ?? 0
              : 0)}
          </>
        )}
        confirmLabel="移除"
        danger
        confirmDisabled={readOnly}
        onCancel={() => setPendingRuleSetRemove(null)}
        onConfirm={confirmRemoveSchemeRuleSet}
      />
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
