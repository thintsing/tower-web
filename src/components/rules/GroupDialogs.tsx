// 策略组弹窗：候选选择、组详情（设置 / 规则）与新建策略组。
import { useEffect, useMemo, useRef, useState } from 'react'
import type { PolicyGroup, ProxyNode, RoutingRule, RuleScheme } from '../../models/types'
import {
  autoGroupReferenceWarning,
  buildNodeFilterGroup,
  findGroupCyclePath,
  nextGroupName,
  previewNodeMatches,
  validateGroupCandidates,
  validateNodeGroupDraft,
  type NodeGroupDraft,
} from '../../rules/groupEditing'
import { analyzeRuleImpact, ruleImpactText } from '../../rules/ruleImpact'
import {
  describeRemoteReferences,
  groupEditorRuleSummary,
  remoteReferenceCount,
} from '../../rules/ruleSetReferences'
import { READONLY_NOTE, writeGuard } from '../../util/readOnlyUi'
import { useWorkspaceStatus } from '../../workspaceSync'
import { groupDisplayName } from '../GroupIcon'

/** 显式候选选择区：策略组 / 内置策略 / 节点三块，共用给新建与编辑对话框。 */
export function GroupCandidatePicker({
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

export function GroupEditorDialog({
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

export function GroupCreateDialog({
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

