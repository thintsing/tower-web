// 规则集弹窗：本地规则集编辑 / 在线规则集导入 / 刷新差异 / 重命名与加入方案。
import { useEffect, useRef, useState } from 'react'
import type {
  LocalRuleSet,
  RuleScheme,
  RuleSetFormat,
  RuleSetRefreshDiff,
} from '../../models/types'
import { parseRuleList } from '../../rules/scheme'
import {
  describeRuleSetParse,
  fetchRuleSet,
  inferRuleSetBehavior,
  parseRuleSetText,
  RULE_SET_FORMAT_TITLES,
  type RuleSetRule,
} from '../../rules/ruleSets'
import { newID } from '../../util/browser'
import { formatDate } from '../../util/formatDate'
import {
  MAX_REMOTE_RULE_SET_URLS,
  remoteRuleSetNameFromURL,
  splitRemoteTextURLs,
} from '../../util/remoteURL'
import { READONLY_NOTE, writeGuard } from '../../util/readOnlyUi'
import { useWorkspaceStatus } from '../../workspaceSync'
import { groupDisplayName } from '../GroupIcon'

export function ruleSetLine(rule: RuleSetRule): string {
  if (rule.type === 'FINAL') return 'FINAL'
  if (rule.raw) return rule.raw
  const options = rule.options?.length
    ? [...rule.options]
    : rule.noResolve ? ['no-resolve'] : []
  return [rule.type, rule.value ?? '', ...options].join(',')
}

export function RuleSetEditorDialog({
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

export function RemoteRuleSetDialog({
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

export function RuleSetDiffView({ diff, stale = false }: { diff: RuleSetRefreshDiff; stale?: boolean }) {
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

export function RenameRuleSetDialog({
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

export function AddRuleSetToSchemeDialog({
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

