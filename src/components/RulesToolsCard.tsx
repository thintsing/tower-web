// 规则页的三个诊断工具：命中解释、方案 lint、规则集版本对比。
// 弹层只用页面内联面板，不新增浮层菜单，避免遮挡/贴底问题。
import { useEffect, useMemo, useState } from 'react'
import type { LocalRuleSet, ProxyNode, RuleScheme } from '../models/types'
import { compileScheme, explainWith, type ExplainResult, type ExplainedStep } from '../rules/ruleExplain'
import { lintScheme, lintSummary, type LintLevel, type SchemeLintIssue } from '../rules/schemeLint'
import { diffRules, diffTotal, filterDiff, type DiffKind, type RuleDiffResult } from '../rules/ruleDiff'
import { clearRuleSetHistory, readRuleSetHistory } from '../rules/ruleSetHistory'
import { groupDisplayName } from './GroupIcon'

type ToolKey = 'explain' | 'lint' | 'diff'

const LEVEL_TITLES: Record<LintLevel, string> = { error: '错误', warn: '警告', info: '提示' }

const STATUS_TITLES: Record<ExplainedStep['evaluation']['status'], string> = {
  match: '命中',
  miss: '未命中',
  skip: '跳过',
  unknown: '无法判定',
}

function originLabel(step: ExplainedStep): string {
  const kind: Record<string, string> = {
    custom: '自定义',
    scheme: '方案',
    local: '本地规则集',
    url: '在线规则集',
    library: '内置规则库',
  }
  return `${kind[step.origin.kind] ?? '规则'} · ${step.origin.source}`
}

function formatTime(value?: number): string {
  if (!value) return '—'
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function ruleLine(rule: { type?: string; value?: string; raw?: string }): string {
  if (rule.raw) return rule.raw
  return `${rule.type ?? ''}${rule.value ? `,${rule.value}` : ''}`
}

/** 输入可能高达上万个字符，表格里只展示开头，避免把整段文本塞进 DOM。 */
function displayInput(value: string, limit = 120): string {
  return value.length > limit ? `${value.slice(0, limit)}…（共 ${value.length} 字符）` : value
}

function ExplainPanel({
  scheme,
  nodes,
  policySelections,
  latencyByNodeId,
  localRuleSets,
  showGroupEmoji,
}: {
  scheme: RuleScheme
  nodes: ProxyNode[]
  policySelections: Record<string, string>
  latencyByNodeId: Record<string, number | null>
  localRuleSets: LocalRuleSet[]
  showGroupEmoji: boolean
}) {
  const [input, setInput] = useState('www.google.com\nhttps://www.youtube.com/watch?v=1\n1.1.1.1\n[2606:4700:4700::1111]:443')
  const [results, setResults] = useState<ExplainResult[]>([])
  const [selected, setSelected] = useState(0)
  const [showAll, setShowAll] = useState(false)
  const [error, setError] = useState('')

  const compiled = useMemo(
    () => compileScheme({ scheme, nodes, policySelections, latencyByNodeId, localRuleSets }),
    [scheme, nodes, policySelections, latencyByNodeId, localRuleSets],
  )
  const compiledKey = `${scheme.id}|${scheme.updatedAt ?? 0}|${nodes.length}|${localRuleSets.map((set) => `${set.id}:${set.paused ? 1 : 0}`).join(',')}`

  useEffect(() => {
    setResults([])
    setSelected(0)
    setError('')
  }, [compiledKey])

  const run = () => {
    const lines = input.split('\n').map((line) => line.trim()).filter(Boolean)
    if (!lines.length) {
      setError('先输入至少一个域名、URL 或 IP')
      return
    }
    if (lines.length > 50) {
      setError('一次最多解释 50 行，请拆开查询')
      return
    }
    setError('')
    setSelected(0)
    setShowAll(false)
    // 5000+ 条规则时 50 行同步解释会阻塞主线程 0.3~0.5s，这里分帧计算并逐步展示。
    const compiledNow = compiled
    const first = explainWith(compiledNow, lines[0])
    setResults([first])
    let cursor = 1
    const step = () => {
      const batch: ExplainResult[] = []
      const end = Math.min(cursor + 5, lines.length)
      for (; cursor < end; cursor += 1) batch.push(explainWith(compiledNow, lines[cursor]))
      if (batch.length) setResults((previous) => [...previous, ...batch])
      if (cursor < lines.length) window.setTimeout(step, 0)
    }
    if (cursor < lines.length) window.setTimeout(step, 0)
  }

  const current = results[selected]
  const steps = current?.steps ?? []
  const stepLimit = 300
  const visibleSteps = showAll || steps.length <= stepLimit
    ? steps
    : [...steps.slice(0, 150), ...steps.slice(-150)]
  const omitted = showAll || steps.length <= stepLimit ? 0 : steps.length - 300

  return (
    <div className="rt-panel">
      <div className="rt-hint">
        解释器直接复用导出管线的规则顺序和策略组解析。导出时会按目标客户端过滤它不支持的规则，这里按完整规则集解释，个别客户端可能略有差异。域名不会解析成 IP，因此 IP-CIDR / GEOIP / IP-ASN 等 IP 规则对域名输入会标记「跳过」；IP 输入只内置中国大陆 IPv4 的 GEOIP 判断。UA / 进程规则在浏览器里无法确定，同样标记「跳过」而不是假装未命中。
      </div>
      <div className="rt-field">
        <textarea
          className="input rt-textarea"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="每行一个：example.com / https://example.com/path / 1.2.3.4 / 1.2.3.4:443 / [::1]:8080"
          aria-label="待解释的请求输入"
        />
        <div className="rt-actions">
          <button className="btn" onClick={run}>解释命中</button>
          <span className="rt-meta">已加载 {compiled.scheme.rules.length} 条规则 · 最多 50 行</span>
        </div>
      </div>
      {error && <div className="form-error" role="alert">{error}</div>}
      {results.length > 0 && (
        <>
          <div className="rt-table-wrap">
            <table className="rt-table">
              <thead>
                <tr>
                  <th>输入</th>
                  <th>命中规则</th>
                  <th>策略组</th>
                  <th>节点</th>
                  <th>兜底</th>
                </tr>
              </thead>
              <tbody>
                {results.map((result, index) => (
                  <tr
                    key={`${result.target.raw}-${index}`}
                    className={index === selected ? 'is-selected' : ''}
                    tabIndex={0}
                    role="button"
                    aria-pressed={index === selected}
                    aria-label={`查看 ${displayInput(result.target.raw)} 的判定链路`}
                    onClick={() => { setSelected(index); setShowAll(false) }}
                    onKeyDown={(event) => {
                      if (event.key !== 'Enter' && event.key !== ' ') return
                      event.preventDefault()
                      setSelected(index)
                      setShowAll(false)
                    }}
                  >
                    <td className="mono" title={result.target.raw}>{displayInput(result.target.raw)}</td>
                    <td className="mono">
                      {result.match
                        ? `#${result.match.index} ${ruleLine(result.match.rule)}`
                        : result.target.kind === 'unknown'
                          ? '输入无法解析'
                          : '无命中 / 无兜底'}
                    </td>
                    <td>{result.final.group ? groupDisplayName(result.final.group, showGroupEmoji) : '—'}</td>
                    <td>{result.final.node ?? '—'}</td>
                    <td>{result.final.isFallback ? '是' : '否'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="rt-summary">
            {current.match ? (
              <>
                <strong>{current.final.isFallback ? '兜底命中' : '命中'}</strong>
                <span>第 {current.match.index} / {current.totalRules} 条 · {current.match.evaluation.matchType}</span>
                <span>策略组 {current.final.group ? groupDisplayName(current.final.group, showGroupEmoji) : '—'}{current.final.groupType ? `（${current.final.groupType}）` : ''}</span>
                <span>候选节点 {current.final.candidates}</span>
                {current.final.node && <span>预计走 <b className="mono">{current.final.node}</b></span>}
              </>
            ) : (
              <>
                <strong className="is-error">{current.target.kind === 'unknown' ? '输入无法解析' : '规则链耗尽'}</strong>
                <span>{current.final.note}</span>
              </>
            )}
          </div>
          {current.final.note && current.match && <div className="rt-hint">{current.final.note}</div>}
          {current.notes.length > 0 && (
            <ul className="rt-notes">
              {current.notes.map((note) => <li key={note}>{note}</li>)}
            </ul>
          )}

          <div className="rt-chain-head">
            <strong>判定链路</strong>
            <span className="rt-meta">共 {steps.length} 条 · first-match 在{current.match ? `第 ${current.match.index} 条` : '未触发'}</span>
            {omitted > 0 && !showAll && (
              <button className="btn ghost" onClick={() => setShowAll(true)}>显示全部 {steps.length} 条</button>
            )}
          </div>
          <div className="rt-chain">
            {visibleSteps.map((step, index) => {
              const skippedGap = omitted > 0 && !showAll && index === 150
              return (
                <div key={`${step.index}-${index}`}>
                  {skippedGap && <div className="rt-gap">…省略中间 {omitted} 条未命中规则…</div>}
                  <div className={`rt-step is-${step.evaluation.status}${current.match?.index === step.index ? ' is-break' : ''}`}>
                    <span className="rt-step-no mono">{String(step.index).padStart(3, ' ')}</span>
                    <span className={`rt-status is-${step.evaluation.status}`}>{STATUS_TITLES[step.evaluation.status]}</span>
                    <span className="rt-step-rule mono">{ruleLine(step.rule)}</span>
                    <span className="rt-step-origin">{originLabel(step)}</span>
                    <span className="rt-step-type">{step.evaluation.matchType}</span>
                    <span className="rt-step-detail">{step.evaluation.detail ?? step.evaluation.reason ?? ''}</span>
                    {current.match?.index === step.index && <span className="rt-break">FIRST MATCH</span>}
                    {step.ruleSetNote && <span className="rt-step-note">{step.ruleSetNote}</span>}
                  </div>
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

function LintPanel({
  scheme,
  nodes,
  policySelections,
  preferRuleSets,
  localRuleSets,
  onLocate,
  onGoExport,
}: {
  scheme: RuleScheme
  nodes: ProxyNode[]
  policySelections: Record<string, string>
  preferRuleSets: boolean
  localRuleSets: LocalRuleSet[]
  onLocate: (issue: SchemeLintIssue) => void
  onGoExport: () => void
}) {
  const [issues, setIssues] = useState<SchemeLintIssue[]>([])
  const [linting, setLinting] = useState(false)
  const [level, setLevel] = useState<LintLevel | 'all'>('all')
  const [error, setError] = useState('')

  const schemeKey = `${scheme.id}|${scheme.updatedAt ?? 0}|${scheme.groups.length}|${scheme.rules.length}|${(scheme.ruleSets ?? []).length}`
  const nodeKey = nodes.map((node) => node.id).join(',')
  const ruleSetKey = localRuleSets.map((set) => `${set.id}:${set.rules.length}:${set.paused ? 1 : 0}`).join(',')

  useEffect(() => {
    let cancelled = false
    setLinting(true)
    setError('')
    const timer = window.setTimeout(() => {
      try {
        const next = lintScheme({ scheme, nodes, policySelections, localRuleSets, preferRuleSets })
        if (!cancelled) setIssues(next)
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e))
      } finally {
        if (!cancelled) setLinting(false)
      }
    }, 120)
    return () => { cancelled = true; window.clearTimeout(timer) }
  }, [scheme, nodes, policySelections, preferRuleSets, localRuleSets, schemeKey, nodeKey, ruleSetKey])

  const summary = lintSummary(issues)
  const visible = issues.filter((issue) => level === 'all' || issue.level === level).slice(0, 300)
  const filteredTotal = issues.filter((issue) => level === 'all' || issue.level === level).length

  return (
    <div className="rt-panel">
      <div className="rt-hint">
        检查默认只提示、不阻断导出；error 也能在导出页选择「仍然导出」。规则序号和实际导出顺序一致。
      </div>
      <div className="rt-actions">
        <div className="rt-filter">
          {(['all', 'error', 'warn', 'info'] as const).map((item) => (
            <button
              key={item}
              className={`rt-chip${level === item ? ' is-active' : ''} is-${item}`}
              onClick={() => setLevel(item)}
            >
              {item === 'all' ? `全部 ${summary.total}` : `${LEVEL_TITLES[item]} ${summary[item]}`}
            </button>
          ))}
        </div>
        <button className="btn ghost" onClick={onGoExport}>去导出页查看兼容性</button>
      </div>
      {linting && <div className="rt-meta">正在检查…</div>}
      {error && <div className="form-error" role="alert">{error}</div>}
      {!linting && issues.length === 0 && <div className="rt-empty">没有发现问题。方案里的规则顺序、策略组和导出兼容性都通过了检查。</div>}
      {visible.length > 0 && (
        <ul className="rt-issues">
          {visible.map((issue) => (
            <li key={issue.id} className={`rt-issue is-${issue.level}`}>
              <span className={`rt-level is-${issue.level}`}>{LEVEL_TITLES[issue.level]}</span>
              <div className="rt-issue-body">
                <div>{issue.message}</div>
                {issue.hint && <small>{issue.hint}</small>}
                <div className="rt-issue-loc">
                  {issue.location.kind === 'rule' && `第 ${(issue.location.ruleIndex ?? 0) + 1} 条规则`}
                  {issue.location.kind === 'group' && `策略组「${issue.location.group ?? ''}」`}
                  {issue.location.kind === 'ruleSet' && `规则集「${issue.location.ruleSet ?? ''}」`}
                  {issue.location.kind === 'target' && `导出目标 ${issue.location.target ?? ''}`}
                  {issue.location.rule && <code>{issue.location.rule}</code>}
                </div>
              </div>
              <button className="btn ghost" onClick={() => onLocate(issue)}>
                {issue.location.kind === 'target' ? '查看导出页' : '定位'}
              </button>
            </li>
          ))}
        </ul>
      )}
      {filteredTotal > visible.length && (
        <div className="rt-meta">仅显示前 {visible.length} 条，共 {filteredTotal} 条。</div>
      )}
    </div>
  )
}

function DiffLines({ result, filter, limit = 500 }: { result: RuleDiffResult; filter: DiffKind | 'all'; limit?: number }) {
  const lines = filterDiff(result, filter).slice(0, limit)
  if (!lines.length) return <div className="rt-empty">这一类没有变化。</div>
  return (
    <div className="rt-diff">
      {lines.map((line, index) => (
        <div key={`${line.kind}-${line.identity}-${index}`} className={`rt-diff-row is-${line.kind}`}>
          <span className="rt-diff-sign">{line.kind === 'added' ? '+' : line.kind === 'removed' ? '−' : '~'}</span>
          <div className="rt-diff-body">
            {line.kind === 'modified' ? (
              <>
                <code className="rt-before">{ruleLine(line.before ?? {})}</code>
                <span className="rt-arrow">→</span>
                <code className="rt-after">{ruleLine(line.after ?? {})}</code>
              </>
            ) : (
              <code>{line.text}</code>
            )}
          </div>
        </div>
      ))}
      {filterDiff(result, filter).length > limit && (
        <div className="rt-meta">仅显示前 {limit} 条。</div>
      )}
    </div>
  )
}

function DiffPanel({
  localRuleSets,
  versionHistoryEnabled,
  revision,
  onRevision,
}: {
  localRuleSets: LocalRuleSet[]
  versionHistoryEnabled: boolean
  revision: number
  onRevision: () => void
}) {
  const withUrls = localRuleSets
  const [mode, setMode] = useState<'history' | 'sets'>('history')
  const history = useMemo(() => readRuleSetHistory(), [localRuleSets, revision])
  const historySets = withUrls.filter((set) => history[set.id]?.previous)
  const historyKeyCount = Object.keys(history).length
  const orphanHistoryCount = historyKeyCount - historySets.length
  const [historySetID, setHistorySetID] = useState('')
  const [leftID, setLeftID] = useState('')
  const [rightID, setRightID] = useState('')
  const [filter, setFilter] = useState<DiffKind | 'all'>('all')

  useEffect(() => {
    if (!historySets.some((set) => set.id === historySetID)) {
      setHistorySetID(historySets[0]?.id ?? '')
    }
  }, [historySets, historySetID])

  useEffect(() => {
    if (!withUrls.some((set) => set.id === leftID)) setLeftID(withUrls[0]?.id ?? '')
    const fallbackRight = withUrls.find((set) => set.id !== leftID)?.id ?? withUrls[0]?.id ?? ''
    if (!withUrls.some((set) => set.id === rightID) || rightID === leftID) setRightID(fallbackRight)
  }, [withUrls, leftID, rightID])

  const historySet = historySets.find((set) => set.id === historySetID)
  const snapshot = historySet ? history[historySet.id]?.previous : undefined
  const result = useMemo(() => {
    if (mode === 'history') {
      if (!historySet || !snapshot?.rules) return null
      return diffRules(snapshot.rules, historySet.rules)
    }
    const left = withUrls.find((set) => set.id === leftID)
    const right = withUrls.find((set) => set.id === rightID)
    if (!left || !right) return null
    return diffRules(left.rules, right.rules)
  }, [mode, historySet, snapshot, withUrls, leftID, rightID])

  const total = result ? diffTotal(result) : 0

  return (
    <div className="rt-panel">
      <div className="rt-hint">
        对比前会按规则文本稳定排序，顺序变化不会产生噪音。历史只保留最近一次刷新前的快照，超大数据集只保留摘要。
        {!versionHistoryEnabled && ' 版本历史已在订阅设置里关闭，新的刷新不会记录。'}
      </div>
      <div className="rt-actions">
        <div className="rt-filter">
          <button className={`rt-chip${mode === 'history' ? ' is-active' : ''}`} onClick={() => setMode('history')}>刷新前后</button>
          <button className={`rt-chip${mode === 'sets' ? ' is-active' : ''}`} onClick={() => setMode('sets')}>两个本地规则集</button>
        </div>
        {mode === 'history' && historySets.length > 0 && (
          <button
            className="btn ghost"
            onClick={() => {
              if (!window.confirm('清除该规则集保存的上一版快照？')) return
              clearRuleSetHistory(historySet?.id)
              onRevision()
            }}
          >
            清除该历史
          </button>
        )}
        {mode === 'history' && historyKeyCount > 0 && (
          <button
            className="btn ghost"
            onClick={() => {
              if (!window.confirm('清除所有规则集保存的历史快照？')) return
              clearRuleSetHistory()
              onRevision()
            }}
          >
            清除全部历史{orphanHistoryCount > 0 ? `（含 ${orphanHistoryCount} 个已删除规则集）` : ''}
          </button>
        )}
      </div>

      {mode === 'history' ? (
        historySets.length === 0 ? (
          <div className="rt-empty">还没有刷新历史。到「我的规则集」手动或自动刷新一次后，这里会显示刷新前后的差异。</div>
        ) : (
          <div className="rt-diff-config">
            <label>
              规则集
              <select className="input" value={historySetID} onChange={(e) => setHistorySetID(e.target.value)}>
                {historySets.map((set) => <option key={set.id} value={set.id}>{set.name}</option>)}
              </select>
            </label>
            {historySet && snapshot && (
              <span className="rt-meta">
                上一版 {snapshot.count} 条 · {formatTime(snapshot.at)} → 当前 {historySet.rules.length} 条 · {formatTime(historySet.updatedAt)}
              </span>
            )}
          </div>
        )
      ) : (
        <div className="rt-diff-config">
          <label>
            规则集 A
            <select className="input" value={leftID} onChange={(e) => setLeftID(e.target.value)}>
              {withUrls.map((set) => <option key={set.id} value={set.id}>{set.name}（{set.rules.length} 条）</option>)}
            </select>
          </label>
          <label>
            规则集 B
            <select className="input" value={rightID} onChange={(e) => setRightID(e.target.value)}>
              {withUrls.map((set) => <option key={set.id} value={set.id}>{set.name}（{set.rules.length} 条）</option>)}
            </select>
          </label>
        </div>
      )}

      {mode === 'history' && snapshot?.truncated && (
        <div className="rt-hint">这个规则集太大，只保留了摘要（{snapshot.count} 条 / {snapshot.digest}），无法做逐行对比。</div>
      )}

      {result && (
        <>
          <div className="rt-diff-summary">
            <span className="is-added">+{result.added.length} 新增</span>
            <span className="is-removed">−{result.removed.length} 删除</span>
            <span className="is-modified">~{result.modified.length} 修改</span>
            <span>{result.unchanged} 条未变</span>
            <span>总计 {total} 处变化</span>
          </div>
          <div className="rt-filter">
            {(['all', 'added', 'removed', 'modified'] as const).map((kind) => (
              <button
                key={kind}
                className={`rt-chip${filter === kind ? ' is-active' : ''}`}
                onClick={() => setFilter(kind)}
              >
                {kind === 'all' ? `全部 ${total}` : kind === 'added' ? `只看新增 ${result.added.length}` : kind === 'removed' ? `只看删除 ${result.removed.length}` : `只看修改 ${result.modified.length}`}
              </button>
            ))}
          </div>
          <DiffLines result={result} filter={filter} />
        </>
      )}
      {!result && mode === 'sets' && <div className="rt-empty">至少需要两个本地规则集才能对比，或换一组选择。</div>}
    </div>
  )
}

export function RulesToolsCard({
  scheme,
  nodes,
  policySelections,
  latencyByNodeId,
  localRuleSets,
  preferRuleSets,
  showGroupEmoji,
  versionHistoryEnabled,
  onLocate,
  onGoExport,
}: {
  scheme?: RuleScheme
  nodes: ProxyNode[]
  policySelections: Record<string, string>
  latencyByNodeId: Record<string, number | null>
  localRuleSets: LocalRuleSet[]
  preferRuleSets: boolean
  showGroupEmoji: boolean
  versionHistoryEnabled: boolean
  onLocate: (issue: SchemeLintIssue) => void
  onGoExport: () => void
}) {
  const [tool, setTool] = useState<ToolKey>('explain')
  const [revision, setRevision] = useState(0)

  if (!scheme) {
    return (
      <div className="card">
        <div className="card-head">
          <h3 style={{ margin: 0 }}>规则工具</h3>
        </div>
        <div className="rt-empty">规则方案还没加载完成。</div>
      </div>
    )
  }

  return (
    <div className="card rules-tools">
      <div className="card-head">
        <div>
          <h3 style={{ margin: 0 }}>规则工具</h3>
          <div className="meta" style={{ margin: 0 }}>命中解释 · 方案检查 · 版本对比</div>
        </div>
        <div className="rt-tabs">
          <button className={`rt-tab${tool === 'explain' ? ' is-active' : ''}`} onClick={() => setTool('explain')}>命中解释</button>
          <button className={`rt-tab${tool === 'lint' ? ' is-active' : ''}`} onClick={() => setTool('lint')}>方案检查</button>
          <button className={`rt-tab${tool === 'diff' ? ' is-active' : ''}`} onClick={() => setTool('diff')}>版本对比</button>
        </div>
      </div>
      {tool === 'explain' && (
        <ExplainPanel
          scheme={scheme}
          nodes={nodes}
          policySelections={policySelections}
          latencyByNodeId={latencyByNodeId}
          localRuleSets={localRuleSets}
          showGroupEmoji={showGroupEmoji}
        />
      )}
      {tool === 'lint' && (
        <LintPanel
          scheme={scheme}
          nodes={nodes}
          policySelections={policySelections}
          preferRuleSets={preferRuleSets}
          localRuleSets={localRuleSets}
          onLocate={onLocate}
          onGoExport={onGoExport}
        />
      )}
      {tool === 'diff' && (
        <DiffPanel
          localRuleSets={localRuleSets}
          versionHistoryEnabled={versionHistoryEnabled}
          revision={revision}
          onRevision={() => setRevision((value) => value + 1)}
        />
      )}
    </div>
  )
}
