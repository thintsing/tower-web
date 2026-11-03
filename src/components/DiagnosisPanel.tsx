// 规则诊断：围绕「这条流量为什么走这里 · 有什么变化 · 导出会不会丢语义」的一条链路。
import { useEffect, useMemo, useState } from 'react'
import type { LocalRuleSet, ProxyNode, RuleScheme } from '../models/types'
import { compileScheme, explainWith, type ExplainedStep, type ExplainResult } from '../rules/ruleExplain'
import { lintScheme, lintSummary, type LintLevel, type SchemeLintIssue } from '../rules/schemeLint'
import {
  buildFixActions,
  describeRuleSetChange,
  findMatchedRuleSet,
  rankLintIssues,
  splitRanked,
  type FixAction,
  type RankedIssue,
} from '../rules/diagnosis'
import { readRuleSetHistory, type RuleSetHistory } from '../rules/ruleSetHistory'
import { groupDisplayName } from './GroupIcon'

const LEVEL_TITLES: Record<LintLevel, string> = { error: '错误', warn: '警告', info: '提示' }

const STATUS_TITLES: Record<ExplainedStep['evaluation']['status'], string> = {
  match: '命中',
  miss: '未命中',
  skip: '跳过',
  unknown: '无法判定',
}

const ORIGIN_KINDS: Record<string, string> = {
  custom: '自定义规则',
  scheme: '方案规则',
  local: '本地规则集',
  url: '在线规则集',
  library: '内置规则库',
}

function originLabel(step: ExplainedStep): string {
  const base = ORIGIN_KINDS[step.origin.kind] ?? '规则'
  return step.origin.setName ? `${base} · ${step.origin.setName}` : `${base} · ${step.origin.source}`
}

function ruleLine(rule: { type?: string; value?: string; raw?: string }): string {
  if (rule.raw) return rule.raw
  return `${rule.type ?? ''}${rule.value ? `,${rule.value}` : ''}`
}

const MATCHED_CHANGE_TEXT: Record<string, string> = {
  added: '这条命中规则是最近一次刷新新增的',
  removed: '这条命中规则已被最近的刷新删除',
  modified: '这条命中规则最近被修改过',
  unchanged: '这条命中规则在最近刷新中未变化',
  'not-found': '最近刷新没有覆盖到这条规则',
  'no-history': '没有可对比的刷新历史',
}

export interface FixOutcome {
  ok: boolean
  message: string
}

interface DiagnosisPanelProps {
  scheme?: RuleScheme
  nodes: ProxyNode[]
  policySelections: Record<string, string>
  latencyByNodeId: Record<string, number | null>
  localRuleSets: LocalRuleSet[]
  preferRuleSets: boolean
  showGroupEmoji: boolean
  versionHistoryEnabled: boolean
  historyRevision?: number
  onLocate: (issue: SchemeLintIssue) => void
  /** 由 App 负责把修改落到自定义方案；返回是否成功。 */
  onApplyFix: (action: FixAction) => FixOutcome
  onGo: (key: 'sub' | 'rules' | 'export') => void
}

export function DiagnosisPanel({
  scheme,
  nodes,
  policySelections,
  latencyByNodeId,
  localRuleSets,
  preferRuleSets,
  showGroupEmoji,
  versionHistoryEnabled,
  historyRevision = 0,
  onLocate,
  onApplyFix,
  onGo,
}: DiagnosisPanelProps) {
  const [input, setInput] = useState('www.google.com')
  const [submitted, setSubmitted] = useState('')
  const [baseline, setBaseline] = useState<ExplainResult | null>(null)
  const [baselineQuery, setBaselineQuery] = useState('')
  const [showAllChain, setShowAllChain] = useState(false)
  const [fixNote, setFixNote] = useState('')
  const [lastFix, setLastFix] = useState<{ code: string; ruleText?: string } | null>(null)
  const [error, setError] = useState('')

  const compiled = useMemo(
    () => (scheme
      ? compileScheme({ scheme, nodes, policySelections, latencyByNodeId, localRuleSets })
      : null),
    [scheme, nodes, policySelections, latencyByNodeId, localRuleSets],
  )

  const result = useMemo(() => {
    if (!compiled || !submitted) return null
    return explainWith(compiled, submitted)
  }, [compiled, submitted])

  // 诊断数据只在用户真正查询后才计算，避免首屏就把 5000 条规则的全部检查跑一遍。
  const lintState = useMemo(() => {
    if (!scheme || !result) return { issues: [] as SchemeLintIssue[], summary: { error: 0, warn: 0, info: 0, total: 0 } }
    const issues = lintScheme({ scheme, nodes, policySelections, localRuleSets, preferRuleSets })
    return { issues, summary: lintSummary(issues) }
  }, [scheme, result, nodes, policySelections, localRuleSets, preferRuleSets])

  const history = useMemo<RuleSetHistory>(
    () => (versionHistoryEnabled ? readRuleSetHistory() : {}),
    [versionHistoryEnabled, historyRevision, scheme?.id, scheme?.updatedAt],
  )

  const matchedSet = result && scheme ? findMatchedRuleSet(scheme, result.match?.rule) : undefined
  const change = result && scheme
    ? describeRuleSetChange(matchedSet, history, result.match?.rule)
    : undefined
  const pausedSource = matchedSet?.sourceRef
    ? localRuleSets.find((set) => set.id === matchedSet.sourceRef)
    : undefined

  const ranked = result && scheme
    ? rankLintIssues(lintState.issues, result, scheme)
    : []
  const { relevant, others } = splitRanked(ranked)

  useEffect(() => {
    setError('')
  }, [submitted])

  const run = () => {
    const value = input.trim()
    if (!value) {
      setError('先输入一个域名、URL 或 IP')
      return
    }
    if (value.split('\n').length > 1) {
      setError('诊断一次只看一条流量；多条解释请到「高级规则工具」里批量查询。')
      return
    }
    setError('')
    setBaseline(null)
    setLastFix(null)
    setFixNote('')
    setShowAllChain(false)
    setSubmitted(value)
  }

  const rerun = () => {
    setBaseline(null)
    setLastFix(null)
    setFixNote('')
    setSubmitted('')
    window.setTimeout(() => setSubmitted(input.trim()), 0)
  }

  const performFix = (issue: SchemeLintIssue, action: FixAction) => {
    if (!result) return
    const outcome = onApplyFix(action)
    if (!outcome.ok) {
      setFixNote(outcome.message)
      return
    }
    setBaseline(result)
    setBaselineQuery(submitted)
    setLastFix({ code: issue.code, ruleText: issue.location.rule })
    setFixNote(outcome.message)
  }

  const stillPresent = lastFix
    ? lintState.issues.some((issue) =>
        issue.code === lastFix.code
        && (!lastFix.ruleText || issue.location.rule === lastFix.ruleText))
    : false

  if (!scheme) {
    return <div className="rt-empty">规则方案还没加载完成，稍后再试。</div>
  }

  return (
    <div className="diag">
      <div className="diag-query card">
        <div className="diag-query-head">
          <div>
            <h3>查一条流量</h3>
            <p>输入域名、URL 或 IP，沿着完整规则链看它最终走到哪个策略组。</p>
          </div>
          <span className="diag-query-meta num">{compiled?.scheme.rules.length ?? 0} 条规则</span>
        </div>
        <div className="diag-query-row">
          <input
            className="input mono"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={(event) => { if (event.key === 'Enter') run() }}
            placeholder="example.com / https://example.com/path / 1.2.3.4 / [::1]:443"
            aria-label="要诊断的域名、URL 或 IP"
          />
          <button className="btn primary" onClick={run} disabled={nodes.length === 0}>运行诊断</button>
        </div>
        <div className="diag-honest">
          解释器按完整方案规则链计算；导出时会按目标客户端过滤它不支持的规则，所以这里的命中不等于客户端的最终行为。导出兼容性会在下面单独标出。
        </div>
        {nodes.length === 0 && (
          <div className="inline-notice error">
            <span>没有可用节点时无法解析策略组。先导入并启用节点，再运行诊断。</span>
            <button className="btn ghost" onClick={() => onGo('sub')}>去导入</button>
          </div>
        )}
        {error && <div className="form-error" role="alert">{error}</div>}
      </div>

      {result && (
        <>
          <section className="diag-section" aria-labelledby="diag-chain-title">
            <div className="diag-section-head">
              <span className="diag-step badge">01 查询</span>
              <h3 id="diag-chain-title">命中链路</h3>
              <span className="diag-meta">
                {result.match
                  ? `命中第 ${result.match.index} / ${result.totalRules} 条`
                  : result.target.kind === 'unknown'
                    ? '输入无法解析'
                    : '没有命中，走兜底或直连'}
              </span>
            </div>
            <div className="diag-verdict">
              {result.match ? (
                <>
                  <div className="diag-verdict-main">
                    <span className={`diag-pill is-${result.match.evaluation.status}`}>{STATUS_TITLES[result.match.evaluation.status]}</span>
                    <code className="diag-rule mono">{ruleLine(result.match.rule)}</code>
                  </div>
                  <div className="diag-verdict-grid">
                    <div><span>策略组</span><strong>{result.final.group ? groupDisplayName(result.final.group, showGroupEmoji) : '—'}</strong></div>
                    <div><span>组类型</span><strong>{result.final.groupType ?? '—'}</strong></div>
                    <div><span>候选节点</span><strong className="num">{result.final.candidates}</strong></div>
                    <div><span>预计节点</span><strong className="mono">{result.final.node ?? '—'}</strong></div>
                  </div>
                </>
              ) : (
                <div className="diag-verdict-empty">
                  <strong>{result.target.kind === 'unknown' ? '输入无法解析' : '规则链没有命中'}</strong>
                  <span>{result.final.note ?? '检查输入格式，或确认方案里存在兜底规则。'}</span>
                </div>
              )}
            </div>
            {result.notes.length > 0 && (
              <ul className="rt-notes">
                {result.notes.map((note) => <li key={note}>{note}</li>)}
              </ul>
            )}
            {result.steps.length > 0 && (
              <>
                <div className="diag-chain-head">
                  <span>最近 {showAllChain ? result.steps.length : Math.min(result.steps.length, 5)} 条判定</span>
                  <button className="btn ghost" onClick={() => setShowAllChain((value) => !value)}>
                    {showAllChain ? '只看最近 5 条' : '展开完整链路'}
                  </button>
                </div>
                <div className="rt-chain">
                  {(showAllChain ? result.steps : result.steps.slice(-5)).map((step, index) => (
                    <div
                      key={`${step.index}-${index}`}
                      className={`rt-step is-${step.evaluation.status}${result.match?.index === step.index ? ' is-break' : ''}`}
                    >
                      <span className="rt-step-no mono">{String(step.index).padStart(3, ' ')}</span>
                      <span className={`rt-status is-${step.evaluation.status}`}>{STATUS_TITLES[step.evaluation.status]}</span>
                      <span className="rt-step-rule mono">{ruleLine(step.rule)}</span>
                      <span className="rt-step-origin">{originLabel(step)}</span>
                      <span className="rt-step-detail">{step.evaluation.detail ?? step.evaluation.reason ?? ''}</span>
                      {result.match?.index === step.index && <span className="rt-break">FIRST MATCH</span>}
                    </div>
                  ))}
                </div>
              </>
            )}
          </section>

          <section className="diag-section" aria-labelledby="diag-context-title">
            <div className="diag-section-head">
              <span className="diag-step badge">02 上下文</span>
              <h3 id="diag-context-title">这条规则最近变过吗</h3>
            </div>
            {!matchedSet ? (
              <div className="diag-context-empty">
                <strong>命中来自方案内置规则或自定义规则</strong>
                <span>它不在任何规则集里，因此没有规则集刷新历史可对比。你可以直接在规则页查看它前后的规则。</span>
                <div className="diag-actions">
                  <button className="btn ghost" onClick={() => onGo('rules')}>去规则页查看</button>
                </div>
              </div>
            ) : (
              <div className="diag-context">
                <div className="diag-context-head">
                  <strong>{matchedSet.name}</strong>
                  <span className="diag-meta">{matchedSet.rules.length} 条 · {matchedSet.group}</span>
                </div>
                {matchedSet.rules.length === 0 && (
                  <div className="inline-notice error"><span>这个规则集是空的，不可能命中任何流量。</span></div>
                )}
                {pausedSource?.paused && (
                  <div className="inline-notice"><span>这个规则集的在线订阅已暂停自动刷新，当前使用的是上次快照。</span></div>
                )}
                {pausedSource?.lastError && (
                  <div className="inline-notice error"><span>最近一次刷新失败：{pausedSource.lastError}</span></div>
                )}
                {change && (
                  <>
                    {change.hasHistory && !change.truncated ? (
                      <>
                        <div className="diag-diff-summary">
                          <span className="is-added">+{change.added} 新增</span>
                          <span className="is-removed">−{change.removed} 删除</span>
                          <span className="is-modified">~{change.modified} 修改</span>
                          <span>{MATCHED_CHANGE_TEXT[change.matched]}</span>
                        </div>
                        {change.matched === 'removed' && (
                          <div className="inline-notice error"><span>提示：本次命中来自当前快照；如果你在旧版本上测试，结果可能不同。</span></div>
                        )}
                        {change.sample.length > 0 && (
                          <div className="diag-diff-sample">
                            {change.sample.map((line, index) => (
                              <div key={`${line.kind}-${line.identity}-${index}`} className={`rt-diff-row is-${line.kind}`}>
                                <span className="rt-diff-sign">{line.kind === 'added' ? '+' : line.kind === 'removed' ? '−' : '~'}</span>
                                <div className="rt-diff-body">
                                  {line.kind === 'modified' ? (
                                    <>
                                      <code className="rt-before">{ruleLine(line.before ?? {})}</code>
                                      <span className="rt-arrow">→</span>
                                      <code className="rt-after">{ruleLine(line.after ?? {})}</code>
                                    </>
                                  ) : <code>{line.text}</code>}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </>
                    ) : (
                      <div className="diag-context-empty">
                        <strong>{change.truncated ? '上次只保存了摘要' : '还没有刷新历史'}</strong>
                        <span>
                          {change.truncated
                            ? '这个规则集太大，历史只记录了规则数量与摘要，无法逐条对比。'
                            : '规则集在最近一次刷新时没有留下快照，或者版本历史已关闭。'}
                        </span>
                      </div>
                    )}
                  </>
                )}
                <div className="diag-actions">
                  <button
                    className="btn ghost"
                    onClick={() => onLocate({
                      id: `ctx:${matchedSet.id}`,
                      level: 'info',
                      code: 'context',
                      message: `打开规则集「${matchedSet.name}」`,
                      location: { kind: 'ruleSet', ruleSet: matchedSet.name, group: matchedSet.group },
                    })}
                  >
                    打开规则集
                  </button>
                  <span className="diag-meta">历史记录：{versionHistoryEnabled ? '已开启' : '已关闭'}</span>
                </div>
              </div>
            )}
          </section>

          <section className="diag-section" aria-labelledby="diag-risk-title">
            <div className="diag-section-head">
              <span className="diag-step badge">03 风险</span>
              <h3 id="diag-risk-title">和这次判定相关的检查项</h3>
              <span className="diag-meta">
                {lintState.summary.error} error · {lintState.summary.warn} warn · {lintState.summary.info} info
              </span>
            </div>
            {relevant.length === 0 ? (
              <div className="diag-context-empty">
                <strong>没有和这条流量直接相关的发现</strong>
                <span>方案整体还有 {others.length} 条检查项，它们在这次判定链路之外。需要时可以展开查看。</span>
              </div>
            ) : (
              <ul className="diag-issues">
                {relevant.slice(0, 8).map((item) => (
                  <IssueCard
                    key={item.issue.id}
                    item={item}
                    onApplyFix={performFix}
                    onLocate={onLocate}
                    onGo={onGo}
                  />
                ))}
              </ul>
            )}
            {relevant.length > 8 && (
              <div className="diag-meta">还有 {relevant.length - 8} 条相关内容，建议先修完上面的高相关项。</div>
            )}
            {others.length > 0 && (
              <details className="diag-others">
                <summary>其他 {others.length} 条与这次查询无关的检查项</summary>
                <ul className="diag-issues">
                  {others.slice(0, 30).map((item) => (
                    <IssueCard
                      key={item.issue.id}
                      item={item}
                      onApplyFix={performFix}
                      onLocate={onLocate}
                      onGo={onGo}
                    />
                  ))}
                </ul>
                {others.length > 30 && <div className="diag-meta">仅显示前 30 条。</div>}
              </details>
            )}
          </section>

          <section className="diag-section" aria-labelledby="diag-verify-title">
            <div className="diag-section-head">
              <span className="diag-step badge">04 验证</span>
              <h3 id="diag-verify-title">修完再跑一次</h3>
            </div>
            {baseline ? (
              <div className="diag-verify">
                <div className="diag-verify-grid">
                  <div>
                    <span>修复前</span>
                    <strong>{baseline.match ? `#${baseline.match.index} · ${ruleLine(baseline.match.rule)}` : '无命中'}</strong>
                    <small>{baseline.final.group ? groupDisplayName(baseline.final.group, showGroupEmoji) : '—'} · {baseline.final.node ?? '—'}</small>
                  </div>
                  <div className="diag-verify-arrow" aria-hidden="true">→</div>
                  <div>
                    <span>修复后（自动重跑「{baselineQuery}」）</span>
                    <strong>{result.match ? `#${result.match.index} · ${ruleLine(result.match.rule)}` : '无命中'}</strong>
                    <small>{result.final.group ? groupDisplayName(result.final.group, showGroupEmoji) : '—'} · {result.final.node ?? '—'}</small>
                  </div>
                </div>
                <div className={`diag-verify-note${stillPresent ? ' is-warn' : ''}`}>
                  {stillPresent
                    ? '同类检查项仍然存在：可能还有第二条相同问题，或修复没有落到当前方案。'
                    : baseline.final.group === result.final.group && baseline.final.node === result.final.node
                      ? `匹配结果没有变化：仍然走「${result.final.group ? groupDisplayName(result.final.group, showGroupEmoji) : '—'}」${result.final.node ? ` · ${result.final.node}` : ''}。${
                        baseline.match && result.match && baseline.match.index !== result.match.index
                          ? '规则序号的变化来自规则集插入位置调整，不是分流改变。'
                          : '删除的是不影响判定的规则，符合预期。'
                      }`
                      : `命中结果已改变：现在走「${result.final.group ? groupDisplayName(result.final.group, showGroupEmoji) : '—'}」。如果这不是预期，请撤销或重新检查规则顺序。`}
                </div>
                <div className="diag-actions">
                  <button className="btn ghost" onClick={rerun}>重新运行同一条查询</button>
                  <button className="btn ghost" onClick={() => onGo('export')}>去导出页确认客户端行为</button>
                </div>
              </div>
            ) : (
              <div className="diag-context-empty">
                <strong>还没有执行过修复</strong>
                <span>在上面的风险里点一个可以一键执行的修复动作，这里会保留修复前后的对照。</span>
                {fixNote && <span className="diag-fix-note">{fixNote}</span>}
              </div>
            )}
          </section>
        </>
      )}

      {!result && (
        <div className="diag-empty">
          <strong>还没有诊断结果</strong>
          <span>输入一条域名或 IP 并运行，就能同时看到命中链路、规则集变更、相关风险和修复动作。</span>
        </div>
      )}
    </div>
  )
}

function IssueCard({
  item,
  onApplyFix,
  onLocate,
  onGo,
}: {
  item: RankedIssue
  onApplyFix: (issue: SchemeLintIssue, action: FixAction) => void
  onLocate: (issue: SchemeLintIssue) => void
  onGo: (key: 'sub' | 'rules' | 'export') => void
}) {
  const { issue } = item
  const actions = buildFixActions(issue)
  const reasons = [...new Set(item.reasons)]
  return (
    <li className={`diag-issue is-${issue.level}`}>
      <div className="diag-issue-head">
        <span className={`rt-level is-${issue.level}`}>{LEVEL_TITLES[issue.level]}</span>
        <div className="diag-issue-message">{issue.message}</div>
      </div>
      {reasons.length > 0 && (
        <div className="diag-reasons">
          {reasons.map((reason) => <span key={reason} className="diag-reason">{reason}</span>)}
        </div>
      )}
      {issue.hint && <div className="diag-hint">{issue.hint}</div>}
      <div className="diag-issue-loc mono">
        {issue.location.kind === 'rule' && `第 ${(issue.location.ruleIndex ?? 0) + 1} 条规则`}
        {issue.location.kind === 'group' && `策略组「${issue.location.group ?? ''}」`}
        {issue.location.kind === 'ruleSet' && `规则集「${issue.location.ruleSet ?? ''}」`}
        {issue.location.kind === 'target' && `导出目标 ${issue.location.target ?? ''}`}
        {issue.location.rule && ` · ${issue.location.rule}`}
      </div>
      <div className="diag-actions">
        {actions.map((action) => {
          if (action.safe) {
            return (
              <button
                key={`${action.kind}-${action.label}`}
                className="btn primary"
                onClick={() => onApplyFix(issue, action)}
                title={action.detail}
              >
                {action.label}
              </button>
            )
          }
          if (action.kind === 'locate-group' || action.kind === 'locate-rule-set') {
            return (
              <button
                key={`${action.kind}-${action.label}`}
                className="btn ghost"
                onClick={() => onLocate(
                  action.kind === 'locate-group'
                    ? { ...issue, location: { kind: 'group', group: action.group } }
                    : { ...issue, location: { kind: 'ruleSet', ruleSet: action.ruleSet, group: issue.location.group } },
                )}
              >
                {action.label}
              </button>
            )
          }
          if (action.kind === 'go-export') {
            return (
              <button key={`${action.kind}-${action.label}`} className="btn ghost" onClick={() => onGo('export')}>
                {action.label}
              </button>
            )
          }
          return (
            <button
              key={`${action.kind}-${action.label}-${action.detail}`}
              className="btn ghost diag-manual"
              onClick={() => onLocate(issue)}
              title={action.detail}
            >
              {action.label}
            </button>
          )
        })}
      </div>
      {actions.filter((action) => action.kind === 'manual').map((action) => (
        <div key={`${action.label}-detail`} className="diag-manual-detail">{action.detail}</div>
      ))}
    </li>
  )
}
