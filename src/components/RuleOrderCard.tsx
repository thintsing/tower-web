// 逐条规则顺序：默认折叠、搜索优先，避免一进规则页就渲染几百条。
import { useMemo, useState } from 'react'
import type { RoutingRule, RuleScheme } from '../models/types'
import { isUnmovableRule } from '../rules/ruleOrder'
import { READONLY_NOTE, writeGuard } from '../util/readOnlyUi'
import { groupDisplayName } from './GroupIcon'

const MAX_MATCH_ROWS = 300
const MAX_BROWSE_ROWS = 100

interface RuleOrderCardProps {
  scheme: RuleScheme
  rules: RoutingRule[]
  readOnly: boolean
  showGroupEmoji: boolean
  undoLabel?: string
  onPin: (scheme: RuleScheme, index: number) => void
  onMove: (scheme: RuleScheme, index: number, delta: -1 | 1) => void
  onUndo: () => void
}

export function RuleOrderCard({
  scheme,
  rules,
  readOnly,
  showGroupEmoji,
  undoLabel,
  onPin,
  onMove,
  onUndo,
}: RuleOrderCardProps) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [browse, setBrowse] = useState(false)
  const query = search.trim().toLowerCase()
  const matched = useMemo(() => {
    if (!query) return { total: 0, rows: [] as { rule: RoutingRule; index: number }[] }
    const rows = rules
      .map((rule, index) => ({ rule, index }))
      .filter(({ rule }) =>
        `${rule.type} ${rule.value ?? ''} ${rule.group} ${rule.sourceName ?? ''}`.toLowerCase().includes(query))
    return { total: rows.length, rows: rows.slice(0, MAX_MATCH_ROWS) }
  }, [rules, query])
  const visible = query
    ? matched.rows
    : browse
      ? rules.slice(0, MAX_BROWSE_ROWS).map((rule, index) => ({ rule, index }))
      : []

  return (
    <details
      className="card rule-order-card"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="card-head rule-order-summary">
        <h3>规则顺序（逐条）</h3>
        <span className="meta">{rules.length} 条 · 搜索后调整</span>
      </summary>
      {open && (
        <div className="rule-order-body">
          <div className="search-wrap rs-search">
            <input
              className="input"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="搜索类型、域名、策略组或规则集…"
              aria-label="搜索规则顺序"
              autoFocus
            />
            {search && (
              <button className="search-clear" aria-label="清空规则搜索" onClick={() => setSearch('')}>×</button>
            )}
          </div>
          {!query && !browse && (
            <div className="rule-order-prompt">
              <span className="hint">输入关键词定位要调整的规则，共 {rules.length} 条。</span>
              <button type="button" className="btn ghost" onClick={() => setBrowse(true)}>
                浏览前 {Math.min(MAX_BROWSE_ROWS, rules.length)} 条
              </button>
            </div>
          )}
          {visible.length > 0 ? (
            <ul className="rule-list rule-order-list">
              {visible.map(({ rule, index }) => {
                const movable = !isUnmovableRule(rule)
                const previous = rules[index - 1]
                const nextRule = rules[index + 1]
                const canUp = movable && !!previous && !isUnmovableRule(previous)
                const canDown = movable && !!nextRule && !isUnmovableRule(nextRule)
                const canPin = movable && index > 0 && !isUnmovableRule(rules[index - 1])
                const disabledNote = !movable
                  ? 'GEOIP / FINAL / MATCH 是兜底锚点，不能手动移动'
                  : readOnly ? READONLY_NOTE : undefined
                const pinNote = disabledNote ?? (canPin ? '移到本段最前（不越过兜底锚点）' : '已经在最前')
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
                        disabled={!canPin || readOnly}
                        aria-label={`置顶规则 ${rule.type} ${rule.value ?? ''}`}
                        title={pinNote}
                        onClick={() => onPin(scheme, index)}
                      >⇈</button>
                      <button
                        type="button"
                        className="icon-btn"
                        disabled={!canUp || readOnly}
                        aria-label={`上移规则 ${rule.type} ${rule.value ?? ''}`}
                        title={upNote}
                        onClick={() => onMove(scheme, index, -1)}
                      >↑</button>
                      <button
                        type="button"
                        className="icon-btn"
                        disabled={!canDown || readOnly}
                        aria-label={`下移规则 ${rule.type} ${rule.value ?? ''}`}
                        title={downNote}
                        onClick={() => onMove(scheme, index, 1)}
                      >↓</button>
                    </span>
                  </li>
                )
              })}
            </ul>
          ) : (query || browse) ? (
            <div className="hint">{query ? '没有匹配的规则' : '当前方案没有可调整的规则。'}</div>
          ) : null}
          {query && matched.total > visible.length && (
            <div className="hint">
              共 {matched.total} 条匹配，仅显示前 {visible.length} 条；用搜索缩小范围后再调整。
            </div>
          )}
          {!query && browse && rules.length > visible.length && (
            <div className="hint">
              仅显示前 {visible.length} 条；用搜索可以精确定位其余规则。
            </div>
          )}
          {undoLabel && (
            <div className="inline-notice" role="status">
              <span>已调整规则「{undoLabel}」顺序。</span>
              <button type="button" className="btn ghost" {...writeGuard(readOnly)} onClick={onUndo}>撤销</button>
            </div>
          )}
          <div className="hint rule-order-hint">
            这里调整的是导出配置里真正从上到下的匹配顺序。自定义规则默认仍排在最前（最具体优先），手动移动后以这里的顺序为准；
            ⇈ 置顶会把它移到普通规则最前。调整策略组顺序会重置这里的逐条顺序（组排序优先）。GEOIP / FINAL / MATCH 是兜底锚点，按钮会明确禁用。
          </div>
        </div>
      )}
    </details>
  )
}
