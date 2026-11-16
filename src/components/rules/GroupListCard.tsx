// 策略组列表：拖动 / 上下移调整顺序，行内选择首选策略，进入组详情查看规则。
import { useState } from 'react'
import type { PolicyGroup, ProxyNode, RoutingRule, RuleScheme } from '../../models/types'
import type { RuleOrderConflict } from '../../rules/orderConflicts'
import { groupRuleSummary } from '../../rules/ruleSetReferences'
import { READONLY_NOTE, writeGuard } from '../../util/readOnlyUi'
import { GroupIcon, groupDisplayName } from '../GroupIcon'

export function policyTypeLabel(type: PolicyGroup['type']): string {
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

export function GroupListCard({
  scheme,
  readOnly,
  showGroupEmoji,
  policySelections,
  schemeRules,
  remoteRefsByGroup,
  meta,
  nodes,
  reorderUndo,
  onSetPolicy,
  onCreateGroup,
  onEditGroup,
  onMoveGroup,
  onReorderGroups,
  onDeleteGroup,
  onUndoReorder,
}: {
  scheme: RuleScheme
  readOnly: boolean
  showGroupEmoji: boolean
  policySelections: Record<string, string>
  schemeRules: RoutingRule[]
  remoteRefsByGroup: Map<string, number>
  meta: string
  nodes: ProxyNode[]
  reorderUndo: { schemeID: string; conflicts: RuleOrderConflict[] } | null
  onSetPolicy: (group: string, value: string) => void
  onCreateGroup: () => void
  onEditGroup: (scheme: RuleScheme, group: PolicyGroup, tab?: 'settings' | 'rules') => void
  onMoveGroup: (scheme: RuleScheme, index: number, delta: -1 | 1) => void
  onReorderGroups: (scheme: RuleScheme, from: number, to: number) => void
  onDeleteGroup: (group: PolicyGroup) => void
  onUndoReorder: () => void
}) {
  const [dragFromIndex, setDragFromIndex] = useState<number | null>(null)
  const [dragOverIndex, setDragOverIndex] = useState<number | null>(null)

  /** 策略组名称匹配到的节点，供首选策略下拉使用。 */
  const nodeChoicesFor = (group: PolicyGroup): string[] => {
    if (!group.nodeFilter) return []
    try {
      const regex = new RegExp(group.nodeFilter)
      return nodes.filter((node) => regex.test(node.name)).map((node) => node.name)
    } catch {
      return []
    }
  }

  return (
    <div className="card">
      <div className="card-head">
        <h3>策略组</h3>
        <div className="row wrap" style={{ gap: 8, alignItems: 'center' }}>
          <span className="meta">{meta}</span>
          <button className="btn ghost" {...writeGuard(readOnly)} onClick={onCreateGroup}>+ 新建策略组</button>
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
                onReorderGroups(scheme, from, index)
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
                  onChange={(e) => onSetPolicy(g.name, e.target.value)}
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
              <button className="btn ghost group-rule-btn" onClick={() => onEditGroup(scheme, g, 'rules')}>
                查看规则
              </button>
              <button
                className="icon-btn"
                aria-label={`编辑策略组「${g.name}」`}
                title="编辑策略组"
                onClick={() => onEditGroup(scheme, g)}
              >✎</button>
              <button
                className="icon-btn"
                disabled={index === 0 || readOnly}
                aria-label={`上移策略组「${g.name}」`}
                title={readOnly ? READONLY_NOTE : '上移'}
                onClick={() => onMoveGroup(scheme, index, -1)}
              >↑</button>
              <button
                className="icon-btn"
                disabled={index === scheme.groups.length - 1 || readOnly}
                aria-label={`下移策略组「${g.name}」`}
                title={readOnly ? READONLY_NOTE : '下移'}
                onClick={() => onMoveGroup(scheme, index, 1)}
              >↓</button>
              <button
                className="icon-btn"
                disabled={scheme.groups.length <= 1 || readOnly}
                aria-label={`删除策略组「${g.name}」`}
                title={readOnly ? READONLY_NOTE : scheme.groups.length <= 1 ? '至少保留一个策略组' : '删除策略组'}
                onClick={() => onDeleteGroup(g)}
              >×</button>
            </div>
          </div>
        )
      })}
      </div>
      {reorderUndo && reorderUndo.schemeID === scheme.id && (
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
          <button type="button" className="btn ghost" {...writeGuard(readOnly)} onClick={onUndoReorder}>撤销</button>
        </div>
      )}
      <div className="hint group-order-hint">
        拖动或上下移会写入客户端的策略组顺序，并把该组规则移到对应的匹配位置；排在前面的组先匹配。
      </div>
    </div>
  )
}
