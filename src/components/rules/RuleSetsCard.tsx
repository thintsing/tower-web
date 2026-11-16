// 规则库与规则集：已加入方案的规则集、本地 / 在线规则集列表及刷新、加入、编辑入口。
import { useMemo, useRef, useState } from 'react'
import type { LocalRuleSet, RuleScheme, SchemeRuleSet } from '../../models/types'
import { ruleSetSummary } from '../../rules/ruleSetReferences'
import { RULE_SET_FORMAT_TITLES } from '../../rules/ruleSets'
import { formatDate } from '../../util/formatDate'
import { READONLY_NOTE, writeGuard } from '../../util/readOnlyUi'
import { groupDisplayName } from '../GroupIcon'
import { RuleSetDiffView } from './RuleSetDialogs'

export function RuleSetsCard({
  scheme,
  readOnly,
  showGroupEmoji,
  localRuleSets,
  ruleSetExclusions,
  orphanExclusionCount,
  ruleSetError,
  refreshingRuleSetID,
  onOpenLibrary,
  onOpenRemote,
  onCreateLocal,
  onImportFiles,
  onClearOrphanExclusions,
  onRefreshSchemeSet,
  onRemoveSchemeSet,
  onRefreshAllLocal,
  onRefreshLocal,
  onToggleLocalPaused,
  onRenameLocal,
  onAddLocalToScheme,
  onEditLocal,
  onDeleteLocal,
}: {
  scheme: RuleScheme
  readOnly: boolean
  showGroupEmoji: boolean
  localRuleSets: LocalRuleSet[]
  ruleSetExclusions: Record<string, string[]>
  orphanExclusionCount: number
  ruleSetError: string | null
  refreshingRuleSetID: string | null
  onOpenLibrary: () => void
  onOpenRemote: () => void
  onCreateLocal: () => void
  onImportFiles: (files: File[]) => void
  onClearOrphanExclusions: () => void
  onRefreshSchemeSet: (set: SchemeRuleSet) => void
  onRemoveSchemeSet: (id: string) => void
  onRefreshAllLocal: () => void
  onRefreshLocal: (set: LocalRuleSet) => void
  onToggleLocalPaused: (set: LocalRuleSet) => void
  onRenameLocal: (set: LocalRuleSet) => void
  onAddLocalToScheme: (set: LocalRuleSet) => void
  onEditLocal: (set: LocalRuleSet) => void
  onDeleteLocal: (set: LocalRuleSet) => void
}) {
  const [localSetSearch, setLocalSetSearch] = useState('')
  const localSetImportRef = useRef<HTMLInputElement>(null)
  const localSetNeedle = localSetSearch.trim().toLowerCase()
  const visibleLocalRuleSets = useMemo(() => (
    localSetNeedle
      ? localRuleSets.filter((set) => {
          const formatLabel = set.format ? RULE_SET_FORMAT_TITLES[set.format] : ''
          return [set.name, set.sourceURL ?? '', formatLabel]
            .some((text) => text.toLowerCase().includes(localSetNeedle))
        })
      : localRuleSets
  ), [localRuleSets, localSetNeedle])

  return (
    <div className="card">
      <div className="card-head">
        <h3>规则库与规则集</h3>
        <div className="row wrap" style={{ gap: 6 }}>
          <button className="btn ghost" onClick={onOpenLibrary}>浏览规则库</button>
          <button className="btn ghost" {...writeGuard(readOnly)} onClick={onOpenRemote}>+ 在线规则集</button>
          <button className="btn ghost" {...writeGuard(readOnly)} onClick={onCreateLocal}>+ 新建规则集</button>
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
              onImportFiles(files)
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
              onClick={onClearOrphanExclusions}
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
                        onClick={() => onRefreshSchemeSet(set)}
                      >
                        {refreshingRuleSetID === set.id ? '刷新中…' : '刷新'}
                      </button>
                    )}
                    {!set.inlined && (
                      <button
                        className="icon-btn"
                        aria-label={`从当前方案移除规则集「${set.name}」`}
                        title="移除整组规则"
                        onClick={() => onRemoveSchemeSet(set.id)}
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
              onClick={onRefreshAllLocal}
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
                        onClick={() => onRefreshLocal(set)}
                      >
                        {refreshingRuleSetID === set.id ? '刷新中…' : '刷新'}
                      </button>
                      <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => onToggleLocalPaused(set)}>
                        {set.paused ? '恢复刷新' : '暂停刷新'}
                      </button>
                      <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => onRenameLocal(set)}>重命名</button>
                    </>
                  )}
                  <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => onAddLocalToScheme(set)}>加入方案</button>
                  {!set.sourceURL && (
                    <button className="btn ghost" {...writeGuard(readOnly)} onClick={() => onEditLocal(set)}>编辑</button>
                  )}
                  <button className="btn ghost danger-text" {...writeGuard(readOnly)} onClick={() => onDeleteLocal(set)}>删除</button>
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
  )
}
