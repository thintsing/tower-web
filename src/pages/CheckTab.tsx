// 规则诊断页：方案检查、托管地址、清理与撤销。
import { useMemo } from 'react'
import type { RuleScheme } from '../models/types'
import type { TabKey } from '../models/navigation'
import { enabledNodes, nodeExactKey, useStore } from '../store'
import { useWorkspaceStatus } from '../workspaceSync'
import { isLoopbackHost, useNetworkInfo } from '../util/networkInfo'
import { resolveHostedBaseURL } from '../rules/remoteFormats'
import { explainNodePool } from '../flow/flow'
import { useScheme } from '../rules/useScheme'
import { createEditableSchemeCopy, undoEditableSchemeCopy } from '../rules/schemeCopy'
import { applyFixAction, type FixAction } from '../rules/diagnosis'
import {
  applyDuplicateCleanup,
  restoreRemovedRules,
  type DuplicateCleanupPlan,
  type RemovedRuleRecord,
} from '../rules/duplicateCleanup'
import { isReadOnlyRuleSet } from '../rules/ruleSetExclusions'
import type { SchemeLintIssue } from '../rules/schemeLint'
import { DiagnosisPanel, type FixOutcome } from '../components/DiagnosisPanel'

// ---------------- 规则诊断 Tab ----------------

// 规则诊断页的「撤销本次清理」只在本机这次会话内有效。
// 放在模块级而不是组件 state：诊断结果刷新会让子组件重渲染，
// 组件内快照容易被重置，撤销按钮就会无声消失。
// 只记录“被删掉的条目 + 原始位置”，撤销时精确回插；不再保存整份方案快照，
// 否则清理之后用户在同一方案里做的其它编辑会被一起回滚。
let cleanupUndoRecord: { schemeID: string; records: RemovedRuleRecord[] } | null = null
/** 本次自动复制出的方案；撤销时删掉副本并回到原内置方案。 */
let copyUndoRecord: { copyID: string; sourceID: string; sourceName: string } | null = null
/** 屏蔽 / 解除屏蔽的撤销槽（只保留最近一次），记录某个规则集完整的屏蔽列表。 */
let exclusionUndoRecord: { setId: string; before: string[]; label: string } | null = null

export function CheckTab({
  onGo,
  onLocate,
}: {
  onGo?: (tab: TabKey) => void
  onLocate?: (issue: SchemeLintIssue) => void
}) {
  const scheme = useScheme()
  const net = useNetworkInfo()
  // 诊断页与导出页共用同一份托管地址；undefined 代表载体未知，不能当可托管。
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
  const errors = useStore((s) => s.errors)
  const policySelections = useStore((s) => s.policySelections)
  const latencyByNodeId = useStore((s) => s.latencyByNodeId)
  const localRuleSets = useStore((s) => s.localRuleSets)
  const preferRuleSets = useStore((s) => s.preferRuleSets)
  const showGroupEmoji = useStore((s) => s.showGroupEmoji)
  const ruleSetVersionHistory = useStore((s) => s.ruleSetVersionHistory)
  const ruleSetExclusions = useStore((s) => s.ruleSetExclusions)
  const customSchemes = useStore((s) => s.customSchemes)
  const readOnly = useWorkspaceStatus().readOnly
  const enabledForRules = useMemo(() => enabledNodes({ sources, nodes }), [sources, nodes])
  const sourceErrors = useMemo(
    () => sources.map((source) => errors[source.id]?.trim()).filter((value): value is string => !!value),
    [sources, errors],
  )
  const manualCount = useMemo(
    () => nodes.filter((node) => node.isManual).length,
    [nodes],
  )
  const excludedCount = useMemo(() => {
    const excludedKeys = new Set(sources.flatMap((source) => source.excludedNodeKeys))
    return nodes.filter((node) =>
      !node.isSubscriptionMetadata
      && (excludedKeys.has(nodeExactKey(node)) || node.isEnabled === false)).length
  }, [nodes, sources])
  const pool = explainNodePool({
    sourceCount: sources.length,
    manualNodeCount: manualCount,
    nodeCount: nodes.filter((node) => !node.isSubscriptionMetadata).length,
    enabledNodeCount: enabledForRules.length,
    excludedNodeCount: excludedCount,
    sourceErrors,
  })

  const canUndoCleanup = cleanupUndoRecord !== null
  const canUndoCopy = copyUndoRecord !== null
  const canUndoExclusion = exclusionUndoRecord !== null
  /** 当前方案是不是内置只读方案：删除前必须显式告知会创建副本。 */
  const requiresCopy = scheme ? !customSchemes.some((item) => item.id === scheme.id) : false

  /** 选中内置方案时，先把当前内容复制成可编辑方案。保留已有 customRules，避免索引错位。 */
  const ensureEditable = (): RuleScheme | null => {
    if (!scheme) return null
    const state = useStore.getState()
    const existing = state.customSchemes.find((item) => item.id === scheme.id)
    if (existing) return existing
    const previousSelections = { ...state.policySelections }
    const editable = createEditableSchemeCopy(scheme, { id: `custom-${Date.now()}` })
    state.addCustomScheme(editable)
    state.setScheme(editable.id)
    for (const [group, selection] of Object.entries(previousSelections)) {
      useStore.getState().setPolicy(group, selection)
    }
    return editable
  }

  const applyFix = (action: FixAction): FixOutcome => {
    if (!scheme) return { ok: false, message: '规则方案还没加载完成。' }
    if (readOnly) return { ok: false, message: '当前工作区只读，无法修改规则。' }

    // 只读规则集的条目：不删快照，改为按签名屏蔽。它不复制方案，改动立即作用于编译与导出。
    if (action.kind === 'block-rule') {
      const setId = action.ruleSetId
      const signature = action.ruleSignature
      const set = scheme.ruleSets?.find((item) => item.id === setId)
      if (!setId || !set || !signature || !isReadOnlyRuleSet(set)) {
        return { ok: false, message: '这条规则不在只读规则集里，请刷新诊断后重试。' }
      }
      const state = useStore.getState()
      exclusionUndoRecord = {
        setId,
        before: [...(state.ruleSetExclusions[setId] ?? [])],
        label: action.ruleText ?? signature,
      }
      state.addRuleSetExclusion(setId, signature)
      return {
        ok: true,
        message: `已屏蔽「${action.ruleText ?? signature}」（来源：${set.name}）。它不会再参与编译与导出，命中可能落到下一条规则；可撤销本次屏蔽。`,
      }
    }

    // 先在当前方案上试算：规则不在了就不要复制出一个多余的「自定义」方案。
    if (!applyFixAction(scheme, action)) return { ok: false, message: '没有找到这条规则，可能已被修改。' }
    const wasReadOnly = requiresCopy
    const editable = ensureEditable()
    if (!editable) return { ok: false, message: '规则方案还没加载完成。' }
    const next = applyFixAction(editable, action)
    if (!next) return { ok: false, message: '没有找到这条规则，可能已被修改。' }
    useStore.getState().addCustomScheme({ ...next.scheme, updatedAt: Date.now() })
    // 单条删除也写入同一条撤销记录：撤销按原位置回插，不会覆盖之后做的其它编辑。
    if (next.removed) {
      cleanupUndoRecord = {
        schemeID: editable.id,
        records: [{ place: next.removed.place, rule: { ...next.removed.rule } }],
      }
    }
    if (wasReadOnly) {
      copyUndoRecord = { copyID: editable.id, sourceID: scheme.id, sourceName: scheme.name }
    } else {
      copyUndoRecord = null
    }
    const where = next.removedFrom === 'custom' ? '自定义规则' : next.removedFrom === 'ruleset' ? '规则集' : '方案规则'
    const copyNote = wasReadOnly
      ? `已创建副本「${editable.name}」，后续修改只作用于副本，原内置方案「${scheme.name}」不变；可撤销本次复制回到原方案。`
      : ''
    return {
      ok: true,
      message: `已从${where}删除「${next.removedText}」，方案已保存${copyNote ? `；${copyNote}` : `；可撤销这次删除。`}`,
    }
  }

  const cleanDuplicates = (plan: DuplicateCleanupPlan): FixOutcome => {
    if (!plan.deletions.length && !plan.shadowed.length) return { ok: false, message: '没有可安全删除的重复规则。' }
    if (!scheme) return { ok: false, message: '规则方案还没加载完成。' }
    // 同上：先确认计划在当前方案上仍然成立，再决定要不要复制方案。
    if (!applyDuplicateCleanup(scheme, plan).removed) {
      return { ok: false, message: '规则已经变化，请重新运行诊断后再清理。' }
    }
    const wasReadOnly = requiresCopy
    const editable = ensureEditable()
    if (!editable) return { ok: false, message: '规则方案还没加载完成。' }
    const result = applyDuplicateCleanup(editable, plan)
    if (!result.removed) return { ok: false, message: '规则已经变化，请重新运行诊断后再清理。' }
    cleanupUndoRecord = {
      schemeID: editable.id,
      records: result.applied.map((item) => ({ place: item.place, rule: { ...item.rule } })),
    }
    if (wasReadOnly) {
      copyUndoRecord = { copyID: editable.id, sourceID: scheme.id, sourceName: scheme.name }
    } else {
      copyUndoRecord = null
    }
    useStore.getState().addCustomScheme({ ...result.scheme, updatedAt: Date.now() })
    const copyNote = wasReadOnly
      ? `已创建副本「${editable.name}」，原内置方案「${scheme.name}」不变；可撤销本次复制回到原方案。`
      : ''
    const directionNote = plan.directionChanges.length
      ? `；保留后一条把 ${plan.directionChanges.map((change) => `「${change.fromGroup}」→「${change.toGroup}」`).join('、')}`
      : ''
    const shadowedNote = plan.shadowedCount ? `，其中遮蔽死规则 ${plan.shadowedCount} 条` : ''
    return {
      ok: true,
      message: `已删除 ${result.removed} 条重复 / 遮蔽规则（同组 ${plan.sameGroupCount} 条 / 跨组 ${plan.crossGroupCount} 条${shadowedNote}），方案已保存${directionNote}${copyNote ? `；${copyNote}` : `；可撤销本次清理（只恢复这几条，不影响其它修改）。`}`,
    }
  }

  const undoCopy = (): FixOutcome => {
    const record = copyUndoRecord
    if (!record) return { ok: false, message: '没有可撤销的复制。' }
    if (readOnly) return { ok: false, message: '当前工作区只读，无法撤销。' }
    const state = useStore.getState()
    const plan = undoEditableSchemeCopy(state.customSchemes, record.sourceID, record.copyID)
    copyUndoRecord = null
    if (!plan.removed) {
      useStore.setState({ selectedSchemeID: record.sourceID })
      return { ok: false, message: '副本已经不在了，已切回原方案。' }
    }
    cleanupUndoRecord = null
    useStore.setState({
      customSchemes: plan.customSchemes,
      selectedSchemeID: plan.selectedSchemeID,
    })
    return { ok: true, message: `已撤销本次复制，删除副本并回到原方案「${record.sourceName}」。` }
  }

  const unblockRule = (ruleSetID: string, signature: string, label: string): FixOutcome => {
    if (readOnly) return { ok: false, message: '当前工作区只读，无法解除屏蔽。' }
    const state = useStore.getState()
    const set = scheme?.ruleSets?.find((item) => item.id === ruleSetID)
    if (!set || !isReadOnlyRuleSet(set)) return { ok: false, message: '找不到这个只读规则集。' }
    const before = [...(state.ruleSetExclusions[ruleSetID] ?? [])]
    if (!before.includes(signature)) return { ok: false, message: '这条规则没有被屏蔽。' }
    exclusionUndoRecord = { setId: ruleSetID, before, label }
    state.removeRuleSetExclusion(ruleSetID, signature)
    return {
      ok: true,
      message: `已解除屏蔽「${label}」，它会重新参与编译与导出；可撤销本次解除。`,
    }
  }

  const undoExclusion = (): FixOutcome => {
    const record = exclusionUndoRecord
    if (!record) return { ok: false, message: '没有可撤销的屏蔽操作。' }
    if (readOnly) return { ok: false, message: '当前工作区只读，无法撤销。' }
    exclusionUndoRecord = null
    useStore.getState().restoreRuleSetExclusions(record.setId, record.before)
    return {
      ok: true,
      message: `已撤销上次屏蔽 / 解除，恢复「${record.label}」之前的屏蔽状态。`,
    }
  }

  const undoCleanup = (): FixOutcome => {
    const record = cleanupUndoRecord
    if (!record) return { ok: false, message: '没有可撤销的清理。' }
    // undoCopy / undoExclusion 都拦了只读；这里漏拦会让 addCustomScheme 被
    // 静默过滤，界面却提示「已恢复」。
    if (readOnly) return { ok: false, message: '当前工作区只读，无法撤销。' }
    const state = useStore.getState()
    const target = state.customSchemes.find((item) => item.id === record.schemeID)
    if (!target) {
      cleanupUndoRecord = null
      return { ok: false, message: '被清理的方案已经被删除，无法撤销这次清理。' }
    }
    const result = restoreRemovedRules(target, record.records)
    cleanupUndoRecord = null
    if (!result.restored) {
      return { ok: false, message: '没有可恢复的条目：规则集可能已被删除或替换。' }
    }
    state.addCustomScheme({ ...result.scheme, updatedAt: Date.now() })
    state.setScheme(record.schemeID)
    const skippedNote = result.skipped
      ? `；${result.skipped} 条因原位置已有同条规则或规则集已被替换而跳过`
      : ''
    return {
      ok: true,
      message: `已恢复 ${result.restored} 条被清理的规则，清理之后的其它修改保持不变${skippedNote}。`,
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">STEP 03 · 检查结果</div>
          <h1>规则诊断</h1>
          <p className="sub">一条流量为什么走这里、规则集最近变过什么、导出时会不会丢语义。</p>
        </div>
        <div className="page-actions">
          <button className="btn ghost" onClick={() => onGo?.('rules')}>调整规则方案</button>
          <button className="btn" onClick={() => onGo?.('export')}>去导出</button>
        </div>
      </div>

      {pool.code !== 'ready' ? (
        <div className={`pool-reason${pool.code === 'source-error' ? ' is-error' : ''}`}>
          <div className="pool-reason-body">
            <strong>{pool.title}</strong>
            <span>{pool.detail}</span>
            <div className="pool-reason-actions">
              <button className="btn" onClick={() => onGo?.('sub')}>去添加或修复订阅</button>
              {pool.code === 'source-error' && <button className="btn ghost" onClick={() => onGo?.('sub')}>查看订阅错误</button>}
            </div>
          </div>
        </div>
      ) : (
        <DiagnosisPanel
          scheme={scheme}
          nodes={enabledForRules}
          policySelections={policySelections}
          latencyByNodeId={latencyByNodeId}
          localRuleSets={localRuleSets}
          ruleSetExclusions={ruleSetExclusions}
          preferRuleSets={preferRuleSets}
          showGroupEmoji={showGroupEmoji}
          versionHistoryEnabled={ruleSetVersionHistory}
          hostedBaseURL={hostedBaseURL}
          historyRevision={ruleSetVersionHistory ? 1 : 0}
          requiresCopy={requiresCopy}
          onLocate={(issue) => onLocate?.(issue)}
          onApplyFix={applyFix}
          onCleanDuplicates={cleanDuplicates}
          onUndoCleanup={undoCleanup}
          canUndoCleanup={canUndoCleanup}
          canUndoCopy={canUndoCopy}
          onUndoCopy={undoCopy}
          copySourceName={copyUndoRecord?.sourceName}
          canUndoExclusion={canUndoExclusion}
          onUnblockRule={unblockRule}
          onUndoExclusion={undoExclusion}
          onGo={(key) => onGo?.(key)}
        />
      )}
    </div>
  )
}
