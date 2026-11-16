// 方案自定义规则与逐条排序：添加 / 删除规则、上移 / 下移 / 置顶与撤销。
import { useMemo, useState } from 'react'
import type { RoutingRule, RuleScheme } from '../models/types'
import { useStore } from '../store'
import { orderedSchemeRules, isUnmovableRule, ruleOrderKeys } from './ruleOrder'
import { analyzeRuleImpact, ruleImpactText } from './ruleImpact'
import type { RulesTabShared } from './useRulesTabShared'

type RuleOrderUndoRecord = { schemeID: string; ruleOrder?: string[]; label: string }
let ruleOrderUndoSlot: RuleOrderUndoRecord | null = null

export function useRulesSchemeCustomRules(shared: RulesTabShared) {
  const { scheme, addCustomScheme, setFlash, readOnly, makeEditableScheme } = shared
  const [customRuleTarget, setCustomRuleTarget] = useState<RuleScheme | null>(null)
  const [customRuleGroup, setCustomRuleGroup] = useState<string | undefined>()
  const [ruleOrderUndo, setRuleOrderUndoState] = useState<RuleOrderUndoRecord | null>(ruleOrderUndoSlot)
  const setRuleOrderUndo = (next: RuleOrderUndoRecord | null) => {
    ruleOrderUndoSlot = next
    setRuleOrderUndoState(next)
  }
  const schemeRules = useMemo(
    () => scheme ? orderedSchemeRules(scheme) : [],
    [scheme],
  )

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

  return {
    schemeRules, customRuleTarget, customRuleGroup, setCustomRuleTarget,
    ruleOrderUndo, setRuleOrderUndo, beginAddCustomRule, saveCustomRule,
    removeCustomRule, pinRule, moveRule, undoRuleOrder,
  }
}
