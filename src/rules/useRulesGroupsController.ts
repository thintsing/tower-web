// 策略组控制器：新建 / 编辑 / 删除、拖动排序与诊断页定位。
import { useEffect, useMemo, useState } from 'react'
import type { PolicyGroup, RuleScheme } from '../models/types'
import type { SchemeLintIssue } from './schemeLint'
import type { RuleOrderConflict } from './orderConflicts'
import { useStore } from '../store'
import { removePolicyGroup } from './groupEditing'
import { matchingGroupNames, matchingOrderAfterDragging } from './matchingOrder'
import { findRuleOrderConflicts } from './orderConflicts'
import { orderedSchemeBaseRules, renameRuleOrderKeys } from './ruleOrder'
import { remoteReferenceCounts } from './ruleSetReferences'
import { groupDisplayName } from '../components/GroupIcon'
import type { RulesTabProps, RulesTabShared } from './useRulesTabShared'

export function useRulesGroupsController(
  shared: RulesTabShared,
  resetRuleOrderUndo: () => void,
  { onGo, locateIssue, onLocateConsumed }: RulesTabProps,
) {
  const {
    scheme, addCustomScheme, setFlash, makeEditableScheme,
  } = shared
  const removePolicy = useStore((s) => s.removePolicy)
  const [creatingGroup, setCreatingGroup] = useState<RuleScheme | null>(null)
  const [pendingGroupDelete, setPendingGroupDelete] = useState<PolicyGroup | null>(null)
  const [groupEditor, setGroupEditor] = useState<{
    scheme: RuleScheme
    group: PolicyGroup
    tab?: 'settings' | 'rules'
    query?: string
  } | null>(null)
  const [reorderUndo, setReorderUndo] = useState<{
    schemeID: string
    groups: PolicyGroup[]
    matchingOrder?: string[]
    ruleOrder?: string[]
    conflicts: RuleOrderConflict[]
  } | null>(null)

  const remoteRefsByGroup = useMemo(() => remoteReferenceCounts(scheme), [scheme])
  const remoteRefTotal = useMemo(
    () => [...remoteRefsByGroup.values()].reduce((sum, count) => sum + count, 0),
    [remoteRefsByGroup],
  )
  const groupCardMeta = useMemo(() => {
    if (!scheme) return ''
    const parts: string[] = []
    const customRules = scheme.customRules?.length ?? 0
    if (customRules > 0) parts.push(`自定义规则 ${customRules} 条`)
    const matchingGroups = scheme.groups.filter((group) => group.nodeFilter?.trim()).length
    if (matchingGroups > 0) parts.push(`${matchingGroups} 个策略组按名称匹配节点`)
    return parts.join(' · ') || '可调整顺序'
  }, [scheme])

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
    if (hadRuleOrder) resetRuleOrderUndo()
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


  return {
    creatingGroup, setCreatingGroup, pendingGroupDelete, setPendingGroupDelete,
    groupEditor, setGroupEditor, reorderUndo, remoteRefsByGroup, remoteRefTotal,
    groupCardMeta, createNodeGroup, deleteNodeGroup, reorderGroups, moveGroup,
    undoGroupReorder, beginEditGroup, locateLintIssue, saveGroupEdit,
  }
}
