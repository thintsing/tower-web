// 规则集控制器：规则库、在线 / 本地规则集、方案内规则集与屏蔽记录。
import { useMemo, useState } from 'react'
import type { LocalRuleSet, RoutingRule, RuleScheme, RuleSetRefreshDiff, SchemeRuleSet } from '../models/types'
import type { RuleSetPayload } from '../components/rules/RuleLibraryDialog'
import { useStore } from '../store'
import {
  describeRuleSetParse,
  fetchRuleSet,
  inferRuleSetBehavior,
  parseRuleSetText,
} from './ruleSets'
import { ruleSetRefreshFailure, ruleSetRefreshSuccess, sumRuleSetDiffs } from './ruleSetRefresh'
import { newID } from '../util/browser'
import { countOrphanRuleSetExclusions } from './ruleSetExclusions'
import { ruleSetRanksBeforeSchemeRules } from './ruleOrder'
import { clearRuleSetHistory, digestRules, recordRuleSetSnapshot } from './ruleSetHistory'
import type { RulesTabShared } from './useRulesTabShared'

export function useRulesRuleSetsController(shared: RulesTabShared) {
  const { scheme, customScheme, customSchemes, addCustomScheme, makeEditableScheme, setFlash } = shared
  const localRuleSets = useStore((s) => s.localRuleSets)
  const ruleSetExclusions = useStore((s) => s.ruleSetExclusions)
  const addLocalRuleSet = useStore((s) => s.addLocalRuleSet)
  const removeLocalRuleSet = useStore((s) => s.removeLocalRuleSet)
  const clearOrphanRuleSetExclusions = useStore((s) => s.clearOrphanRuleSetExclusions)
  const schemeSnapshots = useStore((s) => s.schemeSnapshots)
  const [libraryOpen, setLibraryOpen] = useState(false)
  const [localSetEditor, setLocalSetEditor] = useState<{ set?: LocalRuleSet } | null>(null)
  const [localSetAddTarget, setLocalSetAddTarget] = useState<LocalRuleSet | null>(null)
  const [pendingLocalSetDelete, setPendingLocalSetDelete] = useState<LocalRuleSet | null>(null)
  const [pendingRuleSetRemove, setPendingRuleSetRemove] = useState<SchemeRuleSet | null>(null)
  const [remoteSetOpen, setRemoteSetOpen] = useState(false)
  const [renamingLocalSet, setRenamingLocalSet] = useState<LocalRuleSet | null>(null)
  const [refreshingRuleSetID, setRefreshingRuleSetID] = useState<string | null>(null)
  const [ruleSetError, setRuleSetError] = useState<string | null>(null)

  const orphanExclusionCount = useMemo(() => {
    const live = new Set<string>()
    for (const item of customSchemes) {
      for (const set of item.ruleSets ?? []) live.add(set.id)
    }
    for (const set of localRuleSets) live.add(set.id)
    for (const snapshot of Object.values(schemeSnapshots)) {
      for (const set of snapshot.ruleSets ?? []) live.add(set.id)
    }
    return countOrphanRuleSetExclusions(ruleSetExclusions, live)
  }, [customSchemes, localRuleSets, schemeSnapshots, ruleSetExclusions])

  const applyRuleSet = (source: RuleScheme, payload: RuleSetPayload) => {
    if (payload.rules.length === 0) return
    const editable = makeEditableScheme(source)
    const rules: RoutingRule[] = payload.rules.map((rule) => ({
      ...rule,
      group: payload.group,
      sourceName: payload.name,
    }))
    const existing = editable.ruleSets ?? []
    const existingIndex = payload.sourceRef
      ? existing.findIndex((set) => set.sourceRef === payload.sourceRef && set.group === payload.group)
      : -1
    const snapshot: SchemeRuleSet = {
      id: existingIndex >= 0 ? existing[existingIndex].id : newID(),
      name: payload.name,
      group: payload.group,
      rules,
      sourceKind: payload.sourceKind,
      sourceRef: payload.sourceRef,
      format: payload.format,
      ruleSetBehavior: payload.ruleSetBehavior
        ?? (payload.format === 'yaml' ? inferRuleSetBehavior(payload.rules) : undefined),
      updatedAt: Date.now(),
    }
    const ruleSets = existingIndex >= 0
      ? existing.map((set, index) => index === existingIndex ? snapshot : set)
      : [...existing, snapshot]
    const nextScheme = { ...editable, ruleSets, updatedAt: Date.now() }
    addCustomScheme(nextScheme)
    // 提示与真实顺序同源：用加入后的方案算出它是否真的排在方案规则之前。
    const preposed = ruleSetRanksBeforeSchemeRules(nextScheme, snapshot)
    const summary = existingIndex >= 0
      ? `已更新「${payload.name}」：${rules.length} 条规则仍然加入「${payload.group}」。`
      : `已把「${payload.name}」的 ${rules.length} 条规则加入「${payload.group}」。`
    setFlash(`${summary}${preposed ? '该规则集已排在方案规则之前，导出时优先匹配。' : ''}`)
  }

  const addLocalSetToScheme = (source: RuleScheme, set: LocalRuleSet, group: string) => {
    applyRuleSet(source, {
      name: set.name,
      group,
      rules: set.rules,
      sourceKind: set.sourceURL ? 'url' : 'local',
      sourceRef: set.sourceURL ?? set.id,
      format: set.sourceURL ? set.format : undefined,
      // 透传 provider behavior：漏掉会让 YAML 规则集在导出时退回 classical。
      ruleSetBehavior: set.ruleSetBehavior
        ?? (set.format === 'yaml' ? inferRuleSetBehavior(set.rules) : undefined),
    })
  }

  const saveRemoteRuleSets = (incoming: LocalRuleSet[], joinGroup?: string, notice?: string) => {
    // 同一地址只保留一条订阅，重复添加时更新快照。
    const saved: LocalRuleSet[] = []
    for (const set of incoming) {
      const fresh = useStore.getState()
      const existing = fresh.localRuleSets.find((item) => item.sourceURL === set.sourceURL)
      if (existing && digestRules(existing.rules) !== digestRules(set.rules)) {
        recordRuleSetSnapshot(existing.id, existing.rules, fresh.ruleSetVersionHistory)
      }
      const savedSet = existing ? { ...set, id: existing.id, paused: existing.paused } : set
      addLocalRuleSet(savedSet)
      saved.push(savedSet)
    }
    if (joinGroup && scheme) {
      // 多个规则集依次加入同一个方案；每次读取最新方案，避免后一次覆盖前一次。
      for (const savedSet of saved) {
        const freshScheme = useStore.getState().customSchemes.find((item) => item.id === scheme.id) ?? scheme
        addLocalSetToScheme(freshScheme, savedSet, joinGroup)
      }
    }
    const total = saved.reduce((sum, item) => sum + item.rules.length, 0)
    const detail = notice ? `；${notice}` : ''
    const prefix = joinGroup && scheme ? '已保存并加入' : '已保存'
    setFlash(saved.length === 1
      ? `${prefix}在线规则集「${saved[0].name}」：${total} 条规则${detail}。`
      : `${prefix} ${saved.length} 个在线规则集：共 ${total} 条规则${detail}。`)
  }

  const refreshLocalRuleSet = async (set: LocalRuleSet) => {
    if (!set.sourceURL) return
    setRefreshingRuleSetID(set.id)
    setRuleSetError(null)
    try {
      const parsed = await fetchRuleSet(set.sourceURL)
      // 只有内容真的变了才写快照：刷新成功但内容不变时不覆盖已有历史。
      if (digestRules(parsed.rules) !== digestRules(set.rules)) {
        recordRuleSetSnapshot(set.id, set.rules, useStore.getState().ruleSetVersionHistory)
      }
      const updated = ruleSetRefreshSuccess(set, parsed.rules)
      addLocalRuleSet({
        ...updated,
        format: parsed.format,
        ruleSetBehavior: parsed.format === 'yaml' ? inferRuleSetBehavior(parsed.rules) : undefined,
      })
      const diff = updated.lastDiff
      setFlash(`已刷新「${set.name}」：${parsed.rules.length} 条规则（+${diff?.added ?? 0} −${diff?.removed ?? 0} ~${diff?.modified ?? 0}）；${describeRuleSetParse(parsed)}。`)
    } catch (e) {
      const message = (e as Error).message
      addLocalRuleSet(ruleSetRefreshFailure(set, message))
      setRuleSetError(`「${set.name}」刷新失败：${message}`)
    } finally {
      setRefreshingRuleSetID(null)
    }
  }

  const refreshAllLocalRuleSets = async () => {
    const sets = localRuleSets.filter((set) => set.sourceURL && !set.paused)
    if (!sets.length) return
    setRefreshingRuleSetID('all')
    setRuleSetError(null)
    let ok = 0
    let skippedTotal = 0
    const diffs: (RuleSetRefreshDiff | undefined)[] = []
    const errors: string[] = []
    for (const set of sets) {
      try {
        const parsed = await fetchRuleSet(set.sourceURL!)
        skippedTotal += parsed.skippedLines ?? 0
        if (digestRules(parsed.rules) !== digestRules(set.rules)) {
          recordRuleSetSnapshot(set.id, set.rules, useStore.getState().ruleSetVersionHistory)
        }
        const updated = ruleSetRefreshSuccess(set, parsed.rules)
        addLocalRuleSet({
          ...updated,
          format: parsed.format,
          ruleSetBehavior: parsed.format === 'yaml' ? inferRuleSetBehavior(parsed.rules) : undefined,
        })
        diffs.push(updated.lastDiff)
        ok += 1
      } catch (error) {
        const message = (error as Error).message
        addLocalRuleSet(ruleSetRefreshFailure(set, message))
        errors.push(`「${set.name}」${message}`)
      }
    }
    setRefreshingRuleSetID(null)
    const changed = sumRuleSetDiffs(diffs)
    const totals = ok ? `：+${changed.added} −${changed.removed} ~${changed.modified}` : ''
    setFlash(`已刷新 ${ok} 个在线规则集${totals}${errors.length ? `，${errors.length} 个失败` : ''}${skippedTotal ? `，跳过 ${skippedTotal} 行` : ''}。`)
    if (errors.length) setRuleSetError(errors.join('；'))
  }

  const toggleLocalRuleSetPaused = (set: LocalRuleSet) => {
    addLocalRuleSet({ ...set, paused: !set.paused })
    setFlash(set.paused ? `已恢复「${set.name}」的自动刷新。` : `已暂停「${set.name}」的自动刷新；仍可手动刷新。`)
  }

  const renameLocalRuleSet = (set: LocalRuleSet, name: string) => {
    addLocalRuleSet({ ...set, name: name.trim() })
    setFlash(`已重命名为「${name.trim()}」。已加入方案的条目保持原名称。`)
  }

  const importLocalRuleSetFiles = async (files: File[] | null) => {
    if (!files?.length) return
    if (files.length > 20) {
      setRuleSetError('一次最多导入 20 个规则文件')
      return
    }
    setRuleSetError(null)
    const taken = new Set(localRuleSets.map((set) => set.name.trim()))
    const created: LocalRuleSet[] = []
    const errors: string[] = []
    let skippedTotal = 0
    for (const file of files) {
      try {
        if (file.size > 8 * 1024 * 1024) throw new Error('文件大于 8 MB')
        const textBody = await file.text()
        const parsed = parseRuleSetText(textBody)
        skippedTotal += parsed.skippedLines ?? 0
        const base = file.name.replace(/\.[^.]+$/, '').trim() || '导入规则集'
        let name = base
        let suffix = 2
        while (taken.has(name)) {
          name = `${base} ${suffix}`
          suffix += 1
        }
        taken.add(name)
        created.push({
          id: newID(),
          name,
          rules: parsed.rules,
          updatedAt: Date.now(),
          format: parsed.format,
          ruleSetBehavior: parsed.format === 'yaml' ? inferRuleSetBehavior(parsed.rules) : undefined,
        })
      } catch (error) {
        errors.push(`${file.name}：${(error as Error).message}`)
      }
    }
    for (const set of created) addLocalRuleSet(set)
    if (created.length) setFlash(`已导入 ${created.length} 个规则集${skippedTotal ? `，跳过 ${skippedTotal} 行` : ''}。`)
    if (errors.length) setRuleSetError(errors.join('；'))
  }

  const refreshSchemeRuleSet = async (set: SchemeRuleSet) => {
    const fresh = customScheme
    if (!fresh || set.sourceKind !== 'url' || !set.sourceRef) return
    setRefreshingRuleSetID(set.id)
    setRuleSetError(null)
    try {
      const parsed = await fetchRuleSet(set.sourceRef)
      const rules = parsed.rules.map((rule) => ({
        ...rule,
        group: set.group,
        sourceName: set.name,
      }))
      const updated = {
        ...ruleSetRefreshSuccess(set, rules),
        format: parsed.format,
        ruleSetBehavior: parsed.format === 'yaml' ? inferRuleSetBehavior(rules) : undefined,
      }
      addCustomScheme({
        ...fresh,
        ruleSets: (fresh.ruleSets ?? []).map((item) => item.id === set.id ? updated : item),
        updatedAt: Date.now(),
      })
      const diff = updated.lastDiff
      setFlash(`已刷新「${set.name}」：${parsed.rules.length} 条规则（+${diff?.added ?? 0} −${diff?.removed ?? 0} ~${diff?.modified ?? 0}）；${describeRuleSetParse(parsed)}。`)
    } catch (e) {
      setRuleSetError(`「${set.name}」刷新失败：${(e as Error).message}`)
    } finally {
      setRefreshingRuleSetID(null)
    }
  }

  const removeSchemeRuleSet = (id: string) => {
    const fresh = customScheme
    const target = fresh?.ruleSets?.find((set) => set.id === id)
    if (target) setPendingRuleSetRemove(target)
  }

  const confirmRemoveSchemeRuleSet = () => {
    const target = pendingRuleSetRemove
    const fresh = customScheme
    setPendingRuleSetRemove(null)
    if (!target || !fresh?.ruleSets) return
    const blocked = ruleSetExclusions[target.id]?.length ?? 0
    addCustomScheme({
      ...fresh,
      ruleSets: fresh.ruleSets.filter((set) => set.id !== target.id),
      updatedAt: Date.now(),
    })
    // 屏蔽记录没有迁移目标；移除时一并删掉，避免旧 id 记录变成永久孤儿。
    if (blocked) useStore.getState().restoreRuleSetExclusions(target.id, [])
    setFlash(blocked
      ? `已从当前方案移除「${target.name}」；${blocked} 条屏蔽记录已一并失效。`
      : '已从当前方案移除规则集。')
  }


  const deleteLocalSet = (target: LocalRuleSet) => {
    removeLocalRuleSet(target.id)
    clearRuleSetHistory(target.id)
    setFlash(`已删除本地规则集「${target.name}」；已加入方案的快照保持不变。`)
  }

  return {
    localRuleSets, ruleSetExclusions, orphanExclusionCount, ruleSetError,
    refreshingRuleSetID, libraryOpen, setLibraryOpen, localSetEditor,
    setLocalSetEditor, localSetAddTarget, setLocalSetAddTarget, pendingLocalSetDelete,
    setPendingLocalSetDelete, pendingRuleSetRemove, setPendingRuleSetRemove,
    remoteSetOpen, setRemoteSetOpen, renamingLocalSet, setRenamingLocalSet,
    applyRuleSet, addLocalSetToScheme, saveRemoteRuleSets, refreshLocalRuleSet,
    refreshAllLocalRuleSets, toggleLocalRuleSetPaused, renameLocalRuleSet,
    importLocalRuleSetFiles, refreshSchemeRuleSet, removeSchemeRuleSet,
    confirmRemoveSchemeRuleSet, deleteLocalSet, addLocalRuleSet,
    clearOrphanRuleSetExclusions,
  }
}
