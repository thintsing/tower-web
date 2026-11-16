// 方案固化与上游：服务端检查结果、固化预览、快照回退、恢复初始规则与 Emoji 补全。
import { useEffect, useMemo, useState } from 'react'
import type { SchemeMeta } from './scheme'
import type { BuiltinSchemeFreezePlan, SnapshotRollbackPlan } from './schemeSnapshots'
import type { UpstreamSchemeResult } from './upstreamScheme'
import type { UpstreamStatusPayload } from '../upstreamStatus'
import { useStore } from '../store'
import { flushWorkspaceNow } from '../workspaceSync'
import { loadScheme, BUILTIN_SCHEMES } from './scheme'
import {
  planBuiltinSchemeFreeze,
  planSnapshotRollback,
  resolveBuiltinSchemeSnapshot,
  snapshotsForScheme,
} from './schemeSnapshots'
import { fetchUpstreamScheme } from './upstreamScheme'
import { fetchUpstreamStatus, triggerUpstreamStatusCheck } from '../upstreamStatus'
import { autoFillGroupEmojis } from '../generator/groupIcons'
import type { RulesTabShared } from './useRulesTabShared'

export function useRulesSchemeFreeze(
  shared: RulesTabShared,
  setSchemeError: (message: string | null) => void,
) {
  const {
    scheme, customScheme, customSchemes, addCustomScheme, setScheme, setFlash,
    workspaceMode, selectedMeta, builtinForCustom, makeEditableScheme,
  } = shared
  const builtinSchemeOverrides = useStore((s) => s.builtinSchemeOverrides)
  const schemeSnapshots = useStore((s) => s.schemeSnapshots)
  const saveBuiltinSchemeOverride = useStore((s) => s.saveBuiltinSchemeOverride)
  const restoreBuiltinSchemeSnapshot = useStore((s) => s.restoreBuiltinSchemeSnapshot)
  const clearBuiltinSchemeOverride = useStore((s) => s.clearBuiltinSchemeOverride)
  const checkBuiltinSchemeUpdatesOnOpen = useStore((s) => s.checkBuiltinSchemeUpdatesOnOpen)
  const setCheckBuiltinSchemeUpdatesOnOpen = useStore((s) => s.setCheckBuiltinSchemeUpdatesOnOpen)
  const builtinSchemeUpdateNotices = useStore((s) => s.builtinSchemeUpdateNotices)
  const setBuiltinSchemeUpdateNotice = useStore((s) => s.setBuiltinSchemeUpdateNotice)
  const setShowGroupEmoji = useStore((s) => s.setShowGroupEmoji)
  const localRuleSets = useStore((s) => s.localRuleSets)
  const addLocalRuleSet = useStore((s) => s.addLocalRuleSet)
  const [serverUpstream, setServerUpstream] = useState<UpstreamStatusPayload | null>(null)
  const [serverUpstreamError, setServerUpstreamError] = useState('')
  const [upstreamChecking, setUpstreamChecking] = useState(false)
  const [updatingBuiltinScheme, setUpdatingBuiltinScheme] = useState(false)
  const [pendingFreeze, setPendingFreeze] = useState<{
    meta: SchemeMeta
    result: UpstreamSchemeResult
    plan: BuiltinSchemeFreezePlan
  } | null>(null)
  const [restoreInitialConfirm, setRestoreInitialConfirm] = useState(false)
  const [pendingSnapshotRollback, setPendingSnapshotRollback] = useState<SnapshotRollbackPlan | null>(null)

  // 服务端定时检查的结果只读展示；非服务器模式完全不请求、不轮询。
  useEffect(() => {
    if (workspaceMode !== 'server') {
      setServerUpstream(null)
      setServerUpstreamError('')
      return
    }
    let cancelled = false
    const load = async () => {
      try {
        const next = await fetchUpstreamStatus()
        if (cancelled) return
        setServerUpstream(next)
        setServerUpstreamError('')
      } catch (error) {
        if (!cancelled) setServerUpstreamError((error as Error).message)
      }
    }
    void load()
    const timer = window.setInterval(() => { void load() }, 5 * 60 * 1000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [workspaceMode])

  const checkUpstreamNow = async () => {
    if (upstreamChecking) return
    setUpstreamChecking(true)
    setServerUpstreamError('')
    try {
      await triggerUpstreamStatusCheck()
      const deadline = Date.now() + 180_000
      while (Date.now() < deadline) {
        await new Promise((resolve) => window.setTimeout(resolve, 1500))
        const next = await fetchUpstreamStatus()
        setServerUpstream(next)
        if (!next.checking) break
      }
    } catch (error) {
      setServerUpstreamError((error as Error).message)
    } finally {
      setUpstreamChecking(false)
    }
  }

  const selectedBuiltinResolution = selectedMeta && !('custom' in selectedMeta)
    ? resolveBuiltinSchemeSnapshot(selectedMeta.id, builtinSchemeOverrides, schemeSnapshots)
    : undefined
  const selectedBuiltinOverride = selectedBuiltinResolution?.snapshot
  const selectedSnapshotHistory = useMemo(
    () => selectedMeta && !('custom' in selectedMeta)
      ? snapshotsForScheme(schemeSnapshots, selectedMeta.id)
      : [],
    [selectedMeta, schemeSnapshots],
  )
  const snapshotFallbackNotice = selectedBuiltinResolution?.missingId !== undefined
    ? selectedBuiltinResolution.fallback === 'previous' && selectedBuiltinResolution.snapshot
      ? `固化快照 #${selectedBuiltinResolution.missingId} 损坏或缺失，已自动回落到上一版 #${selectedBuiltinResolution.snapshot.id}。`
      : `固化快照 #${selectedBuiltinResolution.missingId} 损坏或缺失，已自动回落到原厂快照。`
    : undefined
  const freezeBuiltinScheme = async (meta: SchemeMeta) => {
    setUpdatingBuiltinScheme(true)
    setSchemeError(null)
    try {
      const result = await fetchUpstreamScheme(meta)
      const current = await loadScheme(meta, builtinSchemeOverrides, schemeSnapshots)
      const plan = planBuiltinSchemeFreeze({
        currentScheme: current,
        content: result.override,
        customSchemes,
      })
      setPendingFreeze({ meta, result, plan })
    } catch (e) {
      setSchemeError((e as Error).message)
    } finally {
      setUpdatingBuiltinScheme(false)
    }
  }

  /** 预览确认后的实际写入；与旧流程相同的覆盖层 + 3 版环形语义。 */
  const confirmFreeze = async () => {
    if (!pendingFreeze) return
    const { meta, result } = pendingFreeze
    setPendingFreeze(null)
    const snapshotId = saveBuiltinSchemeOverride(meta.id, result.override)
    // 0 表示写保护生效（等待期间切到只读）或内容未通过快照校验。
    if (snapshotId === 0) {
      setSchemeError('未能保存固化快照：当前工作区处于只读状态，或快照内容校验失败。')
      return
    }
    setScheme(meta.id)
    setFlash(`已更新并固化「${meta.name}」：${result.override.source.ruleCount} 条规则、${result.ruleSets.length} 个列表（快照 #${snapshotId}）；已导出的客户端配置不会自动回滚。原厂快照保留，可随时恢复或回退。`)
    if (workspaceMode === 'server') {
      // 固化写入工作区后，服务端状态文件里的结果已过期；等工作区落盘后
      // 再检查一次，让提示从「有新版本」及时回到「已是最新」。
      await flushWorkspaceNow()
      void checkUpstreamNow()
    }
  }

  // 「生成自定义副本」：分支修改用；只写自定义方案与「我的规则集」，不碰覆盖层。
  const copyBuiltinSchemeFromUpstream = async (meta: SchemeMeta) => {
    setUpdatingBuiltinScheme(true)
    setSchemeError(null)
    try {
      const result = await fetchUpstreamScheme(meta)
      for (const set of result.ruleSets) {
        const existing = localRuleSets.find((item) => item.sourceURL === set.sourceURL)
        addLocalRuleSet(existing ? { ...set, id: existing.id, paused: existing.paused } : set)
      }
      // fetchUpstreamScheme 返回的 scheme.id 仍是内置方案 id（它要用来写覆盖层）。
      // 直接塞进 customSchemes 会跟内置方案同 id：列表里显示内置方案，
      // 内容却来自副本，恢复原厂 / 固化都会被副本遮住。
      // 名称补上「· 自定义」，与按钮和提示里的「自定义副本」一致；
      // 上游日期保留，便于在方案列表里区分不同批次。
      const copy = {
        ...result.scheme,
        id: `custom-${Date.now()}`,
        name: `${result.scheme.name} · 自定义`,
        sourceKind: 'copy' as const,
      }
      addCustomScheme(copy)
      setScheme(copy.id)
      setFlash(`已生成自定义副本「${copy.name}」；内置方案未改动。`)
    } catch (e) {
      setSchemeError((e as Error).message)
    } finally {
      setUpdatingBuiltinScheme(false)
    }
  }

  // 清掉覆盖层，立刻回到 public/rulesets 原厂快照；按钮回到初始态。
  const restoreBuiltinSnapshot = async (meta: SchemeMeta) => {
    setUpdatingBuiltinScheme(true)
    setSchemeError(null)
    try {
      clearBuiltinSchemeOverride(meta.id)
      // 覆盖层变化会触发 useScheme 重新 loadScheme；这里只确保仍选中这条内置方案。
      setScheme(meta.id)
      setFlash(`已恢复「${meta.name}」的原厂快照。`)
    } catch (e) {
      setSchemeError(`恢复原厂快照失败：${(e as Error).message}`)
    } finally {
      setUpdatingBuiltinScheme(false)
    }
  }

  // 回退前先算清数字与受影响方案：规则数变化、自定义方案、已导出配置提示。
  const requestSnapshotRollback = (meta: SchemeMeta, snapshotId: number) => {
    const plan = planSnapshotRollback({
      snapshots: schemeSnapshots,
      overrides: builtinSchemeOverrides,
      customSchemes,
      schemeID: meta.id,
      targetID: snapshotId,
      factoryRuleCount: scheme?.rules.length,
    })
    if (!plan) {
      setSchemeError(`快照 #${snapshotId} 不可用，无法回退。`)
      return
    }
    setPendingSnapshotRollback(plan)
  }

  const confirmSnapshotRollback = () => {
    const plan = pendingSnapshotRollback
    setPendingSnapshotRollback(null)
    if (!plan) return
    // 以计划里的 schemeID 为准：弹窗打开期间别的设备同步可能切换当前方案，
    // 用 selectedMeta 会把回退落到错误的内置方案上。
    const targetSchemeID = plan.target.schemeID
    if (!restoreBuiltinSchemeSnapshot(targetSchemeID, plan.target.id)) {
      setSchemeError(`回退失败：快照 #${plan.target.id} 不可用。`)
      return
    }
    const targetMeta = BUILTIN_SCHEMES.find((meta) => meta.id === targetSchemeID)
    setScheme(targetSchemeID)
    setFlash(`已回退「${targetMeta?.name ?? targetSchemeID}」到快照 #${plan.target.id}：规则 ${plan.fromCount} → ${plan.toCount} 条。已导出的客户端配置不会自动回滚，需要重新导出或让客户端刷新订阅。`)
  }

  const restoreInitialRules = async () => {
    if (!customScheme || !builtinForCustom) return
    setRestoreInitialConfirm(false)
    try {
      const original = await loadScheme(builtinForCustom, builtinSchemeOverrides, schemeSnapshots)
      addCustomScheme({
        ...original,
        id: customScheme.id,
        name: customScheme.name,
        description: customScheme.description,
        sourceKind: 'copy',
        rawConfigurationText: undefined,
        customRules: [],
        // 恢复初始规则时用快照重新挂回的只读规则集（inlined）；用户自己加的规则集清空。
        ruleSets: original.ruleSets ?? [],
        matchingOrder: undefined,
        ruleOrder: undefined,
        updatedAt: Date.now(),
      })
      setScheme(customScheme.id)
      setFlash(`已恢复「${builtinForCustom.name}」的初始策略组和规则。`)
    } catch (error) {
      setFlash(`恢复初始规则失败：${error instanceof Error ? error.message : String(error)}`)
    }
  }

  const autoFillGroupEmoji = () => {
    if (!scheme) return
    const editable = customScheme ?? makeEditableScheme(scheme)
    const result = autoFillGroupEmojis(editable)
    if (!result.renamed.length) {
      setFlash('所有策略组都已经带 Emoji。')
      return
    }
    addCustomScheme(result.scheme)
    for (const [oldName, newName] of result.renamed) {
      useStore.getState().renamePolicySelection(oldName, newName)
    }
    setShowGroupEmoji(true)
    setFlash(`已为 ${result.renamed.length} 个策略组补全 Emoji，并同步更新规则引用。`)
  }


  return {
    serverUpstream, serverUpstreamError, upstreamChecking, updatingBuiltinScheme,
    builtinSchemeOverrides, schemeSnapshots, checkBuiltinSchemeUpdatesOnOpen,
    setCheckBuiltinSchemeUpdatesOnOpen, builtinSchemeUpdateNotices,
    setBuiltinSchemeUpdateNotice, selectedBuiltinOverride, selectedSnapshotHistory,
    selectedBuiltinResolution, snapshotFallbackNotice, restoreInitialConfirm,
    setRestoreInitialConfirm, pendingSnapshotRollback, setPendingSnapshotRollback,
    pendingFreeze, setPendingFreeze, checkUpstreamNow, freezeBuiltinScheme,
    confirmFreeze, copyBuiltinSchemeFromUpstream, restoreBuiltinSnapshot,
    requestSnapshotRollback, confirmSnapshotRollback, restoreInitialRules,
    autoFillGroupEmoji,
  }
}
