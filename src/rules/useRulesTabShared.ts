// 规则页共享状态：工作区订阅、当前方案派生值与页面提示。
import { useEffect, useMemo, useState } from 'react'
import type { ProxyNode, RuleScheme } from '../models/types'
import type { SchemeMeta } from './scheme'
import type { SchemeLintIssue } from './schemeLint'
import type { TabKey } from '../models/navigation'
import type { WorkspaceStatus } from '../workspaceSync'
import { enabledNodes, useStore } from '../store'
import { useWorkspaceStatus } from '../workspaceSync'
import { useScheme } from './useScheme'
import { isLoopbackHost, useNetworkInfo } from '../util/networkInfo'
import { resolveHostedBaseURL } from './remoteFormats'
import { allSchemeMetas, BUILTIN_SCHEMES } from './scheme'
import { createEditableSchemeCopy, stripSchemeCustomSuffix } from './schemeCopy'

export interface RulesTabProps {
  onGo?: (tab: TabKey) => void
  /** 从诊断页跳过来时待定位的检查项。 */
  locateIssue?: SchemeLintIssue | null
  onLocateConsumed?: () => void
}

export interface RulesTabShared {
  selectedSchemeID: string
  setScheme: (value: string) => void
  policySelections: Record<string, string>
  setPolicy: (group: string, value: string) => void
  showGroupEmoji: boolean
  readOnly: boolean
  workspaceMode: WorkspaceStatus['mode']
  scheme: RuleScheme | undefined
  customScheme: RuleScheme | undefined
  customSchemes: RuleScheme[]
  addCustomScheme: (scheme: RuleScheme) => void
  removeCustomScheme: (id: string) => void
  selectedMeta: SchemeMeta | undefined
  allMetas: SchemeMeta[]
  builtinForCustom: SchemeMeta | undefined
  enabledForRules: ProxyNode[]
  makeEditableScheme: (source: RuleScheme) => RuleScheme
  setFlash: (message: string) => void
  flash: string
  preferRuleSets: boolean
  latencyByNodeId: Record<string, number | null>
  ruleSetVersionHistory: boolean
  hostedBaseURL: string | undefined
}

export function useRulesTabShared(): RulesTabShared {
  const selectedSchemeID = useStore((s) => s.selectedSchemeID)
  const workspaceStatus = useWorkspaceStatus()
  const readOnly = workspaceStatus.readOnly
  const workspaceMode = workspaceStatus.mode
  const setScheme = useStore((s) => s.setScheme)
  const policySelections = useStore((s) => s.policySelections)
  const setPolicy = useStore((s) => s.setPolicy)
  const showGroupEmoji = useStore((s) => s.showGroupEmoji)
  const preferRuleSets = useStore((s) => s.preferRuleSets)
  const latencyByNodeId = useStore((s) => s.latencyByNodeId)
  const ruleSetVersionHistory = useStore((s) => s.ruleSetVersionHistory)
  const scheme = useScheme()
  const net = useNetworkInfo()
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
  const customSchemes = useStore((s) => s.customSchemes)
  const addCustomScheme = useStore((s) => s.addCustomScheme)
  const removeCustomScheme = useStore((s) => s.removeCustomScheme)
  const [flash, setFlash] = useState('')
  const allMetas = allSchemeMetas(customSchemes)
  const selectedMeta = allMetas.find((m) => m.id === selectedSchemeID)
  const customScheme = customSchemes.find((c) => c.id === scheme?.id)
  const builtinForCustom = customScheme?.sourceKind === 'copy'
    ? BUILTIN_SCHEMES.find((meta) => meta.name === stripSchemeCustomSuffix(customScheme.name))
    : undefined
  const enabledForRules = useMemo(() => enabledNodes({ sources, nodes }), [sources, nodes])

  useEffect(() => {
    if (!flash) return
    const timer = window.setTimeout(() => setFlash(''), 4200)
    return () => window.clearTimeout(timer)
  }, [flash])

  /** 修改内置方案前先复制，保留用户原来的策略组选择。 */
  const makeEditableScheme = (source: RuleScheme): RuleScheme => {
    const existing = customSchemes.find((c) => c.id === source.id)
    if (existing) return existing
    const copy = createEditableSchemeCopy(source, { id: `custom-${Date.now()}` })
    const previousSelections = useStore.getState().policySelections
    addCustomScheme(copy)
    setScheme(copy.id)
    for (const [group, selection] of Object.entries(previousSelections)) {
      useStore.getState().setPolicy(group, selection)
    }
    setFlash(`已创建副本「${copy.name}」，后续修改只作用于副本，原内置方案「${source.name}」不变。`)
    return copy
  }

  return {
    selectedSchemeID, setScheme, policySelections, setPolicy, showGroupEmoji,
    readOnly, workspaceMode, scheme, customScheme, customSchemes, addCustomScheme,
    removeCustomScheme, selectedMeta, allMetas, builtinForCustom, enabledForRules,
    makeEditableScheme, setFlash, flash, preferRuleSets, latencyByNodeId,
    ruleSetVersionHistory, hostedBaseURL,
  }
}
