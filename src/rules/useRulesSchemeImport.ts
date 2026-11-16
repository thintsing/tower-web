// 方案导入与编辑：URL / 粘贴 / 文件导入，方案元信息、全文重建与 DNS 设置。
import { useState } from 'react'
import type { RuleScheme } from '../models/types'
import { enabledNodes, useStore } from '../store'
import { detectRuleSchemeFormat, parseRuleSchemeText } from './importers'
import { policyIssueText, validateSchemePolicy } from './policyValidation'
import { normalizeRemoteTextURL } from '../util/remoteURL'
import { apiFetch } from '../util/apiAuth'
import { SELF_CONFIGURATION_NAME, SELF_CONFIGURATION_URL } from './selfConfiguration'
import type { RulesTabShared } from './useRulesTabShared'

export function useRulesSchemeImport(shared: RulesTabShared) {
  const {
    scheme, customScheme, addCustomScheme, setScheme, setFlash,
    makeEditableScheme,
  } = shared
  const [importingScheme, setImportingScheme] = useState(false)
  const [schemeName, setSchemeName] = useState('')
  const [schemeURL, setSchemeURL] = useState('')
  const [schemeText, setSchemeText] = useState('')
  const [schemeError, setSchemeError] = useState<string | null>(null)
  const [schemeLoading, setSchemeLoading] = useState(false)
  const [pendingSchemeDelete, setPendingSchemeDelete] = useState<RuleScheme | null>(null)
  const [editingScheme, setEditingScheme] = useState<RuleScheme | null>(null)
  const [textEditorScheme, setTextEditorScheme] = useState<RuleScheme | null>(null)
  const [networkEditor, setNetworkEditor] = useState<RuleScheme | null>(null)
  const [refreshingScheme, setRefreshingScheme] = useState(false)
  const [schemeFileName, setSchemeFileName] = useState('')

  const validateScheme = (parsed: RuleScheme) => {
    if (!parsed.groups.length || !parsed.rules.length) {
      throw new Error('没有解析到策略组或规则，请检查方案内容或规则列表地址')
    }
    const available = enabledNodes(useStore.getState())
    const issues = validateSchemePolicy(
      parsed,
      available.map((node) => node.name),
      available.length === 0,
    )
    parsed.policyWarnings = issues.length ? issues.map(policyIssueText) : undefined
    return parsed
  }

  const importSchemeFromRemote = async (name: string, rawURL: string) => {
    if (!name.trim()) { setSchemeError('请先填写方案名称'); return }
    if (!rawURL.trim()) { setSchemeError('请填写方案地址'); return }
    const sourceURL = normalizeRemoteTextURL(rawURL)
    setSchemeLoading(true); setSchemeError(null)
    try {
      const res = await apiFetch(`/api/fetch?url=${encodeURIComponent(sourceURL)}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const text = await res.text()
      const format = detectRuleSchemeFormat(text)
      const parsed = validateScheme(await parseRuleSchemeText(
        `custom-${Date.now()}`, name.trim(), '从 URL 导入', text, format,
      ))
      addCustomScheme({
        ...parsed,
        sourceKind: 'url',
        sourceFormat: format,
        sourceURL,
        rawConfigurationText: text,
        updatedAt: Date.now(),
        customRules: [],
      })
      setScheme(parsed.id)
      setImportingScheme(false); setSchemeName(''); setSchemeURL(''); setSchemeText(''); setSchemeFileName('')
    } catch (e: any) {
      setSchemeError(e.message ?? '导入失败')
    } finally { setSchemeLoading(false) }
  }

  const importSchemeFromURL = () => importSchemeFromRemote(schemeName, schemeURL)

  const importSelfConfiguration = () => importSchemeFromRemote(SELF_CONFIGURATION_NAME, SELF_CONFIGURATION_URL)

  const importSchemeFromText = async () => {
    if (!schemeName.trim()) { setSchemeError('请先填写方案名称'); return }
    if (!schemeText.trim()) { setSchemeError('请粘贴方案内容'); return }
    setSchemeLoading(true); setSchemeError(null)
    try {
      const description = schemeFileName ? `从文件导入：${schemeFileName}` : '粘贴导入'
      const format = detectRuleSchemeFormat(schemeText)
      const parsed = validateScheme(await parseRuleSchemeText(
        `custom-${Date.now()}`, schemeName.trim(), description, schemeText, format,
      ))
      addCustomScheme({
        ...parsed,
        sourceKind: schemeFileName ? 'file' : 'paste',
        sourceFormat: format,
        rawConfigurationText: schemeText,
        updatedAt: Date.now(),
        customRules: [],
      })
      // 与 URL 导入保持一致：导入成功后立即启用新方案。
      setScheme(parsed.id)
      setImportingScheme(false); setSchemeName(''); setSchemeURL(''); setSchemeText(''); setSchemeFileName('')
    } catch (e: any) {
      setSchemeError(e.message ?? '解析失败')
    } finally { setSchemeLoading(false) }
  }

  const readSchemeFile = async (file?: File) => {
    if (!file) return
    setSchemeError(null)
    try {
      const text = await file.text()
      if (!text.trim()) throw new Error('文件内容为空')
      setSchemeText(text)
      setSchemeFileName(file.name)
      if (!schemeName.trim()) setSchemeName(file.name.replace(/\.[^.]+$/, ''))
    } catch (e: any) {
      setSchemeError(e.message ?? '无法读取文件')
    }
  }

  // 从 ACL4SSR 上游拉最新 INI + 全部列表；先算差异预览，用户确认后才写覆盖层。
  // 全有或全无：失败时只报错，不写覆盖层，原厂快照继续兜底。
  const beginEditScheme = () => {
    if (!scheme) return
    const editable = customScheme ?? makeEditableScheme(scheme)
    setEditingScheme(editable)
  }

  const saveSchemeMeta = (next: RuleScheme) => {
    addCustomScheme({ ...next, updatedAt: Date.now() })
    setFlash(`已保存方案「${next.name}」。`)
  }

  const beginEditNetwork = () => {
    if (!scheme) return
    setNetworkEditor(customScheme ?? makeEditableScheme(scheme))
  }

  const saveNetworkSettings = (next: RuleScheme) => {
    addCustomScheme({ ...next, updatedAt: Date.now() })
    setNetworkEditor(null)
    setFlash('DNS 与网络设置已保存。')
  }

  /** 拖动 / 上下移：同时调整策略组顺序和该组规则的匹配位置。 */
  const saveSchemeText = async (text: string): Promise<string | undefined> => {
    const editable = customScheme
    if (!editable) return '请先选择一个自定义方案'
    if (!text.trim()) return '配置内容不能为空'
    try {
      const format = detectRuleSchemeFormat(text)
      const parsed = validateScheme(await parseRuleSchemeText(
        editable.id, editable.name, editable.description, text, format,
      ))
      const validGroups = new Set(parsed.groups.map((group) => group.name))
      const customRules = (editable.customRules ?? []).filter((rule) => validGroups.has(rule.group))
      const ruleSets = (editable.ruleSets ?? [])
        .filter((set) => validGroups.has(set.group))
        .map((set) => ({
          ...set,
          rules: set.rules.filter((rule) => validGroups.has(rule.group)),
        }))
        .filter((set) => set.rules.length > 0)
      addCustomScheme({
        ...parsed,
        id: editable.id,
        name: editable.name,
        description: editable.description,
        sourceKind: editable.sourceKind ?? 'paste',
        sourceURL: editable.sourceURL,
        sourceFormat: format,
        rawConfigurationText: text,
        networkSettings: parsed.networkSettings ?? editable.networkSettings,
        customRules,
        ruleSets,
        matchingOrder: editable.matchingOrder?.filter((group) => validGroups.has(group)),
        // 全文重建后规则身份可能全变，逐条顺序按新内容重新开始。
        ruleOrder: undefined,
        updatedAt: Date.now(),
      })
      setFlash('已按全文重建方案；自定义规则和规则集快照已尽量保留。')
      return undefined
    } catch (e: any) {
      return e.message ?? '解析失败'
    }
  }

  const refreshImportedScheme = async () => {
    const editable = customScheme
    if (!editable?.sourceURL) return
    const sourceURL = normalizeRemoteTextURL(editable.sourceURL)
    setRefreshingScheme(true); setSchemeError(null)
    try {
      const res = await apiFetch(`/api/fetch?url=${encodeURIComponent(sourceURL)}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const text = await res.text()
      const format = detectRuleSchemeFormat(text)
      const parsed = validateScheme(await parseRuleSchemeText(
        editable.id, editable.name, editable.description, text, format,
      ))
      // 保留用户调整过的组顺序；新增组追加到末尾。
      const previousOrder = editable.groups.map((g) => g.name)
      const rank = (name: string) => {
        const index = previousOrder.indexOf(name)
        return index < 0 ? Number.MAX_SAFE_INTEGER : index
      }
      const groups = [...parsed.groups].sort((a, b) => rank(a.name) - rank(b.name))
      const validGroups = new Set(groups.map((g) => g.name))
      const customRules = (editable.customRules ?? []).filter((r) => validGroups.has(r.group))
      const ruleSets = (editable.ruleSets ?? [])
        .filter((set) => validGroups.has(set.group))
        .map((set) => ({
          ...set,
          rules: set.rules.filter((rule) => validGroups.has(rule.group)),
        }))
        .filter((set) => set.rules.length > 0)
      const removed = (editable.customRules ?? []).length - customRules.length
      addCustomScheme({
        ...parsed,
        id: editable.id,
        name: editable.name,
        description: editable.description,
        sourceKind: 'url',
        sourceFormat: format,
        sourceURL,
        rawConfigurationText: text,
        networkSettings: editable.networkSettings ?? parsed.networkSettings,
        updatedAt: Date.now(),
        groups,
        customRules,
        ruleSets,
      })
      setFlash(removed
        ? `方案已刷新；移除了 ${removed} 条指向已删除策略组的自定义规则。`
        : '方案已从来源刷新。')
    } catch (e: any) {
      setSchemeError(e.message ?? '刷新失败')
    } finally { setRefreshingScheme(false) }
  }


  return {
    importingScheme, setImportingScheme, schemeName, setSchemeName, schemeURL,
    setSchemeURL, schemeText, setSchemeText, schemeError, setSchemeError,
    schemeLoading, pendingSchemeDelete, setPendingSchemeDelete, editingScheme,
    setEditingScheme, textEditorScheme, setTextEditorScheme, networkEditor,
    setNetworkEditor, refreshingScheme, schemeFileName,
    importSchemeFromURL, importSchemeFromText, readSchemeFile,
    importSelfConfiguration, beginEditScheme, saveSchemeMeta, beginEditNetwork,
    saveNetworkSettings, saveSchemeText, refreshImportedScheme,
  }
}
