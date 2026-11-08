// 「本机是否有值得保留的工作区内容」的统一判断。
// 参与同步的字段都必须计入：只改了当前方案 / 策略选择 / 配置名 / Auth Key 时，
// 冲突恢复和首次迁移也不能把它们当成空工作区静默覆盖。
// 当前方案和配置名有默认值，只有偏离默认值才算用户内容。
import { BUILTIN_SCHEMES } from './rules/scheme'
import type { WorkspaceData } from './workspaceValidation'

export const DEFAULT_SELECTED_SCHEME_ID = BUILTIN_SCHEMES[0]?.id ?? ''
export const DEFAULT_EXPORT_CONFIG_NAME = 'tower'

export function hasWorkspaceContent(data: WorkspaceData): boolean {
  return data.sources.length > 0
    || data.nodes.length > 0
    || data.customSchemes.length > 0
    || data.localRuleSets.length > 0
    || Object.keys(data.builtinSchemeOverrides).length > 0
    || Object.keys(data.schemeSnapshots).length > 0
    || Object.keys(data.ruleSetExclusions).length > 0
    || data.tailnets.length > 0
    || Object.keys(data.policySelections).length > 0
    || Object.keys(data.tailnetAuthKeys).length > 0
    || (data.selectedSchemeID !== '' && data.selectedSchemeID !== DEFAULT_SELECTED_SCHEME_ID)
    || (data.exportConfigName !== '' && data.exportConfigName !== DEFAULT_EXPORT_CONFIG_NAME)
}
