// 内置 / 只读方案的一次性可编辑副本。
// 复制必须显式告知用户，撤销则删除副本并把选择切回原方案。
import type { RuleScheme } from '../models/types'

/** 自定义方案名可能已带「· 自定义」后缀，展示时只保留一次。 */
export function stripSchemeCustomSuffix(name: string): string {
  return name.replace(/(?:\s*·\s*自定义)+\s*$/u, '').trim() || name
}

export interface EditableSchemeCopyOptions {
  /** 由调用方生成，便于撤销时精确定位这个副本。 */
  id: string
  now?: number
}

/** 复制一份可编辑方案；规则与自定义规则数组都与原方案分开。 */
export function createEditableSchemeCopy(
  source: RuleScheme,
  options: EditableSchemeCopyOptions,
): RuleScheme {
  return {
    ...source,
    id: options.id,
    name: `${stripSchemeCustomSuffix(source.name)} · 自定义`,
    description: source.description,
    sourceKind: 'copy',
    updatedAt: options.now ?? Date.now(),
    rules: [...source.rules],
    customRules: source.customRules ? source.customRules.map((rule) => ({ ...rule })) : [],
    // 规则集也要断开引用：副本后续的编辑不能改到内置快照里的那份。
    ruleSets: source.ruleSets
      ? source.ruleSets.map((set) => ({ ...set, rules: [...set.rules] }))
      : source.ruleSets,
  }
}

/** 撤销本次复制：删除副本、回到原方案，并保留用户现有的策略组选择。 */
export function undoEditableSchemeCopy(
  customSchemes: RuleScheme[],
  sourceSchemeID: string,
  copySchemeID: string,
): { customSchemes: RuleScheme[]; selectedSchemeID: string; removed: boolean } {
  const removed = customSchemes.some((item) => item.id === copySchemeID)
  return {
    customSchemes: removed ? customSchemes.filter((item) => item.id !== copySchemeID) : customSchemes,
    selectedSchemeID: sourceSchemeID,
    removed,
  }
}
