// 规则页控制器入口：共享状态 + 方案 / 策略组 / 规则集三个子控制器。
import { useRulesTabShared, type RulesTabProps } from './useRulesTabShared'
import { useRulesSchemeController } from './useRulesSchemeController'
import { useRulesGroupsController } from './useRulesGroupsController'
import { useRulesRuleSetsController } from './useRulesRuleSetsController'

export type { RulesTabProps }

export function useRulesTabController(props: RulesTabProps) {
  const shared = useRulesTabShared()
  const scheme = useRulesSchemeController(shared)
  const groups = useRulesGroupsController(shared, () => scheme.setRuleOrderUndo(null), props)
  const ruleSets = useRulesRuleSetsController(shared)
  return { ...shared, ...scheme, ...groups, ...ruleSets }
}

export type RulesTabController = ReturnType<typeof useRulesTabController>
