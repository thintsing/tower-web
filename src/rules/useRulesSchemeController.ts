// 方案控制器：组合导入 / 固化 / 自定义规则三个子控制器。
import type { RulesTabShared } from './useRulesTabShared'
import { useRulesSchemeImport } from './useRulesSchemeImport'
import { useRulesSchemeFreeze } from './useRulesSchemeFreeze'
import { useRulesSchemeCustomRules } from './useRulesSchemeCustomRules'

export function useRulesSchemeController(shared: RulesTabShared) {
  const importController = useRulesSchemeImport(shared)
  const freezeController = useRulesSchemeFreeze(shared, importController.setSchemeError)
  const customRulesController = useRulesSchemeCustomRules(shared)
  return { ...importController, ...freezeController, ...customRulesController }
}
