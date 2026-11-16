// 规则工具区块：全量检查、命中解释与规则集版本对比。
import type { RulesTabController } from '../../rules/useRulesTabController'
import type { TabKey } from '../../models/navigation'
import { AdvancedSection } from '../AdvancedSection'
import { RulesToolsCard } from '../RulesToolsCard'

export function RulesToolsSection({ controller, onGo }: {
  controller: RulesTabController
  onGo?: (tab: TabKey) => void
}) {
  const {
    scheme, enabledForRules, policySelections, latencyByNodeId, localRuleSets,
    preferRuleSets, showGroupEmoji, ruleSetVersionHistory, hostedBaseURL,
    locateLintIssue,
  } = controller

  return (
    <>
      <AdvancedSection
        scope="rules-tools"
        title="规则工具与历史"
        summary="全量检查 · 命中解释 · 规则集版本对比；默认收起，展开状态按设备记住"
      >
        <RulesToolsCard
          scheme={scheme}
          nodes={enabledForRules}
          policySelections={policySelections}
          latencyByNodeId={latencyByNodeId}
          localRuleSets={localRuleSets}
          preferRuleSets={preferRuleSets}
          showGroupEmoji={showGroupEmoji}
          versionHistoryEnabled={ruleSetVersionHistory}
          hostedBaseURL={hostedBaseURL}
          onLocate={locateLintIssue}
          onGoExport={() => onGo?.('export')}
        />
      </AdvancedSection>

    </>
  )
}
