// 策略组与规则区块：策略组列表、自定义规则、逐条规则排序。
import type { RulesTabController } from '../../rules/useRulesTabController'
import { GroupListCard } from './GroupListCard'
import { CustomRulesCard } from './CustomRulesCard'
import { RuleOrderCard } from '../RuleOrderCard'

export function RulesGroupsSection({ controller }: { controller: RulesTabController }) {
  const {
    scheme,
    readOnly,
    showGroupEmoji,
    policySelections,
    schemeRules,
    remoteRefsByGroup,
    groupCardMeta,
    enabledForRules,
    reorderUndo,
    setPolicy,
    setCreatingGroup,
    beginEditGroup,
    moveGroup,
    reorderGroups,
    setPendingGroupDelete,
    undoGroupReorder,
    beginAddCustomRule,
    removeCustomRule,
    ruleOrderUndo,
    pinRule,
    moveRule,
    undoRuleOrder,
  } = controller

  return (
    <>
      {scheme && (
        <GroupListCard
          scheme={scheme}
          readOnly={readOnly}
          showGroupEmoji={showGroupEmoji}
          policySelections={policySelections}
          schemeRules={schemeRules}
          remoteRefsByGroup={remoteRefsByGroup}
          meta={groupCardMeta}
          nodes={enabledForRules}
          reorderUndo={reorderUndo}
          onSetPolicy={setPolicy}
          onCreateGroup={() => setCreatingGroup(scheme)}
          onEditGroup={beginEditGroup}
          onMoveGroup={moveGroup}
          onReorderGroups={reorderGroups}
          onDeleteGroup={setPendingGroupDelete}
          onUndoReorder={undoGroupReorder}
        />
      )}

      {scheme && (
        <CustomRulesCard
          scheme={scheme}
          readOnly={readOnly}
          showGroupEmoji={showGroupEmoji}
          onAdd={() => beginAddCustomRule(scheme)}
          onRemove={(rule) => removeCustomRule(scheme, rule)}
        />
      )}

      {scheme && (
        <RuleOrderCard
          scheme={scheme}
          rules={schemeRules}
          readOnly={readOnly}
          showGroupEmoji={showGroupEmoji}
          undoLabel={ruleOrderUndo?.schemeID === scheme.id ? ruleOrderUndo.label : undefined}
          onPin={pinRule}
          onMove={moveRule}
          onUndo={undoRuleOrder}
        />
      )}

    </>
  )
}

