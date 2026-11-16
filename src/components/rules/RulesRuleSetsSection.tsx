// 规则集区块：已加入方案的规则集与我的规则集。
import type { RulesTabController } from '../../rules/useRulesTabController'
import { RuleSetsCard } from './RuleSetsCard'

export function RulesRuleSetsSection({ controller }: { controller: RulesTabController }) {
  const {
    scheme,
    readOnly,
    showGroupEmoji,
    localRuleSets,
    ruleSetExclusions,
    orphanExclusionCount,
    ruleSetError,
    refreshingRuleSetID,
    setLibraryOpen,
    setRemoteSetOpen,
    setLocalSetEditor,
    importLocalRuleSetFiles,
    clearOrphanRuleSetExclusions,
    setFlash,
    refreshSchemeRuleSet,
    removeSchemeRuleSet,
    refreshAllLocalRuleSets,
    refreshLocalRuleSet,
    toggleLocalRuleSetPaused,
    setRenamingLocalSet,
    setLocalSetAddTarget,
    setPendingLocalSetDelete,
  } = controller

  return (
    <>
      {scheme && (
        <RuleSetsCard
          scheme={scheme}
          readOnly={readOnly}
          showGroupEmoji={showGroupEmoji}
          localRuleSets={localRuleSets}
          ruleSetExclusions={ruleSetExclusions}
          orphanExclusionCount={orphanExclusionCount}
          ruleSetError={ruleSetError}
          refreshingRuleSetID={refreshingRuleSetID}
          onOpenLibrary={() => setLibraryOpen(true)}
          onOpenRemote={() => setRemoteSetOpen(true)}
          onCreateLocal={() => setLocalSetEditor({})}
          onImportFiles={(files) => void importLocalRuleSetFiles(files)}
          onClearOrphanExclusions={() => {
            const removed = clearOrphanRuleSetExclusions()
            setFlash(`已清理 ${removed} 条孤儿屏蔽记录（所属规则集已不存在）。`)
          }}
          onRefreshSchemeSet={(set) => void refreshSchemeRuleSet(set)}
          onRemoveSchemeSet={removeSchemeRuleSet}
          onRefreshAllLocal={() => void refreshAllLocalRuleSets()}
          onRefreshLocal={(set) => void refreshLocalRuleSet(set)}
          onToggleLocalPaused={toggleLocalRuleSetPaused}
          onRenameLocal={setRenamingLocalSet}
          onAddLocalToScheme={setLocalSetAddTarget}
          onEditLocal={(set) => setLocalSetEditor({ set })}
          onDeleteLocal={setPendingLocalSetDelete}
        />
      )}

    </>
  )
}

