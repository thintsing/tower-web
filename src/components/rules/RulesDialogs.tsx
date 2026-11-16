// 规则页弹窗：编辑弹窗与确认弹窗统一接线。
import type { RulesTabController } from '../../rules/useRulesTabController'
import { RulesConfirmDialogs } from './RulesConfirmDialogs'
import { RulesEditorDialogs } from './RulesEditorDialogs'

export function RulesDialogs({ controller }: { controller: RulesTabController }) {
  const {
    readOnly,
    scheme,
    customScheme,
    builtinForCustom,
    selectedMeta,
    pendingSchemeDelete,
    setPendingSchemeDelete,
    removeCustomScheme,
    restoreInitialConfirm,
    setRestoreInitialConfirm,
    restoreInitialRules,
    pendingSnapshotRollback,
    setPendingSnapshotRollback,
    confirmSnapshotRollback,
    pendingGroupDelete,
    setPendingGroupDelete,
    deleteNodeGroup,
    pendingRuleSetRemove,
    setPendingRuleSetRemove,
    ruleSetExclusions,
    confirmRemoveSchemeRuleSet,
    pendingLocalSetDelete,
    setPendingLocalSetDelete,
    deleteLocalSet,
    enabledForRules,
    networkEditor,
    setNetworkEditor,
    saveNetworkSettings,
    editingScheme,
    setEditingScheme,
    saveSchemeMeta,
    textEditorScheme,
    setTextEditorScheme,
    saveSchemeText,
    customRuleTarget,
    customRuleGroup,
    setCustomRuleTarget,
    saveCustomRule,
    groupEditor,
    setGroupEditor,
    saveGroupEdit,
    creatingGroup,
    setCreatingGroup,
    createNodeGroup,
    libraryOpen,
    setLibraryOpen,
    applyRuleSet,
    remoteSetOpen,
    setRemoteSetOpen,
    saveRemoteRuleSets,
    renamingLocalSet,
    setRenamingLocalSet,
    renameLocalRuleSet,
    localSetEditor,
    setLocalSetEditor,
    addLocalRuleSet,
    setFlash,
    localSetAddTarget,
    setLocalSetAddTarget,
    addLocalSetToScheme,
  } = controller

  return (
    <>
      <RulesConfirmDialogs
        readOnly={readOnly}
        scheme={scheme}
        customScheme={customScheme}
        builtinForCustom={builtinForCustom}
        selectedMeta={selectedMeta}
        pendingSchemeDelete={pendingSchemeDelete}
        setPendingSchemeDelete={setPendingSchemeDelete}
        removeCustomScheme={removeCustomScheme}
        restoreInitialConfirm={restoreInitialConfirm}
        setRestoreInitialConfirm={setRestoreInitialConfirm}
        restoreInitialRules={() => void restoreInitialRules()}
        pendingSnapshotRollback={pendingSnapshotRollback}
        setPendingSnapshotRollback={setPendingSnapshotRollback}
        confirmSnapshotRollback={confirmSnapshotRollback}
        pendingGroupDelete={pendingGroupDelete}
        setPendingGroupDelete={setPendingGroupDelete}
        deleteNodeGroup={(target, group) => deleteNodeGroup(target, group)}
        pendingRuleSetRemove={pendingRuleSetRemove}
        setPendingRuleSetRemove={setPendingRuleSetRemove}
        ruleSetExclusions={ruleSetExclusions}
        confirmRemoveSchemeRuleSet={confirmRemoveSchemeRuleSet}
        pendingLocalSetDelete={pendingLocalSetDelete}
        setPendingLocalSetDelete={setPendingLocalSetDelete}
        onDeleteLocalSet={deleteLocalSet}
      />

      <RulesEditorDialogs
        scheme={scheme}
        nodes={enabledForRules}
        networkEditor={networkEditor}
        setNetworkEditor={setNetworkEditor}
        saveNetworkSettings={saveNetworkSettings}
        editingScheme={editingScheme}
        setEditingScheme={setEditingScheme}
        saveSchemeMeta={saveSchemeMeta}
        textEditorScheme={textEditorScheme}
        setTextEditorScheme={setTextEditorScheme}
        saveSchemeText={saveSchemeText}
        customRuleTarget={customRuleTarget}
        customRuleGroup={customRuleGroup}
        setCustomRuleTarget={setCustomRuleTarget}
        saveCustomRule={saveCustomRule}
        groupEditor={groupEditor}
        setGroupEditor={setGroupEditor}
        saveGroupEdit={saveGroupEdit}
        creatingGroup={creatingGroup}
        setCreatingGroup={setCreatingGroup}
        createNodeGroup={createNodeGroup}
        libraryOpen={libraryOpen}
        setLibraryOpen={setLibraryOpen}
        applyRuleSet={applyRuleSet}
        remoteSetOpen={remoteSetOpen}
        setRemoteSetOpen={setRemoteSetOpen}
        saveRemoteRuleSets={saveRemoteRuleSets}
        renamingLocalSet={renamingLocalSet}
        setRenamingLocalSet={setRenamingLocalSet}
        renameLocalRuleSet={renameLocalRuleSet}
        localSetEditor={localSetEditor}
        setLocalSetEditor={setLocalSetEditor}
        addLocalRuleSet={addLocalRuleSet}
        setFlash={setFlash}
        localSetAddTarget={localSetAddTarget}
        setLocalSetAddTarget={setLocalSetAddTarget}
        addLocalSetToScheme={addLocalSetToScheme}
      />
    </>
  )
}

