// 规则页的编辑弹窗集合：方案、DNS、自定义规则、策略组、规则库 / 规则集。
import type { LocalRuleSet, PolicyGroup, ProxyNode, RoutingRule, RuleScheme } from '../../models/types'
import { orderedSchemeBaseRules } from '../../rules/ruleOrder'
import { AddCustomRuleDialog, NetworkSettingsDialog, SchemeEditDialog, SchemeTextDialog } from './SchemeDialogs'
import { GroupCreateDialog, GroupEditorDialog } from './GroupDialogs'
import { RuleLibraryDialog, type RuleSetPayload } from './RuleLibraryDialog'
import {
  AddRuleSetToSchemeDialog,
  RemoteRuleSetDialog,
  RenameRuleSetDialog,
  RuleSetEditorDialog,
} from './RuleSetDialogs'

export interface GroupEditorState {
  scheme: RuleScheme
  group: PolicyGroup
  tab?: 'settings' | 'rules'
  query?: string
}

export function RulesEditorDialogs({
  scheme,
  nodes,
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
}: {
  scheme: RuleScheme | undefined
  nodes: ProxyNode[]
  networkEditor: RuleScheme | null
  setNetworkEditor: (value: RuleScheme | null) => void
  saveNetworkSettings: (scheme: RuleScheme) => void
  editingScheme: RuleScheme | null
  setEditingScheme: (value: RuleScheme | null) => void
  saveSchemeMeta: (scheme: RuleScheme) => void
  textEditorScheme: RuleScheme | null
  setTextEditorScheme: (value: RuleScheme | null) => void
  saveSchemeText: (text: string) => Promise<string | undefined>
  customRuleTarget: RuleScheme | null
  customRuleGroup: string | undefined
  setCustomRuleTarget: (value: RuleScheme | null) => void
  saveCustomRule: (scheme: RuleScheme, rule: RoutingRule) => void
  groupEditor: GroupEditorState | null
  setGroupEditor: (value: GroupEditorState | null) => void
  saveGroupEdit: (editor: GroupEditorState, group: PolicyGroup) => void
  creatingGroup: RuleScheme | null
  setCreatingGroup: (value: RuleScheme | null) => void
  createNodeGroup: (scheme: RuleScheme, group: PolicyGroup) => void
  libraryOpen: boolean
  setLibraryOpen: (value: boolean) => void
  applyRuleSet: (scheme: RuleScheme, payload: RuleSetPayload) => void
  remoteSetOpen: boolean
  setRemoteSetOpen: (value: boolean) => void
  saveRemoteRuleSets: (sets: LocalRuleSet[], group?: string, notice?: string) => void
  renamingLocalSet: LocalRuleSet | null
  setRenamingLocalSet: (value: LocalRuleSet | null) => void
  renameLocalRuleSet: (set: LocalRuleSet, name: string) => void
  localSetEditor: { set?: LocalRuleSet } | null
  setLocalSetEditor: (value: { set?: LocalRuleSet } | null) => void
  addLocalRuleSet: (set: LocalRuleSet) => void
  setFlash: (message: string) => void
  localSetAddTarget: LocalRuleSet | null
  setLocalSetAddTarget: (value: LocalRuleSet | null) => void
  addLocalSetToScheme: (scheme: RuleScheme, set: LocalRuleSet, group: string) => void
}) {
  return (
    <>
      {networkEditor && (
        <NetworkSettingsDialog
          scheme={networkEditor}
          onClose={() => setNetworkEditor(null)}
          onSave={saveNetworkSettings}
        />
      )}

      {editingScheme && (
        <SchemeEditDialog
          key={editingScheme.id}
          scheme={editingScheme}
          onClose={() => setEditingScheme(null)}
          onSave={saveSchemeMeta}
        />
      )}
      {textEditorScheme && (
        <SchemeTextDialog
          key={textEditorScheme.id}
          scheme={textEditorScheme}
          onClose={() => setTextEditorScheme(null)}
          onSave={saveSchemeText}
        />
      )}
      {customRuleTarget && (
        <AddCustomRuleDialog
          key={`${customRuleTarget.id}-${customRuleGroup ?? ''}`}
          scheme={customRuleTarget}
          initialGroup={customRuleGroup}
          onClose={() => setCustomRuleTarget(null)}
          onSave={(rule) => saveCustomRule(customRuleTarget, rule)}
        />
      )}
      {groupEditor && (
        <GroupEditorDialog
          key={`${groupEditor.scheme.id}-${groupEditor.group.name}-${groupEditor.tab ?? 'settings'}`}
          scheme={groupEditor.scheme}
          group={groupEditor.group}
          nodes={nodes}
          rules={orderedSchemeBaseRules(groupEditor.scheme)}
          customRules={groupEditor.scheme.customRules ?? []}
          initialTab={groupEditor.tab}
          initialRuleQuery={groupEditor.query}
          onClose={() => setGroupEditor(null)}
          onSave={(updated) => saveGroupEdit(groupEditor, updated)}
          onAddRule={(rule) => saveCustomRule(groupEditor.scheme, rule)}
        />
      )}
      {creatingGroup && (
        <GroupCreateDialog
          key={`${creatingGroup.id}-create-group`}
          scheme={creatingGroup}
          nodes={nodes}
          onClose={() => setCreatingGroup(null)}
          onCreate={(group) => createNodeGroup(creatingGroup, group)}
        />
      )}
      {libraryOpen && scheme && (
        <RuleLibraryDialog
          scheme={scheme}
          onClose={() => setLibraryOpen(false)}
          onAdd={(payload) => applyRuleSet(scheme, payload)}
        />
      )}
      {remoteSetOpen && scheme && (
        <RemoteRuleSetDialog
          key={scheme.id}
          scheme={scheme}
          onClose={() => setRemoteSetOpen(false)}
          onSave={(sets, group, notice) => {
            saveRemoteRuleSets(sets, group, notice)
            setRemoteSetOpen(false)
          }}
        />
      )}
      {renamingLocalSet && (
        <RenameRuleSetDialog
          key={renamingLocalSet.id}
          set={renamingLocalSet}
          onClose={() => setRenamingLocalSet(null)}
          onSave={(name) => {
            renameLocalRuleSet(renamingLocalSet, name)
            setRenamingLocalSet(null)
          }}
        />
      )}
      {localSetEditor && (
        <RuleSetEditorDialog
          key={localSetEditor.set?.id ?? 'new'}
          ruleSet={localSetEditor.set}
          onClose={() => setLocalSetEditor(null)}
          onSave={(set) => {
            addLocalRuleSet(set)
            setFlash(`已保存规则集「${set.name}」，共 ${set.rules.length} 条规则。`)
          }}
        />
      )}
      {localSetAddTarget && scheme && (
        <AddRuleSetToSchemeDialog
          key={`${localSetAddTarget.id}-${scheme.id}`}
          ruleSet={localSetAddTarget}
          scheme={scheme}
          onClose={() => setLocalSetAddTarget(null)}
          onAdd={(group) => addLocalSetToScheme(scheme, localSetAddTarget, group)}
        />
      )}
    </>
  )
}
