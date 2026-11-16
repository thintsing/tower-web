// 规则页的确认弹窗：删除方案 / 策略组 / 规则集，恢复初始规则与快照回退。
import type { LocalRuleSet, PolicyGroup, RuleScheme, SchemeRuleSet } from '../../models/types'
import type { SchemeMeta } from '../../rules/scheme'
import type { SnapshotRollbackPlan } from '../../rules/schemeSnapshots'
import { removePolicyGroup } from '../../rules/groupEditing'
import { describeRuleSetRemovalImpact } from '../../rules/ruleSetExclusions'
import { ConfirmDialog } from '../ConfirmDialog'
import { groupDisplayName } from '../GroupIcon'

export function RulesConfirmDialogs({
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
  onDeleteLocalSet,
}: {
  readOnly: boolean
  scheme: RuleScheme | undefined
  customScheme: RuleScheme | undefined
  builtinForCustom: SchemeMeta | undefined
  selectedMeta: SchemeMeta | undefined
  pendingSchemeDelete: RuleScheme | null
  setPendingSchemeDelete: (value: RuleScheme | null) => void
  removeCustomScheme: (id: string) => void
  restoreInitialConfirm: boolean
  setRestoreInitialConfirm: (value: boolean) => void
  restoreInitialRules: () => void
  pendingSnapshotRollback: SnapshotRollbackPlan | null
  setPendingSnapshotRollback: (value: SnapshotRollbackPlan | null) => void
  confirmSnapshotRollback: () => void
  pendingGroupDelete: PolicyGroup | null
  setPendingGroupDelete: (value: PolicyGroup | null) => void
  deleteNodeGroup: (scheme: RuleScheme, group: PolicyGroup) => void
  pendingRuleSetRemove: SchemeRuleSet | null
  setPendingRuleSetRemove: (value: SchemeRuleSet | null) => void
  ruleSetExclusions: Record<string, string[]>
  confirmRemoveSchemeRuleSet: () => void
  pendingLocalSetDelete: LocalRuleSet | null
  setPendingLocalSetDelete: (value: LocalRuleSet | null) => void
  onDeleteLocalSet: (set: LocalRuleSet) => void
}) {
  return (
    <>
      <ConfirmDialog
        open={!!pendingSchemeDelete}
        title="删除自定义方案？"
        body={<>将删除规则方案 <b>「{pendingSchemeDelete?.name}」</b>。如果它正被使用，会切回内置 ACL4SSR 方案。</>}
        confirmLabel="删除"
        danger
        confirmDisabled={readOnly}
        onCancel={() => setPendingSchemeDelete(null)}
        onConfirm={() => {
          const target = pendingSchemeDelete
          setPendingSchemeDelete(null)
          if (target) removeCustomScheme(target.id)
        }}
      />

      {restoreInitialConfirm && customScheme && builtinForCustom && (
        <ConfirmDialog
          open
          title="恢复初始规则？"
          body={(
            <>
              将把「{customScheme.name}」恢复为「{builtinForCustom.name}」的初始策略组和规则。
              当前自定义规则、规则集快照、Emoji 补全和匹配顺序都会被清空，此操作不可撤销。
            </>
          )}
          confirmLabel="恢复初始规则"
          danger
          confirmDisabled={readOnly}
          onCancel={() => setRestoreInitialConfirm(false)}
          onConfirm={restoreInitialRules}
        />
      )}

      {pendingSnapshotRollback && selectedMeta && !('custom' in selectedMeta) && (
        <ConfirmDialog
          open
          title={`回退「${selectedMeta.name}」到快照 #${pendingSnapshotRollback.target.id}？`}
          body={(
            <>
              <span>{pendingSnapshotRollback.message}</span>
              {pendingSnapshotRollback.affectedSchemes.length > 0 && (
                <span className="hint" style={{ display: 'block', marginTop: 6 }}>
                  受影响的自定义方案会改成引用这份旧版规则集，导出结果随之变化。
                </span>
              )}
            </>
          )}
          confirmLabel="回退至此版"
          danger
          confirmDisabled={readOnly}
          onCancel={() => setPendingSnapshotRollback(null)}
          onConfirm={confirmSnapshotRollback}
        />
      )}

      {pendingGroupDelete && scheme && (
        <ConfirmDialog
          open
          title="删除策略组？"
          body={(
            <>
              {(() => {
                // 与 removePolicyGroup 返回字段同源，避免确认框只数直接规则、
                // 把 providerOnly 远程引用显示成「移除 0 条」。
                const summary = removePolicyGroup(scheme, pendingGroupDelete.name)
                const details: string[] = []
                if (summary.removedRules > 0) details.push(`${summary.removedRules} 条规则`)
                if (summary.removedCustomRules > 0) details.push(`${summary.removedCustomRules} 条自定义规则`)
                if (summary.removedRuleSets > 0) details.push(`${summary.removedRuleSets} 组规则集`)
                if (summary.removedRemoteReferences > 0) details.push(`${summary.removedRemoteReferences} 条远程引用`)
                const referenced = summary.referencingGroups.map((name) => groupDisplayName(name, true))
                return (
                  <>
                    将删除 <b>「{pendingGroupDelete.name}」</b>
                    {details.length > 0 ? `，同时移除 ${details.join('、')}。` : '。'}
                    {referenced.length === 0
                      ? '其他策略组里的引用也会一并移除。'
                      : `候选里引用它的策略组：${referenced.join('、')}，这些候选会一并移除。`}
                  </>
                )
              })()}
              此操作会先复制为自定义方案，内置方案本身不受影响。
            </>
          )}
          confirmLabel="删除策略组"
          danger
          confirmDisabled={readOnly}
          onCancel={() => setPendingGroupDelete(null)}
          onConfirm={() => deleteNodeGroup(scheme, pendingGroupDelete)}
        />
      )}

      <ConfirmDialog
        open={!!pendingRuleSetRemove}
        title="从当前方案移除规则集？"
        body={(
          <>
            {pendingRuleSetRemove?.providerOnly ? (
              <>
                将移除 <b>「{pendingRuleSetRemove.name}」</b>的远程 provider 引用（不保存正文），
                方案里引用它的 RULE-SET 会一并删除。
              </>
            ) : (
              <>将移除 <b>「{pendingRuleSetRemove?.name}」</b>的 {pendingRuleSetRemove?.rules.length ?? 0} 条规则。</>
            )}
            {describeRuleSetRemovalImpact(pendingRuleSetRemove
              ? ruleSetExclusions[pendingRuleSetRemove.id]?.length ?? 0
              : 0)}
          </>
        )}
        confirmLabel="移除"
        danger
        confirmDisabled={readOnly}
        onCancel={() => setPendingRuleSetRemove(null)}
        onConfirm={confirmRemoveSchemeRuleSet}
      />

      <ConfirmDialog
        open={!!pendingLocalSetDelete}
        title="删除本地规则集？"
        body={<>将删除 <b>「{pendingLocalSetDelete?.name}」</b>。已加入方案的规则集快照不会被移除。</>}
        confirmLabel="删除"
        danger
        confirmDisabled={readOnly}
        onCancel={() => setPendingLocalSetDelete(null)}
        onConfirm={() => {
          const target = pendingLocalSetDelete
          setPendingLocalSetDelete(null)
          if (target) onDeleteLocalSet(target)
        }}
      />
    </>
  )
}
