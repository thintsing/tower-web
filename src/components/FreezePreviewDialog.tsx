// 固化前的变更预览：先看 +N / -M / ~K 与受影响策略组，确认后才写快照。
import { useEffect, useRef } from 'react'
import type { BuiltinSchemeFreezePlan } from '../rules/schemeSnapshots'
import { READONLY_NOTE } from '../util/readOnlyUi'

export function FreezePreviewDialog({
  open,
  schemeName,
  plan,
  confirmDisabled,
  onConfirm,
  onCancel,
}: {
  open: boolean
  schemeName: string
  plan: BuiltinSchemeFreezePlan
  confirmDisabled: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    if (open) ref.current?.showModal()
    else ref.current?.close()
  }, [open])
  const changed = plan.added + plan.removed + plan.modified
  return (
    <dialog ref={ref} onClose={onCancel} className="freeze-dialog">
      <h3>更新并固化「{schemeName}」前的变更预览</h3>
      <div className="freeze-stats">
        <span className="pill positive">+{plan.added}</span>
        <span className="pill negative">−{plan.removed}</span>
        <span className="pill">~{plan.modified}</span>
        <span className="hint">未变 {plan.unchanged} · 规则数 {plan.oldCount} → {plan.newCount}</span>
      </div>
      <p className="confirm-body">
        {changed
          ? `上游内容与当前快照有 ${changed} 条差异；确认后才会写入新快照。`
          : '上游内容与当前快照逐条一致，确认后仍会写入一条新快照（指针切换到这一版）。'}
      </p>
      <div className="freeze-section">
        <h4>受影响的策略组（{plan.groups.length}）</h4>
        {plan.groups.length ? (
          <ul className="freeze-groups">
            {plan.groups.map((group) => (
              <li key={group.group}>
                <span className="pill">{group.group}</span>
                <span className="hint">
                  {group.added ? `+${group.added} ` : ''}
                  {group.removed ? `−${group.removed} ` : ''}
                  {group.modified ? `~${group.modified}` : ''}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="hint">没有规则归属发生变化的策略组。</div>
        )}
      </div>
      <div className="freeze-section">
        <h4>引用了旧规则集的自定义方案（{plan.affectedSchemes.length}）</h4>
        {plan.affectedSchemes.length ? (
          <div className="hint">{plan.affectedSchemes.join('、')}。更新后请检查它们的规则集引用是否仍然可用。</div>
        ) : (
          <div className="hint">没有自定义方案引用当前快照的规则集 id / 源地址。</div>
        )}
      </div>
      <div className="hint">
        确认后才写入快照；原厂快照保留，固化仍保留最近 3 版环形，可随时回退。
        已导出的客户端配置不会自动回滚，需要重新导出或让客户端刷新订阅。
      </div>
      <div className="actions">
        <button
          type="button"
          className="btn primary"
          disabled={confirmDisabled}
          title={confirmDisabled ? READONLY_NOTE : undefined}
          onClick={onConfirm}
        >确认更新并固化</button>
        <button type="button" className="btn ghost" autoFocus onClick={onCancel}>取消</button>
      </div>
    </dialog>
  )
}
