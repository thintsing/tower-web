// 通用确认弹窗：标题、正文、主/危险按钮，只读时禁用确认。
import { useEffect, useRef, type ReactNode } from 'react'
import { READONLY_NOTE } from '../util/readOnlyUi'

export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel = '确认',
  danger = false,
  confirmDisabled = false,
  onConfirm,
  onCancel,
}: {
  open: boolean
  title: string
  body: ReactNode
  confirmLabel?: string
  danger?: boolean
  /** 只读模式下由调用方传入，写操作的确认按钮不可点。 */
  confirmDisabled?: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    if (open) ref.current?.showModal()
    else ref.current?.close()
  }, [open])
  return (
    <dialog ref={ref} onClose={onCancel} className="confirm">
      <h3>{title}</h3>
      <p className="confirm-body">{body}</p>
      <div className="actions">
        <button
          className={`btn ${danger ? 'danger' : 'primary'}`}
          disabled={confirmDisabled}
          title={confirmDisabled ? READONLY_NOTE : undefined}
          onClick={onConfirm}
        >{confirmLabel}</button>
        <button className="btn ghost" autoFocus onClick={onCancel}>取消</button>
      </div>
    </dialog>
  )
}
