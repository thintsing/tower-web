import { useId, useState, type ReactNode } from 'react'
import { readAdvancedPref, writeAdvancedPref } from '../flow/prefs'

interface AdvancedSectionProps {
  /** 按设备记忆的键，例如 rules-tools / export-prefs。 */
  scope: string
  title: string
  summary?: string
  children: ReactNode
  defaultOpen?: boolean
}

/**
 * 高级区折叠容器：默认收起，展开状态写入 localStorage，按设备记住。
 * 用真实 button + aria-expanded，键盘可达；不产生浮层，不会遮挡页面。
 */
export function AdvancedSection({ scope, title, summary, children, defaultOpen = false }: AdvancedSectionProps) {
  const [open, setOpen] = useState(() => readAdvancedPref(scope, defaultOpen))
  const contentId = useId()

  const toggle = () => {
    setOpen((value) => {
      const next = !value
      writeAdvancedPref(scope, next)
      return next
    })
  }

  return (
    <section className={`advanced-section${open ? ' is-open' : ''}`}>
      <button
        type="button"
        className="advanced-toggle"
        aria-expanded={open}
        aria-controls={contentId}
        onClick={toggle}
      >
        <span className="advanced-toggle-text">
          <span className="advanced-kicker">高级</span>
          <span className="advanced-title">{title}</span>
          {summary && <span className="advanced-summary">{summary}</span>}
        </span>
        <span className="advanced-chevron" aria-hidden="true">{open ? '−' : '+'}</span>
      </button>
      {open && <div className="advanced-body" id={contentId}>{children}</div>}
    </section>
  )
}
