// 只读模式下写操作入口的统一禁用态：真实 disabled 优先，无法 disabled 的
// 元素（summary / 自定义 div / 菜单项）退回 aria-disabled，样式统一在 styles.css。
export const READONLY_NOTE = '只读模式：服务端离线，改动不会保存'

interface WriteGuardProps {
  disabled?: boolean
  'aria-disabled'?: boolean
  title?: string
}

/** 原生 <button> / <input> / <select>：真实 disabled。 */
export function writeGuard(readOnly: boolean): WriteGuardProps {
  if (!readOnly) return {}
  return { disabled: true, 'aria-disabled': true, title: READONLY_NOTE }
}

/** 不能 disabled 的元素：aria-disabled + title，由 CSS 关掉指针事件。 */
export function writeGuardAria(readOnly: boolean): WriteGuardProps {
  if (!readOnly) return {}
  return { 'aria-disabled': true, title: READONLY_NOTE }
}
