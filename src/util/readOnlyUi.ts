// 只读模式下写操作入口的统一禁用态：真实 disabled 优先，无法 disabled 的
// 元素（summary / 自定义 div / 菜单项）退回 aria-disabled，样式统一在 styles.css。
// 只读不只在「服务端离线」时出现：未授权、工作区损坏、局域网共享关闭、
// 认证冷却都会进入只读，统一提示不能再写死成离线原因。
export const READONLY_NOTE = '只读模式：工作区当前不可写，改动不会保存'

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
