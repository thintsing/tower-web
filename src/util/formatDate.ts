/** 统一的时间展示：月-日 时:分；空值返回空串。 */
export function formatDate(ts?: number): string {
  if (!ts) return ''
  return new Date(ts).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}
