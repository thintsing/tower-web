// 按设备记住「高级区」展开状态，避免每次进入页面都重置。
// 用 localStorage 而不是 zustand，因为这些是纯界面偏好，不应进入备份/同步数据。

const KEY = 'tower-flow-prefs-v1'

type Prefs = Record<string, boolean>

function readAll(): Prefs {
  try {
    const raw = window.localStorage.getItem(KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? parsed as Prefs : {}
  } catch {
    return {}
  }
}

export function readAdvancedPref(scope: string, fallback = false): boolean {
  const all = readAll()
  return typeof all[scope] === 'boolean' ? all[scope] : fallback
}

export function writeAdvancedPref(scope: string, value: boolean): void {
  try {
    const all = readAll()
    all[scope] = value
    window.localStorage.setItem(KEY, JSON.stringify(all))
  } catch {
    // 隐私模式或存储已满：不记忆也不影响使用。
  }
}

/** 导出成功标记：步骤条用它判断第 4 步是否完成。 */
const EXPORT_MARK = 'tower-exported-at'

export function readExportedAt(): number | undefined {
  try {
    const raw = window.localStorage.getItem(EXPORT_MARK)
    const value = raw ? Number(raw) : NaN
    return Number.isFinite(value) ? value : undefined
  } catch {
    return undefined
  }
}

export function markExported(): void {
  try {
    window.localStorage.setItem(EXPORT_MARK, String(Date.now()))
    window.dispatchEvent(new Event('tower:exported'))
  } catch {
    // 忽略。
  }
}
