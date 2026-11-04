// localStorage 包装：配额满时不能让异常从状态更新里抛出。
// zustand 的 persist 默认直接用 localStorage，setItem 抛 QuotaExceededError
// 时会从每个 set() 调用里冒出来，导致刷新订阅/切换开关直接失败。
export interface KeyValueStorage {
  getItem(name: string): string | null
  setItem(name: string, value: string): void
  removeItem(name: string): void
}

export const STORAGE_FULL_EVENT = 'tower:storage-full'

let full = false
const listeners = new Set<(value: boolean) => void>()

export function isStorageFull(): boolean {
  return full
}

export function onStorageFullChange(listener: (value: boolean) => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function markFull(value: boolean) {
  if (full === value) return
  full = value
  for (const listener of listeners) listener(value)
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(STORAGE_FULL_EVENT, { detail: { full: value } }))
  }
}

/**
 * @param resolve 返回底层存储；不可用时返回 null（例如隐私模式或 SSR）。
 * @param isQuotaError 只把容量错误标成「存储已满」；其他异常仍然是写入失败。
 */
export function createSafeStorage(
  resolve: () => KeyValueStorage | null,
  isQuotaError: (error: unknown) => boolean = defaultIsQuotaError,
): KeyValueStorage {
  const withStore = <T>(run: (store: KeyValueStorage) => T, fallback: T): T => {
    const store = resolve()
    if (!store) return fallback
    try {
      return run(store)
    } catch (error) {
      if (isQuotaError(error)) markFull(true)
      return fallback
    }
  }

  return {
    getItem: (name) => withStore((store) => store.getItem(name), null),
    setItem: (name, value) => {
      const store = resolve()
      if (!store) return
      try {
        store.setItem(name, value)
        markFull(false)
      } catch (error) {
        if (isQuotaError(error)) markFull(true)
      }
    },
    removeItem: (name) => withStore((store) => store.removeItem(name), undefined),
  }
}

function defaultIsQuotaError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false
  const name = (error as { name?: unknown }).name
  const code = (error as { code?: unknown }).code
  return name === 'QuotaExceededError'
    || name === 'NS_ERROR_DOM_QUOTA_REACHED'
    || code === 22
    || code === 1014
}

export function browserStorage(): KeyValueStorage | null {
  try {
    return typeof window === 'undefined' ? null : window.localStorage
  } catch {
    return null
  }
}

type ClearableStorage = Pick<Storage, 'length' | 'key' | 'removeItem'>

/**
 * 重置本机数据时只删除塔台自己的键。
 * `localStorage.clear()` 会把同源下其它应用（同一局域网域名下的工具页）的数据
 * 一起清空；塔台的键统一以 `tower` 开头，可以精确清理。
 * @returns 实际删除的键，供自检和提示使用。
 */
export function clearTowerStorage(storage?: ClearableStorage | null): string[] {
  const store = storage ?? (typeof window === 'undefined' ? null : window.localStorage)
  if (!store) return []
  const keys: string[] = []
  try {
    for (let index = 0; index < store.length; index += 1) {
      const key = store.key(index)
      if (key && key.startsWith('tower')) keys.push(key)
    }
  } catch {
    return []
  }
  const removed: string[] = []
  for (const key of keys) {
    try {
      store.removeItem(key)
      removed.push(key)
    } catch {
      // 隐私模式或存储不可用时忽略单条失败。
    }
  }
  return removed
}
