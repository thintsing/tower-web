// localStorage 包装：配额满时不能让异常从状态更新里抛出。
// zustand 的 persist 默认直接用 localStorage，setItem 抛 QuotaExceededError
// 时会从每个 set() 调用里冒出来，导致刷新订阅/切换开关直接失败。
import { formatBytes } from '../workspaceSize'

export interface KeyValueStorage {
  getItem(name: string): string | null
  setItem(name: string, value: string): void
  removeItem(name: string): void
}

export const STORAGE_FULL_EVENT = 'tower:storage-full'

let full = false
/** 每次容量失败都自增；界面据此判断「这是新一次失败」，而不是永久忽略。 */
let failureSerial = 0
const listeners = new Set<(value: boolean) => void>()

export function isStorageFull(): boolean {
  return full
}

export function getStorageFullSerial(): number {
  return failureSerial
}

export function onStorageFullChange(listener: (value: boolean) => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function markFull(value: boolean) {
  const changed = full !== value
  full = value
  if (value) failureSerial += 1
  // 容量错误可能连续发生：即使 full 已经是 true，也要再通知一次，
  // 否则用户点掉提示后，后续失败会全程无声。
  if (!changed && !value) return
  for (const listener of listeners) listener(value)
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(STORAGE_FULL_EVENT, { detail: { full: value, serial: failureSerial } }))
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

export interface StorageUsage {
  totalBytes: number
  top: Array<{ key: string; bytes: number }>
}

type ReadableStorage = Pick<Storage, 'length' | 'key' | 'getItem'>

/** 估算 localStorage 占用；不可用时返回 null，不影响主提示。 */
export function measureStorage(storage?: ReadableStorage | null): StorageUsage | null {
  const store = storage ?? (typeof window === 'undefined' ? null : window.localStorage)
  if (!store) return null
  try {
    let totalBytes = 0
    const items: Array<{ key: string; bytes: number }> = []
    for (let index = 0; index < store.length; index += 1) {
      const key = store.key(index)
      if (!key) continue
      const value = store.getItem(key) ?? ''
      // 用字符数近似字节数：中文 UTF-8 实际更大，但配额本身按 UTF-16 计，
      // 这里只给用户一个量级，不追求精确。
      const bytes = key.length + value.length
      totalBytes += bytes
      items.push({ key, bytes })
    }
    items.sort((left, right) => right.bytes - left.bytes)
    return { totalBytes, top: items.slice(0, 3) }
  } catch {
    return null
  }
}

export interface StorageFullContext {
  mode?: 'local' | 'server' | 'unknown'
  /** 当前工作区状态；只有 online 才代表改动已经在服务端。 */
  state?: string
}

/**
 * 存储满提示必须区分模式与同步状态：
 * local 模式、或服务器模式下尚未 online 时，改动都只在本机内存里；
 * 只有服务器模式且已 online，写不进去的才只是本机缓存。
 */
export function describeStorageFull(
  context: 'local' | 'server' | StorageFullContext,
  usage?: StorageUsage | null,
): string {
  const mode = typeof context === 'string' ? context : context.mode === 'server' ? 'server' : 'local'
  const synced = typeof context === 'string'
    ? mode === 'server'
    : mode === 'server' && context.state === 'online'
  const base = synced
    ? '浏览器本地缓存已满：改动仍会同步到服务器，刷新后可从服务器恢复；仅本机离线时可能显示旧缓存。建议清理不需要的本机备份历史。'
    : mode === 'server'
      ? '浏览器本地缓存已满：当前改动尚未同步到服务器，刷新页面可能丢失。请先恢复同步，或到「导出」页保存备份后再清理不需要的数据。'
      : '浏览器本地缓存已满：当前修改只保留在内存中，刷新后会丢失。请到「导出」页保存备份，再清理不需要的订阅或规则方案。'
  if (!usage || usage.totalBytes <= 0) return base
  const top = usage.top.length
    ? `占用最大：${usage.top.map((item) => `${item.key}约 ${formatBytes(item.bytes)}`).join('、')}。`
    : ''
  return `${base} 本机 localStorage 已用约 ${formatBytes(usage.totalBytes)}。${top}`
}

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
