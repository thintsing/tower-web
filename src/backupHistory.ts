// 本机备份版本历史：只保留最近几份快照，供恢复前回退。
// 快照和备份文件一样含订阅地址与节点凭据，只写本机 localStorage。
import {
  backupCounts,
  createBackup,
  parseBackup,
  type BackupCounts,
  type BackupFile,
  type PersistedData,
} from './backup'

export const BACKUP_HISTORY_KEY = 'tower-web-backup-history'
export const MAX_BACKUP_HISTORY = 3
/** localStorage 通常只有 5 MB 左右，给正在使用的状态留出余量。 */
export const MAX_BACKUP_HISTORY_BYTES = 3 * 1024 * 1024

export class BackupHistoryError extends Error {}

export interface BackupHistoryEntry {
  id: string
  createdAt: string
  /** 记录这份快照是在什么操作前保存的。 */
  label: string
  file: BackupFile
}

export interface BackupHistoryItem {
  id: string
  createdAt: string
  label: string
  counts: BackupCounts
  bytes: number
}

function storageOr(storage?: Storage): Storage {
  if (storage) return storage
  try {
    return window.localStorage
  } catch {
    throw new BackupHistoryError('当前浏览器无法使用本机版本历史')
  }
}

function sizeOf(entry: BackupHistoryEntry): number {
  return JSON.stringify(entry).length
}

/** 按数量和体积裁剪；新的排在最前，先丢最旧的快照。 */
export function pruneBackupHistory(
  entries: BackupHistoryEntry[],
  maxCount = MAX_BACKUP_HISTORY,
  maxBytes = MAX_BACKUP_HISTORY_BYTES,
): BackupHistoryEntry[] {
  const kept = entries.slice(0, Math.max(0, maxCount))
  let total = kept.reduce((sum, entry) => sum + sizeOf(entry), 0)
  while (kept.length > 1 && total > maxBytes) {
    const removed = kept.pop()
    if (removed) total -= sizeOf(removed)
  }
  return kept
}

function validEntry(value: unknown): BackupHistoryEntry | undefined {
  if (typeof value !== 'object' || value === null) return undefined
  const record = value as Record<string, unknown>
  if (typeof record.id !== 'string' || typeof record.createdAt !== 'string') return undefined
  if (typeof record.label !== 'string' || typeof record.file !== 'object' || record.file === null) {
    return undefined
  }
  try {
    const file = parseBackup(JSON.stringify(record.file))
    return { id: record.id, createdAt: record.createdAt, label: record.label, file }
  } catch {
    return undefined
  }
}

/** 读取历史；损坏的条目直接丢弃，不让一份坏快照挡住其他版本。 */
export function readBackupHistory(storage?: Storage): BackupHistoryEntry[] {
  let raw: string | null
  try {
    raw = storageOr(storage).getItem(BACKUP_HISTORY_KEY)
  } catch {
    return []
  }
  if (!raw) return []
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return []
  }
  if (!Array.isArray(parsed)) return []
  return pruneBackupHistory(parsed.map(validEntry).filter((entry): entry is BackupHistoryEntry => !!entry))
}

function writeBackupHistory(entries: BackupHistoryEntry[], storage?: Storage): void {
  try {
    storageOr(storage).setItem(BACKUP_HISTORY_KEY, JSON.stringify(entries))
  } catch {
    throw new BackupHistoryError('本机存储空间不足，无法保存版本历史')
  }
}

export function backupHistoryItems(entries: BackupHistoryEntry[]): BackupHistoryItem[] {
  return entries.map((entry) => ({
    id: entry.id,
    createdAt: entry.createdAt,
    label: entry.label,
    counts: backupCounts(entry.file.data),
    bytes: sizeOf(entry),
  }))
}

export function newHistoryID(now = Date.now()): string {
  return `backup-${now}-${Math.random().toString(36).slice(2, 8)}`
}

/** 保存一份当前快照。内容过大或空间不足时抛出可读错误。 */
export function saveBackupHistory(
  data: PersistedData,
  label: string,
  now = Date.now(),
  storage?: Storage,
): BackupHistoryEntry {
  const file = createBackup(data, now)
  const entry: BackupHistoryEntry = {
    id: newHistoryID(now),
    createdAt: file.exportedAt,
    label: label.trim() || '手动保存',
    file,
  }
  const bytes = sizeOf(entry)
  if (bytes > MAX_BACKUP_HISTORY_BYTES) {
    throw new BackupHistoryError('当前数据超过 3 MB，无法保存到本机版本历史；请改用导出备份')
  }
  const next = pruneBackupHistory([entry, ...readBackupHistory(storage)])
  writeBackupHistory(next, storage)
  return entry
}

export function removeBackupHistory(id: string, storage?: Storage): void {
  writeBackupHistory(readBackupHistory(storage).filter((entry) => entry.id !== id), storage)
}

export function clearBackupHistory(storage?: Storage): void {
  try {
    storageOr(storage).removeItem(BACKUP_HISTORY_KEY)
  } catch {
    throw new BackupHistoryError('无法清除本机版本历史')
  }
}
