// 订阅刷新结果记录：手动「刷新全部」和打开页面时的自动刷新共用。
// 之前批量刷新结束后进度条直接消失，自动刷新失败完全静默；这里把结果留成
// 一份可见的记录，界面负责展示，不弹窗打断。
import { useSyncExternalStore } from 'react'

export type RefreshTrigger = 'manual' | 'auto'

export interface RefreshOutcome {
  id: string
  name: string
  /** 同步失败原因；空串代表这次刷新成功。 */
  error: string
}

export interface RefreshReport {
  trigger: RefreshTrigger
  at: number
  total: number
  succeeded: number
  failures: RefreshOutcome[]
}

let report: RefreshReport | null = null
const listeners = new Set<() => void>()

function emit(): void {
  for (const listener of listeners) listener()
}

export function getRefreshReport(): RefreshReport | null {
  return report
}

export function subscribeRefreshReport(listener: () => void): () => void {
  listeners.add(listener)
  return () => { listeners.delete(listener) }
}

export function useRefreshReport(): RefreshReport | null {
  return useSyncExternalStore(subscribeRefreshReport, getRefreshReport, getRefreshReport)
}

export function publishRefreshReport(next: RefreshReport): void {
  report = next
  emit()
}

export function dismissRefreshReport(): void {
  if (!report) return
  report = null
  emit()
}

/** 把每个订阅的刷新结果收成「成功 X / 失败 Y」。 */
export function buildRefreshReport(
  trigger: RefreshTrigger,
  outcomes: RefreshOutcome[],
  at = Date.now(),
): RefreshReport {
  const failures = outcomes.filter((item) => item.error.trim())
  return {
    trigger,
    at,
    total: outcomes.length,
    succeeded: outcomes.length - failures.length,
    failures,
  }
}

export function describeRefreshReport(report: RefreshReport): string {
  const label = report.trigger === 'auto' ? '打开页面时自动刷新' : '刷新全部'
  return `${label}：成功 ${report.succeeded} / 失败 ${report.failures.length}`
}

/** 失败明细的一行：订阅名 + 原因。 */
export function refreshFailureText(outcome: RefreshOutcome): string {
  return `「${outcome.name}」：${outcome.error}`
}

/**
 * 自动刷新要等工作区状态确定后再跑：
 * 本地模式可以直接刷新；服务器模式必须已在线，否则 store 里可能还是旧缓存，
 * 会按已删除 / 已改地址的订阅刷新，报出根本不存在的失败。
 */
export function autoRefreshReady(mode: 'unknown' | 'local' | 'server', state: string): boolean {
  if (mode === 'local') return true
  return mode === 'server' && state === 'online'
}

/** 手动刷新全部时排除已经在刷新中的订阅，避免同一条重复请求。 */
export function selectRefreshTargets<T extends { id: string }>(
  sources: T[],
  loadingIDs: Iterable<string>,
): T[] {
  const loading = new Set(loadingIDs)
  return sources.filter((source) => !loading.has(source.id))
}
