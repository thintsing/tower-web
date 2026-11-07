// 服务端上游检查状态：只读接口 + 手动触发。
// 检查结果由服务端写独立文件，不进入工作区；这里只展示，不固化。
import { apiFetch } from './util/apiAuth'

export type UpstreamSchemeState = 'unknown' | 'update' | 'current' | 'error'

export interface UpstreamSchemeStatus {
  id: string
  name: string
  status: UpstreamSchemeState
  frozen: boolean
  baseline: { kind: 'snapshot' | 'pin'; commitShort: string }
  commit: string | null
  commitShort: string | null
  behindBy: number | null
  method: 'trees' | 'head' | null
  changedFiles: string[]
  error: string
  checkedAt: number | null
}

export interface UpstreamStatusPayload {
  enabled: boolean
  intervalMs: number
  initialDelayMs: number
  checkedAt: number | null
  nextCheckAt: number | null
  trigger: string
  lastError: string
  checking: boolean
  schemes: UpstreamSchemeStatus[]
}

export async function fetchUpstreamStatus(): Promise<UpstreamStatusPayload> {
  const res = await apiFetch('/api/upstream-status', { cache: 'no-store' })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return await res.json() as UpstreamStatusPayload
}

/** 触发一次后台检查；接口立即返回，调用方轮询 fetchUpstreamStatus 等待 checking 结束。 */
export async function triggerUpstreamStatusCheck(): Promise<void> {
  const res = await apiFetch('/api/upstream-status/check', { method: 'POST' })
  if (res.status === 409) {
    const body = await res.json().catch(() => null) as { error?: string } | null
    throw new Error(body?.error ?? '服务端上游定时检查已关闭')
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
}
