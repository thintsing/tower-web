// 工作区体积与 413 文案：必须在失败提示里说清「多大、上限多少、哪里占最多」，
// 否则用户只知道保存失败，不知道从哪减。
import type { WorkspaceData } from './workspaceValidation'

export const WORKSPACE_MAX_BYTES = 16 * 1024 * 1024

export interface WorkspaceSizeItem {
  label: string
  bytes: number
}

export interface WorkspaceSizeReport {
  bytes: number
  limitBytes: number
  overBytes: number
  largest: WorkspaceSizeItem[]
  message: string
}

export function utf8Bytes(text: string): number {
  return new TextEncoder().encode(text).length
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  if (bytes < 1024) return `${Math.round(bytes)} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function bytesOf(value: unknown): number {
  try {
    return utf8Bytes(JSON.stringify(value))
  } catch {
    return 0
  }
}

/** 计算会真正发给服务端的 JSON 体积；未知字段也要计入，否则会低估。 */
export function workspacePayloadBytes(
  data: WorkspaceData,
  unknown: Record<string, unknown> = {},
): number {
  return bytesOf({ ...unknown, ...data })
}

export function describeWorkspaceTooLarge(
  data: WorkspaceData,
  unknown: Record<string, unknown> = {},
  limitBytes = WORKSPACE_MAX_BYTES,
): WorkspaceSizeReport {
  const bytes = workspacePayloadBytes(data, unknown)
  const largest: WorkspaceSizeItem[] = []
  for (const ruleSet of data.localRuleSets) {
    largest.push({
      label: `本地规则集「${ruleSet.name || ruleSet.id}」`,
      bytes: bytesOf(ruleSet),
    })
  }
  for (const [id, snapshot] of Object.entries(data.schemeSnapshots)) {
    largest.push({
      label: `固化快照 #${id}「${snapshot.scheme?.name || snapshot.schemeID || id}」`,
      bytes: bytesOf(snapshot),
    })
  }
  for (const scheme of data.customSchemes) {
    largest.push({
      label: `自定义方案「${scheme.name || scheme.id}」`,
      bytes: bytesOf(scheme),
    })
  }
  largest.sort((left, right) => right.bytes - left.bytes)
  const top = largest.filter((item) => item.bytes > 0).slice(0, 4)

  const sizeText = `当前工作区约 ${formatBytes(bytes)}，服务端上限 ${formatBytes(limitBytes)}`
  const whereText = top.length
    ? `占用最大的是 ${top.map((item) => `${item.label}约 ${formatBytes(item.bytes)}`).join('、')}。`
    : ''
  const actionText = bytes > limitBytes
    ? '请删除或精简这些规则集 / 快照，或把大规则集改为从上游加载；缩减后会自动重试保存。'
    : '服务端仍返回容量错误，可能还有其它设备同时写入；本地改动会继续自动重试。'

  return {
    bytes,
    limitBytes,
    overBytes: Math.max(0, bytes - limitBytes),
    largest: top,
    message: `工作区超过容量上限，本次改动尚未保存：${sizeText}。${whereText}${actionText}`,
  }
}
