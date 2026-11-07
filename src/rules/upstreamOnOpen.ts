// 打开塔台时检查内置方案上游：只在本地模式执行。
// 服务器版由服务端定时任务统一检查并展示，客户端不再重复请求。
import { checkUpstreamUpdate, type UpstreamUpdateCheck } from './upstreamScheme'
import type { SchemeMeta } from './scheme'
import type { BuiltinSchemeOverrideRef, BuiltinSchemeSnapshot } from '../models/types'

export type WorkspaceMode = 'unknown' | 'local' | 'server'

export interface BuiltinUpdateCheckInput {
  mode: WorkspaceMode
  /** 用户设置「打开塔台时检查内置方案是否有上游更新」。 */
  enabled: boolean
  selectedSchemeID: string
  schemes: SchemeMeta[]
  overrides: Record<string, BuiltinSchemeOverrideRef>
  snapshots: Record<string, BuiltinSchemeSnapshot>
}

export interface BuiltinUpdateCheckDeps {
  check?: (meta: SchemeMeta, stored?: { source: BuiltinSchemeSnapshot['source'] }) => Promise<UpstreamUpdateCheck>
  notify: (schemeID: string, message: string) => void
}

/**
 * 返回实际发起的检查数量。
 * 服务器模式、模式未知或未开启设置时返回 0，并且不会调用 check（不发请求）。
 */
export async function runBuiltinUpdateCheckOnOpen(
  input: BuiltinUpdateCheckInput,
  deps: BuiltinUpdateCheckDeps,
): Promise<number> {
  if (input.mode !== 'local' || !input.enabled) return 0
  const check = deps.check ?? checkUpstreamUpdate
  const targets = input.schemes.filter(
    (meta) => meta.id === input.selectedSchemeID || !!input.overrides[meta.id],
  )
  await Promise.all(targets.map(async (meta) => {
    // 覆盖层只存指针，比对上游需要快照正文；损坏时按原厂比对。
    const ref = input.overrides[meta.id]
    const stored = ref ? input.snapshots[String(ref.snapshotId)] : undefined
    const result = await check(meta, stored)
    if (!result.updateAvailable) return
    const changed = result.changedFiles.length
      ? `：${result.changedFiles.slice(0, 3).map((path) => path.split('/').pop()).join('、')}${
        result.changedFiles.length > 3 ? ` 等 ${result.changedFiles.length} 个文件` : ''}`
      : '：方案配置 / 分组有变更'
    deps.notify(
      meta.id,
      `${meta.name} 上游有更新${result.method === 'head' ? '（备用检测）' : ''}${changed}，可点「更新并固化」。`,
    )
  }))
  return targets.length
}
