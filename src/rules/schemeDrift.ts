// 内置方案上游漂移：把「定时检查拿到的 commit / blob sha」和「规则 diff」接起来。
// 只做对比与展示，绝不自动应用；用户点「吸收」才走现有的更新并固化流程，
// 点「忽略」则记住该 commit，直到上游再次变化。
import type { RuleScheme, RuleSetDiffSample } from '../models/types'
import { summarizeRuleSetRefresh } from './ruleSetRefresh'
import type { SchemeMeta } from './scheme'

export type DriftStatus = 'update' | 'current' | 'unknown'

/** 与现有上游检查保持同一套文案口径。 */
export const DRIFT_STATUS_LABELS: Record<DriftStatus, string> = {
  update: '上游有更新',
  current: '已是最新',
  unknown: '查不到（这不等于没有更新）',
}

export interface SchemeDrift {
  schemeID: string
  /** 上游版本：优先 commit SHA，退化为检查结果里的短 SHA。 */
  version: string
  added: number
  removed: number
  modified: number
  total: number
  samples: RuleSetDiffSample[]
  hidden: number
  checkedAt: number
}

/** 当前方案规则 vs 上游最新方案的净变化；期数全部基于规范化后的规则签名。 */
export function computeSchemeDrift(
  current: RuleScheme,
  upstream: RuleScheme,
  version: string,
  at = Date.now(),
): SchemeDrift {
  const diff = summarizeRuleSetRefresh(current.rules, upstream.rules, at)
  return {
    schemeID: upstream.id,
    version,
    added: diff.added,
    removed: diff.removed,
    modified: diff.modified,
    total: diff.added + diff.removed + diff.modified,
    samples: diff.samples,
    hidden: diff.hidden,
    checkedAt: at,
  }
}

/**
 * 忽略某条规则集到指定上游版本为止。
 * 版本号变化（上游再次提交）后重新提示；没有版本号时不记忆，避免永久静默。
 */
export function shouldPromptDrift(version: string | undefined, ignored?: string): boolean {
  if (!version) return true
  return ignored !== version
}

const IGNORE_KEY = 'tower-web-drift-ignored-v1'

export function readIgnoredDriftVersions(): Record<string, string> {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return {}
    const raw = window.localStorage.getItem(IGNORE_KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
    const result: Record<string, string> = {}
    for (const [key, value] of Object.entries(parsed)) {
      if (typeof value === 'string') result[key] = value
    }
    return result
  } catch {
    return {}
  }
}

export function ignoredDriftVersion(schemeID: string): string | undefined {
  return readIgnoredDriftVersions()[schemeID]
}

export function ignoreDriftVersion(schemeID: string, version: string): void {
  if (!schemeID || !version) return
  try {
    if (typeof window === 'undefined' || !window.localStorage) return
    const map = readIgnoredDriftVersions()
    map[schemeID] = version
    window.localStorage.setItem(IGNORE_KEY, JSON.stringify(map))
  } catch {
    // 隐私模式 / 配额满时忽略记忆；下次打开会重新提示，不影响主流程。
  }
}

export function clearIgnoredDriftVersion(schemeID: string): void {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return
    const map = readIgnoredDriftVersions()
    delete map[schemeID]
    window.localStorage.setItem(IGNORE_KEY, JSON.stringify(map))
  } catch {
    // 同上：清不掉最多多提示一次。
  }
}

/** 内存缓存：同一 scheme + 上游版本只抓一次完整上游内容。 */
const driftCache = new Map<string, Promise<SchemeDrift>>()

export interface LoadSchemeDriftOptions {
  loadCurrent: () => Promise<RuleScheme | undefined>
  fetchUpstream: (meta: SchemeMeta) => Promise<RuleScheme>
  at?: number
}

export function loadSchemeDrift(
  meta: SchemeMeta,
  version: string,
  options: LoadSchemeDriftOptions,
): Promise<SchemeDrift> {
  const key = `${meta.id}:${version}`
  const cached = driftCache.get(key)
  if (cached) return cached
  const request = (async () => {
    const current = await options.loadCurrent()
    if (!current) throw new Error('当前方案还没有加载完成')
    const upstream = await options.fetchUpstream(meta)
    return computeSchemeDrift(current, upstream, version, options.at ?? Date.now())
  })()
  driftCache.set(key, request)
  // 失败不缓存：用户手动重试时还能再抓一次。
  request.catch(() => driftCache.delete(key))
  return request
}
