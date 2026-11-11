// 规则集版本历史：只保留最近一次刷新前的快照，容量超限时退化为摘要，避免撑爆 localStorage。
import type { RuleSetRuleLike } from './ruleDiff'
import { normalizeRule } from './ruleDiff'

const STORAGE_KEY = 'tower-web-ruleset-history-v1'
const MAX_RULES = 5000
const MAX_BYTES = 900 * 1024
/** 单个浏览器最多保留多少个规则集的历史，避免条目无限增长。 */
const MAX_ENTRIES = 200

export interface RuleSetSnapshot {
  at: number
  count: number
  digest: string
  /** 规则明细；超出容量时省略，只保留摘要。 */
  rules?: RuleSetRuleLike[]
  truncated?: boolean
}

export interface RuleSetHistoryEntry {
  previous?: RuleSetSnapshot
}

export type RuleSetHistory = Record<string, RuleSetHistoryEntry>

function storage(): Storage | null {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return null
    return window.localStorage
  } catch {
    return null
  }
}

/** 稳定摘要：按规则签名排序后做 FNV-1a，顺序变化不会改变结果。 */
export function digestRules(rules: RuleSetRuleLike[]): string {
  const signatures = [...new Set(rules.map((rule) => normalizeRule(rule).signature))].sort()
  let hash = 0x811c9dc5
  for (const signature of signatures) {
    for (let index = 0; index < signature.length; index += 1) {
      hash ^= signature.charCodeAt(index)
      hash = (hash * 0x01000193) >>> 0
    }
  }
  return hash.toString(16).padStart(8, '0')
}

function isRuleLike(value: unknown): value is RuleSetRuleLike {
  if (!value || typeof value !== 'object') return false
  const rule = value as Partial<RuleSetRuleLike>
  return typeof rule.type === 'string' && (rule.value === undefined || typeof rule.value === 'string')
}

/** 整组校验：只要有一条明细损坏，就丢弃整份明细只保留摘要，避免 diff 展示残缺数据。 */
function sanitizeRules(value: unknown): RuleSetRuleLike[] | undefined {
  if (!Array.isArray(value)) return undefined
  if (!value.every(isRuleLike)) return undefined
  return value
}

export function readRuleSetHistory(): RuleSetHistory {
  const store = storage()
  // 用无原型对象，避免 setID 为 `__proto__` 时被当成原型赋值而静默丢失。
  const empty = (): RuleSetHistory => Object.create(null) as RuleSetHistory
  if (!store) return empty()
  try {
    const raw = store.getItem(STORAGE_KEY)
    if (!raw) return empty()
    const parsed = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return empty()
    const result = empty()
    for (const [key, value] of Object.entries(parsed)) {
      if (!value || typeof value !== 'object') continue
      const entry = value as RuleSetHistoryEntry
      const previous = entry.previous
      if (!previous || typeof previous.at !== 'number' || typeof previous.digest !== 'string') continue
      const rules = sanitizeRules(previous.rules)
      result[key] = {
        previous: {
          at: previous.at,
          count: typeof previous.count === 'number' ? previous.count : 0,
          digest: previous.digest,
          rules,
          truncated: !!previous.truncated || (Array.isArray(previous.rules) && !rules),
        },
      }
    }
    return result
  } catch {
    return empty()
  }
}

function writeRuleSetHistory(history: RuleSetHistory): void {
  const store = storage()
  if (!store) return
  try {
    store.setItem(STORAGE_KEY, JSON.stringify(history))
  } catch {
    // 配额不足：丢掉体积最大的明细，只留摘要。
    try {
      const trimmed = Object.create(null) as RuleSetHistory
      for (const [key, entry] of Object.entries(history)) {
        trimmed[key] = {
          previous: entry.previous
            ? { ...entry.previous, rules: undefined, truncated: true }
            : undefined,
        }
      }
      store.setItem(STORAGE_KEY, JSON.stringify(trimmed))
    } catch {
      // 仍然写不进去就放弃本次历史记录，不影响刷新流程。
    }
  }
}

/** 超过容量上限时只保留时间较新的条目。 */
function pruneHistory(history: RuleSetHistory): void {
  const keys = Object.keys(history)
  if (keys.length <= MAX_ENTRIES) return
  keys
    .sort((left, right) => (history[left]?.previous?.at ?? 0) - (history[right]?.previous?.at ?? 0))
    .slice(0, keys.length - MAX_ENTRIES)
    .forEach((key) => delete history[key])
}

/** 刷新前调用：保存当前规则作为「上一次快照」。 */
export function recordRuleSetSnapshot(setID: string, rules: RuleSetRuleLike[], enabled = true): void {
  if (!enabled || !setID) return
  const digest = digestRules(rules)
  const history = readRuleSetHistory()
  const snapshot: RuleSetSnapshot = {
    at: Date.now(),
    count: rules.length,
    digest,
  }
  const serialized = JSON.stringify(rules)
  if (rules.length <= MAX_RULES && serialized.length <= MAX_BYTES) {
    snapshot.rules = rules
  } else {
    snapshot.truncated = true
  }
  history[setID] = { previous: snapshot }
  pruneHistory(history)
  writeRuleSetHistory(history)
}

export function previousRuleSetSnapshot(setID: string): RuleSetSnapshot | undefined {
  return readRuleSetHistory()[setID]?.previous
}

export function historySetIDs(): string[] {
  return Object.keys(readRuleSetHistory())
}

export function clearRuleSetHistory(setID?: string): void {
  const store = storage()
  if (!store) return
  if (!setID) {
    try {
      store.removeItem(STORAGE_KEY)
    } catch {
      // 忽略：清不掉也只是多占一点空间。
    }
    return
  }
  const history = readRuleSetHistory()
  delete history[setID]
  writeRuleSetHistory(history)
}
