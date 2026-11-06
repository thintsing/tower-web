// 内置方案固化快照的纯逻辑：校验、指针解引用、环形淘汰、回退计划。
// 放在这里而不是 store / App 里，方便自检脚本直接调用。
import type {
  BuiltinSchemeOverrideRef,
  BuiltinSchemeSnapshot,
  BuiltinSchemeSnapshotContent,
  LocalRuleSet,
  RuleScheme,
  SchemeRuleSet,
} from '../models/types'
import { MAX_BUILTIN_SCHEME_SNAPSHOTS } from '../models/types'
import { ruleSignature } from './ruleDiff'

const COMMIT_SHA = /^[0-9a-f]{40}$/i

/** 沿用上游固化记录的口径：方案结构、commit、逐文件 blob、条数都要齐全。 */
export function isBuiltinSchemeSnapshotValid(value: unknown): value is BuiltinSchemeSnapshot {
  if (!value || typeof value !== 'object') return false
  const snapshot = value as Partial<BuiltinSchemeSnapshot>
  if (typeof snapshot.id !== 'number' || !Number.isInteger(snapshot.id) || snapshot.id <= 0) return false
  if (typeof snapshot.schemeID !== 'string' || !snapshot.schemeID) return false
  if (typeof snapshot.createdAt !== 'number' || !Number.isFinite(snapshot.createdAt)) return false
  const scheme = snapshot.scheme as Partial<RuleScheme> | undefined
  if (!scheme || typeof scheme !== 'object') return false
  if (typeof scheme.id !== 'string' || !scheme.id) return false
  if (!Array.isArray(scheme.groups) || !Array.isArray(scheme.rules)) return false
  if (!Array.isArray(snapshot.ruleSets)) return false
  const source = snapshot.source
  if (!source || typeof source !== 'object') return false
  if (typeof source.iniURL !== 'string' || !source.iniURL) return false
  if (typeof source.commitSha !== 'string' || !COMMIT_SHA.test(source.commitSha)) return false
  // 文件列表可以为空：方案可能全部规则内联、没有任何 .list 引用；旧版固化记录
  // 也可能只存了 iniURL。把空列表判成损坏会整份丢掉仍然可用的固化内容。
  if (!Array.isArray(source.files)) return false
  if (typeof source.fetchedAt !== 'number' || !Number.isFinite(source.fetchedAt)) return false
  if (typeof source.ruleCount !== 'number' || source.ruleCount !== scheme.rules.length) return false
  if (typeof source.ruleSetCount !== 'number' || source.ruleSetCount !== snapshot.ruleSets.length) return false
  return true
}

/**
 * 把固化快照里的列表快照挂回方案，变成可逐条屏蔽的只读规则集。
 *
 * 关键约束：快照的 scheme.rules 里已经内联了这些列表的全部规则，所以挂回来的
 * 规则集必须带 `inlined: true`，编译与导出时不再作为独立块插入。
 * 没有任何屏蔽时，输出与「不挂规则集」逐字节一致（自检 selfcheck-upstream 比对六种格式）。
 *
 * 同时给内联规则补上 sourceSetId / sourceName，让诊断能把它们识别为只读来源并给出「屏蔽」而不是「删除」。
 * 旧快照的 LocalRuleSet 没有 group，按方案里同签名的第一条规则反推。
 */
export function attachSnapshotRuleSets(
  scheme: RuleScheme,
  localRuleSets: LocalRuleSet[] | undefined,
): RuleScheme {
  if (!localRuleSets?.length) return scheme
  const groupBySignature = new Map<string, string>()
  for (const rule of scheme.rules) {
    const signature = ruleSignature(rule)
    if (!groupBySignature.has(signature)) groupBySignature.set(signature, rule.group)
  }
  const resolved: Array<{ set: LocalRuleSet; group: string }> = []
  for (const set of localRuleSets) {
    if (!Array.isArray(set.rules) || !set.rules.length) continue
    const declared = typeof set.group === 'string' && set.group.trim() ? set.group.trim() : undefined
    const group = declared ?? set.rules
      .map((rule) => groupBySignature.get(ruleSignature(rule)))
      .find((name): name is string => typeof name === 'string' && name.length > 0)
    // 反推不到策略组说明这批规则不在 scheme.rules 里：挂上去也无法屏蔽，直接跳过。
    if (!group) continue
    resolved.push({ set, group })
  }
  if (!resolved.length) return scheme

  const ownerBySignature = new Map<string, { id: string; name: string }>()
  for (const { set } of resolved) {
    for (const rule of set.rules) {
      const signature = ruleSignature(rule)
      if (!ownerBySignature.has(signature)) ownerBySignature.set(signature, { id: set.id, name: set.name })
    }
  }
  let rulesChanged = false
  const rules = scheme.rules.map((rule) => {
    if (rule.sourceSetId) return rule
    const owner = ownerBySignature.get(ruleSignature(rule))
    if (!owner) return rule
    rulesChanged = true
    return { ...rule, sourceSetId: owner.id, sourceName: owner.name }
  })

  const ruleSets: SchemeRuleSet[] = resolved.map(({ set, group }) => ({
    id: set.id,
    name: set.name,
    group,
    rules: set.rules.map((rule) => ({ ...rule, group })),
    sourceKind: set.sourceURL ? 'url' : 'library',
    sourceRef: set.sourceURL,
    format: set.format,
    updatedAt: set.updatedAt,
    // 规则已在 scheme.rules 内联；只参与展示与屏蔽，不再单独插入规则块。
    inlined: true,
  }))
  return { ...scheme, rules: rulesChanged ? rules : scheme.rules, ruleSets }
}

/** 某个内置方案的快照，按 id 从新到旧。 */
export function snapshotsForScheme(
  snapshots: Record<string, BuiltinSchemeSnapshot>,
  schemeID: string,
): BuiltinSchemeSnapshot[] {
  return Object.values(snapshots)
    .filter((snapshot) => snapshot && snapshot.schemeID === schemeID && isBuiltinSchemeSnapshotValid(snapshot))
    .sort((a, b) => b.id - a.id)
}

export interface SnapshotResolution {
  snapshot?: BuiltinSchemeSnapshot
  /** 指针存在但指向的版本不可用（缺失或结构损坏）。 */
  missingId?: number
  /** current = 指针命中；previous = 回落到同方案上一版；factory = 原厂快照。 */
  fallback: 'current' | 'previous' | 'factory'
}

/**
 * 解引用：当前指针可用就用；损坏或缺失时回落到同方案上一版，再不行让调用方读原厂。
 */
export function resolveBuiltinSchemeSnapshot(
  schemeID: string,
  overrides?: Record<string, BuiltinSchemeOverrideRef>,
  snapshots?: Record<string, BuiltinSchemeSnapshot>,
): SnapshotResolution {
  const ref = overrides?.[schemeID]
  if (!ref || typeof ref.snapshotId !== 'number') return { fallback: 'factory' }
  const store = snapshots ?? {}
  const exact = store[String(ref.snapshotId)]
  if (exact && exact.schemeID === schemeID && isBuiltinSchemeSnapshotValid(exact)) {
    return { snapshot: exact, fallback: 'current' }
  }
  const previous = snapshotsForScheme(store, schemeID)
    .find((snapshot) => snapshot.id < ref.snapshotId)
  if (previous) return { snapshot: previous, missingId: ref.snapshotId, fallback: 'previous' }
  return { missingId: ref.snapshotId, fallback: 'factory' }
}

/** 下一个全局自增 id：保证淘汰 / 回退后不会复用旧 id。 */
export function nextSnapshotID(
  snapshots: Record<string, BuiltinSchemeSnapshot>,
  snapshotSeq: number,
): number {
  const ids = Object.values(snapshots)
    .map((snapshot) => (typeof snapshot?.id === 'number' && Number.isFinite(snapshot.id) ? snapshot.id : 0))
  return Math.max(snapshotSeq || 0, ...ids) + 1
}

/**
 * 环形淘汰：每个方案只留最近 MAX 个；被覆盖层指针引用、或被自定义方案引用了
 * 其规则集 id 的快照永不淘汰（可能暂时多于 MAX）。
 */
export function pruneBuiltinSchemeSnapshots(
  snapshots: Record<string, BuiltinSchemeSnapshot>,
  overrides: Record<string, BuiltinSchemeOverrideRef>,
  protectedRuleSetIDs?: Iterable<string>,
): Record<string, BuiltinSchemeSnapshot> {
  const protectedIDs = new Set<string>(protectedRuleSetIDs ?? [])
  const referenced = new Set<number>(
    Object.values(overrides)
      .map((ref) => ref?.snapshotId)
      .filter((id): id is number => typeof id === 'number'),
  )
  const keep = new Set<number>()
  const byScheme = new Map<string, BuiltinSchemeSnapshot[]>()
  for (const snapshot of Object.values(snapshots)) {
    if (!snapshot || !isBuiltinSchemeSnapshotValid(snapshot)) continue
    const list = byScheme.get(snapshot.schemeID) ?? []
    list.push(snapshot)
    byScheme.set(snapshot.schemeID, list)
  }
  for (const list of byScheme.values()) {
    list.sort((a, b) => b.id - a.id)
    for (const snapshot of list.slice(0, MAX_BUILTIN_SCHEME_SNAPSHOTS)) keep.add(snapshot.id)
    for (const snapshot of list) {
      if (referenced.has(snapshot.id)) keep.add(snapshot.id)
      if (snapshot.ruleSets.some((ruleSet) => protectedIDs.has(ruleSet.id))) keep.add(snapshot.id)
    }
  }
  const out: Record<string, BuiltinSchemeSnapshot> = {}
  for (const id of keep) {
    const snapshot = snapshots[String(id)]
    if (snapshot) out[String(id)] = snapshot
  }
  return out
}

export interface SnapshotWriteResult {
  snapshot: BuiltinSchemeSnapshot
  snapshots: Record<string, BuiltinSchemeSnapshot>
  overrides: Record<string, BuiltinSchemeOverrideRef>
  snapshotSeq: number
}

/** 固化一次：写快照、改指针、淘汰旧版。 */
export function writeBuiltinSchemeSnapshot(
  snapshots: Record<string, BuiltinSchemeSnapshot>,
  overrides: Record<string, BuiltinSchemeOverrideRef>,
  snapshotSeq: number,
  schemeID: string,
  content: BuiltinSchemeSnapshotContent,
  createdAt: number,
  protectedRuleSetIDs?: Iterable<string>,
): SnapshotWriteResult {
  const id = nextSnapshotID(snapshots, snapshotSeq)
  const snapshot: BuiltinSchemeSnapshot = { ...content, id, schemeID, createdAt }
  const nextSnapshots = { ...snapshots, [String(id)]: snapshot }
  const nextOverrides = { ...overrides, [schemeID]: { snapshotId: id } }
  return {
    snapshot,
    snapshots: pruneBuiltinSchemeSnapshots(nextSnapshots, nextOverrides, protectedRuleSetIDs),
    overrides: nextOverrides,
    snapshotSeq: id,
  }
}

export interface SnapshotRollbackPlan {
  target: BuiltinSchemeSnapshot
  current?: BuiltinSchemeSnapshot
  fromCount: number
  toCount: number
  /** 规则集 id 与被回退版本重合的自定义方案。 */
  affectedSchemes: string[]
  message: string
}

/**
 * 回退前的提示：规则数变化、受影响方案、已导出配置不会自动回滚。
 * `factoryRuleCount` 用于当前指针缺失（原厂）时仍给出数字。
 */
export function planSnapshotRollback(args: {
  snapshots: Record<string, BuiltinSchemeSnapshot>
  overrides: Record<string, BuiltinSchemeOverrideRef>
  customSchemes: Pick<RuleScheme, 'name' | 'ruleSets'>[]
  schemeID: string
  targetID: number
  factoryRuleCount?: number
}): SnapshotRollbackPlan | undefined {
  const target = args.snapshots[String(args.targetID)]
  if (!target || target.schemeID !== args.schemeID || !isBuiltinSchemeSnapshotValid(target)) return undefined
  const currentRef = args.overrides[args.schemeID]
  const current = currentRef ? args.snapshots[String(currentRef.snapshotId)] : undefined
  const validCurrent = current && current.schemeID === args.schemeID && isBuiltinSchemeSnapshotValid(current)
    ? current
    : undefined
  // 规则集 id 只在同一次生成里稳定；方案里的规则集属于「我的规则集」时，
  // 真正能对上的是源地址（sourceRef），所以 id 与地址都要参与比对。
  const replacedIDs = new Set((validCurrent?.ruleSets ?? []).map((ruleSet) => ruleSet.id))
  const replacedRefs = new Set(
    (validCurrent?.ruleSets ?? [])
      .map((ruleSet) => ruleSet.sourceURL)
      .filter((url): url is string => typeof url === 'string' && url.length > 0),
  )
  const affectedSchemes = args.customSchemes
    .filter((scheme) => (scheme.ruleSets ?? []).some((ruleSet) => {
      if (replacedIDs.has(ruleSet.id)) return true
      const ref = ruleSet.sourceRef
      return typeof ref === 'string' && ref.length > 0 && (replacedRefs.has(ref) || replacedIDs.has(ref))
    }))
    .map((scheme) => scheme.name)
  const fromCount = validCurrent?.scheme.rules.length ?? args.factoryRuleCount ?? target.scheme.rules.length
  const toCount = target.scheme.rules.length
  const affected = affectedSchemes.length ? affectedSchemes.join('、') : '无'
  return {
    target,
    current: validCurrent,
    fromCount,
    toCount,
    affectedSchemes,
    message: `规则数 ${fromCount} → ${toCount} 条；受影响的自定义方案：${affected}。已导出的客户端配置不会自动回滚，需要重新导出或让客户端刷新订阅。`,
  }
}
