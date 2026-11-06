import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  ACL4SSR_API_BASE,
  ACL4SSR_RAW_BASE,
  checkUpstreamUpdate,
  fetchUpstreamScheme,
  UpstreamSchemeError,
  upstreamRawURL,
  type UpstreamTextResult,
} from '../src/rules/upstreamScheme'
import { loadScheme } from '../src/rules/scheme'
import type { SchemeMeta } from '../src/rules/scheme'
import {
  attachSnapshotRuleSets,
  planSnapshotRollback,
  resolveBuiltinSchemeSnapshot,
  snapshotsForScheme,
  writeBuiltinSchemeSnapshot,
} from '../src/rules/schemeSnapshots'
import { normalizeBuiltinSchemes } from '../src/backup'
import type { BuiltinSchemeSnapshot, LocalRuleSet, ProxyNode, RuleScheme, SchemeRuleSet, RoutingRule } from '../src/models/types'
import { CLIENTS, type ClientTarget } from '../src/models/types'
import { addRuleSetExclusion, filterExcludedRuleSets, removeRuleSetExclusion } from '../src/rules/ruleSetExclusions'
import { ruleSignature } from '../src/rules/ruleDiff'
import { orderedSchemeRules } from '../src/rules/ruleOrder'
import { prepareSchemeForExport } from '../src/generator/groups'
import { generateConfig } from '../src/generator'
import { lintScheme } from '../src/rules/schemeLint'
import { createHash } from 'node:crypto'
import { useStore } from '../src/store'
import { setWorkspaceReadOnly } from '../src/util/workspaceLock'

// 只测「上游更新」这一层：注入假 fetcher，不碰真实网络，也不依赖浏览器。
let problems = 0
const fail = (message: string) => {
  problems += 1
  console.error(`✗ ${message}`)
}

const meta: SchemeMeta = {
  id: 'acl4ssr-online',
  name: 'ACL4SSR 在线版',
  description: '内置',
  file: 'ACL4SSR_Online.ini',
}

/** 固定的假 commit，避免测试依赖真实上游。 */
const COMMIT = '0123456789abcdef0123456789abcdef01234567'
const NEXT_COMMIT = 'fedcba9876543210fedcba9876543210fedcba98'
const TREE_URL = `${ACL4SSR_API_BASE}/git/trees/master?recursive=1`

const INI_PATH = 'Clash/config/ACL4SSR_Online.ini'
const APPLE_PATH = 'Clash/Apple.list'
const ADS_PATH = 'Clash/Ads.yaml'
const INI_BLOB = '1'.repeat(40)
const APPLE_BLOB = '2'.repeat(40)
const ADS_BLOB = '3'.repeat(40)

const INI = [
  '[custom]',
  'custom_proxy_group=节点选择`select`[]',
  `ruleset=苹果服务,${ACL4SSR_RAW_BASE}/master/${APPLE_PATH}`,
  `ruleset=广告拦截,clash-classic:${ACL4SSR_RAW_BASE}/master/${ADS_PATH}`,
  'ruleset=直连,[]GEOIP,CN',
  'custom_proxy_group=Final`select`[]DIRECT',
].join('\n')

const LISTS: Record<string, { text: string; etag?: string }> = {
  [APPLE_PATH]: { text: 'DOMAIN-SUFFIX,apple.com\nDOMAIN,icloud.com', etag: 'W/"apple-1"' },
  [ADS_PATH]: { text: 'payload:\n  - DOMAIN-SUFFIX,doubleclick.net', etag: 'W/"ads-1"' },
}

function treeBody(commit = COMMIT, blobs: Record<string, string> = {}): string {
  return JSON.stringify({
    sha: commit,
    truncated: false,
    tree: [
      { path: INI_PATH, sha: INI_BLOB, type: 'blob' },
      { path: APPLE_PATH, sha: blobs[APPLE_PATH] ?? APPLE_BLOB, type: 'blob' },
      ...(blobs[ADS_PATH] === undefined ? [{ path: ADS_PATH, sha: ADS_BLOB, type: 'blob' }] : []),
    ],
  })
}

type Override = Record<string, Error | string | UpstreamTextResult>

/** 覆盖项按「仓库内路径」匹配；树 API 单独用 treeOverride。 */
function fetcher(overrides: Override = {}, treeOverride?: Error | string) {
  return async (url: string): Promise<string | UpstreamTextResult> => {
    if (url === TREE_URL) {
      if (treeOverride instanceof Error) throw treeOverride
      return typeof treeOverride === 'string' ? treeOverride : treeBody()
    }
    const marker = `${ACL4SSR_RAW_BASE}/${COMMIT}/`
    if (url.startsWith(marker)) {
      const path = decodeURIComponent(url.slice(marker.length))
      const value = overrides[path]
      if (value instanceof Error) throw value
      if (typeof value === 'string') return value
      if (value) return value
      if (path === INI_PATH) return { text: INI, etag: 'W/"ini"', contentType: 'text/plain', status: 200 }
      const list = LISTS[path]
      if (list) return { text: list.text, etag: list.etag, contentType: 'text/plain', status: 200 }
    }
    throw new Error(`未预置的 URL: ${url}`)
  }
}

// ---------- 成功：trees + 按 commit 拉 INI / 全部列表 ----------
const now = 1_766_000_000_000
const ok = await fetchUpstreamScheme(meta, { fetchText: fetcher(), now })
if (ok.scheme.rules.length !== 4) fail(`成功分支：规则数应为 4，实际 ${ok.scheme.rules.length}`)
const appleRules = ok.scheme.rules.filter((rule) => rule.group === '苹果服务')
if (appleRules.length !== 2) fail(`成功分支：苹果服务应有 2 条列表规则，实际 ${appleRules.length}`)
const adRules = ok.scheme.rules.filter((rule) => rule.group === '广告拦截')
if (adRules.length !== 1 || adRules[0].type !== 'DOMAIN-SUFFIX' || adRules[0].value !== 'doubleclick.net') {
  fail(`成功分支：广告拦截规则解析不正确 → ${JSON.stringify(adRules)}`)
}
const inline = ok.scheme.rules[ok.scheme.rules.length - 1]
if (!(inline.type === 'GEOIP' && inline.value === 'CN' && inline.group === '直连')) {
  fail(`成功分支：内联 GEOIP,CN 应保留在末尾 → ${JSON.stringify(inline)}`)
}
if (ok.scheme.groups.length !== 2) fail(`成功分支：策略组应为 2 组，实际 ${ok.scheme.groups.length}`)
if (ok.scheme.sourceURL !== upstreamRawURL(INI_PATH, COMMIT)) {
  fail(`成功分支：方案没有按 commit 记录上游 INI 来源 → ${ok.scheme.sourceURL}`)
}
if (ok.ruleSets.length !== 2) fail(`成功分支：应保存 2 个列表快照，实际 ${ok.ruleSets.length}`)
const appleSet = ok.ruleSets.find((set) => set.sourceURL === `${ACL4SSR_RAW_BASE}/master/${APPLE_PATH}`)
if (!appleSet || appleSet.rules.length !== 2) fail('成功分支：苹果列表快照缺失或规则不完整')
if (appleSet && appleSet.name !== 'Apple') fail(`成功分支：列表名应为 Apple，实际 ${appleSet?.name}`)

// ---------- 固化记录：commit SHA + 逐文件 blob SHA ----------
if (ok.override.scheme.id !== meta.id || ok.override.scheme.name !== meta.name) {
  fail(`固化记录：应保留内置 id / 原名 → ${ok.override.scheme.id} / ${ok.override.scheme.name}`)
}
if (ok.override.ruleSets.length !== 2) fail('固化记录：应包含列表快照')
if (ok.override.source.ruleCount !== 4 || ok.override.source.ruleSetCount !== 2) {
  fail(`固化记录：条数不正确 → ${ok.override.source.ruleCount} / ${ok.override.source.ruleSetCount}`)
}
if (ok.override.source.commitSha !== COMMIT) {
  fail(`固化记录：commitSha 不正确 → ${ok.override.source.commitSha}`)
}
if (ok.override.source.files.length !== 2) {
  fail(`固化记录：应记录 2 个列表文件，实际 ${ok.override.source.files.length}`)
}
for (const [path, blob] of [[APPLE_PATH, APPLE_BLOB], [ADS_PATH, ADS_BLOB]] as const) {
  const file = ok.override.source.files.find((item) => item.path === path)
  if (!file || file.blobSha !== blob) fail(`固化记录：${path} 的 blobSha 不正确 → ${file?.blobSha}`)
}
for (const file of ok.override.source.files) {
  if (!/^[0-9a-f]{40}$/i.test(file.blobSha)) fail(`固化记录：${file.path} 缺少有效 blobSha`)
}

// ---------- 检测：同 commit 无更新；新 tree 能点名变更文件 ----------
const same = await checkUpstreamUpdate(meta, ok.override, { fetchText: fetcher() })
if (!same.checked || same.updateAvailable || same.method !== 'trees') {
  fail(`检测（无变化）：应 checked=true、无更新、走 trees → ${JSON.stringify(same)}`)
}
const changed = await checkUpstreamUpdate(meta, ok.override, {
  fetchText: fetcher({}, treeBody(NEXT_COMMIT, { [APPLE_PATH]: '4'.repeat(40) })),
})
if (!changed.checked || !changed.updateAvailable) fail('检测（有变化）：应判定有更新')
if (!changed.changedFiles.includes(APPLE_PATH) || changed.changedFiles.length !== 1) {
  fail(`检测（有变化）：应只点名 Apple.list → ${changed.changedFiles.join('|')}`)
}

// ---------- trees API 失败 → HEAD 备用检测 ----------
const headBaselines: Record<string, string | undefined> = {
  [APPLE_PATH]: 'W/"apple-1"',
  [ADS_PATH]: 'W/"ads-2"',
}
const headCheck = await checkUpstreamUpdate(meta, {
  ...ok.override,
  source: {
    ...ok.override.source,
    files: ok.override.source.files.map((file) => ({ ...file, etag: headBaselines[file.path] })),
  },
}, {
  fetchText: fetcher({}, new Error('HTTP 403')),
  fetchHeaders: async (url: string) => {
    const path = decodeURIComponent(url.split(`/${COMMIT}/`)[1] ?? url.split(`/master/`)[1] ?? '')
    return { etag: LISTS[path]?.etag }
  },
})
if (!headCheck.checked || !headCheck.updateAvailable || headCheck.method !== 'head') {
  fail(`备用检测：应 checked=true、有更新、method=head → ${JSON.stringify(headCheck)}`)
}
if (!headCheck.changedFiles.includes(ADS_PATH)) {
  fail(`备用检测：应点名 Ads.yaml → ${headCheck.changedFiles.join('|')}`)
}

// ---------- HTML 404 页：即使 200 也要判失败 ----------
const html = await fetchUpstreamScheme(meta, {
  fetchText: fetcher({ [APPLE_PATH]: { text: '<!DOCTYPE html><html><body>404</body></html>', status: 200, contentType: 'text/html' } }),
  now,
}).then(() => null, (e) => e as UpstreamSchemeError)
if (!html) fail('HTML 误判分支：应抛出错误')
else if (!html.failures.some((line) => line.includes(APPLE_PATH) && line.includes('HTML'))) {
  fail(`HTML 误判分支：错误信息应点名文件并说明 HTML → ${html.failures.join('|')}`)
}

// ---------- 某文件按 SHA 返回 404：整次失败且没有可写入的覆盖层 ----------
const notFound = await fetchUpstreamScheme(meta, {
  fetchText: fetcher({ [ADS_PATH]: new Error('HTTP 404') }),
  now,
}).then(() => null, (e) => e as UpstreamSchemeError)
if (!notFound) fail('文件 404 分支：应抛出错误')
else if (!notFound.failures.some((line) => line.includes(ADS_PATH) && line.includes('HTTP 404'))) {
  fail(`文件 404 分支：错误信息应点名文件与状态码 → ${notFound.failures.join('|')}`)
}
if (notFound && 'override' in (notFound as unknown as Record<string, unknown>)) {
  fail('文件 404 分支：不应返回可写入的覆盖层')
}

// ---------- force-push：tree 里已没有该文件 ----------
const missing = await fetchUpstreamScheme(meta, {
  fetchText: fetcher({}, treeBody(COMMIT, { [ADS_PATH]: '' })),
  now,
}).then(() => null, (e) => e as UpstreamSchemeError)
if (!missing) fail('文件被删分支：应抛出错误')
else if (!missing.failures.some((line) => line.includes(ADS_PATH) && line.includes('不存在'))) {
  fail(`文件被删分支：错误信息应点名文件 → ${missing.failures.join('|')}`)
}

// ---------- 部分失败：整批放弃，错误里点名失败的列表 ----------
const partial = await fetchUpstreamScheme(meta, {
  fetchText: fetcher({ [ADS_PATH]: new Error('HTTP 502') }),
  now,
}).then(() => null, (e) => e as UpstreamSchemeError)
if (!partial) {
  fail('部分失败分支：应抛出错误而不是返回半成品')
} else {
  if (!partial.failures.some((line) => line.includes(ADS_PATH) && line.includes('HTTP 502'))) {
    fail(`部分失败分支：错误信息没有点名失败列表 → ${partial.failures.join('|')}`)
  }
  if (partial.message.includes('当前方案未改动') === false) fail('部分失败分支：错误信息应说明当前方案未改动')
}

// ---------- 全部失败：INI 本身拉不到 ----------
const total = await fetchUpstreamScheme(meta, {
  fetchText: fetcher({ [INI_PATH]: new Error('offline') }),
  now,
}).then(() => null, (e) => e as UpstreamSchemeError)
if (!total) fail('全部失败分支：应抛出错误')
else if (!total.failures.some((line) => line.includes(INI_PATH))) {
  fail(`全部失败分支：错误信息应包含 INI 路径 → ${total.failures.join('|')}`)
}

// ---------- trees API 也失败：无法固定 commit，整次放弃 ----------
const noTree = await fetchUpstreamScheme(meta, {
  fetchText: fetcher({}, new Error('HTTP 403')),
  now,
}).then(() => null, (e) => e as UpstreamSchemeError)
if (!noTree) fail('trees 失败分支：应抛出错误')
else if (!noTree.failures.some((line) => line.includes('trees API'))) {
  fail(`trees 失败分支：错误信息应说明 trees API → ${noTree.failures.join('|')}`)
}

// ---------- 列表内容过短 / 解析后没有规则：同样算失败 ----------
const empty = await fetchUpstreamScheme(meta, {
  fetchText: fetcher({ [APPLE_PATH]: '   ' }),
  now,
}).then(() => null, (e) => e as UpstreamSchemeError)
if (!empty) fail('空列表分支：应抛出错误')

// ---------- 离线兜底：内置 meta 没有 file 时不尝试网络，也不返回结果 ----------
const noFile = await fetchUpstreamScheme({ ...meta, file: undefined }, { fetchText: fetcher(), now })
  .then(() => null, (e) => e as UpstreamSchemeError)
if (!noFile) fail('无 file 分支：应抛出错误')
else if (!noFile.failures.some((line) => line.includes('没有对应的上游 INI'))) {
  fail(`无 file 分支：错误信息应说明缺少上游文件映射 → ${noFile.failures.join('|')}`)
}

// ---------- loadScheme：快照解引用、损坏逐级回落 ----------
// 用仓库里的真实 public/rulesets 快照喂给 loadScheme，避免依赖浏览器同源请求。
const rulesetRoot = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'rulesets')
const realFetch = globalThis.fetch
globalThis.fetch = (async (input: RequestInfo | URL) => {
  const url = String(input)
  const file = url.includes('/rulesets/') ? url.slice(url.indexOf('/rulesets/') + '/rulesets/'.length) : ''
  if (!file) return new Response('not found', { status: 404 })
  try {
    return new Response(readFileSync(join(rulesetRoot, decodeURIComponent(file)), 'utf8'), { status: 200 })
  } catch {
    return new Response('not found', { status: 404 })
  }
}) as typeof fetch

const snapshotV1: BuiltinSchemeSnapshot = { ...ok.override, id: 1, schemeID: meta.id, createdAt: now }
const refs1 = { [meta.id]: { snapshotId: 1 } }
const snapshots1 = { '1': snapshotV1 }

const overridden = await loadScheme(meta, refs1, snapshots1)
if (overridden.rules.length !== 4 || overridden.name !== meta.name) {
  fail(`loadScheme 覆盖层：应读到固化后的 4 条规则且保留原名 → ${overridden.rules.length} / ${overridden.name}`)
}

// 指针指向不存在的版本，但有同方案旧快照 → 回落到上一版（#1），并且能报告 missingId。
const missingRef = { [meta.id]: { snapshotId: 9 } }
const resolution = resolveBuiltinSchemeSnapshot(meta.id, missingRef, snapshots1)
if (resolution.fallback !== 'previous' || resolution.missingId !== 9 || resolution.snapshot?.id !== 1) {
  fail(`解引用缺号：应回落上一版 #1 并报告 missingId=9 → ${JSON.stringify(resolution.fallback)} / ${resolution.missingId}`)
}
const fallbackPrevious = await loadScheme(meta, missingRef, snapshots1)
if (fallbackPrevious.rules.length !== 4) {
  fail(`loadScheme 缺号回落：应使用上一版 4 条规则，实际 ${fallbackPrevious.rules.length}`)
}

// 当前快照正文损坏：指针 #2 坏、旧版 #1 可用 → 用 #1。
const damagedSnapshots = { '1': snapshotV1, '2': { ...snapshotV1, id: 2, scheme: undefined } } as unknown as Record<string, BuiltinSchemeSnapshot>
const fallbackDamaged = await loadScheme(meta, { [meta.id]: { snapshotId: 2 } }, damagedSnapshots)
if (fallbackDamaged.rules.length !== 4) {
  fail(`loadScheme 损坏快照：应回落到上一版 4 条规则，实际 ${fallbackDamaged.rules.length}`)
}
const damagedResolution = resolveBuiltinSchemeSnapshot(meta.id, { [meta.id]: { snapshotId: 2 } }, damagedSnapshots)
if (damagedResolution.fallback !== 'previous' || damagedResolution.missingId !== 2 || damagedResolution.snapshot?.id !== 1) {
  fail(`解引用损坏：应回落上一版 #1 → ${JSON.stringify(damagedResolution.fallback)}`)
}

// 没有任何可用快照 → 原厂；清除指针 → 原厂。
const factory = await loadScheme(meta, missingRef, {})
if (factory.rules.length < 100) {
  fail(`loadScheme 无可用快照：应回落原厂快照（规则数 ${factory.rules.length}）`)
}
const cleared = await loadScheme(meta, {})
if (cleared.rules.length !== factory.rules.length) {
  fail(`loadScheme 清除覆盖层：应保持原厂快照 → ${cleared.rules.length} vs ${factory.rules.length}`)
}

// ---------- 写入 / 单调 id / 3 版环形淘汰 ----------
const extraRule = { type: 'FINAL', group: 'Final' }
const v2Content = {
  ...ok.override,
  scheme: { ...ok.override.scheme, rules: [...ok.override.scheme.rules, extraRule] },
  source: { ...ok.override.source, commitSha: NEXT_COMMIT, ruleCount: 5 },
}
const v3Content = {
  ...v2Content,
  scheme: { ...v2Content.scheme, rules: [...v2Content.scheme.rules, extraRule] },
  source: { ...v2Content.source, ruleCount: 6 },
}
const w1 = writeBuiltinSchemeSnapshot({}, {}, 0, meta.id, ok.override, now)
if (w1.snapshot.id !== 1 || w1.snapshotSeq !== 1) fail(`快照写入：首个 id 应为 1 → ${w1.snapshot.id}`)
const written1 = await loadScheme(meta, w1.overrides, w1.snapshots)
if (written1.rules.length !== 4) fail(`快照写入→读取：应读到 4 条，实际 ${written1.rules.length}`)
const w2 = writeBuiltinSchemeSnapshot(w1.snapshots, w1.overrides, w1.snapshotSeq, meta.id, v2Content, now + 1)
const w3 = writeBuiltinSchemeSnapshot(w2.snapshots, w2.overrides, w2.snapshotSeq, meta.id, v3Content, now + 2)
if (w2.snapshot.id !== 2 || w3.snapshot.id !== 3) fail(`快照 id 应单调递增 → ${w2.snapshot.id} / ${w3.snapshot.id}`)
const kept = snapshotsForScheme(w3.snapshots, meta.id)
if (kept.length !== 2 || kept[0].id !== 3 || kept[1].id !== 2) {
  fail(`环形淘汰：应只保留最近 2 个存储快照 #3/#2 → ${kept.map((s) => s.id).join(',')}`)
}
if (Object.keys(w3.snapshots).length !== 2) {
  fail(`环形淘汰：工作区里应只剩 2 个快照，实际 ${Object.keys(w3.snapshots).length}`)
}
if (w3.snapshotSeq !== 3) fail(`快照序列：应为 3 → ${w3.snapshotSeq}`)

// ---------- 回退计划：规则数变化 / 受影响方案 / 已导出配置提示 ----------
const customSchemes = [{
  name: '引用旧列表的自定义方案',
  ruleSets: [{ id: appleSet!.id } as SchemeRuleSet],
}] as unknown as Pick<RuleScheme, 'name' | 'ruleSets'>[]
const rollback = planSnapshotRollback({
  snapshots: w3.snapshots,
  overrides: w3.overrides,
  customSchemes,
  schemeID: meta.id,
  targetID: 2,
  factoryRuleCount: 4,
})
if (!rollback) {
  fail('回退计划：应能找到目标快照 #2')
} else {
  if (rollback.fromCount !== 6 || rollback.toCount !== 5) {
    fail(`回退计划：规则数应为 6 → 5，实际 ${rollback.fromCount} → ${rollback.toCount}`)
  }
  if (rollback.affectedSchemes.join('、') !== '引用旧列表的自定义方案') {
    fail(`回退计划：受影响方案应点名自定义方案 → ${rollback.affectedSchemes.join('、')}`)
  }
  if (!rollback.message.includes('规则数 6 → 5 条')) fail(`回退计划：提示缺少规则数变化 → ${rollback.message}`)
  if (!rollback.message.includes('已导出的客户端配置不会自动回滚')) fail(`回退计划：提示缺少已导出配置说明 → ${rollback.message}`)
}

// 方案里的规则集通常来自「我的规则集」：id 是本地重新生成的，只有 sourceRef
// 能和快照里的来源对上，受影响清单必须按地址也能命中。
const customByRef = [{
  name: '按源地址引用旧列表的自定义方案',
  ruleSets: [{ id: 'local-rebuilt-id', sourceRef: appleSet!.sourceURL } as SchemeRuleSet],
}] as unknown as Pick<RuleScheme, 'name' | 'ruleSets'>[]
const rollbackByRef = planSnapshotRollback({
  snapshots: w3.snapshots,
  overrides: w3.overrides,
  customSchemes: customByRef,
  schemeID: meta.id,
  targetID: 2,
  factoryRuleCount: 4,
})
if (!rollbackByRef || !rollbackByRef.affectedSchemes.includes('按源地址引用旧列表的自定义方案')) {
  fail(`回退计划：按 sourceRef 引用的方案也应列入受影响清单 → ${rollbackByRef?.affectedSchemes.join('、')}`)
}

// 回退动作：指针改回 #2 后，读到的是 5 条而不是当前 6 条。
const rolledBackRefs = { ...w3.overrides, [meta.id]: { snapshotId: 2 } }
const rolledBack = await loadScheme(meta, rolledBackRefs, w3.snapshots)
if (rolledBack.rules.length !== 5) fail(`回退后读取：应读到 5 条，实际 ${rolledBack.rules.length}`)

// ---------- 旧单版内联结构迁移：不丢固化内容 ----------
const legacy = normalizeBuiltinSchemes({ [meta.id]: ok.override }, undefined, undefined)
if (legacy.builtinSchemeOverrides[meta.id]?.snapshotId !== 1) {
  fail(`旧结构迁移：应生成指针 #1 → ${JSON.stringify(legacy.builtinSchemeOverrides)}`)
}
const legacySnapshot = legacy.schemeSnapshots['1']
if (!legacySnapshot || legacySnapshot.source.files.length !== 2 || legacySnapshot.source.commitSha !== COMMIT) {
  fail('旧结构迁移：快照应保留 commit 与 2 个文件 blob')
}
const legacyLoaded = await loadScheme(meta, legacy.builtinSchemeOverrides, legacy.schemeSnapshots)
if (legacyLoaded.rules.length !== 4) fail(`旧结构迁移：迁移后仍应读到 4 条，实际 ${legacyLoaded.rules.length}`)

// 单条损坏只丢这一条：合法快照保留，坏快照丢弃。
const mixed = normalizeBuiltinSchemes(
  undefined,
  { '1': snapshotV1, '2': { ...snapshotV1, id: 2, scheme: { id: meta.id } } },
  2,
)
if (!mixed.schemeSnapshots['1'] || mixed.schemeSnapshots['2']) {
  fail(`归一化：应只丢损坏的 #2 → ${Object.keys(mixed.schemeSnapshots).join(',')}`)
}
// ---------- U1：固化快照挂回只读规则集，无屏蔽时导出逐字节一致 ----------
const U1_NODES: ProxyNode[] = [
  { id: 'u1-ss', kind: 'ss', name: '样例 SS', server: 'ss.example.com', port: 8388, cipher: 'aes-256-gcm', password: 'p', tls: false, skipCertificateVerification: false },
  { id: 'u1-tr', kind: 'trojan', name: '样例 Trojan', server: 'tr.example.com', port: 443, password: 'p', tls: true, sni: 'tr.example.com', skipCertificateVerification: false },
]
const U1_CLIENTS: Array<[string, ClientTarget]> = [
  ['clash', 'clash-verge'],
  ['surge', 'surge'],
  ['loon', 'loon'],
  ['quanx', 'quanx'],
  ['egern', 'egern'],
  ['sing-box', 'sing-box'],
]

function ruleProjection(rules: RoutingRule[]): Array<Record<string, unknown>> {
  return rules.map((rule) => ({
    type: rule.type,
    value: rule.value ?? '',
    group: rule.group,
    noResolve: !!rule.noResolve,
    options: [...(rule.options ?? [])].sort(),
    raw: rule.raw ?? '',
  }))
}

/** 改前 = loadScheme 只返回 snapshot.scheme；改后 = 额外挂回 ruleSets（inlined）。 */
function u1Compare(label: string, before: RuleScheme, after: RuleScheme): boolean {
  let ok = true
  const beforeRules = ruleProjection(prepareSchemeForExport(before, {}).rules)
  const afterRules = ruleProjection(prepareSchemeForExport(after, {}).rules)
  const sameRules = JSON.stringify(beforeRules) === JSON.stringify(afterRules)
  if (!sameRules) {
    ok = false
    fail(`${label}：规则序列不一致（${beforeRules.length} vs ${afterRules.length} 条）`)
  }
  console.log(`\n${label}：无屏蔽时对比「改前（不挂规则集）」与「改后（挂只读规则集）」`)
  console.log(`  规则序列 ${afterRules.length} 条：条数 / 顺序 / 类型 / 值 / 目标组 / no-resolve ${sameRules ? '全部相同' : '不一致'}`)
  for (const [format, target] of U1_CLIENTS) {
    const client = CLIENTS.find((item) => item.target === target)!
    let beforeText = ''
    let afterText = ''
    try {
      beforeText = generateConfig(client, U1_NODES, before, { contentMode: 'full' }).text
    } catch (e) {
      ok = false
      fail(`${label}/${format}：改前生成失败：${(e as Error).message}`)
    }
    try {
      afterText = generateConfig(client, U1_NODES, after, { contentMode: 'full' }).text
    } catch (e) {
      ok = false
      fail(`${label}/${format}：改后生成失败：${(e as Error).message}`)
    }
    const same = beforeText === afterText && beforeText.length > 0
    if (!same) {
      ok = false
      fail(`${label}/${format}：导出不是逐字节一致（改前 ${beforeText.length} 字节 / 改后 ${afterText.length} 字节）`)
    }
    const hash = createHash('sha256').update(afterText).digest('hex').slice(0, 16)
    console.log(`  ${format.padEnd(8)} bytes=${String(afterText.length).padStart(6)} sha256=${hash} ${same ? '逐字节一致' : '不一致'}`)
  }
  return ok
}

// 真实上游流程产出的固化记录（Apple.list 2 条 + Ads.yaml 1 条内联在 scheme.rules 里）。
const u1RealSnapshot = { ...ok.override, id: 1, schemeID: meta.id, createdAt: now }
const u1RealBefore = { ...u1RealSnapshot.scheme, id: meta.id, name: meta.name, description: meta.description }
const u1RealAfter = attachSnapshotRuleSets(u1RealBefore, u1RealSnapshot.ruleSets)
u1Compare('真实固化快照（上游 INI + 3 条列表规则）', u1RealBefore, u1RealAfter)

// 合成一份带 no-resolve 的固化形态：列表规则同时出现在 scheme.rules 里。
const u1Groups = ['节点选择', '苹果服务', '广告拦截', '直连', 'Final'].map((name) => ({
  name,
  type: 'select' as const,
  options: ['DIRECT'],
}))
const u1SynthScheme: RuleScheme = {
  id: meta.id,
  name: meta.name,
  description: meta.description,
  groups: u1Groups,
  rules: [
    { type: 'DOMAIN-SUFFIX', value: 'apple.com', group: '苹果服务' },
    { type: 'DOMAIN-SUFFIX', value: 'icloud.com', group: '苹果服务' },
    { type: 'DOMAIN-SUFFIX', value: 'doubleclick.net', group: '广告拦截' },
    { type: 'IP-CIDR', value: '10.0.0.0/8', group: '直连', noResolve: true },
    { type: 'IP-CIDR6', value: '2001:db8::/32', group: '直连', noResolve: true },
    { type: 'GEOIP', value: 'CN', group: '直连' },
    { type: 'FINAL', group: 'Final' },
  ],
}
const u1SynthSets: LocalRuleSet[] = [
  { id: 'u1-apple', name: 'Apple', group: '苹果服务', updatedAt: now, sourceURL: 'https://raw.example/Apple.list', rules: [
    { type: 'DOMAIN-SUFFIX', value: 'apple.com' },
    { type: 'DOMAIN-SUFFIX', value: 'icloud.com' },
  ] },
  { id: 'u1-ads', name: 'Ads', group: '广告拦截', updatedAt: now, sourceURL: 'https://raw.example/Ads.yaml', rules: [
    { type: 'DOMAIN-SUFFIX', value: 'doubleclick.net' },
  ] },
  { id: 'u1-ip', name: 'DirectIP', group: '直连', updatedAt: now, rules: [
    { type: 'IP-CIDR', value: '10.0.0.0/8', noResolve: true },
    { type: 'IP-CIDR6', value: '2001:db8::/32', noResolve: true },
  ] },
]
const u1SynthAfter = attachSnapshotRuleSets(u1SynthScheme, u1SynthSets)
u1Compare('合成固化快照（含 IP-CIDR / IP-CIDR6 no-resolve）', u1SynthScheme, u1SynthAfter)

// ---------- U1：屏蔽一条 → 同集其它保留 → 解除恢复 ----------
const u1Blocker = appleSet!.id
const u1BlockedSignature = ruleSignature(appleSet!.rules[0])
const u1KeptSignature = ruleSignature(appleSet!.rules[1])
const u1Table = addRuleSetExclusion({}, u1Blocker, u1BlockedSignature)
const u1Filtered = filterExcludedRuleSets(u1RealAfter, u1Table)
const u1FilteredSignatures = ruleProjection(prepareSchemeForExport(u1Filtered, {}).rules)
const u1FilteredRuleSignatures = prepareSchemeForExport(u1Filtered, {}).rules.map(ruleSignature)
if (u1Filtered.rules.length !== u1RealAfter.rules.length - 1) {
  fail(`U1 屏蔽：规则数应为 ${u1RealAfter.rules.length} → ${u1RealAfter.rules.length - 1}，实际 ${u1Filtered.rules.length}`)
}
if (!u1FilteredRuleSignatures.includes(u1KeptSignature)) {
  fail('U1 屏蔽：同一规则集里的其它条目必须保留')
}
if (u1FilteredRuleSignatures.includes(u1BlockedSignature)
  || u1FilteredSignatures.some((rule) => rule.value === 'apple.com')) {
  fail('U1 屏蔽：被屏蔽条目应从编译结果里消失')
}
const u1SetAfterBlock = u1Filtered.ruleSets?.find((set) => set.id === u1Blocker)
if (!u1SetAfterBlock || u1SetAfterBlock.rules.length !== appleSet!.rules.length) {
  fail('U1 屏蔽：规则集快照本身必须保留，避免解除屏蔽后无法恢复')
}
const u1UnblockedTable = removeRuleSetExclusion(u1Table, u1Blocker, u1BlockedSignature)
const u1Unblocked = filterExcludedRuleSets(u1RealAfter, u1UnblockedTable)
if (u1Unblocked !== u1RealAfter) {
  fail('U1 解除屏蔽：没有排除项时应原样返回方案')
}
const u1Rehash = createHash('sha256').update(generateConfig(
  CLIENTS.find((item) => item.target === 'clash-verge')!,
  U1_NODES,
  u1Unblocked,
  { contentMode: 'full' },
).text).digest('hex')
const u1BaselineHash = createHash('sha256').update(generateConfig(
  CLIENTS.find((item) => item.target === 'clash-verge')!,
  U1_NODES,
  u1RealAfter,
  { contentMode: 'full' },
).text).digest('hex')
console.log(`\n屏蔽/解除：屏蔽后 ${u1RealAfter.rules.length} → ${u1Filtered.rules.length} 条（同集其它保留），解除后导出 sha256 ${u1Rehash === u1BaselineHash ? '与基线一致' : '不一致'}`)
if (u1Rehash !== u1BaselineHash) fail('U1 解除屏蔽：导出没有恢复为基线的逐字节结果')

// ---------- U1：orderedSchemeRules / insertRuleSetBlocks / lint 三处口径一致 ----------
const u1Ordered = ruleProjection(orderedSchemeRules(u1RealAfter))
if (JSON.stringify(u1Ordered) !== JSON.stringify(ruleProjection(prepareSchemeForExport(u1RealAfter, {}).rules))) {
  fail('U1 口径：orderedSchemeRules 与导出准备顺序不一致')
}
const u1OrderedBlocked = ruleProjection(orderedSchemeRules(u1Filtered))
if (JSON.stringify(u1OrderedBlocked) !== JSON.stringify(u1FilteredSignatures)) {
  fail('U1 口径：屏蔽后 orderedSchemeRules 与导出准备顺序不一致')
}
const u1Lint = lintScheme({ scheme: u1RealAfter, nodes: U1_NODES })
if (u1Lint.some((issue) => issue.code === 'duplicateRule')) {
  fail('U1 lint：固化快照不应出现「同一批规则两份」的重复提示')
}
const u1LintBlocked = lintScheme({ scheme: u1Filtered, nodes: U1_NODES, ruleSetExclusions: u1Table })
if (u1LintBlocked.some((issue) => issue.code === 'duplicateRule')) {
  fail('U1 lint：屏蔽后也不应出现重复提示')
}
console.log(`口径一致：orderedSchemeRules / insertRuleSetBlocks / lint 均按 ${u1Ordered.length} 条顺序处理，无重复`)

// ---------- U1：刷新 / 回退快照后屏蔽仍生效 ----------
const u1Current = await loadScheme(meta, w1.overrides, w1.snapshots)
const u1Refreshed = await loadScheme(meta, w2.overrides, w2.snapshots)
const u1RolledBack = await loadScheme(meta, { [meta.id]: { snapshotId: 1 } }, w2.snapshots)
for (const [label, loaded] of [['当前快照', u1Current], ['刷新后的快照', u1Refreshed], ['回退到 #1 的快照', u1RolledBack]] as const) {
  if (!loaded.ruleSets?.some((set) => set.id === u1Blocker)) {
    fail(`U1 刷新/回退：${label} 没有挂回只读规则集`)
    continue
  }
  const blockedRules = filterExcludedRuleSets(loaded, u1Table)
  if (blockedRules.rules.some((rule) => rule.value === 'apple.com')) {
    fail(`U1 刷新/回退：${label} 上屏蔽没有生效`)
  }
}
console.log('刷新/回退：当前、刷新后、回退到 #1 三份快照上的屏蔽都继续生效')

globalThis.fetch = realFetch

// ---------- 只读态写入被拒 ----------
useStore.setState({ builtinSchemeOverrides: {}, schemeSnapshots: {}, snapshotSeq: 0 })
setWorkspaceReadOnly(true)
useStore.getState().saveBuiltinSchemeOverride(meta.id, ok.override)
if (Object.keys(useStore.getState().builtinSchemeOverrides).length !== 0
  || Object.keys(useStore.getState().schemeSnapshots).length !== 0) {
  fail('只读态：固化写入必须被拦截')
}
if (useStore.getState().restoreBuiltinSchemeSnapshot(meta.id, 1)) {
  fail('只读态：回退写入必须被拦截')
}
setWorkspaceReadOnly(false)
const storedID = useStore.getState().saveBuiltinSchemeOverride(meta.id, ok.override)
if (storedID !== 1 || !useStore.getState().builtinSchemeOverrides[meta.id]) {
  fail(`可写态：固化写入应成功并返回快照 id → ${storedID}`)
}
if (!useStore.getState().schemeSnapshots['1']) fail('可写态：快照正文应写入独立表')
useStore.getState().saveBuiltinSchemeOverride(meta.id, v2Content)
useStore.getState().saveBuiltinSchemeOverride(meta.id, v3Content)
if (Object.keys(useStore.getState().schemeSnapshots).length !== 2) {
  fail(`store 环形淘汰：3 次固化后应只剩 2 个快照，实际 ${Object.keys(useStore.getState().schemeSnapshots).length}`)
}
if (!useStore.getState().restoreBuiltinSchemeSnapshot(meta.id, 2)) {
  fail('store 回退：应能切回快照 #2')
}
if (useStore.getState().builtinSchemeOverrides[meta.id]?.snapshotId !== 2) {
  fail('store 回退：指针应指向 #2')
}
useStore.getState().clearBuiltinSchemeOverride(meta.id)

if (problems) {
  console.error(`\nselfcheck-upstream: ${problems} 个问题`)
  process.exit(1)
}
console.log('selfcheck-upstream: 全部通过（成功 / commit+blob 记录 / trees 检测 / HEAD 备用 / HTML 404 / 文件 404 / trees 失败 / 部分失败 / 全部失败 / 空列表 / 无 file / 快照解引用 / 损坏降级 / 环形淘汰 / 回退计划 / 旧结构迁移 / 只读拦截）')
