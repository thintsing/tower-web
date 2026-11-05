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

// ---------- loadScheme：覆盖层优先、清除 / 损坏回落原厂 ----------
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

const overridden = await loadScheme(meta, { [meta.id]: ok.override })
if (overridden.rules.length !== 4 || overridden.name !== meta.name) {
  fail(`loadScheme 覆盖层：应读到固化后的 4 条规则且保留原名 → ${overridden.rules.length} / ${overridden.name}`)
}

const damaged = { [meta.id]: { scheme: { id: meta.id }, ruleSets: [] } } as unknown as Record<string, never>
const fallback = await loadScheme(meta, damaged)
if (fallback.rules.length < 100) {
  fail(`loadScheme 损坏覆盖层：应回落原厂快照（规则数 ${fallback.rules.length}）`)
}

// 清除覆盖层：同一次进程里再读，仍是原厂快照而不是固化内容。
const cleared = await loadScheme(meta, {})
if (cleared.rules.length !== fallback.rules.length) {
  fail(`loadScheme 清除覆盖层：应保持原厂快照 → ${cleared.rules.length} vs ${fallback.rules.length}`)
}
globalThis.fetch = realFetch

// ---------- 只读态写入被拒 ----------
useStore.setState({ builtinSchemeOverrides: {} })
setWorkspaceReadOnly(true)
useStore.getState().saveBuiltinSchemeOverride(meta.id, ok.override)
if (Object.keys(useStore.getState().builtinSchemeOverrides).length !== 0) {
  fail('只读态：固化写入必须被拦截')
}
setWorkspaceReadOnly(false)
useStore.getState().saveBuiltinSchemeOverride(meta.id, ok.override)
if (!useStore.getState().builtinSchemeOverrides[meta.id]) {
  fail('可写态：固化写入应成功')
}
useStore.getState().clearBuiltinSchemeOverride(meta.id)

if (problems) {
  console.error(`\nselfcheck-upstream: ${problems} 个问题`)
  process.exit(1)
}
console.log('selfcheck-upstream: 全部通过（成功 / commit+blob 记录 / trees 检测 / HEAD 备用 / HTML 404 / 文件 404 / trees 失败 / 部分失败 / 全部失败 / 空列表 / 无 file / 覆盖层回落 / 只读拦截）')
