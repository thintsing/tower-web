// 从 ACL4SSR 上游把「方案 INI + 全部规则列表」抓下来，固化到内置方案覆盖层。
//
// 设计约束：
// - 快照优先：内置 public/rulesets 下的文件永远不动，用户没点「更新」就只用快照。
// - 全有或全无：任何一个列表拉取 / 校验失败，整次更新放弃，不写任何状态。
// - 版本可核对：先取上游 commit SHA，再按该 SHA 拉正文；列表用 trees API 的 blob SHA
//   记录，确保 14 个文件来自同一个 commit，不会拼成混合版本。
// - 复用服务端 /api/fetch 的 SSRF 防护（协议白名单、云元数据拦截、大小与超时上限）。

import type { BuiltinSchemeOverride, BuiltinSchemeSource, LocalRuleSet, RoutingRule, RuleScheme } from '../models/types'
import { apiFetch } from '../util/apiAuth'
import {
  parseInlineRule,
  parsePlainRulesetText,
  parseSchemeINIParts,
  parseRuleList,
  subconverterRulesetReference,
  type SchemeMeta,
} from './scheme'
import { parseRuleSetText } from './ruleSets'

export const ACL4SSR_REPO = 'ACL4SSR/ACL4SSR'
export const ACL4SSR_BRANCH = 'master'
export const ACL4SSR_RAW_BASE = `https://raw.githubusercontent.com/${ACL4SSR_REPO}`
export const ACL4SSR_API_BASE = `https://api.github.com/repos/${ACL4SSR_REPO}`
export const ACL4SSR_UPSTREAM_INI_BASE = `${ACL4SSR_RAW_BASE}/${ACL4SSR_BRANCH}/Clash/config/`

/** 单个上游文件大小上限：ACL4SSR 列表最大只有几百 KB，8MB 足够且能挡住异常响应。 */
export const UPSTREAM_FILE_MAX_BYTES = 8 * 1024 * 1024
/** 低于这个字节数视为「过短 / 空文件」，避免 GitHub 的错误页被当成规则。 */
export const UPSTREAM_FILE_MIN_BYTES = 16

export function upstreamINIURL(file: string): string {
  return ACL4SSR_UPSTREAM_INI_BASE + encodePath(file)
}

/** 按 commit 拉某个仓库路径；不使用 branch，避免 force-push 后拼成混合版本。 */
export function upstreamRawURL(path: string, commitSha: string): string {
  return `${ACL4SSR_RAW_BASE}/${commitSha}/${encodePath(path)}`
}

function encodePath(path: string): string {
  return path.split('/').map((part) => encodeURIComponent(part)).join('/')
}

/** raw（branch 或 commit）地址 → 仓库内路径；不是 ACL4SSR 仓库时返回 undefined。 */
export function upstreamPathFromURL(url: string): string | undefined {
  const marker = `${ACL4SSR_RAW_BASE}/`
  if (!url.startsWith(marker)) return undefined
  const rest = url.slice(marker.length)
  const slash = rest.indexOf('/')
  if (slash < 0) return undefined
  try {
    return decodeURIComponent(rest.slice(slash + 1))
  } catch {
    return undefined
  }
}

export interface UpstreamSchemeSource {
  group: string
  target: string
  path?: string
  url?: string
  rules: Omit<RoutingRule, 'group'>[]
}

export interface UpstreamSchemeResult {
  /** 分支用的自定义副本：新 id、名字带「上游 日期」。 */
  scheme: RuleScheme
  /** 固化用的覆盖层：保持内置 id / 原名，写入后同一条内置方案直接生效。 */
  override: BuiltinSchemeOverride
  /** 拉取成功的列表快照。 */
  ruleSets: LocalRuleSet[]
  sources: UpstreamSchemeSource[]
}

export class UpstreamSchemeError extends Error {
  readonly failures: string[]

  constructor(failures: string[]) {
    super(`上游更新失败（${failures.length} 项未完成），当前方案未改动：${failures.join('；')}`)
    this.name = 'UpstreamSchemeError'
    this.failures = failures
  }
}

export interface UpstreamTextResult {
  text: string
  /** 上游响应头；服务端 /api/fetch 已透传 ETag / Content-Type / 长度。 */
  etag?: string
  contentType?: string
  contentLength?: number
  status?: number
}

export interface UpstreamFetchOptions {
  /** 抓文本；默认走 /api/fetch。测试里可注入假实现。 */
  fetchText?: (url: string) => Promise<string | UpstreamTextResult>
  /** 抓响应头（HEAD）；测试里可注入假实现。 */
  fetchHeaders?: (url: string) => Promise<{ etag?: string }>
  /** 固定时间戳（测试用）。 */
  now?: number
}

async function defaultFetchText(url: string): Promise<UpstreamTextResult> {
  const res = await apiFetch(`/api/fetch?url=${encodeURIComponent(url)}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const contentLength = Number(res.headers.get('content-length') ?? '')
  return {
    text: await res.text(),
    etag: res.headers.get('x-upstream-etag') ?? undefined,
    contentType: res.headers.get('content-type') ?? undefined,
    contentLength: Number.isFinite(contentLength) && contentLength > 0 ? contentLength : undefined,
    status: res.status,
  }
}

async function defaultFetchHeaders(url: string): Promise<{ etag?: string }> {
  const res = await apiFetch(`/api/fetch?url=${encodeURIComponent(url)}&headers=1`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return { etag: res.headers.get('x-upstream-etag') ?? undefined }
}

function textOf(value: string | UpstreamTextResult): UpstreamTextResult {
  return typeof value === 'string' ? { text: value } : value
}

/** 列表抓取并发上限：避免一次性把上游打满导致 502。 */
const LIST_FETCH_CONCURRENCY = 4
const LIST_RETRY_DELAY_MS = 400

function isTransientFetchError(message: string): boolean {
  return /HTTP (429|5\d\d)|fetch failed|ECONN|ETIMEDOUT|timeout|aborted|socket|network/i.test(message)
}

/** 按顺序收结果、按上限并发执行。 */
async function mapWithConcurrency<T>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<void>,
): Promise<void> {
  let next = 0
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next
      next += 1
      await worker(items[index], index)
    }
  })
  await Promise.all(runners)
}

/**
 * GitHub 404 页可能以 200 + HTML 返回；逐个文件校验正文，
 * 任一不过即整次失败并点名路径。
 */
export function validateUpstreamText(result: UpstreamTextResult): string {
  if (result.status && (result.status < 200 || result.status >= 300)) {
    throw new Error(`HTTP ${result.status}`)
  }
  if (result.contentLength !== undefined && result.contentLength > UPSTREAM_FILE_MAX_BYTES) {
    throw new Error(`超过大小上限 ${UPSTREAM_FILE_MAX_BYTES} 字节`)
  }
  const type = (result.contentType ?? '').toLowerCase()
  const head = result.text.trimStart().slice(0, 80).toLowerCase()
  if (/text\/html|application\/xhtml/.test(type) || head.startsWith('<!doctype') || head.startsWith('<html')) {
    throw new Error('返回的是 HTML 页面（可能被上游 404 页伪装）')
  }
  const bytes = new TextEncoder().encode(result.text).length
  if (bytes > UPSTREAM_FILE_MAX_BYTES) throw new Error(`超过大小上限 ${UPSTREAM_FILE_MAX_BYTES} 字节`)
  if (bytes < UPSTREAM_FILE_MIN_BYTES) throw new Error(`内容过短（${bytes} 字节）`)
  return result.text
}

interface UpstreamTree {
  commitSha: string
  blobs: Map<string, string>
}

/** 一次 trees API：同时拿到当前 commit SHA 与所有 blob SHA。 */
async function fetchUpstreamTree(
  fetchText: (url: string) => Promise<string | UpstreamTextResult>,
): Promise<UpstreamTree> {
  const url = `${ACL4SSR_API_BASE}/git/trees/${ACL4SSR_BRANCH}?recursive=1`
  const { text } = textOf(await fetchText(url))
  const data = JSON.parse(text) as { sha?: unknown; truncated?: unknown; tree?: Array<{ path?: unknown; sha?: unknown; type?: unknown }> }
  if (typeof data.sha !== 'string' || !/^[0-9a-f]{40}$/i.test(data.sha)) {
    throw new Error('trees API 没有返回 commit SHA')
  }
  if (data.truncated === true) throw new Error('trees API 返回被截断')
  const blobs = new Map<string, string>()
  for (const entry of data.tree ?? []) {
    if (entry.type === 'blob' && typeof entry.path === 'string' && typeof entry.sha === 'string') {
      blobs.set(entry.path, entry.sha)
    }
  }
  return { commitSha: data.sha, blobs }
}

function shortPath(path: string): string {
  return path.split('/').pop() ?? path
}

export async function fetchUpstreamScheme(
  meta: SchemeMeta,
  options: UpstreamFetchOptions = {},
): Promise<UpstreamSchemeResult> {
  if (!meta.file) throw new UpstreamSchemeError([`「${meta.name}」没有对应的上游 INI 文件`])
  const fetchText = options.fetchText ?? defaultFetchText
  const now = options.now ?? Date.now()

  let tree: UpstreamTree
  try {
    tree = await fetchUpstreamTree(fetchText)
  } catch (e) {
    throw new UpstreamSchemeError([`上游 trees API：${(e as Error).message}`])
  }
  const commitSha = tree.commitSha
  const iniPath = `Clash/config/${meta.file}`
  const iniURL = upstreamRawURL(iniPath, commitSha)

  let iniResult: UpstreamTextResult
  try {
    iniResult = textOf(await fetchText(iniURL))
    validateUpstreamText(iniResult)
  } catch (e) {
    throw new UpstreamSchemeError([`方案 INI ${iniPath}（${
      commitSha.slice(0, 7)}）：${(e as Error).message}`])
  }
  const ini = iniResult.text

  const parts = parseSchemeINIParts(ini)
  if (!parts.groups.length) throw new UpstreamSchemeError([`方案 INI ${iniPath}：没有解析到任何策略组`])

  const failures: string[] = []
  const textCache = new Map<string, Promise<UpstreamTextResult>>()
  const loadText = (url: string) => {
    const cached = textCache.get(url)
    if (cached) return cached
    const request = fetchListText(url)
    textCache.set(url, request)
    void request.catch(() => textCache.delete(url))
    return request
  }
  const fetchListText = async (url: string): Promise<UpstreamTextResult> => {
    try {
      const result = textOf(await fetchText(url))
      validateUpstreamText(result)
      return result
    } catch (error) {
      // 一次重试只针对明显的瞬时失败（限流 / 5xx / 网络）；404 之类直接放弃。
      if (!isTransientFetchError((error as Error).message)) throw error
      await new Promise((resolve) => setTimeout(resolve, LIST_RETRY_DELAY_MS))
      const result = textOf(await fetchText(url))
      validateUpstreamText(result)
      return result
    }
  }

  // 每个列表必须能在同一个 commit 的 tree 里找到 blob；找不到就是被删 / force-push。
  const targets = parts.rulesets.map((rs) => {
    const reference = subconverterRulesetReference(rs.target)
    return { group: rs.group, target: rs.target, reference, url: reference.target }
  })

  const textByURL = new Map<string, UpstreamTextResult>()
  const pathByURL = new Map<string, string>()
  const blobByURL = new Map<string, string>()
  await mapWithConcurrency(targets, LIST_FETCH_CONCURRENCY, async (item) => {
    if (!/^https?:\/\//i.test(item.url)) {
      failures.push(`${item.group}：不支持的规则集来源 ${item.url}`)
      return
    }
    const path = upstreamPathFromURL(item.url)
    if (!path) {
      failures.push(`${item.group}：${item.url} 不在 ACL4SSR 上游，无法按 commit 固定`)
      return
    }
    const blobSha = tree.blobs.get(path)
    if (!blobSha) {
      failures.push(`${item.group}：${path} 在 commit ${commitSha.slice(0, 7)} 中不存在（可能被删除或上游 force-push）`)
      return
    }
    try {
      const fetched = await loadText(upstreamRawURL(path, commitSha))
      textByURL.set(item.url, fetched)
      pathByURL.set(item.url, path)
      blobByURL.set(item.url, blobSha)
    } catch (e) {
      failures.push(`${item.group}：${path}（${(e as Error).message}）`)
    }
  })
  if (failures.length) throw new UpstreamSchemeError(failures)

  // 解析和内置加载保持一致：严格模式下「解析后 0 条」也算失败，不能静默丢列表。
  const parsedByURL = new Map<string, Omit<RoutingRule, 'group'>[]>()
  const sources: UpstreamSchemeSource[] = []
  const orderedRules: RoutingRule[] = []
  for (const rs of parts.rulesets) {
    const reference = subconverterRulesetReference(rs.target)
    const url = reference.target
    const fetched = textByURL.get(url)
    if (!fetched) continue
    const text = fetched.text
    let rules = parsedByURL.get(url)
    if (!rules) {
      const looksStructured = text.trim().startsWith('{') || /^\s*(payload:|proxies:|rules:)/m.test(text)
      try {
        rules = reference.plainList && !looksStructured
          ? parsePlainRulesetText(text, reference.plainList)
          : parseRuleSetText(text, reference.format).rules
      } catch {
        rules = parseRuleList(text)
      }
      if (!rules.length) failures.push(`${rs.group}：${pathByURL.get(url) ?? url} 解析后没有规则`)
      parsedByURL.set(url, rules)
    }
    sources.push({ group: rs.group, target: rs.target, path: pathByURL.get(url), url, rules })
    for (const rule of rules) orderedRules.push({ ...rule, group: rs.group })
  }
  if (failures.length) throw new UpstreamSchemeError(failures)

  const rules: RoutingRule[] = [...orderedRules]
  for (const { group, rule } of parts.inlineRules) {
    const parsed = parseInlineRule(rule)
    if (parsed) rules.push({ ...parsed, group })
  }

  const seen = new Set<string>()
  const ruleSets: LocalRuleSet[] = []
  const files: BuiltinSchemeSource['files'] = []
  for (const source of sources) {
    if (!source.url || seen.has(source.url)) continue
    seen.add(source.url)
    const reference = subconverterRulesetReference(source.target)
    const path = source.path ?? pathByURL.get(source.url) ?? ''
    ruleSets.push({
      id: `upstream-${source.url.replace(/[^a-z0-9]+/gi, '-').slice(-48)}`,
      name: ruleSetName(source.url),
      rules: source.rules,
      updatedAt: now,
      sourceURL: source.url,
      format: reference.format,
    })
    const fetched = textByURL.get(source.url)
    files.push({
      path,
      blobSha: blobByURL.get(source.url) ?? '',
      ...(fetched?.etag ? { etag: fetched.etag } : {}),
    })
  }

  const day = new Date(now).toISOString().slice(0, 10)
  const scheme: RuleScheme = {
    id: `${meta.id}-upstream-${now}`,
    name: `${meta.name} · 上游 ${day}`,
    description: `从 ACL4SSR 上游（commit ${commitSha.slice(0, 7)}）更新于 ${day}；规则已内联保存，离线可用。内置快照保持不变。`,
    groups: parts.groups,
    rules,
    sourceKind: 'url',
    sourceFormat: 'ini',
    sourceURL: iniURL,
    updatedAt: now,
  }

  const source: BuiltinSchemeSource = {
    iniURL,
    commitSha,
    files,
    fetchedAt: now,
    ruleCount: rules.length,
    ruleSetCount: ruleSets.length,
  }
  // 固化记录保留内置 id / 原名：更新完成后还是同一条「ACL4SSR 在线版」，
  // 刷新页面 / 换设备 / 重启容器都由工作区里的这份覆盖层决定。
  const override: BuiltinSchemeOverride = {
    scheme: {
      ...scheme,
      id: meta.id,
      name: meta.name,
      description: meta.description,
    },
    ruleSets,
    source,
  }

  return { scheme, override, ruleSets, sources }
}

export interface UpstreamUpdateCheck {
  checked: boolean
  updateAvailable: boolean
  /** trees：GitHub API；head：API 不可用时的备用检测。 */
  method: 'trees' | 'head'
  /** 变化的列表文件（相对仓库路径）；为空但有更新时通常是 INI / 分组变更。 */
  changedFiles: string[]
  commitSha?: string
  error?: string
}

export interface CheckUpstreamOptions {
  fetchText?: (url: string) => Promise<string | UpstreamTextResult>
  fetchHeaders?: (url: string) => Promise<{ etag?: string }>
}

/**
 * 只比对版本，不下载列表正文，也绝不自动覆盖。
 * 先用一次 trees API 看 commit + 14 个列表的 blob SHA；API 失败才退化为逐文件 HEAD 比 ETag。
 */
export async function checkUpstreamUpdate(
  _meta: SchemeMeta,
  stored?: BuiltinSchemeOverride,
  options: CheckUpstreamOptions = {},
): Promise<UpstreamUpdateCheck> {
  const previous = stored?.source
  if (!previous?.commitSha) {
    return { checked: false, updateAvailable: false, method: 'trees', changedFiles: [] }
  }
  const fetchText = options.fetchText ?? defaultFetchText

  try {
    const tree = await fetchUpstreamTree(fetchText)
    const changedFiles = previous.files
      .filter((file) => !tree.blobs.has(file.path) || tree.blobs.get(file.path) !== file.blobSha)
      .map((file) => file.path)
    const updateAvailable = tree.commitSha !== previous.commitSha || changedFiles.length > 0
    return {
      checked: true,
      updateAvailable,
      method: 'trees',
      changedFiles,
      commitSha: tree.commitSha,
    }
  } catch (apiError) {
    const fetchHeaders = options.fetchHeaders ?? defaultFetchHeaders
    const files = previous.files.filter((file) => file.etag)
    if (!files.length) {
      return {
        checked: false,
        updateAvailable: false,
        method: 'head',
        changedFiles: [],
        error: `trees API 失败（${(apiError as Error).message}），且基线没有 ETag，无法使用备用检测`,
      }
    }
    const changedFiles: string[] = []
    const errors: string[] = []
    let changed = false
    await mapWithConcurrency(previous.files, LIST_FETCH_CONCURRENCY, async (file) => {
      if (!file.etag) return
      try {
        const head = await fetchHeaders(upstreamRawURL(file.path, ACL4SSR_BRANCH))
        if (!head.etag) {
          errors.push(`${shortPath(file.path)}：HEAD 没有返回 ETag`)
          return
        }
        if (head.etag !== file.etag) {
          changed = true
          changedFiles.push(file.path)
        }
      } catch (e) {
        errors.push(`${shortPath(file.path)}：${(e as Error).message}`)
      }
    })
    return {
      checked: true,
      updateAvailable: changed,
      method: 'head',
      changedFiles,
      ...(errors.length ? { error: `备用检测有 ${errors.length} 个文件未完成：${errors.join('；')}` } : {}),
    }
  }
}

function ruleSetName(url: string): string {
  try {
    const last = new URL(url).pathname.split('/').filter(Boolean).pop() ?? ''
    return last.replace(/\.(list|txt|yaml|yml|json|conf)$/i, '') || url
  } catch {
    return url
  }
}
