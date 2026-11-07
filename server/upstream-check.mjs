// ACL4SSR 上游版本比对：浏览器与伴生服务端共用同一套算法。
// - 优先一次 GitHub trees API 拿到 commit + 全部文件 blob SHA；
// - trees 失败（限流 / 403 / 超时）才退化为逐文件 HEAD 比 ETag。
// 只比对，不下载正文，也绝不写用户方案。
//
// 前端 src/rules/upstreamScheme.ts 从这里导入并再导出，避免两套实现漂移。

export const ACL4SSR_REPO = 'ACL4SSR/ACL4SSR'
export const ACL4SSR_BRANCH = 'master'
export const ACL4SSR_RAW_BASE = `https://raw.githubusercontent.com/${ACL4SSR_REPO}`
export const ACL4SSR_API_BASE = `https://api.github.com/repos/${ACL4SSR_REPO}`
/** 随塔台打包的 ACL4SSR 规则快照对应的上游 commit（README 里同一值）。 */
export const ACL4SSR_PIN_COMMIT = '802e3abf065f8609e7d9073ba506158dbe2ba6e7'

/** 按 commit 拉某个仓库路径；不使用 branch，避免 force-push 后拼成混合版本。 */
export function upstreamRawURL(path, commitSha) {
  return `${ACL4SSR_RAW_BASE}/${commitSha}/${encodePath(path)}`
}

function encodePath(path) {
  return String(path).split('/').map((part) => encodeURIComponent(part)).join('/')
}

function textOf(value) {
  return typeof value === 'string' ? { text: value } : value
}

/**
 * 一次 trees API：同时拿到当前 commit SHA 与所有 blob SHA。
 * fetchText 由调用方注入，便于测试与复用服务端 / 前端各自的抓取实现。
 */
export async function fetchUpstreamTree(fetchText) {
  const url = `${ACL4SSR_API_BASE}/git/trees/${ACL4SSR_BRANCH}?recursive=1`
  const { text } = textOf(await fetchText(url))
  const data = JSON.parse(text)
  if (typeof data.sha !== 'string' || !/^[0-9a-f]{40}$/i.test(data.sha)) {
    throw new Error('trees API 没有返回 commit SHA')
  }
  if (data.truncated === true) throw new Error('trees API 返回被截断')
  const blobs = new Map()
  for (const entry of data.tree ?? []) {
    if (entry.type === 'blob' && typeof entry.path === 'string' && typeof entry.sha === 'string') {
      blobs.set(entry.path, entry.sha)
    }
  }
  return { commitSha: data.sha, blobs }
}

const LIST_FETCH_CONCURRENCY = 4

/** 按顺序收结果、按上限并发执行。 */
async function mapWithConcurrency(items, limit, worker) {
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

function shortPath(path) {
  return String(path).split('/').pop() ?? path
}

/**
 * 与一条已知基线比较。基线可以是「已固化快照的 source」，
 * 也可以是「内置快照对应的 pin commit」（files 为空时只比 commit）。
 *
 * @param {{ commitSha?: string, files?: Array<{ path: string, blobSha: string, etag?: string }> }} previous
 * @param {{ fetchText: Function, fetchHeaders?: Function }} options
 */
export async function checkUpstreamBaseline(previous, options = {}) {
  const p = previous ?? {}
  if (!p.commitSha) {
    return { checked: false, updateAvailable: false, method: 'trees', changedFiles: [] }
  }
  const fetchText = options.fetchText
  const files = Array.isArray(p.files) ? p.files : []
  try {
    const tree = await fetchUpstreamTree(fetchText)
    const changedFiles = files
      .filter((file) => !tree.blobs.has(file.path) || tree.blobs.get(file.path) !== file.blobSha)
      .map((file) => file.path)
    return {
      checked: true,
      updateAvailable: tree.commitSha !== p.commitSha || changedFiles.length > 0,
      method: 'trees',
      changedFiles,
      commitSha: tree.commitSha,
    }
  } catch (apiError) {
    const fetchHeaders = options.fetchHeaders
    const withEtag = files.filter((file) => file.etag)
    // 没有 ETag 基线就没有备用检测手段；报「查不到」，不能当成「没有更新」。
    if (!fetchHeaders || !withEtag.length) {
      return {
        checked: false,
        updateAvailable: false,
        method: 'head',
        changedFiles: [],
        error: `trees API 失败（${apiError?.message ?? apiError}），且基线没有 ETag，无法使用备用检测`,
      }
    }
    const changedFiles = []
    const errors = []
    let changed = false
    await mapWithConcurrency(files, LIST_FETCH_CONCURRENCY, async (file) => {
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
        errors.push(`${shortPath(file.path)}：${e?.message ?? e}`)
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

/**
 * 从 pin / 快照 commit 到当前 master 落后多少个提交。
 * 只在「确实有更新」且基线是 pin 时调用；失败返回 null，不影响更新判定。
 */
export function commitsBehind(fetchText, fromCommit, cache) {
  if (!fromCommit) return Promise.resolve(null)
  const key = `${fromCommit}...${ACL4SSR_BRANCH}`
  const cached = cache?.get(key)
  if (cached) return cached
  const request = (async () => {
    try {
      const url = `${ACL4SSR_API_BASE}/compare/${fromCommit}...${ACL4SSR_BRANCH}`
      const { text } = textOf(await fetchText(url))
      const data = JSON.parse(text)
      return Number.isInteger(data?.ahead_by) && data.ahead_by >= 0 ? data.ahead_by : null
    } catch {
      return null
    }
  })()
  cache?.set(key, request)
  return request
}
