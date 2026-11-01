// 批量订阅链接：每行一条，忽略空行 / # 注释，并区分常见的 HTTP 代理节点。
// 订阅地址本身可以带 query token，因此这里只做格式判断，不改写用户地址。

export const MAX_BATCH_SUBSCRIPTIONS = 20

export interface SubscriptionBatch {
  urls: string[]
  /** 与前面的地址完全相同的行数。 */
  duplicates: number
  /** 不是 http(s) 地址或缺少主机名的行数。 */
  invalid: number
  /** 看起来是 http(s) 代理节点而不是订阅地址的行数。 */
  proxyCount: number
  /** 超过单次上限、未纳入导入的行数。 */
  truncated: number
}

/** 与 iOS SourceInputDetector 的 HTTP 代理判断保持一致。 */
function looksLikeHttpProxy(url: URL): boolean {
  return url.username !== ''
    || (url.port !== ''
      && url.pathname === '/'
      && (url.protocol === 'http:' || url.hash !== ''))
}

export function splitSubscriptionURLs(raw: string): SubscriptionBatch {
  const urls: string[] = []
  const seen = new Set<string>()
  let duplicates = 0
  let invalid = 0
  let proxyCount = 0

  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    let parsed: URL
    try {
      parsed = new URL(line)
    } catch {
      invalid += 1
      continue
    }
    if (!/^https?:$/.test(parsed.protocol) || !parsed.hostname) {
      invalid += 1
      continue
    }
    if (looksLikeHttpProxy(parsed)) {
      proxyCount += 1
      continue
    }
    if (seen.has(line)) {
      duplicates += 1
      continue
    }
    seen.add(line)
    urls.push(line)
  }

  const truncated = Math.max(0, urls.length - MAX_BATCH_SUBSCRIPTIONS)
  return {
    urls: urls.slice(0, MAX_BATCH_SUBSCRIPTIONS),
    duplicates,
    invalid,
    proxyCount,
    truncated,
  }
}

/** 失败列表里只显示主机和路径，避免把 query 里的订阅 token 带进界面。 */
export function subscriptionLabel(url: string): string {
  try {
    const parsed = new URL(url)
    const path = parsed.pathname === '/' ? '' : parsed.pathname
    return `${parsed.hostname}${path}`.slice(0, 96)
  } catch {
    return url.slice(0, 96)
  }
}
