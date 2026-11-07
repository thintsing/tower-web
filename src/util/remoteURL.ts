/** 单次最多提交的规则集地址数：每个地址都会串行抓取，防止误粘贴整页文本卡住界面。 */
export const MAX_REMOTE_RULE_SET_URLS = 20

/** 从多行 / 空格 / 逗号 / 分号混排的输入里提取规则集地址，保持顺序并去重。 */
export function splitRemoteTextURLs(raw: string): string[] {
  const found = String(raw ?? '').match(/https?:\/\/[^\s<>"'`，。；：！？、（）【】《》「」『』,;]+/gi) ?? []
  const seen = new Set<string>()
  const urls: string[] = []
  for (const token of found) {
    const normalized = normalizeRemoteTextURL(token)
    if (!/^https?:\/\//i.test(normalized)) continue
    const key = normalized.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    urls.push(normalized)
  }
  return urls
}

/** 在线规则集没有填名称时，用地址末段（去掉扩展名）作为默认名。 */
export function remoteRuleSetNameFromURL(url: string): string {
  try {
    const parsed = new URL(url)
    return parsed.pathname.split('/').filter(Boolean).at(-1)?.replace(/\.[^.]+$/, '') || parsed.hostname
  } catch {
    return '在线规则集'
  }
}

/** GitHub / Gitee 网页文件地址 → 可供客户端直接抓取的原始文本地址。 */
export function normalizeRemoteTextURL(raw: string): string {
  const trimmed = raw.trim()
  try {
    const url = new URL(trimmed)
    const host = url.hostname.toLowerCase()
    const parts = url.pathname.split('/').filter(Boolean)
    if ((host === 'github.com' || host === 'www.github.com')
      && parts.length >= 5 && parts[2] === 'blob') {
      return `https://raw.githubusercontent.com/${parts[0]}/${parts[1]}/${parts[3]}/${parts.slice(4).join('/')}`
    }
    if ((host === 'gitee.com' || host === 'www.gitee.com')
      && parts.length >= 5 && parts[2] === 'blob') {
      return `https://gitee.com/${parts[0]}/${parts[1]}/raw/${parts[3]}/${parts.slice(4).join('/')}`
    }
    return url.href
  } catch {
    return trimmed
  }
}
