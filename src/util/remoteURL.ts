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
