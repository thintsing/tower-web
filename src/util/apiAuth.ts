// LAN API key handling. A key is captured from `?key=` when the page is opened,
// stored locally, and attached to every same-origin `/api/*` request. Hiding the
// key from the address bar keeps screenshots and shared links from leaking it.
const STORAGE_KEY = 'tower-web-api-key'

export function getAPIKey(): string {
  try {
    return localStorage.getItem(STORAGE_KEY)?.trim() ?? ''
  } catch {
    return ''
  }
}

export function setAPIKey(key: string): void {
  try {
    const trimmed = key.trim()
    if (trimmed) localStorage.setItem(STORAGE_KEY, trimmed)
    else localStorage.removeItem(STORAGE_KEY)
  } catch {
    // localStorage 不可用时，用户仍可在本机无密钥访问。
  }
}

export function clearAPIKey(): void {
  setAPIKey('')
}

/** 打开 `http://host:8787/?key=…` 时保存密钥，并把密钥从地址栏移除。 */
export function captureAPIKeyFromURL(): void {
  try {
    const url = new URL(window.location.href)
    const key = url.searchParams.get('key')?.trim()
    if (!key) return
    setAPIKey(key)
    url.searchParams.delete('key')
    window.history.replaceState(window.history.state, '', `${url.pathname}${url.search}${url.hash}`)
  } catch {
    // ignore malformed URL / restricted history
  }
}

/** 所有塔台管理 API 都走这里；外部地址和静态文件不附加密钥。 */
export function apiFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const key = getAPIKey()
  if (!key) return fetch(input, init)
  let url: URL
  try {
    url = new URL(input, window.location.origin)
  } catch {
    return fetch(input, init)
  }
  if (url.origin !== window.location.origin || !url.pathname.startsWith('/api/')) {
    return fetch(input, init)
  }
  if (!url.searchParams.has('key')) url.searchParams.set('key', key)
  const headers = new Headers(init.headers)
  headers.set('x-tower-key', key)
  return fetch(url.toString(), { ...init, headers })
}
