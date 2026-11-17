// 客户端专属订阅链接：在已发布地址上补 format / target，可选只要节点。
import { subFormatFor, type ClientInfo } from '../models/types'

export interface ClientSubscriptionLinkOptions {
  /** 服务器模式的地址由服务端固定，不能替换成当前页面的 host。 */
  serverMode: boolean
  /** 本地模式用于把旧地址换成当前访问入口；服务器模式忽略。 */
  origin: string
  /** 只下发节点，不写规则。 */
  nodesOnly?: boolean
}

export function clientSubscriptionLink(
  base: string,
  client: ClientInfo,
  options: ClientSubscriptionLinkOptions,
): string {
  if (!base) return ''
  try {
    const raw = new URL(base, options.origin)
    const url = options.serverMode
      ? new URL(raw.toString())
      : new URL(`${raw.pathname}${raw.search}`, options.origin)
    url.searchParams.set('format', subFormatFor(client))
    // target 让服务端在存在客户端专属变体（如 Stash / Surge Mac）时选对写法。
    url.searchParams.set('target', client.target)
    if (options.nodesOnly) url.searchParams.set('content', 'nodes')
    return url.href
  } catch {
    // localStorage 里的旧地址被改坏时，别让整个导出页白屏。
    return ''
  }
}
