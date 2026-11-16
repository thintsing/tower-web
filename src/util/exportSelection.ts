// 导出页共用的文件名、客户端顺序与节点筛选；从 App.tsx 下沉，供页面组件复用。
import type { ClientInfo, ClientTarget, ExportContentMode, NodeNameFilterSettings, ProxyNode } from '../models/types'
import { CLIENTS } from '../models/types'
import { stripSchemeCustomSuffix } from '../rules/schemeCopy'

/** 配置文件名：去掉 Windows / macOS 不允许的路径字符。 */
export function configFileStem(name: string): string {
  const cleaned = name.trim().replace(/[\\/:*?"<>|]/g, '_').replace(/\s+/g, ' ')
  return cleaned || 'tower'
}

export function schemeDisplayName(name: string, custom?: boolean): string {
  const base = stripSchemeCustomSuffix(name)
  return custom ? `${base} · 自定义` : base
}

/** 全局节点名称筛选：关键词按行，或切换为正则。 */
export function filterNodesByName(
  nodes: ProxyNode[],
  settings: NodeNameFilterSettings,
): { nodes: ProxyNode[]; error?: string } {
  const compile = (text: string) => {
    const lines = text.split('\n').map((line) => line.trim()).filter(Boolean)
    const regexes: RegExp[] = []
    for (const line of lines) {
      try {
        regexes.push(new RegExp(
          settings.useRegex ? line : line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
          settings.caseSensitive ? '' : 'i',
        ))
      } catch {
        return { error: `筛选表达式无效：${line}` }
      }
    }
    return { regexes }
  }
  const included = compile(settings.include)
  if (included.error) return { nodes: [], error: included.error }
  const excluded = compile(settings.exclude)
  if (excluded.error) return { nodes: [], error: excluded.error }
  const include = included.regexes ?? []
  const exclude = excluded.regexes ?? []
  return {
    nodes: nodes.filter((node) => {
      if (exclude.some((regex) => regex.test(node.name))) return false
      return include.length === 0 || include.some((regex) => regex.test(node.name))
    }),
  }
}

export function effectiveContentMode(
  client: ClientInfo,
  modes: Partial<Record<ClientTarget, ExportContentMode>>,
  fallback: ExportContentMode,
): ExportContentMode {
  if (client.contentMode === 'nodes') return 'nodes'
  return modes[client.target] ?? fallback
}

/** 客户端顺序：保留用户排序，新版本新增的客户端自动排在末尾。 */
export function clientsInOrder(order: ClientTarget[]): ClientInfo[] {
  const known = new Map(CLIENTS.map((client) => [client.target, client]))
  const result: ClientInfo[] = []
  const seen = new Set<ClientTarget>()
  for (const target of order) {
    const client = known.get(target)
    if (!client || seen.has(target)) continue
    seen.add(target)
    result.push(client)
  }
  for (const client of CLIENTS) {
    if (!seen.has(client.target)) result.push(client)
  }
  return result
}
