// 自有节点导入：复用订阅解析器，但节点不挂在任何订阅上。
// 订阅刷新、删除订阅都不会影响这些节点；它们会像本地节点一样进入导出。
import type { ProxyNode } from './models/types'
import { parse } from './parser'

export interface ManualNodeImportResult {
  nodes: ProxyNode[]
  /** 解析器无法识别、或不属于节点的行数。 */
  rejected: number
  /** 已经在「自有节点」里存在的重复节点数。 */
  duplicates: number
}

/** 与解析器内部的去重键保持一致；名称不参与比较，改名后仍能识别重复。 */
function identity(node: ProxyNode): string {
  return [
    node.kind,
    node.server.toLowerCase(),
    node.port,
    node.cipher ?? '',
    node.password ?? '',
    node.uuid ?? '',
    node.username ?? '',
    node.transport ?? '',
    node.sni ?? '',
    node.path ?? '',
    node.hostHeader ?? '',
    node.protocolName ?? '',
    node.obfs ?? '',
    node.wireGuardPrivateKey ?? '',
    node.wireGuardPublicKey ?? '',
    node.wireGuardIPv4 ?? '',
    node.wireGuardIPv6 ?? '',
    node.masque?.privateKey ?? '',
    node.masque?.publicKey ?? '',
    node.ssh?.privateKey ?? '',
  ].join('|')
}

/**
 * 把链接 / Base64 / Clash YAML / Surge 配置片段转换成可保存的自有节点。
 * 只跟已有的自有节点去重，不阻止用户把订阅里的同一节点另存一份。
 */
export function prepareManualNodes(
  text: string,
  preferredName: string,
  existing: readonly ProxyNode[],
): ManualNodeImportResult {
  const parsed = parse(text)
  const examples = parsed.nodes.filter((node) => !node.isSubscriptionMetadata)
  const existingKeys = new Set(
    existing.filter((node) => node.isManual).map(identity),
  )
  const nodes: ProxyNode[] = []
  let duplicates = 0
  for (const node of examples) {
    const key = identity(node)
    if (existingKeys.has(key)) {
      duplicates += 1
      continue
    }
    existingKeys.add(key)
    nodes.push({
      ...node,
      sourceID: undefined,
      isManual: true,
      isEnabled: true,
    })
  }

  const cleanName = preferredName.replace(/[\r\n]+/g, ' ').trim().slice(0, 120)
  if (nodes.length === 1 && cleanName) {
    nodes[0] = { ...nodes[0], name: cleanName }
  }

  return { nodes, rejected: parsed.rejectedLineCount, duplicates }
}
