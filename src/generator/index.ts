// Export dispatch: pick the generator for a client target.
import type { ClientInfo, ClientTarget, ExportContentMode, ProxyNode, RuleScheme } from '../models/types'
import { subFormatFor, type SubFormat } from '../models/types'
import { generateBase64Subscription } from './base64Sub'
import { clashSkippedCount, generateClashYAML } from './clashYaml'
import { generateEgern } from './egern'
import { formatSupportsProxyCollections, prepareSchemeForExport, type OutputOptions } from './groups'
import { generateLoon } from './loon'
import { generateQuanX } from './quanx'
import { generateSingBox } from './singbox'
import { generateSurge } from './surge'
import { applyTailnets, applyTailnetsForFormat } from './tailnet'

export interface GeneratedConfig {
  text: string
  extension: string
  mime: string
  skipped: number
  /** 实际写入配置的本地节点数量（不含代理集合里的远程节点）。 */
  exportedNodeCount: number
  /** 写入代理集合的订阅数量；节点由客户端更新，不计入本地节点。 */
  remoteSourceCount: number
  /** Tailscale 等生成后提示，显示在配置预览附近。 */
  notes: string[]
}

/**
 * 发布订阅时一次生成全部载体。
 * 客户端订阅地址按自己的 subFormat 取对应结果：
 *  - yaml   → Clash Verge / Mihomo / Stash / FlClash / Egern / Karing …
 *  - surge  → Surge / Surge Mac
 *  - loon   → Loon（Loon 方言，不是 Surge 语法）
 *  - quanx  → Quantumult X（QuanX 方言）
 *  - json   → sing-box MT / Hiddify
 *  - base64 → Shadowrocket / V2Box / Anywhere
 * 任一格式生成失败不影响其余格式（该键留空；服务端对缺失格式返回 406）。
 */
export interface SubscriptionFormats {
  yaml: string
  surge: string
  loon: string
  quanx: string
  json: string
  base64: string
  egern: string
}

export interface SubscriptionFormatOptions extends OutputOptions {
  policySelections?: Record<string, string>
  preferRuleSets?: boolean
  /** 每个载体可以有自己的内容模式（完整配置 / 仅节点）。 */
  contentModeByFormat?: Partial<Record<SubFormat, ExportContentMode>>
}

export function generateSubscriptionFormats(
  nodes: ProxyNode[],
  scheme: RuleScheme,
  options: SubscriptionFormatOptions = {},
): SubscriptionFormats {
  const safe = (fn: () => string): string => {
    try {
      return fn()
    } catch {
      return ''
    }
  }
  // 通用载体没有 target；给每种格式选一个代表性客户端，按它的规则能力
  // 生成，避免把只在别的客户端可用的规则写进订阅。
  const targetByFormat: Partial<Record<SubFormat, ClientTarget>> = {
    yaml: 'clash-verge',
    surge: 'surge',
    loon: 'loon',
    quanx: 'quanx',
    egern: 'egern',
  }
  const forFormat = (format: SubFormat) =>
    prepareSchemeForExport(scheme, options.policySelections ?? {}, {
      preferRuleSets: options.preferRuleSets,
      format,
      target: options.target ?? targetByFormat[format],
    })
  // 通用载体没有 target；选一个有代表性的图标写法，避免发布出去的订阅丢图标。
  const iconTargetByFormat: Partial<Record<SubFormat, ClientTarget>> = {
    yaml: 'clash-verge',
    surge: 'surge',
    loon: 'loon',
    quanx: 'quanx',
    egern: 'egern',
  }
  const forOutput = (format: SubFormat) => ({
    ...options,
    target: options.target ?? targetByFormat[format],
    contentMode: options.contentModeByFormat?.[format] ?? options.contentMode,
    iconTarget: options.iconTarget ?? iconTargetByFormat[format],
  })
  const yamlMode = forOutput('yaml').contentMode ?? 'full'
  const surgeMode = forOutput('surge').contentMode ?? 'full'
  const jsonMode = forOutput('json').contentMode ?? 'full'
  return {
    yaml: safe(() => applyTailnetsForFormat(
      generateClashYAML(nodes, forFormat('yaml'), forOutput('yaml')),
      'yaml', yamlMode, options.tailnets ?? [],
    )),
    surge: safe(() => applyTailnetsForFormat(
      generateSurge(nodes, forFormat('surge'), forOutput('surge')).text,
      'surge', surgeMode, options.tailnets ?? [],
    )),
    loon: safe(() => generateLoon(nodes, forFormat('loon'), forOutput('loon')).text),
    quanx: safe(() => generateQuanX(nodes, forFormat('quanx'), forOutput('quanx')).text),
    json: safe(() => applyTailnetsForFormat(
      generateSingBox(nodes, forFormat('json'), forOutput('json')).text,
      'json', jsonMode, options.tailnets ?? [],
    )),
    base64: safe(() => generateBase64Subscription(nodes, forOutput('base64')).text),
    egern: safe(() => generateEgern(nodes, forFormat('egern'), forOutput('egern')).text),
  }
}

/** 按客户端声明的 subFormat 生成完整配置文本，供下载 / 预览 / 一键导入复用。 */
export function generateConfig(
  client: ClientInfo,
  nodes: ProxyNode[],
  scheme: RuleScheme,
  options: OutputOptions = {},
): GeneratedConfig {
  const format: SubFormat = subFormatFor(client)
  const contentMode = options.contentMode ?? (client.contentMode === 'nodes' ? 'nodes' : 'full')
  const remoteSources = formatSupportsProxyCollections(format)
    && contentMode !== 'nodes'
    && client.target !== 'shadowrocket'
    ? (options.remoteSubscriptions ?? [])
    : []
  const remoteSourceIDs = new Set(remoteSources.map((source) => source.id))
  const localNodes = nodes.filter((node) => !(node.sourceID && remoteSourceIDs.has(node.sourceID)))
  const targetOptions = { ...options, target: client.target, remoteSubscriptions: remoteSources }
  const base = (() => {
    switch (format) {
      case 'yaml': {
        const skipped = clashSkippedCount(localNodes, client.target)
        return {
          text: generateClashYAML(nodes, scheme, targetOptions),
          extension: 'yaml',
          mime: 'text/yaml',
          skipped,
          exportedNodeCount: Math.max(0, localNodes.length - skipped),
          remoteSourceCount: remoteSources.length,
        }
      }
      case 'surge': {
        const { text, skipped } = generateSurge(nodes, scheme, targetOptions)
        return {
          text, extension: 'conf', mime: 'text/plain', skipped,
          exportedNodeCount: Math.max(0, localNodes.length - skipped),
          remoteSourceCount: remoteSources.length,
        }
      }
      case 'loon': {
        const { text, skipped } = generateLoon(nodes, scheme, targetOptions)
        return {
          text, extension: 'conf', mime: 'text/plain', skipped,
          exportedNodeCount: Math.max(0, localNodes.length - skipped),
          remoteSourceCount: remoteSources.length,
        }
      }
      case 'quanx': {
        const { text, skipped } = generateQuanX(nodes, scheme, targetOptions)
        return {
          text, extension: 'conf', mime: 'text/plain', skipped,
          exportedNodeCount: Math.max(0, localNodes.length - skipped),
          remoteSourceCount: remoteSources.length,
        }
      }
      case 'json': {
        const { text, skipped } = generateSingBox(nodes, scheme, targetOptions)
        return {
          text, extension: 'json', mime: 'application/json', skipped,
          exportedNodeCount: Math.max(0, nodes.length - skipped), remoteSourceCount: 0,
        }
      }
      case 'egern': {
        const { text, skipped } = generateEgern(nodes, scheme, targetOptions)
        return {
          text, extension: 'yaml', mime: 'text/yaml', skipped,
          exportedNodeCount: Math.max(0, localNodes.length - skipped),
          remoteSourceCount: remoteSources.length,
        }
      }
      case 'base64': {
        const { text, skipped } = generateBase64Subscription(nodes, targetOptions)
        return {
          text, extension: 'txt', mime: 'text/plain', skipped,
          exportedNodeCount: Math.max(0, nodes.length - skipped), remoteSourceCount: 0,
        }
      }
    }
  })()
  const applied = applyTailnets(base.text, client.target, contentMode, options.tailnets ?? [])
  return { ...base, text: applied.text, notes: applied.notes }
}
