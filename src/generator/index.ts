// Export dispatch: pick the generator for a client target.
import type { ClientInfo, ClientTarget, ExportContentMode, ProxyNode, RuleScheme, RuleSetExclusionTable } from '../models/types'
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
  /** 只读规则集的本地屏蔽表；发布出去的每个载体都要过滤。 */
  ruleSetExclusions?: RuleSetExclusionTable
  /** 每个载体可以有自己的内容模式（完整配置 / 仅节点）。 */
  contentModeByFormat?: Partial<Record<SubFormat, ExportContentMode>>
}

/** 订阅链接一次携带的载体；顺序与 B 服务端接受顺序一致，也用于结果展示。 */
export const SUBSCRIPTION_FORMAT_ORDER: readonly SubFormat[] = [
  'yaml', 'egern', 'surge', 'loon', 'quanx', 'json', 'base64',
]

export const SUBSCRIPTION_FORMAT_TITLES: Record<SubFormat, string> = {
  yaml: 'Clash / mihomo YAML',
  egern: 'Egern YAML',
  surge: 'Surge',
  loon: 'Loon',
  quanx: 'Quantumult X',
  json: 'sing-box JSON',
  base64: 'Base64 通用链接',
}

export interface SubscriptionFormatFailure {
  format: SubFormat
  /** 生成失败原因：异常信息，或「内容为空」。 */
  reason: string
}

export interface SubscriptionFormatsResult {
  formats: SubscriptionFormats
  /** 没有生成成功的载体；发布前必须逐条展示，否则缺失格式的客户端会收到 406。 */
  failures: SubscriptionFormatFailure[]
}

/** 发布前与目标格式集合对比：返回内容为空 / 缺失的载体。 */
export function missingSubscriptionFormats(
  formats: Partial<Record<SubFormat, string>>,
  required: readonly SubFormat[] = SUBSCRIPTION_FORMAT_ORDER,
): SubFormat[] {
  return required.filter((format) => !(formats[format] ?? '').trim())
}

/** 把失败载体列表写成界面可直接展示的一句话。 */
export function describeSubscriptionFormatFailures(failures: SubscriptionFormatFailure[]): string {
  return failures
    .map((item) => `${SUBSCRIPTION_FORMAT_TITLES[item.format]}（${item.format}）：${item.reason}`)
    .join('；')
}

export function generateSubscriptionFormatsDetailed(
  nodes: ProxyNode[],
  scheme: RuleScheme,
  options: SubscriptionFormatOptions = {},
): SubscriptionFormatsResult {
  const formats: SubscriptionFormats = {
    yaml: '',
    surge: '',
    loon: '',
    quanx: '',
    json: '',
    base64: '',
    egern: '',
  }
  const failures: SubscriptionFormatFailure[] = []
  // 失败必须留下原因：服务端只保存非空载体，静默留空会让部分客户端在拉取时 406。
  const build = (format: SubFormat, run: () => string): void => {
    try {
      const text = run()
      if (!text.trim()) {
        failures.push({ format, reason: '生成的配置内容为空' })
        return
      }
      formats[format] = text
    } catch (error) {
      const reason = error instanceof Error && error.message
        ? error.message
        : String(error) || '未知错误'
      failures.push({ format, reason })
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
      ruleSetExclusions: options.ruleSetExclusions,
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
  build('yaml', () => applyTailnetsForFormat(
    generateClashYAML(nodes, forFormat('yaml'), forOutput('yaml')),
    'yaml', yamlMode, options.tailnets ?? [],
  ))
  build('surge', () => applyTailnetsForFormat(
    generateSurge(nodes, forFormat('surge'), forOutput('surge')).text,
    'surge', surgeMode, options.tailnets ?? [],
  ))
  build('loon', () => generateLoon(nodes, forFormat('loon'), forOutput('loon')).text)
  build('quanx', () => generateQuanX(nodes, forFormat('quanx'), forOutput('quanx')).text)
  build('json', () => applyTailnetsForFormat(
    generateSingBox(nodes, forFormat('json'), forOutput('json')).text,
    'json', jsonMode, options.tailnets ?? [],
  ))
  build('base64', () => generateBase64Subscription(nodes, forOutput('base64')).text)
  build('egern', () => generateEgern(nodes, forFormat('egern'), forOutput('egern')).text)
  return { formats, failures }
}

/** 兼容只需要载体文本的调用方（预览等）；发布流程用 detailed 版本拿到失败原因。 */
export function generateSubscriptionFormats(
  nodes: ProxyNode[],
  scheme: RuleScheme,
  options: SubscriptionFormatOptions = {},
): SubscriptionFormats {
  return generateSubscriptionFormatsDetailed(nodes, scheme, options).formats
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
          text, extension: contentMode === 'nodes' ? 'txt' : 'conf', mime: 'text/plain', skipped,
          exportedNodeCount: Math.max(0, localNodes.length - skipped),
          remoteSourceCount: remoteSources.length,
        }
      }
      case 'loon': {
        const { text, skipped } = generateLoon(nodes, scheme, targetOptions)
        return {
          text, extension: contentMode === 'nodes' ? 'txt' : 'conf', mime: 'text/plain', skipped,
          exportedNodeCount: Math.max(0, localNodes.length - skipped),
          remoteSourceCount: remoteSources.length,
        }
      }
      case 'quanx': {
        const { text, skipped } = generateQuanX(nodes, scheme, targetOptions)
        return {
          text, extension: contentMode === 'nodes' ? 'txt' : 'conf', mime: 'text/plain', skipped,
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
