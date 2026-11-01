// Per-client rule capability summary. The result describes what the current
// generators can actually express, so the export page never promises a
// fully-compatible config when a client will drop rules.
import { subFormatFor, type ClientInfo, type ExportContentMode, type RuleScheme } from '../models/types'
import { targetSupportsRule } from '../rules/capabilities'
import { targetSupportsInlineRuleSets } from '../rules/inlineSets'
import { formatSupportsRemoteRuleSets, supportsRuleSetReference } from '../rules/remoteFormats'
import { prepareSchemeForExport, remoteRuleSetCandidates, remoteRuleSetURL } from './groups'

export interface RuleCompatibility {
  /** The destination only imports node subscriptions. */
  nodeOnly: boolean
  /** Rules our generator will leave out of this client's config. */
  skipped: number
  unsupportedTypes: string[]
  note?: string
  /** The client format can consume at least one native remote rule-set dialect. */
  supportsRemoteRuleSets: boolean
  /** Rule set snapshots added to the scheme. */
  ruleSetCount: number
  /** Snapshots that become one remote reference when preferRuleSets is on. */
  remoteRuleSets: number
  /** Snapshots expanded into individual rules (local sets or unsupported format). */
  inlineRuleSets: number
  /** 规则集为什么没有全部变成远程引用。 */
  ruleSetNote?: string
}

export interface AnalyzeRuleOptions {
  preferRuleSets?: boolean
  /** 仅节点模式会主动省略所有规则，不论客户端本身是否支持。 */
  contentMode?: ExportContentMode
}

/**
 * Analyze one export target against the *source* scheme (not a prepared one).
 * Passing a prepared scheme would double-count custom rules and rule sets.
 */
export function analyzeRuleCompatibility(
  client: ClientInfo,
  scheme: RuleScheme,
  options: AnalyzeRuleOptions = {},
): RuleCompatibility {
  const format = subFormatFor(client)
  const ruleSetCount = scheme.ruleSets?.length ?? 0

  if (format === 'base64' || options.contentMode === 'nodes') {
    return {
      nodeOnly: true,
      skipped: 0,
      unsupportedTypes: [],
      supportsRemoteRuleSets: false,
      ruleSetCount,
      remoteRuleSets: 0,
      inlineRuleSets: 0,
      note: format === 'base64'
        ? `${client.name} 只接收节点订阅，策略组和规则不会写入。`
        : '当前为「仅节点」模式，策略组和规则不会写入配置。',
    }
  }

  const supportsRemoteRuleSets = formatSupportsRemoteRuleSets(format)
  const candidates = remoteRuleSetCandidates(scheme, {
    preferRuleSets: options.preferRuleSets,
    format,
    target: client.target,
  })
  const remoteRuleSets = candidates.filter((item) => item.remote).length
  const inlineRuleSets = ruleSetCount - remoteRuleSets
  const urlSets = (scheme.ruleSets ?? []).filter((set) => remoteRuleSetURL(set)).length
  const blockedByOrder = candidates.some((item) => item.url && !item.remote)
  const localSetsInline = targetSupportsInlineRuleSets(format, client.target)

  // Mirror the actual export pipeline so skipped counts match the generated file.
  const prepared = prepareSchemeForExport(scheme, {}, {
    preferRuleSets: options.preferRuleSets,
    format,
    target: client.target,
  })
  const typeUnsupported = prepared.rules.filter((rule) => !targetSupportsRule(client.target, rule.type))
  const setUnsupported = prepared.rules.filter((rule) =>
    targetSupportsRule(client.target, rule.type)
    && rule.type === 'RULE-SET'
    && !supportsRuleSetReference(rule, format, client.target))
  const skippedRules = [...typeUnsupported, ...setUnsupported]
  const unsupportedTypes = [...new Set(typeUnsupported.map((rule) => rule.type))]
  const noteParts: string[] = []
  if (typeUnsupported.length > 0) {
    noteParts.push(`${client.name} 不支持 ${unsupportedTypes.join('、')} 规则，这 ${typeUnsupported.length} 条会被跳过。`)
  }
  if (setUnsupported.length > 0) {
    noteParts.push(`${setUnsupported.length} 条 RULE-SET 使用了 ${client.name} 无法读取的规则集格式，会被跳过。`)
  }
  const note = noteParts.length ? noteParts.join(' ') : undefined
  const ruleSetNote = options.preferRuleSets && ruleSetCount > 0 && remoteRuleSets < ruleSetCount
    ? blockedByOrder
      ? `方案里还有本地规则；${client.name} 的远程规则集排在本地规则之后，为保持匹配顺序，规则集会展开写入。`
      : urlSets === 0
        ? localSetsInline
          ? '这些规则集来自「我的规则集」，没有可远程引用的地址，会写成客户端内联规则集。'
          : '这些规则集来自「我的规则集」，没有可远程引用的地址，会继续展开写入。'
        : `${client.name} 无法无损转换这些规则集，规则集会展开写入。`
    : undefined

  return {
    nodeOnly: false,
    skipped: skippedRules.length,
    unsupportedTypes,
    supportsRemoteRuleSets,
    ruleSetCount,
    remoteRuleSets,
    inlineRuleSets,
    note,
    ruleSetNote,
  }
}
