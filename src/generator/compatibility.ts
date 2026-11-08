// Per-client rule capability summary. The result describes what the current
// generators can actually express, so the export page never promises a
// fully-compatible config when a client will drop rules.
import { subFormatFor, type ClientInfo, type ExportContentMode, type ProxyNode, type RuleScheme, type RuleSetExclusionTable } from '../models/types'
import { targetSupportsRule } from '../rules/capabilities'
import { targetSupportsInlineRuleSets } from '../rules/inlineSets'
import { formatSupportsRemoteRuleSets, providerOnlyCanReference, supportsRuleSetReference } from '../rules/remoteFormats'
import { prepareSchemeForExport, remoteRuleSetCandidates, remoteRuleSetURL, resolveGroups } from './groups'

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
  /**
   * 方案里有只存 provider 引用的规则集，而当前客户端读不了。
   * 此时导出必须硬阻断：不能生成只有 FINAL 的「看似成功」的配置。
   */
  providerOnlyBlocked: boolean
  providerOnlyNote?: string
  /** 只存 provider 引用的规则集数量（不需要开关也会写成远程引用）。 */
  providerOnlyCount: number
  /**
   * 解析后没有任何成员的策略组。客户端（尤其 mihomo）会拒绝加载这类空组，
   * 导出必须硬阻断，不能产出看似成功但无法加载的配置。
   */
  emptyGroups: string[]
  emptyGroupsBlocked: boolean
  emptyGroupsNote?: string
}

export interface AnalyzeRuleOptions {
  preferRuleSets?: boolean
  /** 仅节点模式会主动省略所有规则，不论客户端本身是否支持。 */
  contentMode?: ExportContentMode
  /** 只读规则集的本地屏蔽表；必须与实际导出使用同一份。 */
  ruleSetExclusions?: RuleSetExclusionTable
  /** 托管规则集的对外基础地址；空字符串表示明确不可用。 */
  hostedBaseURL?: string
  /**
   * 实际参与导出的节点；用于检测解析后为空的策略组。
   * 缺省时跳过该检测（方案检查等不涉及导出的调用保持原行为）。
   */
  nodes?: ProxyNode[]
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
  // 内联规则集（固化快照）已经写在方案规则里，不计入「导出时要展开的规则集」。
  const countedSets = (scheme.ruleSets ?? []).filter((set) => !set.inlined)
  const ruleSetCount = countedSets.length
  const providerOnlySets = countedSets.filter((set) => set.providerOnly)
  const providerOnlyCount = providerOnlySets.length
  const providerOnlyReferenced = providerOnlySets.filter((set) =>
    providerOnlyCanReference(set, format, client.target, options.hostedBaseURL))
  const providerOnlyOmitted = providerOnlySets
    .filter((set) => !providerOnlyReferenced.includes(set))
    .map((set) => set.name)
  // 一条都引用不了才算硬阻断；只丢个别列表（例如 Loon 的 PROCESS-NAME）时明确提示。
  const providerOnlyBlocked = providerOnlyCount > 0 && providerOnlyReferenced.length === 0
  const hostedBaseMissing = providerOnlyCount > 0 && format !== 'yaml' && options.hostedBaseURL === ''
  const providerOnlyNote = providerOnlyBlocked
    ? hostedBaseMissing
      ? `这个方案只保存 ${providerOnlyCount} 组 Clash provider 引用；当前没有可用的托管地址（塔台服务未响应，或没有手机能访问的地址），导出已停止。`
      : `这个方案只保存 ${providerOnlyCount} 组 Clash provider 引用（不保存正文），${client.name} 无法读取；导出已停止。请改用 Clash / mihomo 系客户端。`
    : providerOnlyOmitted.length > 0
      ? `${providerOnlyOmitted.length} 组规则集（${providerOnlyOmitted.join('、')}）无法转换到 ${client.name} 的远程列表格式，导出时会省略。`
      : undefined

  if (format === 'base64' || options.contentMode === 'nodes') {
    return {
      nodeOnly: true,
      skipped: 0,
      unsupportedTypes: [],
      supportsRemoteRuleSets: false,
      ruleSetCount,
      remoteRuleSets: 0,
      inlineRuleSets: 0,
      providerOnlyBlocked: false,
      providerOnlyCount,
      emptyGroups: [],
      emptyGroupsBlocked: false,
      note: format === 'base64'
        ? `${client.name} 只接收节点订阅，策略组和规则不会写入。`
        : '当前为「仅节点」模式，策略组和规则不会写入配置。',
    }
  }

  // 空策略组：客户端会拒绝加载整份配置。这里用与生成器相同的分组解析，
  // 在导出入口一次性阻断，避免每个生成器各弹一次重复提示。
  const emptyGroups = options.nodes === undefined
    ? []
    : resolveGroups(scheme, options.nodes, (item) => item.name)
        .filter((resolved) => resolved.members.length === 0)
        .map((resolved) => resolved.group.name)
  const emptyGroupsBlocked = emptyGroups.length > 0
  const emptyGroupsNote = emptyGroupsBlocked
    ? `${emptyGroups.length === 1
        ? `策略组「${emptyGroups[0]}」`
        : `${emptyGroups.length} 个策略组（${emptyGroups.slice(0, 3).join('、')}）`}在导出时没有任何成员${options.nodes?.length === 0 ? '（当前导出没有可用节点）' : ''}；客户端会拒绝加载这份配置。请先启用节点，或给这些组添加候选策略后再导出。`
    : undefined

  const supportsRemoteRuleSets = formatSupportsRemoteRuleSets(format)
  const candidates = remoteRuleSetCandidates(scheme, {
    preferRuleSets: options.preferRuleSets,
    format,
    target: client.target,
    ruleSetExclusions: options.ruleSetExclusions,
    hostedBaseURL: options.hostedBaseURL,
  })
  const remoteRuleSets = candidates.filter((item) => item.remote).length
  const inlineRuleSets = ruleSetCount - remoteRuleSets
  const urlSets = countedSets.filter((set) => remoteRuleSetURL(set)).length
  const blockedByOrder = candidates.some((item) => item.url && !item.remote)
  const localSetsInline = targetSupportsInlineRuleSets(format, client.target)

  // Mirror the actual export pipeline so skipped counts match the generated file.
  const prepared = prepareSchemeForExport(scheme, {}, {
    preferRuleSets: options.preferRuleSets,
    format,
    target: client.target,
    ruleSetExclusions: options.ruleSetExclusions,
    hostedBaseURL: options.hostedBaseURL,
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
  const ruleSetNote = providerOnlyBlocked
    ? providerOnlyNote
    : options.preferRuleSets && ruleSetCount > 0 && remoteRuleSets < ruleSetCount
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
    providerOnlyBlocked,
    providerOnlyNote,
    providerOnlyCount,
    emptyGroups,
    emptyGroupsBlocked,
    emptyGroupsNote,
  }
}
