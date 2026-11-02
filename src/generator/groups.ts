// Shared group→node resolution for all generators.
// A scheme group's nodeFilter regex is matched against node display names;
// declared options ([]引用 / DIRECT / REJECT) always come first.
import type { ClientTarget, ExportContentMode, PolicyGroup, ProxyNode, RemoteSubscriptionEntry, RoutingRule, RuleScheme, RuleSetFormat, SchemeRuleSet, SubFormat, TailnetExport } from '../models/types'
import {
  classicalRulesFitTarget,
  hostedDialectForFormat,
  hostedRuleSetURL,
  ruleSetFormatForDialect,
  ruleSetFormatOfSet,
  ruleSetRulesFitDialect,
  subFormatSupportsRuleSetFormat,
  targetSupportsRuleSetFormat,
} from '../rules/remoteFormats'
import { mihomoBinaryPlan, singBoxBinaryPlan } from '../rules/binaryRuleSets'
import { inlineRuleSetMetadata } from '../rules/inlineSets'
import { reorderRulesByMatchingOrder } from '../rules/matchingOrder'

/** 所有客户端生成器共用的导出选项。 */
export interface OutputOptions {
  contentMode?: ExportContentMode
  /** 目标客户端；提供时按该客户端的规则能力过滤。 */
  target?: ClientTarget
  /** 图标 / 组名 Emoji 的渲染目标；缺省跟随 target。用于发布通用载体时选代表客户端。 */
  iconTarget?: ClientTarget
  /** 生成配置时使用的节点显示名（例如追加订阅名）；不修改节点本身。 */
  nameForNode?: (node: ProxyNode) => string
  /** 代理集合：把这些启用订阅的原始 URL 写入完整配置。 */
  remoteSubscriptions?: RemoteSubscriptionEntry[]
  /** Tailscale 内网；只在完整配置里写入。 */
  tailnets?: TailnetExport[]
}

export interface ResolvedGroup {
  group: PolicyGroup
  /** Referenced group names, DIRECT/REJECT and matched node names, in order. */
  members: string[]
}

/**
 * Display names must be unique inside a config; airports reuse the same
 * remark. Suffix duplicates `Name`, `Name 2`, `Name 3`… (after escaping).
 */
export function uniqueDisplayNames(
  nodes: ProxyNode[],
  escape: (s: string) => string,
  nameFor?: (node: ProxyNode) => string,
): Map<string, string> {
  const taken = new Map<string, number>()
  const out = new Map<string, string>()
  for (const node of nodes) {
    const base = escape(nameFor?.(node) ?? node.name)
    const count = taken.get(base) ?? 0
    taken.set(base, count + 1)
    out.set(node.id, count === 0 ? base : `${base} ${count + 1}`)
  }
  return out
}

export function resolveGroups(
  scheme: RuleScheme,
  nodes: ProxyNode[],
  displayName: (node: ProxyNode) => string,
): ResolvedGroup[] {
  const names = nodes.map((n) => displayName(n))
  return scheme.groups.map((group) => {
    const members: string[] = [...group.options]
    if (group.nodeFilter) {
      let regex: RegExp | undefined
      try {
        regex = new RegExp(group.nodeFilter)
      } catch {
        regex = undefined
      }
      if (regex) {
        // 正则匹配原始节点名：追加订阅名只改变显示名，不应改变分组归属。
        nodes.forEach((node, index) => {
          const name = names[index]
          if (regex!.test(node.name) && !members.includes(name)) members.push(name)
        })
      }
    }
    // 界面选择的首选成员：先按声明候选匹配，再按原节点名映射到实际显示名。
    if (group.selected) {
      let target = members.includes(group.selected) ? group.selected : undefined
      if (!target) {
        const index = nodes.findIndex((node) => node.name === group.selected)
        if (index >= 0) target = names[index]
      }
      if (target && members.includes(target)) {
        members.splice(members.indexOf(target), 1)
        members.unshift(target)
      }
    }
    return { group, members }
  })
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** 精确匹配节点名的正则；多个名字用 OR 连接。 */
export function exactNamePattern(names: string[]): string {
  const values = [...new Set(names)].map(escapeRegex)
  if (values.length === 0) return ''
  return values.length === 1 ? `^${values[0]}$` : `^(?:${values.join('|')})$`
}

/** 代理集合：把订阅地址写进客户端，节点不再逐条内联。 */
export function formatSupportsProxyCollections(format: SubFormat): boolean {
  return format === 'yaml' || format === 'surge' || format === 'loon'
    || format === 'quanx' || format === 'egern'
}

export interface RemoteNodePlan {
  sources: RemoteSubscriptionEntry[]
  sourceIDs: Set<string>
  /** 仍然需要逐条写进配置的节点。 */
  localNodes: ProxyNode[]
}

export function remoteNodePlan(
  nodes: ProxyNode[],
  remoteSubscriptions: RemoteSubscriptionEntry[] | undefined,
  contentMode: ExportContentMode | undefined,
): RemoteNodePlan {
  const sources = contentMode === 'nodes'
    ? []
    : (remoteSubscriptions ?? []).filter((source) => /^https?:\/\//i.test(source.url))
  const sourceIDs = new Set(sources.map((source) => source.id))
  return {
    sources,
    sourceIDs,
    localNodes: nodes.filter((node) => !(node.sourceID && sourceIDs.has(node.sourceID))),
  }
}

export interface RemoteGroupSelection {
  sources: RemoteSubscriptionEntry[]
  /** 需要客户端按节点名再筛一次；缺省表示整组订阅都可用。 */
  filter?: string
}

/**
 * 哪些代理集合里的节点会进入这个策略组。
 * 有 nodeFilter 时按正规节点名匹配；没有时退回组里声明的节点名。
 */
export function remoteGroupSelection(
  group: PolicyGroup,
  nodes: ProxyNode[],
  remoteSources: RemoteSubscriptionEntry[],
  displayName: (node: ProxyNode) => string = (node) => node.name,
): RemoteGroupSelection {
  if (!remoteSources.length) return { sources: [] }
  let regex: RegExp | undefined
  if (group.nodeFilter) {
    try {
      regex = new RegExp(group.nodeFilter)
    } catch {
      regex = undefined
    }
  }
  const optionNames = new Set(group.options)
  const matches = (node: ProxyNode) => regex
    ? regex.test(node.name)
    : optionNames.has(displayName(node))
  const sources: RemoteSubscriptionEntry[] = []
  const matchedNames: string[] = []
  for (const source of remoteSources) {
    const sourceNodes = nodes.filter((node) => node.sourceID === source.id && matches(node))
    if (!sourceNodes.length) continue
    sources.push(source)
    matchedNames.push(...sourceNodes.map((node) => node.name))
  }
  const filter = regex && group.nodeFilter !== '.*'
    ? group.nodeFilter
    : !regex && matchedNames.length
      ? exactNamePattern(matchedNames)
      : undefined
  return { sources, filter }
}

/** 代理集合在 [Remote Proxy] / [server_remote] 里的显示名，避免和组/节点重名。 */
export function remoteSourceAliases(
  sources: RemoteSubscriptionEntry[],
  usedNames: Set<string>,
  transform: (value: string) => string,
  fallback = '代理集合',
): Map<string, string> {
  const aliases = new Map<string, string>()
  for (const source of sources) {
    const base = transform(source.name) || fallback
    let candidate = base
    let suffix = 2
    while (usedNames.has(candidate)) {
      candidate = `${base} ${suffix}`
      suffix += 1
    }
    usedNames.add(candidate)
    aliases.set(source.id, candidate)
  }
  return aliases
}

export function compileRuleLine(
  rule: { type: string; value?: string; noResolve?: boolean; options?: string[]; raw?: string },
  group: string,
): string {
  if (rule.type === 'FINAL') return `MATCH,${group}`
  if (rule.raw) return `${rule.raw},${group}`
  const options = [...(rule.options ?? [])]
  // no-resolve 只对 IP 类规则有效；GEOIP 带上它会被 mihomo 判为非法参数。
  const sourceNoResolve = options.some((option) => option.toLowerCase() === 'no-resolve')
  if (rule.noResolve && !sourceNoResolve) options.push('no-resolve')
  const filtered = rule.type === 'GEOIP'
    ? options.filter((option) => option.toLowerCase() !== 'no-resolve')
    : options
  return [rule.type, rule.value ?? '', group, ...filtered].join(',')
}

/**
 * 内置 ACL4SSR 快照对应的上游固定提交。用户开启“优先引用规则集”时，
 * Clash / Surge / QuanX 会直接引用这些远程列表，而不是把规则全部内联。
 */
const ACL4SSR_COMMIT = '802e3abf065f8609e7d9073ba506158dbe2ba6e7'

export function remoteRuleSetURL(set: SchemeRuleSet): string | undefined {
  if (set.sourceKind === 'local') return undefined
  if (set.sourceKind === 'url') {
    return /^https?:\/\//i.test(set.sourceRef ?? '') ? set.sourceRef : undefined
  }
  if (!set.sourceRef?.startsWith('ACL4SSR_')) return undefined
  const path = set.sourceRef.startsWith('ACL4SSR_Ruleset_')
    ? `Clash/Ruleset/${set.sourceRef.slice('ACL4SSR_Ruleset_'.length)}`
    : `Clash/${set.sourceRef.slice('ACL4SSR_'.length)}`
  return `https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/${ACL4SSR_COMMIT}/${path}`
}

export interface PrepareSchemeOptions {
  preferRuleSets?: boolean
  format?: SubFormat
  /** 目标客户端；用于判断 MRS、Shadowrocket 等专属限制。 */
  target?: ClientTarget
}

export interface RemoteRuleSetReference {
  url: string
  format: RuleSetFormat
  /** MRS 必须声明 domain / ipcidr。 */
  behavior?: 'domain' | 'ipcidr'
  /** 写在 RULE-SET 行上的参数，例如 ipcidr 的 no-resolve。 */
  options?: string[]
}

export interface RemoteRuleSetCandidate {
  set: SchemeRuleSet
  url?: string
  format?: RuleSetFormat
  /** 一个规则集拆成多个二进制引用（MRS domain + ipcidr）。 */
  references?: RemoteRuleSetReference[]
  /** 远程引用无法覆盖、需要逐条内联的规则。 */
  residual?: RoutingRule[]
  /** 格式兼容且匹配顺序安全，可以直接写成远程引用。 */
  remote: boolean
}

function hostedReference(
  set: SchemeRuleSet,
  dialect: 'mrs-domain' | 'mrs-ipcidr' | 'srs',
): RemoteRuleSetReference | undefined {
  const url = hostedRuleSetURL(set, dialect)
  if (!url) return undefined
  return {
    url,
    format: ruleSetFormatForDialect(dialect),
    behavior: dialect === 'srs' ? undefined : dialect === 'mrs-domain' ? 'domain' : 'ipcidr',
  }
}

/** 规则集快照能否在各载体直接引用；排序敏感的 Loon / QuanX 另行判断。 */
export function remoteRuleSetCandidates(
  scheme: RuleScheme,
  options: PrepareSchemeOptions,
): RemoteRuleSetCandidate[] {
  const sets = scheme.ruleSets ?? []
  const hostedDialect = hostedDialectForFormat(options.format)
  const candidates = sets.map((set) => {
    if (!options.preferRuleSets || !options.format) return { set, url: undefined, format: undefined }
    const originalURL = remoteRuleSetURL(set)
    const originalFormat = ruleSetFormatOfSet(set, originalURL)

    // 经典列表优先压成二进制：mihomo / Stash 用 MRS，sing-box / Hiddify 用 SRS。
    // 表达不了的类型留在 residual 里逐条内联，顺序与原规则集一致。
    if (originalFormat === 'classical' && set.rules.length > 0) {
      if (options.format === 'yaml'
        && options.target
        && targetSupportsRuleSetFormat(options.target, 'mrs')) {
        const plan = mihomoBinaryPlan(set.rules)
        if (plan) {
          const references: RemoteRuleSetReference[] = []
          if (plan.domain.length) {
            const reference = hostedReference(set, 'mrs-domain')
            if (reference) references.push(reference)
          }
          if (plan.ipcidr.length) {
            const reference = hostedReference(set, 'mrs-ipcidr')
            if (reference) {
              references.push({
                ...reference,
                options: plan.ipNoResolve ? ['no-resolve'] : [],
              })
            }
          }
          if (references.length) {
            return {
              set,
              references,
              residual: plan.residual,
              url: undefined,
              format: undefined,
            }
          }
        }
      }
      if (options.format === 'json'
        && (!options.target || targetSupportsRuleSetFormat(options.target, 'singbox-binary'))) {
        const plan = singBoxBinaryPlan(set.rules)
        if (plan) {
          const reference = hostedReference(set, 'srs')
          if (reference) {
            return {
              set,
              references: [reference],
              residual: plan.residual,
              url: undefined,
              format: undefined,
            }
          }
        }
      }
    }

    const originalSupported = !!originalURL && !!originalFormat
      && (originalFormat !== 'mrs' || ['domain', 'ipcidr'].includes(set.ruleSetBehavior ?? ''))
      && (originalFormat !== 'classical' || classicalRulesFitTarget(set.rules, options.target, options.format))
      && (options.target
        ? targetSupportsRuleSetFormat(options.target, originalFormat)
        : subFormatSupportsRuleSetFormat(options.format, originalFormat))
    if (originalSupported) {
      return { set, url: originalURL, format: originalFormat }
    }
    // 经典 Clash 文本可以交给塔台服务转换成 QuanX / Egern / sing-box source。
    if (hostedDialect
      && (originalFormat === 'classical' || originalFormat === 'yaml')
      && ruleSetRulesFitDialect(set.rules, hostedDialect)) {
      const hosted = hostedRuleSetURL(set, hostedDialect)
      if (hosted) {
        return { set, url: hosted, format: ruleSetFormatForDialect(hostedDialect) }
      }
    }
    return { set, url: undefined, format: undefined }
  })
  // Loon / QuanX 的远程列表排在所有本地规则之后；若方案里还有本地规则，
  // 直接引用会改变匹配顺序，这时宁可继续展开。
  const orderSensitive = options.format === 'loon' || options.format === 'quanx'
  const canKeepOrder = !orderSensitive
    || (scheme.rules.every((rule) => rule.type === 'FINAL')
      && candidates.every((item) => item.url || item.references?.length))
  return candidates.map((item) => ({
    ...item,
    remote: (!!item.url || !!item.references?.length) && canKeepOrder,
  }))
}

/**
 * 把界面上的选择转成生成器能直接使用的方案：
 * - select 组带上界面选中的首选成员（组引用、DIRECT/REJECT 或节点名）；
 * - 自定义规则和规则集排到方案规则最前；
 * - 开启优先引用时，可远程读取的规则集折叠成一条 RULE-SET；
 * - 本地规则集/不支持远程的客户端继续内联，保证配置可用。
 */
export function prepareSchemeForExport(
  scheme: RuleScheme,
  policySelections: Record<string, string>,
  options: PrepareSchemeOptions = {},
): RuleScheme {
  const groups = scheme.groups.map((group) => {
    if (group.type !== 'select') return group
    const selected = policySelections[group.name]
    return selected ? { ...group, selected } : group
  })
  const customRules = scheme.customRules ?? []
  const remoteCandidates = remoteRuleSetCandidates(scheme, options)
  const ruleSetRules = remoteCandidates.flatMap(({ set, url, format, remote, references, residual }) => {
    if (remote && references?.length) {
      const remoteRules: RoutingRule[] = references.map((reference) => ({
        type: 'RULE-SET',
        value: reference.url,
        group: set.group,
        sourceName: set.name,
        ruleSetFormat: reference.format,
        ruleSetBehavior: reference.behavior,
        options: reference.options,
      }))
      const residualRules: RoutingRule[] = (residual ?? []).map((rule) => ({
        ...rule,
        group: set.group,
      }))
      return [...remoteRules, ...residualRules]
    }
    if (remote && url) {
      return [{
        type: 'RULE-SET',
        value: url,
        group: set.group,
        sourceName: set.name,
        ruleSetFormat: format,
        ruleSetBehavior: set.ruleSetBehavior,
      }]
    }
    const inline = options.format
      ? inlineRuleSetMetadata(set, options.format, options.target)
      : undefined
    if (inline) {
      return set.rules.map((rule) => ({ ...rule, inlineSet: inline }))
    }
    return set.rules
  })
  return {
    ...scheme,
    groups,
    // 自定义规则始终排在最前；拖动策略组只调整其余规则的匹配顺序。
    rules: [
      ...customRules,
      ...reorderRulesByMatchingOrder(
        [...ruleSetRules, ...scheme.rules],
        scheme.matchingOrder,
      ),
    ],
  }
}
