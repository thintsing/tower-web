// Shared group→node resolution for all generators.
// A scheme group's nodeFilter regex is matched against node display names;
// declared options ([]引用 / DIRECT / REJECT) always come first.
import type { ClientTarget, ExportContentMode, PolicyGroup, ProxyNode, RemoteSubscriptionEntry, RoutingRule, RuleScheme, RuleSetExclusionTable, RuleSetFormat, SchemeRuleSet, SubFormat, TailnetExport } from '../models/types'
import { filterExcludedRuleSets } from '../rules/ruleSetExclusions'
import {
  classicalRulesFitTarget,
  hostedDialectForFormat,
  hostedRuleSetURL,
  providerOnlyCanReference,
  ruleSetFormatForDialect,
  ruleSetFormatOfSet,
  ruleSetRulesFitDialect,
  subFormatSupportsRuleSetFormat,
  targetSupportsRuleSetFormat,
} from '../rules/remoteFormats'
import { mihomoBinaryPlan, singBoxBinaryPlan, SRS_DOMAIN_TYPES } from '../rules/binaryRuleSets'
import { inlineRuleSetMetadata } from '../rules/inlineSets'
import { reorderRulesByMatchingOrder } from '../rules/matchingOrder'
import { applyRuleOrder, insertRuleSetBlocks, sortSupplementRules, type RuleSetBlock } from '../rules/ruleOrder'
import { conditionalDefaultPolicy, effectiveGroupType } from '../rules/capabilities'

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
  /** Surge 自更新首行 `#!MANAGED-CONFIG` 的目标地址；留空则不写。 */
  managedConfigURL?: string
  /**
   * 服务端托管规则集的对外基础地址（例如 TOWER_PUBLIC_URL）。
   * 空字符串表示明确没有可达地址：provider 引用不能退回 localhost。
   */
  hostedBaseURL?: string
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
  const out = new Map<string, string>()
  const used = new Set<string>()
  for (const node of nodes) {
    const base = escape(nameFor?.(node) ?? node.name)
    // 不能只按 base 计数：已有节点本来就叫 "A 2" 时，第三个 "A" 会被
    // 补成 "A 2" 并与之重名，客户端会因此拒绝整份配置。
    let name = base
    let suffix = 2
    while (used.has(name)) {
      name = `${base} ${suffix}`
      suffix += 1
    }
    used.add(name)
    out.set(node.id, name)
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
  target?: ClientTarget,
): string {
  if (rule.type === 'FINAL') return `MATCH,${group}`
  if (rule.raw) return `${rule.raw},${group}`
  const type = rule.type.toUpperCase()
  const options = [...(rule.options ?? [])]
  const sourceNoResolve = options.some((option) => option.toLowerCase() === 'no-resolve')
  // Tower iOS 会给 GEOIP 补 no-resolve，避免上方的 IP/GEOIP 规则为了判断匹配
  // 而提前解析域名；Surge 系的 IP/ASN 规则也需要同样的保护。源规则自己写了
  // no-resolve 时原样保留，不重复追加。
  const surgeIPRule = (target === 'surge' || target === 'surge-mac')
    && ['IP-CIDR', 'IP-CIDR6', 'IP6-CIDR', 'IP-ASN'].includes(type)
  if ((rule.noResolve || type === 'GEOIP' || surgeIPRule) && !sourceNoResolve) {
    options.push('no-resolve')
  }
  return [rule.type, rule.value ?? '', group, ...options].join(',')
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
  /** 只读规则集的本地屏蔽表；编译、检查与导出都必须带上。 */
  ruleSetExclusions?: RuleSetExclusionTable
  /** 托管规则集的对外基础地址；空字符串表示不可用。 */
  hostedBaseURL?: string
}

export interface RemoteRuleSetReference {
  url: string
  format: RuleSetFormat
  /** MRS 必须声明 domain / ipcidr。 */
  behavior?: 'domain' | 'ipcidr'
  /** 写在 RULE-SET 行上的参数，例如 ipcidr 的 no-resolve。 */
  options?: string[]
  /** sing-box DNS 投影专用的 domain-only SRS，不写进路由规则。 */
  dnsDomainURL?: string
}

export interface RemoteRuleSetCandidate {
  set: SchemeRuleSet
  url?: string
  format?: RuleSetFormat
  /** 一个规则集拆成多个二进制引用（MRS domain + ipcidr）。 */
  references?: RemoteRuleSetReference[]
  /**
   * 写在 RULE-SET 行上的参数（例如 no-resolve）。
   * provider-only 的托管路径只在该方言的引用行确实支持时才给出；
   * QuanX / Egern / sing-box 的远程列表没有对应字段，宁可不写也不假装无损。
   */
  ruleLineOptions?: string[]
  /** 远程引用无法覆盖、需要逐条内联的规则。 */
  residual?: RoutingRule[]
  /** 格式兼容且匹配顺序安全，可以直接写成远程引用。 */
  remote: boolean
}

function hostedReference(
  set: SchemeRuleSet,
  dialect: 'mrs-domain' | 'mrs-ipcidr' | 'srs' | 'srs-domain',
  hostedBaseURL?: string,
): RemoteRuleSetReference | undefined {
  const url = hostedRuleSetURL(set, dialect, hostedBaseURL)
  if (!url) return undefined
  return {
    url,
    format: ruleSetFormatForDialect(dialect),
    behavior: dialect === 'srs' || dialect === 'srs-domain'
      ? undefined
      : dialect === 'mrs-domain' ? 'domain' : 'ipcidr',
  }
}

/** 规则集快照能否在各载体直接引用；排序敏感的 Loon / QuanX 另行判断。 */
export function remoteRuleSetCandidates(
  scheme: RuleScheme,
  options: PrepareSchemeOptions,
): RemoteRuleSetCandidate[] {
  // 内联规则集（固化快照）的规则已经在 scheme.rules 里，不能再作为独立块插入，
  // 否则同一批规则会出现两份、并打乱匹配顺序。
  const sets = (scheme.ruleSets ?? []).filter((set) => !set.inlined)
  const hostedDialect = hostedDialectForFormat(options.format)
  // classic 方言是给 provider-only 新增的；普通 YAML 规则集在 Surge / Loon
  // 仍按旧行为展开，不能因为这次新增而悄悄改成远程引用（会改变匹配顺序）。
  const legacyHostedDialect = hostedDialect === 'classic' ? undefined : hostedDialect
  const candidates = sets.map((set): Omit<RemoteRuleSetCandidate, 'remote'> => {
    // provider-only 规则集没有正文可展开，必须原样写成远程引用；
    // 也不能参与「逐条屏蔽」，否则会退化成一条空配置。
    const providerOnly = !!set.providerOnly
    // 有屏蔽条目时必须内联：远程 RULE-SET 引用会把被屏蔽的规则一起带回来。
    if (!providerOnly && options.ruleSetExclusions?.[set.id]?.length) return { set, url: undefined, format: undefined }
    // provider-only 不受「优先引用远程规则集」开关影响：它只有引用这一种形态。
    // 但导出格式仍必须已知（lint 的预检查不传 format，只做空规则集检查）。
    if (!options.format) return { set, url: undefined, format: undefined }
    if (!providerOnly && !options.preferRuleSets) return { set, url: undefined, format: undefined }
    const originalURL = remoteRuleSetURL(set)
    const originalFormat = ruleSetFormatOfSet(set, originalURL)

    // provider-only：Clash 系直接引用原 YAML provider；其他载体交给塔台服务托管转换。
    // 没有正文可以展开，因此这里绝不能退回「内联为空」。
    if (providerOnly) {
      const kind = providerOnlyCanReference(set, options.format, options.target, options.hostedBaseURL)
      if (kind === 'native') {
        return { set, url: originalURL, format: 'yaml', ruleLineOptions: set.ruleSetOptions }
      }
      const dialect = hostedDialectForFormat(options.format)
      if (kind === 'hosted' && dialect) {
        const hosted = hostedRuleSetURL(set, dialect, options.hostedBaseURL)
        if (hosted) {
          // Surge 手册明确 RULE-SET 行接受 no-resolve 参数；Loon 的
          // [Remote Rule] 行只认 policy/tag 等键值参数，QuanX / Egern /
          // sing-box 的列表同样没有逐条参数位，因此这些载体不写。
          const surgy = options.target === 'surge' || options.target === 'surge-mac'
          return {
            set,
            url: hosted,
            format: ruleSetFormatForDialect(dialect),
            ruleLineOptions: dialect === 'classic' && surgy ? set.ruleSetOptions : undefined,
          }
        }
      }
      return { set, url: undefined, format: undefined }
    }

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
            const reference = hostedReference(set, 'mrs-domain', options.hostedBaseURL)
            if (reference) references.push(reference)
          }
          if (plan.ipcidr.length) {
            const reference = hostedReference(set, 'mrs-ipcidr', options.hostedBaseURL)
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
            // 官方 sing-box 的 DNS 规则不能引用包含 IP 条件的 SRS；同一份列表
            // 另托管一个 domain-only SRS，只给 DNS 投影使用（Hiddify 1.13 不投影）。
            const dnsDomainURL = options.target === 'sing-box'
              && plan.covered.some((rule) => SRS_DOMAIN_TYPES.has(rule.type.toUpperCase()))
              ? hostedReference(set, 'srs-domain')?.url
              : undefined
            return {
              set,
              references: [{ ...reference, ...(dnsDomainURL ? { dnsDomainURL } : {}) }],
              residual: plan.residual,
              url: undefined,
              format: undefined,
            }
          }
        }
      }
    }

    const originalSupported = !!originalURL && !!originalFormat
      && (!providerOnly || !!set.ruleSetBehavior)
      && (originalFormat !== 'mrs' || ['domain', 'ipcidr'].includes(set.ruleSetBehavior ?? ''))
      && (originalFormat !== 'classical' || classicalRulesFitTarget(set.rules, options.target, options.format))
      && (options.target
        ? targetSupportsRuleSetFormat(options.target, originalFormat)
        : subFormatSupportsRuleSetFormat(options.format, originalFormat))
    if (originalSupported) {
      return { set, url: originalURL, format: originalFormat }
    }
    // 经典 Clash 文本可以交给塔台服务转换成 QuanX / Egern / sing-box source。
    if (legacyHostedDialect
      && (originalFormat === 'classical' || originalFormat === 'yaml')
      && ruleSetRulesFitDialect(set.rules, legacyHostedDialect)) {
      const hosted = hostedRuleSetURL(set, legacyHostedDialect, options.hostedBaseURL)
      if (hosted) {
        return { set, url: hosted, format: ruleSetFormatForDialect(legacyHostedDialect) }
      }
    }
    return { set, url: undefined, format: undefined }
  })
  // Loon / QuanX 的远程列表排在所有本地规则之后；若方案里还有本地规则，
  // 直接引用会改变匹配顺序，这时宁可继续展开。
  const orderSensitive = options.format === 'loon' || options.format === 'quanx'
  const canKeepOrder = !orderSensitive
    || (scheme.rules.every((rule) => rule.type === 'FINAL')
      // provider-only 未解析时不会贡献本地规则，只是少一组列表，不影响其余引用的顺序。
      && candidates.every((item) => item.url || item.references?.length || item.set.providerOnly))
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
  sourceScheme: RuleScheme,
  policySelections: Record<string, string>,
  options: PrepareSchemeOptions = {},
): RuleScheme {
  // 屏蔽在进入任何生成器之前生效，保证预览、检查与导出看到的是同一份规则。
  const scheme = filterExcludedRuleSets(sourceScheme, options.ruleSetExclusions)
  const groups = scheme.groups.map((group) => {
    let updated = group
    if (group.type === 'conditional'
      && (!options.target || effectiveGroupType(group.type, options.target, group.parameters) !== 'conditional')) {
      // 条件组在目标客户端没有对应类型时，退回默认策略而不是 DIRECT。
      const fallback = conditionalDefaultPolicy(group.parameters)
      if (fallback) updated = { ...updated, options: [fallback] }
    }
    if (updated.type !== 'select') return updated
    const selected = policySelections[updated.name]
    return selected ? { ...updated, selected } : updated
  })
  const customRules = scheme.customRules ?? []
  const remoteCandidates = remoteRuleSetCandidates(scheme, options)
  const ruleSetBlocks: RuleSetBlock[] = remoteCandidates.map(({ set, url, format, remote, references, residual, ruleLineOptions }) => {
    let rules: RoutingRule[]
    if (remote && references?.length) {
      const remoteRules: RoutingRule[] = references.map((reference) => ({
        type: 'RULE-SET',
        value: reference.url,
        group: set.group,
        sourceName: set.name,
        ruleSetFormat: reference.format,
        ruleSetBehavior: reference.behavior,
        options: reference.options,
        ruleSetDNSURL: reference.dnsDomainURL,
      }))
      const residualRules: RoutingRule[] = (residual ?? []).map((rule) => ({
        ...rule,
        group: set.group,
        sourceName: set.name,
        sourceSetId: set.id,
      }))
      rules = [...remoteRules, ...residualRules]
    } else if (remote && url) {
      rules = [{
        type: 'RULE-SET',
        value: url,
        group: set.group,
        sourceName: set.name,
        ruleSetFormat: format,
        ruleSetBehavior: set.ruleSetBehavior,
        // provider-only：键名 / 路径 / 更新间隔随引用一起写出。
        ruleSetProviderKey: set.providerOnly ? set.providerName : undefined,
        ruleSetInterval: set.providerOnly ? set.interval : undefined,
        options: ruleLineOptions,
      }]
    } else {
      const inline = options.format
        ? inlineRuleSetMetadata(set, options.format, options.target)
        : undefined
      rules = inline
        ? set.rules.map((rule) => ({ ...rule, inlineSet: inline, sourceSetId: set.id }))
        : set.rules.map((rule) => ({ ...rule, group: set.group, sourceName: set.name, sourceSetId: set.id }))
    }
    return {
      group: set.group,
      matchRules: set.rules,
      sourceURL: remoteRuleSetURL(set),
      rules,
    }
  })
  // 规则集插到第一条冲突规则之前；自定义规则仍全部前置，并最具体优先。
  const mergedRules = insertRuleSetBlocks(scheme.rules, ruleSetBlocks)
  return {
    ...scheme,
    groups,
    rules: applyRuleOrder(
      [
        ...sortSupplementRules(customRules),
        ...reorderRulesByMatchingOrder(mergedRules, scheme.matchingOrder),
      ],
      scheme.ruleOrder,
    ),
  }
}
