// Import rule schemes from the formats Tower accepts: subconverter INI,
// Clash/mihomo YAML, Surge config, Egern YAML and sing-box JSON.
import { parse as parseYAML } from 'yaml'
import type {
  PolicyGroup,
  PolicyGroupType,
  RuleScheme,
  RuleSchemeDNSProtectionMode,
  RuleSchemeFormat,
  RuleSchemeNetworkSettings,
  RuleSetFormat,
  RoutingRule,
} from '../models/types'
import {
  DEFAULT_NETWORK_SETTINGS,
  isEncryptedDNSServer,
  isPlainDNSServer,
  isHTTPTestURL,
} from '../models/networkSettings'
import { inlineRuleFromFields, parseSchemeINI, splitRuleFields } from './scheme'
import { inferRuleSetFormat } from './remoteFormats'

type Dict = Record<string, unknown>

const MAX_IMPORT_BYTES = 8 * 1024 * 1024

/** 客户端内置策略，不需要在方案里再声明同名策略组。 */
const BUILTIN_POLICIES = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE'])

function dict(value: unknown): Dict | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Dict
    : undefined
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

/** 规则值允许数字（端口、ASN 等）和布尔，统一转成字符串。 */
function scalar(value: unknown): string {
  if (typeof value === 'string') return value.trim()
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return ''
}

function stringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(scalar).filter(Boolean)
  const single = scalar(value)
  return single ? [single] : []
}

function number(value: unknown): number | undefined {
  const parsed = typeof value === 'number' ? value : Number.parseFloat(scalar(value))
  return Number.isFinite(parsed) ? parsed : undefined
}

/** `300` / `"30s"` / `"5m"` / `"1h"` / `"100ms"` → 秒或毫秒。 */
function duration(value: unknown, unit: 'seconds' | 'milliseconds'): number | undefined {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? Math.round(value) : undefined
  }
  const raw = text(value).toLowerCase()
  if (!raw) return undefined
  const match = raw.match(
    /^(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)(ms|s))?$/,
  )
  let seconds = 0
  if (match) {
    if (match[1]) seconds += Number.parseFloat(match[1]) * 3600
    if (match[2]) seconds += Number.parseFloat(match[2]) * 60
    if (match[3]) seconds += Number.parseFloat(match[3]) * (match[4] === 'ms' ? 0.001 : 1)
    return Math.round(unit === 'milliseconds' ? seconds * 1000 : seconds)
  }
  const parsed = Number.parseFloat(raw)
  if (!Number.isFinite(parsed)) return undefined
  return Math.round(parsed)
}

function flag(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value
  if (typeof value === 'number') return value !== 0
  const raw = text(value).toLowerCase()
  if (raw === 'true') return true
  if (raw === 'false') return false
  return undefined
}

function truthy(value: unknown): boolean {
  if (typeof value === 'boolean') return value
  if (typeof value === 'number') return value !== 0
  const raw = text(value).toLowerCase()
  return raw === 'true' || raw === '1' || raw === 'yes'
}

function groupType(value: unknown): PolicyGroupType {
  const type = text(value).toLowerCase()
  switch (type) {
    case 'select':
    case 'static':
    case 'selector':
      return 'select'
    case 'url-test':
    case 'urltest':
    case 'auto_test':
    case 'url-latency-benchmark':
      return 'url-test'
    case 'fallback':
    case 'available':
      return 'fallback'
    case 'load-balance':
    case 'load_balance':
    case 'loadbalance':
    case 'round-robin':
    case 'dest-hash':
      return 'load-balance'
    case 'smart':
      return 'smart'
    case 'conditional':
    case 'subnet':
    case 'ssid':
      return 'conditional'
    case 'relay':
    case 'chain':
      return 'relay'
    default:
      return 'unsupported'
  }
}

function builtinPolicy(value: string): string | undefined {
  const upper = value.trim().toUpperCase()
  return BUILTIN_POLICIES.has(upper) ? upper : undefined
}

function unquote(value: string): string {
  const trimmed = value.trim()
  if (
    trimmed.length >= 2
    && (trimmed[0] === '"' || trimmed[0] === "'")
    && trimmed[trimmed.length - 1] === trimmed[0]
  ) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

/** 去掉行尾注释；只在空白后识别 # / ; / //，保留 URL 和正则里的符号。 */
function stripInlineComment(line: string): string {
  let quote: string | undefined
  let escaped = false
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index]
    if (escaped) {
      escaped = false
      continue
    }
    if (char === '\\') {
      escaped = true
      continue
    }
    if (quote) {
      if (char === quote) quote = undefined
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      continue
    }
    if (index === 0 || /\s/.test(line[index - 1])) {
      if (char === '#' || char === ';' || (char === '/' && line[index + 1] === '/')) {
        return line.slice(0, index).trim()
      }
    }
  }
  return line.trim()
}

function uniqueStrings(values: unknown[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const value of values) {
    const item = scalar(value)
    if (!item || seen.has(item)) continue
    seen.add(item)
    out.push(item)
  }
  return out
}

function regexEscape(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** 规则引用了没有声明的策略组时补一个 select 组；内置策略不补。 */
function ensureGroups(groups: PolicyGroup[], rules: RoutingRule[]): PolicyGroup[] {
  const names = new Set(groups.map((group) => group.name))
  const missing = uniqueStrings(rules.map((rule) => rule.group))
    .filter((name) => !names.has(name) && !builtinPolicy(name))
  if (!missing.length) return groups
  return [...groups, ...missing.map((name) => ({
    name,
    type: 'select' as const,
    options: ['DIRECT'],
  }))]
}

/**
 * 配置里的策略组成员通常是节点名，而 Tower 的节点来自订阅。
 * 内置策略与已声明的组保留为引用，其余转成精确匹配的节点名正则；
 * 这样导出时不会写出当前节点池里不存在的成员。
 */
function normalizeGroupMembers(
  groups: PolicyGroup[],
  aliases?: Map<string, string>,
): PolicyGroup[] {
  const names = new Set(groups.map((group) => group.name))
  return groups.map((group) => {
    const options: string[] = []
    const patterns: string[] = []
    for (const raw of group.options) {
      const member = unquote(raw)
      if (!member) continue
      const resolved = aliases?.get(member) ?? member
      const builtin = builtinPolicy(resolved)
      if (builtin) {
        if (!options.includes(builtin)) options.push(builtin)
      } else if (names.has(resolved)) {
        if (!options.includes(resolved)) options.push(resolved)
      } else {
        const pattern = regexEscape(member)
        if (!patterns.includes(pattern)) patterns.push(pattern)
      }
    }
    let nodeFilter = group.nodeFilter?.trim() || undefined
    if (patterns.length && nodeFilter !== '.*') {
      const explicit = patterns.length === 1
        ? `^${patterns[0]}$`
        : `^(?:${patterns.join('|')})$`
      nodeFilter = nodeFilter ? `${nodeFilter}|${explicit}` : explicit
    }
    return { ...group, options, nodeFilter }
  })
}

function networkSettingsFrom(
  plain: string[],
  domestic: string[],
  remote: string[],
  mode: RuleSchemeDNSProtectionMode,
  ipv6Enabled?: boolean,
  proxyTestURLString?: string,
): RuleSchemeNetworkSettings | undefined {
  const defaults = DEFAULT_NETWORK_SETTINGS
  const safePlain = uniqueStrings(plain).filter(isPlainDNSServer)
  const safeDomestic = uniqueStrings(domestic).filter(isEncryptedDNSServer)
  const safeRemote = uniqueStrings(remote).filter(isEncryptedDNSServer)
  if (!safePlain.length && !safeDomestic.length && !safeRemote.length) return undefined
  return {
    ipv6Enabled,
    dnsServers: safePlain.length ? safePlain : [...defaults.dnsServers],
    encryptedDNSServers: safeDomestic.length ? safeDomestic : [...defaults.encryptedDNSServers],
    remoteDNSServers: safeRemote.length ? safeRemote : [...defaults.remoteDNSServers],
    proxyTestURLString: proxyTestURLString && isHTTPTestURL(proxyTestURLString)
      ? proxyTestURLString
      : undefined,
    dnsProtectionMode: mode,
  }
}

/**
 * Surge 规则是 `类型,值,策略[,参数…]`，Clash 同样把策略放在第三列。
 * 不能简单取最后一列，否则 `IP-CIDR,…,DIRECT,no-resolve` 会把参数当成组名。
 */
function policyRule(line: string, aliases?: Map<string, string>): RoutingRule | undefined {
  const cleaned = stripInlineComment(line)
  if (!cleaned) return undefined
  const fields = splitRuleFields(cleaned)
  const type = fields[0]?.toUpperCase()
  if (!type) return undefined
  if (type === 'FINAL' || type === 'MATCH') {
    const group = unquote(fields[1] ?? '')
    if (!group) return undefined
    return { type: 'FINAL', group: aliases?.get(group) ?? group }
  }
  if (fields.length < 3) return undefined
  const group = unquote(fields[2])
  if (!group) return undefined
  const parsed = inlineRuleFromFields([fields[0], fields[1], ...fields.slice(3)])
  if (!parsed) return undefined
  return { ...parsed, group: aliases?.get(group) ?? group }
}

// ---------------- Clash / mihomo YAML ----------------

interface ClashProvider {
  url?: string
  behavior?: string
  format?: string
  payload: string[]
}

function clashRuleSetFormat(provider: ClashProvider | undefined): RuleSetFormat {
  const declared = text(provider?.format).toLowerCase()
  if (declared === 'mrs') return 'mrs'
  if (declared === 'yaml') return 'yaml'
  return provider?.url ? inferRuleSetFormat(provider.url) : 'classical'
}

function clashProviders(doc: Dict): Map<string, ClashProvider> {
  const providers = new Map<string, ClashProvider>()
  const raw = dict(doc['rule-providers'])
  if (!raw) return providers
  for (const [name, value] of Object.entries(raw)) {
    const item = dict(value)
    if (!item) continue
    providers.set(name, {
      url: text(item.url) || undefined,
      behavior: text(item.behavior) || undefined,
      format: text(item.format) || undefined,
      payload: array(item.payload).map(scalar).filter(Boolean),
    })
  }
  return providers
}

/** `proxies:` 里的 direct / reject 节点实际上指内置策略，规则和组引用需要改名。 */
function clashBuiltinAliases(doc: Dict): Map<string, string> {
  const aliases = new Map<string, string>()
  for (const raw of array(doc.proxies)) {
    const item = dict(raw)
    if (!item) continue
    const name = text(item.name)
    if (!name) continue
    const type = text(item.type).toLowerCase()
    const builtin = type === 'direct'
      ? 'DIRECT'
      : type === 'reject'
        ? 'REJECT'
        : type === 'reject-drop'
          ? 'REJECT-DROP'
          : undefined
    if (builtin) aliases.set(name, builtin)
  }
  return aliases
}

function clashGroup(raw: unknown): PolicyGroup | undefined {
  const item = dict(raw)
  if (!item) return undefined
  const name = text(item.name)
  if (!name) return undefined
  const group: PolicyGroup = {
    name,
    type: groupType(item.type),
    options: stringList(item.proxies).map(unquote),
  }
  const filter = text(item.filter)
  const includeAll = item.use !== undefined
    || item.urls !== undefined
    || truthy(item['include-all'])
    || truthy(item['include-all-proxies'])
  group.nodeFilter = filter || (includeAll ? '.*' : undefined)
  const url = stringList(item.url)[0]
  if (url) group.url = url
  group.interval = duration(item.interval ?? item['check-interval'], 'seconds')
  group.tolerance = duration(item.tolerance, 'milliseconds')
  group.algorithm = text(item.strategy) || text(item.algorithm) || undefined
  const rules = array(item.rules).map(scalar).filter(Boolean)
  if (rules.length) group.parameters = { rules: JSON.stringify(rules) }
  return group
}

/**
 * mihomo `nameserver` 的 `#proxy` 后缀和 `&h3=true` 参数决定它走直连还是代理。
 * 拆成普通 / 国内加密 / 远程加密三类，生成其他客户端时才不会丢语义。
 */
function clashDNSEntry(raw: string): { address: string; proxied: boolean } | undefined {
  const value = unquote(raw)
  if (!value) return undefined
  const hash = value.indexOf('#')
  let address = (hash >= 0 ? value.slice(0, hash) : value).trim()
  const options = hash >= 0
    ? value.slice(hash + 1).split('&').map((part) => part.trim()).filter(Boolean)
    : []
  if (options.some((option) => option.toLowerCase() === 'h3=true') && /^https:\/\//i.test(address)) {
    address = `h3://${address.slice('https://'.length)}`
  }
  const proxy = options.find((option) => !option.includes('='))
  return {
    address,
    proxied: !!proxy && proxy.toUpperCase() !== 'DIRECT',
  }
}

function clashNetwork(doc: Dict, groups: PolicyGroup[]): RuleSchemeNetworkSettings | undefined {
  const dns = dict(doc.dns)
  if (!dns) return undefined
  const plain: string[] = []
  const domestic: string[] = []
  const remote: string[] = []

  for (const raw of stringList(dns['default-nameserver'])) {
    const entry = clashDNSEntry(raw)
    if (entry && isPlainDNSServer(entry.address)) plain.push(entry.address)
  }
  for (const raw of stringList(dns['proxy-server-nameserver'])) {
    const entry = clashDNSEntry(raw)
    if (!entry) continue
    if (isEncryptedDNSServer(entry.address)) domestic.push(entry.address)
    else if (isPlainDNSServer(entry.address)) plain.push(entry.address)
  }
  for (const raw of stringList(dns.nameserver)) {
    const entry = clashDNSEntry(raw)
    if (!entry) continue
    if (entry.proxied) {
      // 经代理访问的普通 UDP DNS 无法映射成加密远程 DNS，宁可不保留。
      if (isEncryptedDNSServer(entry.address)) remote.push(entry.address)
    } else if (isEncryptedDNSServer(entry.address)) {
      domestic.push(entry.address)
    } else if (isPlainDNSServer(entry.address)) {
      plain.push(entry.address)
    }
  }
  for (const raw of stringList(dns.fallback)) {
    const entry = clashDNSEntry(raw)
    if (!entry) continue
    if (isEncryptedDNSServer(entry.address)) remote.push(entry.address)
  }

  // 与 Tower iOS 一致：导入的网络设置默认按标准保护处理。
  const mode: RuleSchemeDNSProtectionMode = 'standard'
  const testURL = groups.find((group) => group.url)?.url
  return networkSettingsFrom(plain, domestic, remote, mode, flag(doc.ipv6), testURL)
}

function inlineProviderRules(
  provider: ClashProvider,
  group: string,
  options: string[],
): RoutingRule[] {
  const behavior = (provider.behavior ?? '').toLowerCase()
  const rules: RoutingRule[] = []
  for (const raw of provider.payload) {
    const line = stripInlineComment(raw)
    if (!line) continue
    let parsed: Omit<RoutingRule, 'group'> | undefined
    if (behavior === 'domain' && !line.includes(',')) {
      parsed = { type: 'DOMAIN-SUFFIX', value: unquote(line), noResolve: false }
    } else if (behavior === 'ipcidr' && !line.includes(',')) {
      parsed = {
        type: line.includes(':') ? 'IP-CIDR6' : 'IP-CIDR',
        value: unquote(line),
        noResolve: true,
      }
    } else {
      parsed = inlineRuleFromFields(splitRuleFields(line))
    }
    if (!parsed) continue
    const ruleOptions = [...(parsed.options ?? []), ...options]
    rules.push({
      ...parsed,
      group,
      options: ruleOptions.length ? [...new Set(ruleOptions)] : undefined,
    })
  }
  return rules
}

function parseClash(id: string, name: string, description: string, textBody: string): RuleScheme {
  let doc: unknown
  try {
    doc = parseYAML(textBody)
  } catch (error) {
    throw new Error(`Clash YAML 解析失败：${error instanceof Error ? error.message : '格式错误'}`)
  }
  const root = dict(doc)
  if (!root) throw new Error('Clash YAML 顶层不是对象')
  const aliases = clashBuiltinAliases(root)
  const groups = array(root['proxy-groups'])
    .map(clashGroup)
    .filter((group): group is PolicyGroup => !!group)
  const providers = clashProviders(root)
  const rules: RoutingRule[] = []
  const subRuleDefinitions = new Map<string, string[]>()
  const rawSubRules = dict(root['sub-rules'])
  if (rawSubRules) {
    for (const [subName, value] of Object.entries(rawSubRules)) {
      subRuleDefinitions.set(subName, array(value).map(scalar).filter(Boolean))
    }
  }

  const appendSubRule = (condition: string, subName: string, depth: number): void => {
    if (depth >= 8) throw new Error('SUB-RULE 嵌套超过 8 层')
    const entries = subRuleDefinitions.get(subName)
    if (!entries) throw new Error(`SUB-RULE「${subName}」没有对应的 sub-rules 定义`)
    const conditionFields = splitRuleFields(condition)
    if (conditionFields.length < 2) throw new Error(`SUB-RULE 条件无法解析：${condition}`)
    for (const entry of entries) {
      const fields = splitRuleFields(stripInlineComment(entry))
      const type = fields[0]?.toUpperCase()
      if (!type) continue
      if (type === 'MATCH' || type === 'FINAL') {
        const policy = unquote(fields[1] ?? '')
        if (!policy) throw new Error(`SUB-RULE「${subName}」的 ${type} 缺少策略`)
        const flattened = [...conditionFields.slice(0, 2), policy, ...conditionFields.slice(2)]
        const rule = policyRule(flattened.join(','), aliases)
        if (!rule) throw new Error(`SUB-RULE「${subName}」的 ${type} 无法展开`)
        rules.push(rule)
        continue
      }
      if (type === 'SUB-RULE') {
        if (fields.length < 3) throw new Error(`SUB-RULE「${subName}」里的嵌套 SUB-RULE 不完整`)
        const inner = unquote(fields[1] ?? '')
        if (!inner.startsWith('(') || !inner.endsWith(')')) {
          throw new Error(`SUB-RULE「${subName}」里的嵌套条件必须用括号包裹`)
        }
        appendSubRule('AND,((' + condition + '),' + inner + ')', unquote(fields[2]), depth + 1)
        continue
      }
      if (type === 'RULE-SET') {
        throw new Error(`SUB-RULE「${subName}」里不支持 RULE-SET，请改用普通规则`)
      }
      const parsed = policyRule(entry, aliases)
      if (!parsed) throw new Error(`SUB-RULE「${subName}」里的规则无法解析：${entry}`)
      // Clash 把策略放在第 3 列，之后的 no-resolve 等参数仍属于条件体。
      const body = [fields[0], fields[1], ...fields.slice(3)].filter(Boolean).join(',')
      rules.push({
        type: 'AND',
        raw: 'AND,((' + condition + '),(' + body + '))',
        group: parsed.group,
        noResolve: false,
      })
    }
  }

  for (const raw of array(root.rules)) {
    const line = scalar(raw)
    if (!line) continue
    const fields = splitRuleFields(stripInlineComment(line))
    const type = fields[0]?.toUpperCase()
    if (!type) continue
    if (type === 'SUB-RULE') {
      if (fields.length < 3 || !fields[1].startsWith('(') || !fields[1].endsWith(')')) {
        throw new Error(`Clash YAML 中的 SUB-RULE 不完整：${line}`)
      }
      appendSubRule(fields[1].slice(1, -1), unquote(fields[2]), 0)
      continue
    }
    if (type === 'RULE-SET') {
      const providerName = unquote(fields[1] ?? '')
      const groupName = unquote(fields[2] ?? '')
      if (!providerName || !groupName) continue
      const group = aliases.get(groupName) ?? groupName
      const options = fields.slice(3).map(unquote).filter(Boolean)
      const provider = providers.get(providerName)
      if (provider?.url) {
        rules.push({
          type: 'RULE-SET',
          value: provider.url,
          group,
          sourceName: providerName,
          ruleSetFormat: clashRuleSetFormat(provider),
          ruleSetBehavior: provider.behavior,
          options: options.length ? options : undefined,
        })
      } else if (provider?.payload.length) {
        rules.push(...inlineProviderRules(provider, group, options))
      } else if (/^https?:\/\//i.test(providerName)) {
        // 少数配置直接写 URL；Clash 生成器会为它补 rule-provider。
        rules.push({
          type: 'RULE-SET',
          value: providerName,
          group,
          ruleSetFormat: inferRuleSetFormat(providerName),
          options: options.length ? options : undefined,
        })
      }
      continue
    }
    const rule = policyRule(line, aliases)
    if (rule) rules.push(rule)
  }
  if (!groups.length && !rules.length) throw new Error('Clash YAML 中没有 proxy-groups 或 rules')
  const ensured = ensureGroups(groups, rules)
  return {
    id,
    name,
    description,
    groups: normalizeGroupMembers(ensured, aliases),
    rules,
    sourceKind: 'paste',
    sourceFormat: 'clash',
    networkSettings: clashNetwork(root, ensured),
  }
}

// ---------------- Surge ----------------

function surgeSections(textBody: string): Map<string, string[]> {
  const sections = new Map<string, string[]>()
  let current = ''
  for (const raw of textBody.split(/\r?\n/)) {
    const line = stripInlineComment(raw)
    if (!line) continue
    const header = line.match(/^\[(.+)]$/)
    if (header) {
      current = header[1].trim().toLowerCase()
      sections.set(current, [])
      continue
    }
    if (!current) continue
    sections.get(current)?.push(line)
  }
  return sections
}

function surgeGroup(line: string): PolicyGroup | undefined {
  const at = line.indexOf('=')
  if (at < 0) return undefined
  const name = unquote(line.slice(0, at))
  const fields = splitRuleFields(line.slice(at + 1))
  if (!name || !fields[0]) return undefined
  const type = groupType(fields[0])
  const options: string[] = []
  const group: PolicyGroup = { name, type, options }
  let includeAll = false
  let regexFilter: string | undefined
  let parameters: Record<string, string> | undefined
  const conditionalFields: string[] = []
  for (const field of fields.slice(1)) {
    const eq = field.indexOf('=')
    if (eq < 0) {
      if (field) options.push(unquote(field))
      continue
    }
    const key = field.slice(0, eq).trim().toLowerCase()
    const value = unquote(field.slice(eq + 1).trim())
    switch (key) {
      case 'url':
        group.url = value
        break
      case 'interval':
        group.interval = duration(value, 'seconds')
        break
      case 'tolerance':
        group.tolerance = duration(value, 'milliseconds')
        break
      case 'strategy':
      case 'algorithm':
        group.algorithm = value
        break
      case 'policy-path':
        includeAll = true
        break
      case 'include-all-proxies':
        if (truthy(value)) includeAll = true
        break
      case 'include-other-group':
        options.push(...value.split(',').map((part) => unquote(part)).filter(Boolean))
        break
      case 'policy-regex-filter':
        regexFilter = value
        break
      case 'timeout':
      case 'evaluate-before-use':
      case 'no-alert':
        // 同方言标量参数；导出到 Surge 时原样写回。
        parameters = { ...(parameters ?? {}), [key]: value }
        break
      default:
        if (group.type === 'conditional' && field.trim()) {
          conditionalFields.push(field.trim())
        }
        break
    }
  }
  if (conditionalFields.length) {
    parameters = { ...(parameters ?? {}), 'subnet-fields': JSON.stringify(conditionalFields) }
  }
  if (parameters) group.parameters = parameters
  if (includeAll) group.nodeFilter = regexFilter || '.*'
  else if (regexFilter) group.nodeFilter = regexFilter
  return group
}

function surgeNetwork(lines: string[]): RuleSchemeNetworkSettings | undefined {
  let ipv6Enabled: boolean | undefined
  let testURL: string | undefined
  const plain: string[] = []
  const domestic: string[] = []
  const remote: string[] = []
  for (const line of lines) {
    const at = line.indexOf('=')
    if (at < 0) continue
    const key = line.slice(0, at).trim().toLowerCase()
    const value = unquote(line.slice(at + 1))
    switch (key) {
      case 'dns-server':
        for (const part of value.split(',').map((item) => item.trim()).filter(Boolean)) {
          if (isPlainDNSServer(part)) plain.push(part)
          else if (isEncryptedDNSServer(part)) domestic.push(part)
        }
        break
      case 'encrypted-dns-server':
        domestic.push(...value.split(',').map((item) => item.trim()).filter(Boolean))
        break
      case 'tower-remote-dns-server':
        remote.push(...value.split(',').map((item) => item.trim()).filter(Boolean))
        break
      case 'proxy-test-url':
      case 'server_check_url':
        testURL = value
        break
      case 'ipv6':
        ipv6Enabled = truthy(value)
        break
      default:
        break
    }
  }
  if (!plain.length && !domestic.length && !remote.length) return undefined
  // Surge 没有 fake-ip 概念；导出到 Clash 时按标准保护处理。
  return networkSettingsFrom(plain, domestic, remote, 'standard', ipv6Enabled, testURL)
}

function parseSurge(id: string, name: string, description: string, textBody: string): RuleScheme {
  const sections = surgeSections(textBody)
  const groups: PolicyGroup[] = (sections.get('proxy group') ?? [])
    .map(surgeGroup)
    .filter((group): group is PolicyGroup => !!group)
  for (const line of sections.get('proxy chain') ?? []) {
    const at = line.indexOf('=')
    if (at < 0) continue
    const groupName = unquote(line.slice(0, at))
    if (!groupName) continue
    groups.push({
      name: groupName,
      type: 'relay',
      options: splitRuleFields(line.slice(at + 1)).map(unquote).filter(Boolean),
    })
  }

  const rules: RoutingRule[] = []
  for (const line of sections.get('rule') ?? []) {
    const rule = policyRule(line)
    if (!rule) continue
    if (rule.type === 'RULE-SET') rule.ruleSetFormat = 'classical'
    rules.push(rule)
  }
  for (const line of sections.get('remote rule') ?? []) {
    const fields = splitRuleFields(line)
    const url = unquote(fields[0] ?? '')
    if (!/^https?:\/\//i.test(url)) continue
    let group = ''
    let disabled = false
    for (const field of fields.slice(1)) {
      const eq = field.indexOf('=')
      if (eq < 0) {
        if (!group) group = unquote(field)
        continue
      }
      const key = field.slice(0, eq).trim().toLowerCase()
      const value = unquote(field.slice(eq + 1).trim())
      if (key === 'policy') group = value
      if (key === 'enabled' && !truthy(value)) disabled = true
    }
    if (group && !disabled) {
      rules.push({ type: 'RULE-SET', value: url, group, ruleSetFormat: 'classical' })
    }
  }

  const ensured = ensureGroups(groups, rules)
  return {
    id,
    name,
    description,
    groups: normalizeGroupMembers(ensured),
    rules,
    sourceKind: 'paste',
    sourceFormat: 'surge',
    networkSettings: surgeNetwork(sections.get('general') ?? []),
  }
}

// ---------------- Egern YAML ----------------

function egernGroup(raw: unknown): PolicyGroup | undefined {
  const item = dict(raw)
  if (!item) return undefined
  const entry = Object.entries(item).find(([, value]) => dict(value))
  if (!entry) return undefined
  const [rawType, rawValue] = entry
  const value = dict(rawValue)!
  const name = text(value.name)
  if (!name) return undefined
  // external 组的真实类型写在 type 里。
  const type = rawType === 'external'
    ? groupType(value.type)
    : groupType(rawType)
  const group: PolicyGroup = {
    name,
    type,
    options: stringList(value.policies).map(unquote),
  }
  const url = stringList(value.latency_test_url)[0] ?? stringList(value.test_url)[0]
  if (url) group.url = url
  group.interval = duration(value.interval ?? value.check_interval, 'seconds')
  group.tolerance = duration(value.tolerance, 'milliseconds')
  group.algorithm = text(value.algorithm) || undefined
  // urls 指向方案自己的订阅；规则方案不导入节点凭据，改用当前节点池。
  const filter = text(value.filter)
  const includeAll = stringList(value.urls).length > 0 || truthy(value.include_all)
  group.nodeFilter = filter || (includeAll ? '.*' : undefined)
  // conditional 组的数据必须整组保留，导出 Egern 时才能原样写回。
  if (group.type === 'conditional') {
    const rules = array(value.rules).filter((rule) => dict(rule))
    if (rules.length) group.parameters = { rules: JSON.stringify(rules) }
    const fallback = text(value.default_policy)
    if (fallback) group.parameters = { ...(group.parameters ?? {}), default_policy: fallback }
  }
  const native: Record<string, string> = {}
  const timeout = scalar(value.timeout)
  if (timeout) native.timeout = timeout
  const flatten = scalar(value.flatten)
  if (flatten) native.flatten = flatten
  const blockQuic = scalar(value.block_quic)
  if (blockQuic) native.block_quic = blockQuic
  if (Object.keys(native).length) group.parameters = { ...(group.parameters ?? {}), ...native }
  return group
}

const EGERN_RULE_TYPES: Record<string, string> = {
  domain: 'DOMAIN',
  domain_suffix: 'DOMAIN-SUFFIX',
  domain_keyword: 'DOMAIN-KEYWORD',
  domain_regex: 'DOMAIN-REGEX',
  domain_wildcard: 'DOMAIN-WILDCARD',
  geoip: 'GEOIP',
  asn: 'IP-ASN',
  url_regex: 'URL-REGEX',
  user_agent: 'USER-AGENT',
  dest_port: 'DEST-PORT',
  protocol: 'PROTOCOL',
}

function egernRules(raw: unknown): RoutingRule[] {
  const item = dict(raw)
  if (!item) return []
  const entry = Object.entries(item).find(([, value]) => dict(value)) ?? Object.entries(item)[0]
  if (!entry) return []
  const [rawType, rawValue] = entry

  // `default: 策略名` 与 `default: {policy: …}` 两种写法都存在。
  if (rawType === 'default') {
    const value = dict(rawValue)
    const group = unquote(value ? text(value.policy) : scalar(rawValue))
    return group ? [{ type: 'FINAL', group }] : []
  }

  const value = dict(rawValue)
  if (!value) return []
  if (truthy(value.disabled)) return []
  const group = unquote(text(value.policy))
  if (!group) return []
  const matches = stringList(value.match).map(unquote)
  if (!matches.length) return []

  if (rawType === 'rule_set') {
    return matches
      .filter((match) => /^https?:\/\//i.test(match))
      .map((match) => ({ type: 'RULE-SET', value: match, group, ruleSetFormat: 'egern' as const }))
  }

  const mapped = rawType === 'ip_cidr' || rawType === 'ip_cidr6'
    ? 'IP-CIDR'
    : EGERN_RULE_TYPES[rawType]
  if (!mapped) return []
  const noResolve = rawType === 'geoip' || rawType === 'asn' || truthy(value.no_resolve)
  return matches.map((match) => ({
    type: rawType === 'ip_cidr'
      ? (match.includes(':') ? 'IP-CIDR6' : 'IP-CIDR')
      : rawType === 'ip_cidr6'
        ? 'IP-CIDR6'
        : mapped,
    value: match,
    group,
    noResolve,
  }))
}

function parseEgern(id: string, name: string, description: string, textBody: string): RuleScheme {
  let doc: unknown
  try {
    doc = parseYAML(textBody)
  } catch (error) {
    throw new Error(`Egern YAML 解析失败：${error instanceof Error ? error.message : '格式错误'}`)
  }
  const root = dict(doc)
  if (!root) throw new Error('Egern YAML 顶层不是对象')
  const groups = array(root.policy_groups)
    .map(egernGroup)
    .filter((group): group is PolicyGroup => !!group)
  const rules = array(root.rules).flatMap(egernRules)
  if (!groups.length && !rules.length) throw new Error('Egern YAML 中没有 policy_groups 或 rules')
  const ensured = ensureGroups(groups, rules)
  return {
    id,
    name,
    description,
    groups: normalizeGroupMembers(ensured),
    rules,
    sourceKind: 'paste',
    sourceFormat: 'egern',
  }
}

// ---------------- sing-box JSON ----------------

const SINGBOX_RULE_TYPES: Record<string, string> = {
  domain: 'DOMAIN',
  domain_suffix: 'DOMAIN-SUFFIX',
  domain_keyword: 'DOMAIN-KEYWORD',
  domain_regex: 'DOMAIN-REGEX',
  geoip: 'GEOIP',
  asn: 'IP-ASN',
  port: 'DEST-PORT',
  network: 'NETWORK',
  protocol: 'PROTOCOL',
  process_name: 'PROCESS-NAME',
  process_path: 'PROCESS-PATH',
  user_agent: 'USER-AGENT',
}

const SINGBOX_GROUP_TYPES = new Set([
  'selector',
  'urltest',
  'url-test',
  'fallback',
  'load-balance',
])

/** sing-box 的 direct / block outbound 对应内置策略，组和规则都改为 DIRECT / REJECT。 */
function singboxBuiltinAliases(root: Dict): Map<string, string> {
  const aliases = new Map<string, string>()
  for (const raw of array(root.outbounds)) {
    const item = dict(raw)
    if (!item) continue
    const tag = text(item.tag)
    if (!tag) continue
    const type = text(item.type).toLowerCase()
    const builtin = type === 'direct' ? 'DIRECT' : type === 'block' ? 'REJECT' : undefined
    if (builtin) aliases.set(tag, builtin)
  }
  return aliases
}

function singboxGroup(raw: unknown): PolicyGroup | undefined {
  const item = dict(raw)
  if (!item) return undefined
  const type = text(item.type)
  if (!SINGBOX_GROUP_TYPES.has(type)) return undefined
  const name = text(item.tag)
  if (!name) return undefined
  const group: PolicyGroup = {
    name,
    type: groupType(type),
    options: stringList(item.outbounds).map(unquote),
  }
  const url = text(item.url)
  if (url) group.url = url
  group.interval = duration(item.interval ?? item['check_interval'], 'seconds')
  group.tolerance = duration(item.tolerance, 'milliseconds')
  return group
}

function singboxRuleSets(root: Dict): Map<string, { url: string; format: RuleSetFormat }> {
  const ruleSets = new Map<string, { url: string; format: RuleSetFormat }>()
  for (const raw of array(dict(root.route)?.['rule_set'])) {
    const item = dict(raw)
    if (!item) continue
    const tag = text(item.tag)
    const url = text(item.url)
    if (!tag || !url) continue
    const declared = text(item.format).toLowerCase()
    const format: RuleSetFormat = declared === 'binary' || url.toLowerCase().includes('.srs')
      ? 'singbox-binary'
      : declared === 'source'
        ? 'singbox'
        : inferRuleSetFormat(url)
    ruleSets.set(tag, { url, format })
  }
  return ruleSets
}

function singboxRules(
  raw: unknown,
  ruleSets: Map<string, { url: string; format: RuleSetFormat }>,
  aliases: Map<string, string>,
): RoutingRule[] {
  const item = dict(raw)
  if (!item) return []
  const action = text(item.action) || 'route'
  if (action !== 'route' && action !== 'reject') return []
  const rawGroup = action === 'reject' ? 'REJECT' : text(item.outbound)
  if (!rawGroup) return []
  const group = action === 'reject' ? 'REJECT' : aliases.get(rawGroup) ?? rawGroup

  interface Condition {
    type: string
    value: string
    ruleSetFormat?: RuleSetFormat
  }
  // 同一个字段的多个值在 sing-box 里是 OR；不同字段之间是 AND。
  interface Family {
    conditions: Condition[]
  }
  const families: Family[] = []
  const ruleSetConditions: Condition[] = stringList(item.rule_set)
    .map(unquote)
    .map((tag) => ruleSets.get(tag))
    .filter((entry): entry is { url: string; format: RuleSetFormat } => !!entry)
    .map((entry) => ({
      type: 'RULE-SET',
      value: entry.url,
      ruleSetFormat: entry.format,
    }))
  if (ruleSetConditions.length) families.push({ conditions: ruleSetConditions })
  for (const [key, value] of Object.entries(item)) {
    if (['outbound', 'action', 'invert', 'type', 'mode', 'rules', 'rule_set'].includes(key)) continue
    const mapped = key === 'ip_cidr' ? 'IP-CIDR' : SINGBOX_RULE_TYPES[key]
    if (!mapped) continue
    const values = stringList(value).map(unquote)
    if (!values.length) continue
    families.push({
      conditions: values.map((entry) => ({
        type: key === 'ip_cidr'
          ? (entry.includes(':') ? 'IP-CIDR6' : 'IP-CIDR')
          : mapped,
        value: entry,
      })),
    })
  }
  if (!families.length) return []

  const invert = truthy(item.invert)
  const isRuleSet = (family: Family) =>
    family.conditions.every((condition) => condition.type === 'RULE-SET')
  const single = (condition: Condition) => `(${condition.type},${condition.value})`
  const expression = (family: Family): string => {
    if (family.conditions.length === 1) return single(family.conditions[0])
    return `(OR,(${family.conditions.map(single).join(',')}))`
  }
  const noResolve = (type: string) => type === 'IP-CIDR' || type === 'IP-CIDR6'
    || type === 'IP-ASN' || type === 'GEOIP'

  // 单一条件（或同一字段的多值）直接展开成普通规则。
  if (families.length === 1 && !invert) {
    return families[0].conditions.map((condition) => ({
      type: condition.type,
      value: condition.value,
      group,
      noResolve: noResolve(condition.type),
      ...(condition.ruleSetFormat ? { ruleSetFormat: condition.ruleSetFormat } : {}),
    }))
  }
  // 规则集不能安全嵌套进逻辑规则，含其他条件时宁可不导入也不误路由。
  if (families.some(isRuleSet)) return []
  if (families.length === 1) {
    const logical = `NOT,(${expression(families[0])})`
    return [{ type: 'NOT', raw: logical, group, noResolve: false }]
  }
  const branches = families.map(expression)
  const and = `AND,(${branches.join(',')})`
  const logical = invert ? `NOT,((AND,(${branches.join(',')})))` : and
  return [{ type: 'AND', raw: logical, group, noResolve: false }]
}

function singboxNetwork(config: Dict, groups: PolicyGroup[]): RuleSchemeNetworkSettings | undefined {
  const dns = dict(config.dns)
  if (!dns) return undefined
  const servers = array(dns.servers).map(dict).filter((item): item is Dict => !!item)
  const plain: string[] = []
  const domestic: string[] = []
  const remote: string[] = []
  const domesticTags: string[] = []
  const remoteTags: string[] = []
  for (const server of servers) {
    const type = text(server.type)
    const tag = text(server.tag)
    const address = text(server.server)
    if (type === 'udp' && isPlainDNSServer(address)) {
      plain.push(address)
      continue
    }
    if (!['https', 'h3', 'tls', 'quic'].includes(type) || !address) continue
    let candidate = address
    if (!/^(?:https|h3|tls|quic):\/\//i.test(address)) {
      const port = number(server.server_port)
      const path = type === 'https'
        ? `/${text(server.path).replace(/^\//, '') || 'dns-query'}`
        : ''
      candidate = `${type}://${address}${port ? `:${port}` : ''}${path}`
    }
    if (!isEncryptedDNSServer(candidate)) continue
    // detour 指向代理 outbound 时是远程 DNS；否则按标签兜底。
    const detour = text(server.detour)
    const proxied = !!detour && detour.toUpperCase() !== 'DIRECT'
    if (proxied || tag.toLowerCase().includes('remote')) {
      remote.push(candidate)
      if (tag) remoteTags.push(tag)
    } else {
      domestic.push(candidate)
      if (tag) domesticTags.push(tag)
    }
  }
  const final = text(dns.final)
  const mode: RuleSchemeDNSProtectionMode = remoteTags.includes(final) ? 'strict' : 'standard'
  const strategy = text(dns.strategy).toLowerCase()
  const ipv6Enabled = strategy === 'ipv4_only'
    ? false
    : strategy === 'prefer_ipv6' || strategy === 'ipv6_only'
      ? true
      : undefined
  const testURL = groups.find((group) => group.url)?.url
  return networkSettingsFrom(plain, domestic, remote, mode, ipv6Enabled, testURL)
}

function parseSingBox(id: string, name: string, description: string, textBody: string): RuleScheme {
  let doc: unknown
  try {
    doc = JSON.parse(textBody)
  } catch (error) {
    throw new Error(`sing-box JSON 解析失败：${error instanceof Error ? error.message : '格式错误'}`)
  }
  const root = dict(doc)
  if (!root) throw new Error('sing-box JSON 顶层不是对象')
  const aliases = singboxBuiltinAliases(root)
  const groups = array(root.outbounds)
    .map(singboxGroup)
    .filter((group): group is PolicyGroup => !!group)
  const ruleSets = singboxRuleSets(root)
  const rules: RoutingRule[] = []
  for (const raw of array(dict(root.route)?.rules)) {
    rules.push(...singboxRules(raw, ruleSets, aliases))
  }
  const final = text(dict(root.route)?.final)
  if (final) rules.push({ type: 'FINAL', group: aliases.get(final) ?? final })
  if (!groups.length && !rules.length) throw new Error('sing-box JSON 中没有 selector/urltest 或 route.rules')
  const ensured = ensureGroups(groups, rules)
  return {
    id,
    name,
    description,
    groups: normalizeGroupMembers(ensured, aliases),
    rules,
    sourceKind: 'paste',
    sourceFormat: 'singbox',
    networkSettings: singboxNetwork(root, ensured),
  }
}

// ---------------- detection / entry point ----------------

export const RULE_SCHEME_FORMAT_TITLES: Record<RuleSchemeFormat, string> = {
  ini: 'subconverter INI',
  clash: 'Clash / mihomo YAML',
  surge: 'Surge 配置',
  egern: 'Egern YAML',
  singbox: 'sing-box JSON',
}

export function detectRuleSchemeFormat(textBody: string): RuleSchemeFormat {
  const body = textBody.trim()
  if (!body) throw new Error('规则方案内容为空')
  if (body.length > MAX_IMPORT_BYTES) throw new Error('规则方案内容过大')

  if (body.startsWith('{')) {
    let value: unknown
    try {
      value = JSON.parse(body)
    } catch {
      throw new Error('JSON 解析失败，请检查 sing-box 配置')
    }
    const root = dict(value)
    if (!root) throw new Error('JSON 顶层不是对象')
    if (Array.isArray(root['proxy-groups'])) return 'clash'
    if (Array.isArray(root.policy_groups)) return 'egern'
    return 'singbox'
  }
  // subconverter INI 先判断，避免被个别 [General] 段落误认成 Surge。
  if (/custom_proxy_group=|^ruleset=/im.test(body)) return 'ini'
  if (/^\[(?:general|proxy|proxy group|proxy chain|rule|remote rule)]/im.test(body)) {
    return 'surge'
  }
  try {
    const value = parseYAML(body)
    const root = dict(value)
    if (root) {
      if (Array.isArray(root.policy_groups)) return 'egern'
      if (Array.isArray(root['proxy-groups']) || Array.isArray(root.rules)) return 'clash'
    }
  } catch {
    // Fall through to INI; the INI parser gives the final error.
  }
  return 'ini'
}

export async function parseRuleSchemeText(
  id: string,
  name: string,
  description: string,
  textBody: string,
  format = detectRuleSchemeFormat(textBody),
): Promise<RuleScheme> {
  if (!textBody.trim()) throw new Error('规则方案内容为空')
  if (textBody.length > MAX_IMPORT_BYTES) throw new Error('规则方案内容过大')
  switch (format) {
    case 'clash':
      return parseClash(id, name, description, textBody)
    case 'surge':
      return parseSurge(id, name, description, textBody)
    case 'egern':
      return parseEgern(id, name, description, textBody)
    case 'singbox':
      return parseSingBox(id, name, description, textBody)
    case 'ini':
    default:
      return parseSchemeINI(id, name, description, textBody)
  }
}
