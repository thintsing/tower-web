// Import standalone rule sets from the formats clients use: Clash classic
// lists / provider YAML, Quantumult X filters, Egern YAML and sing-box source.
import { parse as parseYAML } from 'yaml'
import type { RuleSetFormat, RoutingRule } from '../models/types'
import { apiFetch } from '../util/apiAuth'
import { inlineRuleFromFields, splitRuleFields } from './scheme'

export type RuleSetRule = Omit<RoutingRule, 'group'>

export interface ParsedRuleSet {
  format: RuleSetFormat
  rules: RuleSetRule[]
}

export const RULE_SET_FORMAT_TITLES: Record<RuleSetFormat, string> = {
  classical: 'Clash 经典列表',
  yaml: 'Clash provider YAML',
  mrs: 'MRS 二进制',
  quanx: 'Quantumult X filter',
  egern: 'Egern YAML',
  singbox: 'sing-box source JSON',
  'singbox-binary': 'SRS 二进制',
}

const QX_TYPES: Record<string, string> = {
  host: 'DOMAIN',
  'host-suffix': 'DOMAIN-SUFFIX',
  'host-keyword': 'DOMAIN-KEYWORD',
  'host-wildcard': 'DOMAIN-WILDCARD',
  'ip-cidr': 'IP-CIDR',
  'ip6-cidr': 'IP-CIDR6',
  geoip: 'GEOIP',
  'ip-asn': 'IP-ASN',
  'user-agent': 'USER-AGENT',
  'url-regex': 'URL-REGEX',
}

const EGERN_TYPES: Record<string, string> = {
  domain_set: 'DOMAIN',
  domain_suffix_set: 'DOMAIN-SUFFIX',
  domain_keyword_set: 'DOMAIN-KEYWORD',
  domain_regex_set: 'DOMAIN-REGEX',
  domain_wildcard_set: 'DOMAIN-WILDCARD',
  ip_cidr_set: 'IP-CIDR',
  ip_cidr6_set: 'IP-CIDR6',
  geoip_set: 'GEOIP',
  asn_set: 'IP-ASN',
  url_regex_set: 'URL-REGEX',
  user_agent_set: 'USER-AGENT',
  protocol_set: 'PROTOCOL',
  dest_port_set: 'DEST-PORT',
}

const SINGBOX_FIELDS: Record<string, string> = {
  domain: 'DOMAIN',
  domain_suffix: 'DOMAIN-SUFFIX',
  domain_keyword: 'DOMAIN-KEYWORD',
  domain_regex: 'DOMAIN-REGEX',
  ip_cidr: 'IP-CIDR',
}

const IP_TYPES = new Set(['IP-CIDR', 'IP-CIDR6', 'GEOIP', 'IP-ASN'])

function text(value: unknown): string {
  if (typeof value === 'string') return value.trim()
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return ''
}

function stringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(text).filter(Boolean)
  const single = text(value)
  return single ? [single] : []
}

function isDict(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function requireRules(rules: RuleSetRule[], label: string): RuleSetRule[] {
  if (!rules.length) throw new Error(`${label}中没有解析到规则`)
  if (rules.some((rule) => rule.type === 'FINAL')) {
    throw new Error(`${label}不能包含 FINAL / MATCH 行；最终规则只属于规则方案`)
  }
  return rules
}

/** 严格逐行解析：无法识别的行直接报错，避免远程规则集静默丢规则。 */
function parseClassicLines(textBody: string, label: string): RuleSetRule[] {
  const rules: RuleSetRule[] = []
  for (const raw of textBody.split(/\r?\n/)) {
    let line = raw.trim()
    if (!line || line.startsWith('#') || line.startsWith(';') || line.startsWith('//') || line === 'payload:') continue
    if (line.startsWith('- ')) line = line.slice(2).trim()
    if (!line) continue
    const parsed = inlineRuleFromFields(splitRuleFields(line))
    if (!parsed) throw new Error(`${label}存在无法识别的规则行：${line.slice(0, 80)}`)
    rules.push(parsed)
  }
  return requireRules(rules, label)
}

function parseClassical(textBody: string): ParsedRuleSet {
  return {
    format: 'classical',
    rules: parseClassicLines(textBody, '经典规则列表'),
  }
}

function providerLines(root: unknown): string[] {
  if (Array.isArray(root)) return root.map(text).filter(Boolean)
  if (!isDict(root)) return []
  const payload = root.payload
  if (typeof payload === 'string') return payload.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  if (Array.isArray(payload)) return payload.map(text).filter(Boolean)
  if (Array.isArray(root.rules) && root.rules.every((rule) => typeof rule === 'string')) {
    return root.rules as string[]
  }
  return []
}

function parseProviderYAML(textBody: string): ParsedRuleSet {
  let root: unknown
  try {
    root = parseYAML(textBody)
  } catch (error) {
    throw new Error(`Clash provider YAML 解析失败：${error instanceof Error ? error.message : '格式错误'}`)
  }
  const lines = providerLines(root)
  if (!lines.length) throw new Error('Clash provider YAML 中没有 payload 或 rules')
  return {
    format: 'yaml',
    rules: parseClassicLines(lines.join('\n'), 'Clash provider YAML'),
  }
}

function parseQuanX(textBody: string): ParsedRuleSet {
  const rules: RuleSetRule[] = []
  for (const raw of textBody.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#') || line.startsWith(';') || line.startsWith('//')) continue
    const fields = splitRuleFields(line)
    const mapped = QX_TYPES[fields[0]?.toLowerCase() ?? '']
    if (!mapped) throw new Error(`不支持的 QuanX 规则类型：${fields[0] ?? '空行'}`)
    const value = fields[1]?.trim()
    if (!value) throw new Error(`QuanX ${mapped} 规则缺少值`)
    rules.push({
      type: mapped,
      value,
      noResolve: IP_TYPES.has(mapped),
    })
  }
  return { format: 'quanx', rules: requireRules(rules, 'QuanX filter') }
}

function parseEgern(textBody: string): ParsedRuleSet {
  let root: unknown
  try {
    root = parseYAML(textBody)
  } catch (error) {
    throw new Error(`Egern YAML 解析失败：${error instanceof Error ? error.message : '格式错误'}`)
  }
  if (!isDict(root)) throw new Error('Egern 规则集顶层不是对象')
  const noResolve = text(root.no_resolve).toLowerCase() === 'true' || root.no_resolve === true
  const rules: RuleSetRule[] = []
  for (const [key, raw] of Object.entries(root)) {
    if (key === 'no_resolve') continue
    if (key === 'update_interval' || key === 'name') continue
    const mapped = EGERN_TYPES[key]
    if (!mapped) throw new Error(`不支持的 Egern 规则集字段：${key}`)
    for (const value of stringList(raw)) {
      let type = mapped
      if (key === 'ip_cidr_set' && value.includes(':')) type = 'IP-CIDR6'
      if (key === 'geoip_set' || key === 'asn_set') {
        rules.push({ type, value, noResolve: true })
      } else {
        rules.push({
          type,
          value,
          noResolve: IP_TYPES.has(type) ? noResolve : undefined,
        })
      }
    }
  }
  return { format: 'egern', rules: requireRules(rules, 'Egern YAML') }
}

function parseSingBox(textBody: string): ParsedRuleSet {
  let root: unknown
  try {
    root = JSON.parse(textBody)
  } catch (error) {
    throw new Error(`sing-box source JSON 解析失败：${error instanceof Error ? error.message : '格式错误'}`)
  }
  if (!isDict(root) || !Array.isArray(root.rules)) {
    throw new Error('sing-box source JSON 缺少 rules 数组')
  }
  const rules: RuleSetRule[] = []
  for (const rawRule of root.rules) {
    if (!isDict(rawRule)) throw new Error('sing-box rules 中存在非对象条目')
    // sing-box 的 domain* / geoip / ip_cidr 在同一个 OR 条件组里；拆成多条
    // 规则后语义等价，且所有客户端都能表达，不需要客户端支持逻辑规则。
    for (const [field, value] of Object.entries(rawRule)) {
      const mapped = SINGBOX_FIELDS[field]
      if (!mapped) throw new Error(`不支持的 sing-box 规则字段：${field}`)
      const values = stringList(value)
      if (!values.length) throw new Error(`sing-box ${field} 缺少值`)
      for (const item of values) {
        const type = field === 'ip_cidr'
          ? (item.includes(':') ? 'IP-CIDR6' : 'IP-CIDR')
          : mapped
        rules.push({
          type,
          value: item,
          noResolve: IP_TYPES.has(type),
        })
      }
    }
  }
  return { format: 'singbox', rules: requireRules(rules, 'sing-box source JSON') }
}

/** 自动识别规则集方言；无法确认时按经典文本处理。 */
export function detectRuleSetFormat(textBody: string): RuleSetFormat {
  const body = textBody.trim()
  if (!body) throw new Error('规则集内容为空')
  if (body.startsWith('{')) {
    let root: unknown
    try {
      root = JSON.parse(body)
    } catch {
      throw new Error('JSON 规则集解析失败')
    }
    if (isDict(root) && Array.isArray(root.rules)) return 'singbox'
    throw new Error('JSON 规则集缺少 rules 数组')
  }
  const lines = body.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  const first = lines.find((line) => !line.startsWith('#') && !line.startsWith(';') && !line.startsWith('//'))
  const firstField = first?.split(',')[0]?.trim().toLowerCase() ?? ''
  if (QX_TYPES[firstField]) return 'quanx'
  try {
    const root = parseYAML(body)
    if (isDict(root)) {
      if ('payload' in root) return 'yaml'
      if (Object.keys(root).some((key) => key in EGERN_TYPES) || 'no_resolve' in root) return 'egern'
      if (Array.isArray(root.rules) && root.rules.every((rule) => typeof rule === 'string')) return 'classical'
    }
  } catch {
    // fall through to classical
  }
  return 'classical'
}

export function parseRuleSetText(textBody: string, format?: RuleSetFormat): ParsedRuleSet {
  if (!textBody.trim()) throw new Error('规则集内容为空')
  const resolved = format ?? detectRuleSetFormat(textBody)
  switch (resolved) {
    case 'classical':
      return parseClassical(textBody)
    case 'yaml':
      return parseProviderYAML(textBody)
    case 'quanx':
      return parseQuanX(textBody)
    case 'egern':
      return parseEgern(textBody)
    case 'singbox':
      return parseSingBox(textBody)
    case 'mrs':
    case 'singbox-binary':
      throw new Error(`${RULE_SET_FORMAT_TITLES[resolved]}是二进制规则集，不能直接解析为规则行`)
    default:
      throw new Error(`不支持的规则集格式：${resolved}`)
  }
}

/** 通过塔台 /api/fetch 读取在线规则集并自动识别格式。 */
export async function fetchRuleSet(url: string): Promise<ParsedRuleSet> {
  const target = url.trim()
  if (!/^https?:\/\//i.test(target)) throw new Error('请输入有效的 http(s) 规则集地址')
  const response = await apiFetch(`/api/fetch?url=${encodeURIComponent(target)}`)
  if (!response.ok) {
    const body = await response.json().catch(() => ({}) as { error?: string })
    throw new Error(body.error ?? `规则集地址返回 HTTP ${response.status}`)
  }
  const body = await response.text()
  if (!body.trim()) throw new Error('规则集内容为空')
  return parseRuleSetText(body)
}
