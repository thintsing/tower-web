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
  /** 单行无法识别时被跳过的行数；0 表示全部识别。 */
  skippedLines?: number
  /** 跳过的前几行（最多 5 例），用于错误与导入提示。 */
  skippedSamples?: string[]
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

const SKIP_SAMPLE_LIMIT = 5

/** 去 BOM、行尾 \r、首尾空白；`.txt` 与 provider YAML 的行统一走这里。 */
function normalizeLine(raw: string): string {
  return raw.replace(/^\uFEFF/, '').replace(/\r$/, '').trim()
}

/** 去掉包裹整行的引号（Clash 列表里允许 `'+.foo.com'` 这种写法）。 */
function unquote(value: string): string {
  const trimmed = value.trim()
  if (trimmed.length >= 2 && (trimmed[0] === '"' || trimmed[0] === "'") && trimmed[trimmed.length - 1] === trimmed[0]) {
    return trimmed.slice(1, -1).trim()
  }
  return trimmed
}

const HOST_NAME = /^[a-z0-9_*](?:[a-z0-9_*-]*[a-z0-9_*])?(?:\.[a-z0-9_*](?:[a-z0-9_*-]*[a-z0-9_*])?)+$/

/**
 * 纯域名列表写法：`+.foo.com` / `.foo.com` / `foo.com` 都是「域名及其子域」，
 * 必须导出 DOMAIN-SUFFIX；写成 DOMAIN 会漏掉子域，是真实分流差异。
 */
function hostSuffixRule(line: string): RuleSetRule | undefined {
  const token = unquote(line)
  if (/[\s,:/]/.test(token)) return undefined
  // `*.foo.com` 是子域通配，可以按后缀处理；其它位置的 `*`（如 foo*bar.com）
  // 不是合法域名，不能原样写进 DOMAIN-SUFFIX（客户端会直接判规则无效）。
  if (token.includes('*') && !/^\*\./.test(token)) return undefined
  const bare = token.replace(/^\+/, '').replace(/^\*\./, '').replace(/^\.+/, '').replace(/\.+$/, '').toLowerCase()
  if (!bare) return undefined
  // 纯 IP 列表行写进 DOMAIN-SUFFIX 会静默失效；按 IP-CIDR 处理才是原意。
  const octets = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(bare) ? bare.split('.') : undefined
  if (octets && octets.every((part) => Number(part) <= 255 && String(Number(part)) === part)) {
    return { type: 'IP-CIDR', value: `${bare}/32`, noResolve: false }
  }
  if (!HOST_NAME.test(bare)) return undefined
  return { type: 'DOMAIN-SUFFIX', value: bare, noResolve: false }
}

interface ClassicParse {
  rules: RuleSetRule[]
  total: number
  skippedCount: number
  skippedSamples: string[]
}

function finishClassic(format: RuleSetFormat, label: string, parsed: ClassicParse): ParsedRuleSet {
  if (parsed.rules.some((rule) => rule.type === 'FINAL')) {
    throw new Error(`${label}不能包含 FINAL / MATCH 行；最终规则只属于规则方案`)
  }
  if (!parsed.rules.length) {
    const samples = parsed.skippedSamples.map((line) => `「${line}」`).join('、')
    const skippedPart = parsed.skippedCount
      ? `跳过 ${parsed.skippedCount} 行${samples ? `，前 ${parsed.skippedSamples.length} 例：${samples}` : ''}`
      : ''
    throw new Error([
      `识别为「${RULE_SET_FORMAT_TITLES[format]}」，共 ${parsed.total} 行，没有可用的规则`,
      skippedPart,
      '建议：确认地址返回的是规则列表而不是 HTML 错误页；纯域名列表每行一条（可带 +. 或 . 前缀）；Clash 规则写成 DOMAIN-SUFFIX,example.com 形式',
    ].filter(Boolean).join('。'))
  }
  return {
    format,
    rules: parsed.rules,
    skippedLines: parsed.skippedCount,
    skippedSamples: parsed.skippedSamples,
  }
}

/** UI 提示：实际识别成哪种格式、跳过了多少行（前几例）。 */
export function describeRuleSetParse(parsed: ParsedRuleSet): string {
  const title = RULE_SET_FORMAT_TITLES[parsed.format]
  const skipped = parsed.skippedLines ?? 0
  if (!skipped) return `识别为「${title}」`
  const samples = (parsed.skippedSamples ?? []).map((line) => `「${line}」`).join('、')
  return `识别为「${title}」，跳过 ${skipped} 行${samples ? `（前 ${parsed.skippedSamples?.length ?? 0} 例：${samples}）` : ''}`
}

/** 逐行解析：无法识别的单行只汇总跳过，不中断整批。 */
function parseClassicLines(textBody: string): ClassicParse {
  const rules: RuleSetRule[] = []
  const skippedSamples: string[] = []
  let total = 0
  let skippedCount = 0
  for (const raw of textBody.split(/\r?\n/)) {
    let line = normalizeLine(raw)
    if (!line || line.startsWith('#') || line.startsWith(';') || line.startsWith('//') || line === 'payload:') continue
    if (line.startsWith('- ')) line = line.slice(2).trim()
    line = unquote(line)
    if (!line) continue
    total += 1
    const parsed = inlineRuleFromFields(splitRuleFields(line)) ?? hostSuffixRule(line)
    if (parsed) {
      rules.push(parsed)
      continue
    }
    skippedCount += 1
    if (skippedSamples.length < SKIP_SAMPLE_LIMIT) skippedSamples.push(line.slice(0, 80))
  }
  return { rules, total, skippedCount, skippedSamples }
}

function parseClassical(textBody: string): ParsedRuleSet {
  return finishClassic('classical', '经典规则列表', parseClassicLines(textBody))
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
    throw new Error(`Clash provider YAML 解析失败：${error instanceof Error ? error.message : '格式错误'}。建议：确认文件是带 payload: 的 YAML，或改用纯文本规则列表地址`)
  }
  const lines = providerLines(root)
  if (!lines.length) {
    throw new Error('识别为「Clash provider YAML」，但没有 payload / rules 列表。建议：确认文件含 payload: 数组，或改用纯文本规则列表地址')
  }
  return finishClassic('yaml', 'Clash provider YAML', parseClassicLines(lines.join('\n')))
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

function looksLikeHTML(body: string): boolean {
  const head = body.slice(0, 512).trimStart().toLowerCase()
  if (head.startsWith('<!doctype html') || head.startsWith('<html') || head.startsWith('<?xml')) return true
  return /^<[a-z][\w-]*[\s>]/.test(head) && /<body[\s>]|<head[\s>]|<div[\s>]|<p[\s>]/.test(head)
}

function isCommentLine(line: string): boolean {
  return line.startsWith('#') || line.startsWith(';') || line.startsWith('//')
}

/**
 * 自动识别规则集方言。探测基于内容而非扩展名：带 payload: / YAML 结构才走 YAML，
 * 纯文本行列表按经典文本处理（`.txt` 里也可能出现 jsDelivr 的 HTML 错误页）。
 */
export function detectRuleSetFormat(textBody: string): RuleSetFormat {
  const body = textBody.replace(/^\uFEFF/, '').trim()
  if (!body) throw new Error('规则集内容为空')
  if (looksLikeHTML(body)) {
    throw new Error('识别为「HTML 页面」而不是规则集（常见于 404、登录页或 CDN 错误页）。建议：改用原始文件直链（GitHub 用 raw 地址），并确认浏览器打开该地址看到的是规则行')
  }
  if (body.startsWith('{')) {
    let root: unknown
    try {
      root = JSON.parse(body)
    } catch {
      throw new Error('识别为「JSON」，但解析失败。建议：确认文件是完整 JSON；纯文本规则列表不要用 .json 地址')
    }
    if (isDict(root) && Array.isArray(root.rules)) return 'singbox'
    throw new Error('识别为「JSON」，但缺少 rules 数组。建议：sing-box source 需要 {"rules":[…]}；其他列表请用纯文本或 provider YAML')
  }
  const lines = body.split(/\r?\n/).map(normalizeLine).filter((line) => line && !isCommentLine(line))
  const first = lines[0] ?? ''
  // 只有显式 YAML 键才走 YAML；纯域名列表即便能被 YAML 解析成字符串，也按 text 处理。
  const yamlKey = lines.map((line) => /^([a-z_]+)\s*:(\s|$)/i.exec(line)?.[1]?.toLowerCase()).find(Boolean)
  if (yamlKey === 'payload') return 'yaml'
  const firstField = first.split(',')[0].trim().toLowerCase()
  if (QX_TYPES[firstField]) return 'quanx'
  try {
    const root = parseYAML(body)
    if (isDict(root)) {
      if ('payload' in root) return 'yaml'
      if (Array.isArray(root.rules) && root.rules.every((rule) => typeof rule === 'string')) return 'yaml'
      if (Object.keys(root).some((key) => key in EGERN_TYPES) || 'no_resolve' in root) return 'egern'
    }
  } catch {
    // 纯文本列表通常不是合法 YAML 文档；解析失败即按 text 处理。
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
