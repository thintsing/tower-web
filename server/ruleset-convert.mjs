// Convert a classical Clash rule list into the remote rule-set dialect a
// client can actually download. Every line must be representable; a partial
// conversion is rejected so a remote reference never silently loses rules.

const QUANX_TYPES = {
  DOMAIN: 'host',
  'DOMAIN-SUFFIX': 'host-suffix',
  'DOMAIN-KEYWORD': 'host-keyword',
  'DOMAIN-WILDCARD': 'host-wildcard',
  'IP-CIDR': 'ip-cidr',
  'IP-CIDR6': 'ip6-cidr',
  'IP6-CIDR': 'ip6-cidr',
  GEOIP: 'geoip',
  'IP-ASN': 'ip-asn',
  'USER-AGENT': 'user-agent',
}

const EGERN_KEYS = {
  DOMAIN: 'domain_set',
  'DOMAIN-SUFFIX': 'domain_suffix_set',
  'DOMAIN-KEYWORD': 'domain_keyword_set',
  'DOMAIN-REGEX': 'domain_regex_set',
  'DOMAIN-WILDCARD': 'domain_wildcard_set',
  'IP-CIDR': 'ip_cidr_set',
  'IP-CIDR6': 'ip_cidr6_set',
  'IP6-CIDR': 'ip_cidr6_set',
  GEOIP: 'geoip_set',
  'IP-ASN': 'asn_set',
  'URL-REGEX': 'url_regex_set',
  'USER-AGENT': 'user_agent_set',
}

const SINGBOX_FIELDS = {
  DOMAIN: 'domain',
  'DOMAIN-SUFFIX': 'domain_suffix',
  'DOMAIN-KEYWORD': 'domain_keyword',
  'DOMAIN-REGEX': 'domain_regex',
  'IP-CIDR': 'ip_cidr',
  'IP-CIDR6': 'ip_cidr',
  'IP6-CIDR': 'ip_cidr',
}

const IP_CIDR_TYPES = new Set(['IP-CIDR', 'IP-CIDR6', 'IP6-CIDR'])
const EGERN_IP_TYPES = new Set([...IP_CIDR_TYPES, 'GEOIP', 'IP-ASN'])

const CONTENT_TYPES = {
  quanx: 'text/plain; charset=utf-8',
  egern: 'text/yaml; charset=utf-8',
  singbox: 'application/json; charset=utf-8',
}

export class RuleSetConversionError extends Error {
  constructor(message, status = 422) {
    super(message)
    this.name = 'RuleSetConversionError'
    this.status = status
  }
}

function unquote(value) {
  const text = value.trim()
  if (
    text.length >= 2
    && (text[0] === '"' || text[0] === "'")
    && text[text.length - 1] === text[0]
  ) {
    return text.slice(1, -1)
  }
  return text
}

/** 顶层逗号拆分，保留引号里的逗号；与前端规则解析一致。 */
function splitFields(body) {
  const fields = []
  let current = ''
  let quote
  let escaped = false
  let depth = 0
  for (const char of body) {
    if (escaped) {
      current += char
      escaped = false
      continue
    }
    if (char === '\\') {
      current += char
      escaped = true
      continue
    }
    if (quote) {
      current += char
      if (char === quote) quote = undefined
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      current += char
      continue
    }
    if (char === '(') depth += 1
    if (char === ')') depth = Math.max(0, depth - 1)
    if (char === ',' && depth === 0) {
      fields.push(current.trim())
      current = ''
      continue
    }
    current += char
  }
  fields.push(current.trim())
  return fields
}

function stripComment(line) {
  let quote
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
    if (index > 0 && /\s/.test(line[index - 1])
      && (char === '#' || char === ';' || (char === '/' && line[index + 1] === '/'))) {
      return line.slice(0, index).trim()
    }
  }
  return line.trim()
}

function ruleLines(text) {
  const rules = []
  for (const raw of text.split(/\r?\n/)) {
    let line = stripComment(raw)
    if (!line || line.startsWith('#') || line.startsWith(';') || line.startsWith('//') || line === 'payload:') continue
    if (line.startsWith('- ')) line = line.slice(2).trim()
    if (!line || line.startsWith('- ')) continue
    const fields = splitFields(line)
    const type = fields[0]?.toUpperCase() ?? ''
    if (!type) continue
    rules.push({ type, fields })
  }
  return rules
}

function requireValue(rule, label) {
  const value = unquote(rule.fields[1] ?? '')
  if (!value) throw new RuleSetConversionError(`${label} 第 ${rule.fields[0]} 条规则缺少值`)
  return value
}

function convertQuanX(rules) {
  const lines = []
  for (const rule of rules) {
    const mapped = QUANX_TYPES[rule.type]
    if (!mapped) {
      throw new RuleSetConversionError(`QuanX 远程规则集不能转换 ${rule.type} 规则`)
    }
    if (rule.fields.length < 2 || rule.fields.length > 3) {
      throw new RuleSetConversionError(`QuanX 规则参数无法无损转换：${rule.type}`)
    }
    if (rule.fields.length === 3
      && (!EGERN_IP_TYPES.has(rule.type) || rule.fields[2].toLowerCase() !== 'no-resolve')) {
      throw new RuleSetConversionError(`QuanX 规则参数无法无损转换：${rule.type},${rule.fields[2]}`)
    }
    const value = requireValue(rule, 'QuanX')
    if (value.includes(',')) {
      throw new RuleSetConversionError(`QuanX 规则值包含逗号，无法安全转换：${value}`)
    }
    if (rule.type === 'DOMAIN-SUFFIX' && (value.startsWith('.') || value.startsWith('+.'))) {
      throw new RuleSetConversionError(`QuanX 域名后缀格式无法无损转换：${value}`)
    }
    lines.push(`${mapped}, ${value}, proxy`)
  }
  if (!lines.length) throw new RuleSetConversionError('没有可转换的 QuanX 规则')
  return lines.join('\n') + '\n'
}

function convertEgern(rules) {
  const groups = new Map()
  let sawIP = false
  let ipNoResolve
  for (const rule of rules) {
    const key = EGERN_KEYS[rule.type]
    if (!key) {
      throw new RuleSetConversionError(`Egern 远程规则集不能转换 ${rule.type} 规则`)
    }
    const isIP = EGERN_IP_TYPES.has(rule.type)
    const hasNoResolve = rule.fields.length === 3
      && rule.fields[2].toLowerCase() === 'no-resolve'
    if (rule.fields.length > 3
      || (rule.fields.length === 3 && !hasNoResolve)
      || (!isIP && rule.fields.length === 3)) {
      throw new RuleSetConversionError(`Egern 规则参数无法无损转换：${rule.type}`)
    }
    if (isIP) {
      const state = hasNoResolve || rule.type === 'GEOIP'
      if (sawIP && state !== ipNoResolve) {
        throw new RuleSetConversionError('Egern 规则集无法同时表达带与不带 no-resolve 的 IP 规则')
      }
      sawIP = true
      ipNoResolve = state
    }
    const value = requireValue(rule, 'Egern')
    if (rule.type === 'DOMAIN-SUFFIX' && (value.startsWith('.') || value.startsWith('+.'))) {
      throw new RuleSetConversionError(`Egern 域名后缀格式无法无损转换：${value}`)
    }
    const actualKey = IP_CIDR_TYPES.has(rule.type) && value.includes(':')
      ? 'ip_cidr6_set'
      : key
    const values = groups.get(actualKey) ?? []
    if (!values.includes(value)) values.push(value)
    groups.set(actualKey, values)
  }
  if (!groups.size) throw new RuleSetConversionError('没有可转换的 Egern 规则')
  const lines = []
  if (ipNoResolve) lines.push('no_resolve: true')
  for (const [key, values] of groups) {
    lines.push(`${key}:`)
    for (const value of values) lines.push(`  - ${JSON.stringify(value)}`)
  }
  return lines.join('\n') + '\n'
}

function convertSingBox(rules) {
  const values = new Map()
  for (const rule of rules) {
    const field = SINGBOX_FIELDS[rule.type]
    if (!field) {
      throw new RuleSetConversionError(`sing-box 远程规则集不能转换 ${rule.type} 规则`)
    }
    const isIP = IP_CIDR_TYPES.has(rule.type)
    const hasNoResolve = rule.fields.length === 3
      && rule.fields[2].toLowerCase() === 'no-resolve'
    if (rule.fields.length > 3
      || (rule.fields.length === 3 && (!isIP || !hasNoResolve))
      || (!isIP && rule.fields.length === 3)) {
      throw new RuleSetConversionError(`sing-box 规则参数无法无损转换：${rule.type}`)
    }
    let value = requireValue(rule, 'sing-box')
    if (rule.type === 'DOMAIN-SUFFIX' && (value.startsWith('.') || value.startsWith('+.'))) {
      throw new RuleSetConversionError(`sing-box 域名后缀格式无法无损转换：${value}`)
    }
    if (['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'].includes(rule.type)) {
      value = value.toLowerCase()
    }
    const current = values.get(field) ?? []
    if (!current.includes(value)) current.push(value)
    values.set(field, current)
  }
  if (!values.size) throw new RuleSetConversionError('没有可转换的 sing-box 规则')
  return JSON.stringify({
    version: 2,
    rules: [...values].map(([field, entries]) => ({ [field]: entries })),
  }, null, 2) + '\n'
}

export const RULESET_CONVERT_FORMATS = ['quanx', 'egern', 'singbox']

export function convertRuleSet(text, format) {
  if (typeof text !== 'string' || !text.trim()) {
    throw new RuleSetConversionError('规则集内容为空')
  }
  if (text.length > 8 * 1024 * 1024) {
    throw new RuleSetConversionError('规则集内容过大')
  }
  const rules = ruleLines(text)
  if (!rules.length) throw new RuleSetConversionError('没有解析到规则')
  const normalized = format === 'sing-box' ? 'singbox' : format
  let body
  if (normalized === 'quanx') body = convertQuanX(rules)
  else if (normalized === 'egern') body = convertEgern(rules)
  else if (normalized === 'singbox') body = convertSingBox(rules)
  else throw new RuleSetConversionError(`不支持的规则集格式：${format}`)
  return {
    text: body,
    contentType: CONTENT_TYPES[normalized],
    ruleCount: rules.length,
  }
}
