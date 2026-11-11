// Convert a classical Clash rule list into the remote rule-set dialect a
// client can actually download. Every line must be representable; a partial
// conversion is rejected so a remote reference never silently loses rules.
// Binary MRS / SRS output only contains the subset each format can express;
// the caller keeps every other line inline in the generated profile.
import { isIP } from 'node:net'
import { encodeMihomoRuleSet, encodeSingBoxRuleSet } from './ruleset-binary.mjs'

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
  classic: 'text/plain; charset=utf-8',
  quanx: 'text/plain; charset=utf-8',
  egern: 'text/yaml; charset=utf-8',
  singbox: 'application/json; charset=utf-8',
  mrs: 'application/octet-stream',
  srs: 'application/octet-stream',
  'srs-domain': 'application/octet-stream',
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
    // QuanX 远程列表没有 no-resolve 字段：IP 规则第三段只被接受后被丢弃，
    // 语义上变成「允许 DNS 解析」。这是载体限制，导出侧不能宣称无损。
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
    // sing-box 规则集没有逐条 no-resolve 位；带 no-resolve 的 IP 规则会按
    // 普通 ip_cidr 落地，匹配前可能触发解析。属于载体的语义降级。
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

const HTML_PAGE = /<!doctype|<html[\s>]|<\/html>/i
const RULE_TYPE = /^[A-Z][A-Z0-9-]{0,31}$/
// DNS label：字母/数字/连字符，不能以连字符开头或结尾；不允许通配符 * 与下划线。
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i

/**
 * 解开 Clash provider YAML（payload: 列表），按 behavior 转成普通规则。
 * domain：`+.x` / `*.x` / `.x` → DOMAIN-SUFFIX，裸域名 → DOMAIN；
 * ipcidr：按 v4/v6 生成 IP-CIDR / IP-CIDR6，并带 no-resolve；
 * classical：payload 每行本身就是 `TYPE,value...`，原样拆字段。
 *
 * /api/ruleset 是免密钥 GET，输入不可信：必须存在 block 列表写法的
 * payload:，逐条校验域名 / CIDR / 规则类型，HTML 页面直接 422，
 * 不能「尽量转」。
 */
function providerRules(text, behavior) {
  if (HTML_PAGE.test(text)) {
    throw new RuleSetConversionError('规则集返回的是 HTML 页面，不是 Clash provider YAML')
  }
  if (behavior !== 'domain' && behavior !== 'ipcidr' && behavior !== 'classical') {
    throw new RuleSetConversionError('provider YAML 需要 behavior=domain / ipcidr / classical', 400)
  }
  const lines = text.split(/\r?\n/)
  let payloadIndex = -1
  let payloadTail = ''
  for (let index = 0; index < lines.length; index += 1) {
    const probe = stripComment(lines[index]).trim()
    const match = /^payload\s*:\s*(.*)$/.exec(probe)
    if (!match) continue
    if (payloadIndex >= 0) throw new RuleSetConversionError('provider YAML 出现多个 payload:')
    payloadIndex = index
    payloadTail = match[1].trim()
  }
  if (payloadIndex < 0) throw new RuleSetConversionError('不是 Clash provider YAML：缺少 payload:')
  if (payloadTail === '[]') throw new RuleSetConversionError('provider YAML 的 payload 为空')
  if (payloadTail) {
    throw new RuleSetConversionError(`provider YAML 只支持 block 列表写法：payload: ${payloadTail.slice(0, 40)}`)
  }
  const rules = []
  for (let index = 0; index < lines.length; index += 1) {
    const line = stripComment(lines[index])
    const probe = line.trim()
    if (!probe || probe.startsWith('#') || probe.startsWith(';') || probe.startsWith('//')) continue
    if (index < payloadIndex) {
      throw new RuleSetConversionError(`provider YAML 在 payload: 之前有无法解析的内容：${probe.slice(0, 40)}`)
    }
    if (index === payloadIndex) continue
    const item = /^\s*-\s*(.*)$/.exec(line)
    if (!item) {
      throw new RuleSetConversionError(`provider YAML 列表项必须以 "- " 开头：${probe.slice(0, 60)}`)
    }
    const value = unquote(item[1].trim())
    if (!value) continue
    if (behavior === 'domain') {
      const suffix = value.startsWith('+.') || value.startsWith('*.') || value.startsWith('.')
      const domain = suffix ? value.replace(/^(\+\.|\*\.|\.)/, '') : value
      if (!domain || domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')
        || /[\s,;<>/'"]/.test(domain)
        || domain.split('.').some((label) => !DOMAIN_LABEL.test(label))) {
        throw new RuleSetConversionError(`provider domain 规则无效：${value}`)
      }
      rules.push({ type: suffix ? 'DOMAIN-SUFFIX' : 'DOMAIN', fields: [suffix ? 'DOMAIN-SUFFIX' : 'DOMAIN', domain] })
      continue
    }
    if (behavior === 'ipcidr') {
      const slash = value.indexOf('/')
      const version = slash > 0 ? isIP(value.slice(0, slash)) : 0
      const prefixText = slash > 0 ? value.slice(slash + 1) : ''
      if (!version || !/^\d{1,3}$/.test(prefixText)
        || Number(prefixText) > (version === 6 ? 128 : 32)) {
        throw new RuleSetConversionError(`provider ipcidr 规则无效：${value}`)
      }
      const type = version === 6 ? 'IP-CIDR6' : 'IP-CIDR'
      rules.push({ type, fields: [type, value, 'no-resolve'] })
      continue
    }
    const fields = splitFields(value)
    const type = fields[0]?.toUpperCase() ?? ''
    if (!RULE_TYPE.test(type) || !fields[1]?.trim() || /[<>]/.test(value)) {
      throw new RuleSetConversionError(`provider classical 规则无法解析：${value}`)
    }
    rules.push({ type, fields })
  }
  return rules
}

function convertClassic(rules) {
  const lines = []
  for (const rule of rules) {
    if (!rule.fields[1]) {
      throw new RuleSetConversionError(`经典规则集不能转换 ${rule.type} 规则`)
    }
    // Surge 手册：规则集文件「每行是一条不带策略的规则声明」，no-resolve 是
    // [Rule] 里 RULE-SET 行的参数，因此正文不能带参数。
    // Loon 的 IP 规则文档展示的是 `IP-CIDR,addr,no-resolve`（无策略写法），但托管
    // 正文与 Surge 共用同一个 URL，只能按更严格的 Surge 口径产出；Loon 因此失去
    // no-resolve（语义降级，导出侧不宣称无损）。
    lines.push([rule.fields[0], rule.fields[1]].map(unquote).join(','))
  }
  if (!lines.length) throw new RuleSetConversionError('没有可转换的经典规则')
  return lines.join('\n') + '\n'
}

export const RULESET_CONVERT_FORMATS = ['classic', 'quanx', 'egern', 'singbox', 'mrs', 'srs', 'srs-domain']

function normalizedRule(rule) {
  return {
    type: rule.type,
    value: unquote(rule.fields[1] ?? ''),
    options: rule.fields.slice(2).map(unquote),
  }
}

export function convertRuleSet(text, format, options = {}) {
  const allowEmpty = options.allowEmpty === true
  if (typeof text !== 'string' || (!text.trim() && !allowEmpty)) {
    throw new RuleSetConversionError('规则集内容为空')
  }
  // 远程抓取仍限制 8MB；GEOIP 这类从本地库展开的源可能更大，由调用方显式放宽。
  const maxBytes = Number(options.maxSourceBytes) > 0
    ? Number(options.maxSourceBytes)
    : 8 * 1024 * 1024
  if (text.length > maxBytes) {
    throw new RuleSetConversionError('规则集内容过大')
  }
  const rules = options.provider === 'yaml'
    ? providerRules(text, String(options.behavior ?? '').toLowerCase())
    : ruleLines(text)
  const normalized = format === 'sing-box' ? 'singbox' : format
  // 只有 SRS 能表达零规则占位；其他格式没有合法的空规则集。
  if (!rules.length && !(allowEmpty && normalized === 'srs')) {
    throw new RuleSetConversionError('没有解析到规则')
  }
  let body
  let ruleCount = rules.length
  if (normalized === 'classic') body = convertClassic(rules)
  else if (normalized === 'quanx') body = convertQuanX(rules)
  else if (normalized === 'egern') body = convertEgern(rules)
  else if (normalized === 'singbox') body = convertSingBox(rules)
  else if (normalized === 'mrs') {
    const behavior = String(options.behavior ?? '').toLowerCase()
    if (behavior !== 'domain' && behavior !== 'ipcidr') {
      throw new RuleSetConversionError('MRS 需要 behavior=domain 或 behavior=ipcidr')
    }
    try {
      const binary = encodeMihomoRuleSet(rules.map(normalizedRule), behavior)
      body = binary.body
      ruleCount = binary.ruleCount
    } catch (error) {
      throw new RuleSetConversionError(error?.message ?? 'MRS 编码失败')
    }
  } else if (normalized === 'srs' || normalized === 'srs-domain') {
    try {
      const binary = encodeSingBoxRuleSet(
        rules.map(normalizedRule),
        { domainOnly: normalized === 'srs-domain', allowEmpty },
      )
      body = binary.body
      ruleCount = binary.ruleCount
    } catch (error) {
      throw new RuleSetConversionError(error?.message ?? 'SRS 编码失败')
    }
  } else {
    throw new RuleSetConversionError(`不支持的规则集格式：${format}`)
  }
  return {
    text: body,
    contentType: CONTENT_TYPES[normalized],
    ruleCount,
  }
}
