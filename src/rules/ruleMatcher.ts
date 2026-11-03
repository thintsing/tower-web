// 规则命中判定：解释器和方案检查共用这一套判断，避免两处语义漂移。
// 规则顺序由导出管线的 prepareSchemeForExport 决定，见 ruleExplain.ts。
import { splitRuleFields } from './scheme'
import { CHINA_IP_CIDRS } from './chinaCIDRs'

export type QueryKind = 'domain' | 'ipv4' | 'ipv6' | 'url' | 'unknown'

export interface QueryTarget {
  raw: string
  kind: QueryKind
  host?: string
  ip?: string
  port?: number
  scheme?: 'http' | 'https'
  url?: string
  note?: string
}

export type RuleStepStatus = 'match' | 'miss' | 'skip' | 'unknown'

export interface RuleEvaluation {
  status: RuleStepStatus
  /** 面向用户的中文匹配类型，如「域名后缀」「IP CIDR」「兜底规则」。 */
  matchType: string
  detail?: string
  /** 跳过或无法判定时的原因。 */
  reason?: string
}

interface RuleLike {
  type?: string
  value?: string
  raw?: string
  noResolve?: boolean
  options?: string[]
}

const DOMAIN_TYPES = new Set(['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX'])
const IP_TYPES = new Set(['IP-CIDR', 'IP-CIDR6', 'IP6-CIDR', 'IP-SUFFIX', 'GEOIP', 'IP-ASN'])
const SOURCE_TYPES = new Set([
  'SRC-IP', 'SRC-IP-CIDR', 'SRC-IP-CIDR6', 'SRC-GEOIP', 'SRC-IP-ASN',
  'SRC-PORT', 'IN-PORT', 'SRC-PORT-RANGE',
])

function validIPv4(value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false
    const number = Number(part)
    return number >= 0 && number <= 255
  })
}

function ipv4ToNumber(value: string): number | null {
  if (!validIPv4(value)) return null
  const [a, b, c, d] = value.split('.').map(Number)
  return ((a << 24) >>> 0) + (b << 16) + (c << 8) + d
}

/** 规则值里的 IPv4 必须和 netip.ParsePrefix 一样拒绝前导零。 */
function strictIPv4(value: string): boolean {
  if (!validIPv4(value)) return false
  return value.split('.').every((part) => part === '0' || !part.startsWith('0'))
}

function ipv6ToBigInt(value: string): bigint | null {
  let body = value.trim()
  if (body.startsWith('[') && body.endsWith(']')) body = body.slice(1, -1)
  const zone = body.indexOf('%')
  if (zone >= 0) body = body.slice(0, zone)
  if (!body.includes(':')) return null
  const halves = body.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  // 末尾允许内嵌 IPv4。
  const expand = (groups: string[]): string[] => {
    if (!groups.length) return []
    const last = groups[groups.length - 1]
    if (!last.includes('.')) return groups
    const number = ipv4ToNumber(last)
    if (number === null) return groups
    const hi = ((number >>> 16) & 0xffff).toString(16)
    const lo = (number & 0xffff).toString(16)
    return [...groups.slice(0, -1), hi, lo]
  }
  const headGroups = expand(head)
  const tailGroups = expand(tail)
  const missing = 8 - headGroups.length - tailGroups.length
  if (halves.length === 2 && missing < 1) return null
  if (halves.length === 1 && headGroups.length !== 8) return null
  const groups = halves.length === 2
    ? [...headGroups, ...Array.from({ length: missing }, () => '0'), ...tailGroups]
    : headGroups
  let result = 0n
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null
    result = (result << 16n) + BigInt(parseInt(group, 16))
  }
  return result
}

function ipv6CidrMatch(ip: bigint, network: bigint, prefix: number): boolean {
  if (prefix <= 0) return true
  if (prefix >= 128) return ip === network
  const shift = BigInt(128 - prefix)
  return (ip >> shift) === (network >> shift)
}

interface ParsedCidr {
  family: 4 | 6
  network: number | bigint
  prefix: number
}

function parseCidr(value: string): ParsedCidr | null {
  const parts = value.trim().split('/')
  // mihomo 用 netip.ParsePrefix 解析，`a/b/c`、`/`、`/abc` 都是无效规则。
  if (parts.length > 2) return null
  const address = parts[0]
  const rawPrefix = parts.length === 2 ? parts[1] : undefined
  if (rawPrefix !== undefined && !/^\d{1,3}$/.test(rawPrefix)) return null
  if (strictIPv4(address)) {
    const network = ipv4ToNumber(address)
    if (network === null) return null
    const prefix = rawPrefix === undefined ? 32 : Number(rawPrefix)
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null
    return { family: 4, network, prefix }
  }
  const network = ipv6ToBigInt(address)
  if (network === null) return null
  const prefix = rawPrefix === undefined ? 128 : Number(rawPrefix)
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null
  return { family: 6, network, prefix }
}

function cidrMatch(cidr: ParsedCidr, ip: string): boolean {
  if (cidr.family === 4) {
    const number = ipv4ToNumber(ip)
    if (number === null) return false
    if (cidr.prefix === 0) return true
    const mask = cidr.prefix === 32 ? 0xffffffff : (0xffffffff << (32 - cidr.prefix)) >>> 0
    return (number & mask) === (Number(cidr.network) & mask)
  }
  const number = ipv6ToBigInt(ip)
  if (number === null) return false
  return ipv6CidrMatch(number, cidr.network as bigint, cidr.prefix)
}

/** mihomo IP-SUFFIX：比较 IP 末尾 prefix 位，而不是文本前缀。 */
function ipSuffixMatch(cidr: ParsedCidr, ip: string): boolean {
  if (cidr.prefix === 0) return true
  if (cidr.family === 4) {
    const number = ipv4ToNumber(ip)
    if (number === null) return false
    const mask = cidr.prefix === 32 ? 0xffffffff : ((1 << cidr.prefix) - 1) >>> 0
    return ((number & mask) >>> 0) === ((Number(cidr.network) & mask) >>> 0)
  }
  const number = ipv6ToBigInt(ip)
  if (number === null) return false
  const bits = BigInt(cidr.prefix)
  const mask = cidr.prefix === 128 ? (1n << 128n) - 1n : (1n << bits) - 1n
  return (number & mask) === ((cidr.network as bigint) & mask)
}

function normalizeHost(value: string): string {
  return value.trim().toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '')
}

/**
 * 与 mihomo 的 wildcard.Match 保持一致：`*` 匹配任意长度（可跨过点），
 * `?` 匹配任意单个字符；`*.example.com` 不包含根域 example.com。
 * 用线性通配匹配而不是正则：把长通配串翻译成 `.*.*...` 会产生灾难性回溯。
 */
function wildcardMatch(pattern: string, value: string): boolean {
  const source = pattern.toLowerCase()
  const text = value.toLowerCase()
  let pi = 0
  let ti = 0
  let star = -1
  let mark = 0
  while (ti < text.length) {
    if (pi < source.length && (source[pi] === '?' || source[pi] === text[ti])) {
      pi += 1
      ti += 1
      continue
    }
    if (pi < source.length && source[pi] === '*') {
      star = pi
      mark = ti
      pi += 1
      continue
    }
    if (star !== -1) {
      pi = star + 1
      ti = mark + 1
      mark += 1
      continue
    }
    return false
  }
  while (pi < source.length && source[pi] === '*') pi += 1
  return pi === source.length
}

/**
 * 粗测正则是否可能触发灾难性回溯。只拦截最典型的「量词套量词」与
 * 「带分支的组再被无界量词重复」，避免把普通正则误判为不安全。
 */
function riskyRegex(pattern: string): boolean {
  if (pattern.length > 512) return true
  interface Frame { quantified: boolean; alternation: boolean }
  const stack: Frame[] = [{ quantified: false, alternation: false }]
  let inClass = false
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index]
    if (char === '\\') { index += 1; continue }
    if (inClass) { if (char === ']') inClass = false; continue }
    if (char === '[') { inClass = true; continue }
    const top = stack[stack.length - 1]
    if (char === '|') { top.alternation = true; continue }
    if (char === '(') {
      let next = index + 1
      if (pattern[next] === '?') {
        if (pattern[next + 1] === '<' && (pattern[next + 2] === '=' || pattern[next + 2] === '!')) next += 3
        else next += 2
      }
      stack.push({ quantified: false, alternation: false })
      index = next - 1
      continue
    }
    if (char === ')') {
      const frame = stack.pop()
      if (!frame) return true
      const next = pattern[index + 1]
      if (next === '*' || next === '+') {
        if (frame.quantified || frame.alternation) return true
        index += 1
      } else if (next === '{') {
        const end = pattern.indexOf('}', index + 2)
        if (end > 0) {
          const body = pattern.slice(index + 2, end)
          const [minText, maxText] = body.split(',')
          const unbounded = body.includes(',') && !maxText?.trim()
          const upper = maxText?.trim() ? Number(maxText) : Number(minText)
          if ((unbounded || (Number.isFinite(upper) && upper > 10)) && (frame.quantified || frame.alternation)) return true
          index = end
        }
      }
      const parent = stack[stack.length - 1]
      if (parent) {
        parent.quantified = parent.quantified || frame.quantified
        parent.alternation = parent.alternation || frame.alternation
      }
      continue
    }
    if (char === '*' || char === '+') { top.quantified = true; continue }
    if (char === '{') {
      const end = pattern.indexOf('}', index + 1)
      if (end > 0) { top.quantified = true; index = end }
      continue
    }
    if (char === '?') top.quantified = true
  }
  return false
}

const regexCache = new Map<string, RegExp | null>()

function cachedRegExp(kind: string, value: string): RegExp | null {
  const key = `${kind}:${value}`
  if (regexCache.has(key)) return regexCache.get(key) ?? null
  let regex: RegExp | null = null
  try {
    regex = new RegExp(value)
  } catch {
    regex = null
  }
  regexCache.set(key, regex)
  return regex
}

function portMatches(port: number | undefined, value: string): boolean | undefined {
  if (port === undefined) return undefined
  for (const part of value.split(',').map((item) => item.trim()).filter(Boolean)) {
    if (part.includes('-')) {
      const [from, to] = part.split('-').map((item) => Number(item.trim()))
      if (Number.isInteger(from) && Number.isInteger(to) && port >= from && port <= to) return true
      continue
    }
    if (Number(part) === port) return true
  }
  return false
}

function skip(reason: string, matchType: string): RuleEvaluation {
  return { status: 'skip', matchType, reason }
}

function unknown(reason: string, matchType: string): RuleEvaluation {
  return { status: 'unknown', matchType, reason }
}

function miss(detail: string, matchType: string): RuleEvaluation {
  return { status: 'miss', matchType, detail }
}

function match(detail: string, matchType: string): RuleEvaluation {
  return { status: 'match', matchType, detail }
}

function numberToIPv4(value: number): string {
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.')
}

/** mihomo 在写入 DstIP 时会 Unmap，这里同步把 ::ffff:a.b.c.d 还原成 IPv4。 */
function unmapIPv4Mapped(value: string): string | null {
  const number = ipv6ToBigInt(value)
  if (number === null) return null
  if ((number >> 32n) !== 0xffffn) return null
  return numberToIPv4(Number(number & 0xffffffffn) >>> 0)
}

/** 解析用户输入：域名 / URL / IPv4 / IPv6 / 带端口 / 带路径。 */
export function parseQuery(raw: string): QueryTarget {
  const text = raw.trim().replace(/\s+#.*$/, '')
  if (!text) return { raw, kind: 'unknown', note: '空输入' }
  if (text.length > 4096) return { raw, kind: 'unknown', note: '输入超过 4096 字符，已拒绝解析' }

  const withScheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(text)
  if (withScheme) {
    try {
      const url = new URL(text)
      const rawHost = normalizeHost(url.hostname.replace(/^\[|\]$/g, ''))
      if (rawHost.length > 253) return { raw, kind: 'unknown', note: '主机名超过 253 字符，不是有效域名' }
      const host = rawHost
      const mapped = unmapIPv4Mapped(host)
      const scheme = url.protocol === 'https:' ? 'https' : url.protocol === 'http:' ? 'http' : undefined
      const ip = validIPv4(host) ? host : mapped ?? (ipv6ToBigInt(host) !== null ? host : undefined)
      return {
        raw,
        kind: ip ? (validIPv4(ip) ? 'ipv4' : 'ipv6') : 'url',
        host,
        ip,
        port: url.port ? Number(url.port) : scheme === 'https' ? 443 : scheme === 'http' ? 80 : undefined,
        scheme,
        url: text,
      }
    } catch {
      return { raw, kind: 'unknown', note: 'URL 格式无法解析' }
    }
  }

  // [IPv6]:端口 / [IPv6]
  const bracketed = /^\[([0-9a-fA-F:.%]+)\](?::(\d+))?$/.exec(text)
  if (bracketed) {
    const address = bracketed[1]
    if (ipv6ToBigInt(address) === null) return { raw, kind: 'unknown', note: 'IPv6 地址格式无效' }
    const mapped = unmapIPv4Mapped(address)
    const port = bracketed[2] ? Number(bracketed[2]) : undefined
    if (port !== undefined && port > 65535) return { raw, kind: 'unknown', note: '端口超过 65535，不是有效端口' }
    return {
      raw,
      kind: mapped ? 'ipv4' : 'ipv6',
      host: normalizeHost(mapped ?? address),
      ip: mapped ?? address,
      port,
    }
  }

  // 域名/路径：去掉路径和查询串（IPv6 不含 /）。
  let body = text
  if (!body.startsWith('[')) {
    const slash = body.indexOf('/')
    if (slash >= 0) body = body.slice(0, slash)
    const question = body.indexOf('?')
    if (question >= 0) body = body.slice(0, question)
  }

  let host = body
  let port: number | undefined
  const withPort = /^(.*):(\d+)$/.exec(body)
  if (withPort && !withPort[1].includes(':')) {
    host = withPort[1]
    port = Number(withPort[2])
    if (port > 65535) return { raw, kind: 'unknown', note: '端口超过 65535，不是有效端口' }
  }
  if (!host) return { raw, kind: 'unknown', note: '缺少主机名' }

  if (validIPv4(host)) {
    return { raw, kind: 'ipv4', host: normalizeHost(host), ip: host, port, url: text.startsWith('http') ? text : undefined }
  }
  const mapped = unmapIPv4Mapped(host)
  if (mapped) {
    return { raw, kind: 'ipv4', host: normalizeHost(mapped), ip: mapped, port }
  }
  if (ipv6ToBigInt(host) !== null) {
    return { raw, kind: 'ipv6', host: normalizeHost(host), ip: host, port }
  }
  if (/[^\x20-\x7E]/.test(host)) {
    return { raw, kind: 'unknown', note: '包含无法识别的字符' }
  }
  if (host.length > 253) {
    return { raw, kind: 'unknown', note: '主机名超过 253 字符，不是有效域名' }
  }
  return { raw, kind: 'domain', host: normalizeHost(host), port }
}

interface LogicalLeaf {
  type?: string
  value?: string
  noResolve?: boolean
  options?: string[]
}

interface LogicalExpression {
  op: 'AND' | 'OR' | 'NOT' | 'LEAF'
  leaf?: LogicalLeaf
  items: LogicalExpression[]
}

function stripWrap(value: string): string {
  const trimmed = value.trim()
  if (trimmed.startsWith('(') && trimmed.endsWith(')')) return trimmed.slice(1, -1).trim()
  return trimmed
}

function parseCondition(text: string, depth: number): LogicalExpression | null {
  if (depth > 8) return null
  const body = stripWrap(text)
  if (!body) return null
  const fields = splitRuleFields(body)
  const op = fields[0]?.toUpperCase()
  if (op === 'AND' || op === 'OR' || op === 'NOT') {
    const inner = stripWrap(fields[1] ?? '')
    const parts = splitRuleFields(inner)
    const items = parts.map((part) => parseCondition(part, depth + 1)).filter((item): item is LogicalExpression => item !== null)
    if (!items.length) return null
    return { op, items }
  }
  if (!op) return null
  return {
    op: 'LEAF',
    items: [],
    leaf: {
      type: op,
      value: fields[1],
      noResolve: fields.slice(2).some((option) => option.toLowerCase() === 'no-resolve'),
      options: fields.slice(2),
    },
  }
}

function evaluateExpression(expression: LogicalExpression, target: QueryTarget): RuleEvaluation {
  if (expression.op === 'LEAF') {
    if (!expression.leaf) return unknown('逻辑规则子条件为空', '逻辑规则')
    return evaluateRule(expression.leaf, target)
  }
  const results = expression.items.map((item) => evaluateExpression(item, target))
  if (expression.op === 'NOT') {
    if (results.some((item) => item.status === 'match')) {
      return miss('NOT 子条件命中，因此整条否定', '逻辑规则')
    }
    if (results.every((item) => item.status === 'miss')) {
      return match('NOT 子条件均未命中', '逻辑规则')
    }
    return unknown('NOT 子条件无法完全判定', '逻辑规则')
  }
  if (expression.op === 'OR') {
    if (results.some((item) => item.status === 'match')) return match('OR 中至少一个子条件命中', '逻辑规则')
    if (results.every((item) => item.status === 'miss')) return miss('OR 中所有子条件都未命中', '逻辑规则')
    return unknown('OR 中有子条件无法判定', '逻辑规则')
  }
  if (results.some((item) => item.status === 'miss')) return miss('AND 中至少一个子条件未命中', '逻辑规则')
  if (results.every((item) => item.status === 'match')) return match('AND 中所有子条件都命中', '逻辑规则')
  return unknown('AND 中有子条件无法判定', '逻辑规则')
}

function logicalEvaluation(rule: RuleLike, target: QueryTarget): RuleEvaluation {
  const parsed = parseCondition(rule.raw ?? '', 0)
  if (!parsed || parsed.op === 'LEAF') return unknown('逻辑规则无法离线解析', '逻辑规则')
  return evaluateExpression(parsed, target)
}

/** 单条规则对一次请求的判定。逻辑规则递归求值。 */
export function evaluateRule(rule: RuleLike, target: QueryTarget): RuleEvaluation {
  const type = (rule.type ?? '').toUpperCase()
  const value = (rule.value ?? '').trim()
  const noResolve = rule.noResolve ?? (rule.options ?? []).some((option) => option.toLowerCase() === 'no-resolve')

  if (type === 'AND' || type === 'OR' || type === 'NOT') return logicalEvaluation(rule, target)
  if (type === 'FINAL' || type === 'MATCH') return match('兜底规则：前面都没有命中', '兜底规则')
  if (type === 'RULE-SET') return unknown('规则集引用需要展开后判断', '规则集引用')
  if (type === 'DOMAIN-SET') {
    return unknown('域名规则集需要加载规则内容', '域名规则集')
  }

  if (DOMAIN_TYPES.has(type)) {
    if (!target.host) return skip('输入不是域名', '域名规则')
    if (target.kind === 'ipv4' || target.kind === 'ipv6') {
      // 目标是 IP 时客户端没有域名可匹配，域名规则必定不命中，而不是「无法判断」。
      return miss('输入是 IP，域名类规则不会命中', '域名规则')
    }
    const host = normalizeHost(target.host)
    if (type === 'DOMAIN') {
      const needle = normalizeHost(value)
      return host === needle
        ? match(`host 完全等于 ${needle}`, '域名精确')
        : miss(`host 不等于 ${needle}`, '域名精确')
    }
    if (type === 'DOMAIN-SUFFIX') {
      const suffix = normalizeHost(value)
      return host === suffix || host.endsWith(`.${suffix}`)
        ? match(`host 命中后缀 ${suffix}`, '域名后缀')
        : miss(`host 不以 ${suffix} 结尾`, '域名后缀')
    }
    if (type === 'DOMAIN-KEYWORD') {
      const keyword = value.toLowerCase()
      return host.includes(keyword)
        ? match(`host 含关键词 ${keyword}`, '域名关键词')
        : miss(`host 不含关键词 ${keyword}`, '域名关键词')
    }
    if (type === 'DOMAIN-WILDCARD') {
      if (!value) return miss('通配值为空，不会命中', '域名通配')
      return wildcardMatch(value, host)
        ? match(`host 命中通配 ${value}`, '域名通配')
        : miss(`host 不匹配通配 ${value}`, '域名通配')
    }
    if (type === 'DOMAIN-REGEX') {
      if (riskyRegex(value)) return unknown(`正则过于复杂或可能造成灾难性回溯，已跳过：${value}`, '域名正则')
      const regex = cachedRegExp('regex', value)
      if (!regex) return unknown(`正则表达式无效：${value}`, '域名正则')
      return regex.test(host) ? match(`host 命中正则 ${value}`, '域名正则') : miss(`host 不匹配正则 ${value}`, '域名正则')
    }
  }

  if (IP_TYPES.has(type)) {
    if (type === 'GEOIP') {
      const code = value.toUpperCase()
      if (!target.ip) {
        return noResolve
          ? miss(`GEOIP,${code} 带 no-resolve：域名请求不会解析 IP，因此不会命中`, 'GEOIP')
          : skip(`需要先把域名解析成 IP 才能判断 GEOIP,${code}`, 'GEOIP')
      }
      if (code !== 'CN') return unknown(`离线解释器只内置 CN 的 IP 段，无法判断 GEOIP,${code}`, 'GEOIP')
      if (!validIPv4(target.ip)) return unknown('离线 CN IP 库只覆盖 IPv4', 'GEOIP')
      const inChina = chinaCidrs().some((cidr) => cidrMatch(cidr, target.ip!))
      return inChina
        ? match(`IP ${target.ip} 属于中国大陆网段`, 'GEOIP')
        : miss(`IP ${target.ip} 不在中国大陆网段内`, 'GEOIP')
    }
    if (type === 'IP-ASN') {
      if (!target.ip) {
        return noResolve
          ? miss('IP-ASN 带 no-resolve：域名请求不会解析 IP，因此不会命中', 'IP ASN')
          : skip('需要 ASN 数据库，离线解释器不提供', 'IP ASN')
      }
      return skip('需要 ASN 数据库，离线解释器不提供', 'IP ASN')
    }
    if (!target.ip) {
      return noResolve
        ? miss('该 IP 规则带 no-resolve：域名请求不会解析 IP，因此不会命中', 'IP 规则')
        : skip('该 IP 规则需要 DNS 解析，离线解释器不解析域名', 'IP 规则')
    }
    if (type === 'IP-SUFFIX') {
      if (!value.includes('/')) return unknown(`IP-SUFFIX 需要带前缀位数：${value}`, 'IP 后缀')
      const suffix = parseCidr(value)
      if (!suffix) return unknown(`IP-SUFFIX 格式无效：${value}`, 'IP 后缀')
      const inputFamily = validIPv4(target.ip) ? 4 : 6
      if (suffix.family !== inputFamily) {
        return miss(`地址族不一致：输入是 IPv${inputFamily}，规则是 IPv${suffix.family}`, 'IP 后缀')
      }
      return ipSuffixMatch(suffix, target.ip)
        ? match(`IP ${target.ip} 末尾 ${suffix.prefix} 位命中 ${value}`, 'IP 后缀')
        : miss(`IP ${target.ip} 末尾 ${suffix.prefix} 位不匹配 ${value}`, 'IP 后缀')
    }
    const family = validIPv4(target.ip) ? 4 : 6
    const cidr = parseCidr(value)
    if (!cidr) return unknown(`CIDR 格式无效：${value}`, 'IP CIDR')
    const typeFamily = type === 'IP-CIDR' ? 4 : type === 'IP-CIDR6' || type === 'IP6-CIDR' ? 6 : undefined
    if (typeFamily && cidr.family !== typeFamily) {
      return miss(`规则类型 ${type} 只接受 IPv${typeFamily}，规则值是 IPv${cidr.family}`, 'IP CIDR')
    }
    if (cidr.family !== family) {
      return miss(`地址族不一致：输入是 IPv${family}，规则是 IPv${cidr.family}`, 'IP CIDR')
    }
    return cidrMatch(cidr, target.ip)
      ? match(`IP ${target.ip} 落在 ${value} 网段`, 'IP CIDR')
      : miss(`IP ${target.ip} 不在 ${value} 网段`, 'IP CIDR')
  }

  if (type === 'DST-PORT' || type === 'DEST-PORT') {
    const result = portMatches(target.port, value)
    if (result === undefined) return skip('输入没有端口，无法判断端口规则', '目标端口')
    return result ? match(`端口 ${target.port} 命中 ${value}`, '目标端口') : miss(`端口 ${target.port} 不在 ${value}`, '目标端口')
  }
  if (type === 'SRC-PORT' || type === 'IN-PORT' || type === 'SRC-PORT-RANGE') {
    return skip('浏览器无法得知源端口 / 入站端口', '源端口')
  }
  if (SOURCE_TYPES.has(type)) return skip('浏览器无法得知来源地址', '来源地址')
  if (type === 'NETWORK') {
    if (!target.url) return skip('输入不是 URL，无法判断 TCP/UDP 网络类型', '网络类型')
    if (/^http/i.test(target.url)) {
      return value.toLowerCase() === 'tcp'
        ? match('HTTP(S) 使用 TCP', '网络类型')
        : miss(`HTTP(S) 不走 ${value}`, '网络类型')
    }
    return unknown('无法从输入推断网络类型', '网络类型')
  }
  if (type === 'PROTOCOL') {
    if (!target.scheme) return skip('输入没有协议前缀（http/https），无法判断 PROTOCOL', '协议')
    return value.toLowerCase() === target.scheme
      ? match(`输入协议是 ${target.scheme}`, '协议')
      : miss(`输入协议不是 ${value}`, '协议')
  }
  if (type === 'URL-REGEX') {
    if (!target.url) return skip('输入不是 URL，无法执行 URL 正则', 'URL 正则')
    if (target.url.length > 4096) return unknown('URL 超过 4096 字符，已跳过正则匹配', 'URL 正则')
    if (riskyRegex(value)) return unknown(`正则过于复杂或可能造成灾难性回溯，已跳过：${value}`, 'URL 正则')
    const regex = cachedRegExp('regex', value)
    if (!regex) return unknown(`正则表达式无效：${value}`, 'URL 正则')
    return regex.test(target.url) ? match(`URL 命中正则 ${value}`, 'URL 正则') : miss(`URL 不匹配正则 ${value}`, 'URL 正则')
  }
  if (type === 'USER-AGENT' || type === 'USER-AGENT-REGEX') {
    return skip('解释器不知道客户端 User-Agent', 'User-Agent')
  }
  if (type.startsWith('PROCESS-')) {
    return skip('解释器不知道客户端进程名', '进程规则')
  }
  if (type === 'GEOSITE') return unknown(`需要 GeoSite 数据库，离线解释器无法判断 ${value}`, 'GEOSITE')

  return unknown(`解释器暂不支持 ${type || '未知'} 规则`, '未支持规则')
}

let chinaCache: ParsedCidr[] | null = null
function chinaCidrs(): ParsedCidr[] {
  if (!chinaCache) {
    chinaCache = CHINA_IP_CIDRS.map(parseCidr).filter((item): item is ParsedCidr => item !== null)
  }
  return chinaCache
}

export { DOMAIN_TYPES, IP_TYPES }
