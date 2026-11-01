// ACL4SSR INI scheme loading, following the standard subconverter format:
//   ruleset=组名,https://…/Clash/Ruleset/X.list   (or []GEOIP,CN / []FINAL)
//   custom_proxy_group=组名`类型`[]引用`正则`url`interval`,tolerance
// Bundled rule lists are inlined into per-group rules at load time.
import type { PolicyGroup, PolicyGroupType, RoutingRule, RuleScheme, RuleSchemeFormat, RuleSchemeSource } from '../models/types'
import { ALL_RULE_TYPES } from './capabilities'

export interface SchemeMeta {
  id: string
  name: string
  description: string
  file: string
  sourceKind?: RuleSchemeSource
  sourceFormat?: RuleSchemeFormat
  sourceURL?: string
  updatedAt?: number
}

export const BUILTIN_SCHEMES: SchemeMeta[] = [
  {
    id: 'acl4ssr-online',
    name: 'ACL4SSR 在线版',
    description: '去广告 + 自动测速 + 微软/苹果分流，规则较全',
    file: 'ACL4SSR_Online.ini',
  },
  {
    id: 'acl4ssr-mini',
    name: 'ACL4SSR 精简版',
    description: '去广告 + 自动测速，分组最少',
    file: 'ACL4SSR_Online_Mini.ini',
  },
  {
    id: 'acl4ssr-full',
    name: 'ACL4SSR 全分组版',
    description: '全部媒体/厂商分组，适合精细分流',
    file: 'ACL4SSR_Online_Full.ini',
  },
]

/** Full list of scheme metas (builtin + custom). */
export function allSchemeMetas(customSchemes: RuleScheme[]): Array<SchemeMeta | SchemeMeta & { custom: true }> {
  return [
    ...BUILTIN_SCHEMES,
    ...customSchemes.map((s) => ({
      id: s.id,
      name: s.name,
      description: s.description ?? '自定义规则方案',
      file: s.id,
      sourceKind: s.sourceKind,
      sourceFormat: s.sourceFormat,
      sourceURL: s.sourceURL,
      updatedAt: s.updatedAt,
      custom: true as const,
    })),
  ]
}

interface RawRuleset {
  group: string
  /** Local file name under /rulesets/, or inline like `GEOIP,CN`. */
  file?: string
  inline?: string
}

let indexPromise: Promise<Record<string, string>> | undefined
function rulesetIndex(): Promise<Record<string, string>> {
  indexPromise ??= fetch('/rulesets/index.json')
    .then((r) => {
      if (!r.ok) throw new Error(`规则索引加载失败：HTTP ${r.status}`)
      return r.json()
    })
    .catch((err) => {
      // 失败后不要永久缓存 rejected promise，重新选择方案时还能再试。
      indexPromise = undefined
      throw err
    })
  return indexPromise
}

/** Map an upstream ACL4SSR URL to the bundled local file name. */
function localFileForURL(url: string, index: Record<string, string>): string | undefined {
  const marker = url.indexOf('/Clash/')
  if (marker < 0) return undefined
  const path = url.slice(marker + 1) // Clash/…
  return index[path]
}

export async function loadScheme(meta: SchemeMeta): Promise<RuleScheme> {
  const [ini, index] = await Promise.all([
    fetch(`/rulesets/${meta.file}`).then((r) => {
      if (!r.ok) throw new Error(`规则方案加载失败：HTTP ${r.status}`)
      return r.text()
    }),
    rulesetIndex(),
  ])

  const groups: PolicyGroup[] = []
  const rulesets: RawRuleset[] = []
  const inlineRules: { group: string; rule: string }[] = []

  for (const rawLine of ini.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith(';') || line.startsWith('#') || line.startsWith('[')) continue

    if (line.startsWith('ruleset=')) {
      const body = line.slice('ruleset='.length)
      const comma = body.indexOf(',')
      if (comma < 0) continue
      const group = body.slice(0, comma).trim()
      const target = body.slice(comma + 1).trim()
      if (target.startsWith('[]')) {
        inlineRules.push({ group, rule: target.slice(2) })
      } else {
        const file = localFileForURL(target, index)
        if (file) rulesets.push({ group, file })
        // Unknown remote lists are skipped: the bundled snapshot is the
        // offline source of truth and never fetched at runtime.
      }
      continue
    }

    if (line.startsWith('custom_proxy_group=')) {
      const group = parseProxyGroup(line.slice('custom_proxy_group='.length))
      if (group) groups.push(group)
    }
  }

  // Load referenced lists in parallel and inline them into per-group rules.
  const uniqueFiles = [...new Set(rulesets.map((r) => r.file!))]
  const contents = new Map<string, Omit<RoutingRule, 'group'>[]>()
  await Promise.all(
    uniqueFiles.map(async (file) => {
      const text = await fetch(`/rulesets/${file}`).then((r) => (r.ok ? r.text() : ''))
      contents.set(file, parseRuleList(text))
    }),
  )

  const rules: RoutingRule[] = []
  for (const rs of rulesets) {
    for (const rule of contents.get(rs.file!) ?? []) {
      rules.push({ ...rule, group: rs.group })
    }
  }
  for (const { group, rule } of inlineRules) {
    const parsed = parseInlineRule(rule)
    if (parsed) rules.push({ ...parsed, group })
  }

  // A group with no rules and no regex still earns its place (e.g. 节点选择).
  return { id: meta.id, name: meta.name, description: meta.description, groups, rules }
}

/** Parse raw ACL4SSR INI text (same format as bundled files) into groups + rules.
 *  Used for both bundled schemes (through loadScheme) and user-imported custom schemes.
 *  Remote ruleset URLs are fetched through /api/fetch proxy so the browser's CORS does not block. */
export async function parseSchemeINI(
  id: string,
  name: string,
  description: string,
  ini: string,
): Promise<RuleScheme> {
  const rulesets: { group: string; target: string }[] = []
  const groups: PolicyGroup[] = []
  const inlineRules: { group: string; rule: string }[] = []

  for (const rawLine of ini.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith(';') || line.startsWith('#') || line.startsWith('[')) continue
    if (line.startsWith('ruleset=')) {
      const body = line.slice('ruleset='.length)
      const comma = body.indexOf(',')
      if (comma < 0) continue
      const group = body.slice(0, comma).trim()
      const target = body.slice(comma + 1).trim()
      if (target.startsWith('[]')) {
        inlineRules.push({ group, rule: target.slice(2) })
      } else {
        rulesets.push({ group, target })
      }
      continue
    }
    if (line.startsWith('custom_proxy_group=')) {
      const g = parseProxyGroup(line.slice('custom_proxy_group='.length))
      if (g) groups.push(g)
    }
  }

  // Fetch remote rulesets in parallel. Bundled files are looked up via index.json,
  // unknown remote URLs go through /api/fetch proxy (same origin).
  const localIndex = await rulesetIndex().catch(() => ({} as Record<string, string>))
  const urlFetch = async (url: string): Promise<string> => {
    try {
      const res = await fetch(`/api/fetch?url=${encodeURIComponent(url)}`)
      if (!res.ok) return ''
      return await res.text()
    } catch { return '' }
  }
  const fileFetch = async (file: string): Promise<string> => {
    try {
      const res = await fetch(`/rulesets/${file}`)
      return res.ok ? res.text() : ''
    } catch { return '' }
  }

  const rulesByGroup = new Map<string, Omit<RoutingRule, 'group'>[]>()
  for (const rs of rulesets) {
    let text = ''
    const local = localFileForURL(rs.target, localIndex)
    if (local) text = await fileFetch(local)
    else if (/^https?:\/\//i.test(rs.target)) text = await urlFetch(rs.target)
    else if (rs.target.startsWith('[]')) {
      const parsed = parseInlineRule(rs.target.slice(2))
      if (parsed) rulesByGroup.set(rs.group, [...(rulesByGroup.get(rs.group) ?? []), parsed])
      continue
    }
    const parsed = parseRuleList(text)
    if (parsed.length) rulesByGroup.set(rs.group, [...(rulesByGroup.get(rs.group) ?? []), ...parsed])
  }

  const rules: RoutingRule[] = []
  for (const [group, list] of rulesByGroup) for (const r of list) rules.push({ ...r, group })
  for (const { group, rule } of inlineRules) {
    const parsed = parseInlineRule(rule)
    if (parsed) rules.push({ ...parsed, group })
  }

  return { id, name, description, groups, rules }
}

/** `名称`select`[]A`[]DIRECT`正则  or  名称`url-test`正则`url`interval`,,tolerance` */
function parseProxyGroup(body: string): PolicyGroup | undefined {
  const parts = body.split('`').map((p) => p.trim())
  if (parts.length < 2) return undefined
  const name = parts[0]
  const type = parts[1].toLowerCase() as PolicyGroupType
  if (!name || !['select', 'url-test', 'smart', 'fallback', 'load-balance', 'conditional', 'relay'].includes(type)) return undefined

  const options: string[] = []
  let nodeFilter: string | undefined
  let url: string | undefined
  let interval: number | undefined
  let tolerance: number | undefined

  for (const part of parts.slice(2)) {
    if (!part) continue
    if (part.startsWith('[]')) {
      options.push(part.slice(2))
    } else if (/^https?:\/\//.test(part)) {
      url = part
    } else if (/^\d+(,\d*)*$/.test(part)) {
      // `300,,50` → interval 300, tolerance 50
      const nums = part.split(',').filter(Boolean).map(Number)
      interval = nums[0]
      if (nums.length > 1) tolerance = nums[nums.length - 1]
    } else {
      // Bare regex filters nodes into this group (`.+`, `(香港|HK)` …).
      nodeFilter = part
    }
  }
  return { name, type, options, nodeFilter, url, interval, tolerance }
}

/**
 * ACL4SSR .list files: Clash classical rules, one per line
 * (`DOMAIN-SUFFIX,x.com`), occasionally YAML payload form.
 */
export function parseRuleList(text: string): Omit<RoutingRule, 'group'>[] {
  const rules: Omit<RoutingRule, 'group'>[] = []
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#') || line === 'payload:') continue
    const body = line.startsWith('- ') ? line.slice(2).trim() : line
    const rule = parseInlineRule(body)
    if (rule) rules.push(rule)
  }
  return rules
}

/** 按顶层逗号拆规则，保留括号内的逻辑规则和引号里的逗号。 */
export function splitRuleFields(body: string): string[] {
  const fields: string[] = []
  let current = ''
  let quote: string | undefined
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

/** 去掉字段两侧的引号；Surge / Clash 的规则值允许用引号包住逗号。 */
function unquotedField(value: string): string {
  const trimmed = value.trim()
  if (trimmed.length >= 2 && (trimmed[0] === '"' || trimmed[0] === "'") && trimmed[trimmed.length - 1] === trimmed[0]) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

/**
 * 已经按顶层逗号拆好的规则字段 → 规则。
 * 导入其他客户端配置时先拆一次，避免带逗号的引号值被二次拆分。
 */
export function inlineRuleFromFields(fields: string[]): Omit<RoutingRule, 'group'> | undefined {
  const type = fields[0]?.toUpperCase()
  if (!type || !ALL_RULE_TYPES.has(type)) return undefined
  if (type === 'FINAL' || type === 'MATCH') return { type: 'FINAL' }

  // 逻辑规则保留原始条件；各客户端生成器自己决定是否写回。
  if (type === 'AND' || type === 'OR' || type === 'NOT') {
    return { type, raw: fields.slice(0, 2).join(','), noResolve: false }
  }

  const value = unquotedField(fields[1] ?? '')
  if (!value) return undefined
  const options = fields.slice(2).filter(Boolean).map(unquotedField)
  const ipType = ['IP-CIDR', 'IP-CIDR6', 'IP-SUFFIX', 'IP-ASN', 'GEOIP'].includes(type)
  return {
    type,
    value,
    options: options.length ? options : undefined,
    noResolve: options.some((option) => option.toLowerCase() === 'no-resolve') || ipType,
  }
}

/** `DOMAIN-SUFFIX,x.com` / `IP-CIDR,1.2.3.0/24,no-resolve` / `AND,((…),(…))` / `FINAL` */
export function parseInlineRule(body: string): Omit<RoutingRule, 'group'> | undefined {
  return inlineRuleFromFields(splitRuleFields(body))
}

/** Policy group names referenced by any rule but never declared. */
export function undeclaredGroups(scheme: RuleScheme): string[] {
  const declared = new Set(scheme.groups.map((g) => g.name))
  const missing = new Set<string>()
  for (const rule of scheme.rules) {
    if (!missing.has(rule.group) && !declared.has(rule.group)) missing.add(rule.group)
  }
  return [...missing]
}
