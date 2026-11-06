// ACL4SSR INI scheme loading, following the standard subconverter format:
//   ruleset=组名,https://…/Clash/Ruleset/X.list   (or []GEOIP,CN / []FINAL)
//   custom_proxy_group=组名`类型`[]引用`正则`url`interval`,tolerance
// Bundled rule lists are inlined into per-group rules at load time.
import type { BuiltinSchemeOverrideRef, BuiltinSchemeSnapshot, PolicyGroup, PolicyGroupType, RoutingRule, RuleScheme, RuleSchemeFormat, RuleSchemeSource, RuleSetFormat } from '../models/types'
import { resolveBuiltinSchemeSnapshot, attachSnapshotRuleSets } from './schemeSnapshots'
import { apiFetch } from '../util/apiAuth'
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

export async function loadScheme(
  meta: SchemeMeta,
  overrides?: Record<string, BuiltinSchemeOverrideRef>,
  snapshots?: Record<string, BuiltinSchemeSnapshot>,
): Promise<RuleScheme> {
  // 覆盖层只存指针：解引用成功才用快照；缺失 / 损坏回落到上一版，再回落到原厂。
  // 原厂 `public/rulesets/*.ini` 永不改动，保证离线也能加载。
  const resolution = resolveBuiltinSchemeSnapshot(meta.id, overrides, snapshots)
  if (resolution.snapshot) {
    // 快照正文把列表规则内联在 scheme.rules 里；挂回只读规则集时用 inlined 标记，
    // 保证编译期不重复插入同一批规则，同时让规则页 / 诊断可以逐条屏蔽。
    return attachSnapshotRuleSets(
      { ...resolution.snapshot.scheme, id: meta.id, name: meta.name, description: meta.description },
      resolution.snapshot.ruleSets,
    )
  }
  // 内置方案由 /rulesets 下的静态文件组成；切换 Tab、编辑自定义方案后回到
  // 导出页都会重新调用这里。缓存 Promise 后，第二次起不再重复发起 20+ 个
  // 请求，也不再重复解析上万条规则。失败不缓存，方便用户重试。
  const key = `${meta.id}\u0000${meta.file}`
  const cached = schemeLoadCache.get(key)
  if (cached) return cached
  const promise = loadSchemeUncached(meta)
  schemeLoadCache.set(key, promise)
  void promise.catch(() => {
    if (schemeLoadCache.get(key) === promise) schemeLoadCache.delete(key)
  })
  return promise
}

const schemeLoadCache = new Map<string, Promise<RuleScheme>>()

async function loadSchemeUncached(meta: SchemeMeta): Promise<RuleScheme> {
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

export interface SubconverterRulesetReference {
  target: string
  format?: RuleSetFormat
  plainList?: 'domain' | 'ipcidr'
}

/** subconverter: ruleset=<group>,[<type>:]<url>[,<interval>]. */
export function subconverterRulesetReference(raw: string): SubconverterRulesetReference {
  let target = raw.trim()
  const lastComma = target.lastIndexOf(',')
  if (lastComma > 0 && /^\s*\d+\s*$/.test(target.slice(lastComma + 1))) {
    target = target.slice(0, lastComma).trim()
  }
  const prefix = target.match(/^(clash-domain|clash-ipcidr|clash-classic|quanx|surge):/i)
  if (!prefix) return { target }
  target = target.slice(prefix[0].length).trim()
  switch (prefix[1].toLowerCase()) {
    case 'clash-domain': return { target, plainList: 'domain' }
    case 'clash-ipcidr': return { target, plainList: 'ipcidr' }
    case 'clash-classic': return { target, format: 'classical' }
    case 'quanx': return { target, format: 'quanx' }
    case 'surge': return { target, format: 'classical' }
    default: return { target }
  }
}

/** Clash `behavior: domain` / `behavior: ipcidr` provider payloads. */
export function parsePlainRulesetText(
  text: string,
  kind: 'domain' | 'ipcidr',
): Omit<RoutingRule, 'group'>[] {
  const rules: Omit<RoutingRule, 'group'>[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#') || line.startsWith(';') || line === 'payload:') continue
    const value = (line.startsWith('- ') ? line.slice(2).trim() : line)
    if (!value) continue
    if (kind === 'domain') {
      const type = value.startsWith('+.') || value.startsWith('*.')
        ? 'DOMAIN-SUFFIX'
        : 'DOMAIN'
      const domain = value.replace(/^(\+\.|\*\.)/, '').replace(/^\./, '')
      const rule = parseInlineRule(`${type},${domain}`)
      if (rule) rules.push(rule)
    } else {
      if (!value.includes('/')) continue
      const rule = parseInlineRule(`${value.includes(':') ? 'IP-CIDR6' : 'IP-CIDR'},${value},no-resolve`)
      if (rule) rules.push(rule)
    }
  }
  return rules
}

/** Parse raw ACL4SSR INI text (same format as bundled files) into groups + rules.
 *  Used for both bundled schemes (through loadScheme) and user-imported custom schemes.
 *  Remote ruleset URLs are fetched through /api/fetch proxy so the browser's CORS does not block. */
export interface SchemeINIParts {
  groups: PolicyGroup[]
  /** 按出现顺序排列的 `ruleset=组,目标` 引用（不含 `[]` 内联规则）。 */
  rulesets: { group: string; target: string }[]
  /** `ruleset=组,[]规则` 形式的内联规则。 */
  inlineRules: { group: string; rule: string }[]
}

/** 只做语法拆分，不抓取任何规则集；内置加载与上游更新共用这一份解析。 */
export function parseSchemeINIParts(ini: string): SchemeINIParts {
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
  return { groups, rulesets, inlineRules }
}

export async function parseSchemeINI(
  id: string,
  name: string,
  description: string,
  ini: string,
): Promise<RuleScheme> {
  const { groups, rulesets, inlineRules } = parseSchemeINIParts(ini)

  // Fetch remote rulesets in parallel. Bundled files are looked up via index.json,
  // unknown remote URLs go through /api/fetch proxy (same origin).
  const localIndex = await rulesetIndex().catch(() => ({} as Record<string, string>))
  const urlFetch = async (url: string): Promise<string> => {
    try {
      const res = await apiFetch(`/api/fetch?url=${encodeURIComponent(url)}`)
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
  const textCache = new Map<string, Promise<string>>()
  const fetchOnce = (key: string, load: () => Promise<string>): Promise<string> => {
    const cached = textCache.get(key)
    if (cached) return cached
    const request = load()
    textCache.set(key, request)
    return request
  }
  // 同一方案里可能引用几十个列表；逐个 await 会让导入耗时随列表数线性增长。
  // 先按唯一 URL / 文件并行抓取，再按原顺序合并，保持规则分组语义不变。
  const loaded = await Promise.all(rulesets.map(async (rs) => {
    const reference = subconverterRulesetReference(rs.target)
    const local = localFileForURL(reference.target, localIndex)
    const text = local
      ? await fetchOnce(`file:${local}`, () => fileFetch(local))
      : /^https?:\/\//i.test(reference.target)
        ? await fetchOnce(`url:${reference.target}`, () => urlFetch(reference.target))
        : ''
    if (!text.trim()) return { group: rs.group, rules: [] as Omit<RoutingRule, 'group'>[] }

    let parsed: Omit<RoutingRule, 'group'>[] = []
    const looksStructured = text.trim().startsWith('{') || /^\s*(payload:|proxies:|rules:)/m.test(text)
    if (reference.plainList && !looksStructured) {
      parsed = parsePlainRulesetText(text, reference.plainList)
    } else {
      try {
        // Dynamic import avoids a static cycle: ruleSets.ts imports helpers from
        // this module for its classical parser.
        const { parseRuleSetText } = await import('./ruleSets')
        parsed = parseRuleSetText(text, reference.format).rules
      } catch {
        parsed = parseRuleList(text)
      }
    }
    return { group: rs.group, rules: parsed }
  }))
  for (const { group, rules: parsed } of loaded) {
    if (!parsed.length) continue
    rulesByGroup.set(group, [...(rulesByGroup.get(group) ?? []), ...parsed])
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
