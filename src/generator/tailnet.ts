// Tailnets are added to a finished complete profile, after the normal
// generators have produced text. This mirrors the iOS writer so built-in
// presets and imported schemes get identical output from one place.
import { CLIENTS, type ClientTarget, type ExportContentMode, type TailnetConnection, type TailnetExport } from '../models/types'
import { isIPv6CIDR, tailnetHostname, tailnetPolicyName, tailnetStableSlug, TAILNET_IPV4_RANGE, TAILNET_IPV6_RANGE } from '../models/tailnet'
import { yaml } from './naming'

export type TailnetFlavor = 'surge' | 'stash' | 'mihomo' | 'singBox'

interface TailnetProfile {
  flavor: TailnetFlavor
  targetName: string
  clientSlug: string
}

export function tailnetFlavor(target: ClientTarget): TailnetFlavor | undefined {
  switch (target) {
    case 'surge':
    case 'surge-mac':
      return 'surge'
    case 'clash':
      return 'stash'
    case 'clash-apple':
    case 'clash-verge':
    case 'clashmac':
    case 'flclash':
    case 'mihomo-party':
    case 'clash-mi':
      return 'mihomo'
    case 'sing-box':
      return 'singBox'
    default:
      return undefined
  }
}

export function tailnetSupports(target: ClientTarget): boolean {
  return tailnetFlavor(target) !== undefined
}

function clientName(target: ClientTarget): string {
  return CLIENTS.find((client) => client.target === target)?.name ?? target
}

function profileFor(target: ClientTarget): TailnetProfile | undefined {
  const flavor = tailnetFlavor(target)
  if (!flavor) return undefined
  return { flavor, targetName: clientName(target), clientSlug: target === 'clash' ? 'stash' : target }
}

/** Published formats are shared by several clients; use a neutral profile. */
function profileForFormat(format: 'yaml' | 'surge' | 'json'): TailnetProfile {
  if (format === 'surge') return { flavor: 'surge', targetName: 'Surge', clientSlug: 'surge' }
  if (format === 'json') return { flavor: 'singBox', targetName: 'sing-box', clientSlug: 'sing-box' }
  return { flavor: 'mihomo', targetName: 'Clash / mihomo', clientSlug: 'yaml' }
}

interface TailnetApplication {
  text: string
  notes: string[]
}

function routes(connection: TailnetConnection): { domains: string[]; ipv4: string[]; ipv6: string[] } {
  return {
    domains: connection.magicDNSSuffix ? [connection.magicDNSSuffix] : [],
    ipv4: [TAILNET_IPV4_RANGE, ...connection.subnets.filter((subnet) => !isIPv6CIDR(subnet))],
    ipv6: [TAILNET_IPV6_RANGE, ...connection.subnets.filter(isIPv6CIDR)],
  }
}

function ruleLines(connection: TailnetConnection, name: string): string[] {
  const route = routes(connection)
  return [
    ...route.domains.map((domain) => `DOMAIN-SUFFIX,${domain},${name}`),
    ...route.ipv4.map((cidr) => `IP-CIDR,${cidr},${name},no-resolve`),
    ...route.ipv6.map((cidr) => `IP-CIDR6,${cidr},${name},no-resolve`),
  ]
}

function uniqueName(base: string, taken: Set<string>): string {
  let candidate = base
  let counter = 2
  while (taken.has(candidate)) {
    candidate = `${base} ${counter}`
    counter += 1
  }
  taken.add(candidate)
  return candidate
}

function stashNote(exportItem: TailnetExport, name: string, targetName: string): string {
  const suffix = exportItem.connection.magicDNSSuffix
  if (!suffix) {
    return `“${name}”没有填 MagicDNS 后缀：${targetName} 默认跳过 Tailscale 地址段，只能通过设备名访问，请在内网设置里填写后缀。`
  }
  return `Stash 默认跳过 Tailscale 地址段和局域网网段：请用“设备名.${suffix}”访问“${name}”；按 IP 或访问家里子网，需要先在 Stash 的跳过代理和跳过路由中移除对应网段。`
}

function tailnetNotes(profile: TailnetProfile, exportItem: TailnetExport, name: string): string[] {
  if (profile.flavor === 'surge') return []
  const notes: string[] = []
  if (!exportItem.authKey) {
    notes.push(`“${name}”没有 Auth Key：${profile.targetName} 暂时不能在客户端里登录 Tailscale，请在「内网」页填写 Auth Key。`)
  }
  if (profile.flavor === 'stash') notes.push(stashNote(exportItem, name, profile.targetName))
  return notes
}

function surgeText(text: string, exportItem: TailnetExport, name: string, hostname: string): string {
  const connection = exportItem.connection
  const lines = text.split('\n')
  const policy = `${name} = tailscale, section-name=${tailnetStableSlug(connection)}`
  const proxyIndex = lines.findIndex((line) => line === '[Proxy]')
  if (proxyIndex >= 0) {
    lines.splice(proxyIndex + 1, 0, policy)
  } else {
    const anchor = lines.findIndex((line) => line === '[Proxy Group]' || line === '[Rule]')
    if (anchor >= 0) lines.splice(anchor, 0, '[Proxy]', policy, '')
    else lines.push('[Proxy]', policy, '')
  }
  const rules = ruleLines(connection, name)
  const ruleIndex = lines.findIndex((line) => line === '[Rule]')
  if (ruleIndex >= 0) lines.splice(ruleIndex + 1, 0, ...rules)
  else lines.push('', '[Rule]', ...rules)
  const section = ['', `[Tailscale ${tailnetStableSlug(connection)}]`, 'interactive-login = true']
  if (connection.controlURLString) section.push(`control-url = ${connection.controlURLString}`)
  section.push(`hostname = ${hostname}`)
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()
  return [...lines, ...section].join('\n') + '\n'
}

function insertYamlEntry(lines: string[], entry: string[]): void {
  const proxyIndex = lines.findIndex((line) => line === 'proxies:' || line === 'proxies: []')
  if (proxyIndex >= 0) {
    if (lines[proxyIndex] === 'proxies: []') {
      lines.splice(proxyIndex, 1, 'proxies:', ...entry)
    } else {
      let next = proxyIndex + 1
      while (next < lines.length && lines[next].trim() === '') next += 1
      if (lines[next]?.trim() === '[]') {
        lines.splice(next, 1, ...entry)
      } else {
        lines.splice(proxyIndex + 1, 0, ...entry)
      }
    }
    return
  }
  const anchor = lines.findIndex((line) => line === 'proxy-groups:' || line === 'rules:' || line === 'proxy-providers:')
  if (anchor >= 0) lines.splice(anchor, 0, 'proxies:', ...entry, '')
  else lines.push('proxies:', ...entry)
}

function clashText(
  text: string,
  exportItem: TailnetExport,
  name: string,
  hostname: string,
  flavor: 'stash' | 'mihomo',
): string {
  const connection = exportItem.connection
  const lines = text.split('\n')
  const entry = [
    `  - name: ${yaml(name)}`,
    '    type: tailscale',
  ]
  if (exportItem.authKey) entry.push(`    auth-key: ${yaml(exportItem.authKey)}`)
  if (connection.controlURLString) entry.push(`    control-url: ${yaml(connection.controlURLString)}`)
  entry.push(`    hostname: ${yaml(hostname)}`)
  if (flavor === 'mihomo') {
    entry.push(`    state-dir: ${yaml(tailnetStableSlug(connection))}`)
    entry.push('    udp: true')
    entry.push('    accept-routes: true')
  }
  insertYamlEntry(lines, entry)

  const rules = ruleLines(connection, name)
  const ruleIndex = lines.findIndex((line) => line === 'rules:')
  if (ruleIndex >= 0) lines.splice(ruleIndex + 1, 0, ...rules.map((rule) => `  - ${yaml(rule)}`))
  else lines.push('rules:', ...rules.map((rule) => `  - ${yaml(rule)}`))
  return lines.join('\n')
}

function singBoxText(text: string, exportItem: TailnetExport, name: string, hostname: string): string | undefined {
  let root: Record<string, unknown>
  try {
    root = JSON.parse(text) as Record<string, unknown>
  } catch {
    return undefined
  }
  const connection = exportItem.connection
  const endpoint: Record<string, unknown> = {
    type: 'tailscale',
    tag: name,
    state_directory: tailnetStableSlug(connection),
    hostname,
    accept_routes: true,
  }
  if (exportItem.authKey) endpoint.auth_key = exportItem.authKey
  if (connection.controlURLString) endpoint.control_url = connection.controlURLString
  const endpoints = Array.isArray(root.endpoints) ? root.endpoints as Record<string, unknown>[] : []
  root.endpoints = [...endpoints, endpoint]

  const route = routes(connection)
  if (route.domains.length > 0) {
    const dns = root.dns && typeof root.dns === 'object' && !Array.isArray(root.dns)
      ? root.dns as Record<string, unknown>
      : {}
    const servers = Array.isArray(dns.servers) ? dns.servers as Record<string, unknown>[] : []
    const serverTag = `${name} DNS`
    dns.servers = [...servers, { type: 'tailscale', tag: serverTag, endpoint: name }]
    const dnsRules = Array.isArray(dns.rules) ? dns.rules as Record<string, unknown>[] : []
    dns.rules = [{ action: 'route', domain_suffix: route.domains, server: serverTag }, ...dnsRules]
    root.dns = dns
  }

  const routing = root.route && typeof root.route === 'object' && !Array.isArray(root.route)
    ? root.route as Record<string, unknown>
    : {}
  const rules = Array.isArray(routing.rules) ? routing.rules as Record<string, unknown>[] : []
  const tailnetRule: Record<string, unknown> = {
    action: 'route',
    ip_cidr: [...route.ipv4, ...route.ipv6],
    outbound: name,
    ...(route.domains.length > 0 ? { domain_suffix: route.domains } : {}),
  }
  const position = rules.findIndex((item) => {
    const action = item.action
    return action !== 'sniff' && action !== 'hijack-dns'
  })
  rules.splice(position >= 0 ? position : rules.length, 0, tailnetRule)
  routing.rules = rules
  root.route = routing
  // JSON object order does not affect sing-box, but putting endpoints first
  // keeps the Tailscale block inside the truncated config preview.
  const ordered = { endpoints: root.endpoints, ...root }
  return JSON.stringify(ordered, null, 2) + '\n'
}

function existingNames(text: string, flavor: TailnetFlavor): Set<string> {
  const names = new Set<string>(['DIRECT', 'REJECT', 'direct', 'reject'])
  if (flavor === 'surge') {
    let inPolicySection = false
    for (const line of text.split('\n')) {
      if (line.startsWith('[')) {
        inPolicySection = line === '[Proxy]' || line === '[Proxy Group]'
      } else if (inPolicySection) {
        const separator = line.indexOf(' = ')
        if (separator >= 0) names.add(line.slice(0, separator).trim())
      }
    }
    return names
  }
  if (flavor === 'stash' || flavor === 'mihomo') {
    for (const line of text.split('\n')) {
      const trimmed = line.trim()
      if (!trimmed.startsWith('- name: ')) continue
      let value = trimmed.slice('- name: '.length)
      if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
        value = value.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\')
      } else if (value.startsWith("'") && value.endsWith("'") && value.length >= 2) {
        value = value.slice(1, -1)
      }
      names.add(value)
    }
    return names
  }
  try {
    const root = JSON.parse(text) as Record<string, unknown>
    for (const key of ['outbounds', 'endpoints']) {
      const items = Array.isArray(root[key]) ? root[key] as Record<string, unknown>[] : []
      for (const item of items) {
        if (typeof item.tag === 'string') names.add(item.tag)
      }
    }
  } catch {
    // A malformed JSON profile is left alone below.
  }
  return names
}

function applyWithProfile(
  text: string,
  profile: TailnetProfile,
  exports: TailnetExport[],
): TailnetApplication {
  if (!text.trim() || exports.length === 0) return { text, notes: [] }
  const taken = existingNames(text, profile.flavor)
  let content = text
  const notes: string[] = []
  for (const exportItem of exports) {
    const name = uniqueName(tailnetPolicyName(exportItem.connection), taken)
    const hostname = tailnetHostname(exportItem.connection, profile.clientSlug)
    switch (profile.flavor) {
      case 'surge':
        content = surgeText(content, exportItem, name, hostname)
        break
      case 'stash':
      case 'mihomo':
        content = clashText(content, exportItem, name, hostname, profile.flavor)
        break
      case 'singBox': {
        const next = singBoxText(content, exportItem, name, hostname)
        if (next === undefined) notes.push(`“${name}”未能写入 ${profile.targetName}：配置 JSON 解析失败。`)
        else content = next
        break
      }
    }
    notes.push(...tailnetNotes(profile, exportItem, name))
  }
  return { text: content, notes }
}

/** Apply enabled tailnets to one client's complete profile. */
export function applyTailnets(
  text: string,
  target: ClientTarget,
  contentMode: ExportContentMode,
  exports: TailnetExport[],
): TailnetApplication {
  if (contentMode === 'nodes') return { text, notes: [] }
  const enabled = exports.filter((item) => item.connection.isEnabled)
  if (enabled.length === 0) return { text, notes: [] }
  const profile = profileFor(target)
  if (!profile) {
    // Node-list clients do not have a place for a tailnet, so silence is right.
    if (target === 'v2box' || target === 'anywhere') return { text, notes: [] }
    const names = enabled.map((item) => tailnetPolicyName(item.connection)).join('、')
    return {
      text,
      notes: [`“${names}”不会写入 ${clientName(target)}：它不支持 Tailscale。`],
    }
  }
  return applyWithProfile(text, profile, enabled)
}

/** Published formats are shared; the target-specific exceptions are added by the app. */
export function applyTailnetsForFormat(
  text: string,
  format: 'yaml' | 'surge' | 'json',
  contentMode: ExportContentMode,
  exports: TailnetExport[],
): string {
  if (contentMode === 'nodes') return text
  const enabled = exports.filter((item) => item.connection.isEnabled)
  if (enabled.length === 0) return text
  return applyWithProfile(text, profileForFormat(format), enabled).text
}

/** Preview shows the same-length bullets; copy/download still get the real key. */
export function maskTailnetAuthKeys(text: string, keys: (string | undefined)[]): string {
  let masked = text
  const values = [...new Set(keys.filter((key): key is string => !!key && key.length > 0))]
    .sort((a, b) => b.length - a.length)
  for (const key of values) masked = masked.split(key).join('•'.repeat(key.length))
  return masked
}
