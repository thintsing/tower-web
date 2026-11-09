// 自检：非 Clash 客户端的订阅产物是否能被对应内核真正吃下。
// 用法：npx tsx scripts/selfcheck-clients.ts
// 产物写到 .tmp-clash4/，可再喂给 sing-box check / 客户端做导入验证。
import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { generateBase64Subscription } from '../src/generator/base64Sub'
import { generateConfig, generateSubscriptionFormats } from '../src/generator'
import { SURGE_UPDATE_INTERVAL } from '../src/generator/surge'
import { compileRuleLine, prepareSchemeForExport } from '../src/generator/groups'
import { yaml as yamlScalar, yamlMultiline } from '../src/generator/naming'
import { CLIENTS, clientSupportsImport, type ClientTarget, type ProxyNode, type RuleScheme } from '../src/models/types'

const base = { tls: false, skipCertificateVerification: false } as const

/** 每个客户端都应该能吃下的常见协议，用来验证「不只是 SSR 才出错」。 */
const SAMPLE: ProxyNode[] = [
  { ...base, id: 'ss1', kind: 'ss', name: '样例 SS 香港', server: 'ss.example.com', port: 8388, cipher: 'aes-256-gcm', password: 'p1' },
  { ...base, id: 'vm1', kind: 'vmess', name: '样例 VMess 日本', server: 'vm.example.com', port: 443, uuid: '11111111-2222-3333-4444-555555555555', alterID: 0, cipher: 'auto', tls: true, sni: 'vm.example.com', transport: 'ws', path: '/ws', hostHeader: 'vm.example.com' },
  { ...base, id: 'tr1', kind: 'trojan', name: '样例 Trojan 新加坡', server: 'tr.example.com', port: 443, password: 'p2', tls: true, sni: 'tr.example.com' },
  { ...base, id: 'hy1', kind: 'hysteria2', name: '样例 HY2 美国', server: 'hy.example.com', port: 8443, password: 'p3', tls: true, sni: 'hy.example.com' },
]

const scheme: RuleScheme = {
  id: 'selfcheck',
  name: 'selfcheck',
  description: '',
  groups: [
    { name: '🚀 节点选择', type: 'select', options: ['DIRECT', '♻️ 自动选择'], nodeFilter: '.*' },
    { name: '♻️ 自动选择', type: 'url-test', options: [], nodeFilter: '.*' },
  ],
  rules: [
    { type: 'DOMAIN-SUFFIX', value: 'google.com', group: '🚀 节点选择' } as any,
    { type: 'DOMAIN-REGEX', value: '^foo\\.example$', group: '🚀 节点选择' } as any,
    { type: 'PROCESS-NAME', value: 'curl', group: '🚀 节点选择' } as any,
    { type: 'AND', raw: 'AND,((DOMAIN,foo.example),(NETWORK,udp))', group: '🚀 节点选择' } as any,
    { type: 'GEOIP', value: 'CN', group: 'DIRECT' } as any,
    { type: 'FINAL', group: '🚀 节点选择' } as any,
  ],
  networkSettings: {
    ipv6Enabled: false,
    dnsServers: ['10.0.0.1', '10.0.0.2'],
    encryptedDNSServers: ['https://dns.example/dns-query'],
    remoteDNSServers: ['https://8.8.4.4/dns-query'],
    proxyTestURLString: 'https://probe.example/204',
    dnsProtectionMode: 'strict',
  },
}

const outDir = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp-clash4')
mkdirSync(outDir, { recursive: true })

const client = (target: ClientTarget) =>
  CLIENTS.find((item) => item.target === target)!
const singbox = generateConfig(client('sing-box'), SAMPLE, scheme, { contentMode: 'full' })
const surge = generateConfig(client('surge'), SAMPLE, scheme, { contentMode: 'full' })
const loon = generateConfig(client('loon'), SAMPLE, scheme, { contentMode: 'full' })
const quanx = generateConfig(client('quanx'), SAMPLE, scheme, { contentMode: 'full' })
const b64 = generateBase64Subscription(SAMPLE)
const v2box = generateConfig(client('v2box'), SAMPLE, scheme, { contentMode: 'nodes' })
const anywhere = generateConfig(client('anywhere'), SAMPLE, scheme, { contentMode: 'nodes' })
const egern = generateConfig(client('egern'), SAMPLE, scheme, { contentMode: 'full' })
const shadowrocket = generateConfig(client('shadowrocket'), SAMPLE, scheme, { contentMode: 'full' })
const clashVerge = generateConfig(client('clash-verge'), SAMPLE, scheme, { contentMode: 'full' })
const surgeNodes = generateConfig(client('surge'), SAMPLE, scheme, { contentMode: 'nodes' })
const loonNodes = generateConfig(client('loon'), SAMPLE, scheme, { contentMode: 'nodes' })
const quanxNodes = generateConfig(client('quanx'), SAMPLE, scheme, { contentMode: 'nodes' })
const clashNodes = generateConfig(client('clash-verge'), SAMPLE, scheme, { contentMode: 'nodes' })
const shadowrocketNodes = generateConfig(client('shadowrocket'), SAMPLE, scheme, { contentMode: 'nodes' })
const hiddify = generateConfig(client('hiddify'), SAMPLE, scheme, { contentMode: 'full' })
const generic = generateSubscriptionFormats(SAMPLE, {
  ...scheme,
  rules: [
    ...scheme.rules,
    { type: 'DOMAIN-REGEX', value: '^unsupported\\.example$', group: '🚀 节点选择' },
    { type: 'URL-REGEX', value: '^https://unsupported.example/', group: '🚀 节点选择' },
    { type: 'PROCESS-NAME', value: 'unsupported-process', group: '🚀 节点选择' },
  ],
}, { contentMode: 'full' })

// 条件组只在 Surge subnet / Egern conditional 中原样保留；其他客户端退回默认策略。
const CONDITIONAL: RuleScheme = {
  id: 'conditional',
  name: 'conditional',
  description: '',
  groups: [
    {
      name: '节点选择',
      type: 'select',
      options: ['DIRECT'],
      nodeFilter: '.*',
      parameters: { timeout: '10', 'no-alert': 'true' },
    },
    {
      name: '网络',
      type: 'conditional',
      options: [],
      parameters: {
        'subnet-fields': JSON.stringify(['default=节点选择', 'Wi-Fi=节点选择']),
      },
    },
    {
      name: 'SSID 网络',
      type: 'conditional',
      options: [],
      parameters: {
        rules: JSON.stringify([{ ssid: { match: 'Home', policy: '节点选择' } }]),
        default_policy: '节点选择',
      },
    },
  ],
  rules: [{ type: 'FINAL', group: '节点选择' }],
  networkSettings: scheme.networkSettings,
}
const conditionalSurge = generateConfig(
  client('surge'),
  SAMPLE,
  prepareSchemeForExport(CONDITIONAL, {}, { format: 'surge', target: 'surge' }),
  { contentMode: 'full' },
)
const conditionalEgern = generateConfig(
  client('egern'),
  SAMPLE,
  prepareSchemeForExport(CONDITIONAL, {}, { format: 'egern', target: 'egern' }),
  { contentMode: 'full' },
)
const conditionalClash = generateConfig(
  client('clash-verge'),
  SAMPLE,
  prepareSchemeForExport(CONDITIONAL, {}, { format: 'yaml', target: 'clash-verge' }),
  { contentMode: 'full' },
)

writeFileSync(join(outDir, 'sample.json'), singbox.text, 'utf8')
writeFileSync(join(outDir, 'sample.surge.conf'), surge.text, 'utf8')
writeFileSync(join(outDir, 'sample.loon.conf'), loon.text, 'utf8')
writeFileSync(join(outDir, 'sample.quanx.conf'), quanx.text, 'utf8')
writeFileSync(join(outDir, 'sample.txt'), b64.text, 'utf8')
writeFileSync(join(outDir, 'sample.egern.yaml'), egern.text, 'utf8')
writeFileSync(join(outDir, 'sample.shadowrocket.yaml'), shadowrocket.text, 'utf8')
writeFileSync(join(outDir, 'sample.clashverge.yaml'), clashVerge.text, 'utf8')

console.log(`sing-box: outbounds 由 ${SAMPLE.length} 个节点生成，skipped=${singbox.skipped}`)
console.log(`surge: skipped=${surge.skipped} · loon: skipped=${loon.skipped} · quanx: skipped=${quanx.skipped} · base64: skipped=${b64.skipped}`)
for (const [label, text] of [['surge', surge.text], ['loon', loon.text], ['quanx', quanx.text]] as const) {
  console.log(`${label} 首节点行: ${text.split('\n').find((l) => l.includes(SAMPLE[0].server)) ?? '（缺节点）'}`)
}

// ---------- INI 结构校验：组引用 / 规则引用不能指向不存在的名字 ----------
const problems: string[] = []

function sectionLines(text: string, section: string): string[] {
  const lines = text.split('\n')
  const start = lines.findIndex((l) => l.trim().toLowerCase() === `[${section.toLowerCase()}]`)
  if (start < 0) return []
  const out: string[] = []
  for (let i = start + 1; i < lines.length; i++) {
    const t = lines[i].trim()
    if (/^\[.+]$/.test(t)) break
    if (t) out.push(t)
  }
  return out
}

function validateINI(label: string, text: string, opts: {
  proxySection: string
  proxyNames: (line: string) => string | undefined
  groupSection: string
  groupNames: (line: string) => string | undefined
  groupMembers: (line: string) => string[]
  ruleSection: string
  ruleGroup: (line: string) => string | undefined
}) {
  const proxies = sectionLines(text, opts.proxySection).map(opts.proxyNames).filter(Boolean) as string[]
  const groups = sectionLines(text, opts.groupSection).map(opts.groupNames).filter(Boolean) as string[]
  const known = new Set([...proxies, ...groups, 'DIRECT', 'REJECT', 'direct', 'reject'])
  if (proxies.length === 0) {
    problems.push(`${label}: 一个节点都没写进 [${opts.proxySection}]`)
  }
  for (const line of sectionLines(text, opts.groupSection)) {
    for (const member of opts.groupMembers(line)) {
      if (!known.has(member)) problems.push(`${label}: 分组引用了不存在的成员「${member}」`)
    }
  }
  for (const line of sectionLines(text, opts.ruleSection)) {
    const group = opts.ruleGroup(line)
    if (group && !known.has(group)) problems.push(`${label}: 规则引用了不存在的策略「${group}」`)
  }
  console.log(`${label}: 节点 ${proxies.length} · 分组 ${groups.length} · 规则 ${sectionLines(text, opts.ruleSection).length}`)
}

/** 去掉 `url=` / `interval=` 之类的选项，只留成员名。 */
function membersOf(line: string): string[] {
  const tail = line.slice(line.indexOf('=') + 1)
  return tail
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s && !/^[a-z-]+\s*=/i.test(s))
}

validateINI('surge', surge.text, {
  proxySection: 'Proxy',
  proxyNames: (l) => l.split(' = ')[0]?.trim(),
  groupSection: 'Proxy Group',
  groupNames: (l) => l.split(' = ')[0]?.trim(),
  groupMembers: (l) => membersOf(l).slice(1), // 第一个是类型（select/url-test）
  ruleSection: 'Rule',
  ruleGroup: (l) => {
    if (/^(AND|OR|NOT),/.test(l)) return undefined
    const parts = l.split(',')
    return parts.length >= 3 ? parts[2].trim() : parts.length === 2 ? parts[1].trim() : undefined
  },
})

validateINI('loon', loon.text, {
  proxySection: 'Proxy',
  proxyNames: (l) => l.split(' = ')[0]?.trim(),
  groupSection: 'Proxy Group',
  groupNames: (l) => l.split(' = ')[0]?.trim(),
  groupMembers: (l) => membersOf(l).slice(1), // 第一个是类型（select/url-test）
  ruleSection: 'Rule',
  ruleGroup: (l) => {
    const parts = l.split(',').map((part) => part.trim())
    const tail = parts.at(-1)
    return tail && /^no-resolve$/i.test(tail) ? parts.at(-2) : tail
  },
})

validateINI('quanx', quanx.text, {
  proxySection: 'server_local',
  proxyNames: (l) => l.match(/tag=(.+)$/)?.[1]?.trim(),
  groupSection: 'policy',
  groupNames: (l) => l.split('=')[1]?.split(',')[0]?.trim(),
  groupMembers: membersOf,
  ruleSection: 'filter_local',
  ruleGroup: (l) => l.split(',').slice(-1)[0]?.trim(),
})

// ---------- Egern / Shadowrocket YAML ----------
const egernDoc = parse(egern.text) as any
const shadowDoc = parse(shadowrocket.text) as any
const egernProxies = egernDoc?.proxies?.length ?? 0
const egernGroups = egernDoc?.policy_groups?.length ?? 0
const egernRules = egernDoc?.rules?.length ?? 0
const shadowProxies = shadowDoc?.proxies?.length ?? 0
const shadowGroups = shadowDoc?.['proxy-groups']?.length ?? 0
const shadowRules = shadowDoc?.rules?.length ?? 0
if (egernProxies !== SAMPLE.length) problems.push(`egern: proxies ${egernProxies}/${SAMPLE.length}`)
if (!egernGroups) problems.push('egern: 缺少 policy_groups')
if (!egernRules) problems.push('egern: 缺少 rules')
if ('proxy-groups' in (egernDoc ?? {})) problems.push('egern: 不应写 Clash proxy-groups')
if (shadowProxies !== SAMPLE.length) problems.push(`shadowrocket: proxies ${shadowProxies}/${SAMPLE.length}`)
if (!shadowGroups) problems.push('shadowrocket: 缺少 proxy-groups')
if (!shadowRules) problems.push('shadowrocket: 缺少 rules')

// 规则能力过滤：Loon / QuanX 不写 PROCESS-NAME，Surge 保留；
// 逻辑规则只在支持它的客户端写回。
if (!surge.text.includes('PROCESS-NAME,curl')) problems.push('surge: 未写入 PROCESS-NAME')
if (loon.text.includes('PROCESS-NAME')) problems.push('loon: 不应写入 PROCESS-NAME')
if (quanx.text.includes('PROCESS-NAME')) problems.push('quanx: 不应写入 PROCESS-NAME')
// 逻辑规则里的 NETWORK 要按目标方言归一：Surge / Loon 用 PROTOCOL。
if (!surge.text.includes('AND,((DOMAIN,foo.example),(PROTOCOL,UDP))')) problems.push('surge: 未写入逻辑规则或未转换为 PROTOCOL')
if (!loon.text.includes('AND,((DOMAIN,foo.example),(PROTOCOL,UDP))')) problems.push('loon: 未写入逻辑规则或未转换为 PROTOCOL')
if (hasRule(surge.text, 'NETWORK') || hasRule(loon.text, 'NETWORK')) {
  problems.push('surge/loon: 不应写入 NETWORK 规则')
}
if (!egern.text.includes('domain_regex:')) problems.push('egern: 未写入 domain_regex')
if (egern.text.includes('PROCESS-NAME')) problems.push('egern: 不应写入 PROCESS-NAME')

// 通用订阅按代表性客户端的规则能力过滤，不把别的客户端的规则一起发布。
function hasRule(text: string, type: string): boolean {
  return new RegExp(`(^|\\n)\\s*(?:-\\s*)?${type},`, 'm').test(text)
}
if (hasRule(generic.yaml, 'URL-REGEX')) problems.push('yaml: 不应写入 mihomo 不支持的 URL-REGEX')
if (hasRule(generic.surge, 'DOMAIN-REGEX')) problems.push('surge: 不应写入不支持的 DOMAIN-REGEX')
if (hasRule(generic.loon, 'DOMAIN-REGEX') || hasRule(generic.loon, 'PROCESS-NAME')) {
  problems.push('loon: 不应写入不支持的规则类型')
}
if (hasRule(generic.quanx, 'URL-REGEX') || hasRule(generic.quanx, 'PROCESS-NAME')) {
  problems.push('quanx: 不应写入不支持的规则类型')
}
if (hasRule(generic.egern, 'PROCESS-NAME')) problems.push('egern: 不应写入不支持的 PROCESS-NAME')
if (hasRule(generic.json, 'URL-REGEX') || hasRule(generic.json, 'PROCESS-NAME')) {
  problems.push('json: 不应写入不支持的规则类型')
}

// DNS 与网络设置：普通 DNS、严格保护、IPv6 关闭、方案测试地址。
if (!surge.text.includes('dns-server = 10.0.0.1, 10.0.0.2')) problems.push('surge: 未写入自定义 DNS')
if (!quanx.text.includes('network_check_url=https://probe.example/204')) problems.push('quanx: 未使用方案测试地址')
if (shadowrocket.text.includes('https://8.8.4.4/dns-query')) problems.push('shadowrocket: 不应直连远程 DNS')
if (!shadowrocket.text.includes('ipv6: false')) problems.push('shadowrocket: 未写入 ipv6: false')
if (!egern.text.includes('latency_test_url: "https://probe.example/204"')) problems.push('egern: 未使用方案测试地址')
const clashVergeDoc = parse(clashVerge.text) as any
if (clashVergeDoc?.tun?.enable !== true || clashVergeDoc?.tun?.['strict-route'] !== true) {
  problems.push('clash-verge: 严格模式未写入 TUN / strict-route')
}
if (!(clashVergeDoc?.dns?.nameserver as string[] | undefined)
  ?.some((value) => value.includes('https://8.8.4.4/dns-query'))) {
  problems.push('clash-verge: 严格模式未使用远程 DNS')
}

// GEOIP 默认补 no-resolve；只有 mihomo 系目标在 DNS 已走代理/方案 DNS 时，
// 才释放最后一条 GEOIP 的 no-resolve。Surge 的 IP 规则同样补 no-resolve。
if (compileRuleLine({ type: 'GEOIP', value: 'CN' }, 'DIRECT', 'clash') !== 'GEOIP,CN,DIRECT,no-resolve') {
  problems.push('clash: GEOIP 未补 no-resolve')
}
if (compileRuleLine({ type: 'IP-CIDR', value: '10.0.0.0/8' }, 'DIRECT', 'surge') !== 'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve') {
  problems.push('surge: IP-CIDR 未补 no-resolve')
}
if (compileRuleLine({ type: 'IP-CIDR', value: '10.0.0.0/8' }, 'DIRECT', 'loon') !== 'IP-CIDR,10.0.0.0/8,DIRECT') {
  problems.push('loon: IP-CIDR 不应补 Surge 专属 no-resolve')
}
const clashGeoIP = (clashVergeDoc?.rules as string[] | undefined)
  ?.find((line) => /^GEOIP,CN,DIRECT/.test(line))
if (!clashGeoIP) problems.push('clash-verge: 缺少 GEOIP,CN,DIRECT 规则')
if (clashGeoIP?.includes('no-resolve')) {
  problems.push('clash-verge: DNS 已走代理时末尾 GEOIP 应释放 no-resolve')
}
if (![surge.text, loon.text].every((text) => /GEOIP,CN,DIRECT,no-resolve/.test(text))) {
  problems.push('surge/loon: GEOIP 未补 no-resolve')
}

// 条件组：Surge 写 subnet，Egern 写 conditional；其他目标退回默认策略。
if (!/网络 = subnet, "default"=节点选择/.test(conditionalSurge.text)) {
  problems.push('surge: conditional 组未写成 subnet 或默认策略丢失')
}
if (!conditionalSurge.text.includes('no-alert=true') || !conditionalSurge.text.includes('timeout=10')) {
  problems.push('surge: 同方言标量参数未写回')
}
const conditionalEgernDoc = parse(conditionalEgern.text) as any
const egernConditionalGroup = (conditionalEgernDoc?.policy_groups as any[] | undefined)
  ?.find((item) => item.conditional)
if (!egernConditionalGroup) problems.push('egern: conditional 组未写回')
if (egernConditionalGroup?.conditional?.default_policy !== '节点选择') {
  problems.push('egern: conditional 默认策略丢失')
}
if (!JSON.stringify(egernConditionalGroup?.conditional?.rules ?? []).includes('ssid')) {
  problems.push('egern: conditional 规则丢失')
}
const conditionalClashDoc = parse(conditionalClash.text) as any
const clashConditionalGroup = (conditionalClashDoc?.['proxy-groups'] as any[] | undefined)
  ?.find((item) => item.name === '网络')
if (clashConditionalGroup?.type !== 'select') {
  problems.push('clash: conditional 组未降级为 select')
}
if (!(clashConditionalGroup?.proxies as string[] | undefined)?.includes('节点选择')) {
  problems.push('clash: conditional 降级后未使用默认策略')
}

console.log(`egern: 节点 ${egernProxies} · 分组 ${egernGroups} · 规则 ${egernRules}`)
console.log(`shadowrocket: 节点 ${shadowProxies} · 分组 ${shadowGroups} · 规则 ${shadowRules}`)

// ---------- Surge 自更新首行 #!MANAGED-CONFIG ----------
const managedURL = 'https://tower.example.com/api/sub/abc123?format=surge&target=surge'
const surgeManaged = generateConfig(client('surge'), SAMPLE, scheme, {
  contentMode: 'full',
  managedConfigURL: managedURL,
  remoteSubscriptions: [{ id: 'sub1', name: '机场 A', url: 'https://sub.example.com/clash' }],
})
const managedFirstLine = surgeManaged.text.split('\n')[0]
if (managedFirstLine !== `#!MANAGED-CONFIG ${managedURL} interval=${SURGE_UPDATE_INTERVAL}`) {
  problems.push(`surge: 自更新首行不正确 → ${managedFirstLine}`)
}
// interval 必须与 policy-path 的 update-interval 完全一致，不允许两处不同。
const policyIntervals = [...surgeManaged.text.matchAll(/update-interval=(\d+)/g)].map((m) => Number(m[1]))
if (policyIntervals.length === 0) problems.push('surge: 缺少 policy-path 的 update-interval 样例')
for (const value of policyIntervals) {
  if (value !== SURGE_UPDATE_INTERVAL) problems.push(`surge: update-interval=${value} 与首行 ${SURGE_UPDATE_INTERVAL} 不一致`)
}
// 没有可发布地址 / 仅节点 / 非法地址时都不能写首行，避免制造假地址或破坏首行。
if (surge.text.startsWith('#!MANAGED-CONFIG')) problems.push('surge: 没有可发布地址时不应写自更新首行')
if (surgeNodes.text.includes('#!MANAGED-CONFIG')) problems.push('surge: 仅节点输出不应写自更新首行')
for (const bad of ['https://tower.example.com/a b', 'javascript:alert(1)', 'https://tower.example.com/x\r\nFoo: bar', 'not-a-url']) {
  const generated = generateConfig(client('surge'), SAMPLE, scheme, { contentMode: 'full', managedConfigURL: bad })
  if (generated.text.startsWith('#!MANAGED-CONFIG')) problems.push(`surge: 非法地址不应写首行 → ${JSON.stringify(bad)}`)
}

// ---------- 仅节点交接 / 一键导入 ----------
if (surgeNodes.extension !== 'txt' || surgeNodes.text.includes('[General]') || surgeNodes.text.includes('[Proxy]')) {
  problems.push('surge: 仅节点应输出纯 policy-path 行，不能带回 [General]/[Proxy] 段')
}
if (!surgeNodes.text.includes('hy.example.com')) problems.push('surge: 仅节点缺少 Hysteria2')
if (loonNodes.extension !== 'txt' || loonNodes.text.includes('[General]')) {
  problems.push('loon: 仅节点应输出纯 nodelist 行')
}
if (quanxNodes.extension !== 'txt' || quanxNodes.text.includes('[general]') || quanxNodes.text.includes('[server_local]')) {
  problems.push('quanx: 仅节点应输出纯 server_remote 行')
}
if (!quanxNodes.text.includes('shadowsocks=ss.example.com:8388')) problems.push('quanx: 仅节点缺少 SS 行')
if (quanxNodes.skipped !== 1) problems.push(`quanx: Hysteria2 应跳过 1 个，实际 ${quanxNodes.skipped}`)
const nodeYamlChecks: Array<[string, typeof clashNodes]> = [
  ['clash', clashNodes],
  ['shadowrocket', shadowrocketNodes],
]
for (const [label, generated] of nodeYamlChecks) {
  if (!generated.text.startsWith('proxies:')) problems.push(`${label}: 仅节点应以 proxies: 开头`)
  if (generated.text.includes('mixed-port:') || generated.text.includes('proxy-groups:')) {
    problems.push(`${label}: 仅节点不应写入完整配置骨架`)
  }
  if (!generated.text.includes('ss.example.com')) problems.push(`${label}: 仅节点缺少 SS`)
}

if (!clientSupportsImport(client('surge'), 'full') || clientSupportsImport(client('surge'), 'nodes')) {
  problems.push('surge: 一键导入只应支持完整配置')
}
if (!clientSupportsImport(client('quanx'), 'nodes') || clientSupportsImport(client('quanx'), 'full')) {
  problems.push('quanx: 一键导入只应支持仅节点')
}
for (const target of ['surge-mac', 'flclash', 'clash-mi', 'clash-apple', 'karing', 'sing-box'] as ClientTarget[]) {
  if (!clientSupportsImport(client(target), 'full')) problems.push(`${target}: 缺少完整配置一键导入`)
}
for (const target of ['hiddify', 'loon', 'shadowrocket'] as ClientTarget[]) {
  if (!clientSupportsImport(client(target), 'full') || !clientSupportsImport(client(target), 'nodes')) {
    problems.push(`${target}: 完整配置 / 仅节点一键导入不完整`)
  }
}
for (const target of ['v2box', 'anywhere'] as ClientTarget[]) {
  if (!clientSupportsImport(client(target), 'nodes')) problems.push(`${target}: 缺少仅节点一键导入`)
}
const schemeExpectations: Partial<Record<ClientTarget, string>> = {
  'clash-verge': 'clash://install-config',
  'mihomo-party': 'mihomo://install-config',
  flclash: 'flclash://install-config',
  'clash-mi': 'clashmi://install-config',
  'clash-apple': 'clashmeta://install-config',
  'surge-mac': 'surgeconfig:///install-config',
  'sing-box': 'sing-box://import-remote-profile',
  hiddify: 'hiddify://import/',
  'v2box': 'v2box://install-sub',
  anywhere: 'anywhere://add-proxy',
  egern: 'egern:/profiles/new',
}
for (const [target, prefix] of Object.entries(schemeExpectations) as [ClientTarget, string][]) {
  const mode = target === 'v2box' || target === 'anywhere' ? 'nodes' : 'full'
  const scheme = client(target).importScheme?.('https://example.com/sub', 'tower', mode) ?? ''
  if (!scheme.startsWith(prefix)) problems.push(`${target}: 一键导入链接前缀错误`)
}
// Clash Verge 2.5.8 的 deep link 解析器把 url= 后面的整个 query 当作订阅地址；
// url 内部只能出现 %26，不能把 &name 之类未编码参数追加在后面。
const clashVergeInner = 'https://example.com/sub?format=yaml&target=clash-verge'
const clashVergeScheme = client('clash-verge').importScheme?.(clashVergeInner, 'tower', 'full') ?? ''
const clashVergePrefix = 'clash://install-config?url='
if (!clashVergeScheme.startsWith(clashVergePrefix)) {
  problems.push('clash-verge: 一键导入链接不是 clash://install-config')
} else {
  const payload = clashVergeScheme.slice(clashVergePrefix.length)
  if (payload.includes('&') || decodeURIComponent(payload) !== clashVergeInner) {
    problems.push('clash-verge: url 参数未正确编码')
  }
}
const karingScheme = client('karing').importScheme?.('https://example.com/sub.yaml', 'tower', 'full') ?? ''
if (!karingScheme.startsWith('karing://install-config') || !karingScheme.includes('tower-import')) {
  problems.push('karing: 一键导入链接缺少唯一版本参数')
}
const quanxScheme = client('quanx').importScheme?.('https://example.com/sub.txt', 'tower', 'nodes') ?? ''
if (!quanxScheme.startsWith('quantumult-x:///add-resource') || !quanxScheme.includes('server_remote')) {
  problems.push('quanx: 仅节点一键导入链接格式不正确')
}

// ---------- sing-box MT 三模式 ----------
const singboxDoc = JSON.parse(singbox.text) as any
const singboxTags = (singboxDoc?.outbounds ?? []).map((outbound: any) => outbound.tag)
if (!singboxTags.includes('全局代理') || !singboxTags.includes('全局自动选择')) {
  problems.push('sing-box: 缺少全局代理 / 自动选择')
}
if (singboxDoc?.experimental?.clash_api?.default_mode !== '规则判定') {
  problems.push('sing-box: 未把 clash_api 默认模式设为规则判定')
}
const modeValues = ['规则判定', '全局代理', '直接连接']
if (!modeValues.every((mode) => (singboxDoc?.route?.rules ?? []).some((rule: any) => rule.clash_mode === mode))) {
  problems.push('sing-box: route 缺少三种 clash_mode 规则')
}
if (!['全局代理', '直接连接'].every((mode) => (singboxDoc?.dns?.rules ?? []).some((rule: any) => rule.clash_mode === mode))) {
  problems.push('sing-box: DNS 缺少全局代理 / 直接连接模式规则')
}
if (!(singboxDoc?.dns?.servers ?? []).some((server: any) => server.tag === 'remote-global')) {
  problems.push('sing-box: 缺少 remote-global 解析器')
}
const hiddifyDoc = JSON.parse(hiddify.text) as any
const hiddifyTags = (hiddifyDoc?.outbounds ?? []).map((outbound: any) => outbound.tag)
if (hiddifyDoc?.experimental?.clash_api || hiddifyTags.includes('全局代理')) {
  problems.push('hiddify: 不应写入 1.14 的 clash_api / 三模式')
}

const uriCount = Buffer.from(b64.text, 'base64')
  .toString('utf8')
  .split('\n')
  .filter((l) => /^\w+:\/\//.test(l.trim())).length

if (uriCount !== SAMPLE.length) problems.push(`base64: URI ${uriCount}/${SAMPLE.length}`)
console.log(`base64: URI ${uriCount}/${SAMPLE.length}`)
if (v2box.skipped !== 0) problems.push(`v2box: 应写出全部 4 个 URI，实际跳过 ${v2box.skipped}`)
if (anywhere.skipped !== 1) problems.push(`anywhere: 应跳过 1 个不支持的 VMess，实际跳过 ${anywhere.skipped}`)
console.log(`v2box: skipped=${v2box.skipped} · anywhere: skipped=${anywhere.skipped}`)

// ---------- YAML 标量：订阅备注里的控制字符必须转义 ----------
// mihomo / Go YAML 不允许双引号标量里出现裸 C0 控制字符，否则整份配置被拒。
const hostileName = '节点\u0007\t"引号"\\反斜杠'
const hostileScalar = yamlScalar(hostileName)
if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(hostileScalar)) {
  problems.push('naming: yaml 标量仍含裸控制字符')
}
const roundTrip = (parse(`name: ${hostileScalar}`) as { name?: unknown }).name
if (roundTrip !== hostileName) problems.push('naming: yaml 转义后无法还原原值')
const hostileMultiline = yamlMultiline('KEY\u0001\nSECOND')
if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(hostileMultiline)) {
  problems.push('naming: yamlMultiline 仍含裸控制字符')
}
if (!hostileMultiline.includes('\\x01')) problems.push('naming: yamlMultiline 未写出 \\x01 转义')

// ---------- 规则方言归一化：同一语义在各客户端只写它认识的拼写 ----------
const dialectedScheme: RuleScheme = {
  id: 'dialect',
  name: 'dialect',
  description: '',
  groups: [
    { name: '节点选择', type: 'select', options: ['DIRECT'], nodeFilter: '.*' },
    { name: '广告拦截', type: 'select', options: ['REJECT'] },
  ],
  rules: [
    { type: 'DOMAIN-WILDCARD', value: '*.wild.example', group: '节点选择' },
    { type: 'IP-ASN', value: '13335', group: '节点选择' },
    { type: 'DST-PORT', value: '443', group: '节点选择' },
    { type: 'DEST-PORT', value: '8443', group: '节点选择' },
    { type: 'NETWORK', value: 'udp', group: '节点选择' },
    { type: 'PROTOCOL', value: 'HTTP', group: '节点选择' },
    { type: 'SRC-IP', value: '10.0.0.5/32', group: '节点选择' },
    { type: 'AND', raw: 'AND,((DOMAIN,and.example),(NETWORK,udp))', group: '节点选择' },
    { type: 'GEOIP', value: 'CN', group: '节点选择' },
    { type: 'GEOIP', value: 'PRIVATE', group: '节点选择' },
    { type: 'FINAL', group: '节点选择' },
  ],
}
const dialected = (target: ClientTarget) =>
  generateConfig(client(target), SAMPLE, dialectedScheme, { contentMode: 'full' }).text

const quanxDialect = dialected('quanx')
if (!quanxDialect.includes('geoip, CN')) problems.push('quanx: GEOIP 未写成 geoip')
if (/\ngeo, /.test(quanxDialect)) problems.push('quanx: 不应写 geo')
if (!quanxDialect.includes('host-wildcard, *.wild.example')) problems.push('quanx: 未写 host-wildcard')
if (!quanxDialect.includes('ip-asn, 13335')) problems.push('quanx: 未写 ip-asn')
if (quanxDialect.includes('no-resolve')) problems.push('quanx: filter 不应带 no-resolve')

const loonDialect = dialected('loon')
if (/\nNETWORK,/.test(loonDialect)) problems.push('loon: 不应写 NETWORK')
if (/\nDST-PORT,/.test(loonDialect)) problems.push('loon: 不应写 DST-PORT')
if (!loonDialect.includes('DEST-PORT,443') || !loonDialect.includes('DEST-PORT,8443')) {
  problems.push('loon: 未把端口规则写成 DEST-PORT')
}

const shadowDialect = dialected('shadowrocket')
if (shadowDialect.includes('DEST-PORT,')) problems.push('shadowrocket: 不应写 DEST-PORT')
if (!shadowDialect.includes('DST-PORT,443')) problems.push('shadowrocket: 未写 DST-PORT')
if (!shadowDialect.includes('AND,((DOMAIN,and.example),(PROTOCOL,UDP))')) {
  problems.push('shadowrocket: 逻辑规则未转换为 PROTOCOL')
}
if (/\n\s+- PROTOCOL,HTTP,/.test(shadowDialect)) problems.push('shadowrocket: 不应写独立 PROTOCOL')

const clashDialect = parse(dialected('clash-verge')) as any
const clashDialectRules = (clashDialect?.rules ?? []) as string[]
if (!clashDialectRules.some((line) => line.startsWith('SRC-IP-CIDR,10.0.0.5/32'))) {
  problems.push('mihomo: SRC-IP 未转换为 SRC-IP-CIDR')
}
if (clashDialectRules.some((line) => line.startsWith('DEST-PORT,'))) {
  problems.push('mihomo: 不应写 DEST-PORT')
}
if (clashDialectRules.some((line) => line.startsWith('PROTOCOL,'))) {
  problems.push('mihomo: 不应写 PROTOCOL')
}

const singboxDialect = JSON.parse(dialected('sing-box')) as any
const singboxFlattened = JSON.stringify(singboxDialect?.route?.rules ?? [])
if (!singboxFlattened.includes('"network":["udp"]')) problems.push('sing-box: 未写 network')
if (!singboxFlattened.includes('"protocol":["http"]')) problems.push('sing-box: 未写 protocol')
if (!singboxFlattened.includes('"type":"logical"')) problems.push('sing-box: 未写 logical')
if (!singboxFlattened.includes('"port":[443]')) problems.push('sing-box: 未写 port')
if (!singboxFlattened.includes('"source_ip_cidr":["10.0.0.5/32"]')) {
  problems.push('sing-box: 未写 source_ip_cidr')
}

const egernDialect = parse(dialected('egern')) as any
const egernDestPorts = ((egernDialect?.rules ?? []) as any[])
  .filter((rule) => rule.dest_port?.match === '443')
  .length
if (egernDestPorts !== 1) problems.push(`egern: 443 端口规则应只写一次，实际 ${egernDestPorts}`)

// sing-box / Hiddify：GEOIP 改写成托管国家 CIDR 规则集，LAN / PRIVATE 用内置字段。
for (const target of ['sing-box', 'hiddify'] as ClientTarget[]) {
  const doc = JSON.parse(dialected(target)) as any
  const rules = (doc?.route?.rules ?? []) as any[]
  const geoipSet = (doc?.route?.rule_set ?? [])
    .find((set: any) => set.tag === 'tower-geoip-country-cn')
  if (!geoipSet || !String(geoipSet.url).includes('geoip=CN')) {
    problems.push(`${target}: GEOIP,CN 未写成托管国家规则集`)
  }
  if (!rules.some((rule) => rule.rule_set?.includes('tower-geoip-country-cn'))) {
    problems.push(`${target}: 路由规则未引用 GEOIP 国家规则集`)
  }
  if (!rules.some((rule) => rule.ip_is_private === true)) {
    problems.push(`${target}: GEOIP,PRIVATE 未写成 ip_is_private`)
  }
}

console.log(problems.length ? `\n❌ ${problems.join('\n❌ ')}` : '\n✅ INI / base64 / Egern / Shadowrocket 结构自检通过')
