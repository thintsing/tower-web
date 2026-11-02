// 自检：非 Clash 客户端的订阅产物是否能被对应内核真正吃下。
// 用法：npx tsx scripts/selfcheck-clients.ts
// 产物写到 .tmp-clash4/，可再喂给 sing-box check / 客户端做导入验证。
import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { generateBase64Subscription } from '../src/generator/base64Sub'
import { generateConfig, generateSubscriptionFormats } from '../src/generator'
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
  ruleGroup: (l) => l.split(',').at(-1)?.trim(),
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
if (!surge.text.includes('AND,((DOMAIN,foo.example),(NETWORK,udp))')) problems.push('surge: 未写入逻辑规则')
if (!loon.text.includes('AND,((DOMAIN,foo.example),(NETWORK,udp))')) problems.push('loon: 未写入逻辑规则')
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

console.log(`egern: 节点 ${egernProxies} · 分组 ${egernGroups} · 规则 ${egernRules}`)
console.log(`shadowrocket: 节点 ${shadowProxies} · 分组 ${shadowGroups} · 规则 ${shadowRules}`)

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
  'clash-verge': 'clash-verge://install-config',
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

console.log(problems.length ? `\n❌ ${problems.join('\n❌ ')}` : '\n✅ INI / base64 / Egern / Shadowrocket 结构自检通过')
