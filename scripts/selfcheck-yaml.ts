// 自检：用示例 SSR 节点跑 generateClashYAML，产出可直接喂给 mihomo 的配置。
// 用法：npx tsx scripts/selfcheck-yaml.ts
// 目的：验证生成的 YAML（尤其 dns 段）能被 mihomo 正常加载。
// 注意：这里使用虚构域名和示例密码，禁止把真实订阅节点提交到公开仓库。
import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { generateClashYAML } from '../src/generator/clashYaml'
import { generateSubscriptionFormats } from '../src/generator'
import type { ProxyNode, RuleScheme } from '../src/models/types'

const RAW: [string, string, number][] = [
  ['示例 SSR 香港 01', 'ssr-hk1.example.org', 32103],
  ['示例 SSR 香港 02', 'ssr-hk2.example.org', 32103],
  ['示例 SSR 台湾 01', 'ssr-tw1.example.org', 32101],
  ['示例 SSR 东京 01', 'ssr-jp1.example.org', 11043],
  ['示例 SSR 东京 02', 'ssr-jp2.example.org', 11044],
  ['示例 SSR 大阪 01', 'ssr-jp3.example.org', 32104],
  ['示例 SSR 新加坡 01', 'ssr-sg1.example.org', 51655],
  ['示例 SSR 新加坡 02', 'ssr-sg2.example.org', 51656],
  ['示例 SSR 新加坡 03', 'ssr-sg3.example.org', 51657],
  ['示例 SSR 美国 01', 'ssr-us1.example.org', 51658],
  ['示例 SSR 美国 02', 'ssr-us2.example.org', 51659],
]

const nodes: ProxyNode[] = RAW.map(([name, server, port], i) => ({
  id: `n${i}`,
  kind: 'ssr',
  name,
  server,
  port,
  cipher: 'aes-256-cfb',
  password: 'demo-password',
  protocolName: 'auth_aes128_md5',
  protocolParam: '10102:demo',
  obfs: 'tls1.2_ticket_auth',
  obfsParam: 'demo.example.org',
  tls: false,
  skipCertificateVerification: false,
}))

const scheme: RuleScheme = {
  id: 'selfcheck',
  name: 'selfcheck',
  description: '',
  groups: [{ name: '🚀 节点选择', type: 'select', options: ['DIRECT'], nodeFilter: '.*' }],
  rules: [{ type: 'FINAL', group: '🚀 节点选择' } as any],
}

const yamlText = generateClashYAML(nodes, scheme)

// 结构自检
const doc = parse(yamlText) as any
const proxies = doc?.proxies ?? []
const groups = doc?.['proxy-groups'] ?? []
const dns = doc?.dns ?? {}
const problems: string[] = []
if (proxies.length !== nodes.length) problems.push(`proxies=${proxies.length} 期望 ${nodes.length}`)
if (!groups.length) problems.push('缺少 proxy-groups')
if (!dns['proxy-server-nameserver']) problems.push('dns 缺少 proxy-server-nameserver（fake-ip 下会导致节点全 timeout）')
if (!dns['fake-ip-range']) problems.push('dns 缺少 fake-ip-range')

const outDir = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp-clash4')
mkdirSync(outDir, { recursive: true })
// 换成独立端口，避免与宿主 Clash 冲突
const forMihomo = yamlText
  .replace(/mixed-port: \d+/, 'mixed-port: 17901')
  .replace(/\nproxies:|\n\nproxies:/, '\nexternal-controller: 127.0.0.1:19101\nsecret: \'\'\nproxies:')
writeFileSync(join(outDir, 'out.yaml'), forMihomo, 'utf8')

console.log(`proxies=${proxies.length} groups=${groups.length} dns.proxy-server-nameserver=${JSON.stringify(dns['proxy-server-nameserver'])}`)
console.log(problems.length ? `❌ ${problems.join('; ')}` : '✅ 结构自检通过')
console.log(`已写出 ${join(outDir, 'out.yaml')}`)

// ---------- E2E：走一遍真实的发布/分发链路（需要 companion server 在 8787 上） ----------
const BASE = process.env.TOWER_BASE ?? 'http://127.0.0.1:8787'
try {
  const formats = generateSubscriptionFormats(nodes, scheme)
  writeFileSync(join(outDir, 'out.json'), formats.json, 'utf8')
  writeFileSync(join(outDir, 'out.surge.conf'), formats.surge, 'utf8')
  writeFileSync(join(outDir, 'out.loon.conf'), formats.loon, 'utf8')
  writeFileSync(join(outDir, 'out.quanx.conf'), formats.quanx, 'utf8')
  console.log('\n--- 各客户端首个节点行 ---')
  for (const fmt of ['surge', 'loon', 'quanx'] as const) {
    console.log(`${fmt}: ${formats[fmt].split('\n').find((l) => l.includes(nodes[0].server)) ?? '（缺节点）'}`)
  }
  const post = await fetch(`${BASE}/api/subscribe`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({ title: 'selfcheck', formats }),
  })
  if (!post.ok) throw new Error(`POST /api/subscribe HTTP ${post.status}`)
  const { token } = (await post.json()) as { token: string }
  for (const fmt of ['yaml', 'surge', 'loon', 'quanx', 'json', 'base64'] as const) {
    const res = await fetch(`${BASE}/api/sub/${token}?format=${fmt}`)
    const text = await res.text()
    const head = (text.split('\n').find((l) => l.trim()) ?? '').trim().slice(0, 60)
    // 每个客户端都必须带全部节点，而不是「导入成功但一个节点都测不到」。
    const decoded = fmt === 'base64' ? Buffer.from(text, 'base64').toString('utf8') : text
    // base64 载体里服务器地址还嵌在 ssr:// 的二次编码中，按 URI 条数计。
    const nodeCount =
      fmt === 'base64'
        ? decoded.split('\n').filter((l) => /^(ss|ssr|vmess|vless|trojan|hysteria2?|tuic|wireguard|anytls|snell|socks5?|http|https):\/\//i.test(l.trim())).length
        : nodes.filter((n) => decoded.includes(n.server)).length
    const dnsOK = fmt === 'yaml' ? /proxy-server-nameserver/.test(text) : true
    const countOK = fmt === 'json' ? true : nodeCount === nodes.length // sing-box 已移除 SSR，预期跳过
    const ok = res.ok && text.length > 0 && dnsOK && countOK
    console.log(`${ok ? '✅' : '❌'} ${fmt}: HTTP ${res.status} · ${text.length} 字节 · 节点 ${nodeCount}/${nodes.length} · ${head}`)
    if (!ok) problems.push(`${fmt} 分发异常（节点 ${nodeCount}/${nodes.length}）`)
  }
  await fetch(`${BASE}/api/sub/${token}`, { method: 'DELETE' })

  // GEOIP 托管规则集：服务端从离线国家表生成 SRS，sing-box / Hiddify 直接下载。
  const geoip = await fetch(`${BASE}/api/ruleset?format=srs&geoip=CN`)
  const geoipBytes = Buffer.from(await geoip.arrayBuffer())
  const geoipOK = geoip.ok
    && geoip.headers.get('content-type')?.includes('application/octet-stream')
    && geoipBytes.subarray(0, 4).toString('hex') === '53525302'
    && geoipBytes.length > 1000
  console.log(`${geoipOK ? '✅' : '❌'} geoip: HTTP ${geoip.status} · ${geoipBytes.length} 字节`)
  if (!geoipOK) problems.push('GEOIP 托管规则集分发异常')

  // IP-ASN 托管规则集：服务端从离线 ASN 表展开 CIDR 再编码为 SRS。
  const asn = await fetch(`${BASE}/api/ruleset?format=srs&asn=13335`)
  const asnBytes = Buffer.from(await asn.arrayBuffer())
  const asnOK = asn.ok
    && asn.headers.get('content-type')?.includes('application/octet-stream')
    && asnBytes.subarray(0, 4).toString('hex') === '53525302'
    && asnBytes.length > 1000
  console.log(`${asnOK ? '✅' : '❌'} asn: HTTP ${asn.status} · ${asnBytes.length} 字节`)
  if (!asnOK) problems.push('IP-ASN 托管规则集分发异常')
} catch (err) {
  console.log(`ℹ️ 跳过 E2E（服务端未启动？）：${err instanceof Error ? err.message : String(err)}`)
}

console.log(problems.length ? `\n❌ 总计问题：${problems.join('; ')}` : '\n✅ 全部格式自检通过')
