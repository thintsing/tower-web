// 审计回归检查：凭据百分号编码、Clash 嵌套传输字段、sing-box 规则顺序、
// Hiddify WireGuard、Surge Hysteria 2、地图国家代码、方案加载缓存与并行导入。
// 用法：npm run selfcheck:regressions
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { readFileSync, mkdtempSync, rmSync } from 'node:fs'
import { connect } from 'node:net'
import { networkInterfaces, tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { parse, parseStatusLine, parseUsageDeclaration, parseUserinfoHeader } from '../src/parser'
import { subscriptionUsageSummary, usageFieldsFrom } from '../src/models/types'
import { nodeTransportCapability } from '../src/generator/nodeCapabilities'
import { parseClashYAML } from '../src/parser/clash'
import { canonicalNodeURI } from '../src/generator/base64Sub'
import { generateSingBox } from '../src/generator/singbox'
import { generateSurge } from '../src/generator/surge'
import { generateConfig } from '../src/generator'
import { uniqueDisplayNames } from '../src/generator/groups'
import { clearTowerStorage, createSafeStorage, isStorageFull, onStorageFullChange } from '../src/util/localStore'
import { effectiveNetworkSettings } from '../src/models/networkSettings'
import { loadScheme, parseSchemeINI, BUILTIN_SCHEMES } from '../src/rules/scheme'
import { parseRuleSetText } from '../src/rules/ruleSets'
import { countryNumericCode } from '../src/worldmap/countryCodes'
import { iso3ForRegionCode, regionForName } from '../src/models/region'
import { CLIENTS, type ProxyNode, type RuleScheme } from '../src/models/types'
import { setWorkspaceReadOnly } from '../src/util/workspaceLock'
import { READONLY_NOTE, writeGuard } from '../src/util/readOnlyUi'

const base = { tls: false, skipCertificateVerification: false, rawURI: '' } as const
const SCHEME: RuleScheme = {
  id: 'regression',
  name: 'regression',
  description: '',
  groups: [
    { name: '节点选择', type: 'select', options: ['DIRECT'] },
    { name: '自动选择', type: 'select', options: ['DIRECT'] },
  ],
  rules: [{ type: 'FINAL', group: '节点选择' }],
}

let failures = 0
function check(label: string, run: () => void): void {
  try {
    run()
    console.log(`✓ ${label}`)
  } catch (error) {
    failures += 1
    console.error(`✗ ${label}`)
    console.error(`  ${error instanceof Error ? error.message : String(error)}`)
  }
}

async function checkAsync(label: string, run: () => Promise<void>): Promise<void> {
  try {
    await run()
    console.log(`✓ ${label}`)
  } catch (error) {
    failures += 1
    console.error(`✗ ${label}`)
    console.error(`  ${error instanceof Error ? error.message : String(error)}`)
  }
}

function parseOne(text: string): ProxyNode {
  const node = parse(text).nodes[0]
  assert.ok(node, `应解析出节点：${text}`)
  return node
}

function credentialRoundTrip(raw: string, credential: (node: ProxyNode) => string | undefined): void {
  const parsed = parseOne(raw)
  const uri = canonicalNodeURI(parsed)
  assert.ok(uri, `应生成分享链接：${raw}`)
  const reparsed = parseOne(uri)
  assert.equal(credential(reparsed), credential(parsed))
}

// ---------- 1. URI 凭据不会被二次编码 ----------
check('URI 凭据百分号编码往返（Trojan / Hysteria 2 / SOCKS5 / WireGuard）', () => {
  credentialRoundTrip('trojan://p%40ss%3Aword@tr.example.com:443#T', (node) => node.password)
  credentialRoundTrip('hysteria2://p%40ss@hy.example.com:443#H', (node) => node.password)
  credentialRoundTrip('socks5://u%40ser:p%40ss@socks.example.com:1080#S', (node) => `${node.username}:${node.password}`)
  credentialRoundTrip(
    'wireguard://k%2B%2F%3D@wg.example.com:51820?publickey=pk&address=10.0.0.2#W',
    (node) => node.wireGuardPrivateKey,
  )
})

// ---------- 2. 带空格节点名 / 一行多条链接 ----------
check('节点名里的空格不会被拆行截断，一行多条链接仍可拆分', () => {
  const auth = Buffer.from('aes-256-gcm:pass').toString('base64').replace(/=+$/, '')
  const one = parse(`ss://${auth}@1.2.3.4:8388#My Node`).nodes
  assert.deepEqual(one.map((node) => node.name), ['My Node'])
  const two = parse(`ss://${auth}@1.2.3.4:8388#A ss://${auth}@5.6.7.8:8388#B`).nodes
  assert.deepEqual(two.map((node) => node.name), ['A', 'B'])
})

check('多用户节点不会被当成重复项；SSH / Snell 的 userinfo 正确映射', () => {
  const socks = parse(
    'socks5://u1:p@s.example.com:1080#A\nsocks5://u2:p@s.example.com:1080#B',
  ).nodes
  assert.deepEqual(socks.map((node) => node.username), ['u1', 'u2'])
  const ssh = parse(
    'ssh://u1:p@ssh.example.com:22#U1\nssh://u2:p@ssh.example.com:22#U2',
  ).nodes
  assert.deepEqual(ssh.map((node) => `${node.username}:${node.password}`), ['u1:p', 'u2:p'])
  const snell = parseOne('snell://psk@snell.example.com:443#S')
  assert.equal(snell.password, 'psk')
  const wireguard = parse(
    'wireguard://k1@wg.example.com:51820?publickey=p1&address=10.0.0.2#W1\n'
    + 'wireguard://k2@wg.example.com:51820?publickey=p2&address=10.0.0.3#W2',
  ).nodes
  assert.deepEqual(wireguard.map((node) => node.wireGuardPublicKey), ['p1', 'p2'])
})

// ---------- 3. Clash 嵌套传输字段 ----------
check('Clash YAML 的 ws-opts / grpc-opts / h2-opts / xhttp-opts 不丢字段', () => {
  const yaml = `proxies:
  - name: WS
    type: vmess
    server: ws.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /realtime
      headers:
        Host: cdn.example.com
  - name: GRPC
    type: vless
    server: grpc.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    network: grpc
    grpc-opts:
      grpc-service-name: tower-service
  - name: H2
    type: vless
    server: h2.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    network: h2
    h2-opts:
      path: /h2
      host: [h2.example.com]
  - name: XHTTP
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    network: xhttp
    xhttp-opts:
      path: /xhttp
      host: xhttp.example.com
`
  const parsed = parseClashYAML(yaml)
  assert.equal(parsed.rejected, 0)
  const byName = new Map(parsed.nodes.map((node) => [node.name, node]))
  assert.equal(byName.get('WS')?.transport, 'ws')
  assert.equal(byName.get('WS')?.path, '/realtime')
  assert.equal(byName.get('WS')?.hostHeader, 'cdn.example.com')
  assert.equal(byName.get('GRPC')?.path, 'tower-service')
  assert.equal(byName.get('H2')?.path, '/h2')
  assert.equal(byName.get('H2')?.hostHeader, 'h2.example.com')
  assert.equal(byName.get('XHTTP')?.path, '/xhttp')
  assert.equal(byName.get('XHTTP')?.hostHeader, 'xhttp.example.com')
})

// ---------- 4. sing-box 规则顺序 ----------
check('sing-box 路由规则保持 A/B/A 交错顺序', () => {
  const nodes: ProxyNode[] = [{
    ...base, id: 'n1', kind: 'ss', name: 'N1', server: 'ss.example.com',
    port: 8388, cipher: 'aes-256-gcm', password: 'p1',
  }]
  const scheme: RuleScheme = {
    ...SCHEME,
    id: 'order',
    groups: [
      { name: 'A', type: 'select', options: ['DIRECT'] },
      { name: 'B', type: 'select', options: ['DIRECT'] },
      { name: 'C', type: 'select', options: ['DIRECT'] },
    ],
    rules: [
      { type: 'DOMAIN', value: 'x.example', group: 'A' },
      { type: 'DOMAIN-SUFFIX', value: 'example.com', group: 'B' },
      { type: 'DOMAIN', value: 'a.example.com', group: 'A' },
      { type: 'FINAL', group: 'C' },
    ],
  }
  const config = JSON.parse(generateSingBox(nodes, scheme, {
    target: 'sing-box',
    contentMode: 'full',
  }).text) as { route: { rules: Record<string, unknown>[] } }
  const outbounds = config.route.rules
    .filter((rule) => typeof rule.outbound === 'string' && rule.clash_mode === undefined)
    .map((rule) => rule.outbound)
  assert.deepEqual(outbounds, ['A', 'B', 'A'])
})

// ---------- 5. sing-box 规则集多字段 OR ----------
check('sing-box 规则集的 domain 与 ip_cidr 拆成 OR 规则而不是 AND', () => {
  const parsed = parseRuleSetText(JSON.stringify({
    rules: [{ domain: 'or.example', ip_cidr: '1.2.3.0/24' }],
  }), 'singbox')
  assert.equal(parsed.rules.length, 2)
  assert.equal(parsed.rules[0].type, 'DOMAIN')
  assert.equal(parsed.rules[1].type, 'IP-CIDR')
  assert.equal(parsed.rules.some((rule) => rule.type === 'AND'), false)
})

// ---------- 6. Hiddify WireGuard 服务端字段 ----------
check('Hiddify 旧式 WireGuard outbound 带 server / server_port', () => {
  const wg: ProxyNode = {
    ...base, id: 'wg', kind: 'wireguard', name: 'WG', server: 'wg.example.com', port: 51820,
    wireGuardPrivateKey: 'private', wireGuardPublicKey: 'public', wireGuardIPv4: '10.0.0.2',
    wireGuardAllowedIPs: '0.0.0.0/0', wireGuardReserved: '1,2,3',
  }
  const hiddify = CLIENTS.find((client) => client.target === 'hiddify')!
  const parsed = JSON.parse(generateConfig(hiddify, [wg], SCHEME, { contentMode: 'full' }).text) as {
    outbounds: Record<string, unknown>[]
  }
  const outbound = parsed.outbounds.find((item) => item.type === 'wireguard')
  assert.ok(outbound)
  assert.equal(outbound.server, 'wg.example.com')
  assert.equal(outbound.server_port, 51820)
  assert.deepEqual(outbound.local_address, ['10.0.0.2/32'])
  assert.equal(outbound.peer_public_key, 'public')
})

// ---------- 7. Surge Hysteria 2 Salamander / 端口跳跃 ----------
check('Surge Mac 写出 Hysteria 2 Salamander 与端口跳跃', () => {
  const node: ProxyNode = {
    ...base, id: 'hy2', kind: 'hysteria2', name: 'HY2', server: 'hy.example.com', port: 443,
    password: 'p@ss', tls: true, sni: 'hy.example.com', obfs: 'salamander',
    obfsParam: 'obfs-pass', portHopping: '443,5000-6000', downMbps: 200,
  }
  const mac = generateSurge([node], SCHEME, { target: 'surge-mac', contentMode: 'full' })
  assert.equal(mac.skipped, 0)
  const line = mac.text.split('\n').find((value) => value.startsWith('HY2 = hysteria2'))
  assert.ok(line)
  assert.match(line, /salamander-password=obfs-pass/)
  assert.match(line, /port-hopping=443;5000-6000/)
  assert.match(line, /download-bandwidth=200/)
  // iOS 文档没有 Salamander 参数；宁可跳过，也不生成连不上的节点。
  const ios = generateSurge([node], SCHEME, { target: 'surge', contentMode: 'full' })
  assert.equal(ios.skipped, 1)
})

// ---------- 7. Surge / Loon / QuanX 节点配置往返 ----------
const roundTrip = (target: string, sample: string) => {
  const parsed = parse(sample).nodes
  const client = CLIENTS.find((item) => item.target === target)!
  const generated = generateConfig(client, parsed, SCHEME, { contentMode: 'full' })
  const reparsed = parse(generated.text).nodes
  return { parsed, generated, reparsed }
}
const byName = (nodes: ProxyNode[], name: string): ProxyNode => {
  const node = nodes.find((item) => item.name === name)
  assert.ok(node, `缺少节点 ${name}`)
  return node
}

check('Surge [Proxy] / [WireGuard] 真实语法导入并在 Surge Mac 往返', () => {
  const sample = `[Proxy]
SS1 = ss, ss.example.com, 8388, encrypt-method=aes-256-gcm, password=p1, udp-relay=true, obfs=http, obfs-host=obfs.example.com
VM1 = vmess, vm.example.com, 443, username=11111111-2222-3333-4444-555555555555, encrypt-method=aes-128-gcm, vmess-aead=true, ws=true, ws-path=/ws, ws-headers=Host:cdn.example.com|X-Test:1, tls=true, sni=cdn.example.com, skip-cert-verify=true
TR1 = trojan, tr.example.com, 443, password=p2, ws=true, ws-path=/tr, ws-headers=Host:tr.example.com, sni=tr.example.com
HY1 = hysteria2, hy.example.com, 8443, password=p3, sni=hy.example.com, salamander-password=obfs-password, port-hopping=8443;9000-9100, download-bandwidth=200
TU1 = tuic-v5, tu.example.com, 443, uuid=11111111-2222-3333-4444-555555555555, password=p4, alpn=h3
WG1 = wireguard, section-name=wg1
[WireGuard wg1]
private-key = wg-private
self-ip = 10.0.0.2
self-ip-v6 = fd00::2
dns-server = 10.0.0.1
mtu = 1420
peer = (public-key = wg-public, allowed-ips = "0.0.0.0/0, ::/0", endpoint = wg.example.com:51820, preshared-key = wg-psk, keepalive = 30, client-id = 1/2/3)
[Rule]
FINAL,SS1
`
  const parsed = parse(sample)
  assert.equal(parsed.rejectedLineCount, 0)
  assert.equal(parsed.nodes.length, 6)
  const ss = byName(parsed.nodes, 'SS1')
  assert.equal(ss.cipher, 'aes-256-gcm')
  assert.equal(ss.obfs, 'http')
  assert.equal(ss.obfsParam, 'obfs.example.com')
  const vm = byName(parsed.nodes, 'VM1')
  assert.equal(vm.transport, 'ws')
  assert.equal(vm.path, '/ws')
  assert.equal(vm.hostHeader, 'cdn.example.com')
  assert.equal(vm.sni, 'cdn.example.com')
  assert.equal(vm.skipCertificateVerification, true)
  const hy = byName(parsed.nodes, 'HY1')
  assert.equal(hy.obfs, 'salamander')
  assert.equal(hy.obfsParam, 'obfs-password')
  assert.equal(hy.portHopping, '8443,9000-9100')
  assert.equal(hy.downMbps, 200)
  const tu = byName(parsed.nodes, 'TU1')
  assert.equal(tu.uuid, '11111111-2222-3333-4444-555555555555')
  assert.equal(tu.alpn, 'h3')
  const wg = byName(parsed.nodes, 'WG1')
  assert.equal(wg.server, 'wg.example.com')
  assert.equal(wg.port, 51820)
  assert.equal(wg.wireGuardPrivateKey, 'wg-private')
  assert.equal(wg.wireGuardPublicKey, 'wg-public')
  assert.equal(wg.wireGuardPreSharedKey, 'wg-psk')
  assert.equal(wg.wireGuardIPv4, '10.0.0.2')
  assert.equal(wg.wireGuardIPv6, 'fd00::2')
  assert.equal(wg.wireGuardReserved, '1,2,3')
  assert.equal(wg.wireGuardDNS, '10.0.0.1')
  assert.equal(wg.wireGuardMTU, 1420)
  assert.equal(wg.wireGuardPersistentKeepalive, 30)

  const round = roundTrip('surge-mac', sample)
  assert.equal(round.generated.skipped, 0)
  assert.equal(round.reparsed.length, 6)
  const hy2 = byName(round.reparsed, 'HY1')
  assert.equal(hy2.obfs, 'salamander')
  assert.equal(hy2.obfsParam, 'obfs-password')
  assert.equal(hy2.portHopping, '8443,9000-9100')
  assert.equal(hy2.downMbps, 200)
  const tu2 = byName(round.reparsed, 'TU1')
  assert.equal(tu2.uuid, '11111111-2222-3333-4444-555555555555')
  assert.equal(tu2.alpn, 'h3')
  const wg2 = byName(round.reparsed, 'WG1')
  assert.equal(wg2.wireGuardIPv6, 'fd00::2')
  assert.equal(wg2.wireGuardReserved, '1,2,3')
  assert.equal(wg2.wireGuardDNS, '10.0.0.1')
})

check('Loon [Proxy] 真实语法导入并往返', () => {
  const sample = `[Proxy]
SS1 = Shadowsocks,ss.example.com,8388,aes-256-gcm,"p1",obfs-name=http,obfs-host=obfs.example.com,obfs-uri=/obfs,udp=true
SSR1 = ShadowsocksR,ssr.example.com,32103,aes-256-cfb,"p2",protocol=auth_aes128_md5,protocol-param=10102:demo,obfs=tls1.2_ticket_auth,obfs-param=obfs.example.com,udp=true
VM1 = vmess,vm.example.com,443,aes-128-gcm,"11111111-2222-3333-4444-555555555555",transport=ws,path=/ws,host=cdn.example.com,over-tls=true,tls-name=cdn.example.com,skip-cert-verify=true,alterId=0
VL1 = VLESS, vl.example.com, 443, "22222222-3333-4444-5555-666666666666", transport=ws, path=/vl, host=vl.example.com, over-tls=true, tls-name=vl.example.com
TR1 = trojan, tr.example.com, 443, "p3", transport=ws, path=/tr, host=tr.example.com, tls-name=tr.example.com, udp=true
HY1 = Hysteria2, hy.example.com, 8443, "p4", skip-cert-verify=true, tls-name=hy.example.com, udp=true
WG1 = wireguard,interface-ip=10.0.0.2,interface-ipV6=fd00::2,private-key="wg-private",mtu=1420,dns=10.0.0.1,dnsV6=fd00::1,keeyalive=30,peers=[{public-key="wg-public",preshared-key="wg-psk",reserved=[1,2,3],allowed-ips="0.0.0.0/0,::/0",endpoint=wg.example.com:51820}]
HTTP1 = http, http.example.com, 8080, "user", "pass"
[Proxy Group]
G = select, SS1
`
  const parsed = parse(sample)
  assert.equal(parsed.rejectedLineCount, 0)
  assert.equal(parsed.nodes.length, 8)
  const ss = byName(parsed.nodes, 'SS1')
  assert.equal(ss.obfs, 'http')
  assert.equal(ss.path, '/obfs')
  const vm = byName(parsed.nodes, 'VM1')
  assert.equal(vm.cipher, 'aes-128-gcm')
  assert.equal(vm.transport, 'ws')
  assert.equal(vm.path, '/ws')
  assert.equal(vm.hostHeader, 'cdn.example.com')
  assert.equal(vm.sni, 'cdn.example.com')
  assert.equal(vm.skipCertificateVerification, true)
  const vl = byName(parsed.nodes, 'VL1')
  assert.equal(vl.uuid, '22222222-3333-4444-5555-666666666666')
  assert.equal(vl.transport, 'ws')
  const tr = byName(parsed.nodes, 'TR1')
  assert.equal(tr.transport, 'ws')
  assert.equal(tr.sni, 'tr.example.com')
  const hy = byName(parsed.nodes, 'HY1')
  assert.equal(hy.tls, true)
  assert.equal(hy.sni, 'hy.example.com')
  const wg = byName(parsed.nodes, 'WG1')
  assert.equal(wg.wireGuardDNS, '10.0.0.1,fd00::1')
  assert.equal(wg.wireGuardPersistentKeepalive, 30)
  const http = byName(parsed.nodes, 'HTTP1')
  assert.equal(http.username, 'user')
  assert.equal(http.password, 'pass')

  const round = roundTrip('loon', sample)
  assert.equal(round.generated.skipped, 0)
  assert.equal(round.reparsed.length, 8)
  const vm2 = byName(round.reparsed, 'VM1')
  assert.equal(vm2.cipher, 'aes-128-gcm')
  assert.equal(vm2.transport, 'ws')
  assert.equal(vm2.path, '/ws')
  assert.equal(vm2.hostHeader, 'cdn.example.com')
  assert.equal(vm2.sni, 'cdn.example.com')
  const wg2 = byName(round.reparsed, 'WG1')
  assert.equal(wg2.wireGuardDNS, '10.0.0.1,fd00::1')
  assert.equal(wg2.wireGuardIPv6, 'fd00::2')
  assert.equal(wg2.wireGuardReserved, '1,2,3')
  const http2 = byName(round.reparsed, 'HTTP1')
  assert.equal(http2.username, 'user')
  assert.equal(http2.password, 'pass')
})

check('Quantumult X [server_local] 真实语法导入并往返', () => {
  const sample = `[server_local]
shadowsocks=ss.example.com:8388, method=aes-256-gcm, password=p1, obfs=wss, obfs-host=cdn.example.com, obfs-uri=/ssws, udp-relay=false, tag=SS1
shadowsocks=ss2.example.com:8080, method=aes-128-gcm, password=p2, obfs=http, obfs-host=obfs.example.com, obfs-uri=/obfs, udp-relay=false, tag=SS2
shadowsocks=ssr.example.com:32103, method=aes-256-cfb, password=p3, ssr-protocol=auth_aes128_md5, ssr-protocol-param=10102:demo, obfs=tls1.2_ticket_auth, obfs-host=obfs.example.com, tag=SSR1
vmess=vm.example.com:443, method=aes-128-gcm, password=11111111-2222-3333-4444-555555555555, obfs=wss, obfs-host=cdn.example.com, obfs-uri=/ws, tag=VM1
vless=vl.example.com:443, method=none, password=22222222-3333-4444-5555-666666666666, obfs=over-tls, obfs-host=vl.example.com, tls-alpn=02683208687474702f312e31, reality-base64-pubkey=pub, reality-hex-shortid=0123456789abcdef, vless-flow=xtls-rprx-vision, tag=VL1
trojan=tr.example.com:443, password=p4, over-tls=true, tls-host=tr.example.com, tls-verification=false, tag=TR1
http=http.example.com:8080, username=user, password=pass, over-tls=true, tls-host=http.example.com, tag=HTTP1
socks5=socks.example.com:1080, username=user, password=pass, over-tls=true, tls-host=socks.example.com, tag=SOCKS1
`
  const parsed = parse(sample)
  assert.equal(parsed.rejectedLineCount, 0)
  assert.equal(parsed.nodes.length, 8)
  const ss = byName(parsed.nodes, 'SS1')
  assert.equal(ss.plugin, 'v2ray-plugin')
  assert.equal(ss.pluginMux, false)
  assert.equal(ss.transport, 'ws')
  assert.equal(ss.path, '/ssws')
  assert.equal(ss.tls, true)
  const ss2 = byName(parsed.nodes, 'SS2')
  assert.equal(ss2.obfs, 'http')
  assert.equal(ss2.path, '/obfs')
  const vm = byName(parsed.nodes, 'VM1')
  assert.equal(vm.cipher, 'aes-128-gcm')
  assert.equal(vm.transport, 'ws')
  assert.equal(vm.tls, true)
  const vl = byName(parsed.nodes, 'VL1')
  assert.equal(vl.realityPublicKey, 'pub')
  assert.equal(vl.realityShortID, '0123456789abcdef')
  assert.equal(vl.flow, 'xtls-rprx-vision')
  assert.equal(vl.alpn, 'h2,http/1.1')
  const tr = byName(parsed.nodes, 'TR1')
  assert.equal(tr.tls, true)
  assert.equal(tr.skipCertificateVerification, true)
  const http = byName(parsed.nodes, 'HTTP1')
  assert.equal(http.tls, true)
  assert.equal(http.username, 'user')
  const socks = byName(parsed.nodes, 'SOCKS1')
  assert.equal(socks.tls, true)

  const round = roundTrip('quanx', sample)
  assert.equal(round.generated.skipped, 0)
  assert.equal(round.reparsed.length, 8)
  const ss3 = byName(round.reparsed, 'SS1')
  assert.equal(ss3.plugin, 'v2ray-plugin')
  assert.equal(ss3.pluginMux, false)
  assert.equal(ss3.path, '/ssws')
  const vm2 = byName(round.reparsed, 'VM1')
  assert.equal(vm2.cipher, 'aes-128-gcm')
  assert.equal(vm2.transport, 'ws')
  assert.equal(vm2.hostHeader, 'cdn.example.com')
  const vl2 = byName(round.reparsed, 'VL1')
  assert.equal(vl2.realityPublicKey, 'pub')
  assert.equal(vl2.realityShortID, '0123456789abcdef')
  assert.equal(vl2.flow, 'xtls-rprx-vision')
  assert.equal(vl2.alpn, 'h2,http/1.1')
  const socks2 = byName(round.reparsed, 'SOCKS1')
  assert.equal(socks2.tls, true)
})

// ---------- 8. 地图国家代码映射 ----------
check('地图使用完整 ISO2 → numeric 映射', () => {
  assert.equal(iso3ForRegionCode('PT'), 'PRT')
  assert.equal(iso3ForRegionCode('UK'), 'GBR')
  assert.equal(countryNumericCode('PT'), '620')
  assert.equal(countryNumericCode('SG'), '702')
  assert.equal(countryNumericCode('US'), '840')
  assert.equal(countryNumericCode('GB'), '826')
  assert.equal(countryNumericCode('ZZ'), undefined)
  assert.equal(regionForName('葡萄牙 01')?.code, 'PT')
  assert.equal(countryNumericCode(regionForName('葡萄牙 01')!.code), '620')
})

// ---------- 9. 方案加载缓存 + 并行规则集导入 ----------
const originalFetch = globalThis.fetch
const originalWindow = (globalThis as unknown as { window?: unknown }).window
const originalLocalStorage = (globalThis as unknown as { localStorage?: unknown }).localStorage
let fetchCalls = 0
let allFetchCalls = 0
let activeFetches = 0
let maxActiveFetches = 0
// 配额探测回归：记录探测命中的目标地址，并模拟上游整站失败。
let quotaFailNext = false
const quotaTargets: string[] = []
const QUOTA_HEADER = 'upload=1048576; download=10737418240; total=107374182400; expire=1798761600'

function localRuleset(pathname: string): Response {
  try {
    return new Response(readFileSync(join(process.cwd(), 'public', pathname.slice(1)), 'utf8'), { status: 200 })
  } catch {
    return new Response('', { status: 404 })
  }
}

globalThis.fetch = (async (input: RequestInfo | URL) => {
  allFetchCalls += 1
  const raw = String(input)
  if (raw.startsWith('/rulesets/')) return localRuleset(raw)
  const url = new URL(raw, 'http://localhost')
  if (url.pathname === '/api/fetch') {
    fetchCalls += 1
    activeFetches += 1
    maxActiveFetches = Math.max(maxActiveFetches, activeFetches)
    await new Promise((resolve) => setTimeout(resolve, 15))
    activeFetches -= 1
    const target = url.searchParams.get('url') ?? ''
    if (/^https:\/\/latency\.example\//.test(target)) {
      const auth = Buffer.from('aes-256-gcm:pass').toString('base64').replace(/=+$/, '')
      return new Response(`ss://${auth}@1.2.3.4:8388#刷新后的节点`, { status: 200 })
    }
    if (target.includes('quota-retain.example')) {
      quotaTargets.push(target)
      if (quotaFailNext) {
        return new Response(JSON.stringify({ error: 'upstream down' }), {
          status: 502,
          headers: { 'content-type': 'application/json' },
        })
      }
      const auth = Buffer.from('aes-256-gcm:pass').toString('base64').replace(/=+$/, '')
      // 通用链接不带用量头；只有 clash=1 变体返回用量，且正文固定为一个节点。
      const headers = new URL(target).searchParams.get('clash') === '1'
        ? { 'x-subscription-userinfo': QUOTA_HEADER }
        : {}
      return new Response(`ss://${auth}@1.2.3.4:8388#配额节点`, { status: 200, headers })
    }
    return new Response(`DOMAIN-SUFFIX,${target.split('/').pop()?.replace('.list', '')}.example`, {
      status: 200,
    })
  }
  return originalFetch(input as RequestInfo)
}) as typeof fetch

const memoryStorage = (() => {
  const values = new Map<string, string>()
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value) },
    removeItem: (key: string) => { values.delete(key) },
    clear: () => { values.clear() },
    key: (index: number) => [...values.keys()][index] ?? null,
    get length() { return values.size },
  }
})()
;(globalThis as unknown as { window: unknown }).window = {
  location: { origin: 'http://localhost' },
  localStorage: memoryStorage,
}
;(globalThis as unknown as { localStorage: unknown }).localStorage = memoryStorage

await checkAsync('内置方案第二次加载命中缓存，不再重复请求', async () => {
  const meta = BUILTIN_SCHEMES[2]
  const before = allFetchCalls
  const first = await loadScheme(meta)
  const afterFirst = allFetchCalls
  const second = await loadScheme(meta)
  assert.equal(second, first)
  assert.ok(afterFirst > before)
  assert.equal(allFetchCalls, afterFirst)
  console.log(`  内置方案加载请求 ${afterFirst - before} 次 · 第二次 0 次`)
})

await checkAsync('规则集导入并行抓取且按原顺序合并', async () => {
  const count = 8
  const rulesetLines = Array.from({ length: count }, (_, index) =>
    `ruleset=组${index},https://rules.example/r${index}.list`)
  const ini = ['[General]', ...rulesetLines, 'custom_proxy_group=组0`select`[]DIRECT'].join('\n')
  const started = performance.now()
  const apiBefore = fetchCalls
  const scheme = await parseSchemeINI('parallel', 'parallel', '', ini)
  const elapsed = performance.now() - started
  assert.equal(scheme.rules.length, count)
  assert.ok(maxActiveFetches >= 2, `规则集请求没有并行：max=${maxActiveFetches}`)
  assert.ok(elapsed < count * 15 * 0.6, `并行导入耗时 ${Math.round(elapsed)}ms，超过阈值`)
  console.log(`  规则集 ${count} 个 · API 请求 ${fetchCalls - apiBefore} 次 · 最大并发 ${maxActiveFetches} · 耗时 ${Math.round(elapsed)}ms`)
})

// ---------- 10. 刷新订阅时清理旧节点派生状态 ----------
await checkAsync('订阅刷新后清理旧节点的测速 / 错误状态', async () => {
  const { useStore } = await import('../src/store')
  const oldNode: ProxyNode = {
    ...base, id: 'old-node', kind: 'ss', name: '旧节点', server: 'old.example.com',
    port: 8388, cipher: 'aes-256-gcm', password: 'p', sourceID: 'latency-source',
  }
  useStore.setState({
    sources: [{
      id: 'latency-source',
      name: '延迟刷新测试',
      url: 'https://latency.example/sub',
      isEnabled: true,
      excludedNodeKeys: [],
    }],
    nodes: [oldNode],
    latencyByNodeId: { 'old-node': 123 },
    latencyMethodByNodeId: { 'old-node': 'tcp' },
    probeErrorByNodeId: { 'old-node': 'old-error' },
    loadingSourceIDs: [],
    errors: {},
  })
  await useStore.getState().refreshSource('latency-source')
  const state = useStore.getState()
  assert.equal(state.nodes.some((node) => node.id === 'old-node'), false)
  assert.equal(state.nodes.some((node) => node.name === '刷新后的节点'), true)
  assert.equal('old-node' in state.latencyByNodeId, false)
  assert.equal('old-node' in state.latencyMethodByNodeId, false)
  assert.equal('old-node' in state.probeErrorByNodeId, false)
})

// ---------- 11. 配额探测：命中变体复用 + 失败保留旧用量 ----------
await checkAsync('配额探测命中后复用变体，上游失败时保留旧用量', async () => {
  const { useStore } = await import('../src/store')
  useStore.setState({
    sources: [{
      id: 'quota-retain',
      name: '配额保留测试',
      url: 'https://quota-retain.example/link/token?sub=1',
      isEnabled: true,
      excludedNodeKeys: [],
    }],
    nodes: [],
    loadingSourceIDs: [],
    errors: {},
  })
  quotaFailNext = false
  quotaTargets.length = 0
  await useStore.getState().refreshSource('quota-retain')
  let source = useStore.getState().sources.find((item) => item.id === 'quota-retain')!
  assert.equal(source.totalBytes, 107374182400, 'clash=1 探测应写回总量')
  assert.equal(source.usedBytes, 1048576 + 10737418240, '应写回已用流量')
  assert.equal(source.expireAt, 1798761600000, '应写回到期时间')
  assert.equal(
    quotaTargets.filter((target) => target.includes('clash=1')).length,
    1,
    '首次刷新应只命中一次 clash=1 探测，不应跑完整条链',
  )

  // 第二次刷新：上次命中的变体应排在最前，不再尝试 flag=clash。
  quotaTargets.length = 0
  await useStore.getState().refreshSource('quota-retain')
  assert.equal(
    quotaTargets.filter((target) => target.includes('clash=1')).length,
    1,
    '复用缓存变体时仍只发一次探测',
  )
  assert.equal(
    quotaTargets.filter((target) => target.includes('flag=clash')).length,
    0,
    '缓存命中后不应再试 flag=clash',
  )

  // 上游失败：旧的用量字段必须原样保留，不能变成空。
  quotaFailNext = true
  const before = useStore.getState().sources.find((item) => item.id === 'quota-retain')!
  await useStore.getState().refreshSource('quota-retain')
  const after = useStore.getState().sources.find((item) => item.id === 'quota-retain')!
  assert.equal(after.totalBytes, before.totalBytes, '失败时总量应保留')
  assert.equal(after.usedBytes, before.usedBytes, '失败时已用流量应保留')
  assert.equal(after.expireAt, before.expireAt, '失败时到期时间应保留')
  assert.ok(useStore.getState().errors['quota-retain'], '失败应写入错误提示')
})

// ---------- 12. 只读模式：工作区写被拦，设备偏好仍可改 ----------
await checkAsync('只读模式只拦工作区字段，设备偏好保持可写', async () => {
  const { useStore } = await import('../src/store')
  useStore.setState({
    sources: [{
      id: 'ro-source',
      name: '只读源',
      url: 'https://ro.example/sub',
      isEnabled: true,
      excludedNodeKeys: [],
    }],
    nodes: [],
    selectedSchemeID: 'acl4ssr-online',
    policySelections: {},
    showGroupEmoji: false,
  })
  setWorkspaceReadOnly(true)
  try {
    const store = useStore.getState()
    store.setSourceEnabled('ro-source', false)
    store.setSourceExclusions('ro-source', ['node|1'])
    store.setScheme('custom-scheme')
    store.setPolicy('节点选择', 'REJECT')
    store.setShowGroupEmoji(true)
    const state = useStore.getState()
    assert.equal(state.sources[0].isEnabled, true, '只读时订阅启停不应改变')
    assert.deepEqual(state.sources[0].excludedNodeKeys, [], '只读时节点排除项不应改变')
    assert.equal(state.selectedSchemeID, 'acl4ssr-online', '只读时方案选择不应改变')
    assert.equal('节点选择' in state.policySelections, false, '只读时策略选择不应写入')
    assert.equal(state.showGroupEmoji, true, '设备偏好不受只读闸门影响')
  } finally {
    setWorkspaceReadOnly(false)
  }
})

// ---------- 11b. 只读模式：逐类调用写入口，工作区与 Auth Key 缓存都不变 ----------
await checkAsync('只读模式下所有工作区写入口都无效，设备偏好仍可写', async () => {
  const { useStore } = await import('../src/store')
  const KEY_STORAGE = 'tower-web-tailnet-auth-keys'
  // 本文件前面的缓存测试已经装好了内存 localStorage；这里直接检查它的写入。
  const storage = (globalThis as unknown as { localStorage: Storage }).localStorage
  const source = {
    id: 'ro-a', name: '只读源', url: 'https://ro.example/sub',
    isEnabled: true, excludedNodeKeys: [], userAgent: '',
  }
  const node = {
    id: 'ro-n', sourceID: 'ro-a', kind: 'ss' as const, name: '只读节点',
    server: '1.2.3.4', port: 8388, cipher: 'aes-128-gcm', password: 'pw',
    tls: false, skipCertificateVerification: false, rawURI: '',
  }
  const scheme = {
    id: 'ro-scheme', name: '只读方案', description: '',
    groups: [{ name: '代理', type: 'select' as const, options: ['DIRECT'] }],
    rules: [{ type: 'FINAL' as const, group: '代理' }],
  }
  const localSet = { id: 'ro-set', name: '只读规则集', rules: [], updatedAt: 0 }
  const tailnet = { id: 'ro-t', name: '只读内网', subnets: [], isEnabled: true }
  useStore.setState({
    sources: [source],
    nodes: [node],
    customSchemes: [scheme],
    localRuleSets: [localSet],
    selectedSchemeID: 'ro-scheme',
    policySelections: { 代理: 'DIRECT' },
    exportConfigName: 'tower',
    tailnets: [tailnet],
    tailnetAuthKeys: { 'ro-t': 'tskey-original' },
    showGroupEmoji: false,
    latencyTestMode: 'tcp',
  })
  const workspaceKeys = [
    'sources', 'nodes', 'customSchemes', 'localRuleSets', 'selectedSchemeID',
    'policySelections', 'exportConfigName', 'tailnets', 'tailnetAuthKeys',
  ] as const
  const snapshot = () => {
    const state = useStore.getState() as unknown as Record<string, unknown>
    return JSON.parse(JSON.stringify(Object.fromEntries(workspaceKeys.map((key) => [key, state[key]]))))
  }
  const before = snapshot()
  const authKeysBefore = storage.getItem(KEY_STORAGE)
  const act = (label: string, run: () => unknown) => {
    const prior = snapshot()
    try { run() } catch (error) {
      throw new Error(`${label} 抛出异常：${error instanceof Error ? error.message : String(error)}`)
    }
    const now = snapshot()
    for (const key of workspaceKeys) {
      assert.deepEqual(now[key], prior[key], `只读时 ${label} 不应改动 ${key}`)
    }
  }
  setWorkspaceReadOnly(true)
  try {
    const store = useStore.getState()
    act('addSourceFromText', () => store.addSourceFromText('新源', 'ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@1.2.3.4:8388#audit'))
    act('updateSource', () => store.updateSource('ro-a', { name: '改名' }))
    act('setSourceEnabled', () => store.setSourceEnabled('ro-a', false))
    act('setSourcesEnabled', () => store.setSourcesEnabled(['ro-a'], false))
    act('setSourceExclusions', () => store.setSourceExclusions('ro-a', ['node|1']))
    act('toggleNodeExcluded', () => store.toggleNodeExcluded(node))
    act('removeSource', () => store.removeSource('ro-a'))
    act('setScheme', () => store.setScheme('ro-scheme'))
    act('setPolicy', () => store.setPolicy('代理', 'REJECT'))
    act('removePolicy', () => store.removePolicy('代理'))
    act('renamePolicySelection', () => store.renamePolicySelection('代理', '直连'))
    act('addCustomScheme', () => store.addCustomScheme({ ...scheme, id: 'ro-scheme-2' }))
    act('removeCustomScheme', () => store.removeCustomScheme('ro-scheme'))
    act('addLocalRuleSet', () => store.addLocalRuleSet({ ...localSet, id: 'ro-set-2' }))
    act('removeLocalRuleSet', () => store.removeLocalRuleSet('ro-set'))
    act('addManualNodes', () => store.addManualNodes('ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@1.2.3.4:8388#audit'))
    act('updateManualNode', () => store.updateManualNode('ro-n', { name: '改名' }))
    act('saveManualNode', () => store.saveManualNode({ ...node, name: '改名' }))
    act('removeManualNode', () => store.removeManualNode('ro-n'))
    act('setNodeCountryOverride', () => store.setNodeCountryOverride('ro-n', 'US'))
    act('setNodeDetectedCountries', () => store.setNodeDetectedCountries({ '1.2.3.4': 'JP' }))
    act('setExportConfigName', () => store.setExportConfigName('changed'))
    act('addTailnet', () => store.addTailnet({ ...tailnet, id: 'ro-t2' }))
    act('updateTailnet', () => store.updateTailnet({ ...tailnet, name: '改名' }))
    act('deleteTailnet', () => store.deleteTailnet('ro-t'))
    act('setTailnetEnabled', () => store.setTailnetEnabled('ro-t', false))
    act('setTailnetAuthKey', () => store.setTailnetAuthKey('ro-t', 'tskey-new'))
    act('pruneTailnetKeys', () => store.pruneTailnetKeys())
    act('restoreBackup', () => store.restoreBackup({
      ...before,
      sources: [...before.sources, { ...source, id: 'ro-new' }],
      nodes: [...before.nodes, { ...node, id: 'ro-new-node' }],
      exportConfigName: 'restored',
      autoRefreshOnOpen: true,
    }))
    assert.deepEqual(snapshot(), before, '只读批量调用后工作区应保持原样')
    assert.equal(storage.getItem(KEY_STORAGE), authKeysBefore, '只读时不应改写 Auth Key 的本地缓存')
    // 设备偏好不是服务端工作区数据，只读时仍要能切换。
    const state = useStore.getState()
    state.setShowGroupEmoji(true)
    state.setLatencyTestMode('icmp')
    state.setAutoRefreshOnOpen(true)
    const after = useStore.getState()
    assert.equal(after.showGroupEmoji, true)
    assert.equal(after.latencyTestMode, 'icmp')
    assert.equal(after.autoRefreshOnOpen, true)
  } finally {
    setWorkspaceReadOnly(false)
  }
})

// ---------- 12. 只读禁用态 helper ----------
await checkAsync('禁用态 helper 返回 disabled / aria-disabled 与统一提示', async () => {
  const on = writeGuard(true)
  assert.equal(on.disabled, true)
  assert.equal(on['aria-disabled'], true)
  assert.equal(on.title, READONLY_NOTE)
  const off = writeGuard(false)
  assert.equal(off.disabled, undefined)
  assert.equal(off.title, undefined)
})

// ---------- 13. 畸形 Host / 容器管理密钥 ----------
await checkAsync('畸形 Host 不崩溃；容器内伪造 Host 不能绕过管理密钥', async () => {
  const port = 20000 + Math.floor(Math.random() * 20000)
  const dataDir = mkdtempSync(join(tmpdir(), 'tower-regression-'))
  const child = spawn(process.execPath, ['server/index.mjs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '0.0.0.0',
      TOWER_DATA_DIR: dataDir,
      TOWER_CONTAINER: '1',
    },
    stdio: 'ignore',
  })
  const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
  const decodeChunked = (value: string): string => {
    if (!/^[0-9a-f]+\r\n/i.test(value)) return value
    let offset = 0
    let output = ''
    while (offset < value.length) {
      const lineEnd = value.indexOf('\r\n', offset)
      if (lineEnd < 0) break
      const size = Number.parseInt(value.slice(offset, lineEnd), 16)
      if (!Number.isFinite(size) || size <= 0) break
      offset = lineEnd + 2
      output += value.slice(offset, offset + size)
      offset += size + 2
    }
    return output
  }
  const raw = (
    path: string,
    host: string,
    address = '127.0.0.1',
    method = 'GET',
  ): Promise<{ status: number; body: string }> =>
    new Promise((resolve, reject) => {
      const socket = connect(port, address, () => {
        socket.write(`${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`)
      })
      let output = ''
      socket.on('data', (chunk) => { output += chunk })
      socket.on('error', reject)
      socket.on('close', () => {
        const statusText = output.split('\r\n')[0] ?? ''
        const status = Number(statusText.match(/ (\d{3}) /)?.[1] ?? 0)
        resolve({ status, body: decodeChunked(output.split('\r\n\r\n').slice(1).join('\r\n\r\n')) })
      })
    })
  const lan = Object.values(networkInterfaces())
    .flat()
    .find((address) => address
      && address.family === 'IPv4'
      && !address.internal
      && (/^10\./.test(address.address)
        || /^192\.168\./.test(address.address)
        || /^172\.(?:1[6-9]|2\d|3[01])\./.test(address.address)))
    ?.address
  try {
    let ready = false
    for (let index = 0; index < 60; index += 1) {
      try {
        const health = await originalFetch(`http://127.0.0.1:${port}/api/health`)
        if (health.ok) { ready = true; break }
      } catch {
        // still starting
      }
      await wait(100)
    }
    assert.ok(ready, '回归检查服务没有启动')

    const malformed = await new Promise<string>((resolve, reject) => {
      const socket = connect(port, '127.0.0.1', () => {
        socket.write('GET /api/health HTTP/1.1\r\nHost: %\r\nConnection: close\r\n\r\n')
      })
      let output = ''
      socket.on('data', (chunk) => { output += chunk })
      socket.on('error', reject)
      socket.on('close', () => resolve(output.split('\r\n')[0] ?? ''))
    })
    assert.match(malformed, /400/)
    const health = await originalFetch(`http://127.0.0.1:${port}/api/health`)
    assert.equal(health.status, 200)
    assert.equal(child.exitCode, null)

    // 输入校验：非法订阅 token 直接拒绝；请求体超过上限返回 413，
    // 而不是走到外层 catch 变成 500。
    const badToken = await originalFetch(`http://127.0.0.1:${port}/api/subscribe?token=bad`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ title: 'bad-token', formats: { base64: 'eA==' } }),
    })
    assert.equal(badToken.status, 400)
    const oversizedShare = await originalFetch(`http://127.0.0.1:${port}/api/share`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: Buffer.alloc(8 * 1024 * 1024 + 1),
    })
    assert.equal(oversizedShare.status, 413)

    if (lan) {
      // 宿主机通过 Docker 端口映射访问时是私有地址 + Host: localhost。
      const bootstrap = await raw('/api/settings', `localhost:${port}`, lan)
      assert.equal(bootstrap.status, 200)
      // 没有密钥时，不能仅凭伪造成 localhost 的 Host 头创建首个密钥，
      // 否则局域网客户端可以抢先设置密钥并接管实例。
      const preToken = await raw('/api/settings/token', `localhost:${port}`, lan, 'POST')
      assert.equal(preToken.status, 403)
      assert.match(preToken.body, /local_only/)
      const token = await originalFetch(`http://127.0.0.1:${port}/api/settings/token`, { method: 'POST' })
        .then((response) => response.json() as Promise<{ apiToken?: string }>)
        .then((body) => body.apiToken ?? '')
      assert.ok(token.length >= 16)
      // 局域网客户端伪造 Host: localhost 但没带密钥 → 401，且响应里没有密钥。
      const spoofed = await raw('/api/settings', `localhost:${port}`, lan)
      assert.equal(spoofed.status, 401)
      assert.equal(spoofed.body.includes(token), false)
      const spoofedStatus = JSON.parse((await raw('/api/auth-status', `localhost:${port}`, lan)).body) as {
        local?: boolean
        valid?: boolean
        requiresAuth?: boolean
      }
      assert.equal(spoofedStatus.requiresAuth, true)
      assert.equal(spoofedStatus.local, false)
      assert.equal(spoofedStatus.valid, false)
      // 真正的宿主机页面会用已保存的密钥访问设置。
      const authorized = await raw(`/api/settings?key=${encodeURIComponent(token)}`, `localhost:${port}`, lan)
      assert.equal(authorized.status, 200)
      assert.equal(authorized.body.includes(token), true)
      // 即便伪造 Host，管理 API 仍要求密钥。
      const network = await raw('/api/network', `localhost:${port}`, lan)
      assert.equal(network.status, 401)
      const networkAuthorized = await raw(`/api/network?key=${encodeURIComponent(token)}`, `localhost:${port}`, lan)
      assert.equal(networkAuthorized.status, 200)
      // 关闭共享后，即使 Host 头伪造成 localhost，也只保留恢复设置所需的端点。
      const disable = await originalFetch(`http://127.0.0.1:${port}/api/settings`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ lanSharing: false }),
      })
      assert.equal(disable.status, 200)
      const blockedNetwork = await raw(`/api/network?key=${encodeURIComponent(token)}`, `localhost:${port}`, lan)
      assert.equal(blockedNetwork.status, 403)
      const blockedRuleset = await raw(
        '/api/ruleset?format=mrs&behavior=domain&file=ACL4SSR_Apple.list',
        `localhost:${port}`,
        lan,
      )
      assert.equal(blockedRuleset.status, 403)
      const recovery = await raw(`/api/settings?key=${encodeURIComponent(token)}`, `localhost:${port}`, lan)
      assert.equal(recovery.status, 200)
    } else {
      console.log('… 没有私有局域网地址，跳过容器 Host 鉴权检查')
    }
  } finally {
    child.kill()
    await wait(300)
    if (child.exitCode === null) child.kill('SIGKILL')
    rmSync(dataDir, { recursive: true, force: true })
    globalThis.fetch = originalFetch
    if (originalWindow === undefined) delete (globalThis as unknown as { window?: unknown }).window
    else (globalThis as unknown as { window: unknown }).window = originalWindow
    if (originalLocalStorage === undefined) delete (globalThis as unknown as { localStorage?: unknown }).localStorage
    else (globalThis as unknown as { localStorage: unknown }).localStorage = originalLocalStorage
  }
})

// ---------- 12. 订阅套餐信息解析 ----------
const GB = 1024 ** 3

check('订阅配额：响应头 / STATUS / TRAFFIC / 正文 key=value 都能解析', () => {
  const header = parseUserinfoHeader(
    'upload=1048576; download=10737418240; total=107374182400; expire=0',
  )
  assert.ok(header)
  assert.equal(header.expire, 0, 'expire=0 应保留为「长期有效」')
  assert.equal(header.total, 107374182400)
  assert.equal(header.upload, 1048576)

  // 面板实现差异：expire 可能是毫秒或 ISO 日期，字节数可能带单位。
  const millis = parseUserinfoHeader(
    'upload=1048576; download=10737418240; total=107374182400; expire=1798761600000',
  )
  assert.ok(millis)
  assert.equal(millis.expire, 1798761600, '毫秒应归一到秒')
  assert.equal(usageFieldsFrom(millis).expireAt, 1798761600000)

  const iso = parseUserinfoHeader('total=1GB; expire=2027-01-01')
  assert.ok(iso)
  assert.equal(iso.total, GB)
  assert.equal(iso.expire, new Date(2027, 0, 1).getTime() / 1000)

  const status = parseStatusLine('STATUS=↑:1.2GB ↓:34GB TOT:500GB EXPIRES:2027-01-01')
  assert.ok(status)
  assert.equal(status.upload, Math.floor(1.2 * GB))
  assert.equal(status.download, 34 * GB)
  assert.equal(status.total, 500 * GB)
  assert.equal(status.expire, new Date(2027, 0, 1).getTime() / 1000)

  const traffic = parseStatusLine('TRAFFIC=upload=1.2GB; download=34GB; total=500GB; expire=2027-01-01')
  assert.ok(traffic)
  assert.equal(traffic.total, 500 * GB)
  assert.equal(traffic.expire, new Date(2027, 0, 1).getTime() / 1000)

  const declared = parseUsageDeclaration('upload=1GB\n download=2GB\n total=100GB\nexpire=0')
  assert.ok(declared)
  assert.equal(declared.upload, GB)
  assert.equal(declared.download, 2 * GB)
  assert.equal(declared.expire, 0)

  const auth = Buffer.from('aes-256-gcm:pass').toString('base64').replace(/=+$/, '')
  const parsed = parse(
    'upload=1GB; download=2GB; total=100GB; expire=2027-01-01\n'
    + `ss://${auth}@1.2.3.4:8388#Quota-Node`,
  )
  assert.equal(parsed.nodes.length, 1)
  assert.ok(parsed.status)
  assert.equal(parsed.status.total, 100 * GB)

  // 节点 URI 里的 total= 参数不能被当成套餐信息。
  const withParam = parse(
    'vless://11111111-2222-3333-4444-555555555555@v.example.com:443'
    + '?encryption=none&security=tls&type=ws&path=%2Ftotal%3D1GB#Param-Nodel',
  )
  assert.equal(withParam.status, undefined)
})

// ---------- 13. 剩余流量 / 到期计算 ----------
check('剩余流量、到期天数、低流量与旧快照兼容', () => {
  const now = Date.UTC(2026, 10, 3)
  const expire = (now + 3 * 86_400_000) / 1000
  const usage = {
    upload: 10 * GB,
    download: 81 * GB,
    total: 100 * GB,
    expire,
  }
  const fields = usageFieldsFrom(usage)
  assert.equal(fields.totalBytes, 100 * GB)
  assert.equal(fields.usedBytes, 91 * GB)
  assert.equal(fields.expireAt, now + 3 * 86_400_000)

  const summary = subscriptionUsageSummary({ usage }, now)
  assert.equal(summary.remainingBytes, 9 * GB)
  assert.equal(summary.remainingRatio, 0.09)
  assert.equal(summary.lowTraffic, true)
  assert.equal(summary.daysUntilExpiry, 3)
  assert.equal(summary.expired, false)
  assert.equal(summary.longTerm, false)

  // 恰好 10% 不算低流量（需求是 <10%）。
  const boundary = subscriptionUsageSummary({
    totalBytes: 100 * GB,
    usedBytes: 90 * GB,
    expireAt: now + 8 * 86_400_000,
  }, now)
  assert.equal(boundary.remainingRatio, 0.1)
  assert.equal(boundary.lowTraffic, false)
  assert.equal(boundary.daysUntilExpiry, 8)

  const expired = subscriptionUsageSummary({ expireAt: now - 1 }, now)
  assert.equal(expired.expired, true)
  assert.equal(expired.daysUntilExpiry, 0)

  const longTerm = subscriptionUsageSummary({ usage: { expire: 0 } }, now)
  assert.equal(longTerm.longTerm, true)
  assert.equal(longTerm.expired, false)
  assert.equal(longTerm.daysUntilExpiry, undefined)

  const unknown = subscriptionUsageSummary({}, now)
  assert.equal(unknown.totalBytes, undefined)
  assert.equal(unknown.usedBytes, undefined)
  assert.equal(unknown.remainingBytes, undefined)
  assert.equal(unknown.expireAt, undefined)

  // 新字段优先，旧快照只有 usage 时自动回退。
  const priority = subscriptionUsageSummary({
    usage: { total: 100 * GB, upload: 1 },
    totalBytes: 50 * GB,
    usedBytes: 5 * GB,
    expireAt: 0,
  }, now)
  assert.equal(priority.totalBytes, 50 * GB)
  assert.equal(priority.usedBytes, 5 * GB)
  assert.equal(priority.longTerm, true)
})

// ---------- 14. 协议传输层 / UDP 能力映射 ----------
check('协议传输层与 UDP 转发能力映射', () => {
  const node = (patch: Partial<ProxyNode>): ProxyNode => ({
    ...base,
    id: patch.kind ?? 'cap',
    kind: 'ss',
    name: 'cap',
    server: 'cap.example.com',
    port: 443,
    ...patch,
  })

  const hy2 = nodeTransportCapability(node({ kind: 'hysteria2' }))
  assert.equal(hy2.transport, 'quic')
  assert.equal(hy2.probeMethod, 'icmp')
  assert.equal(hy2.udpForwarding, 'supported')

  assert.equal(nodeTransportCapability(node({ kind: 'tuic' })).transport, 'quic')
  assert.equal(nodeTransportCapability(node({ kind: 'wireguard' })).transport, 'udp')
  assert.equal(nodeTransportCapability(node({ kind: 'wireguard' })).probeMethod, 'icmp')

  assert.equal(nodeTransportCapability(node({
    kind: 'masque',
    masque: { mode: 'basicConnectIP', httpVersion: 3 },
  })).transport, 'quic')
  assert.equal(nodeTransportCapability(node({
    kind: 'masque',
    masque: { mode: 'basicConnectIP', httpVersion: 2 },
  })).transport, 'tcp')

  assert.equal(nodeTransportCapability(node({
    kind: 'trusttunnel',
    trustTunnel: { quic: true },
  })).transport, 'quic')
  assert.equal(nodeTransportCapability(node({
    kind: 'trusttunnel',
    trustTunnel: { quic: false },
  })).transport, 'tcp')

  assert.equal(nodeTransportCapability(node({ kind: 'ss' })).udpForwarding, 'supported')
  assert.equal(nodeTransportCapability(node({
    kind: 'ss',
    plugin: 'v2ray-plugin',
  })).udpForwarding, 'unknown')
  assert.equal(nodeTransportCapability(node({
    kind: 'snell',
    version: 2,
  })).udpForwarding, 'unsupported')
  assert.equal(nodeTransportCapability(node({
    kind: 'snell',
    version: 3,
  })).udpForwarding, 'supported')
  assert.equal(nodeTransportCapability(node({ kind: 'http' })).udpForwarding, 'unsupported')
  assert.equal(nodeTransportCapability(node({
    kind: 'vmess',
    transport: 'quic',
  })).transport, 'quic')
  assert.equal(nodeTransportCapability(node({
    kind: 'hysteria2',
    udpRelayEnabled: false,
  })).udpForwarding, 'unsupported')
})

// ---------- 8. base64 包裹的配置与节点重名 ----------
check('base64 包裹的 Clash YAML 会被解码后解析', () => {
  const yaml = [
    'mixed-port: 7890',
    'proxies:',
    '  - name: HK',
    '    type: ss',
    '    server: hk.example.com',
    '    port: 8388',
    '    cipher: aes-128-gcm',
    '    password: pw',
    '',
  ].join('\n')
  const parsed = parse(Buffer.from(yaml, 'utf8').toString('base64'))
  assert.equal(parsed.nodes.length, 1)
  assert.equal(parsed.nodes[0].kind, 'ss')
})

check('base64 包裹的 Surge 配置（首行是注释）会被解码后解析', () => {
  const surge = [
    '#!MANAGED-CONFIG',
    '[General]',
    'loglevel = notify',
    '[Proxy]',
    'HK = ss, 1.2.3.4, 8388, encrypt-method=aes-128-gcm, password=pw',
    '',
  ].join('\n')
  const parsed = parse(Buffer.from(surge, 'utf8').toString('base64'))
  assert.equal(parsed.nodes.length, 1)
  assert.equal(parsed.nodes[0].name, 'HK')
})

check('重名补丁不会让本身带后缀的节点与其他节点重名', () => {
  const nodes = [
    { ...base, id: 'n1', kind: 'ss', name: 'A', server: 'a.example.com', port: 1, password: 'p' },
    { ...base, id: 'n2', kind: 'ss', name: 'A 2', server: 'b.example.com', port: 1, password: 'p' },
    { ...base, id: 'n3', kind: 'ss', name: 'A', server: 'c.example.com', port: 1, password: 'p' },
  ] as ProxyNode[]
  const names = uniqueDisplayNames(nodes, (value) => value, (node) => node.name)
  const values = nodes.map((node) => names.get(node.id))
  assert.deepEqual(values, ['A', 'A 2', 'A 3'])
  assert.equal(new Set(values).size, values.length)
})

check('localStorage 配额满时写入不抛异常，并通知界面一次', () => {
  const changes: boolean[] = []
  const off = onStorageFullChange((value) => changes.push(value))
  const storage = {
    getItem: () => null,
    setItem: (_name: string, value: string) => {
      if (value.length > 200) {
        const error = new Error('quota exceeded')
        error.name = 'QuotaExceededError'
        throw error
      }
    },
    removeItem: () => {},
  }
  const safe = createSafeStorage(() => storage)
  assert.doesNotThrow(() => safe.setItem('tower-web-state', 'x'.repeat(1000)))
  assert.equal(isStorageFull(), true)
  assert.doesNotThrow(() => safe.setItem('tower-web-state', 'small'))
  assert.equal(isStorageFull(), false)
  assert.deepEqual(changes, [true, false])
  off()
})

check('重置只清理塔台的 localStorage 键，保留同源其它应用数据', () => {
  const memory = new Map<string, string>([
    ['tower-web-state', '{"sources":[]}'],
    ['tower-sub-token', 'abc'],
    ['tower-renewal-notified:1:2026-11-04', '1'],
    ['other-app-prefs', 'keep-me'],
    ['unrelated', 'keep-too'],
  ])
  const snapshot = () => {
    const keys = [...memory.keys()]
    return {
      length: keys.length,
      key: (index: number) => keys[index] ?? null,
      removeItem: (name: string) => { memory.delete(name) },
    }
  }
  const removed = clearTowerStorage(snapshot())
  assert.deepEqual(removed.sort(), [
    'tower-renewal-notified:1:2026-11-04',
    'tower-sub-token',
    'tower-web-state',
  ])
  assert.equal(memory.get('other-app-prefs'), 'keep-me')
  assert.equal(memory.get('unrelated'), 'keep-too')
})

check('旧快照只有部分 networkSettings 时生成器不崩，缺失项回落到默认值', () => {
  const partial = { encryptedDNSServers: ['https://dns.alidns.com/dns-query'] } as Parameters<typeof effectiveNetworkSettings>[0]
  const settings = effectiveNetworkSettings(partial)
  assert.ok(settings.dnsServers.length > 0, '缺少 dnsServers 时应回落到默认值')
  assert.deepEqual(settings.encryptedDNSServers, ['https://dns.alidns.com/dns-query'])
  assert.ok(settings.remoteDNSServers.length > 0)
})

check('Clash 导入 hysteria2 / tuic / anytls 时补回隐式 TLS', () => {
  const text = [
    'proxies:',
    '  - {name: h2, type: hysteria2, server: h2.example.com, port: 443, password: pw}',
    '  - {name: tu, type: tuic, server: tu.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, password: pw}',
    '  - {name: any, type: anytls, server: any.example.com, port: 443, password: pw}',
  ].join('\n')
  const nodes = parseClashYAML(text).nodes
  assert.equal(nodes.length, 3)
  for (const node of nodes) assert.equal(node.tls, true, `${node.name} 应识别为 TLS`)
})

// ---------- 15. sing-box / Hiddify JSON 全协议导入往返 ----------
const jsonNode = (patch: Partial<ProxyNode>): ProxyNode => ({
  ...base,
  id: `json-${patch.name ?? 'node'}`,
  kind: 'ss',
  name: 'node',
  server: 'node.example.com',
  port: 443,
  ...patch,
})

const JSON_NODES: ProxyNode[] = [
  jsonNode({ name: 'SS', kind: 'ss', server: 'ss.example.com', port: 8388, cipher: 'aes-256-gcm', password: 'ss-pass' }),
  jsonNode({
    name: 'SS-V2', kind: 'ss', server: 'ssv2.example.com', port: 443, cipher: 'aes-128-gcm', password: 'v2-pass',
    plugin: 'v2ray-plugin', transport: 'ws', pluginMux: true, tls: true, path: '/ssws', hostHeader: 'ss.host',
  }),
  jsonNode({
    name: 'SS-OBFS', kind: 'ss', server: 'obfs.example.com', port: 8388, cipher: 'aes-128-gcm', password: 'obfs-pass',
    obfs: 'http', obfsParam: 'obfs.host',
  }),
  jsonNode({
    name: 'SS-STLS', kind: 'ss', server: 'stls.example.com', port: 443, cipher: 'aes-256-gcm', password: 'outer-pass',
    plugin: 'shadow-tls', shadowTLS: { version: 3, host: 'shadow.host', password: 'inner-pass', skipCertificateVerification: true },
    fingerprint: 'chrome',
  }),
  jsonNode({
    name: 'VM', kind: 'vmess', server: 'vm.example.com', cipher: 'aes-128-gcm',
    uuid: '11111111-2222-3333-4444-555555555555', alterID: 0, tls: true, sni: 'vm.example.com',
    skipCertificateVerification: true, alpn: 'h2,http/1.1', transport: 'ws', path: '/vm', hostHeader: 'vm.host',
  }),
  jsonNode({
    name: 'VM-HTTP', kind: 'vmess', server: 'vmh.example.com', cipher: 'auto',
    uuid: '44444444-5555-6666-7777-888888888888', transport: 'http', path: '/h2', hostHeader: 'h2.host',
  }),
  jsonNode({
    name: 'VM-HU', kind: 'vmess', server: 'vmhu.example.com', cipher: 'auto',
    uuid: '55555555-6666-7777-8888-999999999999', transport: 'httpupgrade', path: '/hu', hostHeader: 'hu.host',
  }),
  jsonNode({
    name: 'VM-QUIC', kind: 'vmess', server: 'vmq.example.com', cipher: 'auto',
    uuid: '66666666-7777-8888-9999-aaaaaaaaaaaa', transport: 'quic',
  }),
  jsonNode({
    name: 'VL', kind: 'vless', server: 'vl.example.com',
    uuid: '22222222-3333-4444-5555-666666666666', flow: 'xtls-rprx-vision', tls: true, sni: 'vl.example.com',
    realityPublicKey: 'reality-pub', realityShortID: 'abcd', fingerprint: 'chrome', transport: 'grpc', path: 'vl-grpc',
  }),
  jsonNode({
    name: 'TR', kind: 'trojan', server: 'tr.example.com', password: 'tr-pass', tls: true, sni: 'tr.example.com',
    transport: 'ws', path: '/tr', hostHeader: 'tr.host',
  }),
  jsonNode({
    name: 'HY2', kind: 'hysteria2', server: 'hy2.example.com', password: 'hy2-pass', tls: true, sni: 'hy2.example.com',
    skipCertificateVerification: true, obfs: 'salamander', obfsParam: 'obfs-pass', upMbps: 50, downMbps: 200,
    portHopping: '443,5000-6000',
  }),
  jsonNode({
    name: 'HY1', kind: 'hysteria', server: 'hy1.example.com', password: 'hy1-pass', tls: true, sni: 'hy1.example.com',
    obfs: 'http', upMbps: 30, downMbps: 100,
  }),
  jsonNode({
    name: 'TU', kind: 'tuic', server: 'tu.example.com', uuid: '33333333-4444-5555-6666-777777777777',
    password: 'tu-pass', congestionControl: 'bbr', udpRelayMode: 'native', tls: true, sni: 'tu.example.com', alpn: 'h3',
  }),
  jsonNode({
    name: 'ANY', kind: 'anytls', server: 'any.example.com', password: 'any-pass', tls: true, sni: 'any.example.com',
    idleSessionCheckInterval: 30, idleSessionTimeout: 60, minIdleSession: 5,
  }),
  jsonNode({
    name: 'SSH', kind: 'ssh', server: 'ssh.example.com', port: 22, username: 'root', password: 'ssh-pass',
    ssh: { privateKey: 'ssh-private-key', hostKeys: ['ssh-ed25519 AAAA'], hostKeyAlgorithms: ['ssh-ed25519'] },
  }),
  jsonNode({
    name: 'SNELL', kind: 'snell', server: 'snell.example.com', password: 'snell-psk', version: 4,
    obfs: 'http', obfsParam: 'snell.host',
  }),
  jsonNode({ name: 'SOCKS', kind: 'socks5', server: 'socks.example.com', port: 1080, username: 'u', password: 'p' }),
  jsonNode({ name: 'HTTPP', kind: 'http', server: 'http.example.com', port: 8080, username: 'u', password: 'p', tls: true, sni: 'http.example.com' }),
  jsonNode({
    name: 'WG', kind: 'wireguard', server: 'wg.example.com', port: 51820,
    wireGuardPrivateKey: 'wg-private', wireGuardPublicKey: 'wg-public', wireGuardPreSharedKey: 'wg-psk',
    wireGuardIPv4: '10.0.0.2', wireGuardIPv6: 'fd00::2', wireGuardAllowedIPs: '0.0.0.0/0,::/0',
    wireGuardReserved: '1,2,3', wireGuardMTU: 1420, wireGuardPersistentKeepalive: 30,
  }),
  jsonNode({
    name: 'MASQUE', kind: 'masque', server: 'masque.example.com', port: 443, tls: true, sni: 'masque.example.com',
    alpn: 'h3', username: 'u', password: 'p', path: '/masque',
    masque: {
      mode: 'basicConnectIP', httpVersion: 3, mtu: 1400, headers: { 'X-Test': '1' },
      certificate: ['-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'],
    },
  }),
]

check('sing-box JSON 全协议导出后能读回，关键字段不丢', () => {
  const generated = generateSingBox(JSON_NODES, SCHEME, { target: 'sing-box', contentMode: 'nodes' })
  assert.equal(generated.skipped, 0)
  const imported = parse(generated.text)
  assert.equal(imported.nodes.length, JSON_NODES.length)
  assert.equal(imported.rejectedLineCount, 0)

  const ss = byName(imported.nodes, 'SS')
  assert.equal(ss.cipher, 'aes-256-gcm')
  assert.equal(ss.password, 'ss-pass')
  const v2 = byName(imported.nodes, 'SS-V2')
  assert.equal(v2.plugin, 'v2ray-plugin')
  assert.equal(v2.transport, 'ws')
  assert.equal(v2.path, '/ssws')
  assert.equal(v2.hostHeader, 'ss.host')
  assert.equal(v2.pluginMux, true)
  assert.equal(v2.tls, true)
  const obfs = byName(imported.nodes, 'SS-OBFS')
  assert.equal(obfs.plugin, 'obfs-local')
  assert.equal(obfs.obfs, 'http')
  assert.equal(obfs.obfsParam, 'obfs.host')
  const stls = byName(imported.nodes, 'SS-STLS')
  assert.equal(stls.plugin, 'shadow-tls')
  assert.deepEqual(stls.shadowTLS, {
    version: 3, host: 'shadow.host', password: 'inner-pass', skipCertificateVerification: true,
  })
  assert.equal(stls.fingerprint, 'chrome')
  // ShadowTLS 辅助出站不能被当成独立节点。
  assert.equal(imported.nodes.some((node) => node.name.startsWith('tower-shadowtls')), false)

  const vm = byName(imported.nodes, 'VM')
  assert.equal(vm.uuid, '11111111-2222-3333-4444-555555555555')
  assert.equal(vm.cipher, 'aes-128-gcm')
  assert.equal(vm.alterID, 0)
  assert.equal(vm.tls, true)
  assert.equal(vm.sni, 'vm.example.com')
  assert.equal(vm.skipCertificateVerification, true)
  assert.equal(vm.alpn, 'h2,http/1.1')
  assert.equal(vm.transport, 'ws')
  assert.equal(vm.path, '/vm')
  assert.equal(vm.hostHeader, 'vm.host')

  const http2 = byName(imported.nodes, 'VM-HTTP')
  assert.equal(http2.transport, 'http')
  assert.equal(http2.path, '/h2')
  assert.equal(http2.hostHeader, 'h2.host')
  const upgrade = byName(imported.nodes, 'VM-HU')
  assert.equal(upgrade.transport, 'httpupgrade')
  assert.equal(upgrade.path, '/hu')
  assert.equal(upgrade.hostHeader, 'hu.host')
  const quic = byName(imported.nodes, 'VM-QUIC')
  assert.equal(quic.transport, 'quic')

  const vl = byName(imported.nodes, 'VL')
  assert.equal(vl.uuid, '22222222-3333-4444-5555-666666666666')
  assert.equal(vl.flow, 'xtls-rprx-vision')
  assert.equal(vl.realityPublicKey, 'reality-pub')
  assert.equal(vl.realityShortID, 'abcd')
  assert.equal(vl.fingerprint, 'chrome')
  assert.equal(vl.transport, 'grpc')
  assert.equal(vl.path, 'vl-grpc')

  const tr = byName(imported.nodes, 'TR')
  assert.equal(tr.password, 'tr-pass')
  assert.equal(tr.tls, true)
  assert.equal(tr.sni, 'tr.example.com')
  assert.equal(tr.transport, 'ws')
  assert.equal(tr.path, '/tr')
  assert.equal(tr.hostHeader, 'tr.host')

  const hy2 = byName(imported.nodes, 'HY2')
  assert.equal(hy2.password, 'hy2-pass')
  assert.equal(hy2.tls, true)
  assert.equal(hy2.obfs, 'salamander')
  assert.equal(hy2.obfsParam, 'obfs-pass')
  assert.equal(hy2.upMbps, 50)
  assert.equal(hy2.downMbps, 200)
  assert.equal(hy2.portHopping, '443,5000-6000')

  const hy1 = byName(imported.nodes, 'HY1')
  assert.equal(hy1.password, 'hy1-pass')
  assert.equal(hy1.obfs, 'http')
  assert.equal(hy1.upMbps, 30)
  assert.equal(hy1.downMbps, 100)

  const tu = byName(imported.nodes, 'TU')
  assert.equal(tu.uuid, '33333333-4444-5555-6666-777777777777')
  assert.equal(tu.password, 'tu-pass')
  assert.equal(tu.congestionControl, 'bbr')
  assert.equal(tu.udpRelayMode, 'native')
  assert.equal(tu.alpn, 'h3')

  const any = byName(imported.nodes, 'ANY')
  assert.equal(any.password, 'any-pass')
  assert.equal(any.idleSessionCheckInterval, 30)
  assert.equal(any.idleSessionTimeout, 60)
  assert.equal(any.minIdleSession, 5)

  const ssh = byName(imported.nodes, 'SSH')
  assert.equal(ssh.username, 'root')
  assert.equal(ssh.password, 'ssh-pass')
  assert.equal(ssh.ssh?.privateKey, 'ssh-private-key')
  assert.deepEqual(ssh.ssh?.hostKeys, ['ssh-ed25519 AAAA'])
  assert.deepEqual(ssh.ssh?.hostKeyAlgorithms, ['ssh-ed25519'])

  const snell = byName(imported.nodes, 'SNELL')
  assert.equal(snell.password, 'snell-psk')
  assert.equal(snell.version, 4)
  assert.equal(snell.obfs, 'http')
  assert.equal(snell.obfsParam, 'snell.host')

  const socks = byName(imported.nodes, 'SOCKS')
  assert.equal(socks.username, 'u')
  assert.equal(socks.password, 'p')
  const http = byName(imported.nodes, 'HTTPP')
  assert.equal(http.tls, true)
  assert.equal(http.sni, 'http.example.com')

  const wg = byName(imported.nodes, 'WG')
  assert.equal(wg.wireGuardPrivateKey, 'wg-private')
  assert.equal(wg.wireGuardPublicKey, 'wg-public')
  assert.equal(wg.wireGuardPreSharedKey, 'wg-psk')
  assert.equal(wg.wireGuardIPv4, '10.0.0.2')
  assert.equal(wg.wireGuardIPv6, 'fd00::2')
  assert.equal(wg.wireGuardAllowedIPs, '0.0.0.0/0,::/0')
  assert.equal(wg.wireGuardReserved, '1,2,3')
  assert.equal(wg.wireGuardMTU, 1420)
  assert.equal(wg.wireGuardPersistentKeepalive, 30)

  const masque = byName(imported.nodes, 'MASQUE')
  assert.equal(masque.tls, true)
  assert.equal(masque.sni, 'masque.example.com')
  assert.equal(masque.alpn, 'h3')
  assert.equal(masque.username, 'u')
  assert.equal(masque.path, '/masque')
  assert.equal(masque.masque?.httpVersion, 3)
  assert.equal(masque.masque?.mtu, 1400)
  assert.deepEqual(masque.masque?.headers, { 'X-Test': '1' })
  assert.deepEqual(masque.masque?.certificate, JSON_NODES.at(-1)!.masque!.certificate)
})

check('Hiddify JSON 往返：legacy WireGuard、隐藏 ShadowTLS 辅助出站', () => {
  const hiddifyNodes = JSON_NODES.filter((node) => node.kind !== 'masque' && node.kind !== 'snell')
  const generated = generateSingBox(hiddifyNodes, SCHEME, { target: 'hiddify', contentMode: 'nodes' })
  assert.equal(generated.skipped, 0)
  const imported = parse(generated.text)
  assert.equal(imported.nodes.length, hiddifyNodes.length)
  assert.equal(imported.rejectedLineCount, 0)
  assert.equal(imported.nodes.some((node) => node.name.startsWith('§hide§')), false)
  assert.equal(imported.nodes.some((node) => node.name.startsWith('tower-shadowtls')), false)

  const wg = byName(imported.nodes, 'WG')
  assert.equal(wg.server, 'wg.example.com')
  assert.equal(wg.port, 51820)
  assert.equal(wg.wireGuardPrivateKey, 'wg-private')
  assert.equal(wg.wireGuardPublicKey, 'wg-public')
  assert.equal(wg.wireGuardIPv4, '10.0.0.2')
  assert.equal(wg.wireGuardReserved, '1,2,3')
  const stls = byName(imported.nodes, 'SS-STLS')
  assert.equal(stls.shadowTLS?.host, 'shadow.host')
  assert.equal(stls.shadowTLS?.password, 'inner-pass')
  const hy2 = byName(imported.nodes, 'HY2')
  assert.equal(hy2.portHopping, '443,5000-6000')
  assert.equal(hy2.obfsParam, 'obfs-pass')
})

check('sing-box JSON 异常输入给出可读原因，不静默返回 0 节点', () => {
  const array = parse('[1,2,3]')
  assert.equal(array.nodes.length, 0)
  assert.match(array.reason ?? '', /JSON 数组/)

  const empty = parse('{"outbounds":[]}')
  assert.equal(empty.nodes.length, 0)
  assert.match(empty.reason ?? '', /为空/)

  const noOutbounds = parse('{"inbounds":[],"route":{}}')
  assert.match(noOutbounds.reason ?? '', /缺少有效的 outbounds/)

  const unsupported = parse(JSON.stringify({
    outbounds: [
      { type: 'selector', tag: 'group', outbounds: ['a'] },
      { type: 'naive', tag: 'NAIVE', server: 'naive.example.com', server_port: 443 },
    ],
  }))
  assert.equal(unsupported.nodes.length, 0)
  assert.match(unsupported.reason ?? '', /不支持的出站类型：naive/)
  assert.equal(unsupported.rejectedLineCount, 1)

  const missing = parse(JSON.stringify({
    outbounds: [{ type: 'vmess', tag: 'VM', server: 'vm.example.com', server_port: 443 }],
  }))
  assert.match(missing.reason ?? '', /vmess 缺少 uuid/)

  // 完整配置对象 + Hiddify 的 `/` 结尾 tag：组和内置出站跳过，不计数为失败。
  const full = parse(JSON.stringify({
    log: { level: 'info' },
    inbounds: [],
    route: {},
    outbounds: [
      { type: 'selector', tag: 'group', outbounds: ['HK', 'direct'] },
      { type: 'shadowsocks', tag: 'US/JP 02/', server: 'hk.example.com', server_port: 8388, method: 'aes-128-gcm', password: 'pw' },
      { type: 'direct', tag: 'direct' },
    ],
  }))
  assert.equal(full.nodes.length, 1)
  assert.equal(full.nodes[0].name, 'US/JP 02')
  assert.equal(full.rejectedLineCount, 0)

  // 同服务器不同凭据不能被误判为重复。
  const multiUser = parse(JSON.stringify({
    outbounds: [
      { type: 'shadowsocks', tag: 'A', server: 'same.example.com', server_port: 8388, method: 'aes-128-gcm', password: 'one' },
      { type: 'shadowsocks', tag: 'B', server: 'same.example.com', server_port: 8388, method: 'aes-128-gcm', password: 'two' },
    ],
  }))
  assert.equal(multiUser.nodes.length, 2)

  // 第三方配置的多余字段（max_early_data、utls）不应导致整条出站被拒。
  const thirdParty = parse(JSON.stringify({
    outbounds: [{
      type: 'vless', tag: 'VLESS-X', server: 'x.example.com', server_port: 443,
      uuid: '77777777-8888-9999-aaaa-bbbbbbbbbbbb',
      tls: {
        enabled: true, server_name: 'x.example.com',
        utls: { enabled: true, fingerprint: 'chrome' },
        reality: { enabled: true, public_key: 'pk', short_id: 'sid' },
      },
      transport: { type: 'ws', path: '/ws', headers: { Host: 'cdn.example.com' }, max_early_data: 2048 },
    }],
  }))
  assert.equal(thirdParty.nodes.length, 1)
  assert.equal(thirdParty.nodes[0].sni, 'x.example.com')
  assert.equal(thirdParty.nodes[0].realityPublicKey, 'pk')
  assert.equal(thirdParty.nodes[0].realityShortID, 'sid')
  assert.equal(thirdParty.nodes[0].fingerprint, 'chrome')
  assert.equal(thirdParty.nodes[0].transport, 'ws')
  assert.equal(thirdParty.nodes[0].path, '/ws')
  assert.equal(thirdParty.nodes[0].hostHeader, 'cdn.example.com')

  // 顶层是出站数组时也能导入。
  const list = parse(JSON.stringify([
    { type: 'trojan', tag: 'TR', server: 'tr.example.com', server_port: 443, password: 'pw' },
  ]))
  assert.equal(list.nodes.length, 1)
  assert.equal(list.nodes[0].kind, 'trojan')
})

if (failures) {
  console.error(`\n${failures} 项回归检查失败`)
  process.exit(1)
}
console.log('\n全部审计回归检查通过')
