// 自检：Surge 测试版分档与 Anywhere AJSON。
// 用法：npm run selfcheck:surge-anywhere
import assert from 'node:assert/strict'
import type { ProxyNode, RuleScheme } from '../src/models/types'
import { generateSurge } from '../src/generator/surge'
import { anywhereAjsonDocument, anywhereAjsonCount } from '../src/generator/anywhere'
import {
  SURGE_TIER_BUILDS,
  surgeAcceptsVLESS,
  surgeAcceptsVLESSEncryption,
  surgeTierFromUserAgent,
} from '../src/generator/surgeCapabilities'
// 服务端有一份独立的 .mjs；两边门槛必须一致。
import {
  SURGE_TIER_BUILDS as SERVER_BUILDS,
  acceptsAnywhereAjson,
  surgeTierFromUserAgent as serverSurgeTier,
  surgeVariantFor,
} from '../server/surge-capabilities.mjs'

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

function node(overrides: Partial<ProxyNode>): ProxyNode {
  return {
    id: overrides.id ?? 'node',
    kind: 'vless',
    name: overrides.name ?? 'VLESS',
    server: 'example.com',
    port: 443,
    uuid: '11111111-1111-4111-8111-111111111111',
    tls: true,
    skipCertificateVerification: false,
    ...overrides,
  } as ProxyNode
}

const scheme = {
  id: 'selfcheck',
  name: '自检',
  description: '',
  groups: [{ name: '节点选择', type: 'select', options: ['DIRECT'] }],
  rules: [{ type: 'FINAL', group: '节点选择' }],
  customRules: [],
  matchingOrder: ['节点选择'],
} as unknown as RuleScheme

function surge(nodes: ProxyNode[], tier?: 1 | 2 | 3): string {
  return generateSurge(nodes, scheme, { target: 'surge', contentMode: 'full', surgeTier: tier }).text
}

check('前后端 Surge 构建号门槛一致', () => {
  assert.deepEqual(SURGE_TIER_BUILDS, SERVER_BUILDS)
})

check('User-Agent 构建号分档：iOS / Mac 三档', () => {
  assert.equal(surgeTierFromUserAgent('Surge iOS/4023 SurgeCore/6011000'), undefined)
  assert.deepEqual(surgeTierFromUserAgent('Surge iOS/4024 SurgeCore/6011000'), { platform: 'surge', tier: 1 })
  assert.deepEqual(surgeTierFromUserAgent('Surge iOS/4026 SurgeCore/6011000'), { platform: 'surge', tier: 2 })
  assert.deepEqual(surgeTierFromUserAgent('Surge iOS/4027 SurgeCore/6011000'), { platform: 'surge', tier: 3 })
  assert.deepEqual(surgeTierFromUserAgent('Surge Mac/12820 SurgeCore/6012000'), { platform: 'surge-mac', tier: 1 })
  assert.deepEqual(surgeTierFromUserAgent('Surge Mac/12860 SurgeCore/6012000'), { platform: 'surge-mac', tier: 3 })
  assert.equal(surgeTierFromUserAgent('Clash/1.19.0'), undefined)
  assert.deepEqual(surgeTierFromUserAgent('Surge iOS/4027'), serverSurgeTier('Surge iOS/4027'))
})

check('VLESS 基线不写、tier1 写 RAW/TLS，Encryption/XHTTP 从 tier2 开始', () => {
  const raw = node({ id: 'raw' })
  assert.doesNotMatch(surge([raw]), /= vless,/)
  assert.match(surge([raw], 1), /= vless, .*username=11111111-1111-4111-8111-111111111111.*tls=true/)

  const encrypted = node({
    id: 'enc',
    vlessEncryption: 'mlkem768x25519plus.native.0rtt.AAAA',
  })
  assert.equal(surgeAcceptsVLESS(encrypted, 1), false)
  assert.equal(surgeAcceptsVLESS(encrypted, 2), true)
  assert.doesNotMatch(surge([encrypted], 1), /= vless,/)
  assert.match(surge([encrypted], 2), /encryption=mlkem768x25519plus\.native\.0rtt\.AAAA/)

  const xhttp = node({ id: 'xhttp', transport: 'xhttp', transportMode: 'packet-up', path: '/x', hostHeader: 'x.example' })
  assert.doesNotMatch(surge([xhttp], 1), /= vless,/)
  const xhttpText = surge([xhttp], 2)
  assert.match(xhttpText, /xhttp=true/)
  assert.match(xhttpText, /xhttp-path=\/x/)
  assert.match(xhttpText, /xhttp-host=x\.example/)
  assert.match(xhttpText, /xhttp-mode=packet-up/)
})

check('HTTPUpgrade 只在 tier3 写出，VMess / Trojan / VLESS 一致', () => {
  const vmess = node({ id: 'vmess', kind: 'vmess', alterID: 0, transport: 'httpupgrade', path: '/up', hostHeader: 'up.example' })
  const trojan = node({ id: 'trojan', kind: 'trojan', password: 'pass', transport: 'httpupgrade', path: '/up' })
  const vless = node({ id: 'vless-up', transport: 'httpupgrade', path: '/up' })
  for (const target of [vmess, trojan, vless]) {
    assert.doesNotMatch(surge([target], 2), /ws-http-upgrade=true/)
    assert.match(surge([target], 3), /ws=true, ws-http-upgrade=true/)
  }
})

check('REALITY / Vision 字段按 Surge 语法写入', () => {
  const reality = node({
    id: 'reality',
    transport: 'tcp',
    tls: false,
    sni: 'www.example.com',
    realityPublicKey: 'pubkey',
    realityShortID: 'abcd',
    flow: 'xtls-rprx-vision',
  })
  const text = surge([reality], 1)
  assert.match(text, /sni=www\.example\.com/)
  assert.match(text, /reality-public-key=pubkey/)
  assert.match(text, /reality-short-id=abcd/)
  assert.match(text, /flow=xtls-rprx-vision/)
  assert.doesNotMatch(text, /tls=true, sni=www\.example\.com/)
})

check('Anywhere：跳过证书校验的 VLESS / Trojan / AnyTLS 生成 AJSON', () => {
  const vless = node({ id: 'aj-vless', skipCertificateVerification: true })
  const trojan = node({ id: 'aj-trojan', kind: 'trojan', password: 'pass', skipCertificateVerification: true })
  const anytls = node({ id: 'aj-anytls', kind: 'anytls', password: 'pass', skipCertificateVerification: true })
  assert.equal(anywhereAjsonCount([vless, trojan, anytls]), 3)
  const doc = anywhereAjsonDocument([vless, trojan, anytls], '示例订阅')
  assert.ok(doc)
  const parsed = JSON.parse(doc!)
  assert.equal(parsed.anywhere, 1)
  assert.equal(parsed.proxies.length, 3)
  for (const proxy of parsed.proxies) {
    assert.equal(proxy.security.insecure, true)
    assert.equal(proxy.security.fingerprint, 'plain')
  }
})

check('Anywhere：WS / gRPC / XHTTP 的跳过证书节点无法保真，整体不生成 AJSON', () => {
  const ws = node({ id: 'aj-ws', transport: 'ws', path: '/ws', skipCertificateVerification: true })
  assert.equal(anywhereAjsonCount([ws]), 0)
  assert.equal(anywhereAjsonDocument([ws], '示例订阅'), undefined)
})

check('Anywhere：普通节点仍是链接字符串，没有跳过证书节点时不生成 AJSON', () => {
  const normal = node({ id: 'normal', name: '普通 VLESS' })
  assert.equal(anywhereAjsonDocument([normal], '示例订阅'), undefined)
  const mixed = anywhereAjsonDocument([normal, node({ id: 'aj', skipCertificateVerification: true })], '示例订阅')
  assert.ok(mixed)
  const parsed = JSON.parse(mixed!)
  assert.equal(parsed.proxies.length, 2)
  assert.equal(typeof parsed.proxies[0], 'string')
  assert.equal(typeof parsed.proxies[1], 'object')
})

check('服务端按 UA 选择已发布档位，旧版 / 无 UA 回退基线', () => {
  const tiers = { surge: { '1': 'ios-1', '2': 'ios-2', '3': 'ios-3' }, 'surge-mac': { '2': 'mac-2' } }
  assert.equal(surgeVariantFor(tiers, 'Surge iOS/4024'), 'ios-1')
  assert.equal(surgeVariantFor(tiers, 'Surge iOS/4026'), 'ios-2')
  assert.equal(surgeVariantFor(tiers, 'Surge iOS/4027'), 'ios-3')
  assert.equal(surgeVariantFor(tiers, 'Surge Mac/12840'), 'mac-2')
  assert.equal(surgeVariantFor(tiers, 'Surge Mac/12860'), undefined)
  assert.equal(surgeVariantFor(tiers, 'Surge iOS/4023'), undefined)
  assert.equal(surgeVariantFor(tiers, undefined), undefined)
  assert.equal(acceptsAnywhereAjson('ajson/1'), true)
  assert.equal(acceptsAnywhereAjson(' links, AJSON/1 '), true)
  assert.equal(acceptsAnywhereAjson('ajson/2'), false)
  assert.equal(acceptsAnywhereAjson(undefined), false)
})

check('VLESS Encryption 值格式校验', () => {
  assert.equal(surgeAcceptsVLESSEncryption('mlkem768x25519plus.native.0rtt.AAAA'), true)
  assert.equal(surgeAcceptsVLESSEncryption('mlkem768x25519plus.native.0rtt.'), false)
  assert.equal(surgeAcceptsVLESSEncryption('aes-128-gcm'), false)
  assert.equal(surgeAcceptsVLESSEncryption('mlkem768x25519plus.future.0rtt.AAAA'), false)
})

console.log(failures === 0 ? '\n全部 Surge / Anywhere 自检通过' : `\n${failures} 项 Surge / Anywhere 自检失败`)
process.exit(failures === 0 ? 0 : 1)
