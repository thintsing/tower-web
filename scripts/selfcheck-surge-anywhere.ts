// 自检：Surge 测试版分档与 Anywhere AJSON。
// 用法：npm run selfcheck:surge-anywhere
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { ProxyNode, RuleScheme } from '../src/models/types'
import { generateSurge } from '../src/generator/surge'
import { generateSubscriptionFormatsDetailed } from '../src/generator'
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

check('仅节点模式仍按档位写出 VLESS / HTTPUpgrade', () => {
  const vless = node({ id: 'node-only' })
  const nodeOnly = generateSurge([vless], scheme, {
    target: 'surge',
    contentMode: 'nodes',
    surgeTier: 1,
  }).text
  assert.match(nodeOnly, /= vless, /)
  assert.doesNotMatch(nodeOnly, /FINAL/)
  const up = node({ id: 'up', transport: 'httpupgrade', path: '/up' })
  const tier3 = generateSurge([up], scheme, {
    target: 'surge',
    contentMode: 'nodes',
    surgeTier: 3,
  }).text
  assert.match(tier3, /ws=true, ws-http-upgrade=true/)
})

check('发布用的仅节点载体不写规则段', () => {
  const trojan = node({ id: 'publish-node', kind: 'trojan', password: 'pass' })
  const generated = generateSubscriptionFormatsDetailed([trojan], scheme, { contentMode: 'nodes' })
  assert.match(generated.formats.surge, /= trojan, /)
  assert.doesNotMatch(generated.formats.surge, /\[Rule]/)
  assert.ok(generated.formats.base64.length > 0)
  assert.ok(generated.formats.yaml.includes('proxies:'))
})

const ROOT = fileURLToPath(new URL('..', import.meta.url))

/** content=nodes 的变体选择需要真实服务端路由；纯函数覆盖不到查询参数。 */
async function startTestServer(): Promise<{ base: string; stop: () => Promise<void> }> {
  const dir = mkdtempSync(join(tmpdir(), 'tower-node-link-'))
  const port = 20000 + Math.floor(Math.random() * 30000)
  const child = spawn(process.execPath, ['server/index.mjs'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      TOWER_DATA_DIR: dir,
      TOWER_MODE: '',
      TOWER_API_TOKEN: '',
      TOWER_PUBLIC_URL: '',
    },
    stdio: 'ignore',
  })
  const base = `http://127.0.0.1:${port}`
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      if ((await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(500) })).ok) {
        return {
          base,
          stop: async () => {
            child.kill()
            await new Promise((resolve) => setTimeout(resolve, 150))
            rmSync(dir, { recursive: true, force: true })
          },
        }
      }
    } catch {
      // 服务仍在启动
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  child.kill()
  rmSync(dir, { recursive: true, force: true })
  throw new Error('测试服务未启动')
}

try {
  const server = await startTestServer()
  try {
    const publish = await fetch(`${server.base}/api/subscribe?title=node-check`, {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({
        title: 'node-check',
        formats: { surge: 'FULL-SURGE' },
        nodeFormats: { surge: 'NODES-SURGE' },
        nodeTargets: { surge: 'NODES-TARGET' },
        surgeTiers: { surge: { '2': 'FULL-TIER2' } },
        surgeNodeTiers: { surge: { '2': 'NODE-TIER2' } },
      }),
    })
    assert.equal(publish.status, 200)
    const { token } = await publish.json() as { token: string }
    const get = (query: string, userAgent?: string) => fetch(`${server.base}/api/sub/${token}${query}`, {
      headers: userAgent ? { 'user-agent': userAgent } : {},
    })

    const full = await get('?format=surge&target=surge')
    assert.equal(await full.text(), 'FULL-SURGE')
    assert.equal(full.headers.get('x-tower-content'), 'full')

    const nodes = await get('?format=surge&target=surge&content=nodes')
    assert.equal(await nodes.text(), 'NODES-TARGET')
    assert.equal(nodes.headers.get('x-tower-content'), 'nodes')

    const betaFull = await get('?format=surge&target=surge', 'Surge iOS/4026')
    assert.equal(await betaFull.text(), 'FULL-TIER2')
    const betaNodes = await get('?format=surge&target=surge&content=nodes', 'Surge iOS/4026')
    assert.equal(await betaNodes.text(), 'NODE-TIER2')

    // 旧订阅没有仅节点变体时必须明确 406，不能悄悄回退完整配置。
    const missing = await get('?format=base64&content=nodes')
    assert.equal(missing.status, 406)
    console.log('✓ 服务端按 content=nodes 选择仅节点变体，Surge 测试版仍按 UA 选档')
  } finally {
    await server.stop()
  }
} catch (error) {
  failures += 1
  console.error('✗ 服务端按 content=nodes 选择仅节点变体，Surge 测试版仍按 UA 选档')
  console.error(`  ${error instanceof Error ? error.message : String(error)}`)
}

console.log(failures === 0 ? '\n全部 Surge / Anywhere 自检通过' : `\n${failures} 项 Surge / Anywhere 自检失败`)
process.exit(failures === 0 ? 0 : 1)
