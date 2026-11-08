// 自检：Loyalsoldier provider 方案 + 服务端托管转换（provider=yaml）。
// 用法：npm run selfcheck:provider-rulesets
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
// @ts-expect-error server converter is plain ESM and not part of the src tsconfig
import { convertRuleSet, RuleSetConversionError } from '../server/ruleset-convert.mjs'
// @ts-expect-error server metadata is plain ESM and not part of the src tsconfig
import { BUILTIN_PROGRAMMATIC_SCHEMES } from '../server/builtin-scheme-counts.mjs'
import { CLIENTS, type ProxyNode } from '../src/models/types'
import { generateConfig } from '../src/generator'
import { analyzeRuleCompatibility } from '../src/generator/compatibility'
import { prepareSchemeForExport } from '../src/generator/groups'
import { resolveHostedBaseURL } from '../src/rules/remoteFormats'
import { BUILTIN_SCHEMES } from '../src/rules/scheme'
import { buildLoyalsoldierScheme, LOYALSONDIER_SCHEME_ID } from '../src/rules/loyalsoldierScheme'

const BASE = 'https://tower.example'
const PROVIDER_ROOT = 'https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/'
const meta = BUILTIN_SCHEMES.find((item) => item.id === LOYALSONDIER_SCHEME_ID)!
const scheme = buildLoyalsoldierScheme(meta)
const node: ProxyNode = {
  id: 'n1', kind: 'ss', name: '节点 A', server: 'ss.example.com', port: 8388,
  cipher: 'aes-256-gcm', password: 'p', tls: false, skipCertificateVerification: false,
}
const client = (target: string) => CLIENTS.find((item) => item.target === target)!

/** 期望的 provider 顺序、目标组、no-resolve。顺序是方案的一部分。 */
const EXPECTED: Array<[string, string, boolean]> = [
  ['applications', '🎯 全球直连', false],
  ['private', '🎯 全球直连', false],
  ['lancidr', '🎯 全球直连', true],
  ['reject', '🛑 全球拦截', false],
  ['icloud', '🍎 苹果服务', false],
  ['apple', '🍎 苹果服务', false],
  ['google', '🚀 节点选择', false],
  ['proxy', '🚀 节点选择', false],
  ['direct', '🎯 全球直连', false],
  ['cncidr', '🎯 全球直连', true],
  ['gfw', '🚀 节点选择', false],
  ['tld-not-cn', '🚀 节点选择', false],
  ['telegramcidr', '📲 电报信息', true],
]

let failures = 0
async function check(label: string, run: () => void | Promise<void>): Promise<void> {
  try {
    await run()
    console.log(`✓ ${label}`)
  } catch (error) {
    failures += 1
    console.error(`✗ ${label}`)
    console.error(`  ${error instanceof Error ? error.message : String(error)}`)
  }
}

function expectConversionError(text: string, format: string, behavior: string, needle: string): void {
  assert.throws(
    () => convertRuleSet(text, format, { provider: 'yaml', behavior }),
    (error: unknown) => error instanceof RuleSetConversionError && String(error.message).includes(needle),
  )
}

function prepared(target: string, format: string, hostedBaseURL = BASE) {
  return prepareSchemeForExport(scheme, {}, {
    format: format as never,
    target: target as never,
    hostedBaseURL,
  })
}

function refsOf(text: string, target: string): number {
  return (text.match(/\/api\/ruleset\?/g) ?? []).length
}

async function startTower(extraEnv: Record<string, string> = {}): Promise<{ port: number; base: string; stop: () => void }> {
  const dataDir = mkdtempSync(join(tmpdir(), 'tower-provider-'))
  const child = spawn(process.execPath, ['server/index.mjs'], {
    env: { ...process.env, PORT: '0', HOST: '127.0.0.1', TOWER_DATA_DIR: dataDir, ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const port = await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('服务器启动超时')), 15000)
    let buffer = ''
    child.stdout?.on('data', (chunk: Buffer) => {
      buffer += chunk.toString()
      const match = /companion server on http:\/\/127\.0\.0\.1:(\d+)/.exec(buffer)
      if (match) {
        clearTimeout(timer)
        resolve(Number(match[1]))
      }
    })
    child.on('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
    child.on('exit', (code) => {
      clearTimeout(timer)
      reject(new Error(`服务器提前退出：${code}`))
    })
  })
  return {
    port,
    base: `http://127.0.0.1:${port}`,
    stop: () => {
      child.kill()
      rmSync(dataDir, { recursive: true, force: true })
    },
  }
}

async function fixtureServer(): Promise<{ providerURL: string; htmlURL: string; stop: () => void }> {
  const server: Server = createServer((req, res) => {
    if (req.url === '/provider.txt') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
      res.end('payload:\n  - "+.example.com"\n  - "example.org"\n')
      return
    }
    if (req.url === '/html.txt') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end('<!DOCTYPE html><html><body>sign in</body></html>')
      return
    }
    res.writeHead(404).end('nope')
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  const port = typeof address === 'object' && address ? address.port : 0
  return {
    providerURL: `http://127.0.0.1:${port}/provider.txt`,
    htmlURL: `http://127.0.0.1:${port}/html.txt`,
    stop: () => server.close(),
  }
}

async function main(): Promise<void> {
  // ---------- provider YAML → 方言转换 ----------
  await check('provider domain：+.域 / *.域 / 裸域', () => {
    const text = 'payload:\n  - "+.Example.COM"\n  - "*.sub.example.org"\n  - example.com\n'
    const out = convertRuleSet(text, 'classic', { provider: 'yaml', behavior: 'domain' }).text
    assert.equal(out, 'DOMAIN-SUFFIX,Example.COM\nDOMAIN-SUFFIX,sub.example.org\nDOMAIN,example.com\n')
  })

  await check('provider ipcidr：v4 / v6；no-resolve 不写进 classic 正文', () => {
    const text = 'payload:\n  - 1.0.1.0/24\n  - 2001:db8::/32\n'
    const classic = convertRuleSet(text, 'classic', { provider: 'yaml', behavior: 'ipcidr' }).text
    // Surge 手册：规则集文件每行是不带策略的规则声明；no-resolve 写在 RULE-SET 行。
    assert.equal(classic, 'IP-CIDR,1.0.1.0/24\nIP-CIDR6,2001:db8::/32\n')
    const quanx = convertRuleSet(text, 'quanx', { provider: 'yaml', behavior: 'ipcidr' }).text
    assert.match(quanx, /ip-cidr, 1\.0\.1\.0\/24, proxy/)
    const singbox = JSON.parse(convertRuleSet(text, 'singbox', { provider: 'yaml', behavior: 'ipcidr' }).text)
    assert.deepEqual(singbox.rules, [{ ip_cidr: ['1.0.1.0/24', '2001:db8::/32'] }])
  })

  await check('provider classical：PROCESS-NAME 只在 Surge 能落地', () => {
    const text = 'payload:\n  - PROCESS-NAME,git\n'
    assert.equal(convertRuleSet(text, 'classic', { provider: 'yaml', behavior: 'classical' }).text, 'PROCESS-NAME,git\n')
    assert.throws(
      () => convertRuleSet(text, 'quanx', { provider: 'yaml', behavior: 'classical' }),
      RuleSetConversionError,
    )
  })

  await check('HTML 页面 / payload: [] / 缺失 payload / 行内数组全部 422', () => {
    expectConversionError('<!DOCTYPE html><html><body>sign in</body></html>', 'classic', 'domain', 'HTML')
    expectConversionError('payload: []\n', 'classic', 'domain', 'payload 为空')
    expectConversionError('- example.com\n', 'classic', 'domain', '缺少 payload:')
    expectConversionError('payload: [a.com, b.com]\n', 'classic', 'domain', 'block 列表')
    expectConversionError('payload:\n  - a.com\nname: foo\n', 'classic', 'domain', '"- " 开头')
  })

  await check('非法域名 / CIDR 被拒绝', () => {
    expectConversionError('payload:\n  - "+..weird.com"\n', 'classic', 'domain', 'domain 规则无效')
    expectConversionError('payload:\n  - "domains:"\n', 'classic', 'domain', 'domain 规则无效')
    expectConversionError('payload:\n  - 1.0.1.999/24\n', 'classic', 'ipcidr', 'ipcidr 规则无效')
    expectConversionError('payload:\n  - 1.0.1.0\n', 'classic', 'ipcidr', 'ipcidr 规则无效')
  })

  await check('服务端内置方案计数与前端方案定义同步', () => {
    const server = BUILTIN_PROGRAMMATIC_SCHEMES[LOYALSONDIER_SCHEME_ID]
    assert.ok(server, '服务端缺少这个程序化方案')
    // 增删 provider 或策略组时，服务端的工作区差异计数必须同步，不能静默漂移。
    assert.equal(server.rules, scheme.rules.length)
    assert.equal(server.groups, scheme.groups.length)
  })

  await check('13 个 provider 只存引用，不带正文', () => {
    assert.equal(scheme.ruleSets?.length, 13)
    for (const [index, set] of (scheme.ruleSets ?? []).entries()) {
      const [name] = EXPECTED[index]
      assert.equal(set.providerName, name)
      assert.deepEqual(set.rules, [])
      assert.equal(set.format, 'yaml')
      assert.equal(set.providerOnly, true)
      assert.equal(set.interval, 86400)
      assert.equal(set.sourceRef, `${PROVIDER_ROOT}${name}.txt`)
    }
  })

  await check('Clash 原生引用：顺序 / 组映射 / no-resolve / behavior', () => {
    const clash = prepared('clash-verge', 'yaml')
    assert.equal(clash.rules.length, 14)
    EXPECTED.forEach(([name, group, noResolve], index) => {
      const rule = clash.rules[index]
      assert.equal(rule.type, 'RULE-SET')
      assert.equal(rule.value, `${PROVIDER_ROOT}${name}.txt`)
      assert.equal(rule.group, group)
      assert.equal(rule.ruleSetFormat, 'yaml')
      assert.deepEqual(rule.options, noResolve ? ['no-resolve'] : undefined)
      assert.equal(rule.ruleSetProviderKey, name)
      assert.equal(rule.ruleSetInterval, 86400)
    })
    assert.equal(clash.rules[13].type, 'FINAL')
    assert.equal(clash.rules[13].group, '🐟 漏网之鱼')
  })

  await check('Clash YAML：规则集行为与路径写成 provider 名', () => {
    const text = generateConfig(client('clash-verge'), [node], prepared('clash-verge', 'yaml'), {
      contentMode: 'full',
    }).text
    assert.match(text, /  applications:\n    type: http\n    behavior: classical\n    format: yaml/)
    assert.match(text, /    behavior: ipcidr\n    format: yaml/)
    assert.match(text, /    url: "https:\/\/cdn\.jsdelivr\.net\/gh\/Loyalsoldier\/clash-rules@release\/cncidr\.txt"/)
    assert.match(text, /    path: "\.\/ruleset\/cncidr\.yaml"/)
    assert.match(text, /    interval: 86400/)
    assert.doesNotMatch(text, /tower-rule-set-/)
    assert.match(text, /RULE-SET,cncidr,全球直连,no-resolve/)
    assert.match(text, /RULE-SET,telegramcidr,电报信息,no-resolve/)
  })

  await check('Shadowrocket：不把 classical provider 当原生引用', () => {
    const yaml = prepared('shadowrocket', 'yaml')
    assert.equal(yaml.rules.filter((rule) => rule.type === 'RULE-SET').length, 12)
    assert.equal(yaml.rules.some((rule) => rule.value === 'applications'), false)
  })

  await check('Surge：13 条托管引用，no-resolve 写在 RULE-SET 行', () => {
    const surge = prepared('surge', 'surge')
    const refs = surge.rules.filter((rule) => rule.type === 'RULE-SET')
    assert.equal(refs.length, 13)
    assert.match(refs[0].value ?? '', /^https:\/\/tower\.example\/api\/ruleset\?/)
    assert.match(refs[0].value ?? '', /provider=yaml/)
    assert.match(refs[3].value ?? '', /behavior=domain/)
    assert.deepEqual(refs[2].options, ['no-resolve'])
    assert.deepEqual(refs[9].options, ['no-resolve'])
    const text = generateConfig(client('surge'), [node], prepared('surge', 'surge'), {
      contentMode: 'full',
      hostedBaseURL: BASE,
    }).text
    assert.match(text, /RULE-SET,https:\/\/tower\.example\/api\/ruleset\?.*provider=yaml.*,全球拦截/)
    assert.match(text, /,全球直连,no-resolve/)
  })

  await check('Loon / QuanX / Egern / sing-box：12 条托管引用并省略 applications', () => {
    for (const [target, format] of [['loon', 'loon'], ['quanx', 'quanx'], ['egern', 'egern'], ['sing-box', 'json']] as const) {
      const compiled = prepared(target, format)
      const refs = compiled.rules.filter((rule) => rule.type === 'RULE-SET')
      assert.equal(refs.length, 12, target)
      assert.equal(refs.some((rule) => rule.value?.includes('applications')), false, target)
      assert.equal(refs.every((rule) => rule.options === undefined), true, target)
      const text = generateConfig(client(target), [node], compiled, {
        contentMode: 'full',
        hostedBaseURL: BASE,
      }).text
      assert.equal(refsOf(text, target), 12, target)
    }
  })

  // ---------- 托管地址解析（本地模式不能误阻断） ----------
  await check('resolveHostedBaseURL：顺序与本地模式', () => {
    const lan = { publicUrl: '', lan: ['http://192.168.1.5:8080'] }
    assert.equal(resolveHostedBaseURL({ providerOnly: false, net: lan, loopback: true, origin: 'http://localhost:5173' }), undefined)
    assert.equal(resolveHostedBaseURL({ providerOnly: true, net: null, loopback: false, origin: 'http://192.168.1.9' }), '')
    assert.equal(
      resolveHostedBaseURL({ providerOnly: true, net: { publicUrl: 'https://tower.example', lan: [] }, loopback: true, origin: 'http://localhost:5173' }),
      'https://tower.example',
    )
    assert.equal(
      resolveHostedBaseURL({ providerOnly: true, net: { publicUrl: '', lan: [] }, loopback: false, origin: 'https://tower.example' }),
      'https://tower.example',
    )
    assert.equal(
      resolveHostedBaseURL({ providerOnly: true, net: lan, loopback: true, origin: 'http://localhost:5173' }),
      'http://192.168.1.5:8080',
    )
    assert.equal(resolveHostedBaseURL({ providerOnly: true, net: { publicUrl: '', lan: [] }, loopback: true, origin: 'http://localhost:5173' }), '')
  })

  await check('本地模式（伴生服务可用 + localhost）不误阻断非 Clash 导出', () => {
    const base = resolveHostedBaseURL({
      providerOnly: true,
      net: { publicUrl: '', lan: ['http://192.168.1.5:8080'] },
      loopback: true,
      origin: 'http://localhost:5173',
    })!
    assert.notEqual(base, '')
    const loon = generateConfig(client('loon'), [node], prepared('loon', 'loon', base), {
      contentMode: 'full',
      hostedBaseURL: base,
    })
    assert.equal(refsOf(loon.text, 'loon'), 12)
    assert.ok(loon.text.includes('http://192.168.1.5:8080/api/ruleset?'))
    const compat = analyzeRuleCompatibility(client('loon'), scheme, { hostedBaseURL: base })
    assert.equal(compat.providerOnlyBlocked, false)
    assert.equal(compat.remoteRuleSets, 12)
  })

  await check('彻底没有服务端点时硬阻断，不静默产出 FINAL', () => {
    const compat = analyzeRuleCompatibility(client('loon'), scheme, { hostedBaseURL: '' })
    assert.equal(compat.providerOnlyBlocked, true)
    assert.equal(compat.remoteRuleSets, 0)
    assert.throws(
      () => generateConfig(client('loon'), [node], scheme, { contentMode: 'full', hostedBaseURL: '' }),
      /托管转换地址不可用/,
    )
  })

  // ---------- 服务端托管缓存 ----------
  const fixture = await fixtureServer()
  const tower = await startTower()
  try {
    const fetchText = async (path: string) => {
      const res = await fetch(`http://127.0.0.1:${tower.port}${path}`)
      return { status: res.status, cache: res.headers.get('x-tower-ruleset-cache'), text: await res.text() }
    }
    await check('非 provider 托管：第二次请求命中缓存', async () => {
      const path = '/api/ruleset?format=classic&file=ACL4SSR_BanAD.list'
      const first = await fetchText(path)
      assert.equal(first.status, 200)
      assert.equal(first.cache, 'miss')
      assert.ok(first.text.trim().length > 0)
      const second = await fetchText(path)
      assert.equal(second.status, 200)
      assert.equal(second.cache, 'hit')
      assert.equal(second.text, first.text)
    })
    await check('provider 托管：写入键与查询键一致，第二次命中', async () => {
      const path = `/api/ruleset?format=classic&provider=yaml&behavior=domain&url=${encodeURIComponent(fixture.providerURL)}`
      const first = await fetchText(path)
      assert.equal(first.status, 200)
      assert.equal(first.cache, 'miss')
      assert.equal(first.text, 'DOMAIN-SUFFIX,example.com\nDOMAIN,example.org\n')
      const second = await fetchText(path)
      assert.equal(second.status, 200)
      assert.equal(second.cache, 'hit')
      assert.equal(second.text, first.text)
    })
    await check('provider 托管：HTML 页面 422，缺 behavior 400', async () => {
      const html = await fetchText(
        `/api/ruleset?format=classic&provider=yaml&behavior=domain&url=${encodeURIComponent(fixture.htmlURL)}`,
      )
      assert.equal(html.status, 422)
      assert.match(html.text, /HTML/)
      const missingBehavior = await fetchText(
        `/api/ruleset?format=classic&provider=yaml&url=${encodeURIComponent(fixture.providerURL)}`,
      )
      assert.equal(missingBehavior.status, 400)
    })
  } finally {
    tower.stop()
    fixture.stop()
  }

  await check('TOWER_PUBLIC_URL 拒绝回环；私网地址保留', async () => {
    for (const url of ['http://localhost:8787', 'http://127.0.0.1:8787', 'http://[::1]:8787']) {
      const server = await startTower({ TOWER_PUBLIC_URL: url })
      try {
        const network = await (await fetch(`${server.base}/api/network`)).json() as {
          publicUrl: string
          publicUrlError: string
        }
        assert.equal(network.publicUrl, '', url)
        assert.match(network.publicUrlError, /回环/, url)
      } finally {
        server.stop()
      }
    }
    const lan = await startTower({ TOWER_PUBLIC_URL: 'http://192.168.1.5:8080' })
    try {
      const network = await (await fetch(`${lan.base}/api/network`)).json() as { publicUrl: string }
      assert.equal(network.publicUrl, 'http://192.168.1.5:8080')
    } finally {
      lan.stop()
    }
  })

  if (failures > 0) {
    console.error(`\n${failures} 项失败`)
    process.exitCode = 1
  } else {
    console.log('\n全部通过')
  }
}

void main()
