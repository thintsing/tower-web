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
import { prepareSchemeForExport, resolveGroups } from '../src/generator/groups'
import { resolveHostedBaseURL } from '../src/rules/remoteFormats'
import { compileScheme, certaintyFor, explainWith, foldPossibleMatches, POSSIBLE_PREVIEW } from '../src/rules/ruleExplain'
import { evaluateRule, parseQuery } from '../src/rules/ruleMatcher'
import { describeRemoteReferences, groupEditorRuleSummary, groupRuleSummary, remoteReferenceCount, remoteReferenceCounts, ruleSetSummary } from '../src/rules/ruleSetReferences'
import { BUILTIN_SCHEMES } from '../src/rules/scheme'
import { buildLoyalsoldierScheme, LOYALSONDIER_SCHEME_ID } from '../src/rules/loyalsoldierScheme'
import { lintScheme } from '../src/rules/schemeLint'

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

  await check('provider 条目类型：进程名 / 域名 / IP 段', () => {
    const expected: Record<string, string> = {
      applications: 'process',
      private: 'domain',
      lancidr: 'ip',
      reject: 'domain',
      icloud: 'domain',
      apple: 'domain',
      google: 'domain',
      proxy: 'domain',
      direct: 'domain',
      cncidr: 'ip',
      gfw: 'domain',
      'tld-not-cn': 'domain',
      telegramcidr: 'ip',
    }
    for (const set of scheme.ruleSets ?? []) {
      assert.equal(set.providerEntryType, expected[set.providerName ?? ''], `${set.providerName} 的条目类型不对`)
    }
  })

  await check('组行 / 组编辑器计数：直接规则与远程引用分开，不把引用算成正文', () => {
    // 方案卡总数保持真实：只有 1 条 FINAL，13 条 provider 引用另算。
    assert.equal(scheme.rules.length, 1)
    const counts = remoteReferenceCounts(scheme)
    assert.equal([...counts.values()].reduce((sum, count) => sum + count, 0), 13)
    assert.equal(remoteReferenceCount(scheme, '🎯 全球直连'), 5)
    assert.equal(remoteReferenceCount(scheme, '🚀 节点选择'), 4)
    assert.equal(remoteReferenceCount(scheme, '🍎 苹果服务'), 2)
    assert.equal(remoteReferenceCount(scheme, '🛑 全球拦截'), 1)
    assert.equal(remoteReferenceCount(scheme, '📲 电报信息'), 1)
    assert.equal(remoteReferenceCount(scheme, '🐟 漏网之鱼'), 0)
    // 组行：0 条规则 + 5 条远程引用必须是两段，而不是把 5 并进规则数。
    assert.equal(groupRuleSummary(0, 0, 5), '0 条规则 · 5 条远程引用')
    assert.equal(groupRuleSummary(1, 0, 0), '1 条规则')
    // 组编辑器顶部：明确引用由客户端下载，不是塔台保存的正文。
    assert.equal(
      groupEditorRuleSummary(0, 0, 5),
      '0 条我添加的规则 · 0 条方案自带或已展开规则集规则 · 5 条远程引用（由客户端自行下载）',
    )
    assert.equal(describeRemoteReferences(5), '该组规则来自 5 个远程引用，由客户端自行下载。')
  })

  await check('零节点：空策略组被识别，导出在入口被阻断', () => {
    const empty = analyzeRuleCompatibility(client('clash-verge'), scheme, { nodes: [] })
    assert.equal(empty.emptyGroupsBlocked, true)
    assert.deepEqual(empty.emptyGroups, ['♻️ 自动选择'])
    assert.match(empty.emptyGroupsNote ?? '', /自动选择/)
    assert.match(empty.emptyGroupsNote ?? '', /没有可用节点/)
    assert.match(empty.emptyGroupsNote ?? '', /客户端会拒绝加载/)
    const one = analyzeRuleCompatibility(client('clash-verge'), scheme, { nodes: [node] })
    assert.equal(one.emptyGroupsBlocked, false)
    assert.deepEqual(one.emptyGroups, [])
    // 其他调用（方案检查）不传 nodes 时保持原行为，不误阻断。
    assert.equal(analyzeRuleCompatibility(client('clash-verge'), scheme).emptyGroupsBlocked, false)
  })

  await check('命中解释：providerOnly 以 RULE-SET 进入链路，不再说“不会参与匹配”', () => {
    const compiled = compileScheme({ scheme, nodes: [node] })
    // 13 条 provider 引用 + 1 条 FINAL；之前 format 缺失导致只剩 FINAL。
    assert.equal(compiled.scheme.rules.length, 14)
    const google = explainWith(compiled, 'www.google.com')
    assert.equal(google.totalRules, 14)
    const googleStep = google.steps.find((step) => step.rule.ruleSetProviderKey === 'google')
    assert.ok(googleStep, '链路里应出现 RULE-SET,google')
    assert.equal(googleStep?.certainty, 'possible-match')
    assert.match(googleStep?.evaluation.detail ?? '', /RULE-SET,google/)
    assert.match(googleStep?.evaluation.detail ?? '', /可能命中/)
    // FINAL 仍是确定兜底，但结论必须让位给前面的远程引用可能命中。
    assert.equal((google.match?.rule.type ?? '').toUpperCase(), 'FINAL')
    // 无确定命中时，列全所有可能命中的引用（按匹配顺序），而不是只给第一条。
    // 进程类列表对任何静态输入都只能「可能命中」；载体未知时，带 no-resolve 的
    // IP 列表对域名输入也只能「可能命中」，所以 13 条引用全部进入清单。
    assert.deepEqual(
      google.possibleMatches.map((step) => step.rule.ruleSetProviderKey),
      ['applications', 'private', 'lancidr', 'reject', 'icloud', 'apple', 'google', 'proxy', 'direct', 'cncidr', 'gfw', 'tld-not-cn', 'telegramcidr'],
    )
    for (const [index, step] of google.possibleMatches.entries()) {
      assert.equal(step.certainty, 'possible-match')
      assert.equal((step.rule.type ?? '').toUpperCase(), 'RULE-SET')
      if (index > 0) assert.ok(step.index > google.possibleMatches[index - 1].index, '可能命中必须按匹配顺序排列')
    }
    assert.ok(!google.notes.some((note) => note.includes('不会参与匹配')))
    assert.ok(google.notes.some((note) => note.includes('远程引用')))
    // 反向：IP 输入不会把域名列表算成可能命中。
    const ip = explainWith(compiled, '1.1.1.1')
    const privateStep = ip.steps.find((step) => step.rule.ruleSetProviderKey === 'private')
    assert.equal(privateStep?.certainty, 'confirmed-miss')
  })

  await check('条目类型判定：进程名列表只能可能命中，IP 不命中域名列表', () => {
    const compiled = compileScheme({ scheme, nodes: [node] })
    // 域名输入：applications 是 PROCESS-NAME 列表，与规则匹配器一致只标可能命中。
    const domain = explainWith(compiled, 'www.google.com')
    const applications = domain.steps.find((step) => step.rule.ruleSetProviderKey === 'applications')
    assert.equal(applications?.certainty, 'possible-match')
    assert.equal(applications?.evaluation.status, 'skip')
    assert.match(applications?.evaluation.detail ?? '', /进程名列表/)
    assert.ok(domain.possibleMatches.some((step) => step.rule.ruleSetProviderKey === 'applications'))
    // youtube 仍从第一条可能命中的引用 applications 开始，而不是 private。
    const youtube = explainWith(compiled, 'https://www.youtube.com/watch?v=1')
    const ytApplications = youtube.steps.find((step) => step.rule.ruleSetProviderKey === 'applications')
    assert.equal(ytApplications?.certainty, 'possible-match')
    assert.equal(youtube.possibleMatches[0]?.rule.ruleSetProviderKey, 'applications')
    // IP 输入：applications 同样只标可能命中；域名列表 google 确定不命中。
    const ip = explainWith(compiled, '1.1.1.1')
    const ipApplications = ip.steps.find((step) => step.rule.ruleSetProviderKey === 'applications')
    assert.equal(ipApplications?.certainty, 'possible-match')
    assert.equal(ipApplications?.evaluation.status, 'skip')
    assert.match(ipApplications?.evaluation.detail ?? '', /进程名列表/)
    assert.ok(ip.possibleMatches.some((step) => step.rule.ruleSetProviderKey === 'applications'))
    const ipGoogle = ip.steps.find((step) => step.rule.ruleSetProviderKey === 'google')
    assert.equal(ipGoogle?.certainty, 'confirmed-miss')
    assert.match(ipGoogle?.evaluation.detail ?? '', /域名列表/)
    // IP 输入只列出可命中的引用：进程类 + 三个 IP 段，域名列表全部确定不命中。
    assert.deepEqual(
      ip.possibleMatches.map((step) => step.rule.ruleSetProviderKey),
      ['applications', 'lancidr', 'cncidr', 'telegramcidr'],
    )
    assert.equal(ip.possibleMatches[0]?.rule.group, '🎯 全球直连')
  })

  await check('三种口径一致：规则匹配器 / 远程引用解释 / 确定度映射对进程规则都只标可能命中', () => {
    const target = parseQuery('www.google.com')
    // 1) 普通 PROCESS-* 规则：规则匹配器判 skip。
    const direct = evaluateRule({ type: 'PROCESS-NAME', value: 'git', group: 'x' }, target)
    assert.equal(direct.status, 'skip')
    assert.equal(certaintyFor(direct), 'possible-match')
    // 2) providerOnly 进程类远程引用：解释器同样判 skip，而不是 confirmed-miss。
    const compiled = compileScheme({ scheme, nodes: [node] })
    const applications = explainWith(compiled, 'www.google.com').steps
      .find((step) => step.rule.ruleSetProviderKey === 'applications')
    assert.equal(applications?.evaluation.status, 'skip')
    assert.equal(applications?.certainty, 'possible-match')
    // 3) IP 输入也一样，不能被域名/IP 形态差异判死。
    const ipApplications = explainWith(compiled, '1.1.1.1').steps
      .find((step) => step.rule.ruleSetProviderKey === 'applications')
    assert.equal(ipApplications?.evaluation.status, 'skip')
    assert.equal(ipApplications?.certainty, 'possible-match')
  })

  await check('no-resolve 判定按载体分档：Clash 原生 / Surge 确定不命中，其余载体可能命中', () => {
    const domain = 'www.google.com'
    const pick = (format: 'yaml' | 'surge' | 'loon') =>
      explainWith(compileScheme({ scheme, nodes: [node], format }), domain)
        .steps.find((step) => step.rule.ruleSetProviderKey === 'lancidr')
    // lancidr 是 IP 列表且带 no-resolve。
    assert.equal(pick('yaml')?.certainty, 'confirmed-miss')
    assert.match(pick('yaml')?.evaluation.detail ?? '', /一定不会命中/)
    assert.equal(pick('surge')?.certainty, 'confirmed-miss')
    // Loon 的托管行不带逐条参数，域名解析后仍可能命中。
    assert.equal(pick('loon')?.certainty, 'possible-match')
    assert.match(pick('loon')?.evaluation.detail ?? '', /托管行不带 no-resolve/)
    // 未指定载体时按通用口径标可能命中，不替所有客户端下结论。
    const generic = explainWith(compileScheme({ scheme, nodes: [node] }), domain)
      .steps.find((step) => step.rule.ruleSetProviderKey === 'lancidr')
    assert.equal(generic?.certainty, 'possible-match')
  })

  await check('可能命中清单：有确定命中时列出其前的引用，折叠计数正确', () => {
    // 加一条同一策略组的确定命中，验证「确定命中」结论仍会列出可能抢先的引用。
    const withRule = {
      ...scheme,
      rules: [
        { type: 'DOMAIN', value: 'www.google.com', group: '🚀 节点选择' },
        ...scheme.rules,
      ],
    }
    const compiled = compileScheme({ scheme: withRule, nodes: [node] })
    const result = explainWith(compiled, 'www.google.com')
    assert.equal(result.final.isFallback, false, '应有一条确定命中的普通规则')
    assert.equal(result.match?.rule.type, 'DOMAIN')
    assert.ok(result.possibleMatches.length > 0, '确定命中前应列出可能抢先的引用')
    for (const step of result.possibleMatches) {
      assert.ok(step.index < (result.match?.index ?? 0), '可能命中的序号必须都在确定命中之前')
      assert.equal(step.certainty, 'possible-match')
    }

    // 折叠：默认只展示前 N 条，剩余计入 hidden；展开后全部可见。
    const many = result.possibleMatches.length > POSSIBLE_PREVIEW
      ? result.possibleMatches
      : explainWith(compileScheme({ scheme, nodes: [node] }), 'www.google.com').possibleMatches
    const folded = foldPossibleMatches(many, false, POSSIBLE_PREVIEW)
    assert.equal(folded.visible.length, POSSIBLE_PREVIEW)
    assert.equal(folded.hidden, many.length - POSSIBLE_PREVIEW)
    assert.equal(folded.total, many.length)
    const expanded = foldPossibleMatches(many, true, POSSIBLE_PREVIEW)
    assert.equal(expanded.visible.length, many.length)
    assert.equal(expanded.hidden, 0)
    const few = foldPossibleMatches(many.slice(0, 3), false, POSSIBLE_PREVIEW)
    assert.equal(few.visible.length, 3)
    assert.equal(few.hidden, 0)
  })

  await check('规则集卡片副标题：格式标签只出现一次', () => {
    const provider = scheme.ruleSets.find((set) => set.providerName === 'google')!
    const line = ruleSetSummary(provider, 'Clash provider YAML')
    assert.equal(line, '远程引用（不保存正文） · 导出为 RULE-SET · Clash provider YAML')
    assert.equal(line.split('Clash provider YAML').length - 1, 1)
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

  await check('🍎 / 📲 组：追加全部节点，其它组不变，零节点不误判为空', () => {
    const nodes: ProxyNode[] = [
      node,
      { ...node, id: 'n2', name: '节点 B', server: 'b.example.com' },
      { ...node, id: 'n3', name: '节点 C', server: 'c.example.com' },
    ]
    const resolved = resolveGroups(scheme, nodes, (item) => item.name)
    const members = new Map(resolved.map((item) => [item.group.name, item.members]))
    // 组引用在前，全部节点按顺序跟在后面（与 ACL4SSR 的 🚀, 🎯, .* 一致）。
    assert.deepEqual(members.get('🍎 苹果服务'), ['🚀 节点选择', '🎯 全球直连', 'DIRECT', '节点 A', '节点 B', '节点 C'])
    assert.deepEqual(members.get('📲 电报信息'), ['🚀 节点选择', '🎯 全球直连', '节点 A', '节点 B', '节点 C'])
    // 其它组不跟着加节点。
    assert.deepEqual(members.get('🎯 全球直连'), ['DIRECT', '🚀 节点选择', '♻️ 自动选择'])
    assert.deepEqual(members.get('🛑 全球拦截'), ['REJECT', 'DIRECT'])
    // 零节点：两个组仍有组引用成员，不能被当成空组拦下。
    const empty = analyzeRuleCompatibility(client('clash-verge'), scheme, { nodes: [] })
    assert.ok(!empty.emptyGroups.includes('🍎 苹果服务'))
    assert.ok(!empty.emptyGroups.includes('📲 电报信息'))
    assert.deepEqual(empty.emptyGroups, ['♻️ 自动选择'])
    // 导出片段：组引用在前、节点在后。
    const text = generateConfig(client('clash-verge'), nodes, prepared('clash-verge', 'yaml'), {
      contentMode: 'full',
    }).text
    // 导出时组名会去掉表情前缀，这里按客户端实际看到的名称断言。
    assert.match(
      text,
      /- name: "苹果服务"\n    type: select\n(?:    icon: ".*"\n)?    proxies:\n      - "节点选择"\n      - "全球直连"\n      - "DIRECT"\n      - "节点 A"\n      - "节点 B"\n      - "节点 C"/,
    )
    assert.match(
      text,
      /- name: "电报信息"\n    type: select\n(?:    icon: ".*"\n)?    proxies:\n      - "节点选择"\n      - "全球直连"\n      - "节点 A"\n      - "节点 B"\n      - "节点 C"/,
    )
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

  await check('检查面板与导出页同源：所有可导出载体被阻断时提为 error', () => {
    const nonNative = [client('loon'), client('quanx'), client('egern'), client('sing-box')]
    // 静态部署解析结果是空地址：与导出页一样，全部非 Clash 目标被阻断。
    const blocked = lintScheme({ scheme, nodes: [node], clients: nonNative, hostedBaseURL: '' })
    const issue = blocked.find((item) => item.code === 'providerOnlyUnsupported')
    assert.equal(issue?.level, 'error')
    assert.match(issue?.message ?? '', /所有可导出的客户端/)
    // 只有部分载体被阻断时保持 warn，不把可正常导出的 Clash 一起判死。
    const partial = lintScheme({
      scheme, nodes: [node],
      clients: [client('clash-verge'), client('loon')],
      hostedBaseURL: '',
    }).find((item) => item.code === 'providerOnlyUnsupported')
    assert.equal(partial?.level, 'warn')
    // 传入可用的托管地址后，检查面板不再误报阻断。
    const ok = lintScheme({ scheme, nodes: [node], clients: nonNative, hostedBaseURL: BASE })
    assert.equal(ok.some((item) => item.code === 'providerOnlyUnsupported'), false)
  })

  await check('S3：providerOnly 缺少有效远程地址时 lint 报 error', () => {
    const broken = JSON.parse(JSON.stringify(scheme)) as typeof scheme
    broken.ruleSets = (broken.ruleSets ?? []).map((set, index) =>
      index === 0 ? { ...set, sourceRef: 'ftp://rules.example/not-http.list' } : set)
    const issue = lintScheme({ scheme: broken, nodes: [node] })
      .find((item) => item.code === 'providerOnlyMissingReference')
    assert.equal(issue?.level, 'error')
    assert.match(issue?.message ?? '', /地址无效/)
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
