// 自检：多格式规则方案导入（Clash / Surge / Egern / sing-box / INI）。
// 用法：npm run selfcheck:importers
import assert from 'node:assert/strict'
import { detectRuleSchemeFormat, parseRuleSchemeText } from '../src/rules/importers'
import type { PolicyGroup, RuleScheme } from '../src/models/types'

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

function group(scheme: RuleScheme, name: string): PolicyGroup {
  const found = scheme.groups.find((item) => item.name === name)
  assert.ok(found, `缺少策略组「${name}」，现有：${scheme.groups.map((item) => item.name).join(' / ')}`)
  return found
}

const CLASH = `
mixed-port: 7890
ipv6: false
dns:
  enable: true
  enhanced-mode: fake-ip
  default-nameserver:
    - 223.5.5.5
  proxy-server-nameserver:
    - https://223.5.5.5/dns-query
  nameserver:
    - https://doh.pub/dns-query
    - https://8.8.8.8/dns-query#proxy
  fallback:
    - https://1.1.1.1/dns-query
proxies:
  - { name: 直连, type: direct }
  - { name: 拒绝, type: reject }
proxy-groups:
  - name: 节点选择
    type: select
    proxies: [直连, 拒绝, 自动选择, 节点A]
  - name: 自动选择
    type: url-test
    url: http://probe.example/204
    interval: 300
    tolerance: 50
    proxies: [节点A]
  - name: 负载
    type: load-balance
    strategy: round-robin
    url: http://probe.example/204
    interval: 60
    proxies: [节点A]
rules:
  - DOMAIN-SUFFIX,google.com,节点选择
  - IP-CIDR,1.2.3.0/24,DIRECT,no-resolve
  - RULE-SET,ads,REJECT
  - AND,((DOMAIN,foo.example),(NETWORK,udp)),节点选择
  - MATCH,节点选择
rule-providers:
  ads:
    type: http
    behavior: classical
    format: yaml
    url: https://example.com/ads.yaml
    path: ./rules/ads.yaml
`

const SURGE = `
[General]
dns-server = 223.5.5.5, 1.1.1.1
encrypted-dns-server = https://doh.pub/dns-query
tower-remote-dns-server = https://8.8.8.8/dns-query
proxy-test-url = http://probe.example/204
ipv6 = false

[Proxy Group]
节点选择 = select, 直连节点, 自动选择
自动选择 = url-test, 直连节点, url=http://probe.example/204, interval=300, tolerance=50
链式 = relay, 节点选择, 自动选择
外部 = select, policy-path=https://example.com/sub, policy-regex-filter="HK|US"

[Proxy Chain]
链2 = 节点选择, 自动选择

[Rule]
DOMAIN-SUFFIX,google.com,节点选择
IP-CIDR,1.2.3.0/24,DIRECT,no-resolve
RULE-SET,https://example.com/rules.list,节点选择
FINAL,节点选择

[Remote Rule]
https://example.com/remote.list, policy=节点选择, enabled=true
https://example.com/disabled.list, policy=节点选择, enabled=false
`

const SUB_RULE_CLASH = `
proxies:
  - { name: 直连, type: direct }
  - { name: 拒绝, type: reject }
proxy-groups:
  - name: 节点选择
    type: select
    proxies: [直连, 拒绝]
rules:
  - SUB-RULE,(NETWORK,udp),udp-rules
  - SUB-RULE,(AND,((DOMAIN,foo.example),(NETWORK,tcp))),nested-rules
  - FINAL,节点选择
sub-rules:
  udp-rules:
    - DOMAIN-SUFFIX,youtube.example,节点选择
    - IP-CIDR,1.2.3.0/24,节点选择,no-resolve
    - MATCH,DIRECT
  nested-rules:
    - DOMAIN,bar.example,节点选择
`

const EGERN = `
policy_groups:
  - select:
      name: 节点选择
      policies:
        - 自动选择
        - 节点A
        - DIRECT
  - auto_test:
      name: 自动选择
      policies: [节点A]
      latency_test_url: http://probe.example/204
      interval: 300
      tolerance: 50
  - load_balance:
      name: 负载
      policies: [节点A]
      algorithm: hash
  - external:
      name: 外部
      type: select
      policies: [节点A]
rules:
  - domain:
      match: google.com
      policy: 节点选择
  - domain_suffix:
      match: [example.com, example.org]
      policy: 节点选择
  - ip_cidr:
      match: [1.2.3.0/24, 2001:db8::/32]
      policy: DIRECT
      no_resolve: true
  - rule_set:
      match: https://example.com/rules.yaml
      policy: 节点选择
  - default:
      policy: 节点选择
`

const SINGBOX = JSON.stringify({
  dns: {
    servers: [
      { type: 'udp', tag: 'local', server: '223.5.5.5' },
      { type: 'https', tag: 'domestic', server: '223.5.5.5', server_port: 443, path: '/dns-query' },
      { type: 'https', tag: 'remote', server: '8.8.8.8', server_port: 443 },
      { type: 'tls', tag: 'remote-2', server: '1.1.1.1', server_port: 853, detour: 'proxy' },
    ],
    final: 'remote',
    strategy: 'ipv4_only',
  },
  outbounds: [
    { type: 'selector', tag: '节点选择', outbounds: ['自动选择', '节点A', 'direct', 'block'] },
    { type: 'urltest', tag: '自动选择', outbounds: ['节点A'], url: 'http://probe.example/204', interval: '30s', tolerance: '50ms' },
    { type: 'fallback', tag: '回退', outbounds: ['节点A'] },
    { type: 'load-balance', tag: '负载', outbounds: ['节点A'], url: 'http://probe.example/204' },
    { type: 'direct', tag: 'direct' },
    { type: 'block', tag: 'block' },
    { type: 'shadowsocks', tag: '节点A', server: 'ss.example.com', server_port: 8388, method: 'aes-256-gcm', password: 'p' },
  ],
  route: {
    rule_set: [
      { type: 'remote', tag: 'ads', url: 'https://example.com/ads.json', format: 'binary' },
    ],
    rules: [
      { domain_suffix: ['google.com', 'youtube.com'], outbound: '节点选择' },
      { domain: 'foo.example', ip_cidr: '1.2.3.0/24', outbound: '节点选择' },
      { ip_cidr: ['1.1.1.0/24', '2001:db8::/32'], outbound: 'DIRECT' },
      { rule_set: 'ads', outbound: 'REJECT' },
      { action: 'reject', domain: 'ads.example' },
      { rule_set: 'ads', domain: 'multi.example', outbound: '节点选择' },
    ],
    final: '节点选择',
  },
}, null, 2)

const INI = `
[General]
dns-server = 223.5.5.5
custom_proxy_group=节点选择\`select\`[]自动选择\`[]DIRECT
ruleset=节点选择,[]DOMAIN-SUFFIX,google.com
custom_proxy_group=自动选择\`url-test\`.+\`http://www.gstatic.com/generate_204\`300
`

async function main(): Promise<void> {
  // ---------- 格式识别 ----------
  check('detect Clash YAML', () => assert.equal(detectRuleSchemeFormat(CLASH), 'clash'))
  check('detect Surge', () => assert.equal(detectRuleSchemeFormat(SURGE), 'surge'))
  check('detect Egern YAML', () => assert.equal(detectRuleSchemeFormat(EGERN), 'egern'))
  check('detect sing-box JSON', () => assert.equal(detectRuleSchemeFormat(SINGBOX), 'singbox'))
  check('detect subconverter INI', () => assert.equal(detectRuleSchemeFormat(INI), 'ini'))
  check('detect Clash JSON', () => assert.equal(
    detectRuleSchemeFormat('{"proxy-groups":[{"name":"G","type":"select","proxies":["DIRECT"]}],"rules":["DOMAIN,foo,G"]}'),
    'clash',
  ))
  check('empty input rejected', () => assert.throws(() => detectRuleSchemeFormat('   ')))

  // ---------- Clash ----------
  const clash = await parseRuleSchemeText('clash', 'Clash', '', CLASH)
  check('Clash: 内置策略别名与节点名过滤', () => {
    const select = group(clash, '节点选择')
    assert.deepEqual(select.options, ['DIRECT', 'REJECT', '自动选择'])
    assert.equal(select.nodeFilter, '^节点A$')
    assert.equal(group(clash, '自动选择').type, 'url-test')
    assert.equal(group(clash, '自动选择').url, 'http://probe.example/204')
    assert.equal(group(clash, '自动选择').interval, 300)
    assert.equal(group(clash, '自动选择').tolerance, 50)
    assert.equal(group(clash, '负载').type, 'load-balance')
    assert.equal(group(clash, '负载').algorithm, 'round-robin')
    assert.equal(group(clash, '负载').interval, 60)
  })
  check('Clash: 规则策略列与 no-resolve', () => {
    assert.equal(clash.rules.length, 5)
    assert.equal(clash.rules[0].type, 'DOMAIN-SUFFIX')
    assert.equal(clash.rules[0].group, '节点选择')
    const cidr = clash.rules[1]
    assert.equal(cidr.type, 'IP-CIDR')
    assert.equal(cidr.group, 'DIRECT')
    assert.equal(cidr.noResolve, true)
    assert.deepEqual(cidr.options, ['no-resolve'])
  })
  check('Clash: RULE-SET 使用 provider URL', () => {
    const rule = clash.rules[2]
    assert.equal(rule.type, 'RULE-SET')
    assert.equal(rule.value, 'https://example.com/ads.yaml')
    assert.equal(rule.group, 'REJECT')
    assert.equal(rule.sourceName, 'ads')
    assert.equal(rule.ruleSetFormat, 'yaml')
  })
  check('Clash: 逻辑规则保留原始条件', () => {
    assert.equal(clash.rules[3].type, 'AND')
    assert.equal(clash.rules[3].raw, 'AND,((DOMAIN,foo.example),(NETWORK,udp))')
    assert.equal(clash.rules[3].group, '节点选择')
    assert.equal(clash.rules[4].type, 'FINAL')
  })

  const subRuleClash = await parseRuleSchemeText('sub-rule', 'SUB-RULE', '', SUB_RULE_CLASH)
  check('Clash: SUB-RULE 展开为 AND 规则', () => {
    assert.equal(subRuleClash.rules.length, 5)
    assert.equal(subRuleClash.rules[0].type, 'AND')
    assert.equal(subRuleClash.rules[0].raw, 'AND,((NETWORK,udp),(DOMAIN-SUFFIX,youtube.example))')
    assert.equal(subRuleClash.rules[0].group, '节点选择')
    assert.equal(subRuleClash.rules[1].type, 'AND')
    assert.equal(subRuleClash.rules[1].raw, 'AND,((NETWORK,udp),(IP-CIDR,1.2.3.0/24,no-resolve))')
    assert.equal(subRuleClash.rules[2].type, 'NETWORK')
    assert.equal(subRuleClash.rules[2].value, 'udp')
    assert.equal(subRuleClash.rules[2].group, 'DIRECT')
  })

  check('Clash: 嵌套 SUB-RULE 条件会递归组合', () => {
    assert.equal(subRuleClash.rules[3].type, 'AND')
    assert.equal(
      subRuleClash.rules[3].raw,
      'AND,((AND,((DOMAIN,foo.example),(NETWORK,tcp))),(DOMAIN,bar.example))',
    )
    assert.equal(subRuleClash.rules[3].group, '节点选择')
    assert.equal(subRuleClash.rules[4].type, 'FINAL')
  })

  await checkAsync('Clash: 缺失 SUB-RULE 定义会拒绝导入', async () => {
    await assert.rejects(
      parseRuleSchemeText('missing', 'missing', '', `
proxy-groups:
  - name: 节点选择
    type: select
    proxies: [DIRECT]
rules:
  - SUB-RULE,(NETWORK,udp),missing-rules
`),
      /SUB-RULE/,
    )
  })
  check('Clash: DNS 分拆为普通 / 国内 / 远程', () => {
    assert.ok(clash.networkSettings)
    assert.deepEqual(clash.networkSettings.dnsServers, ['223.5.5.5'])
    assert.deepEqual(clash.networkSettings.encryptedDNSServers, [
      'https://223.5.5.5/dns-query',
      'https://doh.pub/dns-query',
    ])
    assert.deepEqual(clash.networkSettings.remoteDNSServers, [
      'https://8.8.8.8/dns-query',
      'https://1.1.1.1/dns-query',
    ])
    assert.equal(clash.networkSettings.ipv6Enabled, false)
    assert.equal(clash.networkSettings.dnsProtectionMode, 'standard')
    assert.equal(clash.networkSettings.proxyTestURLString, 'http://probe.example/204')
  })

  // ---------- Surge ----------
  const surge = await parseRuleSchemeText('surge', 'Surge', '', SURGE)
  check('Surge: 组类型 / 测试参数 / 链式组', () => {
    const select = group(surge, '节点选择')
    assert.deepEqual(select.options, ['自动选择'])
    assert.equal(select.nodeFilter, '^直连节点$')
    assert.equal(group(surge, '自动选择').type, 'url-test')
    assert.equal(group(surge, '自动选择').interval, 300)
    assert.equal(group(surge, '自动选择').tolerance, 50)
    assert.equal(group(surge, '链式').type, 'relay')
    assert.deepEqual(group(surge, '链式').options, ['节点选择', '自动选择'])
    assert.equal(group(surge, '链2').type, 'relay')
    assert.equal(group(surge, '外部').nodeFilter, 'HK|US')
  })
  check('Surge: 规则策略列与远程规则', () => {
    assert.equal(surge.rules.length, 5)
    assert.equal(surge.rules[0].group, '节点选择')
    assert.equal(surge.rules[1].group, 'DIRECT')
    assert.equal(surge.rules[1].noResolve, true)
    assert.equal(surge.rules[2].type, 'RULE-SET')
    assert.equal(surge.rules[2].value, 'https://example.com/rules.list')
    assert.equal(surge.rules[2].ruleSetFormat, 'classical')
    assert.equal(surge.rules[3].type, 'FINAL')
    assert.equal(surge.rules[4].type, 'RULE-SET')
    assert.equal(surge.rules[4].value, 'https://example.com/remote.list')
  })
  check('Surge: General DNS / IPv6 / 测试地址', () => {
    assert.ok(surge.networkSettings)
    assert.deepEqual(surge.networkSettings.dnsServers, ['223.5.5.5', '1.1.1.1'])
    assert.deepEqual(surge.networkSettings.encryptedDNSServers, ['https://doh.pub/dns-query'])
    assert.deepEqual(surge.networkSettings.remoteDNSServers, ['https://8.8.8.8/dns-query'])
    assert.equal(surge.networkSettings.ipv6Enabled, false)
    assert.equal(surge.networkSettings.proxyTestURLString, 'http://probe.example/204')
  })

  // ---------- Egern ----------
  const egern = await parseRuleSchemeText('egern', 'Egern', '', EGERN)
  check('Egern: 组类型 / 测试参数 / 算法', () => {
    const select = group(egern, '节点选择')
    assert.deepEqual(select.options, ['自动选择', 'DIRECT'])
    assert.equal(select.nodeFilter, '^节点A$')
    assert.equal(group(egern, '自动选择').type, 'url-test')
    assert.equal(group(egern, '自动选择').interval, 300)
    assert.equal(group(egern, '自动选择').tolerance, 50)
    assert.equal(group(egern, '负载').type, 'load-balance')
    assert.equal(group(egern, '负载').algorithm, 'hash')
    assert.equal(group(egern, '外部').type, 'select')
  })
  check('Egern: 规则字段展开与 default', () => {
    assert.equal(egern.rules.length, 7)
    assert.equal(egern.rules[0].type, 'DOMAIN')
    assert.equal(egern.rules[1].type, 'DOMAIN-SUFFIX')
    assert.equal(egern.rules[2].type, 'DOMAIN-SUFFIX')
    assert.equal(egern.rules[2].value, 'example.org')
    assert.equal(egern.rules[3].type, 'IP-CIDR')
    assert.equal(egern.rules[4].type, 'IP-CIDR6')
    assert.equal(egern.rules[3].noResolve, true)
    assert.equal(egern.rules[5].type, 'RULE-SET')
    assert.equal(egern.rules[5].value, 'https://example.com/rules.yaml')
    assert.equal(egern.rules[5].ruleSetFormat, 'egern')
    assert.equal(egern.rules[6].type, 'FINAL')
  })

  // ---------- sing-box ----------
  const singbox = await parseRuleSchemeText('singbox', 'sing-box', '', SINGBOX)
  check('sing-box: outbound 组与别名', () => {
    const select = group(singbox, '节点选择')
    assert.deepEqual(select.options, ['自动选择', 'DIRECT', 'REJECT'])
    assert.equal(select.nodeFilter, '^节点A$')
    assert.equal(group(singbox, '自动选择').type, 'url-test')
    assert.equal(group(singbox, '自动选择').interval, 30)
    assert.equal(group(singbox, '自动选择').tolerance, 50)
    assert.equal(group(singbox, '回退').type, 'fallback')
    assert.equal(group(singbox, '负载').type, 'load-balance')
  })
  check('sing-box: 多条件展开为 AND，规则集与 reject', () => {
    assert.equal(singbox.rules.length, 8)
    assert.equal(singbox.rules[0].type, 'DOMAIN-SUFFIX')
    assert.equal(singbox.rules[1].value, 'youtube.com')
    assert.equal(singbox.rules[2].type, 'AND')
    assert.equal(singbox.rules[2].raw, 'AND,((DOMAIN,foo.example),(IP-CIDR,1.2.3.0/24))')
    assert.equal(singbox.rules[3].type, 'IP-CIDR')
    assert.equal(singbox.rules[4].type, 'IP-CIDR6')
    assert.equal(singbox.rules[5].type, 'RULE-SET')
    assert.equal(singbox.rules[5].value, 'https://example.com/ads.json')
    assert.equal(singbox.rules[5].group, 'REJECT')
    assert.equal(singbox.rules[5].ruleSetFormat, 'singbox-binary')
    assert.equal(singbox.rules[6].group, 'REJECT')
    assert.equal(singbox.rules[7].type, 'FINAL')
  })
  check('sing-box: 无法表达的多条件规则不误导入', () => {
    assert.equal(singbox.rules.some((rule) => rule.value === 'multi.example'), false)
  })
  check('sing-box: DNS server 重建与 strict 模式', () => {
    assert.ok(singbox.networkSettings)
    assert.deepEqual(singbox.networkSettings.dnsServers, ['223.5.5.5'])
    assert.deepEqual(singbox.networkSettings.encryptedDNSServers, ['https://223.5.5.5:443/dns-query'])
    assert.deepEqual(singbox.networkSettings.remoteDNSServers, [
      'https://8.8.8.8:443/dns-query',
      'tls://1.1.1.1:853',
    ])
    assert.equal(singbox.networkSettings.ipv6Enabled, false)
    assert.equal(singbox.networkSettings.dnsProtectionMode, 'strict')
    assert.equal(singbox.networkSettings.proxyTestURLString, 'http://probe.example/204')
  })

  // ---------- 未声明组与内置策略 ----------
  try {
    const scheme = await parseRuleSchemeText('misc', 'misc', '', `
proxy-groups:
  - name: G
    type: select
    proxies: [DIRECT]
rules:
  - DOMAIN,foo.example,G
  - DOMAIN,bar.example,DIRECT
  - DOMAIN,baz.example,REJECT
  - DOMAIN,qux.example,未声明组
`)
    assert.deepEqual(scheme.groups.map((item) => item.name), ['G', '未声明组'])
    console.log('✓ 未声明的规则组会补 select 组，内置策略不补')
  } catch (error) {
    failures += 1
    console.error('✗ 未声明的规则组会补 select 组，内置策略不补')
    console.error(`  ${error instanceof Error ? error.message : String(error)}`)
  }

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部导入格式检查通过')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
