// 自检：DNS 投影与纯节点解析组。
// 用法：npm run selfcheck:dns
import assert from 'node:assert/strict'
import { parse } from 'yaml'
import { generateConfig, generateSubscriptionFormats } from '../src/generator'
import { prepareSchemeForExport } from '../src/generator/groups'
import { CLIENTS, type ClientTarget, type ProxyNode, type RuleScheme } from '../src/models/types'

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

const base = { tls: false, skipCertificateVerification: false } as const
const SAMPLE: ProxyNode[] = [
  { ...base, id: 'ss1', kind: 'ss', name: '香港 01', server: 'ss.example.com', port: 8388, cipher: 'aes-256-gcm', password: 'p1' },
  { ...base, id: 'ss2', kind: 'ss', name: '日本 01', server: 'ss2.example.com', port: 8388, cipher: 'aes-256-gcm', password: 'p2' },
]

const NETWORK_STANDARD: NonNullable<RuleScheme['networkSettings']> = {
  ipv6Enabled: true,
  dnsServers: ['223.5.5.5'],
  encryptedDNSServers: ['https://223.5.5.5/dns-query'],
  remoteDNSServers: ['https://8.8.8.8/dns-query', 'https://1.1.1.1/dns-query'],
  proxyTestURLString: 'https://probe.example/204',
  dnsProtectionMode: 'standard',
}

function scheme(pure: boolean, mode: NonNullable<RuleScheme['networkSettings']>['dnsProtectionMode']): RuleScheme {
  return {
    id: pure ? 'pure' : 'no-pure',
    name: 'DNS 自检',
    description: '',
    groups: pure
      ? [
          { name: '节点选择', type: 'select', options: ['自动选择', 'DIRECT'], nodeFilter: '.*' },
          { name: '自动选择', type: 'url-test', options: [], nodeFilter: '.*' },
        ]
      : [{ name: '节点选择', type: 'select', options: ['DIRECT'], nodeFilter: '.*' }],
    rules: [
      { type: 'DOMAIN-SUFFIX', value: 'direct.example', group: 'DIRECT' },
      { type: 'DOMAIN-SUFFIX', value: 'proxy.example', group: '节点选择' },
      { type: 'DOMAIN', value: 'blocked.example', group: 'REJECT' },
      { type: 'FINAL', group: '节点选择' },
    ],
    networkSettings: { ...NETWORK_STANDARD, dnsProtectionMode: mode },
  }
}

const client = (target: ClientTarget) => CLIENTS.find((item) => item.target === target)!

function clash(target: ClientTarget, source: RuleScheme): Record<string, any> {
  return parse(generateConfig(client(target), SAMPLE, source, { contentMode: 'full' }).text)
}

function singbox(source: RuleScheme, target: ClientTarget = 'sing-box'): Record<string, any> {
  return JSON.parse(generateConfig(client(target), SAMPLE, source, { contentMode: 'full' }).text)
}

function dnsRules(config: Record<string, any>): Record<string, any>[] {
  return config.dns?.rules ?? []
}

function groupNamed(config: Record<string, any>, name: string): Record<string, any> | undefined {
  return (config['proxy-groups'] as Record<string, any>[] | undefined)?.find((group) => group.name === name)
}

function main(): void {
  check('Clash 复用纯节点组并让远程 DNS 经它带 ECS 解析', () => {
    const config = clash('clash-verge', scheme(true, 'standard'))
    assert.match(config.dns.nameserver[0], /#自动选择&ecs=114\.114\.114\.0\/24&ecs-override=true/)
    assert.equal(config.dns.nameserver.length, 1)
    assert.ok(config.dns['direct-nameserver'])
    assert.equal(config.dns.fallback, undefined)
    assert.equal(groupNamed(config, 'DNS 自动选择'), undefined)
  })

  check('Clash 没有纯节点组时补隐藏的 DNS 自动选择组', () => {
    const config = clash('clash-verge', scheme(false, 'standard'))
    const group = groupNamed(config, 'DNS 自动选择')
    assert.ok(group)
    assert.equal(group.type, 'url-test')
    assert.equal(group.hidden, true)
    assert.ok(group.proxies.includes('香港 01'))
    assert.ok(group.proxies.includes('日本 01'))
    assert.match(config.dns.nameserver[0], /#DNS 自动选择&ecs=114\.114\.114\.0\/24&ecs-override=true/)
  })

  check('Clash 严格保护不写 direct-nameserver', () => {
    const config = clash('clash-verge', scheme(true, 'strict'))
    assert.match(config.dns.nameserver[0], /#自动选择&ecs=114\.114\.114\.0\/24&ecs-override=true/)
    assert.equal(config.dns['direct-nameserver'], undefined)
  })

  check('通用 YAML 按 mihomo 能力过滤规则并带 ECS', () => {
    const source = scheme(true, 'standard')
    source.rules = [
      ...source.rules,
      { type: 'URL-REGEX', value: '^https://example.com/', group: '节点选择' },
    ]
    const formats = generateSubscriptionFormats(SAMPLE, source, { contentMode: 'full' })
    const config = parse(formats.yaml)
    const rules = (config.rules as string[] | undefined) ?? []
    assert.equal(rules.some((rule) => rule.startsWith('URL-REGEX')), false)
    assert.match(config.dns.nameserver[0], /ecs=114\.114\.114\.0\/24&ecs-override=true/)
  })

  check('不支持代理组后缀的 Clash 客户端只用国内 DNS', () => {
    const config = clash('clash-apple', scheme(true, 'standard'))
    assert.equal(config.dns.nameserver[0], 'https://223.5.5.5/dns-query')
    assert.equal(groupNamed(config, 'DNS 自动选择'), undefined)
  })

  check('跟随方案不创建解析组，也不经代理解析', () => {
    const config = clash('clash-verge', scheme(true, 'follow-scheme'))
    assert.equal(config.dns.nameserver[0], 'https://223.5.5.5/dns-query')
    assert.equal(groupNamed(config, 'DNS 自动选择'), undefined)
  })

  check('sing-box 远程 DNS 经纯节点组，并按域名规则投影', () => {
    const config = singbox(scheme(true, 'standard'))
    const remote = config.dns.servers.find((server: Record<string, any>) => server.tag === 'remote')
    assert.equal(remote?.detour, '自动选择')
    assert.equal(config.dns.final, 'remote')
    const direct = dnsRules(config).find((rule) => rule.domain_suffix?.includes('direct.example'))
    const proxy = dnsRules(config).find((rule) => rule.domain_suffix?.includes('proxy.example'))
    assert.equal(direct?.server, 'domestic')
    assert.equal(proxy?.server, 'remote')
    const blocked = dnsRules(config).find((rule) => rule.domain?.includes('blocked.example'))
    assert.equal(blocked?.action, 'reject')
  })

  check('sing-box DNS 投影保持先到先得的规则顺序', () => {
    const ordered = scheme(true, 'standard')
    ordered.rules = [
      { type: 'DOMAIN-SUFFIX', value: 'repeat.example', group: 'DIRECT' },
      { type: 'DOMAIN-SUFFIX', value: 'repeat.example', group: '节点选择' },
      { type: 'FINAL', group: '节点选择' },
    ]
    const config = singbox(ordered)
    const first = dnsRules(config).find((rule) => rule.domain_suffix?.includes('repeat.example'))
    assert.equal(first?.server, 'domestic')
    const last = [...dnsRules(config)].reverse().find((rule) => rule.domain_suffix?.includes('repeat.example'))
    assert.equal(last?.server, 'remote')
  })

  check('sing-box 使用纯节点组作为 DNS 解析路径', () => {
    const config = singbox(scheme(false, 'standard'))
    const group = config.outbounds.find((outbound: Record<string, any>) =>
      ['DNS 自动选择', '全局自动选择'].includes(outbound.tag))
    assert.ok(group)
    assert.equal(group.type, 'urltest')
    const remote = config.dns.servers.find((server: Record<string, any>) => server.tag === 'remote')
    assert.equal(remote?.detour, group.tag)
  })

  check('sing-box 严格保护把直连域名送去带中国子网的远程 DNS', () => {
    const config = singbox(scheme(true, 'strict'))
    const direct = dnsRules(config).find((rule) => rule.domain_suffix?.includes('direct.example'))
    assert.equal(direct?.server, 'remote-cn')
    assert.equal(direct?.client_subnet, '114.114.114.0/24')
  })

  check('sing-box 追加 remote-cn 与 ECS 评估规则', () => {
    const config = singbox(scheme(true, 'standard'))
    const remoteCn = config.dns.servers.find((server: Record<string, any>) => server.tag === 'remote-cn')
    assert.equal(remoteCn?.detour, '自动选择')
    assert.equal(remoteCn?.tls.server_name, 'dns.google')
    const evaluate = dnsRules(config).find((rule) => rule.action === 'evaluate')
    assert.deepEqual(evaluate?.query_type, ['A', 'AAAA'])
    assert.equal(evaluate?.server, 'remote-cn')
    assert.equal(evaluate?.client_subnet, '114.114.114.0/24')
    const respond = dnsRules(config).find((rule) => rule.match_response === true)
    assert.deepEqual(respond?.rule_set, ['tower-geoip-cn'])
    assert.equal(respond?.action, 'respond')
    const ruleSet = config.route.rule_set.find((set: Record<string, any>) => set.tag === 'tower-geoip-cn')
    assert.ok(ruleSet.rules[0].ip_cidr.length > 1000)
  })

  check('sing-box 远程 SRS 用 domain-only 版本投影 DNS', () => {
    const source = scheme(true, 'standard')
    source.ruleSets = [{
      id: 'srs-set',
      name: '广告列表',
      group: '节点选择',
      sourceKind: 'library',
      sourceRef: 'ACL4SSR_BanAD.list',
      updatedAt: 1,
      rules: [
        { type: 'DOMAIN-SUFFIX', value: 'ads.example', group: '节点选择' },
        { type: 'DOMAIN-KEYWORD', value: 'adkw', group: '节点选择' },
        { type: 'IP-CIDR', value: '1.2.3.0/24', group: '节点选择', options: ['no-resolve'], noResolve: true },
      ],
    }]
    source.rules = [{ type: 'FINAL', group: '节点选择' }]
    const prepared = prepareSchemeForExport(source, {}, {
      preferRuleSets: true,
      format: 'json',
      target: 'sing-box',
    })
    const config = singbox(prepared)
    const routeSets = config.route.rule_set as Record<string, any>[]
    const primary = routeSets.find((set) => /format=srs&/.test(set.url))
    const dns = routeSets.find((set) => /format=srs-domain/.test(set.url))
    assert.ok(primary)
    assert.ok(dns)
    const dnsRule = dnsRules(config).find((rule) => rule.rule_set?.includes(dns.tag))
    assert.ok(dnsRule)
    assert.equal(dnsRule.action, 'route')
    assert.equal(dnsRule.server, 'remote')
    assert.equal(dnsRules(config).some((rule) => rule.ip_cidr), false)

    const hiddifyPrepared = prepareSchemeForExport(source, {}, {
      preferRuleSets: true,
      format: 'json',
      target: 'hiddify',
    })
    const hiddifyConfig = singbox(hiddifyPrepared, 'hiddify')
    const hiddifySets = hiddifyConfig.route.rule_set as Record<string, any>[]
    assert.equal(hiddifySets.some((set) => /format=srs-domain/.test(set.url)), false)
  })

  check('Hiddify 的 1.13 不写 ECS 提示', () => {
    const config = singbox(scheme(true, 'standard'), 'hiddify')
    assert.equal(dnsRules(config).some((rule) => rule.action === 'evaluate'), false)
    assert.equal(config.dns.servers.some((server: Record<string, any>) => server.tag === 'remote-cn'), false)
  })

  check('sing-box 跟随方案保留模式 DNS 规则，但不投影域名规则', () => {
    const config = singbox(scheme(true, 'follow-scheme'))
    const remote = config.dns.servers.find((server: Record<string, any>) => server.tag === 'remote')
    assert.equal(remote?.detour, undefined)
    const modes = dnsRules(config).filter((rule) => rule.clash_mode)
    assert.deepEqual(modes.map((rule) => rule.clash_mode), ['直接连接', '全局代理'])
    assert.equal(dnsRules(config).some((rule) => rule.domain_suffix), false)
    assert.equal(config.dns.final, 'domestic')
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部 DNS 投影检查通过')
}

main()
