// 自检：规则集方言转换与塔台托管产物 URL。
// 用法：npm run selfcheck:rulesets
import assert from 'node:assert/strict'
// @ts-expect-error server converter is plain ESM and not part of the src tsconfig
import { convertRuleSet, RuleSetConversionError } from '../server/ruleset-convert.mjs'
import type { RoutingRule, SchemeRuleSet } from '../src/models/types'
import {
  hostedRuleSetURL,
  ruleSetRulesFitDialect,
} from '../src/rules/remoteFormats'
import {
  detectRuleSetFormat,
  parseRuleSetText,
  RULE_SET_FORMAT_TITLES,
} from '../src/rules/ruleSets'
import { normalizeRemoteTextURL } from '../src/util/remoteURL'

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

const DOMAIN_AND_IP = `
# 测试规则集
DOMAIN,example.com
DOMAIN-SUFFIX,foo.com
DOMAIN-KEYWORD,keyword
IP-CIDR,1.2.3.0/24,no-resolve
GEOIP,CN
`

const WITHOUT_GEOIP = `
DOMAIN,example.com
DOMAIN-SUFFIX,foo.com
DOMAIN-KEYWORD,keyword
IP-CIDR,1.2.3.0/24,no-resolve
`

const MIXED_NO_RESOLVE = `
IP-CIDR,1.2.3.0/24
IP-CIDR,2.2.2.0/24,no-resolve
`

const UNSUPPORTED = `
DOMAIN,example.com
PROCESS-NAME,curl
`

const rule = (type: string, value?: string, extra: Partial<RoutingRule> = {}): RoutingRule => ({
  type,
  value,
  group: '节点选择',
  ...extra,
})

const makeSet = (overrides: Partial<SchemeRuleSet> = {}): SchemeRuleSet => ({
  id: 'set-1',
  name: '测试规则集',
  group: '节点选择',
  rules: [rule('DOMAIN-SUFFIX', 'ads.example')],
  sourceKind: 'library',
  sourceRef: 'ACL4SSR_BanAD.list',
  format: 'classical',
  ...overrides,
})

function main(): void {
  check('QuanX：输出 host / ip-cidr / geoip，丢弃 no-resolve', () => {
    const output = convertRuleSet(DOMAIN_AND_IP, 'quanx').text
    assert.match(output, /^host, example\.com, proxy$/m)
    assert.match(output, /host-suffix, foo\.com, proxy/)
    assert.match(output, /ip-cidr, 1\.2\.3\.0\/24, proxy/)
    assert.match(output, /geoip, CN, proxy/)
    assert.doesNotMatch(output, /no-resolve/)
  })

  check('Egern：统一 no_resolve 并生成集合键', () => {
    const output = convertRuleSet(DOMAIN_AND_IP, 'egern').text
    assert.match(output, /^no_resolve: true$/m)
    assert.match(output, /^domain_set:$/m)
    assert.match(output, /^domain_suffix_set:$/m)
    assert.match(output, /^ip_cidr_set:$/m)
    assert.match(output, /^geoip_set:$/m)
    assert.equal((output.match(/"example\.com"/g) ?? []).length, 1)
  })

  check('sing-box：生成 source format v2 JSON', () => {
    const output = convertRuleSet(WITHOUT_GEOIP, 'singbox').text
    const payload = JSON.parse(output)
    assert.equal(payload.version, 2)
    assert.equal(Array.isArray(payload.rules), true)
    assert.match(output, /"domain"/)
    assert.match(output, /"domain_suffix"/)
    assert.match(output, /"domain_keyword"/)
    assert.match(output, /"ip_cidr"/)
  })

  check('无法无损转换时拒绝整份规则集', () => {
    for (const format of ['quanx', 'egern', 'singbox']) {
      assert.throws(
        () => convertRuleSet(UNSUPPORTED, format),
        (error) => error instanceof RuleSetConversionError,
        format,
      )
    }
    assert.throws(
      () => convertRuleSet(MIXED_NO_RESOLVE, 'egern'),
      /no-resolve/,
    )
  })

  check('前端：可转换类型与 no-resolve 约束', () => {
    const compatible = [
      rule('DOMAIN', 'example.com'),
      rule('DOMAIN-SUFFIX', 'foo.com'),
      rule('IP-CIDR', '1.2.3.0/24', { options: ['no-resolve'], noResolve: true }),
    ]
    for (const dialect of ['quanx', 'egern', 'singbox'] as const) {
      assert.equal(ruleSetRulesFitDialect(compatible, dialect), true, dialect)
    }
    assert.equal(ruleSetRulesFitDialect([rule('PROCESS-NAME', 'curl')], 'quanx'), false)
    assert.equal(ruleSetRulesFitDialect([rule('PROCESS-NAME', 'curl')], 'singbox'), false)
    assert.equal(ruleSetRulesFitDialect([
      rule('IP-CIDR', '1.2.3.0/24'),
      rule('IP-CIDR', '2.2.2.0/24', { options: ['no-resolve'], noResolve: true }),
    ], 'egern'), false)
  })

  check('规则集导入：经典列表 / provider YAML / QuanX / Egern / sing-box', () => {
    const classic = parseRuleSetText('DOMAIN-SUFFIX,ads.example\nIP-CIDR,1.2.3.0/24,no-resolve')
    assert.equal(classic.format, 'classical')
    assert.equal(classic.rules.length, 2)
    const provider = parseRuleSetText('payload:\n  - DOMAIN,foo.example\n  - DOMAIN-SUFFIX,bar.example')
    assert.equal(provider.format, 'yaml')
    assert.equal(provider.rules.length, 2)
    const quanx = parseRuleSetText('host, example.com, proxy\nhost-suffix, foo.com, proxy')
    assert.equal(quanx.format, 'quanx')
    assert.equal(quanx.rules[0].type, 'DOMAIN')
    assert.equal(quanx.rules[1].type, 'DOMAIN-SUFFIX')
    const egern = parseRuleSetText([
      'no_resolve: true',
      'domain_set:',
      '  - example.com',
      'ip_cidr_set:',
      '  - 1.2.3.0/24',
    ].join('\n'))
    assert.equal(egern.format, 'egern')
    assert.equal(egern.rules[1].noResolve, true)
    const singbox = parseRuleSetText(JSON.stringify({
      version: 2,
      rules: [
        { domain_suffix: ['a.example'] },
        { domain: 'foo.example', ip_cidr: ['1.2.3.0/24'] },
      ],
    }))
    assert.equal(singbox.format, 'singbox')
    assert.equal(singbox.rules[0].type, 'DOMAIN-SUFFIX')
    assert.equal(singbox.rules[1].type, 'AND')
    assert.equal(singbox.rules[1].raw, 'AND,((DOMAIN,foo.example),(IP-CIDR,1.2.3.0/24))')
  })

  check('规则集导入：自动识别与 FINAL 拒绝', () => {
    assert.equal(detectRuleSetFormat('host, example.com, proxy'), 'quanx')
    assert.equal(detectRuleSetFormat('payload:\n  - DOMAIN,foo'), 'yaml')
    assert.equal(detectRuleSetFormat('domain_set:\n  - foo.com'), 'egern')
    assert.equal(detectRuleSetFormat(JSON.stringify({ version: 2, rules: [] })), 'singbox')
    assert.equal(RULE_SET_FORMAT_TITLES.quanx, 'Quantumult X filter')
    assert.throws(
      () => parseRuleSetText('DOMAIN,foo\nFINAL'),
      /FINAL/,
    )
    assert.throws(
      () => parseRuleSetText('not a rule set', 'singbox-binary'),
      /二进制/,
    )
  })

  check('GitHub / Gitee 网页地址转换为 raw 地址', () => {
    assert.equal(
      normalizeRemoteTextURL('https://github.com/acl4ssr/ACL4SSR/blob/master/Clash/ACL4SSR_Online.ini'),
      'https://raw.githubusercontent.com/acl4ssr/ACL4SSR/master/Clash/ACL4SSR_Online.ini',
    )
    assert.equal(
      normalizeRemoteTextURL('https://gitee.com/acl4ssr/ACL4SSR/blob/master/Clash/ACL4SSR_Online.ini'),
      'https://gitee.com/acl4ssr/ACL4SSR/raw/master/Clash/ACL4SSR_Online.ini',
    )
    assert.equal(
      normalizeRemoteTextURL('https://raw.githubusercontent.com/acl4ssr/ACL4SSR/master/Clash/ACL4SSR_Online.ini'),
      'https://raw.githubusercontent.com/acl4ssr/ACL4SSR/master/Clash/ACL4SSR_Online.ini',
    )
  })

  check('托管产物 URL：内置文件与在线地址', () => {
    const library = hostedRuleSetURL(makeSet(), 'quanx')
    assert.ok(library?.startsWith('/api/ruleset?') || library?.includes('/api/ruleset?'))
    assert.ok(library?.includes('format=quanx'))
    assert.ok(library?.includes('file=ACL4SSR_BanAD.list'))
    const remote = hostedRuleSetURL(makeSet({
      sourceKind: 'url',
      sourceRef: 'https://rules.example/ads.list?token=abc',
    }), 'egern')
    assert.match(remote ?? '', /\/api\/ruleset\?format=egern&url=https%3A%2F%2Frules\.example%2Fads\.list%3Ftoken%3Dabc/)
    const local = makeSet({ sourceKind: 'local', sourceRef: 'local-1' })
    assert.equal(hostedRuleSetURL(local, 'singbox'), undefined)
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部规则集转换检查通过')
}

main()
