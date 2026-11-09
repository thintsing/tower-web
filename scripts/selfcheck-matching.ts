// 自检：拖动策略组后的规则匹配顺序。
// 用法：npm run selfcheck:matching
import assert from 'node:assert/strict'
import type { PolicyGroup, RoutingRule, RuleScheme } from '../src/models/types'
import {
  matchingGroupNames,
  matchingOrderAfterDragging,
  reorderRulesByMatchingOrder,
} from '../src/rules/matchingOrder'
import {
  autoGroupReferenceWarning,
  buildNodeFilterGroup,
  findGroupCyclePath,
  nextGroupName,
  previewNodeMatches,
  removePolicyGroup,
  validateGroupCandidates,
  validateNodeGroupDraft,
} from '../src/rules/groupEditing'
import { findRuleOrderConflicts } from '../src/rules/orderConflicts'
import { prepareSchemeForExport, resolveGroups } from '../src/generator/groups'
import { generateSubscriptionFormats } from '../src/generator'
import { explainQuery, compileScheme, explainWith, type CompiledScheme } from '../src/rules/ruleExplain'
import { parseQuery, evaluateRule } from '../src/rules/ruleMatcher'
import { lintScheme } from '../src/rules/schemeLint'
import { CLIENTS, type ProxyNode } from '../src/models/types'

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

function rule(group: string, value: string, type = 'DOMAIN'): RoutingRule {
  return { type, value, group }
}

function group(name: string): PolicyGroup {
  return { name, type: 'select', options: ['DIRECT'] }
}

const A = [rule('A', 'a1.example.com'), rule('A', 'a2.example.com', 'IP-CIDR'), rule('A', 'CN', 'GEOIP')]
const B = [rule('B', 'b1.example.com')]
const C = [rule('C', 'c1.example.com')]
const RULES = [...A, ...B, ...C]

function main(): void {
  check('匹配顺序按规则实际出现顺序去重', () => {
    assert.deepEqual(matchingGroupNames(RULES), ['A', 'B', 'C'])
  })

  check('往下拖过有规则的组，排到它之后', () => {
    const next = matchingOrderAfterDragging('A', ['A', 'B', 'C'], ['B', 'C', 'A'], ['A', 'B', 'C'])
    assert.deepEqual(next, ['B', 'C', 'A'])
  })

  check('往上拖过有规则的组，排到它之前', () => {
    const next = matchingOrderAfterDragging('C', ['A', 'B', 'C'], ['C', 'A', 'B'], ['A', 'B', 'C'])
    assert.deepEqual(next, ['C', 'A', 'B'])
  })

  check('越过没有规则的组不改变匹配顺序', () => {
    const next = matchingOrderAfterDragging('A', ['A', '空组', 'B'], ['空组', 'A', 'B'], ['A', 'B'])
    assert.deepEqual(next, ['A', 'B'])
  })

  check('按匹配顺序只搬动被调整的组', () => {
    const result = reorderRulesByMatchingOrder(RULES, ['B', 'A', 'C'])
    assert.deepEqual(matchingGroupNames(result), ['B', 'A', 'C'])
    assert.deepEqual(result.filter((item) => item.group === 'B'), B)
    assert.deepEqual(result.filter((item) => item.group === 'A' && item.type !== 'GEOIP'), A.slice(0, 2))
  })

  check('没有匹配顺序时规则保持原样', () => {
    assert.deepEqual(reorderRulesByMatchingOrder(RULES, undefined), RULES)
    assert.deepEqual(reorderRulesByMatchingOrder(RULES, ['A', 'B', 'C']), RULES)
  })

  check('导出时自定义规则仍然排在最前', () => {
    const scheme: RuleScheme = {
      id: 'scheme-1',
      name: '测试',
      description: '',
      groups: [group('A'), group('B'), group('C')],
      rules: RULES,
      customRules: [rule('B', 'custom.example.com', 'DOMAIN-SUFFIX')],
      matchingOrder: ['B', 'A', 'C'],
    }
    const prepared = prepareSchemeForExport(scheme, {}, {})
    assert.deepEqual(prepared.rules[0], scheme.customRules?.[0])
    assert.deepEqual(
      matchingGroupNames(prepared.rules.slice(1)),
      ['B', 'A', 'C'],
    )
  })

  check('自定义规则按最具体优先排序', () => {
    const scheme: RuleScheme = {
      id: 'supplement-order',
      name: '测试',
      description: '',
      groups: [group('A')],
      rules: [{ type: 'FINAL', group: 'A' }],
      customRules: [
        rule('A', 'example.com', 'DOMAIN-SUFFIX'),
        rule('A', 'ads.example.com', 'DOMAIN-SUFFIX'),
        rule('A', 'example.com', 'DOMAIN'),
        rule('A', 'tracking', 'DOMAIN-KEYWORD'),
        rule('A', '10.0.0.0/8', 'IP-CIDR'),
      ],
    }
    const prepared = prepareSchemeForExport(scheme, {}, {})
    assert.deepEqual(
      prepared.rules.slice(0, 5).map((item) => `${item.type},${item.value ?? ''}`),
      [
        'DOMAIN,example.com',
        'DOMAIN-SUFFIX,ads.example.com',
        'DOMAIN-SUFFIX,example.com',
        'DOMAIN-KEYWORD,tracking',
        'IP-CIDR,10.0.0.0/8',
      ],
    )
    assert.equal(prepared.rules.at(-1)?.type, 'FINAL')
  })

  check('规则集：有同值锚点插在其前，没有锚点时前置', () => {
    const scheme: RuleScheme = {
      id: 'ruleset-placement',
      name: '测试',
      description: '',
      groups: [group('A'), group('B'), group('C')],
      rules: [
        rule('A', 'a.example.com'),
        rule('B', 'b.example.com'),
        rule('C', 'c.example.com'),
        { type: 'FINAL', group: 'A' },
      ],
      ruleSets: [
        {
          id: 'set-b',
          name: 'B 列表',
          group: 'B',
          sourceKind: 'local',
          updatedAt: 1,
          rules: [
            rule('B', 'b.example.com'),
            rule('B', 'b2.example.com'),
          ],
        },
        {
          id: 'set-d',
          name: 'D 列表',
          group: 'C',
          sourceKind: 'local',
          updatedAt: 1,
          rules: [rule('C', 'not-in-template.example.com')],
        },
      ],
    }
    const prepared = prepareSchemeForExport(scheme, {}, {})
    assert.deepEqual(
      prepared.rules.map((item) => `${item.type},${item.value ?? ''},${item.group}`),
      [
        'DOMAIN,not-in-template.example.com,C',
        'DOMAIN,a.example.com,A',
        'DOMAIN,b.example.com,B',
        'DOMAIN,b2.example.com,B',
        'DOMAIN,b.example.com,B',
        'DOMAIN,c.example.com,C',
        'FINAL,,A',
      ],
    )
  })

  check('FINAL 不进入匹配顺序，也不会被拖动前移', () => {
    assert.equal(matchingGroupNames([...RULES, { type: 'FINAL', group: 'D' }]).includes('D'), false)
    const withFinal = [...A, ...B, { type: 'FINAL', group: 'C' }]
    const result = reorderRulesByMatchingOrder(withFinal, ['C', 'A', 'B'])
    assert.equal(result.at(-1)?.type, 'FINAL')
  })

  check('新建节点组使用唯一名称并校验正则', () => {
    const scheme: RuleScheme = {
      id: 'new-group',
      name: '测试',
      description: '',
      groups: [group('自定义节点'), group('B')],
      rules: RULES,
    }
    assert.equal(nextGroupName(scheme), '自定义节点 2')
    assert.equal(
      validateNodeGroupDraft(scheme, { name: 'B', type: 'select', pattern: '.*' }),
      '已经有同名策略组',
    )
    assert.equal(
      validateNodeGroupDraft(scheme, { name: 'DIRECT', type: 'select', pattern: '.*' }),
      '不能使用内置策略名',
    )
    assert.equal(
      validateNodeGroupDraft(scheme, { name: '韩国', type: 'select', pattern: '[' }),
      '节点名称匹配不是有效的正则表达式',
    )
    assert.equal(
      validateNodeGroupDraft(scheme, { name: '韩国', type: 'select', pattern: '韩国|KR' }),
      undefined,
    )
  })

  check('节点组预览与默认参数', () => {
    const preview = previewNodeMatches('首尔|KR', [
      { id: '1', kind: 'ss', name: '🇰🇷 首尔 01', server: 'a.example.com', port: 1, tls: false, skipCertificateVerification: false, rawURI: '' },
      { id: '2', kind: 'ss', name: '🇯🇵 东京 01', server: 'b.example.com', port: 1, tls: false, skipCertificateVerification: false, rawURI: '' },
    ])
    assert.deepEqual(preview.names, ['🇰🇷 首尔 01'])
    const built = buildNodeFilterGroup({ name: '韩国节点', type: 'url-test', pattern: '韩国|KR' })
    assert.equal(built.options.length, 0)
    assert.equal(built.nodeFilter, '韩国|KR')
    assert.equal(built.url, 'http://www.gstatic.com/generate_204')
    assert.equal(built.interval, 300)
    assert.equal(built.tolerance, 50)
  })

  check('拖动后检测到域名从一组改走另一组', () => {
    const scheme: RuleScheme = {
      id: 'conflicts',
      name: 'conflicts',
      description: '',
      groups: [group('A'), group('B')],
      rules: [
        { type: 'DOMAIN', value: 'youtube.com', group: 'A' },
        { type: 'DOMAIN-SUFFIX', value: 'youtube.com', group: 'B' },
        { type: 'DOMAIN-KEYWORD', value: 'spotify', group: 'B' },
      ],
    }
    const conflicts = findRuleOrderConflicts(scheme, ['A', 'B'], ['B', 'A'])
    assert.deepEqual(conflicts, [{ from: 'A', to: 'B', domains: ['youtube.com'] }])
    assert.deepEqual(findRuleOrderConflicts(scheme, ['A', 'B'], ['A', 'B']), [])
  })

  check('删除策略组会清理规则、引用和规则集快照', () => {
    const scheme: RuleScheme = {
      id: 'delete-group',
      name: '测试',
      description: '',
      groups: [
        group('A'),
        { ...group('B'), options: ['A', 'DIRECT'] },
      ],
      rules: [...A, ...B],
      customRules: [rule('A', 'custom-a.example.com', 'DOMAIN-SUFFIX')],
      matchingOrder: ['A', 'B'],
      ruleSets: [
        {
          id: 'set-a', name: 'A 规则集', group: 'A',
          rules: [rule('A', 'set-a.example.com', 'DOMAIN-SUFFIX')],
          sourceKind: 'local', updatedAt: 1,
        },
      ],
    }
    const removed = removePolicyGroup(scheme, 'A')
    assert.deepEqual(removed.scheme.groups.map((item) => item.name), ['B'])
    assert.deepEqual(removed.scheme.groups[0].options, ['DIRECT'])
    assert.equal(removed.scheme.rules.some((item) => item.group === 'A'), false)
    assert.equal(removed.scheme.customRules?.length, 0)
    assert.equal(removed.scheme.ruleSets?.length, 0)
    assert.deepEqual(removed.scheme.matchingOrder, ['B'])
    assert.equal(removed.removedRules, A.length)
    assert.equal(removed.removedCustomRules, 1)
    assert.equal(removed.removedRuleSets, 1)
    assert.deepEqual(removed.referencingGroups, ['B'])
  })

  const NODES: ProxyNode[] = [
    { id: 'n1', kind: 'ss', name: '香港 01', server: 'hk.example.com', port: 443, tls: false, skipCertificateVerification: false, rawURI: '' },
    { id: 'n2', kind: 'ss', name: '日本 01', server: 'jp.example.com', port: 443, tls: false, skipCertificateVerification: false, rawURI: '' },
  ]

  check('新建策略组可引用其他策略组并写入候选', () => {
    const scheme: RuleScheme = {
      id: 'group-refs',
      name: 'group-refs',
      description: '',
      groups: [
        { name: '节点选择', type: 'select', options: ['DIRECT'] },
        { name: '自动选择', type: 'url-test', options: [], nodeFilter: '.*' },
      ],
      rules: [],
    }
    const built = buildNodeFilterGroup({
      name: '新组', type: 'select', pattern: '', options: ['节点选择', '自动选择', 'DIRECT'],
    })
    assert.deepEqual(built.options, ['节点选择', '自动选择', 'DIRECT'])
    assert.equal(built.nodeFilter, undefined)
    assert.equal(
      validateNodeGroupDraft(scheme, { name: '新组', type: 'select', pattern: '', options: ['不存在'] }),
      '候选「不存在」不是当前方案里的策略组；节点请用节点名称匹配加入',
    )
    const draft: RuleScheme = { ...scheme, groups: [...scheme.groups, built] }
    const formats = generateSubscriptionFormats(NODES, draft, { contentMode: 'full' })
    for (const format of ['yaml', 'surge', 'loon', 'quanx', 'json', 'egern'] as const) {
      const text = formats[format]
      const start = text.indexOf('新组')
      assert.ok(start >= 0, `${format} 没有输出新组`)
      assert.ok(text.indexOf('节点选择', start) > start, `${format} 的新组成员缺少节点选择`)
      assert.ok(text.indexOf('自动选择', start) > start, `${format} 的新组成员缺少自动选择`)
    }
  })

  check('自动组里的策略组引用会当场提示 sing-box 过滤', () => {
    const groupNames = ['节点选择', '自动选择']
    for (const type of ['url-test', 'fallback', 'load-balance'] as const) {
      const warning = autoGroupReferenceWarning(type, ['自动选择', 'DIRECT'], groupNames)
      assert.ok(warning?.includes('sing-box 导出会过滤'), type)
      assert.ok(warning?.includes('自动选择'), type)
    }
    assert.equal(autoGroupReferenceWarning('select', ['自动选择'], groupNames), undefined)
    assert.equal(autoGroupReferenceWarning('url-test', ['DIRECT'], groupNames), undefined)
  })

  check('保存前拦截策略组引用成环并指出路径', () => {
    const scheme: RuleScheme = {
      id: 'cycle',
      name: 'cycle',
      description: '',
      groups: [
        { name: 'A', type: 'select', options: ['B'] },
        { name: 'B', type: 'select', options: ['C'] },
      ],
      rules: [],
    }
    assert.equal(
      validateNodeGroupDraft(scheme, { name: 'C', type: 'select', pattern: '', options: ['A'] }),
      '策略组循环引用：C → A → B → C',
    )
    // 改名时原名和现名都算“自己”，不能出现在候选里。
    assert.equal(validateGroupCandidates(scheme, 'C', ['C'], 'A'), '策略组不能把自己加入候选')
    assert.equal(validateGroupCandidates(scheme, 'C', ['A'], 'A'), '策略组不能把自己加入候选')
    assert.deepEqual(
      findGroupCyclePath([...scheme.groups, { name: 'C', type: 'select', options: ['A'] }], 'C'),
      ['C', 'A', 'B', 'C'],
    )
    assert.deepEqual(
      findGroupCyclePath([...scheme.groups, { name: 'C', type: 'select', options: ['DIRECT'] }], 'C'),
      undefined,
    )
  })

  check('select 组第一项候选是默认选中', () => {
    const scheme: RuleScheme = {
      id: 'first-candidate',
      name: 'first-candidate',
      description: '',
      groups: [
        { name: '节点选择', type: 'select', options: ['DIRECT'] },
        { name: '新组', type: 'select', options: ['节点选择', '自动选择', 'DIRECT'] },
        { name: '自动选择', type: 'url-test', options: [], nodeFilter: '.*' },
      ],
      rules: [],
    }
    const plain = resolveGroups(scheme, NODES, (node) => node.name)
    assert.deepEqual(plain.find((item) => item.group.name === '新组')?.members.slice(0, 2), ['节点选择', '自动选择'])
    const prepared = prepareSchemeForExport(scheme, { 新组: '自动选择' }, {})
    const selected = resolveGroups(prepared, NODES, (node) => node.name)
    assert.equal(selected.find((item) => item.group.name === '新组')?.members[0], '自动选择')
  })

  check('悬空组引用会被 lint 报 missingGroupMember', () => {
    const scheme: RuleScheme = {
      id: 'dangling',
      name: 'dangling',
      description: '',
      groups: [{ name: 'A', type: 'select', options: ['已删除的组'] }],
      rules: [],
    }
    const issues = lintScheme({ scheme, nodes: NODES })
    assert.ok(issues.some((issue) => issue.code === 'missingGroupMember' && issue.message.includes('已删除的组')))
  })

  const explainWithIndex = (compiled: CompiledScheme, raw: string) => {
    const result = explainWith(compiled, raw)
    return { result, match: result.match?.index }
  }

  check('输入解析：URL / 端口 / IPv4 / IPv6 / 路径', () => {
    assert.equal(parseQuery('https://www.google.com/search?q=1').host, 'www.google.com')
    assert.equal(parseQuery('https://www.google.com/search?q=1').port, 443)
    assert.equal(parseQuery('example.com:8080').port, 8080)
    assert.equal(parseQuery('example.com/path').host, 'example.com')
    assert.equal(parseQuery('1.2.3.4').kind, 'ipv4')
    assert.equal(parseQuery('[2001:db8::1]:443').kind, 'ipv6')
    assert.equal(parseQuery('[2001:db8::1]:443').ip, '2001:db8::1')
  })

  check('规则判定：后缀 / IPv4 CIDR / IPv6 CIDR / 端口 / 地址族', () => {
    const target = parseQuery('https://www.google.com/a')
    assert.equal(evaluateRule({ type: 'DOMAIN', value: 'google.com' }, target).status, 'miss')
    assert.equal(evaluateRule({ type: 'DOMAIN-SUFFIX', value: 'google.com' }, target).status, 'match')
    assert.equal(evaluateRule({ type: 'DOMAIN-KEYWORD', value: 'GOOGLE' }, target).status, 'match')
    assert.equal(evaluateRule({ type: 'DOMAIN-WILDCARD', value: '*.google.com' }, target).status, 'match')
    assert.equal(evaluateRule({ type: 'DOMAIN-REGEX', value: '^www\\.google\\.' }, target).status, 'match')
    const v4 = parseQuery('1.2.3.4:443')
    assert.equal(evaluateRule({ type: 'IP-CIDR', value: '1.2.3.0/24' }, v4).status, 'match')
    assert.equal(evaluateRule({ type: 'DST-PORT', value: '443' }, v4).status, 'match')
    assert.equal(evaluateRule({ type: 'DST-PORT', value: '80' }, v4).status, 'miss')
    const v6 = parseQuery('[2001:db8::1]')
    assert.equal(evaluateRule({ type: 'IP-CIDR6', value: '2001:db8::/32' }, v6).status, 'match')
    assert.equal(evaluateRule({ type: 'IP-CIDR', value: '2001:db8::/32' }, v6).status, 'miss')
    assert.equal(evaluateRule({ type: 'DOMAIN-SUFFIX', value: 'google.com' }, v4).status, 'miss')
  })

  check('DOMAIN-WILDCARD 与 mihomo 一致：* 不包含根域，可跨点', () => {
    assert.equal(evaluateRule({ type: 'DOMAIN-WILDCARD', value: '*.example.com' }, parseQuery('example.com')).status, 'miss')
    assert.equal(evaluateRule({ type: 'DOMAIN-WILDCARD', value: '*.example.com' }, parseQuery('a.example.com')).status, 'match')
    assert.equal(evaluateRule({ type: 'DOMAIN-WILDCARD', value: '*.example.com' }, parseQuery('a.b.example.com')).status, 'match')
    assert.equal(evaluateRule({ type: 'DOMAIN-WILDCARD', value: 'example.*' }, parseQuery('example.com')).status, 'match')
    // 长通配串以前被翻译成 `.*.*...` 的正则，会在这里卡死几十秒。
    const hostile = parseQuery(`${'a'.repeat(200)}.com`)
    const started = performance.now()
    const result = evaluateRule({ type: 'DOMAIN-WILDCARD', value: `${'*a'.repeat(240)}b` }, hostile)
    const elapsed = performance.now() - started
    assert.equal(result.status, 'miss')
    assert.ok(elapsed < 20, `耗时 ${elapsed.toFixed(1)}ms`)
  })

  check('IP-SUFFIX 按末尾 prefix 位比较（mihomo 语义）', () => {
    // 1.2.3.4/16 的末尾 16 位是 3.4：任意 x.y.3.4 都应命中，而文本前缀比较会漏掉。
    assert.equal(evaluateRule({ type: 'IP-SUFFIX', value: '1.2.3.4/16' }, parseQuery('9.9.3.4')).status, 'match')
    assert.equal(evaluateRule({ type: 'IP-SUFFIX', value: '1.2.3.4/16' }, parseQuery('1.2.4.3')).status, 'miss')
    assert.equal(evaluateRule({ type: 'IP-SUFFIX', value: '1.2.3.0/24' }, parseQuery('1.2.3.4')).status, 'miss')
    assert.equal(evaluateRule({ type: 'IP-SUFFIX', value: '1.2.3.0/24' }, parseQuery('9.2.3.0')).status, 'match')
    assert.equal(evaluateRule({ type: 'IP-SUFFIX', value: '1.2.3.4' }, parseQuery('1.2.3.4')).status, 'unknown')
  })

  check('非法 CIDR / 前导零 / 多余斜杠不会被误判命中', () => {
    const ip = parseQuery('1.2.3.4')
    assert.equal(evaluateRule({ type: 'IP-CIDR', value: '1.2.3.4/24/8' }, ip).status, 'unknown')
    assert.equal(evaluateRule({ type: 'IP-CIDR', value: '1.2.3.4/' }, ip).status, 'unknown')
    assert.equal(evaluateRule({ type: 'IP-CIDR', value: '1.2.3.4/abc' }, ip).status, 'unknown')
    assert.equal(evaluateRule({ type: 'IP-CIDR', value: '001.2.3.4/24' }, ip).status, 'unknown')
    assert.equal(evaluateRule({ type: 'IP-CIDR', value: '1.2.3.0/24' }, ip).status, 'match')
  })

  check('IPv4 映射 IPv6 按 IPv4 处理（对齐 mihomo Unmap）', () => {
    const mapped = parseQuery('[::ffff:1.2.3.4]')
    assert.equal(mapped.kind, 'ipv4')
    assert.equal(mapped.ip, '1.2.3.4')
    assert.equal(evaluateRule({ type: 'IP-CIDR', value: '1.2.3.0/24' }, mapped).status, 'match')
    const urlMapped = parseQuery('http://[::ffff:1.2.3.4]:8080/')
    assert.equal(urlMapped.ip, '1.2.3.4')
    assert.equal(urlMapped.port, 8080)
  })

  check('DOMAIN-REGEX 区分大小写，通配符不区分', () => {
    // 主机名统一小写后再匹配；正则不再强制忽略大小写，和客户端 regexp.Compile 一致。
    const target = parseQuery('www.Google.com')
    assert.equal(evaluateRule({ type: 'DOMAIN-REGEX', value: '^www\\.google' }, target).status, 'match')
    assert.equal(evaluateRule({ type: 'DOMAIN-REGEX', value: '^www\\.Google' }, target).status, 'miss')
    assert.equal(evaluateRule({ type: 'DOMAIN-WILDCARD', value: '*.Google.com' }, target).status, 'match')
  })

  check('逻辑规则 AND / OR / NOT 递归判定', () => {
    const target = parseQuery('https://www.google.com:443')
    const and = evaluateRule({ type: 'AND', raw: 'AND,((DOMAIN-SUFFIX,google.com),(DST-PORT,443))' }, target)
    assert.equal(and.status, 'match')
    const or = evaluateRule({ type: 'OR', raw: 'OR,((DOMAIN-SUFFIX,bing.com),(DOMAIN-SUFFIX,google.com))' }, target)
    assert.equal(or.status, 'match')
    const not = evaluateRule({ type: 'NOT', raw: 'NOT,((DOMAIN-SUFFIX,bing.com))' }, target)
    assert.equal(not.status, 'match')
  })

  check('输入大小写 / 末尾点 / 空串 / 超长', () => {
    assert.equal(evaluateRule({ type: 'DOMAIN', value: 'google.com' }, parseQuery('GOOGLE.COM.')).status, 'match')
    assert.equal(evaluateRule({ type: 'DOMAIN-SUFFIX', value: 'google.com' }, parseQuery('WWW.GOOGLE.COM')).status, 'match')
    assert.equal(parseQuery('').kind, 'unknown')
    assert.equal(parseQuery('a'.repeat(5000)).kind, 'unknown')
    assert.equal(parseQuery(`${'a'.repeat(300)}.com`).kind, 'unknown')
    assert.equal(parseQuery(`${'a'.repeat(4090)}.com`).kind, 'unknown')
    assert.equal(parseQuery('example.com:99999').kind, 'unknown')
    assert.equal(parseQuery('[2001:db8::1]:99999').kind, 'unknown')
  })

  check('DOMAIN-REGEX 拦截灾难性回溯，不阻塞页面', () => {
    const host = parseQuery(`${'a'.repeat(30)}.com`)
    const started = performance.now()
    const result = evaluateRule({ type: 'DOMAIN-REGEX', value: '(a+)+$' }, host)
    const elapsed = performance.now() - started
    assert.equal(result.status, 'unknown')
    assert.match(result.reason ?? '', /灾难性回溯/)
    assert.ok(elapsed < 50, `耗时 ${elapsed.toFixed(1)}ms`)
  })

  const explainScheme: RuleScheme = {
    id: 'explain',
    name: '解释',
    description: '',
    groups: [
      { name: '代理', type: 'select', options: ['🇭🇰 香港 01', 'DIRECT'], nodeFilter: '香港' },
      { name: '自动', type: 'url-test', options: [], nodeFilter: '香港' },
    ],
    rules: [
      rule('代理', 'google.com'),
      rule('代理', 'google.com', 'DOMAIN-SUFFIX'),
      rule('代理', '1.2.3.0/24', 'IP-CIDR'),
      rule('代理', '2001:db8::/32', 'IP-CIDR6'),
      rule('代理', '443', 'DST-PORT'),
      rule('DIRECT', 'ads.example.com', 'DOMAIN-SUFFIX'),
      { ...rule('代理', '10.0.0.0/8', 'IP-CIDR'), noResolve: true },
      { type: 'MATCH', group: '代理' },
    ],
    ruleSets: [
      { id: 'empty-set', name: '空规则集', group: '代理', sourceKind: 'local', updatedAt: 1, rules: [] },
    ],
  }
  const explainNodes: ProxyNode[] = [
    { id: 'n1', kind: 'ss', name: '🇭🇰 香港 01', server: 'hk.example.com', port: 443, tls: true, skipCertificateVerification: false, rawURI: '' },
  ]

  check('命中解释器按导出顺序 first-match，并解析策略组节点', () => {
    const result = explainQuery({ scheme: explainScheme, nodes: explainNodes, policySelections: {} }, 'https://www.google.com/a')
    assert.equal(result.steps.length, 2)
    assert.equal(result.steps[0].evaluation.status, 'miss')
    assert.equal(result.match?.index, 2)
    assert.equal(result.match?.rule.type, 'DOMAIN-SUFFIX')
    assert.equal(result.final.group, '代理')
    assert.equal(result.final.candidates, 1)
    assert.equal(result.final.node, '🇭🇰 香港 01')
    assert.equal(result.notes.some((note) => note.includes('空规则集')), true)
  })

  check('命中解释器区分 IPv4 / IPv6 / 端口与兜底', () => {
    const compiled = compileScheme({ scheme: explainScheme, nodes: explainNodes, policySelections: {} })
    assert.equal(explainWithIndex(compiled, '1.2.3.4').match, 3)
    assert.equal(explainWithIndex(compiled, '[2001:db8::1]:8443').match, 4)
    assert.equal(explainWithIndex(compiled, '8.8.8.8:443').match, 5)
    const fallback = explainWithIndex(compiled, 'unmatched.example.org')
    assert.equal(fallback.result.match?.rule.type, 'MATCH')
    assert.equal(fallback.result.final.isFallback, true)
  })

  check('IP 规则对域名输入给出跳过原因而不是误判未命中', () => {
    const result = explainQuery({ scheme: explainScheme, nodes: explainNodes, policySelections: {} }, 'unknown.example.org')
    const skipped = result.steps.find((step) => step.rule.type === 'IP-CIDR')
    assert.equal(skipped?.evaluation.status, 'skip')
    assert.match(skipped?.evaluation.reason ?? '', /解析|no-resolve/)
  })

  const certaintyScheme: RuleScheme = {
    id: 'certainty',
    name: '确定度',
    description: '',
    groups: [
      { name: '代理', type: 'select', options: ['DIRECT'] },
      { name: '直连', type: 'select', options: ['DIRECT'] },
    ],
    rules: [
      rule('代理', 'example.com'),
      rule('代理', '1.2.3.0/24', 'IP-CIDR'),
      rule('代理', 'CN', 'GEOIP'),
      rule('代理', 'US', 'GEOIP'),
      { type: 'RULE-SET', value: '静态集合', group: '代理' },
      { type: 'RULE-SET', value: '混合集合', group: '直连' },
      { type: 'MATCH', group: '代理' },
    ],
    ruleSets: [
      {
        id: 'static-set',
        name: '静态集合',
        group: '代理',
        sourceKind: 'local',
        updatedAt: 1,
        rules: [rule('代理', 'static.example.com', 'DOMAIN-SUFFIX'), rule('代理', 'static.example.net')],
      },
      {
        id: 'mixed-set',
        name: '混合集合',
        group: '直连',
        sourceKind: 'local',
        updatedAt: 1,
        rules: [rule('直连', 'mixed.example.com'), rule('直连', '9.9.9.0/24', 'IP-CIDR')],
      },
    ],
  }

  check('完整轨迹：确定命中后立即短路，后续规则不再评估', () => {
    const result = explainQuery({ scheme: certaintyScheme, nodes: explainNodes, policySelections: {} }, 'example.com')
    assert.ok(result.match)
    // 命中即停：轨迹长度等于命中序号（1 起算），后面的规则不再评估。
    assert.equal(result.steps.length, result.match.index)
    assert.equal(result.steps.at(-1)?.certainty, 'confirmed-match')
    assert.ok(result.totalRules > result.steps.length)
    assert.equal(result.steps.some((step) => step.rule.type === 'GEOIP'), false)
  })

  check('完整轨迹：只有域名时 IP / GEOIP 规则是可能命中，静态未命中是确定不命中', () => {
    const result = explainQuery({ scheme: certaintyScheme, nodes: explainNodes, policySelections: {} }, 'other.example.org')
    const byType = (type: string, value?: string) => result.steps.find(
      (step) => step.rule.type === type && (value === undefined || step.rule.value === value),
    )
    assert.equal(byType('DOMAIN')?.certainty, 'confirmed-miss')
    assert.equal(byType('IP-CIDR')?.certainty, 'possible-match')
    assert.equal(byType('GEOIP', 'CN')?.certainty, 'possible-match')
    assert.equal(byType('GEOIP', 'US')?.certainty, 'possible-match')
  })

  check('完整轨迹：IP 输入时域名规则确定不命中，缺库 GEOIP 无法判定', () => {
    const result = explainQuery({ scheme: certaintyScheme, nodes: explainNodes, policySelections: {} }, '8.8.8.8')
    const us = result.steps.find((step) => step.rule.type === 'GEOIP' && step.rule.value === 'US')
    assert.equal(us?.evaluation.status, 'unknown')
    assert.equal(us?.certainty, 'undetermined')
    const domain = result.steps.find((step) => step.rule.type === 'DOMAIN')
    assert.equal(domain?.certainty, 'confirmed-miss')
    const last = result.steps[result.steps.length - 1]
    assert.equal(last.rule.type, 'MATCH')
  })

  check('完整轨迹：规则集内混着运行时规则时标可能命中，不误报全部未命中', () => {
    const result = explainQuery({ scheme: certaintyScheme, nodes: explainNodes, policySelections: {} }, 'nomatch.example.org')
    const mixed = result.steps.find((step) => step.rule.type === 'RULE-SET' && step.rule.value === '混合集合')
    assert.equal(mixed?.evaluation.status, 'skip')
    assert.equal(mixed?.certainty, 'possible-match')
    assert.match(mixed?.evaluation.detail ?? '', /1 条需要运行时数据/)
    const statics = result.steps.find((step) => step.rule.type === 'RULE-SET' && step.rule.value === '静态集合')
    assert.equal(statics?.certainty, 'confirmed-miss')
  })

  check('完整轨迹：规则集内联规则命中按确定命中并标出来源', () => {
    const result = explainQuery({ scheme: certaintyScheme, nodes: explainNodes, policySelections: {} }, 'static.example.com')
    assert.equal(result.match?.index, 1)
    assert.equal(result.steps[0].certainty, 'confirmed-match')
    assert.equal(result.steps[0].origin.setName, '静态集合')
    assert.match(result.steps[0].evaluation.detail ?? '', /static\.example\.com/)
  })

  check('方案 lint：重复 / 死规则 / 缺失组 / 空规则集 / 类型候选', () => {
    const lintGroups: PolicyGroup[] = [
      { name: '代理', type: 'select', options: ['🇭🇰 香港 01', 'DIRECT'] },
      { name: '自动', type: 'url-test', options: [], nodeFilter: '香港' },
      { name: '空组', type: 'select', options: [] },
    ]
    const issues = lintScheme({
      scheme: {
        id: 'lint',
        name: 'lint',
        description: '',
        groups: lintGroups,
        rules: [
          rule('代理', 'example.com', 'DOMAIN-SUFFIX'),
          rule('代理', 'ads.example.com', 'DOMAIN'),
          rule('代理', 'example.com', 'DOMAIN'),
          rule('代理', 'dup.example.com', 'DOMAIN-SUFFIX'),
          rule('代理', 'dup.example.com', 'DOMAIN-SUFFIX'),
          rule('不存在的组', 'missing.example.com'),
          { type: 'FINAL', group: '代理' },
        ],
        ruleSets: [{ id: 'empty', name: '空规则集', group: '代理', sourceKind: 'local', updatedAt: 1, rules: [] }],
      },
      nodes: explainNodes,
      clients: [],
    })
    const codes = issues.map((issue) => issue.code)
    assert.ok(codes.includes('duplicateRuleSameGroup'))
    assert.ok(codes.includes('shadowedRule'))
    assert.ok(codes.includes('missingRuleTarget'))
    assert.ok(codes.includes('emptyRuleSet'))
    assert.ok(codes.includes('groupTypeCandidateMismatch'))
    assert.ok(codes.includes('emptyGroup'))
    // 死规则 / 跨组重复只作为提示（info），不把内置方案刷成一片警告。
    assert.equal(issues.find((issue) => issue.code === 'shadowedRule')?.level, 'info')
    // 同一条完全重复的规则只报一次重复，不再叠加「死规则」（重复项本身不产生 dead）。
    assert.equal(issues.filter((issue) => issue.code === 'shadowedRule').length, 4)
    assert.equal(issues.some((issue) => issue.code === 'dead:4'), false)
    // 空组只报 emptyGroup，不再重复报 selectGroupEmpty。
    assert.equal(codes.filter((code) => code === 'selectGroupEmpty').length, 0)
  })

  check('方案 lint 复用客户端兼容性判断', () => {
    const qx = CLIENTS.find((client) => client.name.includes('Quantumult X'))
    assert.ok(qx)
    const issues = lintScheme({
      scheme: {
        id: 'compat',
        name: 'compat',
        description: '',
        groups: [{ name: '代理', type: 'select', options: ['DIRECT'] }],
        rules: [{ type: 'PROCESS-NAME', value: 'curl', group: '代理' }, { type: 'FINAL', group: '代理' }],
      },
      nodes: explainNodes,
      clients: [qx],
    })
    assert.ok(issues.some((issue) => issue.code === 'unsupportedRuleType'))
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部匹配顺序检查通过')
}

main()
