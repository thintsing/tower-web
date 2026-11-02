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
  buildNodeFilterGroup,
  nextGroupName,
  previewNodeMatches,
  removePolicyGroup,
  validateNodeGroupDraft,
} from '../src/rules/groupEditing'
import { findRuleOrderConflicts } from '../src/rules/orderConflicts'
import { prepareSchemeForExport } from '../src/generator/groups'

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

  check('规则集插到第一条冲突规则之前，而不是全部压到最前', () => {
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
        'DOMAIN,a.example.com,A',
        'DOMAIN,b.example.com,B',
        'DOMAIN,b2.example.com,B',
        'DOMAIN,b.example.com,B',
        'DOMAIN,not-in-template.example.com,C',
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
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部匹配顺序检查通过')
}

main()
