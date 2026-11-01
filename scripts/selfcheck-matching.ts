// 自检：拖动策略组后的规则匹配顺序。
// 用法：npm run selfcheck:matching
import assert from 'node:assert/strict'
import type { PolicyGroup, RoutingRule, RuleScheme } from '../src/models/types'
import {
  matchingGroupNames,
  matchingOrderAfterDragging,
  reorderRulesByMatchingOrder,
} from '../src/rules/matchingOrder'
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

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部匹配顺序检查通过')
}

main()
