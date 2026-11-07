// 自检：规则页逐条顺序（ruleOrder）在展示与导出之间保持一致。
// 用法：npx tsx scripts/selfcheck-rule-order.ts
import assert from 'node:assert/strict'
import type { PolicyGroup, RoutingRule, RuleScheme } from '../src/models/types'
import {
  applyRuleOrder,
  isUnmovableRule,
  orderedSchemeRules,
  renameRuleOrderKeys,
  ruleOrderKeys,
} from '../src/rules/ruleOrder'
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

function group(name: string): PolicyGroup {
  return { name, type: 'select', options: ['DIRECT'] }
}

function rule(group: string, value: string, type = 'DOMAIN'): RoutingRule {
  return { type, value, group }
}

function baseScheme(): RuleScheme {
  return {
    id: 'rule-order',
    name: '逐条排序',
    description: '',
    groups: [group('A'), group('B'), group('C')],
    rules: [
      rule('A', 'a.example.com'),
      rule('B', 'b.example.com'),
      rule('A', 'CN', 'GEOIP'),
      rule('C', 'wide.example'),
      { type: 'FINAL', group: 'C' },
    ],
    customRules: [
      rule('C', 'custom.example.com', 'DOMAIN-SUFFIX'),
    ],
  }
}

function orderFrom(rules: RoutingRule[]): string[] {
  return ruleOrderKeys(rules)
}

function main(): void {
  check('兜底锚点：GEOIP / FINAL / MATCH 不可手动移动', () => {
    assert.equal(isUnmovableRule({ type: 'GEOIP', group: 'A' }), true)
    assert.equal(isUnmovableRule({ type: 'FINAL', group: 'A' }), true)
    assert.equal(isUnmovableRule({ type: 'MATCH', group: 'A' }), true)
    assert.equal(isUnmovableRule({ type: 'DOMAIN', value: 'a.com', group: 'A' }), false)
  })

  check('没有 ruleOrder 时保持自定义前置 + 原规则顺序', () => {
    const scheme = baseScheme()
    const ordered = orderedSchemeRules(scheme)
    assert.deepEqual(ordered.map((item) => item.type), ['DOMAIN-SUFFIX', 'DOMAIN', 'DOMAIN', 'GEOIP', 'DOMAIN', 'FINAL'])
    assert.deepEqual(prepareSchemeForExport(scheme, {}, {}).rules, ordered)
  })

  check('逐条上移：展示与导出同步，GEOIP 锚点不动', () => {
    const scheme = baseScheme()
    const ordered = orderedSchemeRules(scheme)
    // 0 是自定义规则；把第 2 条（B）移到第 1 条（A）之前。
    const next = [...ordered]
    const [moved] = next.splice(2, 1)
    next.splice(1, 0, moved)
    scheme.ruleOrder = orderFrom(next)
    const shown = orderedSchemeRules(scheme)
    const exported = prepareSchemeForExport(scheme, {}, {}).rules
    assert.deepEqual(shown, exported)
    assert.deepEqual(shown.map((item) => `${item.type}:${item.value ?? ''}:${item.group}`), [
      'DOMAIN-SUFFIX:custom.example.com:C',
      'DOMAIN:b.example.com:B',
      'DOMAIN:a.example.com:A',
      'GEOIP:CN:A',
      'DOMAIN:wide.example:C',
      'FINAL::C',
    ])
  })

  check('自定义规则可以被手动移到方案规则之后（显式意图优先）', () => {
    const scheme = baseScheme()
    const ordered = orderedSchemeRules(scheme)
    const next = [...ordered]
    const [moved] = next.splice(0, 1)
    next.splice(1, 0, moved)
    scheme.ruleOrder = orderFrom(next)
    const shown = orderedSchemeRules(scheme)
    assert.equal(shown[0].value, 'a.example.com')
    assert.equal(shown[1].value, 'custom.example.com')
    assert.deepEqual(shown, prepareSchemeForExport(scheme, {}, {}).rules)
  })

  check('ruleOrder 不会跨过 GEOIP 锚点把规则挪到兜底段', () => {
    const rules: RoutingRule[] = [
      rule('A', 'a.example.com'),
      rule('B', 'b.example.com'),
      rule('A', 'CN', 'GEOIP'),
      rule('C', 'c.example.com'),
    ]
    // 故意把 GEOIP 之后的规则排在 GEOIP 之前。
    const order = ruleOrderKeys([rules[3], rules[1], rules[0]])
    const applied = applyRuleOrder(rules, order)
    assert.deepEqual(applied.map((item) => item.value), [
      'b.example.com',
      'a.example.com',
      'CN',
      'c.example.com',
    ])
    assert.deepEqual(
      applyRuleOrder(rules, undefined),
      rules,
    )
  })

  check('刷新后新增的未排序规则按原坑位插回，不被挪到末尾', () => {
    const rules: RoutingRule[] = [
      rule('A', 'a.example.com'),
      rule('B', 'b.example.com'),
      rule('C', 'new.example.com'),
      rule('A', 'z.example.com'),
    ]
    const order = ruleOrderKeys([rules[1], rules[0], rules[2], rules[3]])
    const applied = applyRuleOrder(rules, order)
    assert.deepEqual(applied.map((item) => item.value), [
      'b.example.com',
      'a.example.com',
      'new.example.com',
      'z.example.com',
    ])
  })

  check('组改名 / 删除时同步逐条顺序键', () => {
    const keys = ruleOrderKeys([rule('老组', 'a.example.com'), rule('其他', 'b.example.com')])
    const renamed = renameRuleOrderKeys(keys, [['老组', '新组']])
    assert.equal(renamed?.[0].endsWith('新组'), true)
    assert.equal(renamed?.[1].endsWith('其他'), true)
  })

  if (failures) {
    console.error(`\n${failures} 项失败`)
    process.exit(1)
  }
  console.log('\n全部通过')
}

main()
