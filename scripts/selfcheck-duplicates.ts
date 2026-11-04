// 重复规则一键清理自检：判定必须区分「同组纯冗余 / 跨组遮蔽 / 前置已失效 / 只读来源」。
// 用法：npm run selfcheck:duplicates
import assert from 'node:assert/strict'
import type { RoutingRule, RuleScheme, SchemeRuleSet } from '../src/models/types'
import { analyzeDuplicateCleanup, applyDuplicateCleanup } from '../src/rules/duplicateCleanup'

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

function rule(type: string, value: string, group: string, extra: Partial<RoutingRule> = {}): RoutingRule {
  return { type, value, group, ...extra }
}

function scheme(rules: RoutingRule[], extra: Partial<RuleScheme> = {}): RuleScheme {
  return {
    id: 'scheme-test',
    name: '测试方案',
    description: '',
    groups: [],
    rules,
    ...extra,
  }
}

function summary(plan: ReturnType<typeof analyzeDuplicateCleanup>): string {
  return JSON.stringify({
    deletions: plan.deletions.length,
    readOnly: plan.skipped.readOnly.length,
    crossGroup: plan.skipped.crossGroup.length,
    dead: plan.skipped.deadPredecessor.length,
    groups: plan.groups,
  })
}

function main(): void {
  check('同组 + 大小写/首尾点差异 → 判定为可删重复', () => {
    const plan = analyzeDuplicateCleanup(scheme([
      rule('DOMAIN-SUFFIX', 'Cursor.COM', '🚀 节点选择'),
      rule('DOMAIN-SUFFIX', 'cursor.com.', '🚀 节点选择'),
    ]))
    assert.equal(plan.deletions.length, 1)
    assert.equal(plan.deletions[0].duplicateOfIndex, 1)
    assert.equal(plan.groups, 1)
  })

  check('跨组遮蔽 → 不进删除集合，单列「需你决定」', () => {
    const plan = analyzeDuplicateCleanup(scheme([
      rule('DOMAIN-SUFFIX', 'copilot.cloud.microsoft', 'Ⓜ️ 微软Bing'),
      rule('DOMAIN-SUFFIX', 'copilot.cloud.microsoft', '🌍 国外媒体'),
    ]))
    assert.equal(plan.deletions.length, 0)
    assert.equal(plan.skipped.crossGroup.length, 1)
    assert.equal(plan.skipped.crossGroup[0].firstGroup, 'Ⓜ️ 微软Bing')
    assert.equal(plan.skipped.crossGroup[0].group, '🌍 国外媒体')
  })

  check('前置规则本身已被遮蔽 → 不据此判定重复', () => {
    const plan = analyzeDuplicateCleanup(scheme([
      rule('DOMAIN-SUFFIX', 'example.com', '🚀 节点选择'),
      rule('DOMAIN-SUFFIX', 'ads.example.com', '🛑 广告拦截'),
      rule('DOMAIN-SUFFIX', 'ADS.EXAMPLE.COM', '🛑 广告拦截'),
    ]))
    assert.equal(plan.deletions.length, 0)
    assert.equal(plan.skipped.deadPredecessor.length, 1)
    assert.ok(plan.skipped.deadPredecessor[0].firstIndex === 2)
  })

  check('只读规则集内的重复 → 跳过并给出可写性原因', () => {
    const set: SchemeRuleSet = {
      id: 'set-url',
      name: '在线规则集',
      group: '🚀 节点选择',
      sourceKind: 'url',
      sourceRef: 'https://example.com/rules.list',
      rules: [
        rule('DOMAIN-SUFFIX', 'example.com', '🚀 节点选择'),
        rule('DOMAIN-SUFFIX', 'EXAMPLE.COM', '🚀 节点选择'),
      ],
    }
    const plan = analyzeDuplicateCleanup(scheme([rule('FINAL', '', 'DIRECT')], { ruleSets: [set] }))
    assert.equal(plan.deletions.length, 0)
    assert.equal(plan.skipped.readOnly.length, 1)
    assert.match(plan.skipped.readOnly[0].source, /在线规则集/)
  })

  check('同一值出现 3 次 → 保留第一条，其余全部可删', () => {
    const plan = analyzeDuplicateCleanup(scheme([
      rule('DOMAIN', 'example.com', '🚀 节点选择'),
      rule('DOMAIN', 'Example.com', '🚀 节点选择'),
      rule('DOMAIN', ' example.com ', '🚀 节点选择'),
    ]))
    assert.equal(plan.deletions.length, 2)
    assert.deepEqual(plan.deletions.map((item) => item.duplicateOfIndex), [1, 1])
  })

  check('跨来源同组重复 → 删除后出现的方案规则', () => {
    const plan = analyzeDuplicateCleanup(scheme([
      rule('DOMAIN-SUFFIX', 'cursor.com', '🚀 节点选择'),
    ], {
      customRules: [rule('DOMAIN-SUFFIX', 'cursor.com', '🚀 节点选择')],
    }))
    assert.equal(plan.deletions.length, 1)
    assert.equal(plan.deletions[0].place.kind, 'scheme')
  })

  check('选项不同（no-resolve）不算重复', () => {
    const plan = analyzeDuplicateCleanup(scheme([
      rule('IP-CIDR', '1.2.3.0/24', '🚀 节点选择'),
      rule('IP-CIDR', '1.2.3.0/24', '🚀 节点选择', { noResolve: true }),
    ]))
    assert.equal(plan.total, 0)
  })

  check('应用后确实删除后一条并保留第一条', () => {
    const input = scheme([
      rule('DOMAIN-SUFFIX', 'example.com', '🚀 节点选择'),
      rule('DOMAIN-SUFFIX', 'EXAMPLE.COM', '🚀 节点选择'),
    ])
    const plan = analyzeDuplicateCleanup(input)
    const result = applyDuplicateCleanup(input, plan)
    assert.equal(result.removed, 1)
    assert.deepEqual(result.scheme.rules.map((item) => item.value), ['example.com'])
  })

  check('只读来源不会被 apply 误删', () => {
    const set: SchemeRuleSet = {
      id: 'set-url',
      name: '在线规则集',
      group: '🚀 节点选择',
      sourceKind: 'url',
      rules: [
        rule('DOMAIN', 'readonly.example', '🚀 节点选择'),
        rule('DOMAIN', 'readonly.example', '🚀 节点选择'),
      ],
    }
    const input = scheme([rule('FINAL', '', 'DIRECT')], { ruleSets: [set] })
    const plan = analyzeDuplicateCleanup(input)
    const result = applyDuplicateCleanup(input, plan)
    assert.equal(result.removed, 0)
    assert.equal(result.scheme.ruleSets?.[0].rules.length, 2)
  })

  check('摘要计数覆盖四类结果', () => {
    const plan = analyzeDuplicateCleanup(scheme([
      rule('DOMAIN-SUFFIX', 'a.example', 'A'),
      rule('DOMAIN-SUFFIX', 'A.EXAMPLE', 'A'),
      rule('DOMAIN-SUFFIX', 'b.example', 'A'),
      rule('DOMAIN-SUFFIX', 'b.example', 'B'),
      rule('DOMAIN-SUFFIX', 'example.com', 'A'),
      rule('DOMAIN-SUFFIX', 'ads.example.com', 'B'),
      rule('DOMAIN-SUFFIX', 'ADS.EXAMPLE.COM', 'B'),
    ]))
    console.log(`  ${summary(plan)}`)
    assert.equal(plan.total, 3)
    assert.equal(plan.deletions.length, 1)
    assert.equal(plan.skipped.crossGroup.length, 1)
    assert.equal(plan.skipped.deadPredecessor.length, 1)
  })

  console.log(failures === 0 ? '\n全部重复规则清理自检通过' : `\n${failures} 项重复规则清理自检失败`)
  process.exit(failures === 0 ? 0 : 1)
}

main()
