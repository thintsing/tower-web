// 重复规则一键清理自检：判定必须区分「同组纯冗余 / 跨组遮蔽 / 前置已失效 / 只读来源」。
// 用法：npm run selfcheck:duplicates
import assert from 'node:assert/strict'
import type { RoutingRule, RuleScheme, SchemeRuleSet } from '../src/models/types'
import { analyzeDuplicateCleanup, applyDuplicateCleanup, restoreRemovedRules } from '../src/rules/duplicateCleanup'

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

  check('撤销精确回插：只恢复被删条目，清理之后的编辑不动', () => {
    const set: SchemeRuleSet = {
      id: 'set-local',
      name: '本地规则集',
      group: 'A',
      sourceKind: 'local',
      rules: [
        rule('DOMAIN', 'set-a.example', 'A'),
        rule('DOMAIN', 'SET-A.EXAMPLE', 'A'),
        rule('DOMAIN', 'set-b.example', 'A'),
      ],
    }
    const input = scheme([
      rule('DOMAIN', 'keep.example', 'A'),
      rule('DOMAIN', 'KEEP.EXAMPLE', 'A'),
      rule('FINAL', '', 'DIRECT'),
    ], {
      customRules: [
        rule('DOMAIN', 'c1.example', 'A'),
        rule('DOMAIN', 'C1.EXAMPLE', 'A'),
        rule('DOMAIN', 'c2.example', 'A'),
      ],
      ruleSets: [set],
    })
    const plan = analyzeDuplicateCleanup(input)
    const applied = applyDuplicateCleanup(input, plan)
    assert.equal(applied.removed, 3, 'scheme / custom / ruleSet 各删一条')
    assert.deepEqual(
      applied.applied.map((item) => item.place.kind).sort(),
      ['custom', 'ruleSet', 'scheme'],
    )

    // 模拟用户清理后继续编辑：三处各追加一条规则。
    const edited: RuleScheme = {
      ...applied.scheme,
      customRules: [...(applied.scheme.customRules ?? []), rule('DOMAIN', 'later-custom.example', 'A')],
      rules: [...applied.scheme.rules.slice(0, -1), rule('DOMAIN', 'later-scheme.example', 'A'), applied.scheme.rules.at(-1)!],
      ruleSets: applied.scheme.ruleSets?.map((item) => item.id === set.id
        ? { ...item, rules: [...item.rules, rule('DOMAIN', 'later-set.example', 'A')] }
        : item),
    }

    const restored = restoreRemovedRules(edited, applied.applied)
    assert.equal(restored.restored, 3)
    assert.equal(restored.skipped, 0)
    assert.deepEqual(restored.scheme.rules.map((item) => item.value), [
      'keep.example', 'KEEP.EXAMPLE', 'later-scheme.example', '',
    ])
    assert.deepEqual(restored.scheme.customRules?.map((item) => item.value), [
      'c1.example', 'C1.EXAMPLE', 'c2.example', 'later-custom.example',
    ])
    assert.deepEqual(restored.scheme.ruleSets?.[0].rules.map((item) => item.value), [
      'set-a.example', 'SET-A.EXAMPLE', 'set-b.example', 'later-set.example',
    ])
  })

  check('撤销边界：原位已有同条规则时跳过，不重复插入', () => {
    const input = scheme([
      rule('DOMAIN', 'keep.example', 'A'),
      rule('DOMAIN', 'KEEP.EXAMPLE', 'A'),
    ])
    const plan = analyzeDuplicateCleanup(input)
    const applied = applyDuplicateCleanup(input, plan)
    // 用户清理后又手工把同一条加回原位。
    const edited = scheme([
      input.rules[0],
      { ...input.rules[1] },
    ])
    const restored = restoreRemovedRules(edited, applied.applied)
    assert.equal(restored.restored, 0)
    assert.equal(restored.skipped, 1)
    assert.equal(restored.scheme.rules.length, 2)
  })

  check('撤销边界：规则集被替换成只读来源时跳过并计数', () => {
    const set: SchemeRuleSet = {
      id: 'set-local',
      name: '本地规则集',
      group: 'A',
      sourceKind: 'local',
      rules: [
        rule('DOMAIN', 'a.example', 'A'),
        rule('DOMAIN', 'A.EXAMPLE', 'A'),
      ],
    }
    const input = scheme([rule('FINAL', '', 'DIRECT')], { ruleSets: [set] })
    const plan = analyzeDuplicateCleanup(input)
    const applied = applyDuplicateCleanup(input, plan)
    const replaced: RuleScheme = {
      ...applied.scheme,
      ruleSets: applied.scheme.ruleSets?.map((item) => ({ ...item, sourceKind: 'url' as const })),
    }
    const restored = restoreRemovedRules(replaced, applied.applied)
    assert.equal(restored.restored, 0)
    assert.equal(restored.skipped, 1)
    assert.equal(restored.scheme.ruleSets?.[0].rules.length, 1)
  })

  check('撤销边界：规则集已被删除时跳过', () => {
    const set: SchemeRuleSet = {
      id: 'set-local',
      name: '本地规则集',
      group: 'A',
      sourceKind: 'local',
      rules: [
        rule('DOMAIN', 'a.example', 'A'),
        rule('DOMAIN', 'A.EXAMPLE', 'A'),
      ],
    }
    const input = scheme([rule('FINAL', '', 'DIRECT')], { ruleSets: [set] })
    const plan = analyzeDuplicateCleanup(input)
    const applied = applyDuplicateCleanup(input, plan)
    const removed: RuleScheme = { ...applied.scheme, ruleSets: [] }
    const restored = restoreRemovedRules(removed, applied.applied)
    assert.equal(restored.restored, 0)
    assert.equal(restored.skipped, 1)
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
