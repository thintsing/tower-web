// 重复规则一键清理自检：判定必须区分「同组纯冗余 / 跨组冗余 / 前置已失效 / 只读来源」。
// 跨组删除的合法性由命中解释器验证：删除前后同一批样例的命中规则、目标策略组、
// 是否走兜底必须完全一致——这是「删了等于没删」的直接证据。
// 用法：npm run selfcheck:duplicates
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import type { PolicyGroup, ProxyNode, RoutingRule, RuleScheme, SchemeRuleSet } from '../src/models/types'
import { CLIENTS } from '../src/models/types'
import { analyzeDuplicateCleanup, applyDuplicateCleanup, restoreRemovedRules } from '../src/rules/duplicateCleanup'
import { applyFixAction, buildFixActions } from '../src/rules/diagnosis'
import { compileScheme, explainWith } from '../src/rules/ruleExplain'
import { lintScheme, lintSummary } from '../src/rules/schemeLint'
import { ruleSignature } from '../src/rules/ruleDiff'
import { prepareSchemeForExport } from '../src/generator/groups'
import { generateSubscriptionFormats } from '../src/generator'
import { addRuleSetExclusion, filterExcludedRuleSets, normalizeRuleSetExclusions, removeRuleSetExclusion } from '../src/rules/ruleSetExclusions'
import { createEditableSchemeCopy, undoEditableSchemeCopy } from '../src/rules/schemeCopy'
import { useStore } from '../src/store'
import { applyServerData, workspaceSnapshot } from '../src/workspaceSync'
import { normalizeWorkspaceData } from '../src/workspaceValidation'

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
    sameGroup: plan.sameGroupCount,
    crossGroup: plan.crossGroupCount,
    keptGroups: plan.keptGroups,
    droppedGroups: plan.droppedGroups,
    readOnly: plan.skipped.readOnly.length,
    dead: plan.skipped.deadPredecessor.length,
    groups: plan.groups,
  })
}

/** 取出源码里每个 lintScheme(...) 的实参文本，用来确认调用方真的传了屏蔽表。 */
function lintCallArgs(source: string): string[] {
  const calls: string[] = []
  const marker = 'lintScheme('
  let index = source.indexOf(marker)
  while (index >= 0) {
    let depth = 0
    let end = source.length
    for (let cursor = index + marker.length - 1; cursor < source.length; cursor += 1) {
      if (source[cursor] === '(') depth += 1
      if (source[cursor] === ')') {
        depth -= 1
        if (depth === 0) {
          end = cursor
          break
        }
      }
    }
    calls.push(source.slice(index + marker.length, end))
    index = source.indexOf(marker, end)
  }
  return calls
}

function selectGroups(...names: string[]): PolicyGroup[] {
  return names.map((name) => ({ name, type: 'select', options: ['DIRECT'] }))
}

/** 命中规则签名 + 目标策略组 + 是否走兜底；三项都相同才算「删了等于没删」。 */
function verdict(input: RuleScheme, query: string): string {
  const compiled = compileScheme({ scheme: input, nodes: [] })
  const result = explainWith(compiled, query)
  return JSON.stringify({
    rule: result.match ? ruleSignature(result.match.rule) : '(no-match)',
    group: result.final.group ?? '',
    fallback: result.final.isFallback,
  })
}

function nodeFixture(): ProxyNode {
  return {
    id: 'hk', kind: 'ss', name: '香港 01', server: 'hk.example.com', port: 8388,
    cipher: 'aes-256-gcm', password: 'p1', tls: false, skipCertificateVerification: false,
  }
}

function main(): void {
  check('同组 + 大小写/首尾点差异 → 判定为可删重复', () => {
    const plan = analyzeDuplicateCleanup(scheme([
      rule('DOMAIN-SUFFIX', 'Cursor.COM', '🚀 节点选择'),
      rule('DOMAIN-SUFFIX', 'cursor.com.', '🚀 节点选择'),
    ]))
    assert.equal(plan.deletions.length, 1)
    assert.equal(plan.deletions[0].duplicateOfIndex, 1)
    assert.equal(plan.deletions[0].kind, 'sameGroup')
    assert.equal(plan.groups, 1)
  })

  check('跨组重复 + 前一条存活 → 纳入删除，并给出保留/删除配对', () => {
    const plan = analyzeDuplicateCleanup(scheme([
      rule('DOMAIN-SUFFIX', 'copilot.cloud.microsoft', 'Ⓜ️ 微软Bing'),
      rule('DOMAIN-SUFFIX', 'copilot.cloud.microsoft', '🌍 国外媒体'),
    ]))
    assert.equal(plan.deletions.length, 1)
    assert.equal(plan.deletions[0].kind, 'crossGroup')
    assert.equal(plan.deletions[0].duplicateOfGroup, 'Ⓜ️ 微软Bing')
    assert.equal(plan.deletions[0].group, '🌍 国外媒体')
    assert.equal(plan.sameGroupCount, 0)
    assert.equal(plan.crossGroupCount, 1)
    assert.equal(plan.keptGroups, 1)
    assert.equal(plan.droppedGroups, 1)
    assert.equal(plan.crossPairs.length, 1)
    assert.equal(plan.crossPairs[0].keepGroup, 'Ⓜ️ 微软Bing')
    assert.equal(plan.crossPairs[0].dropGroup, '🌍 国外媒体')
    assert.equal(plan.crossPairs[0].count, 1)
    assert.equal(plan.skipped.deadPredecessor.length, 0)
  })

  check('前置规则本身已被遮蔽 → 跨组也不删，维持需你决定', () => {
    const plan = analyzeDuplicateCleanup(scheme([
      rule('DOMAIN-SUFFIX', 'example.com', '🚀 节点选择'),
      rule('DOMAIN-SUFFIX', 'ads.example.com', '🛑 广告拦截'),
      rule('DOMAIN-SUFFIX', 'ADS.EXAMPLE.COM', '🌍 国外媒体'),
    ]))
    assert.equal(plan.deletions.length, 0)
    assert.equal(plan.skipped.deadPredecessor.length, 1)
    assert.equal(plan.skipped.deadPredecessor[0].firstIndex, 2)
    assert.equal(plan.skipped.deadPredecessor[0].group, '🌍 国外媒体')
  })

  check('跨组但选项不同（no-resolve） → 不算重复', () => {
    const plan = analyzeDuplicateCleanup(scheme([
      rule('IP-CIDR', '1.2.3.0/24', '🚀 节点选择'),
      rule('IP-CIDR', '1.2.3.0/24', '🛑 广告拦截', { noResolve: true }),
    ]))
    assert.equal(plan.total, 0)
    assert.equal(plan.deletions.length, 0)
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

  check('跨组但前一条来自只读规则集 → 跳过并计数', () => {
    const set: SchemeRuleSet = {
      id: 'set-url',
      name: '在线规则集',
      group: 'Ⓜ️ 微软Bing',
      sourceKind: 'url',
      sourceRef: 'https://example.com/rules.list',
      rules: [rule('DOMAIN-SUFFIX', 'shared.example', 'Ⓜ️ 微软Bing')],
    }
    const plan = analyzeDuplicateCleanup(scheme([
      rule('DOMAIN-SUFFIX', 'shared.example', '🌍 国外媒体'),
      rule('FINAL', '', 'DIRECT'),
    ], { ruleSets: [set] }))
    assert.equal(plan.deletions.length, 0)
    assert.equal(plan.skipped.readOnly.length, 1)
    assert.equal(plan.skipped.readOnly[0].firstGroup, 'Ⓜ️ 微软Bing')
    assert.match(plan.skipped.readOnly[0].firstSource ?? '', /在线规则集/)
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

  check('跨组删除后撤销 → 精确回插到原位置', () => {
    const input = scheme([
      rule('DOMAIN-SUFFIX', 'keep.example', 'A'),
      rule('DOMAIN-SUFFIX', 'copilot.cloud.microsoft', 'Ⓜ️ 微软Bing'),
      rule('DOMAIN-SUFFIX', 'copilot.cloud.microsoft', '🌍 国外媒体'),
      rule('DOMAIN-SUFFIX', 'tail.example', 'A'),
      rule('FINAL', '', 'DIRECT'),
    ], { groups: selectGroups('A', 'Ⓜ️ 微软Bing', '🌍 国外媒体') })
    const plan = analyzeDuplicateCleanup(input)
    assert.equal(plan.deletions.length, 1)
    assert.equal(plan.deletions[0].kind, 'crossGroup')
    const applied = applyDuplicateCleanup(input, plan)
    assert.equal(applied.removed, 1)
    assert.deepEqual(applied.scheme.rules.map((item) => item.value), [
      'keep.example', 'copilot.cloud.microsoft', 'tail.example', '',
    ])
    assert.deepEqual(applied.scheme.rules.map((item) => item.group), [
      'A', 'Ⓜ️ 微软Bing', 'A', 'DIRECT',
    ])
    const restored = restoreRemovedRules(applied.scheme, applied.applied)
    assert.equal(restored.restored, 1)
    assert.deepEqual(restored.scheme.rules.map((item) => item.value), [
      'keep.example', 'copilot.cloud.microsoft', 'copilot.cloud.microsoft', 'tail.example', '',
    ])
    assert.deepEqual(restored.scheme.rules.map((item) => item.group), [
      'A', 'Ⓜ️ 微软Bing', '🌍 国外媒体', 'A', 'DIRECT',
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

  check('撤销边界：自定义规则全部被删光后仍能恢复', () => {
    const input = scheme([
      rule('DOMAIN-SUFFIX', 'CUSTOM.EXAMPLE', 'A'),
      rule('FINAL', '', 'DIRECT'),
    ], {
      customRules: [rule('DOMAIN-SUFFIX', 'custom.example', 'A')],
      groups: selectGroups('A'),
    })
    const plan = analyzeDuplicateCleanup(input, { keep: 'last' })
    const applied = applyDuplicateCleanup(input, plan)
    assert.equal(applied.removed, 1)
    assert.equal(applied.applied[0].place.kind, 'custom')
    assert.equal(applied.scheme.customRules?.length, 0)
    const restored = restoreRemovedRules(applied.scheme, applied.applied)
    assert.equal(restored.restored, 1)
    assert.deepEqual(restored.scheme.customRules?.map((item) => item.value), ['custom.example'])
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
    assert.equal(plan.deletions.length, 2)
    assert.equal(plan.sameGroupCount, 1)
    assert.equal(plan.crossGroupCount, 1)
    assert.equal(plan.keptGroups, 1)
    assert.equal(plan.droppedGroups, 1)
    assert.equal(plan.crossPairs.length, 1)
    assert.equal(plan.skipped.readOnly.length, 0)
    assert.equal(plan.skipped.deadPredecessor.length, 1)
  })

  check('语义验证：跨组/同组删除后，命中规则与目标策略组完全不变', () => {
    const set: SchemeRuleSet = {
      id: 'set-local',
      name: '本地规则集',
      group: 'A',
      sourceKind: 'local',
      rules: [
        rule('DOMAIN-KEYWORD', 'tracker', 'A'),
        rule('DOMAIN-KEYWORD', 'TRACKER', 'A'),
      ],
    }
    const input = scheme([
      rule('DOMAIN-SUFFIX', 'copilot.cloud.microsoft', 'Ⓜ️ 微软Bing'),
      rule('DOMAIN-SUFFIX', 'COPILOT.cloud.microsoft', '🌍 国外媒体'),
      rule('DOMAIN-SUFFIX', 'example.com', 'A'),
      rule('DOMAIN-SUFFIX', 'EXAMPLE.com', 'A'),
      rule('IP-CIDR', '10.0.0.0/8', 'A'),
      rule('IP-CIDR', '10.0.0.0/8', 'B'),
      rule('DOMAIN-SUFFIX', 'orange.example', 'A'),
      rule('FINAL', '', 'DIRECT'),
    ], {
      groups: selectGroups('A', 'B', 'Ⓜ️ 微软Bing', '🌍 国外媒体'),
      ruleSets: [set],
    })
    const plan = analyzeDuplicateCleanup(input)
    assert.equal(plan.deletions.length, 4, '跨组 2 条 + 同组 2 条（含规则集内 1 条）')
    assert.equal(plan.crossGroupCount, 2)
    const applied = applyDuplicateCleanup(input, plan)
    assert.equal(applied.removed, 4)

    // 每个被删条目取一条命中样例（域名 / IP / 关键字），再加 5 条兜底样例。
    const samples = ['copilot.cloud.microsoft', '10.1.2.3', 'example.com', 'my-tracker.example']
    const fallbacks = [
      'www.google.com',
      'https://example.com/path',
      '1.1.1.1',
      'ads.example.com',
      'unknown.example',
    ]
    const all = [...samples, ...fallbacks]
    for (const query of samples) {
      const before = verdict(input, query)
      const parsed = JSON.parse(before) as { rule: string; fallback: boolean }
      assert.notEqual(parsed.rule, '(no-match)', `${query} 删除前应命中规则`)
      assert.equal(parsed.fallback, false, `${query} 删除前不应走兜底`)
    }
    for (const query of all) {
      const before = verdict(input, query)
      const after = verdict(applied.scheme, query)
      assert.equal(after, before, `${query} 的命中结果在删除后发生了变化`)
    }

    // 反向对照：删掉一条真正生效的规则必须被比对发现；比对恒真时这里会变红。
    const control: RuleScheme = {
      ...input,
      rules: input.rules.filter((item) => item.value !== 'orange.example'),
    }
    assert.notEqual(verdict(control, 'orange.example'), verdict(input, 'orange.example'))
    console.log(`  语义验证：${plan.deletions.length} 条被删条目 + ${fallbacks.length} 条兜底样例全部一致`)
  })

  check('单条检查项：跨组重复 → 可删除，并写明保留组与删除组', () => {
    const input = scheme([
      rule('DOMAIN-SUFFIX', 'copilot.cloud.microsoft', 'Ⓜ️ 微软Bing'),
      rule('DOMAIN-SUFFIX', 'COPILOT.cloud.microsoft', '🌍 国外媒体'),
    ], { groups: selectGroups('Ⓜ️ 微软Bing', '🌍 国外媒体') })
    const issue = lintScheme({ scheme: input, nodes: [] }).find((item) => item.code === 'duplicateRule')
    assert.ok(issue, '应产生跨组重复检查项')
    assert.equal(issue.deletable, true)
    assert.equal(issue.firstGroup, 'Ⓜ️ 微软Bing')
    const action = buildFixActions(issue!).find((item) => item.kind === 'delete-rule')
    assert.ok(action, '应提供一键删除动作')
    assert.equal(action!.safe, true)
    assert.match(action!.label, /微软Bing/)
    assert.match(action!.label, /国外媒体/)
    assert.equal(action!.group, '🌍 国外媒体')
    assert.equal(action!.ruleText, issue.location.rule)
    assert.match(action!.ruleText ?? '', /cloud\.microsoft/i)
  })

  check('单条删除跨组重复 → 命中解释前后一致（3 条样例）', () => {
    const input = scheme([
      rule('DOMAIN-SUFFIX', 'copilot.cloud.microsoft', 'Ⓜ️ 微软Bing'),
      rule('DOMAIN-SUFFIX', 'COPILOT.cloud.microsoft', '🌍 国外媒体'),
      rule('DOMAIN-SUFFIX', 'example.com', 'A'),
      rule('DOMAIN-SUFFIX', 'EXAMPLE.com', 'B'),
      rule('IP-CIDR', '10.0.0.0/8', 'A'),
      rule('IP-CIDR', '10.0.0.0/8', 'B'),
      rule('FINAL', '', 'DIRECT'),
    ], { groups: selectGroups('A', 'B', 'Ⓜ️ 微软Bing', '🌍 国外媒体') })
    const issue = lintScheme({ scheme: input, nodes: [] })
      .find((item) => item.code === 'duplicateRule' && item.location.group === '🌍 国外媒体')
    assert.ok(issue, '应产生媒体组的跨组重复检查项')
    const action = buildFixActions(issue!).find((item) => item.kind === 'delete-rule')
    assert.ok(action)
    const applied = applyFixAction(input, action!)
    assert.ok(applied, '单条删除应成功')
    assert.deepEqual(applied!.scheme.rules.map((item) => item.value), [
      'copilot.cloud.microsoft', 'example.com', 'EXAMPLE.com', '10.0.0.0/8', '10.0.0.0/8', '',
    ])
    const samples = ['copilot.cloud.microsoft', '10.1.2.3', 'www.google.com']
    for (const query of samples) {
      assert.equal(verdict(applied!.scheme, query), verdict(input, query), `${query} 的命中结果在单条删除后发生了变化`)
    }
  })

  check('单条删除后撤销 → 精确回插原位', () => {
    const input = scheme([
      rule('DOMAIN-SUFFIX', 'keep.example', 'A'),
      rule('DOMAIN-SUFFIX', 'copilot.cloud.microsoft', 'Ⓜ️ 微软Bing'),
      rule('DOMAIN-SUFFIX', 'COPILOT.cloud.microsoft', '🌍 国外媒体'),
      rule('DOMAIN-SUFFIX', 'tail.example', 'A'),
      rule('FINAL', '', 'DIRECT'),
    ], { groups: selectGroups('A', 'Ⓜ️ 微软Bing', '🌍 国外媒体') })
    const issue = lintScheme({ scheme: input, nodes: [] })
      .find((item) => item.code === 'duplicateRule' && item.location.group === '🌍 国外媒体')
    assert.ok(issue)
    const action = buildFixActions(issue!).find((item) => item.kind === 'delete-rule')
    assert.ok(action)
    const applied = applyFixAction(input, action!)
    assert.ok(applied?.removed, '单条删除应记录原始位置')
    const restored = restoreRemovedRules(applied!.scheme, [applied!.removed!])
    assert.equal(restored.restored, 1)
    assert.deepEqual(restored.scheme.rules.map((item) => item.value), input.rules.map((item) => item.value))
    assert.deepEqual(restored.scheme.rules.map((item) => item.group), input.rules.map((item) => item.group))
  })

  check('前一条是死规则时，单条动作仍是「需你决定」', () => {
    const issue = lintScheme({
      scheme: scheme([
        rule('DOMAIN-SUFFIX', 'example.com', '🚀 节点选择'),
        rule('DOMAIN-SUFFIX', 'ads.example.com', '🛑 广告拦截'),
        rule('DOMAIN-SUFFIX', 'ADS.EXAMPLE.COM', '🌍 国外媒体'),
      ], { groups: selectGroups('🚀 节点选择', '🛑 广告拦截', '🌍 国外媒体') }),
      nodes: [],
    }).find((item) => item.code === 'duplicateRule')
    assert.ok(issue)
    assert.equal(issue.deletable, false)
    const actions = buildFixActions(issue!)
    assert.equal(actions.some((item) => item.kind === 'delete-rule'), false)
    assert.equal(actions[0].kind, 'manual')
  })

  check('前一条来自只读规则集时，单条动作仍是「需你决定」', () => {
    const set: SchemeRuleSet = {
      id: 'set-url',
      name: '在线规则集',
      group: 'Ⓜ️ 微软Bing',
      sourceKind: 'url',
      sourceRef: 'https://example.com/rules.list',
      rules: [rule('DOMAIN-SUFFIX', 'shared.example', 'Ⓜ️ 微软Bing')],
    }
    const issue = lintScheme({
      scheme: scheme([
        rule('DOMAIN-SUFFIX', 'shared.example', '🌍 国外媒体'),
        rule('FINAL', '', 'DIRECT'),
      ], { groups: selectGroups('Ⓜ️ 微软Bing', '🌍 国外媒体'), ruleSets: [set] }),
      nodes: [],
    }).find((item) => item.code === 'duplicateRule')
    assert.ok(issue)
    assert.equal(issue.firstReadOnly, true)
    assert.equal(issue.deletable, false)
    assert.equal(buildFixActions(issue!).some((item) => item.kind === 'delete-rule'), false)
  })

  check('内置方案删除前复制 → 副本独立，撤销回到原方案且保留策略选择', () => {
    const source = scheme([
      rule('DOMAIN-SUFFIX', 'a.example', '节点选择'),
      rule('FINAL', '', 'DIRECT'),
    ], { id: 'acl4ssr-online', name: 'ACL4SSR 在线', sourceKind: 'builtin' })
    const copy = createEditableSchemeCopy(source, { id: 'copy-test', now: 1 })
    assert.equal(copy.id, 'copy-test')
    assert.equal(copy.name, 'ACL4SSR 在线 · 自定义')
    assert.equal(copy.sourceKind, 'copy')
    assert.equal(copy.rules.length, source.rules.length)
    assert.notEqual(copy.rules, source.rules, '副本必须有独立的规则数组')
    copy.rules.push(rule('DOMAIN', 'local.example', '节点选择'))
    assert.equal(source.rules.length, 2, '改动副本不能影响内置方案')

    const store = useStore.getState()
    store.addCustomScheme(copy)
    store.setScheme(copy.id)
    store.setPolicy('节点选择', 'DIRECT')
    assert.equal(useStore.getState().selectedSchemeID, 'copy-test')

    const undo = undoEditableSchemeCopy(useStore.getState().customSchemes, source.id, copy.id)
    assert.equal(undo.removed, true)
    assert.equal(undo.selectedSchemeID, 'acl4ssr-online')
    useStore.setState({
      customSchemes: undo.customSchemes,
      selectedSchemeID: undo.selectedSchemeID,
      policySelections: useStore.getState().policySelections,
    })
    assert.equal(useStore.getState().customSchemes.some((item) => item.id === 'copy-test'), false)
    assert.equal(useStore.getState().selectedSchemeID, 'acl4ssr-online')
    assert.equal(useStore.getState().policySelections['节点选择'], 'DIRECT', '撤销复制不应清空策略选择')
    useStore.setState({ policySelections: {} })
  })

  check('只读规则集屏蔽 → 命中落到下一条规则，导出里不再出现被屏蔽条目', () => {
    const blocked = rule('DOMAIN-SUFFIX', 'blocked.example', '节点选择')
    // 两个只读集：前一个是被屏蔽规则所在集，后一个是「下一条预期规则」。
    // 规则集块按 ruleSets 顺序排在模板规则之前，因此屏蔽前先命中「节点选择」。
    const schemeWithSets = scheme([], {
      groups: [...selectGroups('节点选择'), ...selectGroups('直连')],
      ruleSets: [
        {
          id: 'set-block', name: '在线分流', group: '节点选择', sourceKind: 'url',
          sourceRef: 'https://example.com/a.yaml',
          rules: [blocked, rule('DOMAIN-SUFFIX', 'keep.example', '节点选择')],
        },
        {
          id: 'set-next', name: '备用分流', group: '直连', sourceKind: 'url',
          sourceRef: 'https://example.com/b.yaml',
          rules: [rule('DOMAIN-KEYWORD', 'blocked', '直连')],
        },
      ],
    })
    const exclusions = addRuleSetExclusion({}, 'set-block', ruleSignature(blocked))

    const before = JSON.parse(verdict(schemeWithSets, 'www.blocked.example')) as { rule: string; group: string }
    const compiled = compileScheme({ scheme: schemeWithSets, nodes: [], ruleSetExclusions: exclusions })
    const afterResult = explainWith(compiled, 'www.blocked.example')
    const after = {
      rule: afterResult.match ? ruleSignature(afterResult.match.rule) : '(no-match)',
      group: afterResult.final.group ?? '',
    }
    assert.equal(before.group, '节点选择')
    assert.equal(after.group, '直连', '屏蔽后应落到下一条规则')
    assert.notEqual(after.rule, ruleSignature(blocked), '不应再命中被屏蔽规则')
    // 三条样例（域名 / 子域 / 大写）都不再命中被屏蔽规则，全部落到备用规则。
    for (const query of ['blocked.example', 'www.blocked.example', 'BLOCKED.EXAMPLE']) {
      const result = explainWith(compiled, query)
      assert.equal(result.final.group, '直连', `${query} 屏蔽后应落到备用规则`)
      assert.notEqual(result.match ? ruleSignature(result.match.rule) : '', ruleSignature(blocked), `${query} 不应命中被屏蔽规则`)
    }

    // 导出路径：启用规则集引用时也必须内联并过滤，否则远程列表会把规则带回来。
    const formats = generateSubscriptionFormats([nodeFixture()], schemeWithSets, {
      preferRuleSets: true,
      ruleSetExclusions: exclusions,
    })
    for (const [format, text] of Object.entries(formats)) {
      if (format === 'base64') continue // 仅节点订阅，不含规则
      assert.equal(text.includes('https://example.com/a.yaml'), false, `${format} 不应保留被屏蔽规则集的远程引用`)
      assert.equal(text.includes('blocked.example'), false, `${format} 仍包含被屏蔽规则`)
      assert.equal(text.includes('keep.example'), true, `${format} 应保留同一规则集里未被屏蔽的条目`)
    }
    // 反向对照：不带屏蔽表时这条规则会正常导出，比对恒真会变红。
    const plain = generateSubscriptionFormats([nodeFixture()], schemeWithSets, { preferRuleSets: true })
    assert.equal(plain.surge.includes('blocked.example'), true)

    // 刷新规则集：同 id、同签名（大小写变化）仍然被屏蔽；新增规则不受影响。
    const refreshed = {
      ...schemeWithSets,
      ruleSets: [
        {
          ...(schemeWithSets.ruleSets![0]),
          rules: [rule('DOMAIN-SUFFIX', 'BLOCKED.example', '节点选择'), rule('DOMAIN-SUFFIX', 'fresh.example', '节点选择')],
        },
        schemeWithSets.ruleSets![1],
      ],
    }
    const filtered = filterExcludedRuleSets(refreshed, exclusions)
    assert.equal(filtered.ruleSets![0].rules.some((item) => item.value?.toLowerCase() === 'blocked.example'), false, '刷新后同签名仍应被屏蔽')
    assert.equal(filtered.ruleSets![0].rules.some((item) => item.value === 'fresh.example'), true, '新增规则不应被误伤')
    const refreshedCompiled = compileScheme({ scheme: refreshed, nodes: [], ruleSetExclusions: exclusions })
    assert.equal(explainWith(refreshedCompiled, 'www.blocked.example').final.group, '直连', '刷新后屏蔽仍然生效')

    // 解除屏蔽后恢复。
    const unblocked = removeRuleSetExclusion(exclusions, 'set-block', ruleSignature(blocked))
    const restoredCompiled = compileScheme({ scheme: schemeWithSets, nodes: [], ruleSetExclusions: unblocked })
    assert.equal(explainWith(restoredCompiled, 'www.blocked.example').final.group, '节点选择')

    // 导出准备函数本身也必须过滤（模拟变异：去掉过滤后这里会变红）。
    const prepared = prepareSchemeForExport(schemeWithSets, {}, { preferRuleSets: true, format: 'surge', ruleSetExclusions: exclusions })
    assert.equal(prepared.rules.some((item) => item.value === 'blocked.example'), false)
  })

  check('排除表归一化容错与工作区同步', () => {
    const raw = {
      'set-a': ['DOMAIN-SUFFIX|a.example|', 42, null, '', ' DOMAIN|b.example|'],
      'set-b': 'bad',
      '': ['x'],
      'set-c': ['DOMAIN|c.example|', 'DOMAIN|c.example|'],
    }
    const normalized = normalizeRuleSetExclusions(raw)
    assert.deepEqual(normalized['set-a'], ['DOMAIN-SUFFIX|a.example|', 'DOMAIN|b.example|'])
    assert.equal(normalized['set-b'], undefined)
    assert.deepEqual(normalized['set-c'], ['DOMAIN|c.example|'], '重复项应去重')

    const data = normalizeWorkspaceData({
      sources: [],
      nodes: [],
      customSchemes: [],
      localRuleSets: [],
      builtinSchemeOverrides: {},
      ruleSetExclusions: raw,
      selectedSchemeID: 'x',
      policySelections: {},
      exportConfigName: '',
      tailnets: [],
      tailnetAuthKeys: {},
    })
    assert.deepEqual(data.ruleSetExclusions, normalized)

    const store = useStore.getState()
    store.restoreRuleSetExclusions('set-ws', ['DOMAIN-SUFFIX|ws.example|'])
    assert.deepEqual(workspaceSnapshot(useStore.getState()).ruleSetExclusions['set-ws'], ['DOMAIN-SUFFIX|ws.example|'])
    store.restoreRuleSetExclusions('set-ws', [])
    assert.equal(workspaceSnapshot(useStore.getState()).ruleSetExclusions['set-ws'], undefined)
  })

  check('工作区同步：快照正文与指针、序列一起落地', () => {
    const snapshot = {
      id: 1,
      schemeID: 'acl4ssr-online',
      createdAt: 1,
      scheme: { id: 'acl4ssr-online', name: '测试固化方案', groups: [], rules: [] },
      ruleSets: [],
      source: {
        iniURL: 'https://example.com/acl.ini',
        commitSha: 'a'.repeat(40),
        files: [],
        fetchedAt: 1,
        ruleCount: 0,
        ruleSetCount: 0,
      },
    }
    const data = normalizeWorkspaceData({
      sources: [],
      nodes: [],
      customSchemes: [],
      localRuleSets: [],
      builtinSchemeOverrides: { 'acl4ssr-online': { snapshotId: 1 } },
      schemeSnapshots: { '1': snapshot },
      snapshotSeq: 9,
      ruleSetExclusions: {},
      selectedSchemeID: 'acl4ssr-online',
      policySelections: {},
      exportConfigName: 'tower',
      tailnets: [],
      tailnetAuthKeys: {},
    })
    assert.equal(data.schemeSnapshots['1'].id, 1)
    assert.equal(data.snapshotSeq, 9)
    // 只同步指针、不同步正文时，第二台设备会回落到原厂；这里锁住整包落地。
    applyServerData(data)
    assert.equal(useStore.getState().schemeSnapshots['1'].id, 1)
    assert.equal(useStore.getState().snapshotSeq, 9)
    useStore.setState({
      schemeSnapshots: {},
      snapshotSeq: 0,
      builtinSchemeOverrides: {},
      ruleSetExclusions: {},
    })
  })

  check('三态动作：可删除 / 可屏蔽 / 不可动，文案说清实际行为', () => {
    const writable = lintScheme({
      scheme: scheme([
        rule('DOMAIN-SUFFIX', 'dup.example', 'A'),
        rule('DOMAIN-SUFFIX', 'dup.example', 'A'),
      ], { groups: selectGroups('A') }),
      nodes: [],
    }).find((item) => item.code === 'duplicateRuleSameGroup')
    assert.ok(writable)
    const deleteAction = buildFixActions(writable!).find((item) => item.kind === 'delete-rule')
    assert.ok(deleteAction)
    assert.match(deleteAction!.label, /可删除/)
    assert.match(deleteAction!.detail, /不会改变/)

    // 后一条来自只读规则集：只能屏蔽；标签必须写明会改变去向。
    // 自定义规则永远排在最前，规则集块随后，因此可写的前一条 + 只读的后一条。
    const readOnlyTarget = lintScheme({
      scheme: scheme([], {
        customRules: [rule('DOMAIN-SUFFIX', 'shared.example', 'B')],
        groups: [...selectGroups('B'), ...selectGroups('A')],
        ruleSets: [
          { id: 'set-ro', name: '只读分流', group: 'A', sourceKind: 'url', sourceRef: 'https://example.com/a.yaml', rules: [rule('DOMAIN-SUFFIX', 'shared.example', 'A')] },
        ],
      }),
      nodes: [],
    }).find((item) => item.code === 'duplicateRule')
    assert.ok(readOnlyTarget)
    assert.equal(readOnlyTarget!.sourceReadOnly, true)
    assert.equal(readOnlyTarget!.sourceSetId, 'set-ro')
    assert.equal(readOnlyTarget!.deletable, false)
    const blockAction = buildFixActions(readOnlyTarget!).find((item) => item.kind === 'block-rule')
    assert.ok(blockAction, '只读来源应给出屏蔽动作')
    assert.match(blockAction!.label, /可屏蔽/)
    assert.match(blockAction!.label, /改变去向/)
    assert.match(blockAction!.detail, /刷新/)
    assert.equal(blockAction!.ruleSetId, 'set-ro')
    assert.equal(blockAction!.ruleSignature, ruleSignature(rule('DOMAIN-SUFFIX', 'shared.example', 'A')))
    assert.equal(buildFixActions(readOnlyTarget!).some((item) => item.kind === 'delete-rule'), false)

    // 前一条是死规则：不可动，不提供删除 / 屏蔽。
    const dead = lintScheme({
      scheme: scheme([
        rule('DOMAIN-SUFFIX', 'example.com', 'A'),
        rule('DOMAIN-SUFFIX', 'ads.example.com', 'C'),
        rule('DOMAIN-SUFFIX', 'ADS.EXAMPLE.COM', 'B'),
      ], { groups: selectGroups('A', 'B', 'C') }),
      nodes: [],
    }).find((item) => item.code === 'duplicateRule')
    assert.ok(dead)
    assert.equal(dead!.firstDead, true)
    assert.equal(buildFixActions(dead!)[0].kind, 'manual')
    assert.match(buildFixActions(dead!)[0].label, /不可动/)
  })

  check('跨组重复：保留后一条会删除前一条，并说明目标组变化', () => {
    const input = scheme([
      rule('DOMAIN-SUFFIX', 'shared.example', 'A'),
      rule('DOMAIN-SUFFIX', 'shared.example', 'B'),
      rule('FINAL', '', 'DIRECT'),
    ], { groups: selectGroups('A', 'B', 'DIRECT') })
    const plan = analyzeDuplicateCleanup(input, { keep: 'last' })
    assert.equal(plan.deletions.length, 1)
    assert.equal(plan.deletions[0].group, 'A')
    assert.equal(plan.deletions[0].duplicateOfGroup, 'B')
    assert.equal(plan.deletions[0].kind, 'crossGroup')
    assert.deepEqual(plan.directionChanges, [{ fromGroup: 'A', toGroup: 'B', count: 1, rules: ['DOMAIN-SUFFIX,shared.example'] }])
    const applied = applyDuplicateCleanup(input, plan)
    assert.equal(applied.removed, 1)
    assert.equal(applied.scheme.rules.filter((item) => item.value === 'shared.example').length, 1)
    assert.equal(applied.scheme.rules.find((item) => item.value === 'shared.example')?.group, 'B')
  })

  check('逐对处理：按签名覆盖保留方向', () => {
    const shared = rule('DOMAIN-SUFFIX', 'shared.example', 'A')
    const twin = rule('DOMAIN-SUFFIX', 'shared.example', 'B')
    const input = scheme([shared, twin, rule('FINAL', '', 'DIRECT')], { groups: selectGroups('A', 'B', 'DIRECT') })
    const signature = ruleSignature(shared)
    const keepFirst = analyzeDuplicateCleanup(input, { keep: 'first', decisions: { [signature]: 'first' } })
    assert.equal(keepFirst.deletions[0].duplicateOfGroup, 'A')
    assert.deepEqual(keepFirst.directionChanges, [])
    const keepLast = analyzeDuplicateCleanup(input, { keep: 'first', decisions: { [signature]: 'last' } })
    assert.equal(keepLast.deletions[0].duplicateOfGroup, 'B')
    assert.equal(keepLast.choices[0].direction, 'last')
  })

  check('遮蔽死规则纳入同一套删除 / 撤销流程', () => {
    const input = scheme([
      rule('DOMAIN-SUFFIX', 'example.com', 'A'),
      rule('DOMAIN-SUFFIX', 'ads.example.com', 'B'),
      rule('FINAL', '', 'DIRECT'),
    ], { groups: selectGroups('A', 'B', 'DIRECT') })
    const plan = analyzeDuplicateCleanup(input)
    assert.equal(plan.deletions.length, 0)
    assert.equal(plan.shadowed.length, 1)
    assert.equal(plan.shadowed[0].kind, 'shadowed')
    assert.match(plan.shadowed[0].shadowedReason ?? '', /永远不会命中/)
    const applied = applyDuplicateCleanup(input, plan)
    assert.equal(applied.removed, 1)
    assert.equal(applied.scheme.rules.some((item) => item.value === 'ads.example.com'), false)
    const restored = restoreRemovedRules(applied.scheme, applied.applied)
    assert.equal(restored.restored, 1)
    assert.equal(restored.scheme.rules.some((item) => item.value === 'ads.example.com'), true)
  })

  check('保留后一条时，只读来源的前一条不可删', () => {
    const set: SchemeRuleSet = {
      id: 'set-url',
      name: '在线规则集',
      group: 'A',
      sourceKind: 'url',
      sourceRef: 'https://example.com/rules.list',
      rules: [rule('DOMAIN-SUFFIX', 'shared.example', 'A')],
    }
    const input = scheme([
      rule('DOMAIN-SUFFIX', 'shared.example', 'B'),
      rule('FINAL', '', 'DIRECT'),
    ], { groups: selectGroups('A', 'B', 'DIRECT'), ruleSets: [set] })
    const plan = analyzeDuplicateCleanup(input, { keep: 'last' })
    assert.equal(plan.deletions.length, 0)
    assert.equal(plan.skipped.readOnly.length, 1)
  })

  check('固化快照：规则集块不重复插入，重复计数与位置编号不偏移', () => {
    const snap = rule('DOMAIN-SUFFIX', 'snap.example', '🚀 节点选择')
    const local = rule('DOMAIN-SUFFIX', 'local.example', '🚀 节点选择')
    // 内置方案的固化快照：规则同时存在于 scheme.rules 和 ruleSets[].rules。
    const set: SchemeRuleSet = {
      id: 'set-frozen',
      name: '固化规则集',
      group: '🚀 节点选择',
      sourceKind: 'url',
      sourceRef: 'https://example.com/frozen.yaml',
      inlined: true,
      rules: [snap],
    }
    const input = scheme([
      { ...snap, sourceSetId: 'set-frozen', sourceName: '固化规则集' },
      { ...snap, sourceSetId: 'set-frozen', sourceName: '固化规则集' },
      local,
      { ...local },
    ], { ruleSets: [set] })

    const plan = analyzeDuplicateCleanup(input)
    // 修复前：固化规则被当作「规则集块」再插一遍，snap 有 3 份 → total 3、readOnly 2。
    assert.equal(plan.total, 2)
    assert.equal(plan.choices.find((choice) => choice.ruleText.includes('snap.example'))!.occurrences, 2)
    assert.equal(plan.skipped.readOnly.length, 1)
    // 固化快照内的重复项仍按「只读来源」归类，且不会指向规则集块。
    const readOnly = plan.skipped.readOnly[0]
    assert.equal(readOnly.index, 2)
    assert.equal(readOnly.firstIndex, 1)
    assert.equal(/固化规则集/.test(readOnly.source), false)
    // 可写的同组重复仍能正常删除，且位置不再被多插的块顶偏。
    assert.equal(plan.deletions.length, 1)
    assert.equal(plan.deletions[0].rule.value, 'local.example')
    assert.equal(plan.deletions[0].place.index + 1, 4)
    assert.equal(plan.deletions[0].duplicateOfIndex, 3)
  })

  check('同一方案 + 同一屏蔽表：诊断页与导出页 lint error 计数一致', () => {
    // 只读规则集里有一条指向不存在策略组的规则 → 屏蔽前必定报 error。
    const bad = rule('DOMAIN-SUFFIX', 'bad.example', '不存在的组')
    const set: SchemeRuleSet = {
      id: 'set-lint',
      name: '在线分流',
      group: '节点选择',
      sourceKind: 'url',
      sourceRef: 'https://example.com/lint.yaml',
      rules: [bad],
    }
    const input = scheme([], { groups: selectGroups('节点选择'), ruleSets: [set] })
    const exclusions = addRuleSetExclusion({}, 'set-lint', ruleSignature(bad))
    const base = { scheme: input, nodes: [nodeFixture()], localRuleSets: [] }
    const clash = CLIENTS.find((client) => client.target === 'clash-verge')!
    const withoutExclusions = lintSummary(lintScheme(base))

    assert.ok(withoutExclusions.error > 0, '屏蔽前应报出 error')
    const diagnosis = lintSummary(lintScheme({ ...base, ruleSetExclusions: exclusions }))
    const exportPage = lintSummary(lintScheme({ ...base, ruleSetExclusions: exclusions, clients: [clash] }))
    assert.equal(diagnosis.error, 0, '屏蔽后诊断页不应再报 error')
    assert.equal(exportPage.error, diagnosis.error, '诊断页与导出页的 error 计数必须一致')
    // 防止参数空转：不传屏蔽表时导出页仍要报错。
    assert.equal(lintSummary(lintScheme({ ...base, clients: [clash] })).error, withoutExclusions.error)

    const restored = removeRuleSetExclusion(exclusions, 'set-lint', ruleSignature(bad))
    assert.equal(lintSummary(lintScheme({ ...base, ruleSetExclusions: restored })).error, withoutExclusions.error)
  })

  check('App 的两处 lintScheme 调用都传了 ruleSetExclusions', () => {
    const calls = lintCallArgs(readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8'))
    assert.ok(calls.length >= 2, `应至少找到 2 处 lintScheme 调用，实际 ${calls.length} 处`)
    for (const call of calls) assert.match(call, /ruleSetExclusions/)
  })

  console.log(failures === 0 ? '\n全部重复规则清理自检通过' : `\n${failures} 项重复规则清理自检失败`)
  process.exit(failures === 0 ? 0 : 1)
}

main()
