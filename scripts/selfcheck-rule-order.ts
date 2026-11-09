// 自检：规则页逐条顺序（ruleOrder）在展示与导出之间保持一致。
// 用法：npx tsx scripts/selfcheck-rule-order.ts
import assert from 'node:assert/strict'
import type { PolicyGroup, RoutingRule, RuleScheme, SchemeRuleSet } from '../src/models/types'
import {
  applyRuleOrder,
  isUnmovableRule,
  orderedSchemeRules,
  renameRuleOrderKeys,
  ruleOrderKeys,
  ruleSetRanksBeforeSchemeRules,
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

function remoteSet(id: string, name: string, groupName: string, value: string, providerName?: string): SchemeRuleSet {
  return {
    id,
    name,
    group: groupName,
    rules: providerName ? [] : [{ type: 'DOMAIN', value, sourceName: name }],
    sourceKind: 'url',
    sourceRef: `https://rules.example.com/${providerName ?? id}.yaml`,
    format: 'yaml',
    ruleSetBehavior: 'domain',
    ...(providerName ? { providerOnly: true, providerName } : {}),
  }
}

/** 新建组「D」还没有任何规则：规则集必须落在方案规则之前。 */
function insertionScheme(sets: SchemeRuleSet[]): RuleScheme {
  return {
    id: 'rule-insert',
    name: '规则集落位',
    description: '',
    groups: [group('A'), group('B'), group('C'), group('D')],
    rules: [
      rule('A', 'a.example.com'),
      rule('B', 'b.example.com'),
      { type: 'FINAL', group: 'C' },
    ],
    ruleSets: sets,
  }
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

  check('新建组加入在线规则集：排在方案规则之前', () => {
    const scheme = insertionScheme([remoteSet('rs-new', '新组规则集', 'D', 'only.example.org')])
    const exported = prepareSchemeForExport(scheme, {}, {}).rules
    assert.deepEqual(exported.map((item) => item.value), [
      'only.example.org',
      'a.example.com',
      'b.example.com',
      undefined,
    ])
    assert.equal(exported[0].group, 'D')
  })

  check('providerOnly：自定义规则集排在引用之前，引用相对顺序不变', () => {
    const scheme: RuleScheme = {
      id: 'provider-insert',
      name: 'provider 落位',
      description: '',
      groups: [group('A'), group('B'), group('C'), group('D')],
      rules: [{ type: 'FINAL', group: 'C' }],
      ruleSets: [
        remoteSet('p1', '引用一', 'A', '', 'pn1'),
        remoteSet('p2', '引用二', 'B', '', 'pn2'),
        remoteSet('p3', '引用三', 'C', '', 'pn3'),
        remoteSet('rs-new', '新组规则集', 'D', 'only.example.org'),
      ],
    }
    const exported = prepareSchemeForExport(scheme, {}, { format: 'yaml', target: 'clash-verge' }).rules
    assert.deepEqual(exported.map((item) => item.type), ['DOMAIN', 'RULE-SET', 'RULE-SET', 'RULE-SET', 'FINAL'])
    assert.equal(exported[0].value, 'only.example.org')
    assert.deepEqual(exported.slice(1, 4).map((item) => item.ruleSetProviderKey), ['pn1', 'pn2', 'pn3'])
  })

  check('同值锚点保持原落位；仅同组不再拦前置', () => {
    // 同值锚点：b.example.com 命中方案规则 → 仍插在它之前。
    const anchored = insertionScheme([remoteSet('rs-b', 'B 组规则集', 'B', 'b.example.com')])
    const anchoredOut = prepareSchemeForExport(anchored, {}, {}).rules
    assert.deepEqual(anchoredOut.map((item) => item.value), [
      'a.example.com',
      'b.example.com',
      'b.example.com',
      undefined,
    ])
    assert.equal(anchoredOut[1].sourceName, 'B 组规则集')

    // 仅同组、没有同值锚点：按方案 A 前置到方案规则之前。
    const groupOnly = insertionScheme([remoteSet('rs-group', 'B 组规则集', 'B', 'only.example.org')])
    const groupOnlyOut = prepareSchemeForExport(groupOnly, {}, {}).rules
    assert.deepEqual(groupOnlyOut.map((item) => item.value), [
      'only.example.org',
      'a.example.com',
      'b.example.com',
      undefined,
    ])
  })

  check('前置提示：真正前置才出现，锚点命中或方案无普通规则时不出现', () => {
    const preposed = insertionScheme([remoteSet('rs-notice', '新组规则集', 'D', 'only.example.org')])
    assert.equal(ruleSetRanksBeforeSchemeRules(preposed, preposed.ruleSets![0]), true)

    const anchored = insertionScheme([remoteSet('rs-anchor', 'B 组规则集', 'B', 'b.example.com')])
    assert.equal(ruleSetRanksBeforeSchemeRules(anchored, anchored.ruleSets![0]), false)

    const noSchemeRules: RuleScheme = {
      id: 'provider-notice',
      name: '无方案规则',
      description: '',
      groups: [group('A'), group('C'), group('D')],
      rules: [{ type: 'FINAL', group: 'C' }],
      ruleSets: [remoteSet('rs-new', '新组规则集', 'D', 'only.example.org')],
    }
    assert.equal(ruleSetRanksBeforeSchemeRules(noSchemeRules, noSchemeRules.ruleSets![0]), false)
  })

  check('置顶：写 ruleOrder 后排在首条，刷新后保持，兜底锚点不动', () => {
    const scheme = baseScheme()
    const ordered = orderedSchemeRules(scheme)
    // 段首是自定义规则；把 b 置顶到该段最前。
    const index = ordered.findIndex((item) => item.value === 'b.example.com')
    let target = index
    for (let cursor = index - 1; cursor >= 0; cursor -= 1) {
      target = cursor
      if (isUnmovableRule(ordered[cursor])) {
        target = cursor + 1
        break
      }
    }
    const next = [...ordered]
    const [moved] = next.splice(index, 1)
    next.splice(target, 0, moved)
    scheme.ruleOrder = orderFrom(next)
    const shown = orderedSchemeRules(scheme)
    assert.equal(shown[0].value, 'b.example.com')
    assert.equal(shown[shown.length - 1].type, 'FINAL')
    assert.deepEqual(shown, prepareSchemeForExport(scheme, {}, {}).rules)
    // 刷新后重新计算顺序仍保持；FINAL 仍不可移动。
    assert.deepEqual(orderedSchemeRules(scheme), shown)
    assert.equal(isUnmovableRule(shown[shown.length - 1]), true)
    // 置顶跨不过 GEOIP：即使顺序键把它排在最前，导出仍在锚点之后。
    const crossed = { ...scheme, ruleOrder: orderFrom([ordered[4], ...ordered.slice(0, 4)]) }
    const exported = prepareSchemeForExport(crossed, {}, {}).rules
    const geoip = exported.findIndex((item) => item.type === 'GEOIP')
    const wide = exported.findIndex((item) => item.value === 'wide.example')
    assert.ok(geoip >= 0 && wide > geoip)
  })

  if (failures) {
    console.error(`\n${failures} 项失败`)
    process.exit(1)
  }
  console.log('\n全部通过')
}

main()
