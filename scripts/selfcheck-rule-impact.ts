// 自检：规则影响面静态分析口径，以及「无历史连接数据」必须显式说明。
// 用法：npx tsx scripts/selfcheck-rule-impact.ts
import assert from 'node:assert/strict'
import type { PolicyGroup, RoutingRule, RuleScheme } from '../src/models/types'
import { analyzeRuleImpact, ruleImpactText } from '../src/rules/ruleImpact'
import { orderedSchemeRules } from '../src/rules/ruleOrder'

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

function rule(group: string, value: string, type = 'DOMAIN-SUFFIX'): RoutingRule {
  return { type, value, group }
}

function baseScheme(): RuleScheme {
  return {
    id: 'rule-impact',
    name: '影响面',
    description: '',
    groups: [group('国内'), group('国外媒体'), group('广告')],
    rules: [
      rule('国内', 'example.com'),
      rule('广告', 'example.com'),
      rule('国外媒体', 'example.com'),
      rule('国内', 'other.example.org'),
      rule('广告', 'ads.example.net'),
    ],
    customRules: [],
  }
}

function main(): void {
  check('同值规则跨策略组时列出全部受影响的组', () => {
    const scheme = baseScheme()
    const impact = analyzeRuleImpact(scheme, rule('国外媒体', 'example.com'))
    assert.deepEqual(impact.affectedGroups, ['国内', '广告', '国外媒体'])
    assert.equal(impact.matchedRules, 3)
    assert.equal(impact.targetGroupRules, 1)
  })

  check('遮蔽数按导出顺序计算，不把前面的规则算进来', () => {
    const scheme = baseScheme()
    // 第 2 条同值规则：第一条在它之前，不会遮蔽它；它遮蔽后面的第 3 条。
    const impact = analyzeRuleImpact(scheme, rule('广告', 'example.com'))
    assert.equal(impact.shadowedRules, 1)
    // 最后一条同值规则不遮蔽任何规则。
    const last = analyzeRuleImpact(scheme, rule('国外媒体', 'example.com'))
    assert.equal(last.shadowedRules, 0)
  })

  check('插入预览把待保存规则放在最前，遮蔽所有已有同值规则', () => {
    const scheme = baseScheme()
    const impact = analyzeRuleImpact(scheme, rule('国外媒体', 'example.com'), { includeCandidate: true })
    assert.equal(impact.matchedRules, 4)
    assert.equal(impact.shadowedRules, 3)
    assert.equal(impact.targetGroupRules, 2)
    // 预览必须与保存后的真实顺序一致：新规则排在自定义规则段之前。
    const ordered = orderedSchemeRules({ ...scheme, customRules: [rule('国外媒体', 'example.com')] })
    assert.equal(ordered[0].group, '国外媒体')
  })

  check('没有历史连接数据时明确标注静态影响面，不编造 0', () => {
    const impact = analyzeRuleImpact(baseScheme(), rule('国内', 'example.com'))
    assert.equal(impact.connections, null)
    const text = ruleImpactText(impact)
    assert.match(text, /无历史数据，仅静态影响面/)
    assert.doesNotMatch(text, /历史连接 0 条/)
  })

  check('不同类型的同值规则不会被算成同一影响面', () => {
    const scheme = baseScheme()
    const impact = analyzeRuleImpact(scheme, { type: 'DOMAIN', value: 'example.com', group: '广告' })
    assert.equal(impact.matchedRules, 0)
    assert.deepEqual(impact.affectedGroups, [])
    assert.match(ruleImpactText(impact), /没有同值规则会被本条遮蔽/)
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部规则影响面检查通过')
}

main()
