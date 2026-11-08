// 自检：移除规则集时屏蔽记录不能静默变孤儿；确认文案要说清后果，并留清理入口。
// 用法：npm run selfcheck:ruleset-exclusions
import assert from 'node:assert/strict'
import {
  countOrphanRuleSetExclusions,
  countRuleSetExclusions,
  describeRuleSetRemovalImpact,
  orphanRuleSetIDs,
  removeOrphanRuleSetExclusions,
} from '../src/rules/ruleSetExclusions'
import type { RuleSetExclusionTable } from '../src/models/types'

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

const table: RuleSetExclusionTable = {
  live: ['a|b|c', 'd|e|f'],
  orphanA: ['x|y|z'],
  orphanB: ['1|2|3', '4|5|6'],
}

check('统计整张屏蔽表的签名总数', () => {
  assert.equal(countRuleSetExclusions(table), 5)
  assert.equal(countRuleSetExclusions({}), 0)
})

check('找出所属规则集已不存在的孤儿记录', () => {
  assert.deepEqual(orphanRuleSetIDs(table, ['live']), ['orphanA', 'orphanB'])
  assert.deepEqual(orphanRuleSetIDs(table, ['live', 'orphanA', 'orphanB']), [])
  assert.equal(countOrphanRuleSetExclusions(table, ['live']), 3)
})

check('清理孤儿后保留仍在使用的记录；没有孤儿时返回原对象', () => {
  const cleaned = removeOrphanRuleSetExclusions(table, ['live'])
  assert.deepEqual(Object.keys(cleaned), ['live'])
  assert.deepEqual(cleaned.live, table.live)
  assert.equal(removeOrphanRuleSetExclusions(table, ['live', 'orphanA', 'orphanB']), table)
})

check('移除确认文案必须写明 N 条屏蔽记录会一并失效', () => {
  const text = describeRuleSetRemovalImpact(3)
  assert.match(text, /3 条屏蔽记录/)
  assert.match(text, /一并失效/)
  assert.equal(describeRuleSetRemovalImpact(0), '该规则集没有屏蔽记录。')
})

if (failures > 0) {
  console.error(`\n${failures} 项屏蔽记录自检失败`)
  process.exitCode = 1
} else {
  console.log('\n全部屏蔽记录自检通过')
}
