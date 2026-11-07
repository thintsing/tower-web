// 内置方案上游漂移自检：diff 计数、忽略记忆、文案口径。
import assert from 'node:assert/strict'
import type { RoutingRule, RuleScheme } from '../src/models/types'
import {
  DRIFT_STATUS_LABELS,
  computeSchemeDrift,
  shouldPromptDrift,
} from '../src/rules/schemeDrift'

function rule(type: string, value: string, extra: Partial<RoutingRule> = {}): RoutingRule {
  return { type, value, group: 'G', ...extra } as RoutingRule
}

function scheme(id: string, rules: RoutingRule[]): RuleScheme {
  return { id, name: id, description: '', groups: [], rules }
}

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

const AT = Date.UTC(2026, 0, 1)

check('漂移检测：新增 / 删除 / 修改分别计数', () => {
  const current = scheme('acl4ssr-online', [
    rule('DOMAIN', 'a.com'),
    rule('DOMAIN', 'b.com'),
    rule('IP-CIDR', '10.0.0.0/8'),
  ])
  const upstream = scheme('acl4ssr-online', [
    rule('DOMAIN', 'a.com'),
    rule('DOMAIN', 'c.com'),
    rule('IP-CIDR', '10.0.0.0/8', { options: ['no-resolve'] }),
  ])
  const drift = computeSchemeDrift(current, upstream, 'commit-1', AT)
  assert.equal(drift.added, 1, `新增应为 1，实际 ${drift.added}`)
  assert.equal(drift.removed, 1, `删除应为 1，实际 ${drift.removed}`)
  assert.equal(drift.modified, 1, `修改应为 1，实际 ${drift.modified}`)
  assert.equal(drift.total, 3)
  assert.equal(drift.samples.length, 3, '少量变化应全部列出')
  assert.equal(drift.hidden, 0)
  assert.equal(drift.version, 'commit-1')
})

check('只有 commit 变化、规则没变时不算漂移', () => {
  const current = scheme('acl4ssr-mini', [rule('DOMAIN', 'a.com'), rule('DOMAIN', 'b.com')])
  const upstream = scheme('acl4ssr-mini', [rule('DOMAIN', 'b.com'), rule('DOMAIN', 'a.com')])
  const drift = computeSchemeDrift(current, upstream, 'commit-2', AT)
  assert.equal(drift.total, 0)
  assert.equal(drift.samples.length, 0)
})

check('忽略当前 commit 后不再提示，上游再次变化后重新提示', () => {
  assert.equal(shouldPromptDrift('commit-1', 'commit-1'), false, '同一 commit 不应重复提示')
  assert.equal(shouldPromptDrift('commit-2', 'commit-1'), true, '上游再变应重新提示')
  assert.equal(shouldPromptDrift(undefined, 'commit-1'), true, '没有版本号时不永久静默')
})

check('查不到上游时不能说「已是最新」', () => {
  assert.equal(DRIFT_STATUS_LABELS.update, '上游有更新')
  assert.equal(DRIFT_STATUS_LABELS.current, '已是最新')
  assert.ok(DRIFT_STATUS_LABELS.unknown.includes('查不到'), DRIFT_STATUS_LABELS.unknown)
  assert.ok(!DRIFT_STATUS_LABELS.unknown.includes('已是最新'), '未知状态不能复用「已是最新」文案')
  assert.ok(DRIFT_STATUS_LABELS.unknown.includes('不等于'), '未知状态要说明不等于没有更新')
})

check('变化很多时只展示有限条目并给出未列出数量', () => {
  const current = scheme('acl4ssr-full', [])
  const upstream = scheme('acl4ssr-full', Array.from({ length: 30 }, (_, i) => rule('DOMAIN', `d${i}.com`)))
  const drift = computeSchemeDrift(current, upstream, 'commit-3', AT)
  assert.equal(drift.added, 30)
  assert.equal(drift.samples.length, 12)
  assert.equal(drift.hidden, 18)
})

if (failures > 0) {
  console.error(`\n${failures} 项失败`)
  process.exit(1)
}
console.log('\n全部上游漂移检查通过')
