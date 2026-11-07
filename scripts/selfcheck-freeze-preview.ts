// 自检：固化前的变更预览（+N / -M / ~K、受影响策略组、引用旧规则集的自定义方案）。
// 用法：npx tsx scripts/selfcheck-freeze-preview.ts
import assert from 'node:assert/strict'
import type { BuiltinSchemeSnapshotContent, RuleScheme } from '../src/models/types'
import { planBuiltinSchemeFreeze } from '../src/rules/schemeSnapshots'

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

const current: Pick<RuleScheme, 'rules' | 'ruleSets'> = {
  rules: [
    { type: 'DOMAIN-SUFFIX', value: 'a.example', group: '直连' },
    { type: 'DOMAIN-SUFFIX', value: 'b.example', group: '国外媒体' },
    { type: 'DOMAIN-SUFFIX', value: 'c.example', group: '国外媒体' },
    { type: 'FINAL', group: '漏网之鱼' },
  ],
  ruleSets: [
    { id: 'upstream-set-a', name: 'set-a', group: '国外媒体', rules: [], sourceRef: 'https://example.com/a.list' },
  ],
}

const content = {
  scheme: {
    id: 'acl4ssr',
    name: 'ACL4SSR',
    description: '',
    groups: [],
    rules: [
      { type: 'DOMAIN-SUFFIX', value: 'a.example', group: '直连' },
      { type: 'DOMAIN-SUFFIX', value: 'b.example', group: '国外媒体' },
      // 新增
      { type: 'DOMAIN-SUFFIX', value: 'new.example', group: '国外媒体' },
      // 修改：同身份换了类型
      { type: 'DOMAIN', value: 'c.example', group: '国外媒体' },
      // 删除：a.example 保留，f.example 只存在于旧版
      { type: 'FINAL', group: '漏网之鱼' },
    ],
    updatedAt: 1,
  },
  ruleSets: [],
  source: { iniURL: 'https://example.com/x.ini', commitSha: 'a'.repeat(40), files: [], fetchedAt: 1, ruleCount: 5, ruleSetCount: 0 },
} as unknown as BuiltinSchemeSnapshotContent

check('差异摘要按 added / removed / modified 统计', () => {
  const plan = planBuiltinSchemeFreeze({ currentScheme: current, content, customSchemes: [] })
  assert.equal(plan.added, 1, '新增 1 条')
  assert.equal(plan.removed, 0, 'c.example 只改了类型，归入修改而不是删除')
  assert.equal(plan.modified, 1, '修改 1 条')
  assert.equal(plan.oldCount, 4)
  assert.equal(plan.newCount, 5)
})

check('受影响策略组聚合到组名', () => {
  const plan = planBuiltinSchemeFreeze({ currentScheme: current, content, customSchemes: [] })
  const media = plan.groups.find((entry) => entry.group === '国外媒体')
  assert.ok(media, '应包含「国外媒体」')
  assert.equal(media?.added, 1)
  assert.equal(media?.modified, 1)
  const direct = plan.groups.find((entry) => entry.group === '直连')
  assert.equal(direct, undefined, '未变化的组不应出现')
})

check('引用了旧规则集 id / 源地址的自定义方案会被列出', () => {
  const plan = planBuiltinSchemeFreeze({
    currentScheme: current,
    content,
    customSchemes: [
      { name: '引用 id', ruleSets: [{ id: 'upstream-set-a', name: 'x', group: 'g', rules: [] }] },
      { name: '引用源地址', ruleSets: [{ id: 'local-1', name: 'y', group: 'g', rules: [], sourceRef: 'https://example.com/a.list' }] },
      { name: '无关方案', ruleSets: [{ id: 'local-2', name: 'z', group: 'g', rules: [] }] },
    ],
  })
  assert.deepEqual(plan.affectedSchemes, ['引用 id', '引用源地址'])
})

check('内容完全一致时 diff 全为 0', () => {
  const plan = planBuiltinSchemeFreeze({
    currentScheme: { ...current, rules: content.scheme.rules },
    content,
    customSchemes: [],
  })
  assert.equal(plan.added + plan.removed + plan.modified, 0)
  assert.equal(plan.unchanged, 5)
  assert.deepEqual(plan.groups, [])
})

if (failures) {
  console.error(`\n${failures} 项失败`)
  process.exit(1)
}
console.log('\n全部通过')
