// 自检：工作区逐字段校验、可见提示、旧结构迁移幂等与未知字段往返。
// 用法：npm run selfcheck:workspace-validation
import assert from 'node:assert/strict'
import { BUILTIN_SCHEMES } from '../src/rules/scheme'
import {
  describeWorkspaceIssues,
  normalizeWorkspaceDataDetailed,
  WorkspaceDataError,
} from '../src/workspaceValidation'

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

const GOOD = {
  sources: [{
    id: 'source-1',
    name: '示例订阅',
    url: 'https://sub.example.com/a',
    isEnabled: true,
    excludedNodeKeys: [] as string[],
    updatedAt: 1_700_000_000_000,
  }],
  nodes: [{
    id: 'node-1',
    kind: 'ss',
    name: '示例节点',
    server: '203.0.113.10',
    port: 8388,
    tls: false,
    skipCertificateVerification: false,
    sourceID: 'source-1',
  }],
  customSchemes: [{
    id: 'scheme-1',
    name: '示例方案',
    description: '',
    groups: [{ name: 'PROXY', type: 'select', options: ['DIRECT'] }],
    rules: [{ type: 'DOMAIN', group: 'PROXY', value: 'example.com' }],
    ruleSets: [{
      id: 'set-1',
      name: '示例规则集',
      group: 'PROXY',
      rules: [],
      sourceKind: 'library',
    }],
  }],
  localRuleSets: [{
    id: 'local-1',
    name: '本地规则集',
    rules: [{ type: 'DOMAIN', value: 'local.example.com' }],
    updatedAt: 1_700_000_000_000,
  }],
  selectedSchemeID: 'scheme-1',
  policySelections: { PROXY: 'DIRECT' },
  exportConfigName: 'tower',
  tailnets: [{
    id: 'tailnet-1',
    name: '内网',
    subnets: ['100.64.0.0/10'],
    isEnabled: true,
  }],
  tailnetAuthKeys: { 'tailnet-1': 'tskey-example' },
  ruleSetExclusions: { 'set-1': ['DOMAIN|example.com'] },
  builtinSchemeOverrides: {},
  schemeSnapshots: {},
  snapshotSeq: 0,
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

function plain<T>(value: T): unknown {
  return JSON.parse(JSON.stringify(value)) as unknown
}

check('完整工作区零问题、零迁移', () => {
  const result = normalizeWorkspaceDataDetailed(clone(GOOD))
  assert.equal(result.issues.length, 0)
  assert.equal(result.migrated, 0)
  assert.equal(result.data.sources.length, 1)
  assert.equal(result.data.customSchemes[0].ruleSets?.length, 1)
})

check('单个顶层键类型损坏只丢该键，其它键正常落地', () => {
  const result = normalizeWorkspaceDataDetailed({ ...clone(GOOD), nodes: 'not-an-array' })
  assert.deepEqual(result.data.nodes, [])
  assert.equal(result.data.sources.length, 1, '订阅不应被节点损坏拖累')
  assert.equal(result.data.customSchemes.length, 1, '方案不应被节点损坏拖累')
  assert.equal(result.data.localRuleSets.length, 1, '规则集不应被节点损坏拖累')
  const issue = result.issues.find((item) => item.key === 'nodes')
  assert.ok(issue, '必须报告 nodes 键')
  assert.equal(issue.wholeKey, true, '整字段损坏要标记，调用方可保留本机原值')
  assert.match(issue.reason, /应该是数组/)
  assert.equal(issue.keyLabel, '节点')
})

check('数组里单条坏记录只丢该条，其余记录保留', () => {
  const raw = clone(GOOD)
  raw.sources.push({ id: 'broken-source', name: '坏订阅' } as never)
  const result = normalizeWorkspaceDataDetailed(raw)
  assert.equal(result.data.sources.length, 1, '好订阅必须保留')
  assert.equal(result.data.sources[0].id, 'source-1')
  const issue = result.issues.find((item) => item.key === 'sources' && item.index === 2)
  assert.ok(issue, '必须指出第 2 条订阅')
  assert.equal(issue.wholeKey, undefined)
  assert.equal(issue.keyLabel, '订阅')
  assert.match(issue.label, /第 2 条/)
  assert.equal(typeof issue.reason, 'string')
})

check('坏数据有可见提示，能说出具体键名与理由', () => {
  const raw = { ...clone(GOOD), nodes: 42, policySelections: 'broken' }
  const result = normalizeWorkspaceDataDetailed(raw)
  const summary = describeWorkspaceIssues(result.issues)
  assert.match(summary, /服务端工作区/)
  assert.match(summary, /2 个字段整块无法读取/)
  const keys = result.issues.filter((item) => item.wholeKey).map((item) => item.keyLabel)
  assert.deepEqual(keys.sort(), ['策略选择', '节点'])
  assert.ok(result.issues.every((item) => item.reason.length > 0))
})

check('旧结构迁移：字符串→数组、对象→数组、数字字符串', () => {
  const legacy = clone(GOOD)
  legacy.sources[0].excludedNodeKeys = 'node-1,node-2' as never
  legacy.nodes[0].port = '8388' as never
  legacy.nodes[0].tls = 'false' as never
  legacy.customSchemes[0].ruleSets = { 'set-1': clone(GOOD.customSchemes[0].ruleSets[0]) } as never
  legacy.customSchemes[0].groups = { PROXY: { type: 'select', options: ['DIRECT'] } } as never
  legacy.localRuleSets = { 'local-1': clone(GOOD.localRuleSets[0]) } as never
  legacy.tailnets[0].subnets = '100.64.0.0/10' as never

  const first = normalizeWorkspaceDataDetailed(legacy)
  assert.deepEqual(first.data.sources[0].excludedNodeKeys, ['node-1', 'node-2'])
  assert.equal(first.data.nodes[0].port, 8388)
  assert.equal(first.data.nodes[0].tls, false)
  assert.equal(first.data.customSchemes[0].ruleSets?.length, 1)
  assert.equal(first.data.customSchemes[0].groups[0].name, 'PROXY')
  assert.equal(first.data.localRuleSets.length, 1)
  assert.deepEqual(first.data.tailnets[0].subnets, ['100.64.0.0/10'])
  assert.ok(first.migrated >= 6, `迁移条目应 >= 6，实际 ${first.migrated}`)
  assert.equal(first.issues.filter((item) => item.severity === 'dropped').length, 0)
})

check('迁移不冲掉用户的规则和规则集', () => {
  const legacy = clone(GOOD)
  legacy.localRuleSets = { 'local-1': clone(GOOD.localRuleSets[0]) } as never
  legacy.customSchemes[0].rules = { 0: clone(GOOD.customSchemes[0].rules[0]) } as never
  const result = normalizeWorkspaceDataDetailed(legacy)
  assert.equal(result.data.localRuleSets[0].rules.length, 1, '本地规则集不能被迁移清空')
  assert.equal(result.data.customSchemes[0].rules.length, 1, '方案规则不能被迁移清空')
  assert.equal(result.data.customSchemes[0].ruleSets?.length, 1, '方案规则集不能被迁移清空')
})

check('迁移幂等：同一份数据连跑两次结果一致，第二次无迁移', () => {
  const legacy = clone(GOOD)
  legacy.sources[0].excludedNodeKeys = 'node-1' as never
  legacy.nodes[0].port = '8388' as never
  legacy.customSchemes[0].ruleSets = { 'set-1': clone(GOOD.customSchemes[0].ruleSets[0]) } as never
  legacy.localRuleSets = { 'local-1': clone(GOOD.localRuleSets[0]) } as never
  const first = normalizeWorkspaceDataDetailed(legacy)
  const second = normalizeWorkspaceDataDetailed(plain(first.data))
  assert.deepEqual(plain(second.data), plain(first.data))
  assert.equal(second.migrated, 0, '第二次不应再报告迁移')
  assert.equal(second.issues.filter((item) => item.severity === 'dropped').length, 0)
})

check('未知顶层字段往返不丢', () => {
  const raw = {
    ...clone(GOOD),
    futureFeature: { enabled: true, ratio: 0.5 },
    futureList: [1, 2, 3],
  }
  const first = normalizeWorkspaceDataDetailed(raw)
  assert.deepEqual(first.unknown, {
    futureFeature: { enabled: true, ratio: 0.5 },
    futureList: [1, 2, 3],
  })
  // 模拟推送时把未知字段拼回顶层；再次载入必须仍然认得出来。
  const wire = { ...first.unknown, ...plain(first.data) }
  const second = normalizeWorkspaceDataDetailed(wire)
  assert.deepEqual(second.unknown, first.unknown)
  assert.deepEqual(plain(second.data), plain(first.data))
})

check('已知记录内部的未知字段也不被抹掉', () => {
  const raw = clone(GOOD) as unknown as { sources: Array<Record<string, unknown>> }
  raw.sources[0].futureSourceField = 'keep-me'
  const result = normalizeWorkspaceDataDetailed(raw)
  assert.equal((result.data.sources[0] as Record<string, unknown>).futureSourceField, 'keep-me')
})

check('旧版内联固化升级为快照 + 指针，且幂等', () => {
  const content = {
    scheme: clone(GOOD.customSchemes[0]),
    ruleSets: [],
    source: {
      iniURL: 'https://example.com/template.ini',
      commitSha: 'a'.repeat(40),
      files: [],
      fetchedAt: 1_700_000_000_000,
    },
  }
  const legacy = { ...clone(GOOD), builtinSchemeOverrides: { 'scheme-1': content } }
  const first = normalizeWorkspaceDataDetailed(legacy)
  assert.deepEqual(first.data.builtinSchemeOverrides, { 'scheme-1': { snapshotId: 1 } })
  assert.ok(first.data.schemeSnapshots['1'])
  assert.ok(first.issues.some((item) => item.severity === 'migrated' && item.key === 'builtinSchemeOverrides'))
  const second = normalizeWorkspaceDataDetailed(plain(first.data))
  assert.deepEqual(plain(second.data), plain(first.data))
  assert.equal(second.migrated, 0)
})

check('回退类问题不算丢弃，也不整字段跳过', () => {
  const result = normalizeWorkspaceDataDetailed({ ...clone(GOOD), selectedSchemeID: 'ghost-scheme' })
  const issue = result.issues.find((item) => item.key === 'selectedSchemeID')
  assert.ok(issue)
  assert.equal(issue.severity, 'fallback')
  assert.equal(issue.wholeKey, undefined)
  assert.equal(result.data.selectedSchemeID, BUILTIN_SCHEMES[0].id)
  assert.match(describeWorkspaceIssues(result.issues), /回退到默认值/)
})

check('映射字段里的坏值逐条跳过，其它条目保留', () => {
  const raw = {
    ...clone(GOOD),
    policySelections: { PROXY: 'DIRECT', BROKEN: 5 },
    ruleSetExclusions: { 'set-1': ['DOMAIN|example.com', 5, ''] },
  }
  const result = normalizeWorkspaceDataDetailed(raw)
  assert.deepEqual(result.data.policySelections, { PROXY: 'DIRECT' })
  const policyIssue = result.issues.find((item) => item.key === 'policySelections')
  assert.ok(policyIssue)
  assert.equal(policyIssue.label, 'BROKEN')
  assert.equal(policyIssue.wholeKey, undefined)
  assert.deepEqual(result.data.ruleSetExclusions, { 'set-1': ['DOMAIN|example.com'] })
  const exclusionIssue = result.issues.find((item) => item.key === 'ruleSetExclusions')
  assert.ok(exclusionIssue)
  assert.match(exclusionIssue.reason, /2 条签名/)
})

check('固化相关顶层容器形状坏掉时产出整键问题', () => {
  const raw = {
    ...clone(GOOD),
    builtinSchemeOverrides: 'broken' as never,
    schemeSnapshots: 42 as never,
  }
  const result = normalizeWorkspaceDataDetailed(raw)
  const overrides = result.issues.find((item) => item.key === 'builtinSchemeOverrides')
  assert.ok(overrides, 'builtinSchemeOverrides 形状坏必须报 issue')
  assert.equal(overrides.severity, 'dropped')
  assert.equal(overrides.wholeKey, true)
  const snapshots = result.issues.find((item) => item.key === 'schemeSnapshots')
  assert.ok(snapshots, 'schemeSnapshots 形状坏必须报 issue')
  assert.equal(snapshots.wholeKey, true)
})

check('根不是对象仍然抛错（不是字段级问题）', () => {
  assert.throws(() => normalizeWorkspaceDataDetailed(['not-an-object']), WorkspaceDataError)
  assert.throws(() => normalizeWorkspaceDataDetailed(null), WorkspaceDataError)
})

if (failures > 0) {
  console.error(`\n${failures} 项自检失败`)
  process.exitCode = 1
} else {
  console.log('\n工作区字段校验自检全部通过')
}
