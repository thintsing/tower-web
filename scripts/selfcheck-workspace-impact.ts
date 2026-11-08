// 自检：历史回滚确认必须报告订阅 / 节点 / 屏蔽表 / 本地规则集的恢复量，
// 不能只比较方案而显示「受影响的方案：无」。
// 用法：npm run selfcheck:workspace-impact
import assert from 'node:assert/strict'
import { describeWorkspaceDataImpact, describeWorkspaceImpact } from '../src/workspaceImpact'
import { normalizeWorkspaceData, type WorkspaceData } from '../src/workspaceValidation'
import type { ProxyNode } from '../src/models/types'

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

function base(patch: Partial<WorkspaceData> = {}): WorkspaceData {
  return normalizeWorkspaceData({ ...patch })
}

function node(id: string, isSubscriptionMetadata = false): ProxyNode {
  return {
    id,
    kind: 'ss',
    name: id,
    server: '127.0.0.1',
    port: 8388,
    isSubscriptionMetadata,
  } as ProxyNode
}

function source(id: string) {
  return { id, name: id, url: `https://example.com/${id}` }
}

check('只改订阅时也要报告恢复数量', () => {
  const current = base({ sources: [source('a')] })
  const target = base({ sources: [source('a'), source('b')] })
  const impact = describeWorkspaceImpact(current, target)
  assert.deepEqual(impact.schemes, [])
  assert.deepEqual(impact.data, ['将恢复 2 个订阅'])
})

check('节点恢复不把订阅元数据节点算进去', () => {
  const current = base()
  const target = base({ nodes: [node('n1'), node('n2'), node('meta', true)] })
  assert.deepEqual(describeWorkspaceDataImpact(current, target), ['将恢复 2 个节点'])
})

check('屏蔽表恢复按签名条数报告', () => {
  const current = base()
  const target = base({ ruleSetExclusions: { set: ['a|b|c', 'd|e|f'] } })
  assert.deepEqual(describeWorkspaceDataImpact(current, target), ['将恢复 2 条屏蔽'])
})

check('本地规则集恢复也要报告', () => {
  const current = base()
  const target = base({
    localRuleSets: [{ id: 'l1', name: '我的规则', rules: [{ type: 'DOMAIN', value: 'example.com' }], updatedAt: 1 }],
  })
  assert.deepEqual(describeWorkspaceDataImpact(current, target), ['将恢复 1 个本地规则集'])
})

check('多项恢复按订阅 / 节点 / 屏蔽 / 规则集顺序汇总', () => {
  const current = base()
  const target = base({
    sources: [source('a')],
    nodes: [node('n1')],
    ruleSetExclusions: { set: ['x|y|z'] },
    localRuleSets: [{ id: 'l1', name: '我的规则', rules: [{ type: 'DOMAIN', value: 'example.com' }], updatedAt: 1 }],
  })
  assert.deepEqual(describeWorkspaceDataImpact(current, target), [
    '将恢复 1 个订阅、1 个节点、1 条屏蔽、1 个本地规则集',
  ])
})

check('目标版本数量为 0 且当前非空时明确提示会移除', () => {
  const current = base({ sources: [source('a'), source('b')] })
  const target = base()
  assert.deepEqual(describeWorkspaceDataImpact(current, target), ['将移除 全部订阅（当前 2 个）'])
})

check('方案与工作区数据都没有变化时不产生影响项', () => {
  const current = base({ sources: [source('a')] })
  const impact = describeWorkspaceImpact(current, current)
  assert.deepEqual(impact.schemes, [])
  assert.deepEqual(impact.data, [])
})

check('目标版本坏字段时明确说明无法逐项列出', () => {
  const current = base({ sources: [source('a')] })
  const impact = describeWorkspaceImpact(current, { sources: 'bad', nodes: [] })
  assert.equal(impact.incomplete, true)
  assert.match(impact.schemes[0], /数据不完整/)
})

check('纯重排不算变化，不能误报恢复 / 移除', () => {
  const current = base({ sources: [source('a'), source('b')] })
  const target = base({ sources: [source('b'), source('a')] })
  assert.deepEqual(describeWorkspaceDataImpact(current, target), [])
  const exclusions = base({ ruleSetExclusions: { set: ['x|y', 'a|b'] } })
  assert.deepEqual(
    describeWorkspaceDataImpact(exclusions, base({ ruleSetExclusions: { set: ['a|b', 'x|y'] } })),
    [],
  )
})

check('目标比当前少时说明「其余 N 项会被移除」', () => {
  const current = base({ sources: [source('a'), source('b'), source('c')] })
  const target = base({ sources: [source('a')] })
  assert.deepEqual(describeWorkspaceDataImpact(current, target), [
    '将恢复 1 个订阅',
    '将移除 其余 2 个订阅',
  ])
})

check('Tailscale 内网也纳入回滚影响', () => {
  const current = base()
  const target = base({
    tailnets: [{ id: 't1', name: '家', subnets: [], isEnabled: true }],
  })
  assert.deepEqual(describeWorkspaceDataImpact(current, target), ['将恢复 1 个 Tailscale 内网'])
})

check('单条坏记录不让整份数据变成「数据不完整」，其余字段照常比较', () => {
  const current = base({ sources: [source('a')] })
  const impact = describeWorkspaceImpact(current, {
    sources: [source('a'), { id: 'bad', name: '坏订阅' }],
    nodes: [node('n1')],
  })
  assert.equal(impact.incomplete, false)
  assert.deepEqual(impact.data, ['将恢复 1 个节点'])
})

if (failures > 0) {
  console.error(`\n${failures} 项回滚影响自检失败`)
  process.exitCode = 1
} else {
  console.log('\n全部回滚影响自检通过')
}
