// 自检：批量刷新与自动刷新都要留下「成功 X / 失败 Y」汇总和失败明细。
// 用法：npm run selfcheck:refresh-report
import assert from 'node:assert/strict'
import {
  autoRefreshReady,
  buildRefreshReport,
  describeRefreshReport,
  refreshFailureText,
  selectRefreshTargets,
  type RefreshOutcome,
} from '../src/subscriptionRefreshReport'

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

check('手动刷新汇总成功与失败数量', () => {
  const outcomes: RefreshOutcome[] = [
    { id: 'a', name: '机场 A', error: '' },
    { id: 'b', name: '机场 B', error: 'HTTP 502' },
    { id: 'c', name: '机场 C', error: '节点解析失败' },
  ]
  const report = buildRefreshReport('manual', outcomes, 12345)
  assert.equal(report.total, 3)
  assert.equal(report.succeeded, 1)
  assert.equal(report.failures.length, 2)
  assert.equal(report.at, 12345)
  assert.equal(describeRefreshReport(report), '刷新全部：成功 1 / 失败 2')
})

check('自动刷新同样可汇总，文案区分触发来源', () => {
  const report = buildRefreshReport('auto', [
    { id: 'a', name: '机场 A', error: '' },
    { id: 'b', name: '机场 B', error: '超时' },
  ])
  assert.equal(describeRefreshReport(report), '打开页面时自动刷新：成功 1 / 失败 1')
})

check('失败明细能看出是哪个订阅、什么原因', () => {
  const report = buildRefreshReport('manual', [
    { id: 'b', name: '机场 B', error: 'HTTP 502' },
  ])
  assert.equal(refreshFailureText(report.failures[0]), '「机场 B」：HTTP 502')
})

check('只有空白的错误串不算失败（例如订阅在刷新途中被删除）', () => {
  const report = buildRefreshReport('auto', [
    { id: 'a', name: '机场 A', error: '   ' },
  ])
  assert.equal(report.failures.length, 0)
  assert.equal(report.succeeded, 1)
})

check('自动刷新等工作区就绪后再跑，避免按本地旧缓存刷新', () => {
  assert.equal(autoRefreshReady('unknown', 'checking'), false)
  assert.equal(autoRefreshReady('server', 'connecting'), false)
  assert.equal(autoRefreshReady('server', 'offline'), false)
  assert.equal(autoRefreshReady('server', 'conflict'), false)
  assert.equal(autoRefreshReady('server', 'online'), true)
  assert.equal(autoRefreshReady('local', 'local'), true)
})

check('刷新全部排除已经在刷新中的订阅', () => {
  const sources = [
    { id: 'a', name: 'A' },
    { id: 'b', name: 'B' },
    { id: 'c', name: 'C' },
  ]
  assert.deepEqual(selectRefreshTargets(sources, ['b']).map((item) => item.id), ['a', 'c'])
})

if (failures > 0) {
  console.error(`\n${failures} 项刷新汇总自检失败`)
  process.exitCode = 1
} else {
  console.log('\n全部刷新汇总自检通过')
}
