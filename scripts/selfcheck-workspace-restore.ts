// 自检：历史回滚在冲突 / 只读 / 离线时必须禁用，本机未落盘时必须中止。
// 用法：npm run selfcheck:workspace-restore
import assert from 'node:assert/strict'
import { restoreAbortReason, restoreAllowed, restoreBlockedReason } from '../src/workspaceRestore'

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

const online = {
  mode: 'server' as const,
  state: 'online',
  readOnly: false,
  conflict: false,
  busy: false,
}

check('在线且无冲突时允许回滚', () => {
  assert.equal(restoreAllowed(online), true)
  assert.equal(restoreBlockedReason(online), '')
})

check('冲突未解决时禁止回滚，并说明先处理冲突', () => {
  const gate = { ...online, conflict: true, readOnly: true }
  assert.equal(restoreAllowed(gate), false)
  assert.match(restoreBlockedReason(gate), /冲突/)
})

check('只读 / 离线 / 忙碌时分别给出原因', () => {
  assert.match(restoreBlockedReason({ ...online, readOnly: true }), /只读/)
  assert.match(restoreBlockedReason({ ...online, state: 'offline' }), /未连接/)
  assert.match(restoreBlockedReason({ ...online, busy: true }), /上一次操作/)
})

check('本机改动没写进服务端时中止回滚，不覆盖本机数据', () => {
  assert.equal(restoreAbortReason(true), '')
  assert.match(restoreAbortReason(false), /中止回滚/)
})

if (failures > 0) {
  console.error(`\n${failures} 项回滚门禁自检失败`)
  process.exitCode = 1
} else {
  console.log('\n全部回滚门禁自检通过')
}
