// 自检：工作区保存失败后的「未保存」状态、退避重试、413 可操作文案，
// 以及两种模式下 localStorage 配额已满的不同提示。
// 用法：npm run selfcheck:workspace-save
import assert from 'node:assert/strict'
import type { WorkspaceData } from '../src/workspaceValidation'
import { describeWorkspaceTooLarge } from '../src/workspaceSize'
import {
  initialSaveState,
  nextSaveFailure,
  nextSaveSuccess,
  saveRetryDelay,
  shouldShowUnsavedBanner,
} from '../src/workspaceSaveNotice'
import {
  createSafeStorage,
  describeStorageFull,
  getStorageFullSerial,
  isStorageFull,
  measureStorage,
  onStorageFullChange,
} from '../src/util/localStore'

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

check('保存失败进入未保存状态，重复失败仍可见', () => {
  const first = nextSaveFailure(initialSaveState(), '请求过大')
  assert.equal(first.state, 'unsaved')
  assert.equal(first.failures, 1)
  assert.match(first.message, /自动重试已失败 1 次/)

  const second = nextSaveFailure(first, '请求过大')
  assert.equal(second.state, 'unsaved')
  assert.equal(second.failures, 2)
  assert.match(second.message, /自动重试已失败 2 次/)

  // 用户点掉同一文案的提示后，未保存横幅仍必须显示；同一错误反复出现不能被永久压制。
  assert.equal(shouldShowUnsavedBanner(second.state, second.message), true)
  assert.equal(shouldShowUnsavedBanner('online', second.message), false)
})

check('重试成功把未保存状态收回', () => {
  const failed = nextSaveFailure(initialSaveState(), '请求过大')
  const success = nextSaveSuccess()
  assert.equal(success.state, 'online')
  assert.equal(success.failures, 0)
  assert.equal(success.message, '')
  assert.equal(shouldShowUnsavedBanner(success.state, failed.message), false)
})

check('退避间隔递增并封顶 30 秒', () => {
  const delays = [1, 2, 3, 4, 5, 6, 7].map((failures) => saveRetryDelay(failures))
  assert.deepEqual(delays, [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000])
})

check('413 文案包含当前体积、上限和占用最大的规则集/快照', () => {
  const data = {
    localRuleSets: [{
      id: 'big-set',
      name: '超大规则集',
      rules: [{ type: 'DOMAIN', value: 'x'.repeat(200_000) }],
    }],
    schemeSnapshots: {
      '3': {
        id: 3,
        schemeID: 'scheme-1',
        createdAt: 1,
        scheme: { id: 'scheme-1', name: '旧方案', groups: [], rules: [] },
        ruleSets: [],
        source: {},
      },
    },
    customSchemes: [],
  } as unknown as WorkspaceData
  const report = describeWorkspaceTooLarge(data, { futureField: 'y'.repeat(2_000) }, 100 * 1024)
  assert.ok(report.bytes > 100 * 1024, '体积应超过测试上限')
  assert.match(report.message, /尚未保存/)
  assert.match(report.message, /当前工作区约/)
  assert.match(report.message, /服务端上限 100\.0 KB/)
  assert.match(report.message, /本地规则集「超大规则集」/)
  assert.match(report.message, /固化快照 #3/)
  assert.match(report.message, /缩减后会自动重试保存/)
})

check('local 与 server 模式的存储满文案不同', () => {
  const localText = describeStorageFull('local')
  assert.match(localText, /当前修改只保留在内存中，刷新后会丢失/)

  const serverText = describeStorageFull('server')
  assert.match(serverText, /仍会同步到服务器/)
  assert.match(serverText, /刷新后可从服务器恢复/)
  assert.doesNotMatch(serverText, /刷新后会丢失/)
  assert.notEqual(localText, serverText)
})

check('服务器模式未同步时不能声称已保存到服务器', () => {
  const offline = describeStorageFull({ mode: 'server', state: 'offline' })
  assert.match(offline, /尚未同步到服务器/)
  assert.match(offline, /刷新页面可能丢失/)
  assert.doesNotMatch(offline, /刷新后可从服务器恢复/)

  const unsaved = describeStorageFull({ mode: 'server', state: 'unsaved' })
  assert.match(unsaved, /尚未同步到服务器/)

  const online = describeStorageFull({ mode: 'server', state: 'online' })
  assert.match(online, /仍会同步到服务器/)
})

check('存储满提示可给出占用估算与最重的项', () => {
  const fake = {
    length: 2,
    key(index: number) {
      return ['tower-web-history', 'tower-web-state'][index] ?? null
    },
    getItem(key: string) {
      return key === 'tower-web-history' ? 'x'.repeat(4_096) : 'y'.repeat(128)
    },
  } as unknown as Pick<Storage, 'length' | 'key' | 'getItem'>
  const usage = measureStorage(fake)
  assert.ok(usage)
  assert.equal(usage.top[0].key, 'tower-web-history')
  const text = describeStorageFull('server', usage)
  assert.match(text, /本机 localStorage 已用约/)
  assert.match(text, /tower-web-history/)
})

check('配额连续失败每次都重新通知，不是只在状态翻转时通知', () => {
  const before = getStorageFullSerial()
  let notifications = 0
  const off = onStorageFullChange(() => { notifications += 1 })
  const failing = {
    getItem: () => null,
    setItem: () => { throw new Error('quota exceeded') },
    removeItem: () => {},
  }
  const safe = createSafeStorage(() => failing, () => true)
  safe.setItem('a', '1')
  safe.setItem('a', '2')
  assert.equal(notifications, 2, '两次失败应通知两次')
  assert.equal(getStorageFullSerial(), before + 2)
  assert.equal(isStorageFull(), true)

  // 恢复一次成功写入，避免影响后续检查。
  const good = {
    getItem: () => null,
    setItem: () => {},
    removeItem: () => {},
  }
  createSafeStorage(() => good, () => true).setItem('a', '1')
  assert.equal(isStorageFull(), false)
  off()
})

if (failures > 0) {
  console.error(`\n${failures} 项自检失败`)
  process.exitCode = 1
} else {
  console.log('\n工作区保存与存储提示自检全部通过')
}
