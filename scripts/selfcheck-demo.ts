// 自检：示例工作区隔离边界——独立存储键、恢复示例数据、服务端写操作禁用。
// 用法：npm run selfcheck:demo
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  DEMO_MODE,
  DEMO_PUBLISH_NOTE,
  demoBlocksServerWrites,
  demoStorageKeys,
  demoWorkspaceKeys,
  resetDemoWorkspace,
} from '../src/demo/demoMode'
import { DEMO_LATENCY, DEMO_NODES, demoSeedState } from '../src/demo/demoWorkspace'

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

/** 最小 Storage 替身：只实现恢复示例数据用到的读取与删除。 */
class MemoryStorage {
  private readonly map = new Map<string, string>()

  get length(): number {
    return this.map.size
  }

  key(index: number): string | null {
    return [...this.map.keys()][index] ?? null
  }

  getItem(key: string): string | null {
    return this.map.get(key) ?? null
  }

  setItem(key: string, value: string): void {
    this.map.set(key, value)
  }

  removeItem(key: string): void {
    this.map.delete(key)
  }
}

check('示例与真实工作区使用完全不相交的存储键', () => {
  const real = demoStorageKeys(false)
  const demo = demoStorageKeys(true)
  for (const key of Object.keys(real) as Array<keyof typeof real>) {
    assert.notEqual(demo[key], real[key], `${key} 不应与真实键相同`)
    assert.ok(demo[key].endsWith('-demo'), `${demo[key]} 应带 -demo 后缀`)
  }
  assert.ok(!Object.values(real).includes(demo.store))
})

check('Node 环境默认不是示例模式，恢复操作也不会动真实键', () => {
  assert.equal(DEMO_MODE, false)
  assert.equal(demoBlocksServerWrites(DEMO_MODE), false)
  const storage = new MemoryStorage()
  storage.setItem('tower-web-state', 'real-workspace')
  assert.deepEqual(resetDemoWorkspace(storage), [])
  assert.equal(storage.getItem('tower-web-state'), 'real-workspace')
})

check('恢复示例数据只清演示键，真实工作区与订阅链接保持原样', () => {
  const storage = new MemoryStorage()
  const real = demoStorageKeys(false)
  const demo = demoStorageKeys(true)
  storage.setItem(real.store, 'real-workspace')
  storage.setItem(real.subToken, 'real-token')
  storage.setItem(real.subURL, 'https://example.com/real')
  storage.setItem(real.subUpdatedAt, '1700000000000')
  for (const key of demoWorkspaceKeys()) storage.setItem(key, 'demo-value')

  const removed = resetDemoWorkspace(storage, true)
  assert.deepEqual([...removed].sort(), [...demoWorkspaceKeys()].sort())
  for (const key of demoWorkspaceKeys()) assert.equal(storage.getItem(key), null, `${key} 应被清除`)
  assert.equal(storage.getItem(real.store), 'real-workspace')
  assert.equal(storage.getItem(real.subToken), 'real-token')
  assert.equal(storage.getItem(real.subURL), 'https://example.com/real')
  assert.equal(storage.getItem(real.subUpdatedAt), '1700000000000')
  assert.deepEqual(resetDemoWorkspace(storage, true), [])
  assert.equal(storage.length, 4)
  assert.equal(demo.store, 'tower-web-state-demo')
})

check('示例种子数据：虚构节点、无真实域名、延迟与节点一一对应', () => {
  const seed = demoSeedState()
  assert.equal(seed.nodes.length, 6)
  assert.equal(new Set(seed.nodes.map((node) => node.id)).size, seed.nodes.length)
  for (const node of seed.nodes) {
    assert.ok(node.server.endsWith('.invalid'), `${node.server} 不是 .invalid 示例域名`)
    assert.equal(seed.latencyByNodeId[node.id], DEMO_LATENCY[node.id])
    assert.equal(seed.latencyMethodByNodeId[node.id], 'tcp')
  }
  assert.deepEqual(seed.probeErrorByNodeId, {})
  assert.equal(DEMO_NODES.length, seed.nodes.length)
})

check('示例模式禁止服务端写操作，并给出可理解的提示', () => {
  assert.equal(demoBlocksServerWrites(true), true)
  assert.equal(demoBlocksServerWrites(false), false)
  assert.match(DEMO_PUBLISH_NOTE, /不生成服务端订阅链接/)
})

check('导出页与设置弹窗在示例模式走隔离分支', () => {
  const exportTab = readFileSync(new URL('../src/pages/ExportTab.tsx', import.meta.url), 'utf8')
  const publishGuards = exportTab.match(/demoBlocksServerWrites\(DEMO_MODE\)/g) ?? []
  assert.ok(publishGuards.length >= 2, `导出页至少应拦截发布与分享，实际 ${publishGuards.length} 处`)
  assert.ok(exportTab.includes('DEMO_PUBLISH_NOTE'), '导出页应展示示例模式说明')
  assert.ok(exportTab.includes("if (DEMO_MODE) return"), '示例模式不应请求 /api/network')

  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8')
  assert.ok(app.includes('{!DEMO_MODE && <LANAccessGate />}'), '示例模式不应经过局域网访问门')
  assert.ok(app.includes('restoreDemoWorkspace'), '示例横幅应提供恢复示例数据')

  const settings = readFileSync(new URL('../src/components/SubscriptionSettingsDialog.tsx', import.meta.url), 'utf8')
  assert.ok(settings.includes('if (!DEMO_MODE) void loadServerAccess()'), '示例模式不应读取服务端设置')
})

console.log(failures === 0 ? '\n全部示例工作区自检通过' : `\n${failures} 项示例工作区自检失败`)
process.exit(failures === 0 ? 0 : 1)
