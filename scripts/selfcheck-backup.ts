// 自检：数据备份格式、兼容缺失设置、损坏数据拒绝与文件名。
// 用法：npm run selfcheck:backup
import assert from 'node:assert/strict'
import {
  BACKUP_APP,
  BACKUP_VERSION,
  backupCounts,
  backupFileName,
  createBackup,
  parseBackup,
  type PersistedData,
} from '../src/backup'
import {
  BACKUP_HISTORY_KEY,
  MAX_BACKUP_HISTORY,
  MAX_BACKUP_HISTORY_BYTES,
  pruneBackupHistory,
  readBackupHistory,
  removeBackupHistory,
  saveBackupHistory,
  BackupHistoryError,
  type BackupHistoryEntry,
} from '../src/backupHistory'

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

const DATA: PersistedData = {
  sources: [{
    id: 'source-1',
    name: '示例订阅',
    url: 'https://sub.example.com/a',
    isEnabled: true,
    excludedNodeKeys: [],
  }],
  nodes: [
    {
      id: 'node-1', kind: 'ss', name: '订阅节点', server: 'ss.example.com',
      port: 8388, tls: false, skipCertificateVerification: false,
      rawURI: 'ss://demo', sourceID: 'source-1',
    },
    {
      id: 'node-2', kind: 'ss', name: '自有节点', server: 'manual.example.com',
      port: 8388, tls: false, skipCertificateVerification: false,
      rawURI: 'ss://demo', isManual: true, isEnabled: true,
    },
  ],
  selectedSchemeID: 'acl4ssr-online',
  policySelections: { 节点选择: '自动选择' },
  customSchemes: [],
  localRuleSets: [],
  autoRefreshOnOpen: true,
  autoRefreshRuleSetsOnOpen: false,
  preferRuleSets: true,
  exportContentMode: 'full',
  exportContentModes: { surge: 'nodes' },
  embedRemoteSubscriptions: false,
  exportProtocols: ['ss'],
  exportConfigName: '家用',
  appendSourceName: true,
  clientOrder: [],
  hiddenClients: [],
  nodeNameFilter: { include: '', exclude: '', useRegex: false, caseSensitive: false },
  filterSubscriptionInfoNodes: false,
  renewalRemindersEnabled: true,
  latencyTestMode: 'automatic',
  tailnets: [],
}

function wrap(data: unknown): string {
  return JSON.stringify({
    app: BACKUP_APP,
    version: BACKUP_VERSION,
    exportedAt: '2026-11-01T12:00:00.000Z',
    data,
  })
}

class MemoryStorage {
  private values = new Map<string, string>()

  get length(): number {
    return this.values.size
  }

  clear(): void {
    this.values.clear()
  }

  getItem(key: string): string | null {
    return this.values.get(key) ?? null
  }

  key(index: number): string | null {
    return Array.from(this.values.keys())[index] ?? null
  }

  removeItem(key: string): void {
    this.values.delete(key)
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value)
  }
}

function entry(label: string, now: number): BackupHistoryEntry {
  return {
    id: `id-${now}`,
    createdAt: new Date(now).toISOString(),
    label,
    file: createBackup(DATA, now),
  }
}

function main(): void {
  check('备份导出与恢复可以往返', () => {
    const file = createBackup(DATA)
    const parsed = parseBackup(JSON.stringify(file))
    assert.equal(parsed.data.sources.length, 1)
    assert.equal(parsed.data.nodes.length, 2)
    assert.deepEqual(parsed.data.policySelections, { 节点选择: '自动选择' })
    assert.equal(parsed.data.autoRefreshOnOpen, true)
    assert.equal(parsed.data.exportContentModes.surge, 'nodes')
    assert.equal(parsed.data.latencyTestMode, 'automatic')
  })

  check('缺失设置项回退默认值，但用户数据保留', () => {
    const parsed = parseBackup(wrap({
      sources: DATA.sources,
      nodes: DATA.nodes,
      selectedSchemeID: 'custom-1',
      policySelections: {},
      customSchemes: [],
      localRuleSets: [],
    }))
    assert.equal(parsed.data.autoRefreshOnOpen, false)
    assert.equal(parsed.data.exportConfigName, 'tower')
    assert.equal(parsed.data.latencyTestMode, 'tcp')
    assert.equal(parsed.data.sources.length, 1)
    assert.equal(parsed.data.nodes.length, 2)
  })

  check('非 JSON、错误应用、错误版本都会被拒绝', () => {
    assert.throws(() => parseBackup('not json'), /JSON/)
    assert.throws(() => parseBackup(JSON.stringify({ app: 'other', version: 1, data: {} })), /塔台/)
    assert.throws(() => parseBackup(JSON.stringify({ app: BACKUP_APP, version: 99, data: {} })), /版本/)
  })

  check('损坏的节点或订阅数据会被拒绝，不会恢复成空配置', () => {
    const badNode = { ...DATA, nodes: [{ id: 'x', kind: 'ss', name: '坏节点', server: 'x', port: 0 }] }
    assert.throws(() => parseBackup(wrap(badNode)), /节点数据/)
    const badSource = { ...DATA, sources: [{ id: 1, name: '坏订阅', url: '' }] }
    assert.throws(() => parseBackup(wrap(badSource)), /订阅数据/)
    const badEnabled = { ...DATA, sources: [{ ...DATA.sources[0], isEnabled: 0 }] }
    assert.throws(() => parseBackup(wrap(badEnabled)), /订阅数据/)
  })

  check('备份不保留未知密钥字段', () => {
    const parsed = parseBackup(wrap({ ...DATA, tailnetAuthKeys: { secret: 'key' } }))
    assert.equal('tailnetAuthKeys' in parsed.data, false)
  })

  check('备份统计区分订阅节点与自有节点', () => {
    const counts = backupCounts(DATA)
    assert.deepEqual(counts, {
      sources: 1,
      nodes: 2,
      manualNodes: 1,
      schemes: 0,
      ruleSets: 0,
      tailnets: 0,
    })
  })

  check('备份文件名包含日期时间', () => {
    assert.match(backupFileName(new Date(2026, 10, 1, 9, 5)), /^tower-backup-20261101-0905\.json$/)
  })

  check('版本历史只保留最新快照并保持顺序', () => {
    const storage = new MemoryStorage() as unknown as Storage
    for (let index = 0; index <= MAX_BACKUP_HISTORY + 1; index += 1) {
      saveBackupHistory(DATA, `版本 ${index}`, 1000 + index, storage)
    }
    const history = readBackupHistory(storage)
    assert.equal(history.length, MAX_BACKUP_HISTORY)
    assert.equal(history[0].label, `版本 ${MAX_BACKUP_HISTORY + 1}`)
    assert.ok(history[0].createdAt > history[1].createdAt)
  })

  check('版本历史会忽略损坏的条目', () => {
    const storage = new MemoryStorage() as unknown as Storage
    const valid = entry('有效版本', 1000)
    storage.setItem(BACKUP_HISTORY_KEY, JSON.stringify([
      valid,
      { id: 'bad', createdAt: 'x', label: '坏版本', file: { app: 'other' } },
      'not an entry',
    ]))
    const history = readBackupHistory(storage)
    assert.equal(history.length, 1)
    assert.equal(history[0].label, '有效版本')
  })

  check('版本历史可以保存、读取和删除', () => {
    const storage = new MemoryStorage() as unknown as Storage
    const saved = saveBackupHistory(DATA, '手动保存', 2000, storage)
    assert.equal(readBackupHistory(storage)[0].id, saved.id)
    removeBackupHistory(saved.id, storage)
    assert.equal(readBackupHistory(storage).length, 0)
  })

  check('版本历史裁剪遵守体积上限', () => {
    const entries = [entry('最新', 3000), entry('中间', 2000), entry('最旧', 1000)]
    const newSize = JSON.stringify(entries[0]).length
    const pruned = pruneBackupHistory(entries, entries.length, newSize)
    assert.equal(pruned.length, 1)
    assert.equal(pruned[0].label, '最新')
  })

  check('超过体积上限的单份快照会被拒绝', () => {
    const huge: PersistedData = {
      ...DATA,
      nodes: [{ ...DATA.nodes[0], password: 'x'.repeat(MAX_BACKUP_HISTORY_BYTES) }],
    }
    const storage = new MemoryStorage() as unknown as Storage
    assert.throws(
      () => saveBackupHistory(huge, '过大', 3000, storage),
      (error: unknown) => error instanceof BackupHistoryError && /3 MB/.test(error.message),
    )
    assert.equal(readBackupHistory(storage).length, 0)
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部数据备份检查通过')
}

main()
