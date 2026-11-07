// 自检：数据备份格式、兼容缺失设置、损坏数据拒绝与文件名。
// 用法：npm run selfcheck:backup
import assert from 'node:assert/strict'
import {
  BACKUP_APP,
  BACKUP_VERSION,
  backupCounts,
  backupFileName,
  clearCorruptPersistence,
  createBackup,
  inspectSnapshotHealth,
  parseBackup,
  type PersistedData,
} from '../src/backup'
import type { BuiltinSchemeOverrideRef, BuiltinSchemeSnapshot } from '../src/models/types'
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

  check('单条坏数据只丢这一条，其余条目照常恢复并逐条记录原因', () => {
    const badNode = { ...DATA, nodes: [{ ...DATA.nodes[0], port: 0 }, DATA.nodes[1]] }
    const parsedNode = parseBackup(wrap(badNode))
    assert.equal(parsedNode.data.nodes.length, 1)
    assert.equal(parsedNode.data.nodes[0].id, 'node-2')
    assert.equal(parsedNode.rejected?.[0].kind, 'node')
    assert.equal(parsedNode.rejected?.[0].index, 1)
    assert.match(parsedNode.rejected?.[0].reason ?? '', /端口/)

    const badSource = { ...DATA, sources: [DATA.sources[0], { id: 1, name: '坏订阅', url: '' }] }
    const parsedSource = parseBackup(wrap(badSource))
    assert.equal(parsedSource.data.sources.length, 1)
    assert.equal(parsedSource.rejected?.[0].kind, 'source')
    assert.equal(parsedSource.rejected?.[0].index, 2)

    const badEnabled = { ...DATA, sources: [{ ...DATA.sources[0], isEnabled: 0 }] }
    const parsedEnabled = parseBackup(wrap(badEnabled))
    assert.equal(parsedEnabled.data.sources.length, 0)
    assert.equal(parsedEnabled.rejected?.[0].kind, 'source')
  })

  check('备份只丢弃损坏的方案组、规则、规则集与节点类型', () => {
    const goodScheme = {
      id: 'scheme-good', name: '正常方案', description: '', groups: [], rules: [], ruleSets: [],
    }
    const badGroup = {
      ...DATA,
      customSchemes: [{ id: 'scheme-1', name: '坏方案', groups: [null], rules: [] }, goodScheme],
    }
    const parsedGroup = parseBackup(wrap(badGroup))
    assert.equal(parsedGroup.data.customSchemes.length, 1)
    assert.equal(parsedGroup.data.customSchemes[0].id, 'scheme-good')
    assert.equal(parsedGroup.rejected?.[0].kind, 'scheme')
    assert.match(parsedGroup.rejected?.[0].label, /坏方案/)

    const badRule = {
      ...DATA,
      customSchemes: [{
        id: 'scheme-2', name: '坏规则', description: '', groups: [],
        rules: [{ type: 'DOMAIN', value: 'example.com' }], ruleSets: [],
      }],
    }
    assert.equal(parseBackup(wrap(badRule)).data.customSchemes.length, 0)
    assert.equal(parseBackup(wrap(badRule)).rejected?.[0].kind, 'scheme')

    const badRuleSet = {
      ...DATA,
      localRuleSets: [{ id: 'set-1', name: '坏规则集', rules: [null] }],
    }
    const parsedRuleSet = parseBackup(wrap(badRuleSet))
    assert.equal(parsedRuleSet.data.localRuleSets.length, 0)
    assert.equal(parsedRuleSet.rejected?.[0].kind, 'ruleSet')

    const badKind = { ...DATA, nodes: [{ ...DATA.nodes[0], kind: 'not-a-real-kind' }] }
    const parsedKind = parseBackup(wrap(badKind))
    assert.equal(parsedKind.data.nodes.length, 0)
    assert.match(parsedKind.rejected?.[0].reason ?? '', /协议 kind/)
  })

  check('顶层字段类型错误按空恢复并记录，不再整包拒绝', () => {
    const parsed = parseBackup(wrap({
      ...DATA,
      sources: 'not-an-array',
      selectedSchemeID: 42,
    }))
    assert.equal(parsed.data.sources.length, 0)
    assert.equal(parsed.data.selectedSchemeID, '')
    assert.ok(parsed.rejected?.some((item) => item.kind === 'topLevel' && item.label === 'sources'))
    assert.ok(parsed.rejected?.some((item) => item.kind === 'topLevel' && item.label === 'selectedSchemeID'))
    // 其余用户数据照常恢复。
    assert.equal(parsed.data.nodes.length, 2)
  })

  check('悬空快照指针被记录为拒绝项，并可从数据体检里清除', () => {
    const dangling: Record<string, BuiltinSchemeOverrideRef> = { 'acl4ssr-online': { snapshotId: 99 } }
    const parsed = parseBackup(wrap({ ...DATA, builtinSchemeOverrides: dangling, schemeSnapshots: {} }))
    assert.equal(parsed.rejected?.[0].kind, 'override')
    assert.match(parsed.rejected?.[0].reason ?? '', /不存在/)

    const health = inspectSnapshotHealth(dangling, {})
    assert.equal(health.dangling.length, 1)
    const cleaned = clearCorruptPersistence(dangling, {})
    assert.equal(cleaned.pointersCleared, 1)
    assert.deepEqual(cleaned.overrides, {})
    assert.equal(inspectSnapshotHealth(cleaned.overrides, cleaned.snapshots).dangling.length, 0)
  })

  check('损坏快照只丢这一条，可用快照与指针保留', () => {
    const snapshot: BuiltinSchemeSnapshot = {
      id: 1,
      schemeID: 'acl4ssr-online',
      createdAt: 1000,
      scheme: {
        id: 'acl4ssr-online', name: '示例方案', description: '', groups: [], rules: [], ruleSets: [],
      },
      ruleSets: [],
      source: {
        iniURL: 'https://example.com/demo.ini',
        commitSha: '0123456789abcdef0123456789abcdef01234567',
        files: [],
        fetchedAt: 1000,
        ruleCount: 0,
        ruleSetCount: 0,
      },
    }
    const damaged = { '1': snapshot, '2': { ...snapshot, id: 2, scheme: undefined } } as unknown as Record<string, BuiltinSchemeSnapshot>
    const overrides: Record<string, BuiltinSchemeOverrideRef> = { 'acl4ssr-online': { snapshotId: 1 } }
    const cleaned = clearCorruptPersistence(overrides, damaged)
    assert.equal(cleaned.snapshotsCleared, 1)
    assert.equal(cleaned.pointersCleared, 0)
    assert.deepEqual(Object.keys(cleaned.snapshots), ['1'])
    assert.deepEqual(cleaned.overrides, overrides)
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

  check('旧备份缺少 excludedNodeKeys 时补成空数组并保持启用', () => {
    const legacy = JSON.stringify({
      app: BACKUP_APP,
      version: BACKUP_VERSION,
      exportedAt: '2025-01-01T00:00:00.000Z',
      data: {
        ...DATA,
        sources: [{ id: 'old-source', name: '旧订阅', url: 'https://sub.example.com/old' }],
      },
    })
    const restored = parseBackup(legacy)
    assert.deepEqual(restored.data.sources[0].excludedNodeKeys, [])
    assert.equal(restored.data.sources[0].isEnabled, true)
    // 界面会直接读 .length；恢复后的对象必须能安全访问。
    assert.equal(restored.data.sources[0].excludedNodeKeys.length, 0)
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部数据备份检查通过')
}

main()
