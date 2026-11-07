// 服务端工作区历史自检：覆盖前备份、列表元数据、回滚生成新版本号、
// 回滚前先备份、容量淘汰保留当前版前一版、并发回滚 409、损坏历史不阻断写入。
// 用法：npm run selfcheck:workspace-history
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const MAX_HISTORY_BYTES = 50 * 1024 * 1024

async function waitFor(base: string, timeoutMs = 8000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(500) })
      if (response.ok) return true
    } catch {
      // 服务还在启动
    }
    await new Promise((resolve) => setTimeout(resolve, 120))
  }
  return false
}

interface TestServer {
  base: string
  dir: string
  stop: () => Promise<void>
}

async function startServer(
  env: Record<string, string>,
  setup?: (dir: string) => void,
): Promise<TestServer> {
  const dir = mkdtempSync(join(tmpdir(), 'tower-workspace-history-'))
  setup?.(dir)
  const port = 20000 + Math.floor(Math.random() * 30000)
  const child = spawn(process.execPath, ['server/index.mjs'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      TOWER_DATA_DIR: dir,
      TOWER_MODE: '',
      TOWER_API_TOKEN: '',
      TOWER_CONTAINER: '',
      ...env,
    },
    stdio: 'ignore',
  })
  const base = `http://127.0.0.1:${port}`
  if (!await waitFor(base)) {
    child.kill()
    throw new Error(`测试服务未启动（PORT=${port}）`)
  }
  return {
    base,
    dir,
    stop: async () => {
      child.kill()
      await new Promise((resolve) => setTimeout(resolve, 150))
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

function apiURL(base: string, key: string, path: string): string {
  return `${base}${path}?key=${encodeURIComponent(key)}`
}

function put(base: string, key: string, body: unknown, headers: Record<string, string> = {}) {
  return fetch(apiURL(base, key, '/api/workspace'), {
    method: 'PUT',
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
    body: JSON.stringify(body),
  })
}

function getWorkspace(base: string, key: string) {
  return fetch(apiURL(base, key, '/api/workspace')).then((response) => response.json()) as Promise<{
    version: number
    data: { marker?: string }
  }>
}

function getHistory(base: string, key: string) {
  return fetch(apiURL(base, key, '/api/workspace/history')).then((response) => response.json()) as Promise<{
    current: { version: number; counts: Record<string, number> }
    entries: Array<{
      id: string
      version: number
      trigger: string
      bytes: number
      source: { ip: string; ua: string }
      counts: Record<string, number>
      diff: Record<string, { before: number; after: number }> | null
      data?: unknown
    }>
    totalBytes: number
    limits: { entries: number; bytes: number }
  }>
}

function restore(base: string, key: string, id: string, version?: number, useHeader = false) {
  const headers: Record<string, string> = { 'content-type': 'application/json; charset=utf-8' }
  if (useHeader && version !== undefined) headers['if-match'] = `"v${version}"`
  return fetch(apiURL(base, key, `/api/workspace/history/${encodeURIComponent(id)}/restore`), {
    method: 'POST',
    headers,
    body: JSON.stringify(version === undefined ? {} : { version }),
  })
}

function buildData(marker: string, ruleCount: number, nodeCount: number, sourceCount = 2) {
  const scheme = {
    id: 'scheme-0',
    name: '自检方案',
    groups: [
      { name: '节点选择', type: 'select' },
      { name: '自动测速', type: 'url-test' },
    ],
    rules: Array.from({ length: ruleCount }, (_, index) => ({
      type: 'DOMAIN-SUFFIX',
      value: `rule-${index}.example.com`,
      group: '节点选择',
    })),
  }
  return {
    marker,
    selectedSchemeID: 'scheme-0',
    sources: Array.from({ length: sourceCount }, (_, index) => ({
      id: `source-${index}`,
      name: `订阅 ${index}`,
      url: `https://example.com/sub-${index}`,
    })),
    nodes: Array.from({ length: nodeCount }, (_, index) => ({
      id: `node-${index}`,
      name: `节点 ${index}`,
      kind: 'ss',
    })),
    customSchemes: [scheme],
  }
}

let failures = 0
async function check(label: string, run: () => Promise<void>): Promise<void> {
  try {
    await run()
    console.log(`✓ ${label}`)
  } catch (error) {
    failures += 1
    console.error(`✗ ${label}`)
    console.error(`  ${error instanceof Error ? error.message : String(error)}`)
  }
}

async function main(): Promise<void> {
  const server = await startServer({ TOWER_MODE: 'server', TOWER_API_TOKEN: 'history-key' })
  try {
    await check('历史接口同样需要访问密钥', async () => {
      const response = await fetch(`${server.base}/api/workspace/history`)
      assert.equal(response.status, 401)
      const body = await response.json() as { code?: string }
      assert.equal(body.code, 'auth_required')
    })

    await check('首次创建不产生历史（没有旧版可归档）', async () => {
      const created = await put(server.base, 'history-key', { version: 0, data: buildData('A', 5, 3) })
      assert.equal(created.status, 200)
      const history = await getHistory(server.base, 'history-key')
      assert.equal(history.current.version, 1)
      assert.equal(history.entries.length, 0)
    })

    let firstID = ''
    await check('覆盖写前归档旧版并带来源与差异摘要', async () => {
      const response = await put(
        server.base,
        'history-key',
        { version: 1, data: buildData('B', 2, 1) },
        { 'user-agent': 'tower-history-selfcheck' },
      )
      assert.equal(response.status, 200)
      const history = await getHistory(server.base, 'history-key')
      assert.equal(history.current.version, 2)
      assert.equal(history.entries.length, 1)
      const entry = history.entries[0]
      firstID = entry.id
      assert.match(entry.id, /^v1-\d{8}T\d{9}Z$/)
      assert.equal(entry.version, 1)
      assert.ok(entry.bytes > 0)
      assert.equal(entry.source.ip, '127.0.0.1')
      assert.ok(entry.source.ua.includes('tower-history-selfcheck'))
      assert.equal(entry.counts.rules, 5)
      assert.equal(entry.counts.nodes, 3)
      assert.equal(entry.counts.subscriptions, 2)
      assert.equal(entry.counts.schemes, 4)
      assert.equal(entry.counts.groups, 2)
      assert.equal(entry.diff?.rules.before, 5)
      assert.equal(entry.diff?.rules.after, 2)
      assert.equal(entry.diff?.nodes.before, 3)
      assert.equal(entry.diff?.nodes.after, 1)
      // 列表只给元数据，不带正文。
      assert.equal('data' in entry, false)
    })

    await check('单版接口返回归档正文', async () => {
      const response = await fetch(apiURL(server.base, 'history-key', `/api/workspace/history/${firstID}`))
      assert.equal(response.status, 200)
      const body = await response.json() as { version: number; data: { marker?: string } }
      assert.equal(body.version, 1)
      assert.equal(body.data.marker, 'A')
    })

    await check('非法历史 id 返回 404', async () => {
      const response = await fetch(apiURL(server.base, 'history-key', '/api/workspace/history/not-a-version'))
      assert.equal(response.status, 404)
      const body = await response.json() as { code?: string }
      assert.equal(body.code, 'history_not_found')
    })

    await check('回滚必须带版本号，过期版本返回 409', async () => {
      const missing = await restore(server.base, 'history-key', firstID)
      assert.equal(missing.status, 400)
      assert.equal(((await missing.json()) as { code?: string }).code, 'missing_version')
      const stale = await restore(server.base, 'history-key', firstID, 1)
      assert.equal(stale.status, 409)
      const current = await getWorkspace(server.base, 'history-key')
      assert.equal(current.version, 2)
      assert.equal(current.data.marker, 'B')
    })

    await check('回滚以旧版为基础生成新版本号（不退版本）', async () => {
      const response = await restore(server.base, 'history-key', firstID, 2, true)
      assert.equal(response.status, 200)
      const result = await response.json() as {
        version: number
        restoredFrom: { id: string; version: number }
        previous: { id: string; version: number } | null
      }
      assert.equal(result.version, 3)
      assert.equal(result.restoredFrom.id, firstID)
      assert.equal(result.restoredFrom.version, 1)
      // 回滚前当前版 v2 应已归档，供撤销使用。
      assert.ok(result.previous)
      assert.equal(result.previous?.version, 2)
      const current = await getWorkspace(server.base, 'history-key')
      assert.equal(current.version, 3)
      assert.equal(current.data.marker, 'A')
      const history = await getHistory(server.base, 'history-key')
      assert.equal(history.entries.length, 2)
      const preRestore = history.entries.find((entry) => entry.version === 2)
      assert.ok(preRestore)
      assert.equal(preRestore?.trigger, 'restore')
      assert.equal(preRestore?.counts.rules, 2)
      assert.equal(preRestore?.diff?.rules.after, 5)
    })

    await check('回滚的回滚可用：再回滚到 v2 恢复旧内容', async () => {
      const history = await getHistory(server.base, 'history-key')
      const target = history.entries.find((entry) => entry.version === 2)!
      const response = await restore(server.base, 'history-key', target.id, 3)
      assert.equal(response.status, 200)
      assert.equal(((await response.json()) as { version: number }).version, 4)
      const current = await getWorkspace(server.base, 'history-key')
      assert.equal(current.version, 4)
      assert.equal(current.data.marker, 'B')
      const after = await getHistory(server.base, 'history-key')
      const restoredVersion = after.entries.find((entry) => entry.version === 3)
      assert.ok(restoredVersion)
      assert.equal(restoredVersion?.trigger, 'restore')
    })

    await check('并发回滚同一版本只有一个成功，另一个 409', async () => {
      const history = await getHistory(server.base, 'history-key')
      const first = history.entries.find((entry) => entry.version === 1)!
      const second = history.entries.find((entry) => entry.version === 2)!
      const responses = await Promise.all([
        restore(server.base, 'history-key', first.id, 4),
        restore(server.base, 'history-key', second.id, 4),
      ])
      const statuses = responses.map((response) => response.status).sort()
      assert.deepEqual(statuses, [200, 409], `实际状态：${statuses}`)
      const current = await getWorkspace(server.base, 'history-key')
      assert.equal(current.version, 5)
    })

    await check('损坏的历史文件不影响正常写入', async () => {
      const corruptID = 'v999-20260101T000000000Z'
      writeFileSync(join(server.dir, 'history', `${corruptID}.json`), '{ not json', 'utf8')
      const before = await getWorkspace(server.base, 'history-key')
      const response = await put(server.base, 'history-key', { version: before.version, data: buildData('C', 4, 2) })
      assert.equal(response.status, 200)
      const current = await getWorkspace(server.base, 'history-key')
      assert.equal(current.version, before.version + 1)
      assert.equal(current.data.marker, 'C')
      const list = await fetch(apiURL(server.base, 'history-key', '/api/workspace/history'))
      assert.equal(list.status, 200)
      const broken = await fetch(apiURL(server.base, 'history-key', `/api/workspace/history/${corruptID}`))
      assert.equal(broken.status, 422)
      assert.equal(((await broken.json()) as { code?: string }).code, 'history_corrupt')
    })
  } finally {
    await server.stop()
  }

  // 最近 10 版：连续覆盖后只保留 10 条，且当前版的前一版一定在。
  const retention = await startServer({ TOWER_MODE: 'server', TOWER_API_TOKEN: 'retention-key' })
  try {
    await check('连续写入后只保留最近 10 版并保留当前版前一版', async () => {
      const first = await put(retention.base, 'retention-key', { version: 0, data: buildData('v1', 5, 3) })
      assert.equal(first.status, 200)
      let version = 1
      for (let index = 2; index <= 14; index += 1) {
        const response = await put(retention.base, 'retention-key', {
          version,
          data: buildData(`v${index}`, 5 - (index % 3), 3),
        })
        assert.equal(response.status, 200)
        version += 1
      }
      const current = await getWorkspace(retention.base, 'retention-key')
      assert.equal(current.version, 14)
      const history = await getHistory(retention.base, 'retention-key')
      assert.equal(history.entries.length, 10)
      const versions = history.entries.map((entry) => entry.version)
      assert.deepEqual(versions, [13, 12, 11, 10, 9, 8, 7, 6, 5, 4])
      assert.ok(versions.includes(13), '当前版前一版必须保留')
      const files = readdirSync(join(retention.dir, 'history')).filter((name) => name.endsWith('.json') && !name.endsWith('.meta.json'))
      assert.equal(files.length, 10)
    })
  } finally {
    await retention.stop()
  }

  // 体积上限：预置 7 个 8MB 历史（56MB），写入后必须压到 50MB 以内，
  // 且当前版前一版（刚归档的 v10）不能被删。
  const budget = await startServer(
    { TOWER_MODE: 'server', TOWER_API_TOKEN: 'budget-key' },
    (dir) => {
      writeFileSync(
        join(dir, 'workspace.json'),
        JSON.stringify({ version: 10, updatedAt: 1, data: buildData('budget', 3, 2) }),
        'utf8',
      )
      const historyDir = join(dir, 'history')
      // 目录在服务器启动时创建；这里先建好再写入大文件。
      mkdirSync(historyDir, { recursive: true })
      const blob = 'x'.repeat(8 * 1024 * 1024)
      for (let version = 1; version <= 7; version += 1) {
        const id = `v${version}-20260101T000000000Z`
        const body = JSON.stringify({ version, updatedAt: 1, data: { blob } })
        writeFileSync(join(historyDir, `${id}.json`), body, 'utf8')
        writeFileSync(join(historyDir, `${id}.meta.json`), JSON.stringify({
          id,
          version,
          updatedAt: 1,
          archivedAt: version,
          bytes: Buffer.byteLength(body),
          trigger: 'write',
          source: { ip: '', ua: '' },
          counts: { subscriptions: 0, nodes: 0, rules: 0, schemes: 0, groups: 0 },
          diff: null,
        }), 'utf8')
      }
    },
  )
  try {
    await check('总占用超过 50MB 时从最旧删起，保留当前版前一版', async () => {
      const response = await put(budget.base, 'budget-key', { version: 10, data: buildData('after', 3, 2) })
      assert.equal(response.status, 200)
      const history = await getHistory(budget.base, 'budget-key')
      assert.ok(history.totalBytes <= MAX_HISTORY_BYTES, `总占用 ${history.totalBytes}`)
      const versions = history.entries.map((entry) => entry.version)
      assert.ok(versions.includes(10), '当前版前一版必须保留')
      assert.ok(!versions.includes(1), '最旧的版本应被删除')
      assert.ok(history.entries.length <= 10)
      const files = readdirSync(join(budget.dir, 'history'))
        .filter((name) => name.endsWith('.json') && !name.endsWith('.meta.json'))
      assert.ok(!files.some((name) => name.startsWith('v1-')), 'v1 正文应已删除')
    })
  } finally {
    await budget.stop()
  }

  // 本地模式：历史接口与工作区接口行为一致（404 workspace_disabled）。
  const local = await startServer({ TOWER_API_TOKEN: '' })
  try {
    await check('local 模式历史接口返回 workspace_disabled', async () => {
      const list = await fetch(`${local.base}/api/workspace/history`)
      assert.equal(list.status, 404)
      assert.equal(((await list.json()) as { code?: string }).code, 'workspace_disabled')
      const one = await fetch(`${local.base}/api/workspace/history/v1-20260101T000000000Z`)
      assert.equal(one.status, 404)
      assert.equal(((await one.json()) as { code?: string }).code, 'workspace_disabled')
    })
  } finally {
    await local.stop()
  }

  console.log(failures === 0 ? '\n全部工作区历史自检通过' : `\n${failures} 项工作区历史自检失败`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
