// 服务端上游更新检查自检：
// 结果文件读写与损坏容错、已固化/未固化两条比对路径、失败后 6 小时退避、
// 关闭开关不发请求、检查结果不写工作区（版本号不变）。
// 用法：npm run selfcheck:upstream-status
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  BUILTIN_UPSTREAM_SCHEMES,
  createUpstreamChecker,
  FAILURE_BACKOFF_MS,
  readUpstreamStatusFile,
  UPSTREAM_STATUS_FILE,
  writeUpstreamStatusFile,
} from '../server/upstream-status.mjs'
import { ACL4SSR_API_BASE, ACL4SSR_PIN_COMMIT } from '../server/upstream-check.mjs'
import { BUILTIN_SCHEMES } from '../src/rules/scheme'
import { runBuiltinUpdateCheckOnOpen } from '../src/rules/upstreamOnOpen'

const ROOT = fileURLToPath(new URL('..', import.meta.url))

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

async function startServer(env: Record<string, string>): Promise<TestServer> {
  const dir = mkdtempSync(join(tmpdir(), 'tower-upstream-status-'))
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
      TOWER_UPSTREAM_CHECK: '',
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

const NOW = 1_000_000_000

function treeBody(commit: string, blobs: Record<string, string> = {}): string {
  return JSON.stringify({
    sha: commit,
    truncated: false,
    tree: Object.entries(blobs).map(([path, sha]) => ({ path, sha, type: 'blob' })),
  })
}

interface FakeUpstream {
  fetchText: (url: string) => Promise<{ text: string; etag?: string }>
  fetchHeaders: (url: string) => Promise<{ etag?: string }>
  calls: string[]
}

/** 按 URL 返回可控的上游响应；真实 GitHub 不会被访问。 */
function fakeUpstream(options: {
  commit: string
  blobs?: Record<string, string>
  aheadBy?: number | null
  treeError?: string
  headError?: string
}): FakeUpstream {
  const calls: string[] = []
  return {
    calls,
    async fetchText(url: string) {
      calls.push(url)
      if (url.includes('/git/trees/')) {
        if (options.treeError) throw new Error(options.treeError)
        return { text: treeBody(options.commit, options.blobs) }
      }
      if (url.includes('/compare/')) {
        return { text: JSON.stringify({ ahead_by: options.aheadBy ?? null }) }
      }
      throw new Error(`未预期的请求：${url}`)
    },
    async fetchHeaders(url: string) {
      calls.push(`HEAD ${url}`)
      if (options.headError) throw new Error(options.headError)
      return { etag: '"fresh"' }
    },
  }
}

const SNAPSHOT_COMMIT = 'a'.repeat(40)
const NEXT_COMMIT = 'b'.repeat(40)
const RULESET_PATH = 'Clash/Ruleset/ACL4SSR/ACL4SSR_Online.list'

function workspaceWithSnapshot(fileBlob = 'c'.repeat(40), etag = '"old"') {
  return {
    builtinSchemeOverrides: { 'acl4ssr-online': { snapshotId: 7 } },
    schemeSnapshots: {
      7: {
        id: 7,
        source: {
          commitSha: SNAPSHOT_COMMIT,
          files: [{ path: RULESET_PATH, blobSha: fileBlob, etag }],
        },
      },
    },
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
  const dir = mkdtempSync(join(tmpdir(), 'tower-upstream-status-unit-'))

  await check('内置方案清单：服务端检查列表与前端 BUILTIN_SCHEMES 完全一致', async () => {
    const frontend = new Map(BUILTIN_SCHEMES.map((meta) => [meta.id, meta]))
    assert.equal(BUILTIN_UPSTREAM_SCHEMES.length, BUILTIN_SCHEMES.length)
    for (const meta of BUILTIN_UPSTREAM_SCHEMES) {
      const local = frontend.get(meta.id)
      assert.ok(local, `服务端多出/写错了方案 id：${meta.id}`)
      assert.equal(local.name, meta.name, `方案 ${meta.id} 名称不一致`)
      assert.equal(local.file, meta.file, `方案 ${meta.id} 的 INI 文件不一致`)
      assert.ok(
        existsSync(join(ROOT, 'public', 'rulesets', meta.file)),
        `方案 ${meta.id} 的 INI 文件不存在：${meta.file}`,
      )
    }
  })

  await check('结果文件读写：原子落盘并保留元数据', async () => {
    const status = {
      checkedAt: NOW,
      nextCheckAt: NOW + 1000,
      trigger: 'manual',
      lastError: '',
      results: {
        'acl4ssr-online': {
          id: 'acl4ssr-online',
          name: 'ACL4SSR 在线版',
          status: 'update',
          frozen: false,
          baseline: { kind: 'pin', commitShort: ACL4SSR_PIN_COMMIT.slice(0, 7) },
          commit: NEXT_COMMIT,
          commitShort: NEXT_COMMIT.slice(0, 7),
          behindBy: 3,
          method: 'trees',
          changedFiles: [RULESET_PATH],
          error: '',
          checkedAt: NOW,
        },
      },
    }
    assert.equal(writeUpstreamStatusFile(dir, status), true)
    const loaded = readUpstreamStatusFile(dir)
    assert.equal(loaded.corrupt, false)
    assert.equal(loaded.status?.checkedAt, NOW)
    assert.equal(loaded.status?.results['acl4ssr-online'].status, 'update')
    assert.equal(loaded.status?.results['acl4ssr-online'].behindBy, 3)
  })

  await check('结果文件损坏：读取标记 corrupt，服务仍可启动', async () => {
    writeFileSync(join(dir, UPSTREAM_STATUS_FILE), '{ not json', 'utf8')
    const corrupt = readUpstreamStatusFile(dir)
    assert.equal(corrupt.corrupt, true)
    assert.equal(corrupt.status, null)
    const upstream = fakeUpstream({ commit: ACL4SSR_PIN_COMMIT })
    const checker = createUpstreamChecker({
      dataDir: dir,
      getWorkspaceData: () => ({}),
      fetchText: upstream.fetchText,
      fetchHeaders: upstream.fetchHeaders,
      env: {},
      logger: { warn() {}, log() {} },
      now: () => NOW,
      setTimer: () => ({ unref() {} }),
      clearTimer: () => {},
    })
    checker.start()
    const payload = checker.getPayload()
    assert.equal(payload.enabled, true)
    assert.equal(payload.schemes.length, 3)
    assert.equal(payload.schemes[0].status, 'unknown')
    assert.equal(upstream.calls.length, 0)
  })

  await check('已固化方案：与快照 commit/blob 比对，无变化判 current', async () => {
    const upstream = fakeUpstream({
      commit: SNAPSHOT_COMMIT,
      blobs: { [RULESET_PATH]: 'c'.repeat(40) },
    })
    const checker = createUpstreamChecker({
      dataDir: dir,
      getWorkspaceData: () => workspaceWithSnapshot(),
      fetchText: upstream.fetchText,
      fetchHeaders: upstream.fetchHeaders,
      env: {},
      logger: { warn() {}, log() {} },
      now: () => NOW,
      setTimer: () => ({ unref() {} }),
      clearTimer: () => {},
    })
    const result = await checker.runNow('manual')
    const online = (result as { status: { results: Record<string, { status: string; frozen: boolean; baseline: { kind: string } }> } })
      .status.results['acl4ssr-online']
    assert.equal(online.status, 'current')
    assert.equal(online.frozen, true)
    assert.equal(online.baseline.kind, 'snapshot')
  })

  await check('已固化方案：blob 变化判 update 并列出文件', async () => {
    const upstream = fakeUpstream({
      commit: NEXT_COMMIT,
      blobs: { [RULESET_PATH]: 'd'.repeat(40) },
    })
    const checker = createUpstreamChecker({
      dataDir: dir,
      getWorkspaceData: () => workspaceWithSnapshot(),
      fetchText: upstream.fetchText,
      fetchHeaders: upstream.fetchHeaders,
      env: {},
      logger: { warn() {}, log() {} },
      now: () => NOW,
      setTimer: () => ({ unref() {} }),
      clearTimer: () => {},
    })
    const result = await checker.runNow('manual')
    const status = result as { status: { results: Record<string, { status: string; changedFiles: string[]; commitShort: string }> } }
    const online = status.status.results['acl4ssr-online']
    assert.equal(online.status, 'update')
    assert.deepEqual(online.changedFiles, [RULESET_PATH])
    assert.equal(online.commitShort, NEXT_COMMIT.slice(0, 7))
  })

  await check('从未固化：与 pin commit 比对并显示落后提交数', async () => {
    const upstream = fakeUpstream({ commit: NEXT_COMMIT, aheadBy: 12 })
    const checker = createUpstreamChecker({
      dataDir: dir,
      getWorkspaceData: () => ({}),
      fetchText: upstream.fetchText,
      fetchHeaders: upstream.fetchHeaders,
      env: {},
      logger: { warn() {}, log() {} },
      now: () => NOW,
      setTimer: () => ({ unref() {} }),
      clearTimer: () => {},
    })
    const result = await checker.runNow('manual')
    const status = result as {
      status: { results: Record<string, { status: string; frozen: boolean; behindBy: number; baseline: { kind: string; commitShort: string } }> }
    }
    const online = status.status.results['acl4ssr-online']
    assert.equal(online.status, 'update')
    assert.equal(online.frozen, false)
    assert.equal(online.baseline.kind, 'pin')
    assert.equal(online.baseline.commitShort, ACL4SSR_PIN_COMMIT.slice(0, 7))
    assert.equal(online.behindBy, 12)
    assert.ok(upstream.calls.some((url) => url.includes(`${ACL4SSR_API_BASE}/compare/`)))
  })

  await check('从未固化且 pin 就是最新：判 current，不出现落后提交数', async () => {
    const upstream = fakeUpstream({ commit: ACL4SSR_PIN_COMMIT })
    const checker = createUpstreamChecker({
      dataDir: dir,
      getWorkspaceData: () => ({}),
      fetchText: upstream.fetchText,
      fetchHeaders: upstream.fetchHeaders,
      env: {},
      logger: { warn() {}, log() {} },
      now: () => NOW,
      setTimer: () => ({ unref() {} }),
      clearTimer: () => {},
    })
    const result = await checker.runNow('manual')
    const status = result as { status: { results: Record<string, { status: string; behindBy: number | null }> } }
    const online = status.status.results['acl4ssr-online']
    assert.equal(online.status, 'current')
    assert.equal(online.behindBy, null)
  })

  await check('检查失败：状态为 error 且至少 6 小时后才重试', async () => {
    const upstream = fakeUpstream({ commit: NEXT_COMMIT, treeError: 'HTTP 403 rate limit' })
    const checker = createUpstreamChecker({
      dataDir: dir,
      getWorkspaceData: () => ({}),
      fetchText: upstream.fetchText,
      fetchHeaders: upstream.fetchHeaders,
      env: {},
      logger: { warn() {}, log() {} },
      now: () => NOW,
      setTimer: () => ({ unref() {} }),
      clearTimer: () => {},
    })
    const result = await checker.runNow('timer')
    const status = result as { status: { results: Record<string, { status: string; error: string }>; nextCheckAt: number; checkedAt: number } }
    const online = status.status.results['acl4ssr-online']
    assert.equal(online.status, 'error')
    assert.match(online.error, /403|ETag/)
    assert.ok(status.status.nextCheckAt >= status.status.checkedAt + FAILURE_BACKOFF_MS)
    const payload = checker.getPayload()
    assert.equal(payload.checking, false)
    assert.match(payload.lastError, /查不到|失败/)
  })

  await check('关闭开关：不发任何上游请求，手动检查也拒绝', async () => {
    const upstream = fakeUpstream({ commit: NEXT_COMMIT })
    const checker = createUpstreamChecker({
      dataDir: dir,
      getWorkspaceData: () => ({}),
      fetchText: upstream.fetchText,
      fetchHeaders: upstream.fetchHeaders,
      env: { TOWER_UPSTREAM_CHECK: 'off' },
      logger: { warn() {}, log() {} },
      now: () => NOW,
      setTimer: () => ({ unref() {} }),
      clearTimer: () => {},
    })
    checker.start()
    const result = await checker.runNow('manual')
    assert.equal((result as { disabled: boolean }).disabled, true)
    assert.equal(upstream.calls.length, 0)
    const payload = checker.getPayload()
    assert.equal(payload.enabled, false)
    assert.equal(checker.checkNow().disabled, true)
  })

  await check('重启不立刻检查：首次调度至少等 initialDelay', async () => {
    const upstream = fakeUpstream({ commit: NEXT_COMMIT })
    let scheduled: number | null = null
    // 用全新目录，避免前一条失败退避写入的 nextCheckAt 影响首次调度。
    const freshDir = mkdtempSync(join(tmpdir(), 'tower-upstream-status-initial-'))
    const checker = createUpstreamChecker({
      dataDir: freshDir,
      getWorkspaceData: () => ({}),
      fetchText: upstream.fetchText,
      fetchHeaders: upstream.fetchHeaders,
      env: { TOWER_UPSTREAM_CHECK_INITIAL_DELAY_MS: '900000' },
      logger: { warn() {}, log() {} },
      now: () => NOW,
      setTimer: (_fn: () => void, ms: number) => {
        scheduled = ms
        return { unref() {} }
      },
      clearTimer: () => {},
    })
    checker.start()
    assert.equal(scheduled, 900000)
    assert.equal(upstream.calls.length, 0)
    checker.stop()
    rmSync(freshDir, { recursive: true, force: true })
  })

  await check('结果不写工作区：内存工作区与 workspace.json 都不变', async () => {
    const workspace = workspaceWithSnapshot()
    const before = JSON.stringify(workspace)
    const upstream = fakeUpstream({
      commit: NEXT_COMMIT,
      blobs: { [RULESET_PATH]: 'd'.repeat(40) },
      aheadBy: 2,
    })
    const checker = createUpstreamChecker({
      dataDir: dir,
      getWorkspaceData: () => workspace,
      fetchText: upstream.fetchText,
      fetchHeaders: upstream.fetchHeaders,
      env: {},
      logger: { warn() {}, log() {} },
      now: () => NOW,
      setTimer: () => ({ unref() {} }),
      clearTimer: () => {},
    })
    await checker.runNow('manual')
    assert.equal(JSON.stringify(workspace), before)
    assert.equal(existsSync(join(dir, 'workspace.json')), false)
    assert.equal(existsSync(join(dir, UPSTREAM_STATUS_FILE)), true)
  })

  await check('服务端开关：TOWER_UPSTREAM_CHECK=off 时状态接口可用、手动检查 409', async () => {
    const server = await startServer({
      TOWER_MODE: 'server',
      TOWER_API_TOKEN: 'selfcheck-key',
      TOWER_UPSTREAM_CHECK: 'off',
    })
    try {
      const base = server.base
      const key = 'selfcheck-key'
      const statusRes = await fetch(`${base}/api/upstream-status?key=${key}`)
      assert.equal(statusRes.status, 200)
      const status = await statusRes.json() as { enabled: boolean; schemes: unknown[]; checking: boolean }
      assert.equal(status.enabled, false)
      assert.equal(status.schemes.length, 3)
      assert.equal(status.checking, false)
      const checkRes = await fetch(`${base}/api/upstream-status/check?key=${key}`, { method: 'POST' })
      assert.equal(checkRes.status, 409)
      const body = await checkRes.json() as { code: string }
      assert.equal(body.code, 'upstream_check_disabled')
    } finally {
      await server.stop()
    }
  })

  await check('HTTP 链路：检查前后工作区版本号不变', async () => {
    const server = await startServer({
      TOWER_MODE: 'server',
      TOWER_API_TOKEN: 'selfcheck-key',
      TOWER_UPSTREAM_CHECK: 'off',
    })
    try {
      const base = server.base
      const key = 'selfcheck-key'
      const put = await fetch(`${base}/api/workspace?key=${key}`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify({ version: 0, data: { sources: [], marker: 'no-change' } }),
      })
      assert.equal(put.status, 200)
      const before = await fetch(`${base}/api/workspace/version?key=${key}`).then((r) => r.json()) as { version: number }
      await fetch(`${base}/api/upstream-status/check?key=${key}`, { method: 'POST' })
      const after = await fetch(`${base}/api/workspace/version?key=${key}`).then((r) => r.json()) as { version: number }
      assert.equal(before.version, after.version)
    } finally {
      await server.stop()
    }
  })

  await check('非服务器模式：返回 workspace_disabled', async () => {
    const server = await startServer({ TOWER_MODE: '' })
    try {
      const res = await fetch(`${server.base}/api/upstream-status`)
      assert.equal(res.status, 404)
      const body = await res.json() as { code: string }
      assert.equal(body.code, 'workspace_disabled')
    } finally {
      await server.stop()
    }
  })

  await check('打开时检查：服务器模式不发请求，本地模式行为不变', async () => {
    const calls: string[] = []
    const selected = BUILTIN_SCHEMES[0]
    const overridden = BUILTIN_SCHEMES[1]
    const input = {
      enabled: true,
      selectedSchemeID: selected.id,
      schemes: BUILTIN_SCHEMES,
      overrides: { [overridden.id]: { snapshotId: 7 } },
      snapshots: {
        7: { id: 7, schemeID: overridden.id, createdAt: NOW, scheme: {} as never, ruleSets: [], source: {} as never },
      },
    }
    const deps = {
      check: async () => {
        calls.push('check')
        return { checked: true, updateAvailable: false, method: 'trees' as const, changedFiles: [] }
      },
      notify: () => {},
    }

    // 服务器版交给服务端定时任务：模式未确定 / server 都不调用检查。
    assert.equal(await runBuiltinUpdateCheckOnOpen({ ...input, mode: 'unknown' }, deps), 0)
    assert.equal(await runBuiltinUpdateCheckOnOpen({ ...input, mode: 'server' }, deps), 0)
    assert.deepEqual(calls, [])

    // 本地模式：选中的方案 + 已固化过的方案各检查一次。
    assert.equal(await runBuiltinUpdateCheckOnOpen({ ...input, mode: 'local' }, deps), 2)
    assert.equal(calls.length, 2)

    // 本地模式但用户关掉设置：同样不发请求。
    calls.length = 0
    assert.equal(await runBuiltinUpdateCheckOnOpen({ ...input, mode: 'local', enabled: false }, deps), 0)
    assert.deepEqual(calls, [])
  })

  rmSync(dir, { recursive: true, force: true })
  if (failures) {
    console.error(`\n${failures} 项上游检查自检失败`)
    process.exit(1)
  }
  console.log('\n上游更新检查自检全部通过')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
