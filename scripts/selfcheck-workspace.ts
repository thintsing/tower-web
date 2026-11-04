// 服务器版工作区接口自检：版本递增、304、409、首次创建、密钥放宽、
// 回环地址也必须带密钥、坏文件保留现场、16MB 上限、并发写与失败节流。
// 用法：npm run selfcheck:workspace
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

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

async function startServer(
  env: Record<string, string>,
  setup?: (dir: string) => void,
): Promise<TestServer> {
  const dir = mkdtempSync(join(tmpdir(), 'tower-workspace-'))
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

function workspaceURL(base: string, key?: string, path = '/api/workspace'): string {
  return key ? `${base}${path}?key=${encodeURIComponent(key)}` : `${base}${path}`
}

function put(base: string, key: string, body: unknown, headers: Record<string, string> = {}) {
  return fetch(workspaceURL(base, key), {
    method: 'PUT',
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
    body: JSON.stringify(body),
  })
}

function readWorkspaceFile(dir: string): { version: number; updatedAt: number; data: Record<string, unknown> } {
  const raw = JSON.parse(readFileSync(join(dir, 'workspace.json'), 'utf8'))
  return raw as { version: number; updatedAt: number; data: Record<string, unknown> }
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
  const server = await startServer({ TOWER_MODE: 'server', TOWER_API_TOKEN: 'a' })

  try {
    await check('auth-status 报告 server 模式', async () => {
      const status = await (await fetch(`${server.base}/api/auth-status`)).json() as {
        mode?: string
        valid?: boolean
        requiresAuth?: boolean
      }
      assert.equal(status.mode, 'server')
      assert.equal(status.requiresAuth, true)
      // 服务器模式没有本机豁免：127.0.0.1 不带密钥也不算 valid。
      assert.equal(status.valid, false)
    })

    await check('回环地址不带密钥也不能读写工作区', async () => {
      const get = await fetch(workspaceURL(server.base))
      assert.equal(get.status, 401)
      assert.equal(((await get.json()) as { code?: string }).code, 'auth_required')
      const version = await fetch(workspaceURL(server.base, undefined, '/api/workspace/version'))
      assert.equal(version.status, 401)
      const write = await put(server.base, '', { version: 0, data: {} })
      assert.equal(write.status, 401)
    })

    await check('四种密钥来源都可用（query / header / Bearer / cookie）', async () => {
      const query = await fetch(workspaceURL(server.base, 'a'))
      assert.equal(query.status, 200)
      const header = await fetch(workspaceURL(server.base), { headers: { 'x-tower-key': 'a' } })
      assert.equal(header.status, 200)
      const bearer = await fetch(workspaceURL(server.base), { headers: { authorization: 'Bearer a' } })
      assert.equal(bearer.status, 200)
      const cookie = await fetch(workspaceURL(server.base), { headers: { cookie: 'tower_key=a' } })
      assert.equal(cookie.status, 200)
    })

    await check('空工作区返回 version=0 且 data 为空对象', async () => {
      const response = await fetch(workspaceURL(server.base, 'a'))
      const body = await response.json() as { version: number; updatedAt: number; data: unknown }
      assert.equal(body.version, 0)
      assert.deepEqual(body.data, {})
      assert.ok(response.headers.get('etag'))
    })

    await check('version=0 创建首份工作区并递增版本', async () => {
      const response = await put(server.base, 'a', { version: 0, data: { marker: 'first', sources: [] } })
      assert.equal(response.status, 200)
      assert.equal(((await response.json()) as { version: number }).version, 1)
      const current = await (await fetch(workspaceURL(server.base, 'a'))).json() as {
        version: number
        data: { marker?: string }
      }
      assert.equal(current.version, 1)
      assert.equal(current.data.marker, 'first')
      assert.equal(readWorkspaceFile(server.dir).version, 1)
    })

    await check('GET 支持 If-None-Match 与 ?version= 命中 304', async () => {
      const fresh = await fetch(workspaceURL(server.base, 'a'))
      const etag = fresh.headers.get('etag')!
      const byETag = await fetch(workspaceURL(server.base, 'a'), { headers: { 'if-none-match': etag } })
      assert.equal(byETag.status, 304)
      const byWeak = await fetch(workspaceURL(server.base, 'a'), { headers: { 'if-none-match': `W/${etag}` } })
      assert.equal(byWeak.status, 304)
      const byVersion = await fetch(workspaceURL(server.base, 'a', '/api/workspace') + '&version=1')
      assert.equal(byVersion.status, 304)
      const stale = await fetch(workspaceURL(server.base, 'a', '/api/workspace') + '&version=0')
      assert.equal(stale.status, 200)
      const probe = await (await fetch(workspaceURL(server.base, 'a', '/api/workspace/version'))).json() as { version: number }
      assert.equal(probe.version, 1)
    })

    await check('已有数据时 version=0 被拒绝（409 + 当前版本）', async () => {
      const response = await put(server.base, 'a', { version: 0, data: { marker: 'overwrite' } })
      assert.equal(response.status, 409)
      const body = await response.json() as { code?: string; version?: number }
      assert.equal(body.code, 'version_conflict')
      assert.equal(body.version, 1)
    })

    await check('版本不匹配返回 409，不覆盖数据', async () => {
      const response = await put(server.base, 'a', { version: 7, data: { marker: 'wrong' } })
      assert.equal(response.status, 409)
      const current = await (await fetch(workspaceURL(server.base, 'a'))).json() as { data: { marker?: string } }
      assert.equal(current.data.marker, 'first')
    })

    await check('递增写入并保留上一版 .bak', async () => {
      const response = await put(server.base, 'a', { version: 1, data: { marker: 'second' } })
      assert.equal(response.status, 200)
      assert.equal(((await response.json()) as { version: number }).version, 2)
      const backup = JSON.parse(readFileSync(join(server.dir, 'workspace.json.bak'), 'utf8')) as { version: number }
      assert.equal(backup.version, 1)
      assert.equal(readWorkspaceFile(server.dir).version, 2)
    })

    await check('请求体超过 16MB 返回 413 且工作区不变', async () => {
      const huge = 'x'.repeat(17 * 1024 * 1024)
      const response = await put(server.base, 'a', { version: 2, data: { marker: 'huge', blob: huge } })
      assert.equal(response.status, 413)
      const probe = await (await fetch(workspaceURL(server.base, 'a', '/api/workspace/version'))).json() as { version: number }
      assert.equal(probe.version, 2)
    })

  } finally {
    await server.stop()
  }

  // 并发写单独开一个干净实例，避免上一条故意超限的请求影响连接池。
  const concurrent = await startServer({ TOWER_MODE: 'server', TOWER_API_TOKEN: 'concurrent-key' })
  try {
    await check('50 个并发 PUT 只有一个成功，文件仍可解析', async () => {
      const responses = await Promise.all(
        Array.from({ length: 50 }, (_, index) => put(concurrent.base, 'concurrent-key', {
          version: 0,
          data: { marker: `concurrent-${index}` },
        })),
      )
      const statuses = responses.map((response) => response.status)
      assert.equal(statuses.filter((status) => status === 200).length, 1, `200 数量异常：${statuses}`)
      assert.equal(statuses.filter((status) => status === 409).length, 49)
      const winner = statuses.indexOf(200)
      const file = readWorkspaceFile(concurrent.dir)
      assert.equal(file.version, 1)
      assert.equal(file.data.marker, `concurrent-${winner}`)
      const current = await (await fetch(workspaceURL(concurrent.base, 'concurrent-key'))).json() as {
        version: number
        data: { marker?: string }
      }
      assert.equal(current.version, 1)
      assert.equal(current.data.marker, `concurrent-${winner}`)
    })
  } finally {
    await concurrent.stop()
  }

  // 坏文件：启动时必须改名保留现场，并让接口明确报错而不是当空工作区。
  const corrupt = await startServer(
    { TOWER_MODE: 'server', TOWER_API_TOKEN: 'repair-key' },
    (dir) => writeFileSync(join(dir, 'workspace.json'), '{ not json', 'utf8'),
  )
  try {
    await check('损坏的 workspace.json 改名为 .broken-* 并返回明确错误', async () => {
      const response = await fetch(workspaceURL(corrupt.base, 'repair-key'))
      assert.equal(response.status, 500)
      const body = await response.json() as { code?: string; error?: string }
      assert.equal(body.code, 'workspace_corrupt')
      assert.ok(body.error && body.error.includes('.broken-'))
      const broken = readdirSync(corrupt.dir).filter((name) => name.startsWith('workspace.json.broken-'))
      assert.equal(broken.length, 1)
      assert.ok(!readdirSync(corrupt.dir).includes('workspace.json'))
      const write = await put(corrupt.base, 'repair-key', { version: 0, data: {} })
      assert.equal(write.status, 500)
    })
  } finally {
    await corrupt.stop()
  }

  // 已有合法文件：启动读取成功并写 .bak。
  const existing = await startServer(
    { TOWER_MODE: 'server', TOWER_API_TOKEN: 'existing-key' },
    (dir) => writeFileSync(
      join(dir, 'workspace.json'),
      JSON.stringify({ version: 5, updatedAt: 123, data: { marker: 'persisted' } }),
      'utf8',
    ),
  )
  try {
    await check('启动载入已有工作区并写 .bak', async () => {
      const body = await (await fetch(workspaceURL(existing.base, 'existing-key'))).json() as {
        version: number
        data: { marker?: string }
      }
      assert.equal(body.version, 5)
      assert.equal(body.data.marker, 'persisted')
      const backup = JSON.parse(readFileSync(join(existing.dir, 'workspace.json.bak'), 'utf8')) as { version: number }
      assert.equal(backup.version, 5)
    })
  } finally {
    await existing.stop()
  }

  // 密钥放宽：1 字符可用，首尾空白被 trim；内部空白 / 超长被拒绝。
  const shortKey = await startServer({ TOWER_MODE: 'server', TOWER_API_TOKEN: ' b ' })
  try {
    await check('服务器模式允许 1 字符密钥并 trim 首尾空白', async () => {
      const ok = await fetch(workspaceURL(shortKey.base, 'b'))
      assert.equal(ok.status, 200)
      const padded = await fetch(workspaceURL(shortKey.base, ' b '))
      assert.equal(padded.status, 200)
      const wrong = await fetch(workspaceURL(shortKey.base, 'c'))
      assert.equal(wrong.status, 401)
    })
  } finally {
    await shortKey.stop()
  }

  const blankKey = await startServer({ TOWER_MODE: 'server', TOWER_API_TOKEN: 'a b' })
  try {
    await check('含内部空白的密钥被拒绝（等同于未设置）', async () => {
      const status = await (await fetch(`${blankKey.base}/api/auth-status`)).json() as { requiresAuth?: boolean }
      assert.equal(status.requiresAuth, false)
      const response = await fetch(workspaceURL(blankKey.base, 'a b'))
      assert.equal(response.status, 401)
      assert.equal(((await response.json()) as { code?: string }).code, 'workspace_key_required')
    })
  } finally {
    await blankKey.stop()
  }

  const longKey = await startServer({ TOWER_MODE: 'server', TOWER_API_TOKEN: 'k'.repeat(129) })
  try {
    await check('超过 128 字符的密钥被拒绝', async () => {
      const status = await (await fetch(`${longKey.base}/api/auth-status`)).json() as { requiresAuth?: boolean }
      assert.equal(status.requiresAuth, false)
      const response = await fetch(workspaceURL(longKey.base, 'k'.repeat(129)))
      assert.equal(response.status, 401)
    })
  } finally {
    await longKey.stop()
  }

  // 暴力破解节流：同 IP 连续 10 次失败后冷却，正确密钥也会 429。
  const throttle = await startServer({ TOWER_MODE: 'server', TOWER_API_TOKEN: 'throttle-key-123' })
  try {
    await check('连续 10 次认证失败后冷却 60 秒', async () => {
      for (let index = 0; index < 10; index += 1) {
        const response = await fetch(workspaceURL(throttle.base, 'wrong-key'))
        assert.equal(response.status, 401)
      }
      const blocked = await fetch(workspaceURL(throttle.base, 'throttle-key-123'))
      assert.equal(blocked.status, 429)
      assert.equal(((await blocked.json()) as { code?: string }).code, 'too_many_attempts')
      const retryAfter = Number(blocked.headers.get('retry-after'))
      assert.ok(retryAfter > 0 && retryAfter <= 60)
    })
  } finally {
    await throttle.stop()
  }

  // 本地模式保持原样：工作区接口关闭，短密钥仍按原来的 16 位下限忽略。
  const local = await startServer({ TOWER_API_TOKEN: 'short-key' })
  try {
    await check('local 模式工作区接口不存在，短密钥行为不变', async () => {
      const status = await (await fetch(`${local.base}/api/auth-status`)).json() as {
        mode?: string
        requiresAuth?: boolean
      }
      assert.equal(status.mode, 'local')
      assert.equal(status.requiresAuth, false)
      const response = await fetch(workspaceURL(local.base))
      assert.equal(response.status, 404)
      assert.equal(((await response.json()) as { code?: string }).code, 'workspace_disabled')
    })
  } finally {
    await local.stop()
  }

  console.log(failures === 0 ? '\n全部工作区自检通过' : `\n${failures} 项工作区自检失败`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
