// 服务器模式固定订阅 token、规范地址、重置语义与迁移策略的自检。
// 用法：npx tsx scripts/selfcheck-sub-token.ts
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const PUBLIC_URL = 'http://tower.example.test:8787'

const BODY = JSON.stringify({
  title: 'probe',
  formats: {
    base64: 'eA==',
    yaml: 'proxies: []\nrules:\n  - DOMAIN,example.com,http://127.0.0.1:1/api/ruleset?format=quanx&file=probe.list\n',
  },
})

interface TestServer {
  base: string
  port: number
  dir: string
  stop: (removeDir?: boolean) => Promise<void>
}

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

async function startServer(
  env: Record<string, string>,
  setup?: (dir: string) => void,
  existingDir?: string,
): Promise<TestServer> {
  const dir = existingDir ?? mkdtempSync(join(tmpdir(), 'tower-sub-token-'))
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
      TOWER_PUBLIC_URL: '',
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
    port,
    dir,
    stop: async (removeDir = true) => {
      child.kill()
      await new Promise((resolve) => setTimeout(resolve, 150))
      if (removeDir) rmSync(dir, { recursive: true, force: true })
    },
  }
}

function post(token?: string): Promise<Response> {
  return fetch(`http://127.0.0.1:${CURRENT_PORT}/api/subscribe${token ? `?token=${encodeURIComponent(token)}` : ''}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: BODY,
  })
}

// post 需要当前服务端口；每个 check 执行前设置，避免把 base 传来传去。
let CURRENT_PORT = 0

interface RawResponse {
  status: number
  body: string
}

function rawRequest(port: number, path: string, opts: { method?: string; host?: string; body?: string } = {}): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const payload = opts.body ?? ''
    const headers: Record<string, string | number> = {}
    if (opts.host) headers.host = opts.host
    if (payload) {
      headers['content-type'] = 'application/json; charset=utf-8'
      headers['content-length'] = Buffer.byteLength(payload)
    }
    const req = httpRequest({
      host: '127.0.0.1',
      port,
      path,
      method: opts.method ?? 'GET',
      headers,
    }, (res) => {
      let body = ''
      res.on('data', (chunk) => { body += chunk })
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }))
    })
    req.on('error', reject)
    if (payload) req.write(payload)
    req.end()
  })
}

function readSettings(dir: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(dir, 'settings.json'), 'utf8')) as Record<string, unknown>
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
  {
    // 多带一个尾斜杠，验证服务端会去掉后再作为规范前缀。
    let server = await startServer({ TOWER_MODE: 'server', TOWER_PUBLIC_URL: `${PUBLIC_URL}/` })
    CURRENT_PORT = server.port
    try {
      let canonical = ''

      await check('服务器模式两次无 token 发布返回同一 token 和绝对规范地址', async () => {
        const first = await (await post()).json() as { token: string; url: string; refreshed: boolean; publicUrl: string }
        const second = await (await post()).json() as { token: string; url: string; refreshed: boolean }
        canonical = first.token
        assert.equal(second.token, first.token)
        assert.equal(first.publicUrl, PUBLIC_URL)
        assert.ok(first.url.startsWith(`${PUBLIC_URL}/api/sub/`), first.url)
        assert.equal(first.refreshed, false)
        assert.equal(second.refreshed, true)
      })

      await check('服务器模式忽略客户端传入的任意 token', async () => {
        const response = await (await post('legacy-token-1234567890')).json() as { token: string; url: string }
        assert.equal(response.token, canonical)
        assert.ok(response.url.includes(canonical))
        const legacy = await fetch(`${server.base}/api/sub/legacy-token-1234567890?format=base64`)
        assert.equal(legacy.status, 404)
      })

      await check('不同 Host 的 POST 返回同一绝对地址', async () => {
        const a = await rawRequest(server.port, '/api/subscribe', {
          method: 'POST',
          host: '192.168.1.50:9999',
          body: BODY,
        })
        const b = await rawRequest(server.port, '/api/subscribe', {
          method: 'POST',
          host: 'tunnel.example.com',
          body: BODY,
        })
        assert.equal(a.status, 200)
        assert.equal(b.status, 200)
        const bodyA = JSON.parse(a.body) as { url: string; token: string }
        const bodyB = JSON.parse(b.body) as { url: string; token: string }
        assert.equal(bodyA.url, bodyB.url)
        assert.equal(bodyA.token, bodyB.token)
        assert.ok(bodyA.url.startsWith(PUBLIC_URL))
      })

      await check('订阅正文里的规则集地址不随 Host 变化', async () => {
        const path = `/api/sub/${canonical}?format=yaml&target=clash`
        const a = await rawRequest(server.port, path, { host: '192.168.1.50:9999' })
        const b = await rawRequest(server.port, path, { host: 'tunnel.example.com' })
        assert.equal(a.status, 200)
        assert.equal(b.status, 200)
        assert.equal(a.body, b.body)
        assert.ok(a.body.includes(`${PUBLIC_URL}/api/ruleset`), a.body)
        assert.ok(!a.body.includes('127.0.0.1:1/api/ruleset'))
      })

      await check('重启后 canonical token 不变', async () => {
        await server.stop(false)
        server = await startServer({ TOWER_MODE: 'server', TOWER_PUBLIC_URL: PUBLIC_URL }, undefined, server.dir)
        CURRENT_PORT = server.port
        const response = await (await post()).json() as { token: string; refreshed: boolean }
        assert.equal(response.token, canonical)
        assert.equal(response.refreshed, true)
      })

      let resetToken = ''
      await check('重置 canonical：旧 token 立即 404，新 token 接管内容', async () => {
        const before = canonical
        const response = await fetch(`${server.base}/api/sub/${before}`, { method: 'DELETE' })
        assert.equal(response.status, 200)
        const body = await response.json() as { reset: boolean; token: string; url: string; publicUrl: string }
        assert.equal(body.reset, true)
        assert.ok(body.token && body.token !== before)
        assert.ok(body.url.startsWith(PUBLIC_URL))
        assert.equal(body.publicUrl, PUBLIC_URL)
        resetToken = body.token
        assert.equal((await fetch(`${server.base}/api/sub/${before}?format=base64`)).status, 404)
        assert.equal((await fetch(`${server.base}/api/sub/${resetToken}?format=base64`)).status, 200)
        canonical = resetToken
      })

      await check('重置后重启仍是新 token', async () => {
        await server.stop(false)
        server = await startServer({ TOWER_MODE: 'server', TOWER_PUBLIC_URL: PUBLIC_URL }, undefined, server.dir)
        CURRENT_PORT = server.port
        const response = await (await post()).json() as { token: string }
        assert.equal(response.token, resetToken)
      })
    } finally {
      if (server.port) await server.stop()
    }
  }

  {
    const server = await startServer({ TOWER_MODE: 'server', TOWER_PUBLIC_URL: 'ftp://bad host' })
    CURRENT_PORT = server.port
    try {
      await check('非法 TOWER_PUBLIC_URL 可见报错且回退相对地址', async () => {
        const network = await (await fetch(`${server.base}/api/network`)).json() as {
          publicUrl: string
          publicUrlConfigured: boolean
          publicUrlError: string
        }
        assert.equal(network.publicUrl, '')
        assert.equal(network.publicUrlConfigured, false)
        assert.ok(network.publicUrlError.includes('空白'), network.publicUrlError)
        const published = await (await post()).json() as { url: string; publicUrl: string; publicUrlError: string }
        assert.ok(published.url.startsWith('/api/sub/'))
        assert.equal(published.publicUrl, '')
        assert.ok(published.publicUrlError.length > 0)
      })
    } finally {
      await server.stop()
    }
  }

  {
    const server = await startServer({})
    CURRENT_PORT = server.port
    try {
      await check('本地模式行为不变：无 token 新发、带 token 复用、相对地址', async () => {
        const first = await (await post()).json() as { token: string; url: string; publicUrl?: string; refreshed: boolean }
        const second = await (await post()).json() as { token: string; url: string }
        assert.notEqual(first.token, second.token)
        assert.ok(first.url.startsWith('/api/sub/'))
        assert.equal(first.publicUrl, undefined)
        const reused = await (await post(first.token)).json() as { token: string; refreshed: boolean }
        assert.equal(reused.token, first.token)
        assert.equal(reused.refreshed, true)
        assert.equal((await fetch(`${server.base}/api/sub/${first.token}?format=base64`)).status, 200)
        assert.equal((await fetch(`${server.base}/api/sub/${second.token}?format=base64`)).status, 200)
      })

      await check('本地模式撤销仍是单 token 删除，不重置其它链接', async () => {
        const a = await (await post()).json() as { token: string }
        const b = await (await post()).json() as { token: string }
        const deleted = await (await fetch(`${server.base}/api/sub/${a.token}`, { method: 'DELETE' })).json() as { ok: boolean; reset?: boolean }
        assert.equal(deleted.ok, true)
        assert.equal(deleted.reset, undefined)
        assert.equal((await fetch(`${server.base}/api/sub/${a.token}?format=base64`)).status, 404)
        assert.equal((await fetch(`${server.base}/api/sub/${b.token}?format=base64`)).status, 200)
      })
    } finally {
      await server.stop()
    }
  }

  {
    const newestStrong = 'V_KbxptGcWDu744l2zP9ig'
    const olderStrong = 'AAAAAAAAAAAAAAAAAAAAAA'
    const server = await startServer(
      { TOWER_MODE: 'server', TOWER_PUBLIC_URL: PUBLIC_URL },
      (dir) => {
        writeFileSync(join(dir, 'subscriptions.json'), JSON.stringify({
          weak: { formats: { base64: 'eA==' }, updatedAt: 100, title: 'weak' },
          [olderStrong]: { formats: { base64: 'eA==' }, updatedAt: 200, title: 'older' },
          [newestStrong]: { formats: { base64: 'eA==' }, updatedAt: 300, title: 'newest' },
        }))
      },
    )
    CURRENT_PORT = server.port
    try {
      await check('迁移沿用最近发布的强 token，且不删除旧记录', async () => {
        assert.equal(readSettings(server.dir).subscriptionToken, newestStrong)
        const published = await (await post()).json() as { token: string; refreshed: boolean }
        assert.equal(published.token, newestStrong)
        assert.equal(published.refreshed, true)
        assert.equal((await fetch(`${server.base}/api/sub/${olderStrong}?format=base64`)).status, 200)
        assert.equal((await fetch(`${server.base}/api/sub/weak?format=base64`)).status, 200)
      })

      await check('服务器模式用升级前的旧 token 触发重置，仍作用于 canonical', async () => {
        const response = await fetch(`${server.base}/api/sub/weak`, { method: 'DELETE' })
        assert.equal(response.status, 200)
        const body = await response.json() as { reset: boolean; token: string }
        assert.equal(body.reset, true)
        assert.notEqual(body.token, newestStrong)
        assert.equal((await fetch(`${server.base}/api/sub/${newestStrong}?format=base64`)).status, 404)
        assert.equal((await fetch(`${server.base}/api/sub/${body.token}?format=base64`)).status, 200)
        // 旧记录本身不删，避免仍在用旧链接的客户端立刻断掉。
        assert.equal((await fetch(`${server.base}/api/sub/weak?format=base64`)).status, 200)
      })
    } finally {
      await server.stop()
    }
  }

  if (failures > 0) {
    console.error(`\n${failures} 项失败`)
    process.exit(1)
  }
  console.log('\n全部通过')
}

void main()
