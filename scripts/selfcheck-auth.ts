// 自检：局域网共享开关 / API 访问密钥 / 密钥 cookie / 规则集豁免。
// 用 127.0.0.2 或本机网卡地址模拟「非本机」请求；环境不支持时跳过网络部分。
// 用法：npm run selfcheck:auth
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { networkInterfaces, tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const PORT = 20000 + Math.floor(Math.random() * 20000)
const LOCAL = `http://127.0.0.1:${PORT}`
// Windows 会把 127.0.0.2 的来源归一成 127.0.0.1，不能用回环别名模拟局域网；
// 改用本机真实网卡地址，并要求服务端确认来源不是本机。
const LAN_CANDIDATES = lanURLs()

function lanURLs(): string[] {
  const urls: string[] = []
  for (const addresses of Object.values(networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (address.family === 'IPv4' && !address.internal) {
        urls.push(`http://${address.address}:${PORT}`)
      }
    }
  }
  return urls
}

async function waitFor(url: string, timeoutMs = 8000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${url}/api/health`, { signal: AbortSignal.timeout(500) })
      if (response.ok) return true
    } catch {
      // server still starting
    }
    await new Promise((resolve) => setTimeout(resolve, 120))
  }
  return false
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
  const dataDir = mkdtempSync(join(tmpdir(), 'tower-auth-'))
  const child = spawn(process.execPath, ['server/index.mjs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: {
      ...process.env,
      PORT: String(PORT),
      HOST: '0.0.0.0',
      TOWER_DATA_DIR: dataDir,
      TOWER_CONTAINER: '',
    },
    stdio: 'ignore',
  })

  try {
    if (!await waitFor(LOCAL)) throw new Error('测试服务未启动')

    let lanBase = ''
    for (const candidate of LAN_CANDIDATES) {
      if (!await waitFor(candidate, 700)) continue
      const status = await fetch(`${candidate}/api/auth-status`).then((res) => res.json()).catch(() => null)
      if (status && status.local === false) { lanBase = candidate; break }
    }

    const settings = await (await fetch(`${LOCAL}/api/settings`)).json() as {
      lanSharing: boolean
      requiresAuth: boolean
      apiToken: string
      mobileURL?: string
    }
    await check('默认设置：局域网共享开启，未启用密钥', async () => {
      assert.equal(settings.lanSharing, true)
      assert.equal(settings.requiresAuth, false)
      assert.equal(settings.apiToken, '')
    })

    const token = await (await fetch(`${LOCAL}/api/settings/token`, { method: 'POST' })).json()
      .then((body: { apiToken?: string }) => body.apiToken ?? '')
    await check('生成本机访问密钥并持久化到 settings.json', async () => {
      assert.match(token, /^[A-Za-z0-9_-]{32}$/)
      const saved = JSON.parse(readFileSync(join(dataDir, 'settings.json'), 'utf8'))
      assert.equal(saved.apiToken, token)
    })

    if (!lanBase) {
      console.log('… 当前环境没有可用的非本机地址，跳过局域网请求检查')
      return
    }

    await check('局域网请求：无密钥 401，带密钥 200', async () => {
      const denied = await fetch(`${lanBase}/api/network`, { redirect: 'manual' })
      assert.equal(denied.status, 401)
      assert.equal((await denied.json() as { code?: string }).code, 'auth_required')
      const allowed = await fetch(`${lanBase}/api/network?key=${encodeURIComponent(token)}`)
      assert.equal(allowed.status, 200)
    })

    await check('局域网请求：设置接口只能在本机修改', async () => {
      const denied = await fetch(`${lanBase}/api/settings?key=${encodeURIComponent(token)}`)
      assert.equal(denied.status, 403)
      assert.equal((await denied.json() as { code?: string }).code, 'local_only')
    })

    await check('局域网请求：订阅 / 订阅分享 / 托管规则集无需管理密钥', async () => {
      const health = await fetch(`${lanBase}/api/health`)
      assert.equal(health.status, 200)
      const ruleset = await fetch(`${lanBase}/api/ruleset?format=mrs&behavior=domain&file=ACL4SSR_Apple.list`)
      assert.equal(ruleset.status, 200)
      assert.equal(ruleset.headers.get('content-type'), 'application/octet-stream')
    })

    await check('局域网页面：?key= 登录后种下 cookie', async () => {
      const page = await fetch(`${lanBase}/?key=${encodeURIComponent(token)}`)
      assert.equal(page.status, 200)
      const cookie = page.headers.get('set-cookie') ?? ''
      assert.match(cookie, /tower_key=/)
      const cookieValue = cookie.split(';')[0]
      const api = await fetch(`${lanBase}/api/network`, {
        headers: { cookie: cookieValue },
      })
      assert.equal(api.status, 200)
    })

    await check('关闭局域网共享后：本机仍可用，局域网被拒绝', async () => {
      const update = await fetch(`${LOCAL}/api/settings`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ lanSharing: false }),
      })
      assert.equal(update.status, 200)
      const local = await fetch(`${LOCAL}/api/network`)
      assert.equal(local.status, 200)
      const denied = await fetch(`${lanBase}/api/network?key=${encodeURIComponent(token)}`)
      assert.equal(denied.status, 403)
      assert.equal((await denied.json() as { code?: string }).code, 'lan_disabled')
      const ruleset = await fetch(`${lanBase}/api/ruleset?format=mrs&behavior=domain&file=ACL4SSR_Apple.list`)
      assert.equal(ruleset.status, 403)
      const status = await fetch(`${lanBase}/api/auth-status`)
      assert.equal(status.status, 200)
      assert.equal((await status.json() as { lanSharing?: boolean }).lanSharing, false)
    })

    await check('轮换密钥后旧密钥失效', async () => {
      const update = await fetch(`${LOCAL}/api/settings`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ lanSharing: true }),
      })
      assert.equal(update.status, 200)
      const rotated = await (await fetch(`${LOCAL}/api/settings/token`, { method: 'POST' })).json()
        .then((body: { apiToken?: string }) => body.apiToken ?? '')
      assert.notEqual(rotated, token)
      const oldKey = await fetch(`${lanBase}/api/network?key=${encodeURIComponent(token)}`)
      assert.equal(oldKey.status, 401)
      const newKey = await fetch(`${lanBase}/api/network?key=${encodeURIComponent(rotated)}`)
      assert.equal(newKey.status, 200)
    })

    await check('关闭鉴权后局域网恢复无密钥访问', async () => {
      const removed = await fetch(`${LOCAL}/api/settings/token`, { method: 'DELETE' })
      assert.equal(removed.status, 200)
      const allowed = await fetch(`${lanBase}/api/network`)
      assert.equal(allowed.status, 200)
      const saved = JSON.parse(readFileSync(join(dataDir, 'settings.json'), 'utf8'))
      assert.equal(saved.apiToken, '')
    })
  } finally {
    child.kill()
    await new Promise((resolve) => setTimeout(resolve, 300))
    if (!child.killed) child.kill('SIGKILL')
    rmSync(dataDir, { recursive: true, force: true })
  }

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部局域网鉴权检查通过')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
