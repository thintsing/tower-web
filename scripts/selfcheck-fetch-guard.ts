// `/api/fetch` 重定向守卫自检：本地假上游 + 真实塔台服务端。
// 覆盖正常 302 链、相对 Location、链路本地/云元数据/组播拦截、
// 跳数上限、非 http(s) 协议、局域网放行，以及最终一跳的用量头透传。
// 用法：npm run selfcheck:fetch-guard
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const USERINFO = 'upload=1; download=2; total=1000'

async function startFakeUpstream(): Promise<{ base: string; close: () => Promise<void> }> {
  let base = ''
  const server: Server = createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0]
    const redirect = (location: string) => {
      res.writeHead(302, { location })
      res.end()
    }
    switch (path) {
      case '/start':
        // 两跳 + 第二跳是相对地址：/start → /hop → ./final
        return redirect('/hop')
      case '/hop':
        return redirect('./final')
      case '/relative':
        return redirect('final')
      case '/final':
        res.writeHead(200, {
          'content-type': 'text/plain; charset=utf-8',
          'subscription-userinfo': USERINFO,
        })
        res.end('FINAL')
        return
      case '/to-meta':
        return redirect('http://169.254.169.254/latest/meta-data')
      case '/to-alibaba':
        return redirect('http://100.100.100.200/')
      case '/to-ec2':
        return redirect('http://[fd00:ec2::254]/')
      case '/to-multicast':
        return redirect('http://224.0.0.1/')
      case '/to-ftp':
        return redirect('ftp://example.com/rules.list')
      case '/to-lan':
        // 私网 / 回环地址按现有设计放行；这里用回环地址充当局域网目标。
        return redirect(`${base}/final`)
      case '/loop0': return redirect('/loop1')
      case '/loop1': return redirect('/loop2')
      case '/loop2': return redirect('/loop3')
      case '/loop3': return redirect('/loop4')
      case '/loop4': return redirect('/loop5')
      case '/loop5': return redirect('/loop0')
    }
    res.writeHead(404).end()
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('假上游未监听')
  base = `http://127.0.0.1:${address.port}`
  return {
    base,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  }
}

interface Tower {
  base: string
  token: string
  dir: string
  stop: () => Promise<void>
}

async function waitForHealth(base: string): Promise<boolean> {
  const deadline = Date.now() + 8000
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

async function startTower(): Promise<Tower> {
  const dir = mkdtempSync(join(tmpdir(), 'tower-fetch-guard-'))
  const port = 20000 + Math.floor(Math.random() * 30000)
  const token = 'fetch-guard-test'
  const child = spawn(process.execPath, ['server/index.mjs'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      TOWER_DATA_DIR: dir,
      TOWER_MODE: 'server',
      TOWER_API_TOKEN: token,
      TOWER_CONTAINER: '',
    },
    stdio: 'ignore',
  })
  const base = `http://127.0.0.1:${port}`
  if (!await waitForHealth(base)) {
    child.kill()
    throw new Error(`测试服务未启动（PORT=${port}）`)
  }
  return {
    base,
    token,
    dir,
    stop: async () => {
      child.kill()
      await new Promise((resolve) => setTimeout(resolve, 150))
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

async function fetchThroughTower(tower: Tower, upstream: string, path: string) {
  const params = new URLSearchParams({ url: `${upstream}${path}`, key: tower.token })
  const response = await fetch(`${tower.base}/api/fetch?${params.toString()}`)
  return {
    status: response.status,
    text: await response.text(),
    header: response.headers.get('x-subscription-userinfo'),
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
  const upstream = await startFakeUpstream()
  const tower = await startTower()
  try {
    await check('正常 302 跟随，并透传最终一跳的 subscription-userinfo', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/start')
      assert.equal(result.status, 200)
      assert.equal(result.text, 'FINAL')
      assert.equal(result.header, USERINFO)
    })

    await check('相对 Location 按当前地址解析成绝对地址', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/relative')
      assert.equal(result.status, 200)
      assert.equal(result.text, 'FINAL')
    })

    await check('重定向到 169.254.169.254 被拦截，且说明第几跳', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/to-meta')
      assert.equal(result.status, 502)
      assert.match(result.text, /第 1 跳/)
      assert.match(result.text, /169\.254\.169\.254/)
      assert.match(result.text, /被拦截/)
      assert.match(result.text, /链路本地/)
    })

    await check('重定向到 100.100.100.200 被拦截', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/to-alibaba')
      assert.equal(result.status, 502)
      assert.match(result.text, /100\.100\.100\.200/)
      assert.match(result.text, /云元数据/)
    })

    await check('重定向到 fd00:ec2::254 被拦截', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/to-ec2')
      assert.equal(result.status, 502)
      assert.match(result.text, /fd00:ec2::254/)
    })

    await check('重定向到组播地址被拦截', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/to-multicast')
      assert.equal(result.status, 502)
      assert.match(result.text, /224\.0\.0\.1/)
      assert.match(result.text, /组播/)
    })

    await check('重定向超过 5 跳直接失败', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/loop0')
      assert.equal(result.status, 502)
      assert.match(result.text, /超过 5 跳/)
    })

    await check('非 http(s) 的 Location 被拒绝', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/to-ftp')
      assert.equal(result.status, 502)
      assert.match(result.text, /不支持的协议/)
      assert.match(result.text, /ftp:/)
    })

    await check('重定向到局域网 / 回环地址仍放行', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/to-lan')
      assert.equal(result.status, 200)
      assert.equal(result.text, 'FINAL')
      assert.equal(result.header, USERINFO)
    })
  } finally {
    await tower.stop()
    await upstream.close()
  }

  if (failures > 0) {
    console.error(`\n${failures} 项失败`)
    process.exit(1)
  }
  console.log('\n全部抓取守卫检查通过')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
