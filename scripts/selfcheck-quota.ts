// 订阅套餐链路自检：假上游（本地 HTTP）→ 塔台 /api/fetch → 前端解析/渲染。
// 覆盖响应头转发、四种 expire 单位、无响应头时的占位渲染。
// 用法：npm run selfcheck:quota
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { gzipSync } from 'node:zlib'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { renderToStaticMarkup } from 'react-dom/server'

import { mergeUsage, parse, parseUserinfoHeader } from '../src/parser'
import { QUOTA_PROBE_MISS_TTL_MS, quotaProbeMissFresh, quotaProbeURLs, rememberQuotaProbeMiss } from '../src/store'
import { subscriptionUsageSummary, usageFieldsFrom } from '../src/models/types'
import { formatBytes, SourceUsage, shouldShowSourceUsage } from '../src/components/SourceUsage'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const GB = 1024 ** 3

const NODE = `ss://${Buffer.from('aes-256-gcm:pass').toString('base64')}@1.2.3.4:8388#Quota-Node`
const BODY = `${NODE}\n`

const HEADERS = {
  seconds: 'upload=1048576; download=10737418240; total=107374182400; expire=1798761600',
  millis: 'upload=1048576; download=10737418240; total=107374182400; expire=1798761600000',
  iso: 'upload=1048576; download=10737418240; total=107374182400; expire=2027-01-01',
  zero: 'upload=1048576; download=10737418240; total=107374182400; expire=0',
}

async function startFakeUpstream(): Promise<{ base: string; close: () => Promise<void> }> {
  const server: Server = createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0]
    if (path === '/full') {
      res.writeHead(200, {
        'content-type': 'text/plain; charset=utf-8',
        'subscription-userinfo': HEADERS.seconds,
      })
      res.end(BODY)
      return
    }
    if (path === '/millis') {
      res.writeHead(200, { 'content-type': 'text/plain', 'subscription-userinfo': HEADERS.millis })
      res.end(BODY)
      return
    }
    if (path === '/iso') {
      res.writeHead(200, { 'content-type': 'text/plain', 'Subscription-Userinfo': HEADERS.iso })
      res.end(BODY)
      return
    }
    if (path === '/zero') {
      res.writeHead(200, { 'content-type': 'text/plain', 'subscription-userinfo': HEADERS.zero })
      res.end(BODY)
      return
    }
    if (path === '/none') {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(BODY)
      return
    }
    if (path === '/gate-flag') {
      // 模拟只在 Clash 版链接（flag=clash）上下发用量的机场。
      const hasFlag = req.url?.includes('flag=clash') ?? false
      res.writeHead(200, {
        'content-type': 'text/plain',
        ...(hasFlag ? { 'subscription-userinfo': HEADERS.seconds } : {}),
      })
      res.end(BODY)
      return
    }
    if (path === '/gate-ua') {
      // 模拟只认某个 Clash 转换器 UA 的机场。
      const ua = String(req.headers['user-agent'] ?? '')
      res.writeHead(200, {
        'content-type': 'text/plain',
        ...(ua.startsWith('clash.meta') ? { 'subscription-userinfo': HEADERS.seconds } : {}),
      })
      res.end(BODY)
      return
    }
    if (path === '/ua') {
      res.writeHead(200, {
        'content-type': 'text/plain',
        'subscription-userinfo': HEADERS.seconds,
      })
      res.end(`# ua=${req.headers['user-agent'] ?? ''}\n${BODY}`)
      return
    }
    if (path === '/redirect') {
      res.writeHead(302, { location: '/full' })
      res.end()
      return
    }
    if (path === '/gzip') {
      res.writeHead(200, {
        'content-type': 'text/plain',
        'content-encoding': 'gzip',
        'subscription-userinfo': HEADERS.seconds,
      })
      res.end(gzipSync(Buffer.from(BODY, 'utf8')))
      return
    }
    if (path === '/big') {
      // 模拟几 MB 的订阅正文；配额探测只该取响应头，不应把正文带回来。
      res.writeHead(200, {
        'content-type': 'text/plain',
        'subscription-userinfo': HEADERS.seconds,
      })
      res.end(Buffer.alloc(2 * 1024 * 1024, 0x61))
      return
    }
    res.writeHead(404).end()
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('假上游未监听')
  return {
    base: `http://127.0.0.1:${address.port}`,
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
  const dir = mkdtempSync(join(tmpdir(), 'tower-quota-'))
  const port = 20000 + Math.floor(Math.random() * 30000)
  const token = 'quota-test'
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

function fetchURL(tower: Tower, upstream: string, path: string, ua?: string): string {
  const params = new URLSearchParams({ url: `${upstream}${path}`, key: tower.token })
  if (ua) params.set('ua', ua)
  return `${tower.base}/api/fetch?${params.toString()}`
}

async function fetchThroughTower(tower: Tower, upstream: string, path: string, ua?: string) {
  const response = await fetch(fetchURL(tower, upstream, path, ua))
  assert.equal(response.status, 200, `${path} 应返回 200`)
  const text = await response.text()
  const header = response.headers.get('x-subscription-userinfo')
  return { text, header }
}

/** 与 store.refreshSource 相同的数据合并顺序。 */
function storeState(text: string, header: string | null) {
  const parsed = parse(text, 'quota-source')
  const usage = mergeUsage(parsed.status, parseUserinfoHeader(header))
  const fields = usageFieldsFrom(usage)
  return { nodes: parsed.nodes, usage, ...fields }
}

function render(usage: ReturnType<typeof storeState>['usage'], fields: ReturnType<typeof usageFieldsFrom>): string {
  return renderToStaticMarkup(
    SourceUsage({ summary: subscriptionUsageSummary({ usage, ...fields }) }),
  )
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
    await check('/api/fetch 转发 subscription-userinfo（秒）', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/full')
      assert.equal(result.header, HEADERS.seconds, '响应头应原样转发为 x-subscription-userinfo')
      const state = storeState(result.text, result.header)
      assert.equal(state.nodes.length, 1, '节点正文应正常解析')
      assert.equal(state.usage?.total, 107374182400)
      assert.equal(state.totalBytes, 107374182400)
      assert.equal(state.usedBytes, 1048576 + 10737418240)
      assert.equal(state.expireAt, 1798761600000)
      const html = render(state.usage, usageFieldsFrom(state.usage))
      assert.ok(html.includes('剩余'), '有数据时应显示剩余流量')
      assert.ok(html.includes('到期'), '有数据时应显示到期时间')
      assert.ok(html.includes('data-usage="known"'))
    })

    await check('expire 毫秒归一（header + 渲染）', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/millis')
      const state = storeState(result.text, result.header)
      assert.equal(state.expireAt, 1798761600000, '毫秒不应再乘 1000')
      const html = render(state.usage, usageFieldsFrom(state.usage))
      assert.ok(html.includes('2027'), `到期日期应是 2027 年：${html}`)
    })

    await check('expire ISO 日期（header 大小写不敏感）', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/iso')
      const state = storeState(result.text, result.header)
      // 纯日期按本地日历日解析：东八区是当天 0 点，而不是 UTC 午夜（当天 08:00）。
      assert.equal(state.expireAt, new Date(2027, 0, 1).getTime())
      const html = render(state.usage, usageFieldsFrom(state.usage))
      assert.ok(html.includes('2027'))
    })

    await check('expire=0 渲染为长期有效', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/zero')
      const state = storeState(result.text, result.header)
      assert.equal(state.expireAt, 0)
      const html = render(state.usage, usageFieldsFrom(state.usage))
      assert.ok(html.includes('长期有效'))
    })

    await check('跟随重定向后仍保留响应头', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/redirect')
      assert.equal(result.header, HEADERS.seconds)
    })

    await check('gzip 响应解压后仍保留响应头', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/gzip')
      assert.equal(result.header, HEADERS.seconds)
      const state = storeState(result.text, result.header)
      assert.equal(state.nodes.length, 1)
    })

    await check('上游不返回头时：字段为空，但 UI 仍渲染占位', async () => {
      const result = await fetchThroughTower(tower, upstream.base, '/none')
      assert.equal(result.header, null, '不应凭空伪造 x-subscription-userinfo')
      const state = storeState(result.text, result.header)
      assert.equal(state.totalBytes, undefined)
      assert.equal(state.usedBytes, undefined)
      assert.equal(state.expireAt, undefined)
      const html = render(state.usage, usageFieldsFrom(state.usage))
      assert.ok(html.includes('流量 —'), `应显示流量占位而不是空白：${html}`)
      assert.ok(html.includes('到期 —'), `应显示到期占位而不是空白：${html}`)
      assert.ok(html.includes('机场未返回用量信息'), '应给出原因说明')
      assert.ok(html.includes('data-usage="unknown"'))
    })

    await check('刷新 / 探测失败时保留旧用量，不被 undefined 覆盖', async () => {
      const old = { upload: 1, download: 1024, total: 107374182400, expire: 1798761600000 }
      assert.deepEqual(mergeUsage(old, undefined), old)
      assert.deepEqual(mergeUsage(old, {}), old)
      // 明确的新值（包括 total=0 表示无限制）仍要覆盖。
      assert.deepEqual(mergeUsage(old, { total: 0 }), { ...old, total: 0 })
    })

    await check('自定义 UA 透传（机场按 UA 下发用量）', async () => {
      // 假上游不区分 UA，这里只断言参数确实传到 /api/fetch，且不覆盖响应头。
      const result = await fetchThroughTower(tower, upstream.base, '/full', 'clash-verge/v2.5.8')
      assert.equal(result.header, HEADERS.seconds)
      assert.equal(storeState(result.text, result.header).expireAt, 1798761600000)
    })

    await check('请求头里的 User-Agent 随 ua 参数变化', async () => {
      const custom = await fetchThroughTower(tower, upstream.base, '/ua', 'clash.meta')
      assert.match(custom.text, /ua=clash\.meta/)
      const fallback = await fetchThroughTower(tower, upstream.base, '/ua')
      assert.match(fallback.text, /ua=clash-verge\/v2\.4\.2/)
    })

    await check('只在 flag=clash 时给头：首次请求无头，flag 探测能拿到', async () => {
      const main = await fetchThroughTower(tower, upstream.base, '/gate-flag')
      assert.equal(main.header, null, '非 Clash 链接不应凭空得到用量')
      const probe = await fetchThroughTower(tower, upstream.base, '/gate-flag?flag=clash')
      assert.equal(probe.header, HEADERS.seconds, 'flag=clash 探测应拿到用量')
      // 与 refreshSource 的合并顺序一致：主请求解析节点，探测只补 header。
      const state = storeState(main.text, probe.header)
      assert.equal(state.expireAt, 1798761600000)
    })

    await check('配额探测覆盖 flag=clash 与 ?clash=1 两种方言', async () => {
      assert.deepEqual(
        quotaProbeURLs('https://a.example/api/v1/client/subscribe?token=t&flag=ss'),
        [
          'https://a.example/api/v1/client/subscribe?token=t&flag=clash',
          'https://a.example/api/v1/client/subscribe?token=t&clash=1',
        ],
        '通用链接应替换 flag，并用 clash=1 再探测',
      )
      assert.deepEqual(
        quotaProbeURLs('https://a.example/api/v1/client/subscribe?token=t'),
        [
          'https://a.example/api/v1/client/subscribe?token=t&flag=clash',
          'https://a.example/api/v1/client/subscribe?token=t&clash=1',
        ],
        '无 flag 的链接应同时探测 flag=clash 与 clash=1',
      )
      // 真实机场：/link/token?sub=1 是通用链接，只有去掉 sub 后 ?clash=1 才下发用量头。
      assert.deepEqual(
        quotaProbeURLs('https://a.example/link/token?sub=1'),
        [
          'https://a.example/link/token?clash=1',
          'https://a.example/link/token?sub=1&flag=clash',
          'https://a.example/link/token?sub=1&clash=1',
        ],
        '带 sub 的通用链接应先去掉 sub 再试 clash=1',
      )
      assert.deepEqual(
        quotaProbeURLs('https://a.example/link/token?sub=1&clash=1'),
        [
          'https://a.example/link/token?clash=1',
          'https://a.example/link/token?sub=1&clash=1&flag=clash',
          'https://a.example/link/token?sub=1&clash=1',
        ],
        '带 sub 时即使已有 clash=1 也必须先探测去掉 sub 的链接',
      )
      assert.deepEqual(
        quotaProbeURLs('https://a.example/link/token?sub=1&flag=clash'),
        [
          'https://a.example/link/token?flag=clash&clash=1',
          'https://a.example/link/token?sub=1&flag=clash',
          'https://a.example/link/token?sub=1&clash=1',
        ],
        '带 sub 时 flag=clash 同样会被通用链接压制，不能跳过探测',
      )
      assert.deepEqual(
        quotaProbeURLs('https://a.example/sub/clash?token=t&flag=clash'),
        [],
        '已经是 Clash 版链接时不重复探测',
      )
      assert.deepEqual(
        quotaProbeURLs('https://a.example/link/token?clash=1'),
        [],
        '已经是 ?clash=1 的链接不重复探测',
      )
    })

    await check('配额探测只取响应头（headers=1 不返回正文）', async () => {
      const params = new URLSearchParams({ url: `${upstream.base}/big`, key: tower.token, headers: '1' })
      const response = await fetch(`${tower.base}/api/fetch?${params.toString()}`)
      assert.equal(response.status, 200)
      assert.equal(response.headers.get('x-subscription-userinfo'), HEADERS.seconds)
      const text = await response.text()
      assert.equal(text.length, 0, 'headers=1 应返回空正文，不能把 2MB 订阅带回来')
    })

    await check('配额探测负缓存：6 小时内不重试，过期后自动清理', async () => {
      const t0 = 1_800_000_000_000
      const misses = new Map<string, number>()
      rememberQuotaProbeMiss(misses, 'src-a', t0)
      assert.equal(quotaProbeMissFresh(misses, 'src-a', t0 + QUOTA_PROBE_MISS_TTL_MS - 1), true)
      assert.equal(quotaProbeMissFresh(misses, 'src-a', t0 + QUOTA_PROBE_MISS_TTL_MS), false)
      assert.equal(misses.has('src-a'), false, '过期条目应被清掉，下一次刷新要真重试')
      assert.equal(quotaProbeMissFresh(new Map(), 'src-a', t0), false, '没记录过就不该跳过探测')
    })

    await check('配额负缓存上限与命中缓存一致（LRU 64）', async () => {
      const misses = new Map<string, number>()
      const t0 = 1_800_000_000_000
      for (let i = 0; i < 65; i += 1) rememberQuotaProbeMiss(misses, `src-${i}`, t0 + i)
      assert.equal(misses.size, 64)
      assert.equal(misses.has('src-0'), false, '最老的条目应被淘汰')
      assert.equal(misses.has('src-64'), true, '最新写入的条目必须保留')
      rememberQuotaProbeMiss(misses, 'src-10', t0 + 100)
      assert.equal([...misses.keys()].at(-1), 'src-10', '再次写入应刷新到队尾')
    })

    await check('只有 upload/download 时视为已知但不完整，不再提示换 UA', async () => {
      const usage = parseUserinfoHeader('upload=1GB; download=2GB')
      const fields = usageFieldsFrom(usage)
      const html = render(usage, fields)
      assert.ok(html.includes('已用'), `应渲染已用流量：${html}`)
      assert.ok(html.includes('总量未知'), `应说明总量未知：${html}`)
      assert.ok(!html.includes('机场未返回用量信息'), '已有 upload/download 时不能误判为缺失')
      assert.ok(html.includes('data-usage="known"'))
    })

    await check('流量格式化不出现「1024 KB」式进位', async () => {
      assert.equal(formatBytes(1048575), '1.0 MB')
      assert.equal(formatBytes(1073741823), '1.0 GB')
      assert.equal(formatBytes(1023), '1023 B')
      assert.equal(formatBytes(1024), '1.0 KB')
      assert.equal(formatBytes(8796093022208), '8.0 TB')
      assert.equal(formatBytes(0), '0 B')
      assert.equal(formatBytes(-1), '0 B')
      assert.equal(formatBytes(Number.NaN), '—')
      assert.equal(formatBytes(undefined), '—')
    })

    await check('粘贴内容 / 手动来源不渲染用量块', async () => {
      assert.equal(shouldShowSourceUsage({ url: '' }), false)
      assert.equal(shouldShowSourceUsage({ url: '   ' }), false)
      assert.equal(shouldShowSourceUsage({}), false)
      assert.equal(shouldShowSourceUsage({ url: 'https://a.example/sub' }), true)
    })

    await check('只认 clash.meta 的机场：默认 UA 无头，兼容 UA 能拿到', async () => {
      const main = await fetchThroughTower(tower, upstream.base, '/gate-ua')
      assert.equal(main.header, null)
      const compat = await fetchThroughTower(tower, upstream.base, '/gate-ua', 'clash.meta')
      assert.equal(compat.header, HEADERS.seconds)
    })
  } finally {
    await tower.stop()
    await upstream.close()
  }

  console.log(failures === 0 ? '\n全部套餐链路自检通过' : `\n${failures} 项套餐链路自检失败`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
