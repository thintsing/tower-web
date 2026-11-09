// 自检：未保存改动不会被远端覆盖；整块损坏字段不会把空值推回服务端；
// 首次创建失败必须进入「未保存」而不是静默停在 connecting。
// 每个场景在独立子进程里跑，避免 workspaceSync 的模块级状态串味。
// 用法：npm run selfcheck:workspace-overwrite
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const selfPath = fileURLToPath(import.meta.url)
const scenario = process.env.SCENARIO ?? ''
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

const sourceA = { id: 'source-a', name: 'A', url: 'https://a.example/sub', excludedNodeKeys: [] }
const sourceLocal = { id: 'local-edit', name: 'Local', url: 'https://local.example/sub', excludedNodeKeys: [] }
const sourceRemote = { id: 'remote-edit', name: 'Remote', url: 'https://remote.example/sub', excludedNodeKeys: [] }
const node = {
  id: 'node-1',
  kind: 'ss',
  name: 'N1',
  server: '1.2.3.4',
  port: 8388,
  tls: false,
  skipCertificateVerification: false,
  rawURI: 'ss://demo',
}

const server = {
  version: 1,
  data: {} as Record<string, unknown>,
  put: 'ok' as 'ok' | '413' | 'offline',
  puts: [] as Array<Record<string, any>>,
  gets: 0,
  holdGet: false,
}

let releaseGet: (() => void) | undefined

function reply(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function installEnvironment(): Map<string, () => void> {
  const stored = new Map<string, string>()
  const storage = {
    getItem: (key: string) => (stored.has(key) ? stored.get(key)! : null),
    setItem: (key: string, value: string) => { stored.set(key, String(value)) },
    removeItem: (key: string) => { stored.delete(key) },
    get length() { return stored.size },
    key: (index: number) => [...stored.keys()][index] ?? null,
  }
  const listeners = new Map<string, () => void>()
  ;(globalThis as any).localStorage = storage
  storage.setItem('tower-web-api-key', 'test-key')
  ;(globalThis as any).window = {
    location: { origin: 'http://tower.test' },
    localStorage: storage,
    setTimeout,
    clearTimeout,
    setInterval: () => 1,
    clearInterval: () => {},
    addEventListener: (type: string, fn: () => void) => { listeners.set(type, fn) },
    removeEventListener: (type: string) => { listeners.delete(type) },
    dispatchEvent: () => true,
  }
  ;(globalThis as any).document = { visibilityState: 'visible', addEventListener: () => {} }
  ;(globalThis as any).fetch = async (input: unknown, init: any = {}) => {
    const url = new URL(String(input))
    const method = String(init.method ?? 'GET').toUpperCase()
    if (url.pathname === '/api/auth-status') {
      return reply(200, {
        mode: 'server',
        lanSharing: true,
        requiresAuth: false,
        local: true,
        valid: true,
      })
    }
    if (url.pathname === '/api/workspace/version') return reply(200, { version: server.version })
    if (url.pathname === '/api/workspace' && method === 'GET') {
      server.gets += 1
      if (server.holdGet) {
        server.holdGet = false
        await new Promise<void>((resolve) => { releaseGet = resolve })
      }
      return reply(200, { version: server.version, data: server.data })
    }
    if (url.pathname === '/api/workspace' && method === 'PUT') {
      const body = JSON.parse(String(init.body))
      server.puts.push(body)
      if (server.put === 'offline') throw new TypeError('network down')
      if (server.put === '413') return reply(413, { error: '工作区超过 16 MB 上限' })
      server.version = Number(body.version) + 1
      server.data = body.data
      return reply(200, { version: server.version })
    }
    return reply(404, { error: `unexpected ${method} ${url.pathname}` })
  }
  return listeners
}

async function waitFor(
  label: string,
  predicate: () => boolean,
  timeout = 6_000,
): Promise<void> {
  const started = Date.now()
  while (Date.now() - started < timeout) {
    if (predicate()) return
    await wait(50)
  }
  throw new Error(`等待超时：${label}`)
}

async function runWorker(): Promise<void> {
  const listeners = installEnvironment()
  // 按脚本自身位置解析，Linux runner 与本地 Windows 都能找到同一份源码。
  const { useStore } = await import(new URL('../src/store.ts', import.meta.url).href)
  const sync = await import(new URL('../src/workspaceSync.ts', import.meta.url).href)
  const status = () => sync.getWorkspaceStatus()

  if (scenario === 'p01-focus') {
    server.version = 1
    server.data = { sources: [sourceA] }
    server.put = '413'
    await sync.initWorkspaceSync()
    await waitFor('online', () => status().state === 'online')
    useStore.setState({ sources: [sourceLocal] })
    await waitFor('unsaved', () => status().state === 'unsaved')

    const getsBefore = server.gets
    server.version = 2
    server.data = { sources: [sourceRemote] }
    listeners.get('focus')?.()
    await wait(400)

    assert.equal(status().state, 'unsaved', '未保存状态应保持')
    assert.deepEqual(
      useStore.getState().sources.map((item: any) => item.id),
      ['local-edit'],
      '本机编辑不能被服务端数据覆盖',
    )
    assert.equal(server.gets, getsBefore, '未保存时不应拉取服务端全量')
    assert.match(status().message, /自动重试已失败/)
    return
  }

  if (scenario === 'p01-offline') {
    server.version = 1
    server.data = { sources: [sourceA] }
    server.put = 'ok'
    await sync.initWorkspaceSync()
    await waitFor('online', () => status().state === 'online')
    useStore.setState({ sources: [sourceLocal] })
    server.put = 'offline'
    await waitFor('offline', () => status().state === 'offline')
    assert.deepEqual(
      useStore.getState().sources.map((item: any) => item.id),
      ['local-edit'],
      '离线时本机编辑应保留',
    )

    server.put = 'ok'
    await waitFor('重新联网后保存成功', () => status().state === 'online')
    const last = server.puts.at(-1)!
    assert.deepEqual(last.data.sources.map((item: any) => item.id), ['local-edit'])
    assert.deepEqual((server.data.sources as any[]).map((item: any) => item.id), ['local-edit'])
    return
  }

  if (scenario === 'p02-preserve') {
    server.version = 1
    server.data = { nodes: [node], sources: 'broken-server-value', exportConfigName: 'srv' }
    server.put = 'ok'
    await sync.initWorkspaceSync()
    await waitFor('online', () => status().state === 'online')
    const issues = status().issues
    assert.ok(
      issues.some((item: any) => item.key === 'sources' && item.wholeKey),
      '整块损坏的 sources 应产生 wholeKey issue',
    )

    useStore.setState({ exportConfigName: 'edited' })
    await waitFor('推送完成', () => server.puts.length > 0)
    const body = server.puts.at(-1)!
    assert.equal(body.data.sources, 'broken-server-value', '损坏字段必须原样写回，不能推空数组')
    assert.equal(body.data.exportConfigName, 'edited')
    assert.deepEqual(body.data.nodes, [node])
    return
  }

  if (scenario === 'p14-boot-edit') {
    // 服务端首次拉取挂起期间用户已经编辑：不能拿服务端数据静默覆盖。
    server.version = 1
    server.data = { sources: [sourceA] }
    server.holdGet = true
    const init = sync.initWorkspaceSync()
    await waitFor('等待首次拉取挂起', () => server.gets > 0)
    useStore.setState({ sources: [sourceLocal] })
    releaseGet?.()
    await init
    await waitFor('首连后进入冲突', () => status().state === 'conflict')
    assert.deepEqual(
      useStore.getState().sources.map((item: any) => item.id),
      ['local-edit'],
      '首连前编辑的内容必须保留为草稿',
    )
    assert.equal(server.puts.length, 0, '不能自动写服务端掩盖冲突')
    assert.deepEqual(
      (server.data.sources as any[]).map((item: any) => item.id),
      ['source-a'],
      '服务端数据不能被心跳写回覆盖',
    )
    assert.match(status().message, /未保存/)
    return
  }

  if (scenario === 'p13-create') {
    server.version = 0
    server.data = {}
    server.put = '413'
    useStore.setState({ sources: [sourceA] })
    await sync.initWorkspaceSync()
    await waitFor('创建失败进入未保存', () => status().state === 'unsaved')
    assert.match(status().message, /尚未保存/)
    assert.match(status().message, /容量/)
    assert.equal(server.puts.length, 1)
    return
  }

  throw new Error(`未知场景：${scenario}`)
}

if (scenario) {
  runWorker().then(
    () => process.exit(0),
    (error) => {
      console.error(error instanceof Error ? error.message : String(error))
      process.exit(1)
    },
  )
} else {
  const scenarios: Array<[string, string]> = [
    ['p01-focus', '未保存时切回前台不会用服务端覆盖本机改动'],
    ['p01-offline', '离线重连先推本机改动，写不进去也不拉服务端'],
    ['p02-preserve', '新设备不会把整块损坏字段的空值推回服务端'],
    ['p13-create', '首次创建保存失败进入未保存而不是静默'],
    ['p14-boot-edit', '首次连接前编辑的工作区不会被服务端静默覆盖'],
  ]

  let failures = 0
  for (const [name, label] of scenarios) {
    const result = await new Promise<{ code: number | null; output: string }>((resolve) => {
      const child = spawn(process.execPath, ['--import', 'tsx', selfPath], {
        cwd: fileURLToPath(new URL('..', import.meta.url)),
        env: { ...process.env, SCENARIO: name },
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      let output = ''
      child.stdout.on('data', (chunk) => { output += String(chunk) })
      child.stderr.on('data', (chunk) => { output += String(chunk) })
      child.on('close', (code) => resolve({ code, output }))
    })
    if (result.code === 0) {
      console.log(`✓ ${label}`)
    } else {
      failures += 1
      console.error(`✗ ${label}`)
      console.error(`  ${result.output.trim()}`)
    }
  }

  if (failures > 0) {
    console.error(`\n${failures} 项自检失败`)
    process.exitCode = 1
  } else {
    console.log('\n工作区覆盖保护自检全部通过')
  }
}
