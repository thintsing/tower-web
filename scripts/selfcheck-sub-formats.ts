// 自检：发布前对比目标载体集合，单个载体生成失败必须留下原因，不能静默留空。
// 用法：npm run selfcheck:sub-formats
import assert from 'node:assert/strict'
import { CLIENTS, type ProxyNode, type RuleScheme } from '../src/models/types'
import { clientSubscriptionLink } from '../src/util/subscriptionLinks'
import {
  SUBSCRIPTION_FORMAT_ORDER,
  describeSubscriptionFormatFailures,
  generateSubscriptionFormatsDetailed,
  missingSubscriptionFormats,
} from '../src/generator'

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

function scheme(): RuleScheme {
  return {
    id: 'selfcheck-sub-formats',
    name: '自检方案',
    description: '',
    groups: [],
    rules: [],
    ruleSets: [],
  }
}

check('目标格式集合覆盖服务端全部载体', () => {
  assert.deepEqual(
    [...SUBSCRIPTION_FORMAT_ORDER],
    ['yaml', 'egern', 'surge', 'loon', 'quanx', 'json', 'base64'],
  )
})

check('空内容载体算缺失，不会被当作生成成功', () => {
  const missing = missingSubscriptionFormats({ yaml: 'x', surge: '   ', base64: 'y' })
  assert.deepEqual(missing, ['egern', 'surge', 'loon', 'quanx', 'json'])
})

check('没有节点时保留失败原因，不吞掉 base64 空载体', () => {
  const result = generateSubscriptionFormatsDetailed([], scheme())
  assert.equal(result.formats.base64, '')
  const base64 = result.failures.find((item) => item.format === 'base64')
  assert.ok(base64, 'base64 缺失必须出现在 failures 里')
  assert.equal(base64.reason, '生成的配置内容为空')
})

check('任一载体抛错时其余载体仍生成，失败原因逐条可读', () => {
  const throwingNodes = new Proxy([] as ProxyNode[], {
    get(target, property, receiver) {
      if (typeof property === 'string' || property === Symbol.iterator) {
        throw new Error('模拟载体生成失败')
      }
      return Reflect.get(target, property, receiver)
    },
  })
  const result = generateSubscriptionFormatsDetailed(throwingNodes, scheme())
  assert.ok(result.failures.length > 0, '抛错必须记录为失败而不是静默返回空串')
  for (const item of result.failures) {
    assert.equal(item.reason, '模拟载体生成失败')
    assert.equal(result.formats[item.format], '')
  }
  const text = describeSubscriptionFormatFailures(result.failures)
  for (const item of result.failures) {
    assert.match(text, new RegExp(item.format))
    assert.match(text, /模拟载体生成失败/)
  }
})

check('只缺一个载体时其余载体仍然完整保留', () => {
  const missingOnlyBase64 = generateSubscriptionFormatsDetailed([], scheme())
  for (const format of SUBSCRIPTION_FORMAT_ORDER) {
    if (format === 'base64') continue
    // 空节点下 YAML / sing-box 等仍是合法空配置；只要不抛错就必须非空。
    if (!missingOnlyBase64.failures.some((item) => item.format === format)) {
      assert.ok(missingOnlyBase64.formats[format].length > 0, `${format} 未失败却为空`)
    }
  }
})

check('客户端链接补 format / target / content，服务器模式不改写 host', () => {
  const base = 'http://127.0.0.1:8787/api/sub/token?name=tower'
  const clash = CLIENTS.find((client) => client.target === 'clash-verge')
  const surge = CLIENTS.find((client) => client.target === 'surge')
  assert.ok(clash && surge)

  const local = new URL(clientSubscriptionLink(base, clash!, {
    serverMode: false,
    origin: 'http://192.168.1.9:8787',
  }))
  assert.equal(local.host, '192.168.1.9:8787')
  assert.equal(local.searchParams.get('format'), 'yaml')
  assert.equal(local.searchParams.get('target'), 'clash-verge')
  assert.equal(local.searchParams.get('name'), 'tower')

  const nodes = new URL(clientSubscriptionLink(base, surge!, {
    serverMode: true,
    origin: 'http://10.0.0.2:8787',
    nodesOnly: true,
  }))
  assert.equal(nodes.host, '127.0.0.1:8787')
  assert.equal(nodes.searchParams.get('format'), 'surge')
  assert.equal(nodes.searchParams.get('target'), 'surge')
  assert.equal(nodes.searchParams.get('content'), 'nodes')

  assert.equal(clientSubscriptionLink('', clash!, { serverMode: false, origin: 'http://x' }), '')
  assert.equal(clientSubscriptionLink('http://[bad', clash!, { serverMode: false, origin: 'http://x' }), '')
})

if (failures > 0) {
  console.error(`\n${failures} 项载体自检失败`)
  process.exitCode = 1
} else {
  console.log('\n全部载体自检通过')
}
