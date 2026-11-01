// 自检：批量订阅链接识别、去重、HTTP 代理排除与上限。
// 用法：npm run selfcheck:batch
import assert from 'node:assert/strict'
import { MAX_BATCH_SUBSCRIPTIONS, splitSubscriptionURLs, subscriptionLabel } from '../src/batchSubscriptions'

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

const BATCH = `
# 两条主订阅
https://sub.example.com/a?token=one

https://sub.example.com/b?token=two
http://sub.example.com/c
`

function main(): void {
  check('批量订阅：每行一条，忽略空行和注释', () => {
    const batch = splitSubscriptionURLs(BATCH)
    assert.equal(batch.urls.length, 3)
    assert.equal(batch.invalid, 0)
    assert.equal(batch.duplicates, 0)
  })

  check('批量订阅：完全重复的地址只保留一条', () => {
    const batch = splitSubscriptionURLs(`
https://sub.example.com/a
https://sub.example.com/a
https://sub.example.com/b
`)
    assert.deepEqual(batch.urls, ['https://sub.example.com/a', 'https://sub.example.com/b'])
    assert.equal(batch.duplicates, 1)
  })

  check('批量订阅：格式无效的行单独计数', () => {
    const batch = splitSubscriptionURLs(`
https://sub.example.com/a
not a url
ftp://sub.example.com/a
https://
`)
    assert.equal(batch.urls.length, 1)
    assert.equal(batch.invalid, 3)
  })

  check('批量订阅：HTTP 代理节点不按订阅地址导入', () => {
    const batch = splitSubscriptionURLs(`
http://proxy.example.com:8080
https://sub.example.com/a
http://user:pass@proxy.example.com
`)
    assert.deepEqual(batch.urls, ['https://sub.example.com/a'])
    assert.equal(batch.proxyCount, 2)
  })

  check('批量订阅：单次超过上限只保留前 20 条', () => {
    const lines = Array.from({ length: MAX_BATCH_SUBSCRIPTIONS + 3 }, (_, index) =>
      `https://sub.example.com/${index + 1}`)
    const batch = splitSubscriptionURLs(lines.join('\n'))
    assert.equal(batch.urls.length, MAX_BATCH_SUBSCRIPTIONS)
    assert.equal(batch.truncated, 3)
  })

  check('失败列表不显示订阅 query token', () => {
    assert.equal(
      subscriptionLabel('https://sub.example.com/a?token=secret'),
      'sub.example.com/a',
    )
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部批量订阅检查通过')
}

main()
