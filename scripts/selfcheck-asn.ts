// 自检：离线 IP 网络组织库（IPv4 / IPv6 二分查找与名称池）。
// 用法：npm run selfcheck:asn
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { loadIPASNData, organizationForAddress } from '../server/ip-asn.mjs'

const dir = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'server', 'ip-asn')

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

function main(): void {
  const data = loadIPASNData(dir)
  assert.ok(data, 'ASN 数据没有加载成功')

  check('IPv4 查询 Cloudflare', () => {
    const result = organizationForAddress(data, '1.1.1.1')
    assert.ok(result)
    assert.equal(result.asn, 13335)
    assert.match(result.organization, /Cloudflare/i)
  })

  check('IPv4 查询 Google', () => {
    const result = organizationForAddress(data, '8.8.8.8')
    assert.ok(result)
    assert.equal(result.asn, 15169)
    assert.match(result.organization, /Google/i)
  })

  check('IPv6 查询 Cloudflare', () => {
    const result = organizationForAddress(data, '2606:4700:4700::1111')
    assert.ok(result)
    assert.equal(result.asn, 13335)
    assert.match(result.organization, /Cloudflare/i)
  })

  check('非法地址与缺失数据库安全返回 null', () => {
    assert.equal(organizationForAddress(data, 'not-an-ip'), null)
    assert.equal(organizationForAddress(data, ''), null)
    assert.equal(organizationForAddress(null, '1.1.1.1'), null)
    assert.equal(loadIPASNData(join(dir, 'missing')), null)
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部 ASN 网络组织检查通过')
}

main()
