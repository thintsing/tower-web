// 自检：在线规则库目录（ACL4SSR + blackmatrix7）的数量、去重、来源与常用项。
// 用法：npm run selfcheck:catalog
import assert from 'node:assert/strict'
import { ACL4SSR_CATALOG_REVISION, ONLINE_RULE_CATALOG } from '../src/rules/ruleCatalog'

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

function find(provider: string, title: string) {
  return ONLINE_RULE_CATALOG.find((entry) => entry.provider === provider && entry.title === title)
}

function main(): void {
  check('在线规则目录包含 871 个上游列表', () => {
    assert.equal(ONLINE_RULE_CATALOG.length, 871)
  })

  check('ACL4SSR 与 blackmatrix7 数量正确', () => {
    assert.equal(ONLINE_RULE_CATALOG.filter((entry) => entry.provider === 'ACL4SSR').length, 182)
    assert.equal(ONLINE_RULE_CATALOG.filter((entry) => entry.provider === 'blackmatrix7').length, 689)
  })

  check('目录 id 与上游地址不重复', () => {
    assert.equal(new Set(ONLINE_RULE_CATALOG.map((entry) => entry.id)).size, ONLINE_RULE_CATALOG.length)
    assert.equal(new Set(ONLINE_RULE_CATALOG.map((entry) => entry.sourceURL)).size, ONLINE_RULE_CATALOG.length)
  })

  check('ACL4SSR 使用固定目录版本', () => {
    const entry = find('ACL4SSR', 'Apple')
    assert.ok(entry)
    assert.ok(entry.sourceURL.includes(ACL4SSR_CATALOG_REVISION))
    assert.ok(entry.sourceURL.endsWith('/Clash/Apple.list'))
    assert.equal(entry.category, '厂商服务')
  })

  check('blackmatrix7 使用 master 原始文件地址', () => {
    const entry = find('blackmatrix7', 'Netflix')
    assert.ok(entry)
    assert.ok(entry.sourceURL.startsWith('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/'))
    assert.ok(entry.sourceURL.endsWith('/Netflix.list'))
  })

  check('常用项保留中文名称与别名', () => {
    const netflix = find('blackmatrix7', 'Netflix')
    assert.ok(netflix)
    assert.ok(netflix.aliases.includes('奈飞'))
    assert.equal(netflix.category, '媒体与服务')

    const ad = find('blackmatrix7', 'Advertising')
    assert.ok(ad)
    assert.equal(ad.category, '广告与净化')
    assert.ok(ad.aliases.includes('广告拦截'))
  })

  check('每个条目都有分类和来源', () => {
    for (const entry of ONLINE_RULE_CATALOG) {
      assert.ok(entry.category.trim(), `${entry.id} 缺少分类`)
      assert.ok(/^https:\/\//.test(entry.sourceURL), `${entry.id} 来源不是 HTTPS`)
      assert.ok(entry.path.endsWith('.list'), `${entry.id} 路径不是列表文件`)
    }
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部在线规则目录检查通过')
}

main()
