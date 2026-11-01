// 自检：自有节点导入、去重、改名与解析失败提示。
// 用法：npm run selfcheck:manual
import assert from 'node:assert/strict'
import { prepareManualNodes } from '../src/manualNodes'

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

const SS = 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@ss.example.com:8388#NodeA'
const CLASH = `
proxies:
  - name: Clash SS
    type: ss
    server: ss1.example.com
    port: 8389
    cipher: aes-256-gcm
    password: clash-pass
  - name: Clash VLESS
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    tls: true
    network: ws
`

function main(): void {
  check('单条节点链接导入为自有节点', () => {
    const result = prepareManualNodes(SS, '我的节点', [])
    assert.equal(result.nodes.length, 1)
    const node = result.nodes[0]
    assert.equal(node.isManual, true)
    assert.equal(node.isEnabled, true)
    assert.equal(node.sourceID, undefined)
    assert.equal(node.name, '我的节点')
    assert.equal(node.kind, 'ss')
  })

  check('再次导入同一节点会跳过重复项', () => {
    const first = prepareManualNodes(SS, '', [])
    const second = prepareManualNodes(SS, '', first.nodes)
    assert.equal(second.nodes.length, 0)
    assert.equal(second.duplicates, 1)
  })

  check('Clash YAML 可一次导入多个自有节点', () => {
    const result = prepareManualNodes(CLASH, '批量节点', [])
    assert.equal(result.nodes.length, 2)
    assert.equal(result.rejected, 0)
    assert.deepEqual(result.nodes.map((node) => node.name), ['Clash SS', 'Clash VLESS'])
    assert.ok(result.nodes.every((node) => node.isManual && node.isEnabled === true))
  })

  check('无法识别的文本会报解析失败而不是留下空节点', () => {
    const result = prepareManualNodes('这不是节点内容', '错误内容', [])
    assert.equal(result.nodes.length, 0)
    assert.ok(result.rejected > 0)
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部自有节点检查通过')
}

main()
