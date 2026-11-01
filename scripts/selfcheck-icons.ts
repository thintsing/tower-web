// 自检：策略组图标导出、组名去 Emoji / 引用重命名，以及客户端能力矩阵修正。
// 用法：npm run selfcheck:icons
import assert from 'node:assert/strict'
import type { PolicyGroup, ProxyNode, RuleScheme } from '../src/models/types'
import { withPolicyGroupIcons } from '../src/generator/groupIcons'
import { clashSkippedCount, generateClashYAML } from '../src/generator/clashYaml'
import { generateSurge } from '../src/generator/surge'
import { generateLoon } from '../src/generator/loon'
import { generateQuanX } from '../src/generator/quanx'
import { generateEgern } from '../src/generator/egern'

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

const GROUPS: PolicyGroup[] = [
  { name: '🚀 节点选择', type: 'select', options: ['♻️ 自动选择', '🔁 故障转移', 'DIRECT'] },
  { name: '♻️ 自动选择', type: 'url-test', options: ['DIRECT'] },
  { name: '🔁 故障转移', type: 'fallback', options: ['DIRECT'] },
  { name: '⚖️ 负载均衡', type: 'load-balance', options: ['DIRECT'] },
  { name: '🇭🇰 香港节点', type: 'select', options: ['DIRECT'] },
  { name: '香港节点', type: 'select', options: ['DIRECT'] },
  { name: '🎯 全球直连', type: 'select', options: ['DIRECT'] },
  { name: '🛑 广告拦截', type: 'select', options: ['REJECT'] },
  { name: '🧩 条件组', type: 'relay', options: ['🚀 节点选择', '♻️ 自动选择'] },
]

const SCHEME: RuleScheme = {
  id: 'icon-test',
  name: 'icon-test',
  description: '',
  groups: GROUPS,
  rules: [
    { type: 'DOMAIN-SUFFIX', value: 'example.com', group: '🚀 节点选择' },
    { type: 'FINAL', value: '', group: '🚀 节点选择' },
  ],
}

const node = (id: string, kind: ProxyNode['kind']): ProxyNode => ({
  id,
  kind,
  name: id,
  server: `${id}.example.com`,
  port: 443,
  uuid: '00000000-0000-0000-0000-000000000001',
  password: 'pass',
  tls: true,
  skipCertificateVerification: false,
  rawURI: '',
})

const FLUENT_ROCKET = 'https://cdn.jsdelivr.net/gh/microsoft/fluentui-emoji@1ffb34c752ecf5d402f04cfb4b392c77f57c54bc/assets/Rocket/3D/rocket_3d.png'
const FLAG_HK = 'https://cdn.jsdelivr.net/gh/pengchujin/tower@425b0a7acce67b19f442d01a0722c2ae4cf8a477/Rulesets/PolicyGroupIcons/ac7e0eb3259eb62aa6100c435607e2fe03896a97/hk.png'
const CIRCLE_ROCKET = 'https://raw.githubusercontent.com/pengchujin/tower/b1cfedcb29b4a6498a7331ebf5021fc0d84d57ad/Rulesets/PolicyGroupIcons/FluentCircle/1f680.png'
const CIRCLE_HK = 'https://raw.githubusercontent.com/pengchujin/tower/b1cfedcb29b4a6498a7331ebf5021fc0d84d57ad/Rulesets/PolicyGroupIcons/FluentCircle/1f1ed-1f1f0.png'

check('Clash Verge 写图标、去 Emoji 并同步引用', () => {
  const result = withPolicyGroupIcons(SCHEME, 'clash-verge')
  const rocket = result.groups.find((group) => group.name === '节点选择')
  assert.ok(rocket)
  assert.equal(rocket.icon, FLUENT_ROCKET)
  assert.deepEqual(rocket.options, ['自动选择', '故障转移', 'DIRECT'])

  const region = result.groups.find((group) => group.name === '🇭🇰 香港节点')
  assert.ok(region)
  assert.equal(region.icon, FLAG_HK)
  const plainRegion = result.groups.find((group) => group.name === '香港节点')
  assert.ok(plainRegion)
  assert.equal(plainRegion.icon, FLAG_HK)

  const relay = result.groups.find((group) => group.name === '🧩 条件组')
  assert.ok(relay)
  assert.equal(relay.icon, undefined)
  assert.equal(result.rules[0].group, '节点选择')
})

check('Clash Apple 写 icon 但保留组名 Emoji', () => {
  const result = withPolicyGroupIcons(SCHEME, 'clash-apple')
  const rocket = result.groups.find((group) => group.name === '🚀 节点选择')
  assert.ok(rocket)
  assert.equal(rocket.icon, FLUENT_ROCKET)
  assert.equal(result.rules[0].group, '🚀 节点选择')
})

check('Surge 不写地区组图标，地区名保留国旗', () => {
  const result = withPolicyGroupIcons(SCHEME, 'surge')
  const rocket = result.groups.find((group) => group.name === '节点选择')
  assert.ok(rocket)
  assert.equal(rocket.icon, FLUENT_ROCKET)
  const region = result.groups.find((group) => group.name === '🇭🇰 香港节点')
  assert.ok(region)
  assert.equal(region.icon, undefined)
})

check('Quantumult X 使用圆底图标与圆旗', () => {
  const result = withPolicyGroupIcons(SCHEME, 'quanx')
  const rocket = result.groups.find((group) => group.name === '节点选择')
  assert.ok(rocket)
  assert.equal(rocket.icon, CIRCLE_ROCKET)
  const region = result.groups.find((group) => group.name === '🇭🇰 香港节点')
  assert.ok(region)
  assert.equal(region.icon, CIRCLE_HK)
})

check('去掉 Emoji 会撞名时保留原名', () => {
  const collision: RuleScheme = {
    ...SCHEME,
    groups: [
      { name: '🚀 节点选择', type: 'select', options: ['DIRECT'] },
      { name: '节点选择', type: 'select', options: ['DIRECT'] },
    ],
    rules: [{ type: 'FINAL', value: '', group: '🚀 节点选择' }],
  }
  const result = withPolicyGroupIcons(collision, 'clash-verge')
  assert.deepEqual(result.groups.map((group) => group.name), ['🚀 节点选择', '节点选择'])
  assert.equal(result.rules[0].group, '🚀 节点选择')
})

check('各客户端写出对应图标字段', () => {
  const verge = generateClashYAML([], SCHEME, { target: 'clash-verge' })
  assert.ok(verge.includes(`icon: ${JSON.stringify(FLUENT_ROCKET)}`))
  assert.ok(verge.includes('name: "节点选择"'))

  const surge = generateSurge([], SCHEME, { target: 'surge' })
  assert.ok(surge.text.includes(`icon-url=${FLUENT_ROCKET}`))
  assert.ok(!surge.text.includes(`icon-url=${FLAG_HK}`))

  const loon = generateLoon([], SCHEME, { target: 'loon' })
  assert.ok(loon.text.includes(`img-url=${FLUENT_ROCKET}`))

  const quanx = generateQuanX([], SCHEME, { target: 'quanx' })
  assert.ok(quanx.text.includes(`img-url=${CIRCLE_ROCKET}`))

  const egern = generateEgern([], SCHEME, { target: 'egern' })
  assert.ok(egern.text.includes(`icon: ${JSON.stringify(FLUENT_ROCKET)}`))
})

check('Loon 不再写 TUIC，但仍写 Hysteria 2', () => {
  const tuic = node('tuic', 'tuic')
  const hy2 = node('hy2', 'hysteria2')
  const loonTuic = generateLoon([tuic], SCHEME, { target: 'loon' })
  assert.equal(loonTuic.skipped, 1)
  assert.ok(!loonTuic.text.includes('TUIC'))
  const loonHy2 = generateLoon([hy2], SCHEME, { target: 'loon' })
  assert.equal(loonHy2.skipped, 0)
  assert.ok(loonHy2.text.includes('Hysteria2'))
})

check('Quantumult X 不再写 Hysteria 2 / TUIC', () => {
  const result = generateQuanX([node('hy2', 'hysteria2'), node('tuic', 'tuic')], SCHEME, { target: 'quanx' })
  assert.equal(result.skipped, 2)
  assert.ok(!result.text.includes('hysteria2='))
  assert.ok(!result.text.includes('tuic='))
})

check('Karing 不再写 Snell', () => {
  const snell: ProxyNode = {
    ...node('snell', 'snell'),
    cipher: undefined,
    uuid: undefined,
    tls: false,
  }
  assert.equal(clashSkippedCount([snell], 'karing'), 1)
  const text = generateClashYAML([snell], SCHEME, { target: 'karing' })
  assert.ok(!text.includes('type: snell'))
})

if (failures) {
  console.error(`\n${failures} 项检查失败`)
  process.exit(1)
}
console.log('\n全部策略组图标 / 能力矩阵检查通过')
