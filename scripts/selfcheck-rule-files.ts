// 自检：独立规则文件导出（.list / .yaml / .json）。
// 用法：npm run selfcheck:rule-files
import assert from 'node:assert/strict'
import { CLIENTS, type RuleScheme } from '../src/models/types'
import { generateRuleFile } from '../src/generator/ruleFiles'
import { analyzeRuleCompatibility } from '../src/generator/compatibility'
import { targetRuleTypes } from '../src/rules/capabilities'

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

const scheme: RuleScheme = {
  id: 'selfcheck-rules',
  name: '自检规则',
  description: '',
  groups: [{ name: '节点选择', type: 'select', options: ['DIRECT'] }],
  rules: [
    { type: 'DOMAIN-SUFFIX', value: 'example.com', group: '节点选择' },
    { type: 'GEOSITE', value: 'netflix', group: '节点选择' },
    { type: 'FINAL', group: '节点选择' },
  ],
  customRules: [
    { type: 'DOMAIN', value: 'custom.example', group: '节点选择' },
  ],
  ruleSets: [
    {
      id: 'local-set',
      name: '本地列表',
      group: '节点选择',
      rules: [{ type: 'IP-CIDR', value: '10.0.0.0/8', group: '节点选择', noResolve: true }],
      sourceKind: 'local',
    },
    {
      id: 'provider-set',
      name: '远程 provider',
      group: '节点选择',
      rules: [],
      sourceKind: 'url',
      sourceRef: 'https://example.com/domain.yaml',
      format: 'yaml',
      ruleSetBehavior: 'domain',
      providerOnly: true,
      providerName: 'domain',
      interval: 86400,
    },
  ],
}

check('.list 只写规则行，不带策略列和 FINAL', () => {
  const result = generateRuleFile(scheme, { target: 'clash-verge', format: 'list' })
  assert.equal(result.extension, 'list')
  assert.match(result.text, /^DOMAIN,custom\.example$/m)
  assert.match(result.text, /^DOMAIN-SUFFIX,example\.com$/m)
  assert.match(result.text, /^IP-CIDR,10\.0\.0\.0\/8,no-resolve$/m)
  assert.match(result.text, /^RULE-SET,https:\/\/example\.com\/domain\.yaml$/m)
  assert.doesNotMatch(result.text, /节点选择/)
  assert.doesNotMatch(result.text, /FINAL|MATCH/)
  // mihomo 支持 GEOSITE；Surge 不支持，见下一项。
  assert.match(result.text, /^GEOSITE,netflix$/m)
})

check('.yaml 写成 Clash classical provider payload', () => {
  const result = generateRuleFile(scheme, { target: 'clash-verge', format: 'yaml' })
  assert.equal(result.extension, 'yaml')
  assert.match(result.text, /^payload:$/m)
  assert.match(result.text, /- "DOMAIN-SUFFIX,example\.com"/)
  // provider YAML 不能再嵌套 RULE-SET。
  assert.doesNotMatch(result.text, /RULE-SET/)
  assert.equal(result.skipped, 1)
  assert.equal(result.referencedRuleSets, 1)
})

check('.json 保留类型、参数与分组，且不含 FINAL', () => {
  const result = generateRuleFile(scheme, { target: 'clash-verge', format: 'json' })
  const parsed = JSON.parse(result.text) as {
    name: string
    target: string
    rules: { type: string; value: string; group?: string; noResolve?: boolean }[]
  }
  assert.equal(parsed.name, '自检规则')
  assert.equal(parsed.target, 'clash-verge')
  assert.equal(parsed.rules.some((rule) => rule.type === 'FINAL'), false)
  const ip = parsed.rules.find((rule) => rule.type === 'IP-CIDR')
  assert.ok(ip)
  assert.equal(ip!.noResolve, true)
  assert.equal(ip!.group, '节点选择')
  assert.ok(parsed.rules.some((rule) => rule.type === 'RULE-SET' && rule.value === 'https://example.com/domain.yaml'))
})

check('目标客户端不支持的规则计入 skipped', () => {
  const result = generateRuleFile(scheme, { target: 'surge', format: 'list' })
  assert.doesNotMatch(result.text, /GEOSITE/)
  assert.ok(result.skipped >= 1)
  // Surge 不读 YAML provider，引用也会被跳过。
  assert.doesNotMatch(result.text, /RULE-SET,https:\/\/example\.com\/domain\.yaml/)
})

check('没有规则时输出空载体而不是崩溃', () => {
  const empty: RuleScheme = {
    id: 'empty',
    name: '空方案',
    description: '',
    groups: [{ name: '节点选择', type: 'select', options: ['DIRECT'] }],
    rules: [{ type: 'FINAL', group: '节点选择' }],
  }
  const list = generateRuleFile(empty, { target: 'clash-verge', format: 'list' })
  assert.equal(list.text, '')
  assert.equal(list.ruleCount, 0)
  const yaml = generateRuleFile(empty, { target: 'clash-verge', format: 'yaml' })
  assert.match(yaml.text, /payload: \[\]/)
})

check('按客户端诊断列出规则白名单与跳过类型', () => {
  const surge = CLIENTS.find((client) => client.target === 'surge')
  const mihomo = CLIENTS.find((client) => client.target === 'clash-verge')
  const v2box = CLIENTS.find((client) => client.target === 'v2box')
  assert.ok(surge && mihomo && v2box)

  const report = analyzeRuleCompatibility(surge!, scheme, { contentMode: 'full', preferRuleSets: false })
  assert.ok(report.skipped >= 1)
  assert.ok(report.unsupportedTypes.includes('GEOSITE'))
  assert.ok(report.note?.includes('GEOSITE'))

  const surgeTypes = targetRuleTypes('surge')
  assert.ok(surgeTypes.includes('DOMAIN-SUFFIX'))
  assert.equal(surgeTypes.includes('GEOSITE'), false)
  assert.ok(targetRuleTypes('clash-verge').includes('GEOSITE'))

  const nodeReport = analyzeRuleCompatibility(v2box!, scheme, { contentMode: 'nodes' })
  assert.equal(nodeReport.nodeOnly, true)
  assert.equal(nodeReport.skipped, 0)
})

console.log(failures === 0 ? '\n全部规则文件自检通过' : `\n${failures} 项规则文件自检失败`)
process.exit(failures === 0 ? 0 : 1)
