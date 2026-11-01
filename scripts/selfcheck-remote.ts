// 自检：代理集合与远程规则集跨客户端（Clash / Surge / Loon / QuanX / Egern / sing-box）。
// 用法：npm run selfcheck:remote
import assert from 'node:assert/strict'
import { CLIENTS, type ProxyNode, type RemoteSubscriptionEntry, type RuleScheme } from '../src/models/types'
import { generateConfig } from '../src/generator'
import { generateClashYAML } from '../src/generator/clashYaml'
import { generateLoon } from '../src/generator/loon'
import { generateSurge } from '../src/generator/surge'
import { formatSupportsProxyCollections, prepareSchemeForExport, remoteRuleSetCandidates } from '../src/generator/groups'

const base = { tls: false, skipCertificateVerification: false } as const
const localNode = (id: string, name: string): ProxyNode => ({
  ...base, id, kind: 'ss', name, server: 'ss.example.com', port: 8388,
  cipher: 'aes-256-gcm', password: 'p',
})
const remoteNode = (id: string, sourceID: string, name: string): ProxyNode => ({
  ...localNode(id, name), sourceID,
})

const nodes: ProxyNode[] = [
  localNode('local-1', '本地节点'),
  remoteNode('a-1', 'source-a', 'HK 香港'),
  remoteNode('a-2', 'source-a', '日本 东京'),
  remoteNode('b-1', 'source-b', 'US 美国'),
]
const remoteSubscriptions: RemoteSubscriptionEntry[] = [
  { id: 'source-a', name: '机场 A', url: 'https://a.example/sub' },
  { id: 'source-b', name: '机场 B', url: 'https://b.example/sub' },
]

const scheme: RuleScheme = {
  id: 'remote-check',
  name: 'remote-check',
  description: '',
  groups: [
    { name: '节点选择', type: 'select', options: ['DIRECT'], nodeFilter: '.*' },
    { name: '香港', type: 'select', options: ['DIRECT'], nodeFilter: 'HK|香港' },
    { name: '自动选择', type: 'url-test', options: [], nodeFilter: '.*' },
  ],
  rules: [
    { type: 'RULE-SET', value: 'https://rules.example/classic.list', group: '节点选择', ruleSetFormat: 'classical' },
    { type: 'RULE-SET', value: 'https://rules.example/provider.yaml', group: '节点选择', ruleSetFormat: 'yaml' },
    { type: 'RULE-SET', value: 'https://rules.example/mrs.mrs', group: '节点选择', ruleSetFormat: 'mrs', ruleSetBehavior: 'domain' },
    { type: 'RULE-SET', value: 'https://rules.example/quanx.list', group: '节点选择', ruleSetFormat: 'quanx' },
    { type: 'RULE-SET', value: 'https://rules.example/egern.yaml', group: '节点选择', ruleSetFormat: 'egern' },
    { type: 'RULE-SET', value: 'https://rules.example/source.json', group: '节点选择', ruleSetFormat: 'singbox' },
    { type: 'RULE-SET', value: 'https://rules.example/rule.srs', group: '节点选择', ruleSetFormat: 'singbox-binary' },
    { type: 'DOMAIN-SUFFIX', value: 'example.com', group: '节点选择' },
    { type: 'FINAL', group: '节点选择' },
  ],
}

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

const client = (target: string) => CLIENTS.find((item) => item.target === target)!
const generate = (target: string) => {
  const info = client(target)
  const out = generateConfig(info, nodes, scheme, {
    contentMode: 'full',
    remoteSubscriptions,
  })
  return { ...out, json: out.extension === 'json' ? JSON.parse(out.text) : undefined }
}
const section = (text: string, name: string): string => {
  const start = text.indexOf(`[${name}]`)
  if (start < 0) return ''
  const rest = text.slice(start + name.length + 2)
  const next = rest.search(/\n\[[^\n]+\]/)
  return next < 0 ? rest : rest.slice(0, next)
}

async function main(): Promise<void> {
  check('载体能力：Loon / QuanX / Egern 支持代理集合', () => {
    assert.equal(formatSupportsProxyCollections('loon'), true)
    assert.equal(formatSupportsProxyCollections('quanx'), true)
    assert.equal(formatSupportsProxyCollections('egern'), true)
    assert.equal(formatSupportsProxyCollections('json'), false)
    assert.equal(formatSupportsProxyCollections('base64'), false)
  })

  const clash = generate('clash-verge')
  check('Clash：代理集合与原生规则集格式', () => {
    assert.equal(clash.remoteSourceCount, 2)
    assert.match(clash.text, /proxy-providers:/)
    assert.match(clash.text, /https:\/\/a\.example\/sub/)
    assert.match(clash.text, /tower-rule-set-\d+:/)
    assert.match(clash.text, /format: mrs/)
    assert.match(clash.text, /behavior: domain/)
    assert.match(clash.text, /format: yaml/)
    assert.doesNotMatch(clash.text, /rules\.example\/egern\.yaml/)
    assert.doesNotMatch(clash.text, /rules\.example\/source\.json/)
    assert.doesNotMatch(clash.text, /rules\.example\/rule\.srs/)
    assert.doesNotMatch(clash.text, /name: "HK 香港"/)
  })

  const shadowrocket = generate('shadowrocket')
  check('Shadowrocket：无代理集合，跳过 MRS', () => {
    assert.equal(shadowrocket.remoteSourceCount, 0)
    assert.equal(shadowrocket.exportedNodeCount, 4)
    assert.doesNotMatch(shadowrocket.text, /proxy-providers:/)
    assert.doesNotMatch(shadowrocket.text, /format: mrs/)
    assert.match(shadowrocket.text, /rules\.example\/classic\.list/)
  })

  const surge = generate('surge')
  check('Surge：代理集合与经典规则集', () => {
    assert.equal(surge.remoteSourceCount, 2)
    assert.match(surge.text, /policy-path="https:\/\/a\.example\/sub"/)
    assert.ok(surge.text.includes('include-other-group="机场 A,机场 B"'))
    assert.match(surge.text, /RULE-SET,https:\/\/rules\.example\/classic\.list/)
    assert.doesNotMatch(surge.text, /rules\.example\/quanx\.list/)
    assert.doesNotMatch(surge.text, /rules\.example\/egern\.yaml/)
    assert.doesNotMatch(surge.text, /HK 香港/)
  })

  const loon = generate('loon')
  check('Loon：远程代理、筛选与远程规则', () => {
    assert.equal(loon.remoteSourceCount, 2)
    assert.match(section(loon.text, 'Remote Proxy'), /机场 A = https:\/\/a\.example\/sub/)
    assert.match(section(loon.text, 'Remote Proxy'), /机场 B = https:\/\/b\.example\/sub/)
    assert.match(section(loon.text, 'Remote Filter'), /NameRegex, 机场 A, FilterKey = "HK\|香港"/)
    assert.match(loon.text, /节点选择 = select, DIRECT, 本地节点, 机场 A,机场 B/)
    assert.match(section(loon.text, 'Remote Rule'), /rules\.example\/classic\.list/)
    assert.doesNotMatch(section(loon.text, 'Remote Rule'), /provider\.yaml/)
    assert.doesNotMatch(section(loon.text, 'Proxy'), /HK 香港/)
    assert.doesNotMatch(section(loon.text, 'Rule'), /RULE-SET/)
  })

  const quanx = generate('quanx')
  check('QuanX：[server_remote] 与 policy 资源筛选', () => {
    assert.equal(quanx.remoteSourceCount, 2)
    assert.match(section(quanx.text, 'server_remote'), /https:\/\/a\.example\/sub, tag=机场 A/)
    assert.ok(quanx.text.includes('resource-tag-regex=^(?:机场 A|机场 B)$'))
    assert.ok(quanx.text.includes('server-tag-regex=HK|香港'))
    assert.match(section(quanx.text, 'filter_remote'), /rules\.example\/quanx\.list/)
    assert.doesNotMatch(section(quanx.text, 'filter_remote'), /classic\.list/)
    assert.doesNotMatch(section(quanx.text, 'server_local'), /HK 香港/)
    assert.ok(quanx.text.indexOf('[policy]') < quanx.text.indexOf('[server_remote]'))
    assert.ok(quanx.text.indexOf('[server_remote]') < quanx.text.indexOf('[server_local]'))
  })

  const egern = generate('egern')
  check('Egern：组 urls / filter 与原生规则集', () => {
    assert.equal(egern.remoteSourceCount, 2)
    assert.ok(egern.text.includes('      urls:\n        - "https://a.example/sub"\n        - "https://b.example/sub"'))
    assert.ok(egern.text.includes('      filter: "HK|香港"'))
    assert.match(egern.text, /rules\.example\/egern\.yaml/)
    assert.doesNotMatch(egern.text, /rules\.example\/classic\.list/)
    assert.doesNotMatch(egern.text, /match: "HK 香港"/)
  })

  const singbox = generate('sing-box')
  check('sing-box：source / binary 规则集与 http_clients', () => {
    assert.equal(singbox.remoteSourceCount, 0)
    assert.match(singbox.text, /"rule_set": \[/)
    assert.match(singbox.text, /"format": "source"/)
    assert.match(singbox.text, /"format": "binary"/)
    assert.match(singbox.text, /"http_clients": \[/)
    assert.match(singbox.text, /"default_http_client": "tower-rule-set"/)
    assert.doesNotMatch(singbox.text, /rules\.example\/classic\.list/)
    assert.doesNotMatch(singbox.text, /rules\.example\/egern\.yaml/)
  })
  const hiddify = generate('hiddify')
  check('Hiddify：不用 1.14 专属 http_clients，下载走代理出站', () => {
    assert.doesNotMatch(hiddify.text, /"http_clients"/)
    assert.match(hiddify.text, /rules\.example\/rule\.srs/)
    assert.match(hiddify.text, /"download_detour": "节点选择"/)
  })

  // ---------- 规则集快照 → 远程引用 ----------
  const snapshotScheme: RuleScheme = {
    id: 'snapshot',
    name: 'snapshot',
    description: '',
    groups: [{ name: '节点选择', type: 'select', options: ['DIRECT'], nodeFilter: '.*' }],
    ruleSets: [{
      id: 'set-1',
      name: 'ACL4SSR 广告',
      group: '节点选择',
      sourceKind: 'library',
      sourceRef: 'ACL4SSR_BanAD.list',
      format: 'classical',
      rules: [{ type: 'DOMAIN-SUFFIX', value: 'ads.example', group: '节点选择' }],
    }],
    rules: [
      { type: 'DOMAIN-SUFFIX', value: 'local.example', group: '节点选择' },
      { type: 'FINAL', group: '节点选择' },
    ],
  }
  check('规则集快照：YAML / Surge 直接引用', () => {
    const yaml = prepareSchemeForExport(snapshotScheme, {}, {
      preferRuleSets: true, format: 'yaml', target: 'clash-verge',
    })
    assert.equal(yaml.rules[0]?.type, 'RULE-SET')
    assert.equal(yaml.rules[0]?.ruleSetFormat, 'classical')
    const surge = prepareSchemeForExport(snapshotScheme, {}, {
      preferRuleSets: true, format: 'surge', target: 'surge',
    })
    assert.equal(surge.rules[0]?.type, 'RULE-SET')
  })
  check('规则集快照：Loon 有后续本地规则时展开', () => {
    const loon = prepareSchemeForExport(snapshotScheme, {}, {
      preferRuleSets: true, format: 'loon', target: 'loon',
    })
    assert.equal(loon.rules.some((rule) => rule.type === 'RULE-SET'), false)
    assert.ok(loon.rules.some((rule) => rule.value === 'ads.example'))
  })
  check('规则集快照：Loon 只有 FINAL 时可远程引用', () => {
    const finalOnly = {
      ...snapshotScheme,
      rules: [{ type: 'FINAL', group: '节点选择' }],
    }
    const loon = prepareSchemeForExport(finalOnly, {}, {
      preferRuleSets: true, format: 'loon', target: 'loon',
    })
    assert.equal(loon.rules[0]?.type, 'RULE-SET')
  })
  check('规则集快照：Loon 不引用含不支持类型的列表', () => {
    const processSet: RuleScheme = {
      ...snapshotScheme,
      ruleSets: [{
        ...snapshotScheme.ruleSets![0],
        rules: [{ type: 'PROCESS-NAME', value: 'curl', group: '节点选择' }],
      }],
      rules: [{ type: 'FINAL', group: '节点选择' }],
    }
    const loon = prepareSchemeForExport(processSet, {}, {
      preferRuleSets: true, format: 'loon', target: 'loon',
    })
    assert.equal(loon.rules.some((rule) => rule.type === 'RULE-SET'), false)
    assert.ok(loon.rules.some((rule) => rule.type === 'PROCESS-NAME'))
  })
  check('规则集快照：经典列表转换为 QuanX / Egern / sing-box 托管产物', () => {
    const finalOnly = { ...snapshotScheme, rules: [{ type: 'FINAL', group: '节点选择' }] }
    for (const [format, target, expected] of [
      ['quanx', 'quanx', 'quanx'],
      ['egern', 'egern', 'egern'],
      ['json', 'sing-box', 'singbox'],
    ] as const) {
      const prepared = prepareSchemeForExport(finalOnly, {}, {
        preferRuleSets: true, format, target,
      })
      assert.equal(prepared.rules[0]?.type, 'RULE-SET', format)
      assert.equal(prepared.rules[0]?.ruleSetFormat, expected, format)
      assert.ok(prepared.rules[0]?.value?.startsWith('/api/ruleset?'), prepared.rules[0]?.value)
      assert.ok(prepared.rules[0]?.value?.includes(`format=${format === 'json' ? 'singbox' : format}`))
      assert.ok(prepared.rules[0]?.value?.includes('file=ACL4SSR_BanAD.list'))
    }
  })
  check('规则集快照：无法无损转换时保持内联', () => {
    const finalOnly = { ...snapshotScheme, rules: [{ type: 'FINAL', group: '节点选择' }] }
    const processSet: RuleScheme = {
      ...finalOnly,
      ruleSets: [{
        ...snapshotScheme.ruleSets![0],
        rules: [{ type: 'PROCESS-NAME', value: 'curl', group: '节点选择' }],
      }],
    }
    for (const [format, target] of [['quanx', 'quanx'], ['egern', 'egern'], ['json', 'sing-box']] as const) {
      const prepared = prepareSchemeForExport(processSet, {}, {
        preferRuleSets: true, format, target,
      })
      assert.equal(prepared.rules.some((rule) => rule.type === 'RULE-SET'), false, format)
      assert.ok(prepared.rules.some((rule) => rule.type === 'PROCESS-NAME'), format)
    }
  })
  check('规则集快照：MRS 只给支持它的 Clash 目标', () => {
    const mrsSet: RuleScheme = {
      ...snapshotScheme,
      ruleSets: [{
        ...snapshotScheme.ruleSets![0],
        sourceKind: 'url',
        format: 'mrs',
        ruleSetBehavior: 'domain',
        sourceRef: 'https://rules.example/domain.mrs',
      }],
      rules: [{ type: 'FINAL', group: '节点选择' }],
    }
    for (const target of ['clash-verge', 'clash'] as const) {
      const prepared = prepareSchemeForExport(mrsSet, {}, {
        preferRuleSets: true, format: 'yaml', target,
      })
      assert.equal(prepared.rules[0]?.type, 'RULE-SET', target)
    }
    for (const target of ['karing', 'shadowrocket'] as const) {
      const prepared = prepareSchemeForExport(mrsSet, {}, {
        preferRuleSets: true, format: 'yaml', target,
      })
      assert.equal(prepared.rules.some((rule) => rule.type === 'RULE-SET'), false, target)
    }
  })
  check('本地规则集：Clash / Stash 写成内联 provider', () => {
    const localScheme: RuleScheme = {
      id: 'inline',
      name: 'inline',
      description: '',
      groups: [{ name: '节点选择', type: 'select', options: ['DIRECT'], nodeFilter: '.*' }],
      ruleSets: [
        {
          id: 'local-domain',
          name: '本地域名',
          group: '节点选择',
          sourceKind: 'local',
          sourceRef: 'local-domain',
          rules: [
            { type: 'DOMAIN-SUFFIX', value: 'ads.example', group: '节点选择' },
            { type: 'DOMAIN', value: 'foo.example', group: '节点选择' },
          ],
        },
        {
          id: 'local-ip',
          name: '本地 IP',
          group: '节点选择',
          sourceKind: 'local',
          sourceRef: 'local-ip',
          rules: [
            { type: 'IP-CIDR', value: '1.2.3.0/24', group: '节点选择', options: ['no-resolve'], noResolve: true },
          ],
        },
      ],
      rules: [{ type: 'FINAL', group: '节点选择' }],
    }
    const prepared = prepareSchemeForExport(localScheme, {}, {
      preferRuleSets: true, format: 'yaml', target: 'clash-verge',
    })
    const text = generateClashYAML([], prepared, { contentMode: 'full', target: 'clash-verge' })
    assert.match(text, /type: inline/)
    assert.match(text, /behavior: domain/)
    assert.match(text, /behavior: ipcidr/)
    assert.ok(text.includes('+.ads.example'))
    assert.match(text, /RULE-SET,tower-local-1,节点选择/)
    assert.match(text, /RULE-SET,tower-local-2,节点选择,no-resolve/)
    assert.doesNotMatch(text, /DOMAIN-SUFFIX,ads\.example,节点选择/)

    const karing = prepareSchemeForExport(localScheme, {}, {
      preferRuleSets: true, format: 'yaml', target: 'karing',
    })
    assert.equal(karing.rules.some((rule) => rule.inlineSet), false)
    const karingText = generateClashYAML([], karing, { contentMode: 'full', target: 'karing' })
    assert.doesNotMatch(karingText, /type: inline/)
    assert.match(karingText, /DOMAIN-SUFFIX,ads\.example,节点选择/)
  })

  check('本地规则集：Surge 混合域名/IP 保持逐条展开', () => {
    const localScheme: RuleScheme = {
      id: 'inline-surge',
      name: 'inline-surge',
      description: '',
      groups: [{ name: '节点选择', type: 'select', options: ['DIRECT'], nodeFilter: '.*' }],
      ruleSets: [{
        id: 'local-surge',
        name: 'Surge 本地',
        group: '节点选择',
        sourceKind: 'local',
        sourceRef: 'local-surge',
        rules: [
          { type: 'DOMAIN-SUFFIX', value: 'surge.example', group: '节点选择' },
          { type: 'IP-CIDR', value: '10.0.0.0/8', group: '节点选择', options: ['no-resolve'], noResolve: true },
        ],
      }],
      rules: [{ type: 'FINAL', group: '节点选择' }],
    }
    const prepared = prepareSchemeForExport(localScheme, {}, {
      preferRuleSets: true, format: 'surge', target: 'surge',
    })
    // 域名 + IP 混排时保持逐条展开，避免一个 no-resolve 标记影响域名规则。
    assert.equal(prepared.rules.some((rule) => rule.inlineSet), false)
    const text = generateSurge([], prepared, { contentMode: 'full', target: 'surge' }).text
    assert.equal(text.includes('[Ruleset tower-local-1]'), false)
    assert.match(text, /DOMAIN-SUFFIX,surge\.example,节点选择/)
    assert.match(text, /IP-CIDR,10\.0\.0\.0\/8,节点选择,no-resolve/)
  })

  check('本地规则集：仅域名时 Surge 使用原生内联集', () => {
    const localScheme: RuleScheme = {
      id: 'inline-surge-domain',
      name: 'inline-surge-domain',
      description: '',
      groups: [{ name: '节点选择', type: 'select', options: ['DIRECT'], nodeFilter: '.*' }],
      ruleSets: [{
        id: 'local-surge-domain',
        name: 'Surge 域名',
        group: '节点选择',
        sourceKind: 'local',
        sourceRef: 'local-surge-domain',
        rules: [{ type: 'DOMAIN-SUFFIX', value: 'surge.example', group: '节点选择' }],
      }],
      rules: [{ type: 'FINAL', group: '节点选择' }],
    }
    const prepared = prepareSchemeForExport(localScheme, {}, {
      preferRuleSets: true, format: 'surge', target: 'surge',
    })
    const text = generateSurge([], prepared, { contentMode: 'full', target: 'surge' }).text
    assert.match(text, /RULE-SET,tower-local-1,节点选择/)
    assert.match(text, /\[Ruleset tower-local-1]/)
    assert.match(text, /DOMAIN-SUFFIX,surge\.example/)
  })

  check('本地规则集：Loon 不支持内联集时保持逐条规则', () => {
    const localScheme: RuleScheme = {
      id: 'inline-loon',
      name: 'inline-loon',
      description: '',
      groups: [{ name: '节点选择', type: 'select', options: ['DIRECT'], nodeFilter: '.*' }],
      ruleSets: [{
        id: 'local-loon',
        name: 'Loon 本地',
        group: '节点选择',
        sourceKind: 'local',
        sourceRef: 'local-loon',
        rules: [{ type: 'DOMAIN-SUFFIX', value: 'loon.example', group: '节点选择' }],
      }],
      rules: [{ type: 'FINAL', group: '节点选择' }],
    }
    const prepared = prepareSchemeForExport(localScheme, {}, {
      preferRuleSets: true, format: 'loon', target: 'loon',
    })
    assert.equal(prepared.rules.some((rule) => rule.inlineSet), false)
    const text = generateLoon([], prepared, { contentMode: 'full', target: 'loon' }).text
    assert.match(text, /DOMAIN-SUFFIX,loon\.example,节点选择/)
    assert.doesNotMatch(text, /tower-local/)
  })

  check('规则集快照：原生方言按目标引用', () => {
    const egernSet: RuleScheme = {
      ...snapshotScheme,
      ruleSets: [{
        ...snapshotScheme.ruleSets![0],
        sourceKind: 'url',
        format: 'egern',
        sourceRef: 'https://rules.example/egern.yaml',
        rules: [{ type: 'DOMAIN', value: 'egern.example', group: '节点选择' }],
      }],
      rules: [{ type: 'FINAL', group: '节点选择' }],
    }
    const egern = prepareSchemeForExport(egernSet, {}, {
      preferRuleSets: true, format: 'egern', target: 'egern',
    })
    assert.equal(egern.rules[0]?.ruleSetFormat, 'egern')
    const yaml = prepareSchemeForExport(egernSet, {}, {
      preferRuleSets: true, format: 'yaml', target: 'clash-verge',
    })
    assert.equal(yaml.rules.some((rule) => rule.type === 'RULE-SET'), false)
    const candidates = remoteRuleSetCandidates(egernSet, {
      preferRuleSets: true, format: 'egern', target: 'egern',
    })
    assert.equal(candidates.filter((item) => item.remote).length, 1)
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部远程规则集 / 代理集合检查通过')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
