// 自检：四步主线的推进条件、规则诊断的相关性排序与修复动作。
// 用法：npm run selfcheck:flow
import assert from 'node:assert/strict'
import { buildFlow, explainNodePool, recommendedStep } from '../src/flow/flow'
import { applyFixAction, buildFixActions, describeRuleSetChange, rankLintIssues } from '../src/rules/diagnosis'
import { compileScheme, explainWith } from '../src/rules/ruleExplain'
import type { SchemeLintIssue } from '../src/rules/schemeLint'
import type { RuleSetHistory } from '../src/rules/ruleSetHistory'
import type { ProxyNode, RuleScheme } from '../src/models/types'

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

const base = { tls: false, skipCertificateVerification: false } as const
const NODES: ProxyNode[] = [
  { ...base, id: 'hk', kind: 'ss', name: '香港 01', server: 'hk.example.com', port: 8388, cipher: 'aes-256-gcm', password: 'p1' },
]

function makeScheme(): RuleScheme {
  return {
    id: 'flow-scheme',
    name: '流程自检方案',
    description: '',
    groups: [
      { name: '节点选择', type: 'select', options: ['自动选择', 'DIRECT'], nodeFilter: '' },
      { name: '自动选择', type: 'url-test', options: [], nodeFilter: '.*' },
      { name: '未使用组', type: 'select', options: [], nodeFilter: '' },
    ],
    rules: [
      { type: 'DOMAIN-SUFFIX', value: 'google.com', group: '节点选择' },
      { type: 'DOMAIN-SUFFIX', value: 'google.com', group: '节点选择' },
      { type: 'GEOIP', value: 'CN', group: 'DIRECT' },
    ],
    ruleSets: [
      {
        id: 'set-google',
        name: 'Google 规则集',
        group: '节点选择',
        sourceKind: 'local',
        sourceRef: 'local-google',
        rules: [
          { type: 'DOMAIN-SUFFIX', value: 'google.com', group: '节点选择' },
          { type: 'DOMAIN', value: 'mail.google.com', group: '节点选择' },
        ],
      },
    ],
    updatedAt: 1,
  }
}

function issue(partial: Partial<SchemeLintIssue> & Pick<SchemeLintIssue, 'id' | 'code' | 'message' | 'location'>): SchemeLintIssue {
  return { level: 'warn', ...partial }
}

check('空节点池：没有订阅时给出添加引导', () => {
  const reason = explainNodePool({
    sourceCount: 0, manualNodeCount: 0, nodeCount: 0, enabledNodeCount: 0, excludedNodeCount: 0, sourceErrors: [],
  })
  assert.equal(reason.code, 'no-source')
  assert.equal(reason.action, 'add-source')
})

check('空节点池：有订阅但 0 节点时区分解析失败与全被排除', () => {
  const failed = explainNodePool({
    sourceCount: 1, manualNodeCount: 0, nodeCount: 0, enabledNodeCount: 0, excludedNodeCount: 0, sourceErrors: ['HTTP 403'],
  })
  assert.equal(failed.code, 'source-error')
  assert.equal(failed.action, 'retry-source')
  assert.match(failed.detail, /HTTP 403/)

  const excluded = explainNodePool({
    sourceCount: 1, manualNodeCount: 0, nodeCount: 3, enabledNodeCount: 0, excludedNodeCount: 3, sourceErrors: [],
  })
  assert.equal(excluded.code, 'all-excluded')
  assert.equal(excluded.action, 'enable-nodes')
})

check('空节点池：只有被停用的自有节点时不再提示添加订阅', () => {
  const reason = explainNodePool({
    sourceCount: 0, manualNodeCount: 1, nodeCount: 1, enabledNodeCount: 0, excludedNodeCount: 1, sourceErrors: [],
  })
  assert.equal(reason.code, 'all-excluded')
  assert.equal(reason.action, 'enable-nodes')
  assert.match(reason.title, /没有启用/)
})

check('四步主线：只有被停用的自有节点时第 1 步阻断并提示恢复', () => {
  const steps = buildFlow({
    sourceCount: 0, manualNodeCount: 1, nodeCount: 1, enabledNodeCount: 0, excludedNodeCount: 1, sourceErrors: [],
    hasExportable: false, schemeReady: true, schemeName: '默认方案', schemeCustomized: false,
    lintErrors: 0, lintWarnings: 0, published: false,
  })
  assert.equal(steps[0].status, 'blocked')
  assert.equal(steps[0].detail, '没有启用的节点')
  assert.equal(steps[0].actionLabel, '恢复节点')
})

check('四步主线：没有订阅时第 1 步待开始，检查与导出被阻断', () => {
  const steps = buildFlow({
    sourceCount: 0, manualNodeCount: 0, nodeCount: 0, enabledNodeCount: 0, excludedNodeCount: 0, sourceErrors: [],
    hasExportable: false, schemeReady: true, schemeName: '默认方案', schemeCustomized: false,
    lintErrors: 0, lintWarnings: 0, published: false,
  })
  assert.deepEqual(steps.map((step) => step.status), ['todo', 'done', 'blocked', 'blocked'])
  assert.equal(recommendedStep(steps)?.key, 'import')
})

check('四步主线：有节点但有 lint 错误时，第 3 步阻断并指向修复', () => {
  const steps = buildFlow({
    sourceCount: 1, manualNodeCount: 0, nodeCount: 1, enabledNodeCount: 1, excludedNodeCount: 0, sourceErrors: [],
    hasExportable: true, schemeReady: true, schemeName: '默认方案', schemeCustomized: false,
    lintErrors: 2, lintWarnings: 1, published: false,
  })
  assert.equal(steps[0].status, 'done')
  assert.equal(steps[2].status, 'blocked')
  assert.match(steps[2].detail, /2 个错误/)
  assert.equal(recommendedStep(steps)?.key, 'check')
})

check('四步主线：发布后四步全部完成', () => {
  const steps = buildFlow({
    sourceCount: 1, manualNodeCount: 1, nodeCount: 2, enabledNodeCount: 2, excludedNodeCount: 0, sourceErrors: [],
    hasExportable: true, schemeReady: true, schemeName: '我的方案', schemeCustomized: true,
    lintErrors: 0, lintWarnings: 3, published: true,
  })
  assert.deepEqual(steps.map((step) => step.status), ['done', 'done', 'done', 'done'])
})

check('相关性排序：命中规则本身排在最前，无关项置底', () => {
  const scheme = makeScheme()
  const compiled = compileScheme({ scheme, nodes: NODES, policySelections: {}, localRuleSets: [] })
  const explain = explainWith(compiled, 'www.google.com')
  assert.ok(explain.match)

  const issues: SchemeLintIssue[] = [
    issue({ id: 'unrelated', code: 'emptyGroup', message: '未使用组没有候选', location: { kind: 'group', group: '未使用组' } }),
    issue({
      id: 'same-rule', code: 'duplicateRuleSameGroup', message: '同组重复规则',
      location: { kind: 'rule', group: '节点选择', rule: 'DOMAIN-SUFFIX,google.com', ruleIndex: 0 },
    }),
    issue({
      id: 'after-match', code: 'missingRuleTarget', message: '后续规则指向不存在的组',
      location: { kind: 'rule', group: '节点选择', rule: 'DOMAIN-SUFFIX,example.com', ruleIndex: 4 },
    }),
  ]
  const ranked = rankLintIssues(issues, explain, scheme)
  assert.equal(ranked[0].issue.id, 'same-rule')
  assert.ok(ranked[0].reasons.includes('与命中规则是同一条'))
  assert.equal(ranked[ranked.length - 1].issue.id, 'unrelated')
})

check('规则集上下文：没有历史时明确返回 no-history，有历史时能判断命中规则是否变化', () => {
  const scheme = makeScheme()
  const compiled = compileScheme({ scheme, nodes: NODES, policySelections: {}, localRuleSets: [] })
  const explain = explainWith(compiled, 'www.google.com')
  const set = scheme.ruleSets?.[0]
  assert.ok(set && explain.match)

  const noHistory = describeRuleSetChange(set, {}, explain.match.rule)
  assert.equal(noHistory?.matched, 'no-history')
  assert.equal(noHistory?.setName, 'Google 规则集')

  const history: RuleSetHistory = {
    'local-google': {
      previous: {
        at: 1,
        count: 1,
        digest: 'x',
        rules: [{ type: 'DOMAIN', value: 'mail.google.com' }],
      },
    },
  }
  const changed = describeRuleSetChange(set, history, explain.match.rule)
  assert.equal(changed?.matched, 'added')
  assert.equal(changed?.added, 1)
})

check('修复动作：同组重复给出一键删除，跨组重复需要用户决定', () => {
  const sameGroup = issue({
    id: 'dup', code: 'duplicateRuleSameGroup', message: '同组重复规则',
    location: { kind: 'rule', group: '节点选择', rule: 'DOMAIN-SUFFIX,google.com', ruleIndex: 1 },
  })
  const actions = buildFixActions(sameGroup)
  assert.equal(actions[0].kind, 'delete-rule')
  assert.equal(actions[0].safe, true)

  // 跨组重复删掉后一条会悄悄改变路由，不能进一键删除。
  const crossGroup = issue({
    id: 'cross', code: 'duplicateRule', message: '跨组重复规则',
    location: { kind: 'rule', group: '国外媒体', rule: 'DOMAIN-SUFFIX,google.com', ruleIndex: 1 },
  })
  const crossActions = buildFixActions(crossGroup)
  assert.equal(crossActions[0].kind, 'manual')
  assert.equal(crossActions[0].safe, undefined)

  const missing = issue({
    id: 'missing', code: 'missingRuleTarget', message: '规则指向不存在的组',
    location: { kind: 'rule', group: '不存在的组', rule: 'DOMAIN-SUFFIX,x.com', ruleIndex: 3 },
  })
  const manual = buildFixActions(missing)
  assert.equal(manual[0].kind, 'manual')
  assert.match(manual[0].detail, /改绑/)
})

check('一键修复：删除同组重复规则后方案只剩一条且其它规则不受影响', () => {
  const scheme = makeScheme()
  const duplicate = issue({
    id: 'dup', code: 'duplicateRuleSameGroup', message: '同组重复规则',
    location: { kind: 'rule', group: '节点选择', rule: 'DOMAIN-SUFFIX,google.com', ruleIndex: 1 },
  })
  const action = buildFixActions(duplicate)[0]
  const result = applyFixAction(scheme, action)
  assert.ok(result)
  assert.equal(result?.removedFrom, 'scheme')
  const google = result?.scheme.rules.filter((rule) => rule.value === 'google.com')
  assert.equal(google?.length, 1)
  assert.equal(result?.scheme.rules.length, 2)
})

if (failures > 0) {
  console.error(`\n${failures} 个自检失败`)
  process.exit(1)
}
console.log('\n全部通过')
