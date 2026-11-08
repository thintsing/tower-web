// Loyalsoldier/clash-rules 内置方案：只保存 provider 的 URL / behavior / interval，
// 不保存任何规则正文。导出 Clash / mihomo 系时写成 rule-providers + RULE-SET，
// 客户端按 URL 自行下载；其他客户端由塔台服务的 /api/ruleset 托管转换，
// 拿不到对外地址时该载体硬阻断。
import type { PolicyGroup, RuleScheme, SchemeRuleSet } from '../models/types'
import type { SchemeMeta } from './scheme'

export const LOYALSONDIER_SCHEME_ID = 'loyalsoldier-clash-rules'
const PROVIDER_BASE = 'https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/'
const PROVIDER_INTERVAL = 86400

/** 与 ACL4SSR 方案共用的组名，界面可显示图标、导出时沿用既有映射。 */
const GROUP = {
  proxy: '🚀 节点选择',
  auto: '♻️ 自动选择',
  direct: '🎯 全球直连',
  reject: '🛑 全球拦截',
  apple: '🍎 苹果服务',
  telegram: '📲 电报信息',
  final: '🐟 漏网之鱼',
} as const

function groups(): PolicyGroup[] {
  return [
    { name: GROUP.proxy, type: 'select', options: [GROUP.auto, 'DIRECT'], nodeFilter: '.*' },
    {
      name: GROUP.auto,
      type: 'url-test',
      options: [],
      nodeFilter: '.*',
      url: 'http://www.gstatic.com/generate_204',
      interval: 300,
      tolerance: 50,
    },
    { name: GROUP.direct, type: 'select', options: ['DIRECT', GROUP.proxy, GROUP.auto] },
    { name: GROUP.reject, type: 'select', options: ['REJECT', 'DIRECT'] },
    { name: GROUP.apple, type: 'select', options: [GROUP.proxy, GROUP.direct, 'DIRECT'] },
    { name: GROUP.telegram, type: 'select', options: [GROUP.proxy, GROUP.direct] },
    { name: GROUP.final, type: 'select', options: [GROUP.proxy, GROUP.direct, GROUP.auto], nodeFilter: '.*' },
  ]
}

interface ProviderSpec {
  name: string
  label: string
  group: string
  behavior: 'domain' | 'ipcidr' | 'classical'
  /** 需要随 RULE-SET 写出 no-resolve 的 IP 列表。 */
  noResolve?: boolean
}

/**
 * 顺序是方案的一部分，不能随意调整：
 * applications 最先；private / lancidr 必须在 reject 与任何代理组之前；
 * reject 紧跟其后；direct 在 gfw 之前；cncidr 在 gfw 之前且必须 no-resolve；
 * tld-not-cn 在 gfw 之后；telegramcidr 最后；FINAL 永远兜底。
 */
const PROVIDERS: ProviderSpec[] = [
  { name: 'applications', label: '应用分流（applications）', group: GROUP.direct, behavior: 'classical' },
  { name: 'private', label: '私有网络（private）', group: GROUP.direct, behavior: 'domain' },
  { name: 'lancidr', label: '局域网 IP（lancidr）', group: GROUP.direct, behavior: 'ipcidr', noResolve: true },
  { name: 'reject', label: '全球拦截（reject）', group: GROUP.reject, behavior: 'domain' },
  { name: 'icloud', label: 'iCloud（icloud）', group: GROUP.apple, behavior: 'domain' },
  { name: 'apple', label: 'Apple（apple）', group: GROUP.apple, behavior: 'domain' },
  { name: 'google', label: 'Google（google）', group: GROUP.proxy, behavior: 'domain' },
  { name: 'proxy', label: '代理域名（proxy）', group: GROUP.proxy, behavior: 'domain' },
  { name: 'direct', label: '直连域名（direct）', group: GROUP.direct, behavior: 'domain' },
  { name: 'cncidr', label: '国内 IP（cncidr）', group: GROUP.direct, behavior: 'ipcidr', noResolve: true },
  { name: 'gfw', label: 'GFW（gfw）', group: GROUP.proxy, behavior: 'domain' },
  { name: 'tld-not-cn', label: '非中国 TLD（tld-not-cn）', group: GROUP.proxy, behavior: 'domain' },
  { name: 'telegramcidr', label: '电报 IP（telegramcidr）', group: GROUP.telegram, behavior: 'ipcidr', noResolve: true },
]

function providerRuleSets(): SchemeRuleSet[] {
  return PROVIDERS.map((spec) => ({
    id: `${LOYALSONDIER_SCHEME_ID}:${spec.name}`,
    name: spec.label,
    group: spec.group,
    // 硬约束：不保存正文。rules 恒为空，客户端按 URL 自行下载。
    rules: [],
    sourceKind: 'url',
    sourceRef: `${PROVIDER_BASE}${spec.name}.txt`,
    // 这批 .txt 实际是 YAML `payload:`，写成 text 会导致客户端拒绝整份 provider。
    format: 'yaml',
    ruleSetBehavior: spec.behavior,
    providerOnly: true,
    providerName: spec.name,
    ruleSetOptions: spec.noResolve ? ['no-resolve'] : undefined,
    interval: PROVIDER_INTERVAL,
  }))
}

export function buildLoyalsoldierScheme(meta: SchemeMeta): RuleScheme {
  return {
    id: meta.id,
    name: meta.name,
    description: meta.description,
    groups: groups(),
    rules: [{ type: 'FINAL', group: GROUP.final }],
    ruleSets: providerRuleSets(),
  }
}
