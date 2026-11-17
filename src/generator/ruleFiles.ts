// 独立规则文件：只导出编译后的规则，不生成客户端整份配置。
import { CLIENTS, subFormatFor, type ClientTarget, type RuleScheme, type RoutingRule } from '../models/types'
import { targetSupportsRule } from '../rules/capabilities'
import { supportsRuleSetReference } from '../rules/remoteFormats'
import { prepareSchemeForExport, type PrepareSchemeOptions } from './groups'

export type RuleFileFormat = 'list' | 'yaml' | 'json'

export interface RuleFileOptions {
  target: ClientTarget
  format: RuleFileFormat
  name?: string
  ruleSetExclusions?: PrepareSchemeOptions['ruleSetExclusions']
}

export interface RuleFileResult {
  text: string
  extension: RuleFileFormat
  mime: string
  ruleCount: number
  skipped: number
  /** 无法展开、以 RULE-SET 引用保留的规则集数量（YAML 会跳过并计入 skipped）。 */
  referencedRuleSets: number
}

/** 规则集引用行不带策略列；普通规则保留 no-resolve 等参数。 */
function ruleLine(rule: RoutingRule): string {
  if (rule.raw) return rule.raw
  const options = [...(rule.options ?? [])]
  if (rule.noResolve && !options.some((option) => option.toLowerCase() === 'no-resolve')) {
    options.push('no-resolve')
  }
  return [rule.type, rule.value ?? '', ...options].filter((part, index) => index < 2 || part).join(',')
}

/**
 * 把方案展开成单条规则。FINAL 不写入独立文件（由引用它的配置决定兜底策略），
 * 目标客户端不支持的规则计入 skipped；provider-only 规则集没有正文，保留
 * RULE-SET 引用（YAML provider 不支持嵌套 RULE-SET，因此只计入 skipped）。
 */
export function generateRuleFile(
  scheme: RuleScheme,
  options: RuleFileOptions,
): RuleFileResult {
  const client = CLIENTS.find((item) => item.target === options.target)
  const format = client ? subFormatFor(client) : undefined
  const prepared = prepareSchemeForExport(scheme, {}, {
    preferRuleSets: false,
    format,
    target: options.target,
    ruleSetExclusions: options.ruleSetExclusions,
  })
  const rules: RoutingRule[] = []
  let skipped = 0
  let referencedRuleSets = 0
  for (const rule of prepared.rules) {
    if (rule.type === 'FINAL') continue
    if (!targetSupportsRule(options.target, rule.type)) {
      skipped += 1
      continue
    }
    if (rule.type === 'RULE-SET') {
      if (!format || !supportsRuleSetReference(rule, format, options.target)) {
        skipped += 1
        continue
      }
      referencedRuleSets += 1
      if (options.format === 'yaml') {
        skipped += 1
        continue
      }
    }
    rules.push(rule)
  }
  const lines = rules.map(ruleLine)
  const name = options.name?.trim() || scheme.name || 'tower'
  if (options.format === 'list') {
    return {
      text: lines.length ? `${lines.join('\n')}\n` : '',
      extension: 'list',
      mime: 'text/plain; charset=utf-8',
      ruleCount: rules.length,
      skipped,
      referencedRuleSets,
    }
  }
  if (options.format === 'yaml') {
    const payload = lines.length
      ? `\n${lines.map((line) => `  - ${JSON.stringify(line)}`).join('\n')}`
      : ' []'
    return {
      text: `# ${name} rules\npayload:${payload}\n`,
      extension: 'yaml',
      mime: 'text/yaml; charset=utf-8',
      ruleCount: rules.length,
      skipped,
      referencedRuleSets,
    }
  }
  const jsonRules = rules.map((rule) => ({
    type: rule.type,
    value: rule.value ?? '',
    ...(rule.options?.length ? { options: rule.options } : {}),
    ...(rule.noResolve ? { noResolve: true } : {}),
    ...(rule.group ? { group: rule.group } : {}),
    ...(rule.type === 'RULE-SET' && rule.ruleSetFormat ? { ruleSetFormat: rule.ruleSetFormat } : {}),
    ...(rule.type === 'RULE-SET' && rule.ruleSetBehavior ? { ruleSetBehavior: rule.ruleSetBehavior } : {}),
  }))
  return {
    text: `${JSON.stringify({ name, target: options.target, rules: jsonRules }, null, 2)}\n`,
    extension: 'json',
    mime: 'application/json; charset=utf-8',
    ruleCount: rules.length,
    skipped,
    referencedRuleSets,
  }
}
