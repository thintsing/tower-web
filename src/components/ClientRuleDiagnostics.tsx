// 导出页规则诊断：按客户端列出规则白名单、规则集引用方式和被跳过的规则原因。
import { useMemo } from 'react'
import { analyzeRuleCompatibility } from '../generator/compatibility'
import { SUBSCRIPTION_FORMAT_TITLES } from '../generator'
import { subFormatFor, type ClientInfo, type ClientTarget, type ExportContentMode, type ProxyNode, type RuleScheme, type RuleSetExclusionTable } from '../models/types'
import { targetRuleTypes } from '../rules/capabilities'
import { effectiveContentMode } from '../util/exportSelection'

export function ClientRuleDiagnostics({
  clients,
  scheme,
  nodes,
  preferRuleSets,
  exportContentMode,
  exportContentModes,
  ruleSetExclusions,
  hostedBaseURL,
}: {
  clients: ClientInfo[]
  scheme: RuleScheme
  nodes: ProxyNode[]
  preferRuleSets: boolean
  exportContentMode: ExportContentMode
  exportContentModes: Partial<Record<ClientTarget, ExportContentMode>>
  ruleSetExclusions: RuleSetExclusionTable
  hostedBaseURL?: string
}) {
  const rows = useMemo(() => clients.map((client) => {
    const contentMode = effectiveContentMode(client, exportContentModes, exportContentMode)
    return {
      client,
      contentMode,
      report: analyzeRuleCompatibility(client, scheme, {
        preferRuleSets,
        contentMode,
        ruleSetExclusions,
        hostedBaseURL,
        nodes,
      }),
      types: targetRuleTypes(client.target),
    }
  }), [clients, scheme, nodes, preferRuleSets, exportContentMode, exportContentModes, ruleSetExclusions, hostedBaseURL])

  return (
    <>
      {rows.map(({ client, contentMode, report, types }) => {
        const format = subFormatFor(client)
        const nodeOnly = report.nodeOnly || contentMode === 'nodes'
        return (
          <div key={client.target} className="sub-url-wrap" style={{ marginTop: 12 }}>
            <div className="sub-url-label">
              {client.name} · {SUBSCRIPTION_FORMAT_TITLES[format]}
              {nodeOnly ? ' · 仅节点' : ' · 完整配置'}
            </div>
            {nodeOnly ? (
              <div className="hint">该载体不写规则，只导出节点。</div>
            ) : (
              <>
                <div className="hint">
                  规则集 {report.ruleSetCount} 组：远程引用 {report.remoteRuleSets}、展开 {report.inlineRuleSets}；
                  跳过 {report.skipped} 条规则。
                </div>
                {report.note && <div className="hint">{report.note}</div>}
                {report.ruleSetNote && <div className="hint">{report.ruleSetNote}</div>}
                {report.providerOnlyBlocked && (
                  <div className="error">{report.providerOnlyNote}</div>
                )}
                {report.emptyGroupsBlocked && (
                  <div className="error">{report.emptyGroupsNote}</div>
                )}
                <details style={{ marginTop: 6 }}>
                  <summary className="hint">查看支持规则类型（{types.length}）</summary>
                  <div className="hint" style={{ marginTop: 4 }}>{types.join(' · ')}</div>
                </details>
              </>
            )}
          </div>
        )
      })}
    </>
  )
}
