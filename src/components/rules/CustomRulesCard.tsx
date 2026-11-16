// 自定义规则卡片：逐条列出方案内自定义规则，支持删除。
import type { RoutingRule, RuleScheme } from '../../models/types'
import { READONLY_NOTE, writeGuard } from '../../util/readOnlyUi'
import { groupDisplayName } from '../GroupIcon'

export function CustomRulesCard({
  scheme,
  readOnly,
  showGroupEmoji,
  onAdd,
  onRemove,
}: {
  scheme: RuleScheme
  readOnly: boolean
  showGroupEmoji: boolean
  onAdd: () => void
  onRemove: (rule: RoutingRule) => void
}) {
  return (
    <div className="card">
      <div className="card-head">
        <h3>自定义规则</h3>
        <button className="btn ghost" {...writeGuard(readOnly)} onClick={onAdd}>+ 添加规则</button>
      </div>
      {(scheme.customRules?.length ?? 0) > 0 ? (
        <ul className="custom-rule-list">
          {scheme.customRules!.map((rule) => (
            <li key={`${rule.group}-${rule.type}-${rule.value ?? ''}`}>
              <span className="pill">{groupDisplayName(rule.group, showGroupEmoji)}</span>
              <span className="mono rule-type">{rule.type}</span>
              <span className="mono rule-value">{rule.value ?? '—'}</span>
              {rule.noResolve && <span className="hint">no-resolve</span>}
              <button
                className="icon-btn"
                aria-label={`删除规则 ${rule.type} ${rule.value ?? ''}`}
                title={readOnly ? READONLY_NOTE : '删除这条自定义规则'}
                {...writeGuard(readOnly)}
                onClick={() => onRemove(rule)}
              >×</button>
            </li>
          ))}
        </ul>
      ) : (
        <div className="hint">还没有自定义规则。添加的规则会排在方案规则最前；内置方案会先复制一份再修改。</div>
      )}
    </div>
  )
}
