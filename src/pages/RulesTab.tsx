// 规则配置页：只负责页面骨架，各区块由独立组件渲染。
import { useRulesTabController, type RulesTabProps } from '../rules/useRulesTabController'
import { RulesSchemeSection } from '../components/rules/RulesSchemeSection'
import { RulesGroupsSection } from '../components/rules/RulesGroupsSection'
import { RulesRuleSetsSection } from '../components/rules/RulesRuleSetsSection'
import { RulesToolsSection } from '../components/rules/RulesToolsSection'
import { RulesDialogs } from '../components/rules/RulesDialogs'

export function RulesTab(props: RulesTabProps) {
  const controller = useRulesTabController(props)

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">分流规则 · 03</div>
          <h1>配置分流规则</h1>
          <div className="sub">选择规则方案、调整策略组顺序，或添加自定义规则</div>
        </div>
      </div>

      {controller.flash && <div className="flash" role="status" aria-live="polite">{controller.flash}</div>}

      <RulesSchemeSection controller={controller} />
      <RulesGroupsSection controller={controller} />
      <RulesRuleSetsSection controller={controller} />
      <RulesToolsSection controller={controller} onGo={props.onGo} />
      <RulesDialogs controller={controller} />
    </div>
  )
}
