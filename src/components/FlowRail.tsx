import type { FlowStep, FlowStepKey } from '../flow/flow'

interface FlowRailProps {
  steps: FlowStep[]
  current: FlowStepKey
  onGo: (key: FlowStepKey) => void
}

const STATUS_LABEL: Record<FlowStep['status'], string> = {
  done: '已完成',
  todo: '待开始',
  blocked: '需处理',
}

/**
 * 四步主线：始终展示，当前步骤高亮，已完成的步骤可以点回去。
 * 不是 tab 的替代品：它是“该做什么”的导航，左侧栏仍是工作区切换。
 */
export function FlowRail({ steps, current, onGo }: FlowRailProps) {
  const currentStep = steps.find((step) => step.key === current)
  return (
    <nav className="flow-rail" aria-label="主流程">
      <ol className="flow-rail-list">
        {steps.map((step) => {
          const active = step.key === current
          return (
            <li key={step.key}>
              <button
                type="button"
                className={`flow-step is-${step.status}${active ? ' is-current' : ''}`}
                aria-current={active ? 'step' : undefined}
                onClick={() => onGo(step.key)}
                title={step.detail}
              >
                <span className="flow-step-index num">{String(step.index).padStart(2, '0')}</span>
                <span className="flow-step-body">
                  <span className="flow-step-title">{step.title}</span>
                  <span className="flow-step-detail">{step.detail}</span>
                </span>
                <span className="flow-step-status">{STATUS_LABEL[step.status]}</span>
              </button>
            </li>
          )
        })}
      </ol>
      {currentStep && (
        <div className="flow-rail-hint">
          <span className="flow-rail-hint-label">当前</span>
          <span>{currentStep.title}</span>
          {currentStep.actionLabel && (
            <span className="flow-rail-hint-action">{currentStep.actionLabel}</span>
          )}
        </div>
      )}
    </nav>
  )
}
