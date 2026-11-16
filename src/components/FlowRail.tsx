import type { FlowStep, FlowStepKey } from '../flow/flow'
import { recommendedStep } from '../flow/flow'

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
 * 四步主线：宽屏展示完整步骤条，窄屏收成「当前步骤 + 进度 + 下一步」。
 * 不是 tab 的替代品：它是“该做什么”的导航，左侧栏仍是工作区切换。
 */
export function FlowRail({ steps, current, onGo }: FlowRailProps) {
  const currentIndex = steps.findIndex((step) => step.key === current)
  const currentStep = currentIndex >= 0 ? steps[currentIndex] : undefined
  // 优先走到当前步骤的下一步；已经到最后一步时回落到推荐步骤，避免按钮消失。
  const nextStep = steps[currentIndex + 1] ?? recommendedStep(steps)
  const showNext = !!nextStep && nextStep.key !== current
  const progress = currentStep ? `${String(currentStep.index).padStart(2, '0')}/${steps.length}` : ''
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
      {currentStep && (
        <div className={`flow-compact is-${currentStep.status}`}>
          <span className="flow-compact-progress num" aria-label={`进度 ${progress}`}>{progress}</span>
          <span className="flow-compact-body">
            <span className="flow-compact-title">{currentStep.short}</span>
            <span className="flow-compact-status">{STATUS_LABEL[currentStep.status]}</span>
          </span>
          {showNext && (
            <button
              type="button"
              className="flow-compact-next"
              onClick={() => onGo(nextStep!.key)}
            >
              下一步：{nextStep!.short}
              <span aria-hidden="true">→</span>
            </button>
          )}
        </div>
      )}
    </nav>
  )
}
