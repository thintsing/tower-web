// 主流程（导入 → 方案 → 检查 → 导出）的纯逻辑，便于自检与界面复用。

export type FlowStepKey = 'import' | 'scheme' | 'check' | 'export'

export type FlowStepStatus = 'done' | 'todo' | 'blocked'

export interface FlowInput {
  sourceCount: number
  manualNodeCount: number
  nodeCount: number
  enabledNodeCount: number
  excludedNodeCount: number
  /** 订阅刷新/解析失败的原因，已去重。 */
  sourceErrors: string[]
  hasExportable: boolean
  schemeReady: boolean
  schemeName?: string
  schemeCustomized?: boolean
  lintErrors: number
  lintWarnings: number
  published: boolean
  exportedAt?: number
}

export interface FlowStep {
  key: FlowStepKey
  index: number
  title: string
  /** 窄屏或步骤条中的短标题。 */
  short: string
  status: FlowStepStatus
  /** 这一步现在是什么情况，展示在步骤条下方。 */
  detail: string
  /** 用户可以立刻做的事；没有则为空。 */
  actionLabel?: string
}

export type EmptyReasonCode =
  | 'ready'
  | 'no-source'
  | 'source-error'
  | 'no-nodes'
  | 'all-excluded'
  | 'all-sources-off'

export interface EmptyReason {
  code: EmptyReasonCode
  title: string
  detail: string
  action: 'add-source' | 'retry-source' | 'enable-nodes' | 'none'
}

function sourceErrorText(errors: string[]): string {
  const first = errors[0]?.trim()
  if (!first) return ''
  const extra = errors.length - 1
  return extra > 0 ? `${first}（另有 ${extra} 个订阅失败）` : first
}

/** 解释「节点池为什么没有可用节点」，供订阅页与检查页共用。 */
export function explainNodePool(input: Pick<FlowInput, 'sourceCount' | 'manualNodeCount' | 'nodeCount' | 'enabledNodeCount' | 'excludedNodeCount' | 'sourceErrors'>): EmptyReason {
  const { sourceCount, manualNodeCount, nodeCount, enabledNodeCount, excludedNodeCount, sourceErrors } = input
  const hasSource = sourceCount > 0 || manualNodeCount > 0
  if (!hasSource) {
    return {
      code: 'no-source',
      title: '还没有订阅或自有节点',
      detail: '先添加一条订阅链接；也可以手动添加节点或扫码导入。',
      action: 'add-source',
    }
  }
  if (enabledNodeCount > 0) {
    return {
      code: 'ready',
      title: '节点池已有可用节点',
      detail: `本地 ${enabledNodeCount} 个节点可用于测速和导出。`,
      action: 'none',
    }
  }
  const errorText = sourceErrorText(sourceErrors)
  if (nodeCount === 0 && errorText) {
    return {
      code: 'source-error',
      title: '订阅没有返回可解析的节点',
      detail: `最近的刷新失败：${errorText}。检查链接是否过期，或换一个网络环境重试。`,
      action: 'retry-source',
    }
  }
  if (nodeCount === 0) {
    return {
      code: 'no-nodes',
      title: '订阅解析到 0 个节点',
      detail: '链接可能返回了 HTML 错误页，或不是受支持的订阅格式。刷新后仍为空就换一条订阅。',
      action: 'retry-source',
    }
  }
  if (sourceCount > 0 && manualNodeCount === 0) {
    return {
      code: 'all-excluded',
      title: excludedNodeCount > 0 ? `全部 ${nodeCount} 个节点都已排除` : '所有订阅都已停用',
      detail: excludedNodeCount > 0
        ? '恢复至少一个节点，或在订阅里重新启用，才能测速和导出。'
        : '在订阅卡片里打开至少一条订阅，节点才会进入节点池。',
      action: 'enable-nodes',
    }
  }
  return {
    code: 'all-excluded',
    title: '没有启用的节点',
    detail: '节点可能都被排除了；在订阅页恢复节点后重试。',
    action: 'enable-nodes',
  }
}

/** 根据当前数据推导四步主线的状态；顺序固定，界面只读。 */
export function buildFlow(input: FlowInput): FlowStep[] {
  const pool = explainNodePool(input)
  const hasSource = input.sourceCount > 0 || input.manualNodeCount > 0

  let importStatus: FlowStepStatus = 'todo'
  let importDetail = '还没有订阅或自有节点'
  let importAction: string | undefined = '添加订阅'
  if (hasSource) {
    if (input.enabledNodeCount > 0) {
      importStatus = 'done'
      importDetail = `节点池 ${input.enabledNodeCount} 个可用节点${input.sourceErrors.length ? ` · ${input.sourceErrors.length} 个订阅失败` : ''}`
      importAction = undefined
    } else {
      importStatus = 'blocked'
      importDetail = pool.title
      importAction = pool.action === 'retry-source' ? '重试订阅' : pool.action === 'enable-nodes' ? '恢复节点' : '检查订阅'
    }
  }

  let schemeStatus: FlowStepStatus = 'todo'
  let schemeDetail = '规则方案加载中'
  let schemeAction: string | undefined
  if (input.schemeReady) {
    schemeStatus = 'done'
    schemeDetail = input.schemeCustomized
      ? `自定义方案「${input.schemeName ?? '未命名'}」`
      : `默认方案「${input.schemeName ?? '默认'}」，可直接使用`
    schemeAction = '调整方案'
  }

  let checkStatus: FlowStepStatus = 'todo'
  let checkDetail = '还没有检查规则结果'
  let checkAction: string | undefined = '运行检查'
  if (!input.schemeReady || input.enabledNodeCount === 0) {
    checkStatus = 'blocked'
    checkDetail = input.enabledNodeCount === 0 ? '先导入并启用节点' : '等待规则方案加载'
    checkAction = input.enabledNodeCount === 0 ? '去导入' : undefined
  } else if (input.lintErrors > 0) {
    checkStatus = 'blocked'
    checkDetail = `${input.lintErrors} 个错误待处理${input.lintWarnings > 0 ? ` · ${input.lintWarnings} 个提醒` : ''}`
    checkAction = '查看并修复'
  } else {
    checkStatus = 'done'
    checkDetail = input.lintWarnings > 0 ? `无阻断项 · ${input.lintWarnings} 个提醒可忽略` : '无阻断项'
    checkAction = '再查一条流量'
  }

  let exportStatus: FlowStepStatus = 'todo'
  let exportDetail = '还没有导出或发布配置'
  let exportAction: string | undefined = '去导出'
  if (!input.hasExportable) {
    exportStatus = 'blocked'
    exportDetail = input.enabledNodeCount === 0 ? '没有可用节点' : '当前客户端没有可导出的节点'
    exportAction = '检查节点'
  } else if (input.published || input.exportedAt) {
    exportStatus = 'done'
    exportDetail = input.published ? '订阅链接已生成' : '配置已导出'
    exportAction = '再导出一次'
  }

  return [
    { key: 'import', index: 1, title: '导入订阅或配置', short: '导入', status: importStatus, detail: importDetail, actionLabel: importAction },
    { key: 'scheme', index: 2, title: '选规则方案', short: '方案', status: schemeStatus, detail: schemeDetail, actionLabel: schemeAction },
    { key: 'check', index: 3, title: '检查结果', short: '检查', status: checkStatus, detail: checkDetail, actionLabel: checkAction },
    { key: 'export', index: 4, title: '导出客户端配置', short: '导出', status: exportStatus, detail: exportDetail, actionLabel: exportAction },
  ]
}

/** 推荐下一步：第一个未完成的步骤。前面步骤未完成时，后面的阻断只是连带反应。 */
export function recommendedStep(steps: FlowStep[]): FlowStep | undefined {
  return steps.find((step) => step.status !== 'done') ?? steps[steps.length - 1]
}
