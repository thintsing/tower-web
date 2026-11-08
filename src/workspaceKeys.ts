// 服务器版工作区会落盘的顶层字段：只同步「多设备应该一致」的数据。
// 这份清单同时用于 store 的只读护栏和工作区逐字段校验，避免两处漂移。
export const WORKSPACE_STATE_KEYS = [
  'sources',
  'nodes',
  'customSchemes',
  'localRuleSets',
  'builtinSchemeOverrides',
  'schemeSnapshots',
  'snapshotSeq',
  'ruleSetExclusions',
  'selectedSchemeID',
  'policySelections',
  'exportConfigName',
  'tailnets',
  'tailnetAuthKeys',
] as const

export type WorkspaceStateKey = typeof WORKSPACE_STATE_KEYS[number]

/** 界面展示用的字段名；报告必须说清是哪个键坏了。 */
export const WORKSPACE_FIELD_LABELS: Record<WorkspaceStateKey, string> = {
  sources: '订阅',
  nodes: '节点',
  customSchemes: '自定义方案',
  localRuleSets: '本地规则集',
  builtinSchemeOverrides: '内置方案固化指针',
  schemeSnapshots: '固化快照',
  snapshotSeq: '快照序号',
  ruleSetExclusions: '规则集屏蔽表',
  selectedSchemeID: '当前方案',
  policySelections: '策略选择',
  exportConfigName: '配置名称',
  tailnets: 'Tailscale 内网',
  tailnetAuthKeys: 'Tailscale 密钥',
}

const WORKSPACE_KEY_SET = new Set<string>(WORKSPACE_STATE_KEYS)

export function isWorkspaceStateKey(key: string): key is WorkspaceStateKey {
  return WORKSPACE_KEY_SET.has(key)
}
