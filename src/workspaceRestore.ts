// 历史回滚前置条件与中止原因。
// 抽成纯模块，自检可以覆盖「冲突 / 只读 / 离线时不能点确认」和「本机未落盘就中止回滚」。

export interface RestoreGate {
  mode: 'unknown' | 'local' | 'server'
  state: string
  readOnly: boolean
  conflict: boolean
  busy: boolean
}

/** 为空表示可以回滚；否则是按钮的禁用说明。 */
export function restoreBlockedReason(gate: RestoreGate): string {
  if (gate.conflict) return '请先处理工作区冲突，再回滚历史版本'
  if (gate.readOnly) return '工作区当前只读，无法回滚'
  if (gate.mode !== 'server' || gate.state !== 'online') return '服务端未连接，无法回滚'
  if (gate.busy) return '正在处理上一次操作'
  return ''
}

export function restoreAllowed(gate: RestoreGate): boolean {
  return restoreBlockedReason(gate) === ''
}

/** `flushWorkspaceNow` 返回 false 时，回滚必须中止，不能让服务端覆盖本机未保存的改动。 */
export function restoreAbortReason(flushOk: boolean): string {
  return flushOk
    ? ''
    : '工作区有尚未写入服务端的改动，已中止回滚；请先恢复连接或处理冲突，再试一次。'
}
