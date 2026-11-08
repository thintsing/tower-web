// 「未保存」状态的纯逻辑：失败次数、退避间隔和提示文案。
// 放在独立模块里，自检可以不启动浏览器就验证失败→重试→再失败的可见行为。
export const SAVE_RETRY_BASE_MS = 1_000
export const SAVE_RETRY_MAX_MS = 30_000

export interface SaveStateView {
  state: 'online' | 'unsaved'
  failures: number
  message: string
}

export function initialSaveState(): SaveStateView {
  return { state: 'online', failures: 0, message: '' }
}

/** 每次失败都增加计数：同一错误反复出现时必须还能被用户看见。 */
export function nextSaveFailure(previous: SaveStateView, message: string): SaveStateView {
  const failures = previous.failures + 1
  return {
    state: 'unsaved',
    failures,
    message: unsavedMessage(message, failures),
  }
}

export function nextSaveSuccess(): SaveStateView {
  return initialSaveState()
}

/** 500ms 防抖之后从 1s 起翻倍，封顶 30s；容量问题不会因为重试变好。 */
export function saveRetryDelay(failures: number): number {
  const exponent = Math.max(0, Math.min(failures - 1, 5))
  return Math.min(SAVE_RETRY_MAX_MS, SAVE_RETRY_BASE_MS * 2 ** exponent)
}

export function unsavedMessage(message: string, failures: number): string {
  return `${message}（自动重试已失败 ${failures} 次，仍在继续）`
}

/**
 * 未保存横幅永远不允许被「知道了」永久压掉。
 * 其它 info 横幅可以按文案或问题签名隐藏，这里刻意返回 true。
 */
export function shouldShowUnsavedBanner(
  state: SaveStateView['state'],
  _dismissedSignature = '',
): boolean {
  return state === 'unsaved'
}
