// 409 冲突的判定与文案：先留住本机草稿，再让用户明确选择，不替用户决定。
// 放在纯模块里，自检可以直接覆盖「标签页 / 客户端」区分、刷新后恢复规则、
// 探测失败后的重试链，以及「服务端为空」时不允许反向上传本机数据。

export type ConflictSource = 'tab' | 'client'

/** 另一个标签页写入后多久内仍算「同浏览器的另一个标签页」。 */
export const CONFLICT_PEER_WINDOW_MS = 60_000

export interface ConflictDraft {
  /** 进入冲突时本机工作区内容的签名；用于判断本机是否还是当年那份草稿。 */
  signature: string
  source: ConflictSource
  /** 冲突时服务端最新版本号；「保留本机」会用它（或再探测到的更新版本）重试。 */
  serverVersion: number
  at: number
  /** 记录冲突的标签页。只有它（或内容完全一致的旧标记）可以清除这条标记。 */
  tabId?: string
  /** 用户选择「改用服务端」时服务端工作区为空；需要再确认一次才清空本机。 */
  serverEmpty?: boolean
}

/** 同浏览器标签页会写本机 localStorage；最近写过就说明冲突来自标签页而不是设备。 */
export function conflictSourceFromPeerWrite(
  lastPeerWriteAt: number | undefined,
  now = Date.now(),
  windowMs = CONFLICT_PEER_WINDOW_MS,
): ConflictSource {
  if (typeof lastPeerWriteAt !== 'number' || !Number.isFinite(lastPeerWriteAt)) return 'client'
  const age = now - lastPeerWriteAt
  return age >= 0 && age <= windowMs ? 'tab' : 'client'
}

export function conflictSourceText(source: ConflictSource): string {
  return source === 'tab' ? '同一个浏览器的另一个标签页' : '另一个客户端'
}

export function conflictMessage(source: ConflictSource, restored = false): string {
  const who = conflictSourceText(source)
  if (restored) {
    return `上次未解决的工作区冲突仍然保留着：${who}改过服务端，本机草稿没有丢。`
      + '请选择「保留本机，用本机覆盖服务端」或「改用服务端版本」。'
  }
  return `${who}刚改过工作区，本机还有未保存的改动。`
    + '请选择「保留本机，用本机覆盖服务端」或「改用服务端版本」；在此之前不会自动覆盖任何一边。'
}

/** 刷新后恢复冲突时所需的本地上下文。 */
export interface ConflictResumeContext {
  /** 当前标签页 id：sessionStorage 持久化，刷新后同标签页不变。 */
  tabId: string
  signature: string
  hasLocalContent: boolean
}

export type ConflictResumeDecision = 'resume' | 'resume-edited' | 'ignore' | 'foreign'

/**
 * 刷新 / 重连后是否恢复冲突。
 * - 别的标签页的标记不由本标签页恢复，更不能被本标签页清掉；
 * - 签名不一致说明冲突后本机又编辑过，草稿仍要保留，但界面要说明「又有改动」。
 */
export function decideConflictResume(
  draft: ConflictDraft | null | undefined,
  context: ConflictResumeContext,
): ConflictResumeDecision {
  if (!draft || !context.hasLocalContent) return 'ignore'
  if (draft.tabId && draft.tabId !== context.tabId) return 'foreign'
  return draft.signature === context.signature ? 'resume' : 'resume-edited'
}

/**
 * 页面刷新后是否恢复冲突提示。
 * 本机没有任何内容时不拦截服务端数据，避免提示变成一个没有草稿的幽灵；
 * 不传上下文时保持旧行为（只要本机有内容就恢复）。
 */
export function shouldResumeConflictDraft(
  draft: ConflictDraft | null | undefined,
  hasLocalContent: boolean,
  context?: ConflictResumeContext,
): draft is ConflictDraft {
  if (!draft || !hasLocalContent) return false
  if (!context) return true
  const decision = decideConflictResume(draft, context)
  return decision === 'resume' || decision === 'resume-edited'
}

/**
 * 谁能清除冲突标记。
 * 有 tabId 时只有记录它的标签页能清；旧标记没有 tabId，则只在内容签名仍一致时清除，
 * 避免 B 标签页把 A 标签页的草稿保护顺手删掉。
 */
export function canClearConflictMarker(
  draft: ConflictDraft | null | undefined,
  context: ConflictResumeContext,
): boolean {
  if (!draft) return true
  if (draft.tabId) return draft.tabId === context.tabId
  return draft.signature === context.signature
}

export type ConflictProbeAction = 'resolved' | 'retry' | 'wait-for-key' | 'left-server-mode'

/**
 * 冲突期间探测服务端版本失败后该做什么。
 * `retry` 必须真的重新排一次重试：冲突态下轮询 / 聚焦刷新 / 自动保存都提前返回，
 * 这一次不排就再也没有任何路径尝试连接。
 */
export function conflictProbeAction(
  version: number | null,
  state: { serverMode: boolean; state: string },
): ConflictProbeAction {
  if (!state.serverMode) return 'left-server-mode'
  if (version !== null) return 'resolved'
  if (state.state === 'unauthorized') return 'wait-for-key'
  return 'retry'
}

export type ServerChoicePlan = 'fetch-server' | 'confirm-empty-server' | 'retry'

/**
 * 用户点「改用服务端版本」前的处置。
 * 服务端版本为 0 说明工作区为空：绝不能走首次迁移分支把本机数据反向上传，
 * 必须先让用户单独确认「清空本机」。
 */
export function planServerChoice(probeVersion: number | null): ServerChoicePlan {
  if (probeVersion === null) return 'retry'
  if (probeVersion <= 0) return 'confirm-empty-server'
  return 'fetch-server'
}

export const CONFLICT_KEEP_LOCAL_LABEL = '保留本机，用本机覆盖服务端'
export const CONFLICT_USE_SERVER_LABEL = '改用服务端版本'
export const CONFLICT_CLEAR_LOCAL_LABEL = '清空本机并改用服务端'
