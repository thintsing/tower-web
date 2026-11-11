// 工作区写入上限：服务端据此返回 413，前端据此生成「多大 / 上限多少」的失败文案。
// 两端共用同一值，避免各自定义后漂移。前端经 workspace-limits.d.mts 复用。
export const WORKSPACE_MAX_BYTES = 16 * 1024 * 1024