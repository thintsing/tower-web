/**
 * 示例工作区开关：`?demo=1` 时启用。
 *
 * 隔离边界（示例模式只隔离本地状态与服务端写操作，不等于完全离线）：
 * - 工作区数据（订阅、节点、方案、规则集、导出偏好）只写入带 `-demo` 后缀的
 *   localStorage 键，不读写真实工作区，也不进入服务端 workspace.json；
 * - 发布链接属于服务端状态：`/api/subscribe` 会写入 subscriptions.json，
 *   `/api/share` 会创建进程内一次性临时链接。示例模式统一禁用两者：
 *   示例节点全是虚构的，生成链接没有实际用途，同时避免留下服务端残留；
 * - 不启动工作区同步、工作区历史、上游更新检查，也不修改服务端设置；
 * - 页面仍可能通过本机服务读取展示所需的信息（例如局域网地址、远程规则集文本）。
 */
const params = typeof location !== 'undefined' ? new URLSearchParams(location.search) : undefined

export const DEMO_MODE = params?.get('demo') === '1'

/** 示例模式与真实工作区使用的存储键集合；两边必须完全不相交。 */
export function demoStorageKeys(demo: boolean) {
  return {
    store: demo ? 'tower-web-state-demo' : 'tower-web-state',
    subToken: demo ? 'tower-sub-token-demo' : 'tower-sub-token',
    subURL: demo ? 'tower-sub-url-demo' : 'tower-sub-url',
    subUpdatedAt: demo ? 'tower-sub-updated-at-demo' : 'tower-sub-updated-at',
  }
}

const keys = demoStorageKeys(DEMO_MODE)

export const STORE_KEY = keys.store
export const SUB_TOKEN_KEY = keys.subToken
export const SUB_URL_KEY = keys.subURL
export const SUB_UPDATED_AT_KEY = keys.subUpdatedAt

/** 示例模式是否禁止会在服务端留下状态的写操作（发布订阅、分享链接、服务端设置）。 */
export function demoBlocksServerWrites(demo: boolean): boolean {
  return demo
}

export const DEMO_PUBLISH_NOTE = '示例工作区不生成服务端订阅链接：持久链接会写入服务端，一次性分享链接也会创建临时 token；可以下载配置文件或复制预览内容。'

/** 演示命名空间内的全部键；恢复示例数据时只清这些键。 */
export function demoWorkspaceKeys(): string[] {
  const demoKeys = demoStorageKeys(true)
  return [demoKeys.store, demoKeys.subToken, demoKeys.subURL, demoKeys.subUpdatedAt]
}

/** 恢复示例数据只需要读取与删除，便于在自检里用内存替身。 */
export interface DemoStorage {
  getItem(key: string): string | null
  removeItem(key: string): void
}

/** 只清演示命名空间，返回实际删除的键；真实工作区与真实订阅链接不受影响。 */
export function resetDemoWorkspace(storage: DemoStorage, demo: boolean = DEMO_MODE): string[] {
  if (!demo) return []
  const removed: string[] = []
  for (const key of demoWorkspaceKeys()) {
    if (storage.getItem(key) === null) continue
    storage.removeItem(key)
    removed.push(key)
  }
  return removed
}
