/**
 * 示例工作区开关：`?demo=1` 时启用。
 * 使用独立的 localStorage 命名空间，示例数据不会写入真实工作区。
 */
const params = typeof location !== 'undefined' ? new URLSearchParams(location.search) : undefined

export const DEMO_MODE = params?.get('demo') === '1'

export const STORE_KEY = DEMO_MODE ? 'tower-web-state-demo' : 'tower-web-state'
export const SUB_TOKEN_KEY = DEMO_MODE ? 'tower-sub-token-demo' : 'tower-sub-token'
export const SUB_URL_KEY = DEMO_MODE ? 'tower-sub-url-demo' : 'tower-sub-url'
