// 上游和分享者可控的 Content-Type 收敛到白名单：text/html 或 SVG 会让浏览器
// 在塔台自己的源上执行脚本，读走 localStorage 里的管理密钥和整份工作区。
// 原始类型另存 x-upstream-content-type，上游漂移检测仍按真实类型判断。
const PASSTHROUGH_CONTENT_TYPES = new Set([
  'text/plain',
  'text/yaml',
  'application/yaml',
  'application/x-yaml',
  'text/x-yaml',
  'application/json',
  'text/json',
  'application/octet-stream',
  'application/base64',
])

export function safeContentType(value) {
  const raw = String(value ?? '').trim()
  const essence = raw.split(';')[0].trim().toLowerCase()
  return PASSTHROUGH_CONTENT_TYPES.has(essence) ? raw : 'text/plain; charset=utf-8'
}
