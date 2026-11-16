// 示例工作区：虚构节点与测速结果，让新用户不导入真实订阅也能走完四步主线。
// 域名统一使用 .invalid，避免任何真实的网络请求落到示例节点上。
import type { LatencyTestMethod, ProxyNode } from '../models/types'

interface DemoNodeDef {
  id: string
  name: string
  server: string
  latency: number
}

const DEMO_DEFS: DemoNodeDef[] = [
  { id: 'demo-hk-01', name: '🇭🇰 香港 01 · 示例', server: 'hk1.demo.invalid', latency: 38 },
  { id: 'demo-jp-01', name: '🇯🇵 东京 01 · 示例', server: 'jp1.demo.invalid', latency: 52 },
  { id: 'demo-sg-01', name: '🇸🇬 新加坡 01 · 示例', server: 'sg1.demo.invalid', latency: 76 },
  { id: 'demo-us-01', name: '🇺🇸 洛杉矶 01 · 示例', server: 'us1.demo.invalid', latency: 168 },
  { id: 'demo-de-01', name: '🇩🇪 法兰克福 01 · 示例', server: 'de1.demo.invalid', latency: 210 },
  { id: 'demo-uk-01', name: '🇬🇧 伦敦 01 · 示例', server: 'uk1.demo.invalid', latency: 196 },
]

export const DEMO_NODES: ProxyNode[] = DEMO_DEFS.map(({ id, name, server }) => ({
  id,
  kind: 'ss',
  name,
  server,
  port: 443,
  cipher: 'aes-256-gcm',
  password: 'demo-only',
  tls: false,
  skipCertificateVerification: false,
  rawURI: `ss://${id}@${server}:443#${encodeURIComponent(name)}`,
  isManual: true,
  isEnabled: true,
}))

/** 节点 id → 示例延迟；仅用于展示，不会触发真实测速。 */
export const DEMO_LATENCY: Record<string, number> = Object.fromEntries(
  DEMO_DEFS.map((node) => [node.id, node.latency]),
)

export const DEMO_LATENCY_METHOD: Record<string, LatencyTestMethod> = Object.fromEntries(
  DEMO_DEFS.map((node) => [node.id, 'tcp' as const]),
)

/** 首次进入示例模式时注入的部分 store 状态；之后的编辑仍按演示命名空间保存。 */
export function demoSeedState() {
  return {
    nodes: DEMO_NODES,
    latencyByNodeId: DEMO_LATENCY,
    latencyMethodByNodeId: DEMO_LATENCY_METHOD,
    probeErrorByNodeId: {},
  }
}
