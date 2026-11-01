// Quantumult X 完整配置生成（QuanX 专用方言）。
// [server_local] 行形如：shadowsocks=host:port, method=aes-128-gcm, password=xxx, tag=name
// [policy]       行形如：static=分组名, direct, reject, 节点标签…
// [filter_local] 行形如：host-suffix, google.com, 分组名 / final, 分组名
import type { ProxyNode, RuleScheme } from '../models/types'
import { confName } from './naming'
import {
  exactNamePattern,
  remoteGroupSelection,
  remoteNodePlan,
  remoteSourceAliases,
  resolveGroups,
  uniqueDisplayNames,
  type OutputOptions,
} from './groups'
import { effectiveGroupType, filterRulesForTarget } from '../rules/capabilities'
import { supportsRuleSetReference } from '../rules/remoteFormats'
import { latencyTestURL } from '../models/networkSettings'
import { withPolicyGroupIcons } from './groupIcons'

/** QuanX 里 DIRECT / REJECT 要写成小写 direct / reject。 */
function qxPolicy(name: string): string {
  const upper = name.toUpperCase()
  if (upper === 'DIRECT') return 'direct'
  if (upper === 'REJECT') return 'reject'
  return confName(name)
}

function qxNode(node: ProxyNode, tag: string): string | undefined {
  const host = node.server.includes(':') ? `[${node.server}]` : node.server
  const addr = `${host}:${node.port}`
  const tls = (): string[] => {
    const parts: string[] = []
    if (node.sni) parts.push(`tls-host=${node.sni}`)
    if (node.skipCertificateVerification) parts.push('tls-verification=false')
    return parts
  }
  switch (node.kind) {
    case 'ss': {
      if (node.shadowTLS) return undefined
      const parts = [`shadowsocks=${addr}`, `method=${node.cipher ?? 'aes-256-gcm'}`, `password=${node.password ?? ''}`]
      if (node.obfs) {
        // QuanX 的 ss obfs 只有 simple-obfs 的 http / tls 两种
        if (node.obfs === 'http' || node.obfs === 'tls') parts.push(`obfs=${node.obfs}`)
      }
      if (node.obfsParam) parts.push(`obfs-host=${node.obfsParam}`)
      parts.push('fast-open=false', 'udp-relay=false', `tag=${tag}`)
      return parts.join(', ')
    }
    case 'ssr': {
      // QuanX 的 SSR 也写在 shadowsocks= 行里，靠 ssr-protocol / obfs 区分。
      const parts = [`shadowsocks=${addr}`,
        `method=${node.cipher ?? 'aes-256-cfb'}`,
        `password=${node.password ?? ''}`,
        `ssr-protocol=${node.protocolName ?? 'origin'}`,
        `obfs=${node.obfs ?? 'plain'}`]
      if (node.protocolParam) parts.push(`ssr-protocol-param=${node.protocolParam}`)
      if (node.obfsParam) parts.push(`obfs-host=${node.obfsParam}`)
      parts.push('udp-relay=false', `tag=${tag}`)
      return parts.join(', ')
    }
    case 'vmess': {
      const parts = [`vmess=${addr}`, 'method=none', `password=${node.uuid ?? ''}`]
      if (node.transport === 'ws') {
        parts.push('obfs=ws', `obfs-uri=${node.path || '/'}`)
        if (node.hostHeader) parts.push(`obfs-host=${node.hostHeader}`)
      }
      if (node.tls) {
        parts.push('over-tls=true')
        if (node.sni) parts.push(`tls-host=${node.sni}`)
        parts.push(`tls-verification=${node.skipCertificateVerification ? 'false' : 'true'}`)
      }
      parts.push('fast-open=false', 'udp-relay=false', `tag=${tag}`)
      return parts.join(', ')
    }
    case 'vless': {
      const parts = [`vless=${addr}`, `password=${node.uuid ?? ''}`]
      if (node.transport === 'ws') {
        parts.push('obfs=ws', `obfs-uri=${node.path || '/'}`)
        if (node.hostHeader) parts.push(`obfs-host=${node.hostHeader}`)
      }
      if (node.tls || node.realityPublicKey) {
        parts.push('over-tls=true')
        if (node.sni) parts.push(`tls-host=${node.sni}`)
      }
      parts.push('udp-relay=false', `tag=${tag}`)
      return parts.join(', ')
    }
    case 'trojan': {
      const parts = [`trojan=${addr}`, `password=${node.password ?? ''}`, 'over-tls=true']
      if (node.transport === 'ws') {
        parts.push('obfs=ws', `obfs-uri=${node.path || '/'}`)
        if (node.hostHeader) parts.push(`obfs-host=${node.hostHeader}`)
      }
      parts.push(...tls(), 'udp-relay=false', `tag=${tag}`)
      return parts.join(', ')
    }
    case 'socks5': {
      const parts = [`socks5=${addr}`]
      if (node.username) parts.push(`username=${node.username}`)
      if (node.password) parts.push(`password=${node.password}`)
      parts.push('udp-relay=false', `tag=${tag}`)
      return parts.join(', ')
    }
    case 'http': {
      const parts = [`${node.tls ? 'https' : 'http'}=${addr}`]
      if (node.username) parts.push(`username=${node.username}`)
      if (node.password) parts.push(`password=${node.password}`)
      if (node.tls) parts.push(...tls())
      parts.push(`tag=${tag}`)
      return parts.join(', ')
    }
    default:
      // snell / wireguard / ssh / ssr：QuanX 无对应语法
      return undefined
  }
}

/** Surge / Clash 规则类型 → QuanX filter_local 类型。 */
const QX_RULE_TYPE: Record<string, string> = {
  DOMAIN: 'host',
  'DOMAIN-SUFFIX': 'host-suffix',
  'DOMAIN-KEYWORD': 'host-keyword',
  'IP-CIDR': 'ip-cidr',
  'IP-CIDR6': 'ip6-cidr',
  GEOIP: 'geo',
  'USER-AGENT': 'user-agent',
}

export function generateQuanX(
  nodes: ProxyNode[],
  scheme: RuleScheme,
  options: OutputOptions = {},
): { text: string; skipped: number } {
  scheme = withPolicyGroupIcons(scheme, options.iconTarget ?? options.target)
  const nodesOnly = options.contentMode === 'nodes'
  const usable = nodes.filter((n) => !n.isSubscriptionMetadata)
  const names = uniqueDisplayNames(usable, confName, options.nameForNode)
  const displayName = (n: ProxyNode) => names.get(n.id)!
  const testURL = latencyTestURL(scheme.networkSettings)
  const remotePlan = remoteNodePlan(usable, options.remoteSubscriptions, options.contentMode)

  const serverLines: string[] = []
  const emitted = new Set<string>()
  let skipped = 0
  for (const node of remotePlan.localNodes) {
    const line = qxNode(node, displayName(node))
    if (line) {
      serverLines.push(line)
      emitted.add(node.id)
    } else {
      skipped += 1
    }
  }
  const emittedNodes = remotePlan.localNodes.filter((n) => emitted.has(n.id))
  const remoteNodes = usable.filter((n) => n.sourceID && remotePlan.sourceIDs.has(n.sourceID))
  const groupNodes = remotePlan.sources.length ? [...emittedNodes, ...remoteNodes] : emittedNodes
  const resolved = nodesOnly ? [] : resolveGroups(scheme, groupNodes, displayName)
  const remoteNameToSource = new Map(remoteNodes.map((node) => [displayName(node), node.sourceID!]))
  const usedNames = new Set([
    ...resolved.map(({ group }) => confName(group.name)),
    ...emittedNodes.map(displayName),
  ])
  const remoteAliases = remoteSourceAliases(remotePlan.sources, usedNames, confName)

  const out: string[] = [
    '[general]',
    `network_check_url=${testURL}`,
    `server_check_url=${testURL}`,
    'dns_exclusion_list=*.cn',
  ]
  if (!nodesOnly) {
    out.push('', '[policy]')
    for (const { group, members } of resolved) {
      const list = members
        .filter((member) => !remoteNameToSource.has(member))
        .map(qxPolicy)
      const selection = remoteGroupSelection(group, groupNodes, remotePlan.sources, displayName)
      if (selection.sources.length) {
        const aliases = selection.sources
          .map((source) => remoteAliases.get(source.id))
          .filter((value): value is string => !!value)
        const aliasPattern = exactNamePattern(aliases)
        if (aliasPattern) list.push(`resource-tag-regex=${aliasPattern}`)
        if (selection.filter) list.push(`server-tag-regex=${selection.filter}`)
      }
      if (!list.length) list.push('direct')
      const kind = effectiveGroupType(group.type, options.target)
      const type = kind === 'url-test' || kind === 'fallback' || kind === 'smart'
        ? 'url-latency-benchmark'
        : kind === 'load-balance' ? 'round-robin' : 'static'
      const name = confName(group.name)
      const line = type === 'static'
        ? `static=${name}, ${list.join(', ')}`
        : `${type}=${name}, ${list.join(', ')}, check-interval=300`
      out.push(group.icon ? `${line}, img-url=${group.icon}` : line)
    }

    out.push('', '[server_remote]')
    for (const source of remotePlan.sources) {
      out.push(`${source.url}, tag=${remoteAliases.get(source.id)}, update-interval=86400, enabled=true`)
    }

    // 远程规则集走 [filter_remote]；普通规则走 [filter_local]。
    const remote: string[] = []
    const local: string[] = []
    for (const rule of filterRulesForTarget(scheme.rules, options.target)) {
      const group = qxPolicy(rule.group)
      if (rule.type === 'FINAL') {
        local.push(`final, ${group}`)
        continue
      }
      if (rule.type === 'RULE-SET') {
        if (!rule.value || !supportsRuleSetReference(rule, 'quanx', options.target)) continue
        remote.push(`${rule.value}, tag=tower-rule-set-${remote.length + 1}, force-policy=${group}, enabled=true`)
        continue
      }
      const mapped = QX_RULE_TYPE[rule.type]
      if (!mapped || !rule.value) continue
      // QuanX 的 geo / final 不接受 no-resolve
      const tail = rule.noResolve && mapped !== 'geo' ? ', no-resolve' : ''
      local.push(`${mapped}, ${rule.value}, ${group}${tail}`)
    }
    out.push('', '[filter_remote]', ...remote)
    out.push('', '[rewrite_remote]')
    out.push('', '[server_local]', ...serverLines)
    out.push('', '[filter_local]', ...local)
    out.push('', '[rewrite_local]', '', '[task_local]', '', '[http_backend]', '', '[mitm]')
  } else {
    out.push('', '[server_local]', ...serverLines)
  }

  return { text: out.join('\n') + '\n', skipped }
}
