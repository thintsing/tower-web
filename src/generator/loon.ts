// Loon 完整配置生成（Loon 专用方言，不是 Surge 语法）。
// Loon Proxy 行形如：Name = Shadowsocks,host,port,aes-128-gcm,password
//                 Name = VMess,host,port,username=uuid,tls=true,ws=true,ws-path=/...
import type { ProxyNode, RuleScheme } from '../models/types'
import { confName } from './naming'
import { nodeSupportedForTarget } from './nodeCapabilities'
import {
  compileRuleLine,
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

function loonQuoted(value: string): string {
  return JSON.stringify(value.replace(/\r\n/g, ' ').replace(/\r/g, ' '))
}

function loonNode(node: ProxyNode, name: string): string | undefined {
  if (!nodeSupportedForTarget(node, 'loon')) return undefined
  const n = confName(name)
  const host = node.server.includes(':') ? `[${node.server}]` : node.server
  const tlsTail = (): string[] => {
    const parts: string[] = []
    if (node.tls || node.sni || node.kind === 'trojan' || node.kind === 'hysteria2' || node.kind === 'tuic') {
      parts.push('tls=true')
    }
    if (node.sni) parts.push(`sni=${node.sni}`)
    if (node.skipCertificateVerification) parts.push('skip-cert-verify=true')
    return parts
  }

  switch (node.kind) {
    case 'ss': {
      const parts = [`${n} = Shadowsocks, ${host}, ${node.port}`, node.cipher ?? 'aes-256-gcm', node.password ?? '']
      if (node.shadowTLS) {
        parts.push(`shadow-tls-password=${node.shadowTLS.password}`)
        parts.push(`shadow-tls-sni=${node.shadowTLS.host}`)
        parts.push(`shadow-tls-version=${node.shadowTLS.version}`)
      } else if (node.obfs) {
        // Loon 里 `obfs` 是 SSR 专用字段；simple-obfs 要用 obfs-name / obfs-host。
        parts.push(`obfs-name=${node.obfs}`)
        if (node.obfsParam) parts.push(`obfs-host=${node.obfsParam}`)
      }
      if (node.udpRelayEnabled !== undefined) parts.push(`udp=${node.udpRelayEnabled}`)
      return parts.join(', ')
    }
    case 'ssr': {
      // Loon 的 SSR 行：Name = ShadowsocksR, host, port, cipher, password, protocol=…, obfs=…
      const parts = [`${n} = ShadowsocksR, ${host}, ${node.port}`,
        node.cipher ?? 'aes-256-cfb',
        node.password ?? '',
        `protocol=${node.protocolName ?? 'origin'}`,
        `obfs=${node.obfs ?? 'plain'}`]
      if (node.protocolParam) parts.push(`protocol-param=${node.protocolParam}`)
      if (node.obfsParam) parts.push(`obfs-param=${node.obfsParam}`)
      parts.push('udp=true')
      return parts.join(', ')
    }
    case 'vmess': {
      const parts = [`${n} = VMess, ${host}, ${node.port}`, `username=${node.uuid ?? ''}`, `alterId=${node.alterID ?? 0}`]
      if (node.transport === 'ws') {
        parts.push('ws=true', `ws-path=${node.path || '/'}`)
        if (node.hostHeader) parts.push(`ws-headers=Host:${node.hostHeader}`)
      }
      parts.push(...tlsTail())
      return parts.join(', ')
    }
    case 'vless': {
      const parts = [`${n} = VLESS, ${host}, ${node.port}`, `username=${node.uuid ?? ''}`]
      if (node.transport === 'ws') {
        parts.push('ws=true', `ws-path=${node.path || '/'}`)
        if (node.hostHeader) parts.push(`ws-headers=Host:${node.hostHeader}`)
      }
      parts.push(...tlsTail())
      return parts.join(', ')
    }
    case 'trojan': {
      const parts = [`${n} = Trojan, ${host}, ${node.port}`, node.password ?? '']
      if (node.transport === 'ws') {
        parts.push('ws=true', `ws-path=${node.path || '/'}`)
        if (node.hostHeader) parts.push(`ws-headers=Host:${node.hostHeader}`)
      }
      parts.push(...tlsTail())
      return parts.join(', ')
    }
    case 'hysteria2': {
      const parts = [`${n} = Hysteria2, ${host}, ${node.port}`, node.password ?? '']
      if (node.sni) parts.push(`sni=${node.sni}`)
      if (node.skipCertificateVerification) parts.push('skip-cert-verify=true')
      if (node.obfs) parts.push(`obfs=${node.obfs}`)
      if (node.obfsParam) parts.push(`obfs-password=${node.obfsParam}`)
      return parts.join(', ')
    }
    case 'wireguard': {
      if (!node.wireGuardPrivateKey || !node.wireGuardPublicKey) return undefined
      if (!node.wireGuardIPv4 && !node.wireGuardIPv6) return undefined
      if (!node.wireGuardAllowedIPs) return undefined
      const reserved = node.wireGuardReserved?.trim()
      if (reserved) {
        const bytes = reserved.split(',').map((item) => Number(item.trim()))
        if (!bytes.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)) return undefined
      }
      const parts = [
        `${n} = wireguard`,
        `interface-ip=${node.wireGuardIPv4 ?? ''}`,
      ]
      if (node.wireGuardIPv6) parts.push(`interface-ipv6=${node.wireGuardIPv6}`)
      parts.push(`private-key=${loonQuoted(node.wireGuardPrivateKey)}`)
      if (node.wireGuardMTU !== undefined) parts.push(`mtu=${node.wireGuardMTU}`)
      if (node.wireGuardDNS) parts.push(`dns=${node.wireGuardDNS}`)
      if (node.wireGuardPersistentKeepalive !== undefined) {
        parts.push(`keepalive=${node.wireGuardPersistentKeepalive}`)
      }
      const peer = [
        `public-key=${loonQuoted(node.wireGuardPublicKey)}`,
        `allowed-ips=${loonQuoted(node.wireGuardAllowedIPs)}`,
        `endpoint=${host}:${node.port}`,
      ]
      if (reserved) peer.push(`reserved=[${reserved}]`)
      if (node.wireGuardPreSharedKey) peer.push(`preshared-key=${loonQuoted(node.wireGuardPreSharedKey)}`)
      parts.push(`peers=[{${peer.join(',')}}]`, 'udp=true')
      return parts.join(', ')
    }
    case 'socks5': {
      const parts = [`${n} = SOCKS5, ${host}, ${node.port}`]
      if (node.username) parts.push(`username=${node.username}`)
      if (node.password) parts.push(`password=${node.password}`)
      return parts.join(', ')
    }
    case 'http': {
      const parts = [`${n} = ${node.tls ? 'HTTPS' : 'HTTP'}, ${host}, ${node.port}`]
      if (node.username) parts.push(`username=${node.username}`)
      if (node.password) parts.push(`password=${node.password}`)
      if (node.tls) parts.push(...tlsTail())
      return parts.join(', ')
    }
    default:
      // snell / wireguard / ssh / ssr：Loon 无对应语法
      return undefined
  }
}

export function generateLoon(
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

  const proxyLines: string[] = []
  const emitted = new Set<string>()
  let skipped = 0
  for (const node of remotePlan.localNodes) {
    const line = loonNode(node, displayName(node))
    if (line) {
      proxyLines.push(line)
      emitted.add(node.id)
    } else {
      skipped += 1
    }
  }
  if (nodesOnly) {
    return { text: proxyLines.join('\n') + (proxyLines.length ? '\n' : ''), skipped }
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
  const remoteFilters: { name: string; aliases: string; pattern: string }[] = []

  const out: string[] = [
    '[General]',
    'internet-test-url = https://cp.cloudflare.com/generate_204',
    'proxy-test-url = https://cp.cloudflare.com/generate_204',
    'test-interval = 300',
    'ipv6 = false',
    '',
    '[Proxy]',
    ...proxyLines,
  ]
  if (!nodesOnly) {
    if (remotePlan.sources.length) {
      out.push('', '[Remote Proxy]')
      for (const source of remotePlan.sources) {
        out.push(`${remoteAliases.get(source.id)} = ${source.url}`)
      }
    }

    out.push('', '[Proxy Group]')
    resolved.forEach(({ group, members }, index) => {
      const localMembers = members.filter((member) => !remoteNameToSource.has(member))
      const selection = remoteGroupSelection(group, groupNodes, remotePlan.sources, displayName)
      let remoteMember: string | undefined
      if (selection.sources.length) {
        if (selection.filter) {
          const name = confName(`塔台筛选 ${index + 1} · ${group.name}`)
          const aliases = selection.sources
            .map((source) => remoteAliases.get(source.id))
            .filter((value): value is string => !!value)
            .join(',')
          if (aliases) {
            remoteFilters.push({ name, aliases, pattern: selection.filter })
            remoteMember = name
          }
        } else {
          remoteMember = selection.sources
            .map((source) => remoteAliases.get(source.id))
            .filter((value): value is string => !!value)
            .join(',')
        }
      }
      const list = [...localMembers]
      if (remoteMember) list.push(remoteMember)
      const finalList = list.length ? list : ['DIRECT']
      const kind = effectiveGroupType(group.type, options.target, group.parameters)
      const type = kind === 'load-balance' ? 'load-balance' : kind === 'fallback' ? 'fallback' : kind === 'url-test' ? 'url-test' : 'select'
      const tail =
        kind === 'select'
          ? ''
          : `, url=${group.url ?? testURL}, interval=${group.interval ?? 300}`
      const icon = group.icon ? `, img-url=${group.icon}` : ''
      out.push(`${confName(group.name)} = ${type}, ${finalList.join(', ')}${tail}${icon}`)
    })
    if (remoteFilters.length) {
      out.push('', '[Remote Filter]')
      for (const filter of remoteFilters) {
        out.push(`${filter.name} = NameRegex, ${filter.aliases}, FilterKey = "${filter.pattern.replace(/"/g, '\\"')}"`)
      }
    }
    out.push('', '[Rule]')
    const remoteRules: string[] = []
    for (const rule of filterRulesForTarget(scheme.rules, options.target)) {
      const group = confName(rule.group)
      if (rule.type === 'FINAL') {
        out.push(`FINAL,${group}`)
        continue
      }
      if (rule.type === 'RULE-SET') {
        if (!rule.value || !supportsRuleSetReference(rule, 'loon', options.target)) continue
        remoteRules.push(`${rule.value},policy=${group},tag=tower-rule-set-${remoteRules.length + 1},enabled=true`)
        continue
      }
      out.push(compileRuleLine(rule, group, 'loon'))
    }
    if (remoteRules.length) out.push('', '[Remote Rule]', ...remoteRules)
  }
  return { text: out.join('\n') + '\n', skipped }
}
