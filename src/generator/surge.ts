// Surge full-config generation (INI).
import type { ProxyNode, RoutingRule, RuleScheme } from '../models/types'
import { confName } from './naming'
import { compileRuleLine, resolveGroups, uniqueDisplayNames, type OutputOptions } from './groups'
import { effectiveGroupType, filterRulesForTarget } from '../rules/capabilities'
import { inlineSetReference, surgeInlinePayload } from '../rules/inlineSets'
import { supportsRuleSetReference } from '../rules/remoteFormats'
import { effectiveNetworkSettings, latencyTestURL } from '../models/networkSettings'
import { nodeSupportedForTarget } from './nodeCapabilities'
import { withPolicyGroupIcons } from './groupIcons'

function wireGuardSectionName(node: ProxyNode): string {
  const id = node.id.toLowerCase().replace(/[^a-z0-9-]/g, '')
  return `tower-${id || 'node'}`
}

function wireGuardEndpoint(node: ProxyNode): string {
  const host = node.server.includes(':') && !(node.server.startsWith('[') && node.server.endsWith(']'))
    ? `[${node.server}]`
    : node.server
  return `${host}:${node.port}`
}

function wireGuardReserved(node: ProxyNode): number[] | undefined {
  const values = (node.wireGuardReserved ?? '').split(',').map((item) => item.trim()).filter(Boolean)
  if (!values.length) return []
  const bytes = values.map(Number)
  return bytes.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255) ? bytes : undefined
}

function surgeWireGuardSections(nodes: ProxyNode[]): string[] {
  const out: string[] = []
  for (const node of nodes) {
    if (node.kind !== 'wireguard') continue
    out.push('', `[WireGuard ${wireGuardSectionName(node)}]`)
    out.push(`private-key = ${node.wireGuardPrivateKey ?? ''}`)
    if (node.wireGuardIPv4) out.push(`self-ip = ${node.wireGuardIPv4}`)
    if (node.wireGuardIPv6) out.push(`self-ip-v6 = ${node.wireGuardIPv6}`)
    if (node.wireGuardDNS) out.push(`dns-server = ${node.wireGuardDNS}`)
    if (node.wireGuardMTU !== undefined) out.push(`mtu = ${node.wireGuardMTU}`)
    const peer = [
      `public-key = ${node.wireGuardPublicKey ?? ''}`,
      `allowed-ips = "${node.wireGuardAllowedIPs || '0.0.0.0/0, ::/0'}"`,
      `endpoint = ${wireGuardEndpoint(node)}`,
    ]
    if (node.wireGuardPreSharedKey) peer.push(`preshared-key = ${node.wireGuardPreSharedKey}`)
    if (node.wireGuardPersistentKeepalive !== undefined) {
      peer.push(`keepalive = ${node.wireGuardPersistentKeepalive}`)
    }
    const reserved = wireGuardReserved(node)
    if (reserved?.length === 3) peer.push(`client-id = ${reserved.join('/')}`)
    out.push(`peer = (${peer.join(', ')})`)
  }
  return out
}

function surgeNode(node: ProxyNode, name: string): string | undefined {
  if (!nodeSupportedForTarget(node, 'surge')) return undefined
  const n = confName(name)
  const server = node.server.includes(':') ? `[${node.server}]` : node.server
  const tlsFlags = () => {
    const parts: string[] = []
    if (node.sni) parts.push(`sni=${node.sni}`)
    if (node.skipCertificateVerification) parts.push('skip-cert-verify=true')
    return parts
  }
  switch (node.kind) {
    case 'ss': {
      const parts = [`${n} = ss, ${server}, ${node.port}`,
        `encrypt-method=${node.cipher ?? 'aes-256-gcm'}`,
        `password=${node.password ?? ''}`]
      if (node.shadowTLS) {
        parts.push(`shadow-tls-password=${node.shadowTLS.password.replace(/%/g, '%25')}`)
        parts.push(`shadow-tls-sni=${node.shadowTLS.host}`)
        parts.push(`shadow-tls-version=${node.shadowTLS.version}`)
      } else if (node.obfs) {
        parts.push(`obfs=${node.obfs}`)
        if (node.obfsParam) parts.push(`obfs-host=${node.obfsParam}`)
      }
      if (node.udpRelayEnabled !== undefined) parts.push(`udp-relay=${node.udpRelayEnabled}`)
      return parts.join(', ')
    }
    case 'ssr': {
      // Surge 5 原生支持 SSR（与 Loon / QuanX 的字段名不同，别混用）。
      const parts = [`${n} = ssr, ${server}, ${node.port}`,
        `encrypt-method=${node.cipher ?? 'aes-256-cfb'}`,
        `password=${node.password ?? ''}`,
        `protocol=${node.protocolName ?? 'origin'}`,
        `obfs=${node.obfs ?? 'plain'}`]
      if (node.protocolParam) parts.push(`protocol-param=${node.protocolParam}`)
      if (node.obfsParam) parts.push(`obfs-param=${node.obfsParam}`)
      return parts.join(', ')
    }
    case 'vmess': {
      const parts = [`${n} = vmess, ${server}, ${node.port}`, `username=${node.uuid ?? ''}`,
        `vmess-aead=${node.alterID === 0 || node.alterID === undefined}`]
      if (node.cipher && ['aes-128-gcm', 'chacha20-ietf-poly1305'].includes(node.cipher.toLowerCase())) {
        parts.push(`encrypt-method=${node.cipher}`)
      }
      if (node.transport === 'ws') {
        parts.push('ws=true')
        parts.push(`ws-path=${node.path || '/'}`)
        if (node.hostHeader) parts.push(`ws-headers=Host:${node.hostHeader}`)
      }
      if (node.tls) {
        parts.push('tls=true', ...tlsFlags())
      }
      return parts.join(', ')
    }
    case 'trojan': {
      const parts = [`${n} = trojan, ${server}, ${node.port}`, `password=${node.password ?? ''}`]
      parts.push(...tlsFlags())
      if (node.transport === 'ws') {
        parts.push('ws=true')
        parts.push(`ws-path=${node.path || '/'}`)
        if (node.hostHeader) parts.push(`ws-headers=Host:${node.hostHeader}`)
      }
      return parts.join(', ')
    }
    case 'hysteria2': {
      const parts = [`${n} = hysteria2, ${server}, ${node.port}`, `password=${node.password ?? ''}`, ...tlsFlags()]
      return parts.join(', ')
    }
    case 'tuic': {
      const parts = [`${n} = tuic, ${server}, ${node.port}`,
        `uuid=${node.uuid ?? ''}`, `password=${node.password ?? ''}`, ...tlsFlags()]
      return parts.join(', ')
    }
    case 'snell': {
      const parts = [`${n} = snell, ${server}, ${node.port}`, `psk=${node.password ?? ''}`]
      if (node.version !== undefined) parts.push(`version=${node.version}`)
      if (node.obfs) parts.push(`obfs=${node.obfs}`)
      if (node.obfsParam) parts.push(`obfs-host=${node.obfsParam}`)
      return parts.join(', ')
    }
    case 'anytls': {
      const parts = [`${n} = anytls, ${server}, ${node.port}`, `password=${node.password ?? ''}`, ...tlsFlags()]
      parts.push('udp-relay=true')
      return parts.join(', ')
    }
    case 'wireguard': {
      if (!node.wireGuardPrivateKey || !node.wireGuardPublicKey) return undefined
      if (!node.wireGuardIPv4 && !node.wireGuardIPv6) return undefined
      if (!node.wireGuardAllowedIPs) return undefined
      if (wireGuardReserved(node) === undefined) return undefined
      return `${n} = wireguard, section-name=${wireGuardSectionName(node)}`
    }
    case 'masque': {
      // Surge 只接受 Basic-auth CONNECT；mihomo / sing-box 的 CONNECT-IP 方言不写。
      if (node.masque) return undefined
      if (node.username?.includes(':')) return undefined
      const parts = [`${n} = masque, ${server}, ${node.port}`]
      if (node.username) parts.push(`username=${node.username}`)
      if (node.password) parts.push(`password=${node.password}`)
      if (node.sni) parts.push(`sni=${node.sni}`)
      if (node.skipCertificateVerification) parts.push('skip-cert-verify=true')
      if (node.alpn) parts.push(`alpn=${node.alpn}`)
      if (node.certificateFingerprint) {
        parts.push(`server-cert-fingerprint-sha256=${node.certificateFingerprint}`)
      }
      return parts.join(', ')
    }
    case 'ssh': {
      // Surge 的密钥登录需要 [Keystore]；没有密钥库时只写密码登录。
      if (node.ssh?.privateKey?.trim()) return undefined
      const parts = [`${n} = ssh, ${server}, ${node.port}`, `username=${node.username ?? ''}`]
      if (node.password) parts.push(`password=${node.password}`)
      const hostKeys = node.ssh?.hostKeys ?? []
      if (hostKeys.length > 0) parts.push(`server-fingerprint="${hostKeys.join(', ')}"`)
      return parts.join(', ')
    }
    case 'trusttunnel': {
      const parts = [
        `${n} = trust-tunnel, ${server}, ${node.port}`,
        `username=${node.username ?? ''}`,
        `password=${node.password ?? ''}`,
        ...tlsFlags(),
      ]
      if (node.trustTunnel?.quic) parts.push('h3=true')
      if (node.certificateFingerprint) {
        parts.push(`server-cert-fingerprint-sha256=${node.certificateFingerprint}`)
      }
      return parts.join(', ')
    }
    case 'socks5': {
      const parts = [`${n} = socks5, ${server}, ${node.port}`]
      if (node.username) parts.push(`username=${node.username}`)
      if (node.password) parts.push(`password=${node.password}`)
      return parts.join(', ')
    }
    case 'http': {
      const parts = [`${n} = ${node.tls ? 'https' : 'http'}, ${server}, ${node.port}`]
      if (node.username) parts.push(`username=${node.username}`)
      if (node.password) parts.push(`password=${node.password}`)
      if (node.tls) parts.push(...tlsFlags())
      return parts.join(', ')
    }
    default:
      return undefined
  }
}

export function generateSurge(
  nodes: ProxyNode[],
  scheme: RuleScheme,
  options: OutputOptions = {},
): { text: string; skipped: number } {
  scheme = withPolicyGroupIcons(scheme, options.iconTarget ?? options.target)
  const nodesOnly = options.contentMode === 'nodes'
  const remoteSources = nodesOnly
    ? []
    : (options.remoteSubscriptions ?? []).filter((source) => /^https?:\/\//i.test(source.url))
  const remoteSourceIDs = new Set(remoteSources.map((source) => source.id))
  const usable = nodes.filter((n) => !n.isSubscriptionMetadata)
  const inlineNodes = usable.filter((n) => !(n.sourceID && remoteSourceIDs.has(n.sourceID)))
  const names = uniqueDisplayNames(usable, confName, options.nameForNode)
  const displayName = (n: ProxyNode) => names.get(n.id)!
  const network = effectiveNetworkSettings(scheme.networkSettings)
  const testURL = latencyTestURL(scheme.networkSettings)

  const proxyLines: string[] = []
  let skipped = 0
  const emitted = new Set<string>()
  for (const node of inlineNodes) {
    // Surge's policy-path list is proxy lines only and cannot carry the
    // separate [WireGuard …] section, so keep those in full-profile export.
    if (nodesOnly && node.kind === 'wireguard') {
      skipped += 1
      continue
    }
    const line = surgeNode(node, displayName(node))
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
  const emittedNodes = inlineNodes.filter((n) => emitted.has(n.id))
  const allNames = new Set(usable.map(displayName))
  const emittedNames = new Set(emittedNodes.map(displayName))
  const groupNodes = remoteSources.length > 0 ? usable : emittedNodes
  const resolved = nodesOnly ? [] : resolveGroups(scheme, groupNodes, displayName)

  const remoteNameToSource = new Map<string, string>()
  for (const node of usable) {
    if (node.sourceID && remoteSourceIDs.has(node.sourceID)) {
      remoteNameToSource.set(displayName(node), node.sourceID)
    }
  }
  const usedSourceNames = new Set(resolved.map((item) => confName(item.group.name)))
  for (const name of emittedNodes.map(displayName)) usedSourceNames.add(name)
  const sourceGroupNames = new Map<string, string>()
  for (const source of remoteSources) {
    const base = confName(source.name) || '代理集合'
    let candidate = base
    let suffix = 2
    while (usedSourceNames.has(candidate)) {
      candidate = `${base} ${suffix}`
      suffix += 1
    }
    usedSourceNames.add(candidate)
    sourceGroupNames.set(source.id, candidate)
  }
  const quote = (value: string) => `"${value.replace(/"/g, '\\"')}"`

  const out: string[] = [
    '[General]',
    'loglevel = notify',
    'skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local',
    `dns-server = ${network.dnsServers.join(', ')}`,
    'test-timeout = 5',
    '',
    '[Proxy]',
    ...proxyLines,
    ...surgeWireGuardSections(inlineNodes.filter((node) => emitted.has(node.id) && node.kind === 'wireguard')),
  ]
  if (!nodesOnly) {
    out.push('', '[Proxy Group]')
    for (const source of remoteSources) {
      const name = sourceGroupNames.get(source.id)!
      out.push(`${name} = select, policy-path=${quote(source.url)}, update-interval=86400, hidden=true`)
    }
    for (const { group, members } of resolved) {
      const inlineMembers = members.filter(
        (member) => !remoteNameToSource.has(member) && (emittedNames.has(member) || !allNames.has(member)),
      )
      const includedSources = group.nodeFilter
        ? [...new Set(
            members
              .map((member) => remoteNameToSource.get(member))
              .filter((sourceID): sourceID is string => !!sourceID),
          )].map((sourceID) => sourceGroupNames.get(sourceID)).filter(Boolean) as string[]
        : []
      const list = inlineMembers.length ? inlineMembers : includedSources.length ? [] : ['DIRECT']
      const kind = effectiveGroupType(group.type, options.target)
      const parts: string[] = [...list]
      if (kind !== 'select') {
        parts.push(`url=${group.url ?? testURL}`)
        parts.push(`interval=${group.interval ?? 300}`)
        if (group.tolerance) parts.push(`tolerance=${group.tolerance}`)
      }
      if (includedSources.length) {
        parts.push(`include-other-group=${quote(includedSources.join(','))}`)
        if (group.nodeFilter) parts.push(`policy-regex-filter=${quote(group.nodeFilter)}`)
      }
      if (parts.length === 0) parts.push('DIRECT')
      const line = `${confName(group.name)} = ${kind}, ${parts.join(', ')}`
      out.push(group.icon ? `${line}, icon-url=${group.icon}` : line)
    }
    const filteredRules = filterRulesForTarget(scheme.rules, options.target)
    const inlineRuleSets = new Map<string, {
      key: string
      meta: NonNullable<RoutingRule['inlineSet']>
      lines: string[]
    }>()
    for (const rule of filteredRules) {
      if (!rule.inlineSet) continue
      const existing = inlineRuleSets.get(rule.inlineSet.id)
      const line = surgeInlinePayload(rule)
      if (!line) continue
      if (existing) {
        if (!existing.lines.includes(line)) existing.lines.push(line)
        continue
      }
      inlineRuleSets.set(rule.inlineSet.id, {
        key: `tower-local-${inlineRuleSets.size + 1}`,
        meta: rule.inlineSet,
        lines: [line],
      })
    }

    out.push('', '[Rule]')
    const emittedInlineSets = new Set<string>()
    for (const rule of filteredRules) {
      const group = confName(rule.group)
      if (rule.inlineSet) {
        if (emittedInlineSets.has(rule.inlineSet.id)) continue
        const set = inlineRuleSets.get(rule.inlineSet.id)
        if (set) {
          emittedInlineSets.add(rule.inlineSet.id)
          out.push(inlineSetReference(set.key, set.meta, group))
          continue
        }
      }
      if (rule.type === 'FINAL') out.push(`FINAL,${group}`)
      else if (rule.type === 'RULE-SET' && !supportsRuleSetReference(rule, 'surge', options.target)) continue
      else out.push(compileRuleLine(rule, group))
    }
    for (const set of inlineRuleSets.values()) {
      out.push('', `[Ruleset ${set.key}]`, ...set.lines)
    }
  }
  return { text: out.join('\n') + '\n', skipped }
}
