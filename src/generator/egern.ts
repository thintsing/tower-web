// Egern full-config YAML. Unlike Clash YAML, Egern uses `policy_groups`
// and one mapping per rule (`- domain: { match, policy }`).
import type { ProxyNode, RemoteSubscriptionEntry, RuleScheme, RoutingRule } from '../models/types'
import { yaml, yamlMultiline } from './naming'
import {
  remoteGroupSelection,
  remoteNodePlan,
  resolveGroups,
  uniqueDisplayNames,
  type OutputOptions,
} from './groups'
import { effectiveGroupType, filterRulesForTarget } from '../rules/capabilities'
import { supportsRuleSetReference } from '../rules/remoteFormats'
import { latencyTestURL } from '../models/networkSettings'
import { withPolicyGroupIcons } from './groupIcons'

function csv(value: string | undefined): string[] {
  return (value ?? '').split(',').map((item) => item.trim()).filter(Boolean)
}

function skipTLS(node: ProxyNode): string[] {
  const lines: string[] = []
  if (node.sni) lines.push(`      sni: ${yaml(node.sni)}`)
  lines.push(`      skip_tls_verify: ${node.skipCertificateVerification ? 'true' : 'false'}`)
  if (node.certificateFingerprint) {
    lines.push(`      fingerprint_sha256: ${yaml(node.certificateFingerprint)}`)
  }
  return lines
}

function reality(node: ProxyNode, indent: string): string[] {
  if (!node.realityPublicKey) return []
  return [
    `${indent}reality:`,
    `${indent}  public_key: ${yaml(node.realityPublicKey)}`,
    ...(node.realityShortID ? [`${indent}  short_id: ${yaml(node.realityShortID)}`] : []),
  ]
}

/** Egern nests V2Ray-style transports under `transport`. */
function transport(node: ProxyNode): string[] | undefined {
  if (node.kind === 'trojan' && node.transport === 'ws') {
    const lines = ['      websocket:', `        path: ${yaml(node.path || '/')}`]
    if (node.hostHeader) lines.push(`        host: ${yaml(node.hostHeader)}`)
    return lines
  }
  if (node.kind !== 'vmess' && node.kind !== 'vless') return undefined
  const method = node.transport ?? 'tcp'
  if (method === 'tcp' && !node.tls && !node.realityPublicKey) return undefined

  const lines = ['      transport:']
  switch (method) {
    case 'tcp':
      lines.push('        tls:')
      if (node.sni) lines.push(`          sni: ${yaml(node.sni)}`)
      lines.push(...reality(node, '          '))
      break
    case 'ws':
      lines.push(`        ${node.tls ? 'wss' : 'ws'}:`)
      lines.push(`          path: ${yaml(node.path || '/')}`)
      if (node.hostHeader) {
        lines.push('          headers:')
        lines.push(`            Host: ${yaml(node.hostHeader)}`)
      }
      if (node.tls && node.sni) lines.push(`          sni: ${yaml(node.sni)}`)
      break
    case 'http':
    case 'h2':
      lines.push(`        ${method === 'http' ? 'http1' : 'http2'}:`)
      lines.push(`          path: ${yaml(node.path || '/')}`)
      if (node.hostHeader) {
        lines.push('          headers:')
        lines.push(`            Host: ${yaml(node.hostHeader)}`)
      }
      if (node.sni) lines.push(`          sni: ${yaml(node.sni)}`)
      break
    case 'grpc':
      lines.push('        grpc:')
      if (node.path) {
        const service = node.path.startsWith('/') ? node.path.slice(1) : node.path
        lines.push(`          service_name: ${yaml(service)}`)
      }
      if (node.sni) lines.push(`          sni: ${yaml(node.sni)}`)
      lines.push(...reality(node, '          '))
      break
    default:
      return undefined
  }
  if (node.tls || node.realityPublicKey) {
    lines.push(`          skip_tls_verify: ${node.skipCertificateVerification ? 'true' : 'false'}`)
    if (node.certificateFingerprint) {
      lines.push(`          fingerprint_sha256: ${yaml(node.certificateFingerprint)}`)
    }
  }
  return lines
}

function egernNode(node: ProxyNode, name: string): string | undefined {
  // Egern documents ShadowTLS v3 only and has no native SS-over-TLS transport.
  if (node.kind === 'ss') {
    if (node.tls) return undefined
    if (node.shadowTLS && node.shadowTLS.version !== 3) return undefined
    if (node.shadowTLS && node.shadowTLS.skipCertificateVerification) return undefined
    if (node.plugin === 'v2ray-plugin') return undefined
  }

  const body = [`      name: ${yaml(name)}`]
  const endpoint = () => {
    body.push(`      server: ${yaml(node.server)}`)
    body.push(`      port: ${node.port}`)
  }
  let type: string
  switch (node.kind) {
    case 'ss':
      type = 'shadowsocks'
      body.push(`      method: ${yaml((node.cipher ?? 'aes-256-gcm') === 'chacha20-ietf-poly1305' ? 'chacha20-poly1305' : (node.cipher ?? 'aes-256-gcm'))}`)
      body.push(`      password: ${yaml(node.password ?? '')}`)
      endpoint()
      if (node.shadowTLS) {
        body.push('      shadow_tls:')
        body.push(`        password: ${yaml(node.shadowTLS.password)}`)
        body.push(`        sni: ${yaml(node.shadowTLS.host)}`)
      }
      if (!node.shadowTLS && node.obfs) {
        body.push(`      obfs: ${yaml(node.obfs)}`)
        if (node.obfsParam) body.push(`      obfs_host: ${yaml(node.obfsParam)}`)
      }
      body.push(`      udp_relay: ${node.udpRelayEnabled ?? true}`)
      break
    case 'vmess':
      type = 'vmess'
      endpoint()
      body.push(`      user_id: ${yaml(node.uuid ?? '')}`)
      body.push(`      security: ${yaml(node.cipher ?? 'auto')}`)
      body.push('      legacy: false')
      body.push('      udp_relay: true')
      break
    case 'vless':
      type = 'vless'
      endpoint()
      body.push(`      user_id: ${yaml(node.uuid ?? '')}`)
      if (node.flow) body.push(`      flow: ${yaml(node.flow)}`)
      body.push('      udp_relay: true')
      break
    case 'trojan':
    case 'anytls':
      type = node.kind
      endpoint()
      body.push(`      password: ${yaml(node.password ?? '')}`)
      if (node.sni) body.push(`      sni: ${yaml(node.sni)}`)
      body.push('      udp_relay: true')
      break
    case 'hysteria2':
      type = 'hysteria2'
      endpoint()
      body.push(`      auth: ${yaml(node.password ?? '')}`)
      if (node.sni) body.push(`      sni: ${yaml(node.sni)}`)
      if (node.portHopping) body.push(`      port_hopping: ${yaml(node.portHopping)}`)
      if (node.obfs) {
        body.push(`      obfs: ${yaml(node.obfs)}`)
        body.push(`      obfs_password: ${yaml(node.obfsParam ?? '')}`)
      }
      if (node.upMbps !== undefined) body.push(`      bandwidth: ${node.upMbps}`)
      body.push('      udp_relay: true')
      break
    case 'tuic':
      type = 'tuic'
      endpoint()
      body.push(`      uuid: ${yaml(node.uuid ?? '')}`)
      body.push(`      password: ${yaml(node.password ?? '')}`)
      if (node.sni) body.push(`      sni: ${yaml(node.sni)}`)
      body.push(`      alpn: [${(csv(node.alpn).length ? csv(node.alpn) : ['h3']).map(yaml).join(', ')}]`)
      if (node.udpRelayMode) body.push(`      udp_relay_mode: ${yaml(node.udpRelayMode)}`)
      body.push('      udp_relay: true')
      break
    case 'wireguard':
      type = 'wireguard'
      endpoint()
      body.push(`      private_key: ${yaml(node.wireGuardPrivateKey ?? '')}`)
      body.push(`      peer_public_key: ${yaml(node.wireGuardPublicKey ?? '')}`)
      if (node.wireGuardIPv4) body.push(`      local_ipv4: ${yaml(node.wireGuardIPv4)}`)
      if (node.wireGuardIPv6) body.push(`      local_ipv6: ${yaml(node.wireGuardIPv6)}`)
      if (node.wireGuardPreSharedKey) body.push(`      preshared_key: ${yaml(node.wireGuardPreSharedKey)}`)
      if (node.wireGuardReserved) {
        body.push(`      reserved: [${csv(node.wireGuardReserved).join(', ')}]`)
      }
      if (node.wireGuardDNS) body.push(`      dns_servers: [${csv(node.wireGuardDNS).map(yaml).join(', ')}]`)
      if (node.wireGuardMTU !== undefined) body.push(`      mtu: ${node.wireGuardMTU}`)
      if (node.wireGuardPersistentKeepalive !== undefined) {
        body.push(`      keepalive: ${node.wireGuardPersistentKeepalive}`)
      }
      body.push('      udp_relay: true')
      break
    case 'snell':
      type = 'snell'
      endpoint()
      body.push(`      psk: ${yaml(node.password ?? '')}`)
      body.push(`      version: ${node.version ?? 4}`)
      body.push('      udp_relay: true')
      break
    case 'socks5':
    case 'http': {
      const secure = node.tls
      type = node.kind === 'socks5'
        ? (secure ? 'socks5_tls' : 'socks5')
        : (secure ? 'https' : 'http')
      endpoint()
      if (node.username) body.push(`      username: ${yaml(node.username)}`)
      if (node.password) body.push(`      password: ${yaml(node.password)}`)
      if (secure && node.sni) body.push(`      sni: ${yaml(node.sni)}`)
      if (secure) body.push(`      skip_tls_verify: ${node.skipCertificateVerification ? 'true' : 'false'}`)
      body.push('      udp_relay: true')
      break
    }
    case 'ssh':
      // Egern 2.20+ 支持私钥，但不接受私钥口令。
      if (node.ssh?.privateKeyPassphrase?.trim()) return undefined
      type = 'ssh'
      endpoint()
      body.push(`      username: ${yaml(node.username ?? '')}`)
      if (node.password) body.push(`      password: ${yaml(node.password)}`)
      if (node.ssh?.privateKey?.trim()) {
        body.push(`      private_key: ${yamlMultiline(node.ssh.privateKey.trim())}`)
      }
      const hostKeys = node.ssh?.hostKeys ?? []
      if (hostKeys.length > 0) {
        body.push(`      host_keys: [${hostKeys.map(yaml).join(', ')}]`)
      }
      break
    default:
      // ssr / hysteria1 / masque / trusttunnel: no faithful Egern encoding.
      return undefined
  }

  if (node.realityPublicKey && node.kind !== 'vmess' && node.kind !== 'vless') {
    body.push('      reality:')
    body.push(`        public_key: ${yaml(node.realityPublicKey)}`)
    if (node.realityShortID) body.push(`        short_id: ${yaml(node.realityShortID)}`)
  } else if (![ 'vmess', 'vless' ].includes(node.kind) && (node.tls || node.kind === 'trojan' || node.kind === 'hysteria2' || node.kind === 'tuic' || node.kind === 'anytls')) {
    const extra = skipTLS(node).filter((line) => {
      // hysteria2/tuic/anytls/trojan already wrote `sni` above when present.
      return !line.trimStart().startsWith('sni:')
    })
    body.push(...extra)
  }

  const nested = transport(node)
  if (nested) body.push(...nested)
  return `  - ${type}:\n${body.join('\n')}\n`
}

function groupLines(
  groups: ReturnType<typeof resolveGroups>,
  target: OutputOptions['target'],
  testURL: string,
  allNodes: ProxyNode[],
  remoteSources: RemoteSubscriptionEntry[],
  displayName: (node: ProxyNode) => string,
  remoteNameToSource: Map<string, string>,
): string[] {
  const lines: string[] = ['policy_groups:']
  const membersBlock = (
    policies: string[],
    urls: string[],
    filter: string | undefined,
  ): string[] => {
    const block: string[] = []
    if (policies.length) {
      block.push('      policies:')
      for (const policy of policies) block.push(`        - ${yaml(policy)}`)
    }
    if (urls.length) {
      block.push('      urls:')
      for (const url of urls) block.push(`        - ${yaml(url)}`)
      block.push('      update_interval: 86400')
      if (filter) block.push(`      filter: ${yaml(filter)}`)
    }
    if (!block.length) {
      block.push('      policies:', '        - DIRECT')
    }
    return block
  }
  for (const { group, members } of groups) {
    const policies = members.filter((member) => !remoteNameToSource.has(member))
    const selection = remoteGroupSelection(group, allNodes, remoteSources, displayName)
    const urls = [...new Set(selection.sources.map((source) => source.url))]
    const name = yaml(group.name)
    const kind = effectiveGroupType(group.type, target)
    switch (kind) {
      case 'url-test':
      case 'smart':
      case 'fallback': {
        const egernKind = kind === 'fallback' ? 'fallback' : 'auto_test'
        lines.push(`  - ${egernKind}:`)
        lines.push(`      name: ${name}`)
        lines.push(...membersBlock(policies, urls, selection.filter))
        lines.push(`      interval: ${group.interval ?? 300}`)
        lines.push(`      latency_test_url: ${yaml(group.url ?? testURL)}`)
        if (kind !== 'fallback') lines.push(`      tolerance: ${group.tolerance ?? 50}`)
        lines.push('      timeout: 5')
        break
      }
      case 'load-balance':
        lines.push('  - load_balance:')
        lines.push(`      name: ${name}`)
        lines.push(...membersBlock(policies, urls, selection.filter))
        lines.push(`      algorithm: ${yaml(group.algorithm?.trim() || 'hash')}`)
        break
      default:
        lines.push('  - select:')
        lines.push(`      name: ${name}`)
        lines.push(...membersBlock(policies, urls, selection.filter))
    }
    if (group.icon) lines.push(`      icon: ${yaml(group.icon)}`)
  }
  return lines
}

interface EgernRuleLine {
  key: string
  value?: string
  noResolve?: boolean
}

function mapRule(rule: RoutingRule): EgernRuleLine | undefined {
  switch (rule.type) {
    case 'DOMAIN':
    case 'DOMAIN-SUFFIX':
    case 'DOMAIN-KEYWORD':
    case 'DOMAIN-REGEX':
    case 'DOMAIN-WILDCARD':
      return { key: `domain${rule.type === 'DOMAIN' ? '' : rule.type.slice('DOMAIN'.length).toLowerCase().replace('-', '_')}`, value: rule.value }
    case 'GEOIP':
      return { key: 'geoip', value: rule.value, noResolve: true }
    case 'IP-ASN':
      return { key: 'asn', value: rule.value, noResolve: rule.noResolve ?? true }
    case 'IP-CIDR':
    case 'IP-CIDR6':
      return { key: rule.value?.includes(':') ? 'ip_cidr6' : 'ip_cidr', value: rule.value, noResolve: rule.noResolve }
    case 'URL-REGEX':
      return { key: 'url_regex', value: rule.value }
    case 'USER-AGENT':
      return { key: 'user_agent', value: rule.value }
    case 'DEST-PORT':
    case 'DST-PORT':
      return { key: 'dest_port', value: rule.value }
    case 'PROTOCOL':
    case 'NETWORK':
      return { key: 'protocol', value: rule.value?.toLowerCase() }
    default:
      return undefined
  }
}

export function generateEgern(
  nodes: ProxyNode[],
  scheme: RuleScheme,
  options: OutputOptions = {},
): { text: string; skipped: number } {
  scheme = withPolicyGroupIcons(scheme, options.iconTarget ?? options.target)
  const contentMode = options.contentMode ?? 'full'
  const usable = nodes.filter((node) => !node.isSubscriptionMetadata)
  const names = uniqueDisplayNames(usable, (value) => value.trim() || '节点', options.nameForNode)
  const displayName = (node: ProxyNode) => names.get(node.id)!
  const remotePlan = remoteNodePlan(usable, options.remoteSubscriptions, contentMode)
  const emitted: ProxyNode[] = []
  const proxyLines: string[] = []
  let skipped = 0
  for (const node of remotePlan.localNodes) {
    const line = egernNode(node, displayName(node))
    if (line) {
      proxyLines.push(line)
      emitted.push(node)
    } else {
      skipped += 1
    }
  }

  const lines: string[] = ['proxies:']
  lines.push(...(proxyLines.length ? proxyLines : ['  []']))
  if (contentMode === 'nodes') {
    return { text: lines.join('\n') + '\n', skipped }
  }

  const remoteNodes = usable.filter((node) => node.sourceID && remotePlan.sourceIDs.has(node.sourceID))
  const groupNodes = remotePlan.sources.length ? [...emitted, ...remoteNodes] : emitted
  const groups = resolveGroups(scheme, groupNodes, displayName)
  const remoteNameToSource = new Map(remoteNodes.map((node) => [displayName(node), node.sourceID!]))
  lines.push(...groupLines(
    groups,
    options.target,
    latencyTestURL(scheme.networkSettings),
    groupNodes,
    remotePlan.sources,
    displayName,
    remoteNameToSource,
  ))

  const finalGroup = scheme.rules.find((rule) => rule.type === 'FINAL')?.group
    ?? groups[0]?.group.name
    ?? 'DIRECT'
  const rules: string[] = ['rules:']
  for (const rule of filterRulesForTarget(scheme.rules, options.target)) {
    if (rule.type === 'FINAL') continue
    if (rule.type === 'RULE-SET') {
      if (!rule.value || !supportsRuleSetReference(rule, 'egern', options.target)) continue
      rules.push('  - rule_set:')
      rules.push(`      match: ${yaml(rule.value)}`)
      rules.push(`      policy: ${yaml(rule.group)}`)
      rules.push('      update_interval: 86400')
      continue
    }
    const mapped = mapRule(rule)
    if (!mapped || !mapped.value) continue
    rules.push(`  - ${mapped.key}:`)
    rules.push(`      match: ${yaml(mapped.value)}`)
    rules.push(`      policy: ${yaml(rule.group)}`)
    if (mapped.noResolve) rules.push('      no_resolve: true')
  }
  rules.push('  - default:')
  rules.push(`      policy: ${yaml(finalGroup)}`)
  lines.push(...rules)
  return { text: lines.join('\n') + '\n', skipped }
}

