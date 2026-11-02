// mihomo / Clash YAML full-config generation, faithful to Tower iOS
// ConfigurationGenerator clashNode + clashConfiguration.
import type { ClientTarget, ProxyNode, RoutingRule, RuleScheme, RuleSchemeNetworkSettings, RuleSetFormat } from '../models/types'
import { yaml, yamlMultiline } from './naming'
import { compileRuleLine, resolveGroups, uniqueDisplayNames, type OutputOptions, type ResolvedGroup } from './groups'
import { effectiveGroupType, filterRulesForTarget } from '../rules/capabilities'
import { clashInlinePayload, inlineSetReference } from '../rules/inlineSets'
import { ruleSetFormatOfRule, supportsRuleSetReference } from '../rules/remoteFormats'
import {
  CHINA_CLIENT_SUBNET,
  DEFAULT_NETWORK_SETTINGS,
  effectiveNetworkSettings,
  latencyTestURL,
  supportsClientSubnet,
} from '../models/networkSettings'
import { withPolicyGroupIcons } from './groupIcons'

function dnsList(key: string, values: string[]): string[] {
  return [`  ${key}:`, ...values.map((value) => `    - ${value}`)]
}

/** 文档确认支持 mihomo `#<代理组>` DNS 后缀的客户端。 */
const CLASH_PROXIED_DNS_TARGETS: ClientTarget[] = [
  'clash-verge', 'clashmac', 'flclash', 'mihomo-party', 'clash-mi',
]

/**
 * 远程 DNS 只挑会尊重 ECS 的解析器，并带上中国子网。只把 DNS 查询交给
 * “客户端附近的解析器”不够，CDN 仍会按节点出口返回海外地址。
 */
function clashProxiedResolvers(network: RuleSchemeNetworkSettings, group: string): string[] {
  const remote = network.remoteDNSServers.filter(supportsClientSubnet)
  const chosen = remote.length
    ? remote
    : DEFAULT_NETWORK_SETTINGS.remoteDNSServers.filter(supportsClientSubnet)
  return chosen.map((value) =>
    `${value}${value.includes('#') ? '&' : '#'}${group}&ecs=${CHINA_CLIENT_SUBNET}&ecs-override=true`,
  )
}

/** 只用节点、不含 DIRECT 或其他组的策略组，且组名可安全放进 DNS 后缀。 */
function clashPureNodeGroup(
  resolved: ResolvedGroup[],
  nodeNames: Set<string>,
): string | undefined {
  return resolved.find(({ group, members }) =>
    members.length > 0
    && members.every((member) => nodeNames.has(member))
    && !group.name.includes('#')
    && !group.name.includes('&'),
  )?.group.name
}

function uniqueDNSGroupName(base: string, used: Set<string>): string {
  let name = base
  let suffix = 2
  while (used.has(name)) {
    name = `${base} ${suffix}`
    suffix += 1
  }
  return name
}

function clashDNSSection(
  network: RuleSchemeNetworkSettings,
  target?: ClientTarget,
  dnsGroup?: string,
): string[] {
  const lines = ['dns:', '  enable: true']
  if (network.dnsProtectionMode !== 'follow-scheme') {
    lines.push(
      '  enhanced-mode: fake-ip',
      '  fake-ip-range: 198.18.0.1/16',
      '  fake-ip-filter:',
      "    - '*.lan'",
      "    - '+.local'",
      "    - '+.msftconnecttest.com'",
      "    - '+.msftncsi.com'",
    )
  }
  lines.push(...dnsList('default-nameserver', network.dnsServers))
  lines.push(...dnsList('proxy-server-nameserver', network.encryptedDNSServers))
  const proxied = network.dnsProtectionMode !== 'follow-scheme' && !!dnsGroup
  if (proxied) {
    // 远程 DNS 经纯节点组发出，并带中国子网，避免落到含 DIRECT 的策略组。
    lines.push(...dnsList('nameserver', clashProxiedResolvers(network, dnsGroup)))
    if (network.dnsProtectionMode === 'standard') {
      lines.push(...dnsList('direct-nameserver', network.encryptedDNSServers))
    }
  } else {
    // 不支持 #代理组 的客户端只能走国内加密 DNS；不再写 fallback，
    // 否则国外域名会同时直连远程解析器，绕过代理。
    lines.push(...dnsList('nameserver', network.encryptedDNSServers))
  }
  // 与 Tower iOS 一致：只有文档确认支持 TUN 的客户端在严格模式下写 TUN。
  const tunTargets: ClientTarget[] = [
    'clash-apple', 'clash-verge', 'clashmac', 'flclash', 'mihomo-party', 'clash-mi',
  ]
  if (network.dnsProtectionMode === 'strict' && target && tunTargets.includes(target)) {
    lines.push(
      '',
      'tun:',
      '  enable: true',
      '  stack: mixed',
      '  auto-route: true',
      '  auto-detect-interface: true',
      '  dns-hijack:',
      '    - any:53',
      '    - tcp://any:53',
      '  strict-route: true',
    )
  }
  return lines
}

function csv(value: string | undefined): string[] {
  return (value ?? '').split(',').map((v) => v.trim()).filter(Boolean)
}

function clashNode(node: ProxyNode, name: string, target?: ClientTarget): string {
  const lines: string[] = [
    `  - name: ${yaml(name)}`,
    `    type: ${node.kind === 'ss' ? 'ss' : node.kind}`,
    `    server: ${yaml(node.server)}`,
    `    port: ${node.port}`,
  ]
  const alpn = () => {
    const entries = csv(node.alpn)
    if (entries.length) lines.push(`    alpn: [${entries.map(yaml).join(', ')}]`)
  }
  const certFP = () => {
    if (node.certificateFingerprint)
      lines.push(`    fingerprint: ${yaml(node.certificateFingerprint)}`)
  }
  const clientFP = () => {
    if (node.fingerprint) lines.push(`    client-fingerprint: ${yaml(node.fingerprint)}`)
  }
  const reality = () => {
    if (!node.realityPublicKey) return
    lines.push('    reality-opts:')
    lines.push(`      public-key: ${yaml(node.realityPublicKey)}`)
    if (node.realityShortID) lines.push(`      short-id: ${yaml(node.realityShortID)}`)
    // mihomo defaults the fingerprint when REALITY is on but absent.
    lines.push(`    client-fingerprint: ${yaml(node.fingerprint ?? 'chrome')}`)
  }
  const transport = () => {
    lines.push(`    tls: ${node.tls}`)
    lines.push(`    skip-cert-verify: ${node.skipCertificateVerification}`)
    if (node.sni) {
      // Trojan's key is `sni`; `servername` belongs to VMess/VLESS.
      lines.push(`    ${node.kind === 'trojan' ? 'sni' : 'servername'}: ${yaml(node.sni)}`)
    }
    if (node.kind === 'trojan') alpn()
    certFP()
    reality()
    if (node.kind === 'vless' && node.flow) lines.push(`    flow: ${yaml(node.flow)}`)
    if (node.kind === 'vless' && node.vlessEncryption)
      lines.push(`    encryption: ${yaml(node.vlessEncryption)}`)
    clientFP()
    const t = node.transport
    if (t && t !== 'tcp') {
      lines.push(`    network: ${yaml(t === 'httpupgrade' ? 'ws' : t)}`)
      switch (t) {
        case 'ws':
        case 'httpupgrade': {
          lines.push('    ws-opts:')
          lines.push(`      path: ${yaml(node.path || '/')}`)
          if (node.hostHeader) {
            lines.push('      headers:')
            lines.push(`        Host: ${yaml(node.hostHeader)}`)
          }
          if (t === 'httpupgrade') lines.push('      v2ray-http-upgrade: true')
          break
        }
        case 'grpc': {
          lines.push('    grpc-opts:')
          if (node.path) {
            const service = node.path.startsWith('/') ? node.path.slice(1) : node.path
            lines.push(`      grpc-service-name: ${yaml(service)}`)
          }
          break
        }
        case 'http': {
          lines.push('    http-opts:')
          lines.push(`      path: [${yaml(node.path || '/')}]`)
          if (node.hostHeader) {
            lines.push('      headers:')
            lines.push(`        Host: [${yaml(node.hostHeader)}]`)
          }
          break
        }
        case 'h2': {
          lines.push('    h2-opts:')
          lines.push(`      path: ${yaml(node.path || '/')}`)
          if (node.hostHeader) lines.push(`      host: [${yaml(node.hostHeader)}]`)
          break
        }
        case 'xhttp': {
          lines.push('    xhttp-opts:')
          lines.push(`      path: ${yaml(node.path || '/')}`)
          if (node.hostHeader) lines.push(`      host: ${yaml(node.hostHeader)}`)
          break
        }
      }
    }
  }

  switch (node.kind) {
    case 'ss': {
      lines.push(`    cipher: ${yaml(node.cipher ?? 'aes-256-gcm')}`)
      lines.push(`    password: ${yaml(node.password ?? '')}`)
      lines.push(`    udp: ${node.udpRelayEnabled ?? true}`)
      if (node.shadowTLS) {
        lines.push('    plugin: shadow-tls')
        if (node.fingerprint) lines.push(`    client-fingerprint: ${yaml(node.fingerprint)}`)
        lines.push('    plugin-opts:')
        lines.push(`      host: ${yaml(node.shadowTLS.host)}`)
        lines.push(`      password: ${yaml(node.shadowTLS.password)}`)
        lines.push(`      version: ${node.shadowTLS.version}`)
        if (node.shadowTLS.skipCertificateVerification) lines.push('      skip-cert-verify: true')
      } else if (node.plugin === 'v2ray-plugin') {
        lines.push('    plugin: v2ray-plugin')
        lines.push('    plugin-opts:')
        lines.push('      mode: websocket')
        if (node.pluginMux !== undefined) lines.push(`      mux: ${node.pluginMux}`)
        if (node.tls) lines.push('      tls: true')
        if (node.hostHeader) lines.push(`      host: ${yaml(node.hostHeader)}`)
        if (node.path) lines.push(`      path: ${yaml(node.path)}`)
      } else if (node.obfs) {
        lines.push('    plugin: obfs')
        lines.push('    plugin-opts:')
        lines.push(`      mode: ${yaml(node.obfs)}`)
        if (node.obfsParam) lines.push(`      host: ${yaml(node.obfsParam)}`)
      }
      break
    }
    case 'ssr': {
      lines.push(`    cipher: ${yaml(node.cipher ?? 'aes-256-cfb')}`)
      lines.push(`    password: ${yaml(node.password ?? '')}`)
      lines.push(`    protocol: ${yaml(node.protocolName ?? 'origin')}`)
      lines.push(`    obfs: ${yaml(node.obfs ?? 'plain')}`)
      if (node.protocolParam) lines.push(`    protocol-param: ${yaml(node.protocolParam)}`)
      if (node.obfsParam) lines.push(`    obfs-param: ${yaml(node.obfsParam)}`)
      break
    }
    case 'vmess':
      lines.push(`    uuid: ${yaml(node.uuid ?? '')}`)
      lines.push(`    alterId: ${node.alterID ?? 0}`)
      lines.push(`    cipher: ${yaml(node.cipher ?? 'auto')}`)
      lines.push('    udp: true')
      transport()
      break
    case 'vless':
      lines.push(`    uuid: ${yaml(node.uuid ?? '')}`)
      lines.push('    udp: true')
      transport()
      break
    case 'trojan':
      lines.push(`    password: ${yaml(node.password ?? '')}`)
      lines.push('    udp: true')
      transport()
      break
    case 'hysteria2':
      lines.push(`    password: ${yaml(node.password ?? '')}`)
      lines.push(`    skip-cert-verify: ${node.skipCertificateVerification}`)
      lines.push('    udp: true')
      if (node.sni) lines.push(`    sni: ${yaml(node.sni)}`)
      if (node.portHopping) lines.push(`    ports: ${yaml(node.portHopping)}`)
      alpn()
      certFP()
      if (node.obfs) {
        lines.push(`    obfs: ${yaml(node.obfs)}`)
        lines.push(`    obfs-password: ${yaml(node.obfsParam ?? '')}`)
      }
      break
    case 'hysteria':
      lines.push(`    auth-str: ${yaml(node.password ?? '')}`)
      lines.push(`    up: ${node.upMbps ?? 50}`)
      lines.push(`    down: ${node.downMbps ?? 100}`)
      lines.push(`    skip-cert-verify: ${node.skipCertificateVerification}`)
      if (node.sni) lines.push(`    sni: ${yaml(node.sni)}`)
      certFP()
      if (node.obfs && node.obfs.toLowerCase() !== 'none') lines.push(`    obfs: ${yaml(node.obfs)}`)
      if (node.protocolName) lines.push(`    protocol: ${yaml(node.protocolName)}`)
      alpn()
      break
    case 'tuic':
      lines.push(`    uuid: ${yaml(node.uuid ?? '')}`)
      lines.push(`    password: ${yaml(node.password ?? '')}`)
      lines.push(`    skip-cert-verify: ${node.skipCertificateVerification}`)
      lines.push('    udp: true')
      if (node.sni) lines.push(`    sni: ${yaml(node.sni)}`)
      if (node.congestionControl) lines.push(`    congestion-controller: ${yaml(node.congestionControl)}`)
      if (node.udpRelayMode) lines.push(`    udp-relay-mode: ${yaml(node.udpRelayMode)}`)
      if (node.portHopping) lines.push(`    ports: ${yaml(node.portHopping)}`)
      alpn()
      certFP()
      clientFP()
      break
    case 'anytls':
      lines.push(`    password: ${yaml(node.password ?? '')}`)
      lines.push(`    skip-cert-verify: ${node.skipCertificateVerification}`)
      lines.push('    udp: true')
      if (node.sni) lines.push(`    sni: ${yaml(node.sni)}`)
      if (node.idleSessionCheckInterval !== undefined)
        lines.push(`    idle-session-check-interval: ${node.idleSessionCheckInterval}`)
      if (node.idleSessionTimeout !== undefined)
        lines.push(`    idle-session-timeout: ${node.idleSessionTimeout}`)
      if (node.minIdleSession !== undefined)
        lines.push(`    min-idle-session: ${node.minIdleSession}`)
      alpn()
      certFP()
      clientFP()
      break
    case 'snell':
      lines.push(`    psk: ${yaml(node.password ?? '')}`)
      if (node.version !== undefined) lines.push(`    version: ${node.version}`)
      if ((node.version ?? 4) >= 3) lines.push('    udp: true')
      if (node.obfs && node.obfs.toLowerCase() !== 'none') {
        lines.push('    obfs-opts:')
        lines.push(`      mode: ${yaml(node.obfs)}`)
        if (node.obfsParam) lines.push(`      host: ${yaml(node.obfsParam)}`)
      }
      break
    case 'ssh': {
      // Stash spells the login `user`; mihomo and Shadowrocket use `username`.
      lines.push(`    ${target === 'clash' ? 'user' : 'username'}: ${yaml(node.username ?? '')}`)
      if (node.password) lines.push(`    password: ${yaml(node.password)}`)
      const privateKey = node.ssh?.privateKey?.trim()
      if (privateKey) lines.push(`    private-key: ${yamlMultiline(privateKey)}`)
      if (node.ssh?.privateKeyPassphrase) {
        lines.push(`    private-key-passphrase: ${yaml(node.ssh.privateKeyPassphrase)}`)
      }
      const hostKeys = node.ssh?.hostKeys ?? []
      if (hostKeys.length > 0) lines.push(`    host-key: [${hostKeys.map(yaml).join(', ')}]`)
      const hostKeyAlgorithms = node.ssh?.hostKeyAlgorithms ?? []
      if (hostKeyAlgorithms.length > 0) {
        lines.push(`    host-key-algorithms: [${hostKeyAlgorithms.map(yaml).join(', ')}]`)
      }
      break
    }
    case 'masque': {
      const options = node.masque
      if (!options) break
      lines.push(`    private-key: ${yaml(options.privateKey ?? '')}`)
      lines.push(`    public-key: ${yaml(options.publicKey ?? '')}`)
      lines.push(`    udp: ${node.udpRelayEnabled ?? false}`)
      if (options.ipv4) lines.push(`    ip: ${yaml(options.ipv4)}`)
      if (options.ipv6) lines.push(`    ipv6: ${yaml(options.ipv6)}`)
      if (options.mtu !== undefined) lines.push(`    mtu: ${options.mtu}`)
      const network = options.network ?? 'quic'
      // mihomo / Shadowrocket 把 MASQUE 的 QUIC 写作 network: quic。
      lines.push(`    network: ${yaml(network === 'h3' ? 'quic' : network)}`)
      if (node.sni) lines.push(`    sni: ${yaml(node.sni)}`)
      const defaultRemoteDNS = ['clash-apple', 'clash-verge', 'clashmac', 'flclash', 'mihomo-party', 'clash-mi']
        .includes(target ?? '')
      const remoteDNS = options.remoteDNSResolve ?? (defaultRemoteDNS ? true : undefined)
      if (remoteDNS !== undefined) lines.push(`    remote-dns-resolve: ${remoteDNS}`)
      const dns = options.dns ?? (remoteDNS === true ? ['1.1.1.1', '8.8.8.8'] : undefined)
      if (dns) lines.push(`    dns: [${dns.map(yaml).join(', ')}]`)
      break
    }
    case 'trusttunnel':
      lines.push(`    username: ${yaml(node.username ?? '')}`)
      lines.push(`    password: ${yaml(node.password ?? '')}`)
      if (node.sni) lines.push(`    sni: ${yaml(node.sni)}`)
      lines.push(`    skip-cert-verify: ${node.skipCertificateVerification}`)
      alpn()
      certFP()
      if (node.trustTunnel?.quic) lines.push('    quic: true')
      if (target !== 'clash') {
        if (node.udpRelayEnabled) lines.push('    udp: true')
        clientFP()
      }
      break
    case 'socks5':
    case 'http':
      if (node.username) lines.push(`    username: ${yaml(node.username)}`)
      if (node.password) lines.push(`    password: ${yaml(node.password)}`)
      lines.push(`    tls: ${node.tls}`)
      if (node.tls) {
        if (node.sni) lines.push(`    sni: ${yaml(node.sni)}`)
        lines.push(`    skip-cert-verify: ${node.skipCertificateVerification}`)
        alpn()
        certFP()
        clientFP()
      }
      break
    case 'wireguard': {
      if (!node.wireGuardPrivateKey || !node.wireGuardPublicKey) return lines.join('\n')
      if (node.wireGuardPrivateKey) lines.push(`    private-key: ${yaml(node.wireGuardPrivateKey)}`)
      if (node.wireGuardPublicKey) lines.push(`    public-key: ${yaml(node.wireGuardPublicKey)}`)
      if (node.wireGuardPreSharedKey) lines.push(`    pre-shared-key: ${yaml(node.wireGuardPreSharedKey)}`)
      const ipv4 = node.wireGuardIPv4
      if (ipv4) lines.push(`    ip: ${yaml(ipv4.includes('/') ? ipv4 : `${ipv4}/32`)}`)
      if (node.wireGuardIPv6) lines.push(`    ipv6: ${yaml(node.wireGuardIPv6)}`)
      const reserved = csv(node.wireGuardReserved)
      if (reserved.length) lines.push(`    reserved: [${reserved.join(', ')}]`)
      if (node.wireGuardMTU) lines.push(`    mtu: ${node.wireGuardMTU}`)
      lines.push('    udp: true')
      break
    }
    default:
      break
  }
  return lines.join('\n')
}

/** mihomo 能表达的代理类型；不在表内或字段缺失的节点必须剔除，
 *  否则整份配置校验失败，客户端会报「订阅创建失败」。 */
const CLASH_KINDS = new Set([
  'ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria2', 'hysteria',
  'tuic', 'anytls', 'snell', 'socks5', 'http', 'wireguard', 'ssh', 'trusttunnel', 'masque',
])

function masqueSupported(node: ProxyNode): boolean {
  const options = node.masque
  if (node.kind !== 'masque' || !options || options.mode !== 'keyConnectIP') return false
  if (!options.privateKey || !options.publicKey || !(options.ipv4 || options.ipv6)) return false
  if (options.mtu !== undefined && (options.mtu < 1280 || options.mtu > 1500)) return false
  if (options.network && !['quic', 'h3', 'h2'].includes(options.network.toLowerCase())) return false
  return !node.username && !node.password && !node.alpn
    && !node.certificateFingerprint && !node.skipCertificateVerification
}

function clashSupported(node: ProxyNode, target?: ClientTarget): boolean {
  if (!CLASH_KINDS.has(node.kind)) return false
  if (node.kind === 'masque') {
    // 密钥模式只给 mihomo 系和 Shadowrocket；Stash / Karing / 通用 YAML 不写。
    return masqueSupported(node) && target !== undefined
      && ['clash-apple', 'clash-verge', 'clashmac', 'flclash', 'mihomo-party', 'clash-mi', 'shadowrocket']
        .includes(target)
  }
  if (node.kind === 'wireguard') return !!(node.wireGuardPrivateKey && node.wireGuardPublicKey)
  if (node.kind === 'ssh') {
    // Shadowrocket 2.2.92 会在认证前关闭私钥会话；Surge 不在这个 writer 里。
    if (target === 'shadowrocket' && node.ssh?.privateKey?.trim()) return false
    // Stash 不能固定 host key，丢弃固定会变成信任任意服务器。
    if (target === 'clash' && (node.ssh?.hostKeys?.length ?? 0) > 0) return false
  }
  if (node.kind === 'trusttunnel') {
    // Karing 没有 TrustTunnel；Stash 3.4 的 HTTP/2 会超时，只接受 H3。
    if (target === 'karing') return false
    if (target === 'clash' && !node.trustTunnel?.quic) return false
  }
  // Karing 的客户端指南没有 Snell，写入会得到无法加载的配置。
  if (node.kind === 'snell' && target === 'karing') return false
  return true
}

/** 供导出页统计：这些节点不会写入 Clash YAML。 */
export function clashSkippedCount(nodes: ProxyNode[], target?: ClientTarget): number {
  return nodes.filter((node) => !node.isSubscriptionMetadata && !clashSupported(node, target)).length
}

export function generateClashYAML(
  nodes: ProxyNode[],
  scheme: RuleScheme,
  options: OutputOptions = {},
): string {
  scheme = withPolicyGroupIcons(scheme, options.iconTarget ?? options.target)
  const nodesOnly = options.contentMode === 'nodes'
  const remoteSources = nodesOnly
    ? []
    : (options.remoteSubscriptions ?? []).filter((source) => /^https?:\/\//i.test(source.url))
  const remoteSourceIDs = new Set(remoteSources.map((source) => source.id))
  const usable = nodes.filter((n) => !n.isSubscriptionMetadata && clashSupported(n, options.target))
  const inlineNodes = usable.filter((n) => !(n.sourceID && remoteSourceIDs.has(n.sourceID)))
  const names = uniqueDisplayNames(usable, (s) => s.replace(/["\\]/g, '').trim() || '节点', options.nameForNode)
  const displayName = (n: ProxyNode) => names.get(n.id)!
  if (nodesOnly) {
    // Node-only subscriptions are merged into an existing profile; a full
    // skeleton would overwrite the host's ports, DNS and mode.
    if (inlineNodes.length === 0) return 'proxies: []\n'
    return ['proxies:', ...inlineNodes.map((node) => clashNode(node, displayName(node), options.target))].join('\n') + '\n'
  }
  const resolved = resolveGroups(scheme, usable, displayName)
  const network = effectiveNetworkSettings(scheme.networkSettings)
  const testURL = latencyTestURL(scheme.networkSettings)
  const providerKeys = new Map(remoteSources.map((source, index) => [source.id, `tower-source-${index + 1}`]))
  const remoteNameToSource = new Map<string, string>()
  for (const node of usable) {
    if (node.sourceID && remoteSourceIDs.has(node.sourceID)) {
      remoteNameToSource.set(displayName(node), node.sourceID)
    }
  }

  const nodeNames = new Set(usable.map(displayName))
  const reusableDNSGroup = !nodesOnly && options.target && CLASH_PROXIED_DNS_TARGETS.includes(options.target)
    ? clashPureNodeGroup(resolved, nodeNames)
    : undefined
  const dedicatedDNSGroup = !nodesOnly && !reusableDNSGroup
    && options.target && CLASH_PROXIED_DNS_TARGETS.includes(options.target)
    && network.dnsProtectionMode !== 'follow-scheme'
    && (inlineNodes.length > 0 || remoteSources.length > 0)
    ? uniqueDNSGroupName(
        'DNS 自动选择',
        new Set([...resolved.map(({ group }) => group.name), ...nodeNames]),
      )
    : undefined
  const dnsGroup = reusableDNSGroup ?? dedicatedDNSGroup

  const out: string[] = [
    'mixed-port: 7890',
    'allow-lan: false',
    `mode: ${nodesOnly ? 'global' : 'rule'}`,
    'log-level: info',
    'unified-delay: true',
    `ipv6: ${network.ipv6Enabled ?? true}`,
    // 不写 external-controller / dns.listen：Clash Verge 等宿主会自己指定端口，
    // 写死容易与宿主端口冲突导致「订阅创建失败」。
    //
    // DNS 必须写全：fake-ip 模式下若缺少 proxy-server-nameserver，
    // 内核会把「代理服务器域名」也解析成 198.18.x.x 假 IP，
    // 于是所有节点 TCP 层可达但握手必然超时（表现为「测速全部 timeout」）。
    ...clashDNSSection(network, options.target, dnsGroup),
  ]
  if (inlineNodes.length > 0) {
    out.push('proxies:')
    for (const node of inlineNodes) out.push(clashNode(node, displayName(node), options.target))
  } else {
    out.push('proxies: []')
  }

  if (remoteSources.length > 0) {
    out.push('proxy-providers:')
    for (const source of remoteSources) {
      const key = providerKeys.get(source.id)!
      out.push(`  ${key}:`)
      out.push('    type: http')
      out.push(`    url: ${yaml(source.url)}`)
      out.push(`    path: ${yaml(`./providers/${key}.yaml`)}`)
      out.push('    interval: 86400')
      if (source.userAgent) {
        out.push('    header:')
        out.push('      User-Agent:')
        out.push(`        - ${yaml(source.userAgent)}`)
      }
    }
  }

  if (!nodesOnly) {
    out.push('proxy-groups:')
    for (const { group, members } of resolved) {
      const kind = effectiveGroupType(group.type, options.target)
      out.push(`  - name: ${yaml(group.name)}`)
      out.push(`    type: ${kind}`)
      if (group.icon) out.push(`    icon: ${yaml(group.icon)}`)
      if (kind !== 'select') {
        out.push(`    url: ${yaml(group.url ?? testURL)}`)
        out.push(`    interval: ${group.interval ?? 300}`)
        if (group.tolerance) out.push(`    tolerance: ${group.tolerance}`)
      }
      if (kind === 'load-balance') {
        const strategy = group.algorithm?.trim().toLowerCase()
        if (strategy && ['random', 'round-robin', 'consistent-hashing'].includes(strategy)) {
          out.push(`    strategy: ${yaml(strategy)}`)
        }
      }
      const inlineMembers = members.filter((member) => !remoteNameToSource.has(member))
      const providers = group.nodeFilter
        ? [...new Set(
            members
              .map((member) => remoteNameToSource.get(member))
              .filter((sourceID): sourceID is string => !!sourceID),
          )].map((sourceID) => providerKeys.get(sourceID)).filter(Boolean) as string[]
        : []
      const list = inlineMembers.length ? inlineMembers : providers.length ? [] : ['DIRECT']
      if (list.length > 0) {
        out.push('    proxies:')
        for (const member of list) out.push(`      - ${yaml(member)}`)
      }
      if (providers.length > 0) {
        out.push('    use:')
        for (const provider of providers) out.push(`      - ${yaml(provider)}`)
        if (group.nodeFilter) out.push(`    filter: ${yaml(group.nodeFilter)}`)
      }
    }
    if (dedicatedDNSGroup) {
      out.push(`  - name: ${yaml(dedicatedDNSGroup)}`)
      out.push('    type: url-test')
      out.push(`    url: ${yaml(testURL)}`)
      out.push('    interval: 300')
      out.push('    tolerance: 50')
      out.push('    hidden: true')
      if (inlineNodes.length) {
        out.push('    proxies:')
        for (const node of inlineNodes) out.push(`      - ${yaml(displayName(node))}`)
      }
      if (providerKeys.size) {
        out.push('    use:')
        for (const key of providerKeys.values()) out.push(`      - ${yaml(key)}`)
      }
    }

    const filteredRules = filterRulesForTarget(scheme.rules, options.target)
    const remoteRuleSets = new Map<string, {
      key: string
      format: RuleSetFormat
      behavior: string
      extension: string
    }>()
    for (const rule of filteredRules) {
      if (rule.type !== 'RULE-SET' || !rule.value || !/^https?:\/\//i.test(rule.value)) continue
      if (!supportsRuleSetReference(rule, 'yaml', options.target)) continue
      const format = ruleSetFormatOfRule(rule)
      if (!format) continue
      const behavior = format === 'mrs'
        ? (rule.ruleSetBehavior ?? '')
        : (rule.ruleSetBehavior || 'classical')
      if (format === 'mrs' && !['domain', 'ipcidr'].includes(behavior)) continue
      if (remoteRuleSets.has(rule.value)) continue
      remoteRuleSets.set(rule.value, {
        key: `tower-rule-set-${remoteRuleSets.size + 1}`,
        format,
        behavior,
        extension: format === 'mrs' ? 'mrs' : format === 'yaml' ? 'yaml' : 'list',
      })
    }
    const inlineRuleSets = new Map<string, {
      key: string
      meta: NonNullable<RoutingRule['inlineSet']>
      lines: string[]
    }>()
    for (const rule of filteredRules) {
      if (!rule.inlineSet) continue
      const existing = inlineRuleSets.get(rule.inlineSet.id)
      if (existing) {
        const line = clashInlinePayload(rule, existing.meta)
        if (line && !existing.lines.includes(line)) existing.lines.push(line)
        continue
      }
      const line = clashInlinePayload(rule, rule.inlineSet)
      if (!line) continue
      inlineRuleSets.set(rule.inlineSet.id, {
        key: `tower-local-${inlineRuleSets.size + 1}`,
        meta: rule.inlineSet,
        lines: [line],
      })
    }

    if (remoteRuleSets.size > 0 || inlineRuleSets.size > 0) {
      out.push('rule-providers:')
      for (const [url, provider] of remoteRuleSets) {
        out.push(`  ${provider.key}:`)
        out.push('    type: http')
        out.push(`    behavior: ${provider.behavior}`)
        out.push(`    format: ${provider.format === 'mrs' ? 'mrs' : provider.format === 'yaml' ? 'yaml' : 'text'}`)
        out.push(`    url: ${yaml(url)}`)
        out.push(`    path: ${yaml(`./rules/${provider.key}.${provider.extension}`)}`)
        out.push('    interval: 86400')
      }
      for (const provider of inlineRuleSets.values()) {
        out.push(`  ${provider.key}:`)
        out.push('    type: inline')
        out.push(`    behavior: ${provider.meta.behavior}`)
        out.push('    payload:')
        for (const line of provider.lines) out.push(`      - ${yaml(line)}`)
      }
    }

    out.push('rules:')
    const emittedInlineSets = new Set<string>()
    for (const rule of filteredRules) {
      if (rule.inlineSet) {
        if (emittedInlineSets.has(rule.inlineSet.id)) continue
        const provider = inlineRuleSets.get(rule.inlineSet.id)
        if (provider) {
          emittedInlineSets.add(rule.inlineSet.id)
          out.push(`  - ${inlineSetReference(provider.key, provider.meta, rule.group)}`)
          continue
        }
      }
      if (rule.type === 'RULE-SET' && rule.value) {
        const provider = remoteRuleSets.get(rule.value)
        if (provider) {
          out.push(`  - ${compileRuleLine({ ...rule, value: provider.key }, rule.group)}`)
        }
        continue
      }
      out.push(`  - ${compileRuleLine(rule, rule.group)}`)
    }
  }

  return out.join('\n') + '\n'
}
