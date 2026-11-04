// sing-box JSON full-config generation.
import type {
  ClientTarget,
  ProxyNode,
  RoutingRule,
  RuleScheme,
  RuleSchemeNetworkSettings,
} from '../models/types'
import { resolveGroups, uniqueDisplayNames, type OutputOptions } from './groups'
import { effectiveGroupType, filterRulesForTarget } from '../rules/capabilities'
import { nodeSupportedForTarget, v2rayPluginSupported } from './nodeCapabilities'
import { ruleSetFormatOfRule, supportsRuleSetReference } from '../rules/remoteFormats'
import {
  CHINA_CLIENT_SUBNET,
  DEFAULT_NETWORK_SETTINGS,
  effectiveNetworkSettings,
  encryptDNServer,
  latencyTestURL,
  supportsClientSubnet,
  type EncryptedDNSEntry,
} from '../models/networkSettings'
import { CHINA_IP_CIDRS } from '../rules/chinaCIDRs'

type SingBoxDNSServer = Record<string, unknown>

const CHINA_RULE_SET_TAG = 'tower-geoip-cn'
const REMOTE_CN_TAG = 'remote-cn'

/** 加密 DNS 条目 → sing-box server，补上 TLS 名称、路径与启动解析器。 */
function encryptedDNSServer(
  entry: EncryptedDNSEntry,
  tag: string,
  proxyGroup?: string,
  bootstrapTag?: string,
): SingBoxDNSServer {
  const defaultPort = entry.type === 'https' || entry.type === 'h3' ? 443 : 853
  return {
    type: entry.type,
    tag,
    server: entry.server,
    server_port: entry.port ?? defaultPort,
    ...(entry.path ? { path: entry.path } : {}),
    tls: { enabled: true, server_name: entry.serverName },
    ...(proxyGroup ? { detour: proxyGroup } : {}),
    ...(bootstrapTag && !entry.isLiteral ? { domain_resolver: bootstrapTag } : {}),
  }
}

function dnsTags(count: number, base: string): string[] {
  return Array.from({ length: count }, (_, index) => index === 0 ? base : `${base}-${index + 1}`)
}

function singBoxDNS(network: RuleSchemeNetworkSettings, proxyGroup?: string): {
  servers: SingBoxDNSServer[]
  final: string
  localTag: string
  domesticTag: string
  remoteTag: string
} {
  const servers: SingBoxDNSServer[] = []
  const plainTags = dnsTags(network.dnsServers.length, 'local')
  network.dnsServers.forEach((server, index) => {
    servers.push({ type: 'udp', tag: plainTags[index], server })
  })
  const bootstrapTag = plainTags[0]
  const domesticTags = dnsTags(network.encryptedDNSServers.length, 'domestic')
  network.encryptedDNSServers.forEach((value, index) => {
    const entry = encryptDNServer(value)
    if (!entry) return
    servers.push(encryptedDNSServer(entry, domesticTags[index], undefined, bootstrapTag))
  })
  const remoteTags = dnsTags(network.remoteDNSServers.length, 'remote')
  network.remoteDNSServers.forEach((value, index) => {
    const entry = encryptDNServer(value)
    if (!entry) return
    // 远程 DNS 只经纯节点组，避免解析流量落到某个含 DIRECT 的策略组。
    servers.push(encryptedDNSServer(entry, remoteTags[index], proxyGroup, bootstrapTag))
  })
  const localTag = plainTags[0] ?? domesticTags[0] ?? remoteTags[0] ?? 'local'
  const domesticTag = domesticTags[0] ?? localTag
  const remoteTag = remoteTags[0] ?? domesticTag
  const final = proxyGroup
    ? remoteTag
    : domesticTag
  return { servers, final, localTag, domesticTag, remoteTag }
}

/** 策略组默认出口是否会落到 DIRECT；只有 selector 看默认项，其余组看全部成员。 */
function defaultsToDirect(
  tag: string,
  definitions: Map<string, Outbound>,
  visiting = new Set<string>(),
): boolean {
  if (tag === 'direct' || tag === 'DIRECT') return true
  if (visiting.has(tag)) return false
  const definition = definitions.get(tag)
  if (!definition) return false
  const children = definition.outbounds as string[] | undefined
  if (!children?.length) return false
  const next = new Set(visiting).add(tag)
  if (definition.type === 'selector') {
    const selected = (definition.default as string | undefined) ?? children[0]
    if (!children.includes(selected)) return false
    return defaultsToDirect(selected, definitions, next)
  }
  return children.every((child) => defaultsToDirect(child, definitions, next))
}

/** 只用节点、不含 DIRECT 或其他组的策略组，可作为 DNS 解析路径。 */
function pureNodeGroupTag(groupTags: Outbound[], nodeTags: Set<string>): string | undefined {
  return groupTags.find((candidate) => {
    const tag = candidate.tag
    const children = candidate.outbounds as string[] | undefined
    return typeof tag === 'string'
      && !!children?.length
      && children.every((child) => nodeTags.has(child))
  })?.tag as string | undefined
}

function uniqueTag(base: string, used: Set<string>): string {
  let tag = base
  let suffix = 2
  while (used.has(tag)) {
    tag = `${base} ${suffix}`
    suffix += 1
  }
  return tag
}

/** 带中国子网的远程解析器；优先用户列表里支持 ECS 的第一项。 */
function chinaECSServer(
  network: RuleSchemeNetworkSettings,
  proxyGroup: string,
  servers: SingBoxDNSServer[],
  bootstrapTag: string,
): { tag: string; server: SingBoxDNSServer } | undefined {
  if (!CHINA_IP_CIDRS.length) return undefined
  const value = network.remoteDNSServers.find(supportsClientSubnet)
    ?? DEFAULT_NETWORK_SETTINGS.remoteDNSServers.find(supportsClientSubnet)
  const entry = value ? encryptDNServer(value) : undefined
  if (!entry) return undefined
  const used = new Set(servers.map((server) => server.tag).filter((tag): tag is string => typeof tag === 'string'))
  const tag = uniqueTag(REMOTE_CN_TAG, used)
  return { tag, server: encryptedDNSServer(entry, tag, proxyGroup, bootstrapTag) }
}

interface DNSBucket {
  [key: string]: unknown
  action: 'route' | 'reject'
  server?: string
  client_subnet?: string
  domain: string[]
  domain_suffix: string[]
  domain_keyword: string[]
  domain_regex: string[]
  rule_set: string[]
}

/**
 * 把路由里的域名条件投影成 DNS 规则：DIRECT 组用国内加密 DNS，代理组用远程 DNS。
 * 只投影域名条件，不投影 IP / GEOIP，避免 DNS 查询先落到错误的解析器。
 */
function projectedDNSRules(
  rules: RoutingRule[],
  definitions: Map<string, Outbound>,
  protection: RuleSchemeNetworkSettings['dnsProtectionMode'],
  domesticTag: string,
  remoteTag: string,
  chinaTag: string | undefined,
  ruleSetTags: Map<string, string>,
  dnsRuleSetTags?: Map<string, string>,
): Record<string, unknown>[] {
  if (protection === 'follow-scheme') return []
  // 保持路由规则顺序；只有连续命中同一个解析器时才合并，避免重复域名
  // 因分桶而改变先到先得的匹配结果。
  const output: Record<string, unknown>[] = []
  let currentKey = ''
  let current: DNSBucket | undefined
  const append = (
    key: string,
    action: 'route' | 'reject',
    server: string | undefined,
    field: keyof DNSBucket,
    value: string,
    clientSubnet?: string,
  ) => {
    if (!current || currentKey !== key) {
      current = {
        action,
        server,
        ...(clientSubnet ? { client_subnet: clientSubnet } : {}),
        domain: [], domain_suffix: [], domain_keyword: [], domain_regex: [], rule_set: [],
      }
      currentKey = key
      output.push(current)
    }
    ;(current[field] as string[]).push(value)
  }
  const routeTarget = (group: string): { key: string; server: string; clientSubnet?: string } => {
    const direct = defaultsToDirect(group, definitions)
    if (direct && protection === 'strict' && chinaTag) {
      return { key: `route:${chinaTag}`, server: chinaTag, clientSubnet: CHINA_CLIENT_SUBNET }
    }
    const server = direct && protection !== 'strict' ? domesticTag : remoteTag
    return { key: `route:${server}`, server }
  }
  for (const rule of rules) {
    if (rule.type === 'RULE-SET') {
      const value = rule.value ?? ''
      const dnsTag = dnsRuleSetTags?.get(value)
      const tag = ruleSetTags.get(value)
      if (!dnsTag && (!tag || rule.ruleSetBehavior !== 'domain')) continue
      const group = rule.group
      if (group.toUpperCase() === 'REJECT') {
        append('reject', 'reject', undefined, 'rule_set', dnsTag ?? tag!)
      } else {
        const target = routeTarget(group)
        append(target.key, 'route', target.server, 'rule_set', dnsTag ?? tag!, target.clientSubnet)
      }
      continue
    }
    if (!rule.value) continue
    const field = rule.type === 'DOMAIN' ? 'domain'
      : rule.type === 'DOMAIN-SUFFIX' ? 'domain_suffix'
        : rule.type === 'DOMAIN-KEYWORD' ? 'domain_keyword'
          : rule.type === 'DOMAIN-REGEX' ? 'domain_regex'
            : undefined
    if (!field) continue
    const group = rule.group
    if (group.toUpperCase() === 'REJECT') {
      append('reject', 'reject', undefined, field, rule.value)
    } else {
      const target = routeTarget(group)
      append(target.key, 'route', target.server, field, rule.value, target.clientSubnet)
    }
  }
  return output
}

type Outbound = Record<string, unknown>

/** basic CONNECT-IP 只有 sing-box 的 masque-client endpoint 能完整表达。 */
function singboxMasqueSupported(node: ProxyNode): boolean {
  const options = node.masque
  if (!options || options.mode !== 'basicConnectIP') return false
  if (!node.server || !Number.isInteger(node.port) || node.port < 1 || node.port > 65535) return false
  if (/[\s,/\\@?#=]/.test(node.server)) return false
  if (node.shadowTLS || node.realityPublicKey || node.portHopping) return false
  if (node.certificateFingerprint) return false
  if (options.mtu !== undefined && (options.mtu < 1280 || options.mtu > 1500)) return false
  if (options.httpVersion !== undefined && ![1, 2, 3].includes(options.httpVersion)) return false
  // HTTP/1.1 与 HTTP/2 需要 TLS；HTTP/3（QUIC）可以不带。
  if (options.httpVersion !== undefined && options.httpVersion !== 3 && !node.tls) return false
  return !(node.username ?? '').includes(':')
}

function masqueBasicEndpoint(node: ProxyNode, name: string): Outbound | undefined {
  if (!singboxMasqueSupported(node)) return undefined
  const options = node.masque!
  const endpoint: Outbound = {
    type: 'masque-client',
    tag: name,
    server: node.server,
    server_port: node.port,
    version: options.httpVersion ?? 3,
    system: false,
  }
  if (node.username) endpoint.username = node.username
  if (node.password) endpoint.password = node.password
  if (node.path) endpoint.path = node.path
  if (options.mtu !== undefined) endpoint.mtu = options.mtu
  if (options.headers && Object.keys(options.headers).length) endpoint.headers = options.headers
  if (options.disableVersionFallback !== undefined) {
    endpoint.disable_version_fallback = options.disableVersionFallback
  }
  if (node.tls) {
    const tls: Record<string, unknown> = {
      enabled: true,
      insecure: node.skipCertificateVerification,
    }
    if (node.sni) tls.server_name = node.sni
    if (options.certificate?.length) tls.certificate = options.certificate
    const alpn = (node.alpn ?? '').split(',').map((s) => s.trim()).filter(Boolean)
    if (alpn.length) tls.alpn = alpn
    endpoint.tls = tls
  }
  return endpoint
}

function csvValues(value: string | undefined): string[] {
  return (value ?? '').split(',').map((item) => item.trim()).filter(Boolean)
}

/** WireGuard `reserved` is three bytes; invalid input means the node cannot connect. */
function wireGuardReservedBytes(node: ProxyNode): number[] | undefined {
  const values = csvValues(node.wireGuardReserved)
  if (!values.length) return []
  const bytes = values.map(Number)
  return bytes.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
    ? bytes
    : undefined
}

function singboxWireGuardSupported(node: ProxyNode): boolean {
  if (node.kind !== 'wireguard') return false
  if (!node.server || !Number.isInteger(node.port) || node.port < 1 || node.port > 65535) return false
  if (!node.wireGuardPrivateKey?.trim() || !node.wireGuardPublicKey?.trim()) return false
  if (!node.wireGuardIPv4 && !node.wireGuardIPv6) return false
  if (!node.wireGuardAllowedIPs?.trim()) return false
  return wireGuardReservedBytes(node) !== undefined
}

function wireGuardAddresses(node: ProxyNode): string[] {
  const addresses: string[] = []
  if (node.wireGuardIPv4) {
    addresses.push(node.wireGuardIPv4.includes('/') ? node.wireGuardIPv4 : `${node.wireGuardIPv4}/32`)
  }
  if (node.wireGuardIPv6) {
    addresses.push(node.wireGuardIPv6.includes('/') ? node.wireGuardIPv6 : `${node.wireGuardIPv6}/128`)
  }
  return addresses
}

/** sing-box 1.11+ 把 WireGuard 写成顶层 endpoints，而不是 outbounds。 */
function singboxWireGuardEndpoint(node: ProxyNode, name: string): Outbound | undefined {
  if (!singboxWireGuardSupported(node)) return undefined
  const peer: Outbound = {
    address: node.server,
    port: node.port,
    public_key: node.wireGuardPublicKey,
    allowed_ips: csvValues(node.wireGuardAllowedIPs),
  }
  if (node.wireGuardPreSharedKey) peer.pre_shared_key = node.wireGuardPreSharedKey
  const reserved = wireGuardReservedBytes(node)
  if (reserved?.length) peer.reserved = reserved
  if (node.wireGuardPersistentKeepalive !== undefined) {
    peer.persistent_keepalive_interval = node.wireGuardPersistentKeepalive
  }
  const endpoint: Outbound = {
    type: 'wireguard',
    tag: name,
    address: wireGuardAddresses(node),
    private_key: node.wireGuardPrivateKey,
    peers: [peer],
  }
  if (node.wireGuardMTU !== undefined) endpoint.mtu = node.wireGuardMTU
  return endpoint
}

/** Hiddify 内嵌的 1.13 使用旧式 WireGuard outbound（local_address / peer_public_key）。 */
function singboxWireGuardOutbound(node: ProxyNode, name: string): Outbound | undefined {
  if (!singboxWireGuardSupported(node)) return undefined
  const outbound: Outbound = {
    type: 'wireguard',
    tag: name,
    // 旧式 outbound 不会从顶层 endpoint 继承服务端地址；漏掉这两个字段
    // 时 Hiddify 能导入配置，但这个 WireGuard 节点永远无法拨号。
    server: node.server,
    server_port: node.port,
    local_address: wireGuardAddresses(node),
    private_key: node.wireGuardPrivateKey,
    peer_public_key: node.wireGuardPublicKey,
  }
  if (node.wireGuardPreSharedKey) outbound.pre_shared_key = node.wireGuardPreSharedKey
  const reserved = wireGuardReservedBytes(node)
  if (reserved?.length) outbound.reserved = reserved
  if (node.wireGuardMTU !== undefined) outbound.mtu = node.wireGuardMTU
  return outbound
}

/**
 * ShadowTLS 在 sing-box 里是“SS outbound + ShadowTLS detour”的两个出站。
 * 辅助出站不进策略组；Hiddify 用 §hide§ 前缀避免它出现在可选节点里。
 */
function singboxShadowTLSOutbounds(
  node: ProxyNode,
  name: string,
  target: ClientTarget | undefined,
  occupied: Set<string>,
): Outbound[] | undefined {
  const options = node.shadowTLS
  if (!options || node.plugin !== 'shadow-tls') return undefined
  if (!nodeSupportedForTarget(node, target)) return undefined
  const prefix = target === 'hiddify' ? '§hide§' : ''
  let tag = `${prefix}tower-shadowtls-${occupied.size}`
  while (occupied.has(tag)) tag += '-'
  occupied.add(tag)
  const tls: Record<string, unknown> = {
    enabled: true,
    server_name: options.host,
    insecure: options.skipCertificateVerification === true,
  }
  if (node.fingerprint) tls.utls = { enabled: true, fingerprint: node.fingerprint }
  return [
    {
      type: 'shadowtls',
      tag,
      server: node.server,
      server_port: node.port,
      version: options.version,
      password: options.password,
      tls,
    },
    {
      type: 'shadowsocks',
      tag: name,
      server: node.server,
      server_port: node.port,
      method: node.cipher ?? 'aes-256-gcm',
      password: node.password ?? '',
      detour: tag,
      network: 'tcp',
    },
  ]
}

function singboxOutbound(node: ProxyNode, name: string, target?: ClientTarget): Outbound | undefined {
  const tls = (enabled: boolean) => {
    if (!enabled) return undefined
    const t: Record<string, unknown> = { enabled: true }
    if (node.sni) t.server_name = node.sni
    if (node.skipCertificateVerification) t.insecure = true
    const alpn = (node.alpn ?? '').split(',').map((s) => s.trim()).filter(Boolean)
    if (alpn.length) t.alpn = alpn
    if (node.realityPublicKey) {
      t.reality = { enabled: true, public_key: node.realityPublicKey, short_id: node.realityShortID ?? '' }
      t.utls = { enabled: true, fingerprint: node.fingerprint ?? 'chrome' }
    } else if (node.fingerprint) {
      t.utls = { enabled: true, fingerprint: node.fingerprint }
    }
    return t
  }
  const transport = () => {
    switch (node.transport) {
      case 'ws':
        return {
          type: 'ws',
          path: node.path || '/',
          ...(node.hostHeader ? { headers: { Host: node.hostHeader } } : {}),
        }
      case 'grpc':
        return { type: 'grpc', service_name: node.path?.replace(/^\//, '') ?? '' }
      case 'http':
      case 'h2':
        return { type: 'http', path: node.path || '/', host: node.hostHeader ? [node.hostHeader] : [] }
      case 'httpupgrade':
        return {
          type: 'httpupgrade',
          path: node.path || '/',
          ...(node.hostHeader ? { headers: { Host: node.hostHeader } } : {}),
        }
      case 'quic':
        return { type: 'quic' }
      default:
        return undefined
    }
  }
  const base = { type: '', tag: name, server: node.server, server_port: node.port }
  if (!nodeSupportedForTarget(node, target)) return undefined
  switch (node.kind) {
    case 'ss': {
      if (node.shadowTLS || node.plugin === 'shadow-tls') return undefined
      if (node.plugin === 'v2ray-plugin' && v2rayPluginSupported(node, target)) {
        const options = ['mode=websocket']
        if (node.pluginMux !== undefined) options.push(`mux=${node.pluginMux ? 1 : 0}`)
        if (node.tls) options.push('tls')
        if (node.hostHeader) options.push(`host=${node.hostHeader}`)
        if (node.path) options.push(`path=${node.path}`)
        return {
          ...base,
          type: 'shadowsocks',
          method: node.cipher ?? 'aes-256-gcm',
          password: node.password ?? '',
          plugin: 'v2ray-plugin',
          plugin_opts: options.join(';'),
        }
      }
      return {
        ...base,
        type: 'shadowsocks',
        method: node.cipher ?? 'aes-256-gcm',
        password: node.password ?? '',
        ...(node.obfs
          ? { plugin: 'obfs-local', plugin_opts: `obfs=${node.obfs}${node.obfsParam ? `;obfs-host=${node.obfsParam}` : ''}` }
          : {}),
      }
    }
    case 'vmess':
      return {
        ...base,
        type: 'vmess',
        uuid: node.uuid ?? '',
        security: node.cipher ?? 'auto',
        alter_id: node.alterID ?? 0,
        tls: tls(node.tls),
        transport: transport(),
      }
    case 'vless':
      return {
        ...base,
        type: 'vless',
        uuid: node.uuid ?? '',
        ...(node.flow ? { flow: node.flow } : {}),
        tls: tls(node.tls),
        transport: transport(),
      }
    case 'trojan':
      return { ...base, type: 'trojan', password: node.password ?? '', tls: tls(true), transport: transport() }
    case 'hysteria2':
      return {
        ...base,
        type: 'hysteria2',
        password: node.password ?? '',
        ...(node.upMbps !== undefined ? { up_mbps: node.upMbps } : {}),
        ...(node.downMbps !== undefined ? { down_mbps: node.downMbps } : {}),
        ...(node.portHopping
          ? { server_ports: node.portHopping.split(',').map((item) => item.trim().replace(/-/g, ':')).filter(Boolean) }
          : {}),
        tls: tls(true),
        ...(node.obfs ? { obfs: { type: node.obfs, password: node.obfsParam ?? '' } } : {}),
      }
    case 'hysteria':
      return {
        ...base,
        type: 'hysteria',
        auth_str: node.password ?? '',
        up_mbps: node.upMbps ?? 50,
        down_mbps: node.downMbps ?? 100,
        ...(node.obfs && node.obfs.toLowerCase() !== 'none' ? { obfs: node.obfs } : {}),
        tls: tls(true),
      }
    case 'snell':
      // Hiddify 不提供 Snell；官方 sing-box 用 version 4，不支持 QUIC。
      if (target !== 'sing-box' || !node.password) return undefined
      return {
        ...base,
        type: 'snell',
        psk: node.password,
        version: 4,
        ...(node.obfs?.toLowerCase() === 'http'
          ? { obfs_mode: 'http', ...(node.obfsParam ? { obfs_host: node.obfsParam } : {}) }
          : {}),
      }
    case 'tuic':
      return {
        ...base,
        type: 'tuic',
        uuid: node.uuid ?? '',
        password: node.password ?? '',
        congestion_control: node.congestionControl ?? 'cubic',
        ...(node.udpRelayMode ? { udp_relay_mode: node.udpRelayMode } : {}),
        tls: tls(true),
      }
    case 'anytls':
      return {
        ...base,
        type: 'anytls',
        password: node.password ?? '',
        ...(node.idleSessionCheckInterval !== undefined
          ? { idle_session_check_interval: `${node.idleSessionCheckInterval}s` }
          : {}),
        ...(node.idleSessionTimeout !== undefined
          ? { idle_session_timeout: `${node.idleSessionTimeout}s` }
          : {}),
        ...(node.minIdleSession !== undefined ? { min_idle_session: node.minIdleSession } : {}),
        tls: tls(true),
      }
    case 'ssh': {
      const options = node.ssh
      if (!node.username || (!node.password && !options?.privateKey)) return undefined
      return {
        ...base,
        type: 'ssh',
        user: node.username,
        ...(node.password ? { password: node.password } : {}),
        ...(options?.privateKey ? { private_key: options.privateKey } : {}),
        ...(options?.privateKeyPassphrase ? { private_key_passphrase: options.privateKeyPassphrase } : {}),
        ...(options?.hostKeys?.length ? { host_key: options.hostKeys } : {}),
        ...(options?.hostKeyAlgorithms?.length ? { host_key_algorithms: options.hostKeyAlgorithms } : {}),
      }
    }
    case 'socks5':
      return {
        ...base,
        type: 'socks',
        version: 5,
        ...(node.username ? { username: node.username } : {}),
        ...(node.password ? { password: node.password } : {}),
      }
    case 'http':
      return {
        ...base,
        type: 'http',
        ...(node.username ? { username: node.username } : {}),
        ...(node.password ? { password: node.password } : {}),
        tls: tls(node.tls),
      }
    default:
      // ssr / hysteria1 / snell / key-MASQUE…: 没有对应的 sing-box 出站。
      return undefined
  }
}

export function generateSingBox(
  nodes: ProxyNode[],
  scheme: RuleScheme,
  options: OutputOptions = {},
): { text: string; skipped: number } {
  const nodesOnly = options.contentMode === 'nodes'
  const usable = nodes.filter((n) => !n.isSubscriptionMetadata)
  const names = uniqueDisplayNames(usable, (s) => s.trim() || '节点', options.nameForNode)
  const displayName = (n: ProxyNode) => names.get(n.id)!

  const outbounds: Outbound[] = []
  const endpoints: Outbound[] = []
  const occupiedTags = new Set(usable.map((node) => displayName(node)))
  occupiedTags.add('direct')
  occupiedTags.add('REJECT')
  let skipped = 0
  const emitted = new Set<string>()
  for (const node of usable) {
    const name = displayName(node)
    // sing-box MT（1.11+）把 CONNECT-IP 与 WireGuard 写在顶层 endpoints；Hiddify 不写。
    const endpoint = options.target === 'sing-box'
      ? (masqueBasicEndpoint(node, name) ?? singboxWireGuardEndpoint(node, name))
      : undefined
    if (endpoint) {
      endpoints.push(endpoint)
      emitted.add(node.id)
      continue
    }
    const shadowTLS = singboxShadowTLSOutbounds(
      node,
      name,
      options.target,
      occupiedTags,
    )
    if (shadowTLS) {
      outbounds.push(...shadowTLS)
      emitted.add(node.id)
      continue
    }
    // Hiddify 内嵌 1.13 仍使用旧式 WireGuard outbound。
    const outbound = (options.target === 'hiddify' ? singboxWireGuardOutbound(node, name) : undefined)
      ?? singboxOutbound(node, name, options.target)
    if (outbound) {
      outbounds.push(outbound)
      emitted.add(node.id)
    } else {
      skipped += 1
    }
  }

  if (nodesOnly) {
    const config: Record<string, unknown> = {
      outbounds: [...outbounds, { type: 'direct', tag: 'direct' }],
    }
    if (endpoints.length) config.endpoints = endpoints
    const text = JSON.stringify(config, undefined, 2)
    return { text: text + '\n', skipped }
  }

  const emittedNodes = usable.filter((n) => emitted.has(n.id))
  const resolved = resolveGroups(scheme, emittedNodes, displayName)
  const network = effectiveNetworkSettings(scheme.networkSettings)
  const protection = network.dnsProtectionMode
  const testURL = latencyTestURL(scheme.networkSettings)
  const filteredRules = filterRulesForTarget(scheme.rules, options.target)

  const groupTags: Outbound[] = []
  for (const { group, members } of resolved) {
    // sing-box 1.11 起 `block` 出站已移除，组里不能再引用 REJECT。
    const list = members.length ? members.filter((m) => m !== 'REJECT') : []
    if (!list.length) list.push('DIRECT')
    const kind = effectiveGroupType(group.type, options.target, group.parameters)
    if (kind === 'select') {
      groupTags.push({ type: 'selector', tag: group.name, outbounds: list })
    } else {
      const testable = list.filter((m) => m !== 'DIRECT' && !resolved.some((r) => r.group.name === m))
      groupTags.push({
        type: 'urltest',
        tag: group.name,
        outbounds: testable.length ? testable : ['DIRECT'],
        url: group.url ?? testURL,
        interval: `${group.interval ?? 300}s`,
        ...(group.tolerance ? { tolerance: group.tolerance } : {}),
      })
    }
  }

  const definitions = new Map<string, Outbound>(
    groupTags.map((group) => [group.tag as string, group]),
  )
  const nodeTags = new Set(emittedNodes.map(displayName))
  // Official sing-box MT exposes the Clash API's mode switch. Add a global
  // selector and the matching route/DNS rules; Hiddify keeps its 1.13 dialect.
  let globalProxyTag: string | undefined
  let globalAutoTag: string | undefined
  if (options.target === 'sing-box' && nodeTags.size > 0) {
    const used = new Set<string>([
      ...nodeTags,
      ...groupTags.map((group) => group.tag as string),
      'direct',
    ])
    globalAutoTag = uniqueTag('全局自动选择', used)
    used.add(globalAutoTag)
    const automatic: Outbound = {
      type: 'urltest',
      tag: globalAutoTag,
      outbounds: [...nodeTags],
      url: testURL,
      interval: '300s',
      tolerance: 50,
    }
    groupTags.push(automatic)
    definitions.set(globalAutoTag, automatic)
    globalProxyTag = uniqueTag('全局代理', used)
    used.add(globalProxyTag)
    const selector: Outbound = {
      type: 'selector',
      tag: globalProxyTag,
      outbounds: [globalAutoTag, ...nodeTags],
      default: globalAutoTag,
      interrupt_exist_connections: true,
    }
    // Keep the mode selector at the top so the client shows it first.
    groupTags.unshift(selector)
    definitions.set(globalProxyTag, selector)
  }
  let dnsProxyGroup = protection === 'follow-scheme' || nodeTags.size === 0
    ? undefined
    : pureNodeGroupTag(groupTags, nodeTags)
  if (protection !== 'follow-scheme' && nodeTags.size > 0 && !dnsProxyGroup) {
    // 没有纯节点组时补一个隐藏的自动选择组，避免 DNS 落到含 DIRECT 的策略组。
    const used = new Set<string>([
      ...nodeTags,
      ...groupTags.map((group) => group.tag as string),
    ])
    const tag = uniqueTag('DNS 自动选择', used)
    dnsProxyGroup = tag
    const group: Outbound = {
      type: 'urltest',
      tag,
      outbounds: [...nodeTags],
      url: testURL,
      interval: '300s',
      tolerance: 50,
    }
    groupTags.push(group)
    definitions.set(tag, group)
  }
  const dnsPlan = singBoxDNS(network, dnsProxyGroup)
  let globalDNSTag: string | undefined
  if (options.target === 'sing-box' && globalProxyTag) {
    const remote = dnsPlan.servers.find((server) => server.tag === dnsPlan.remoteTag)
    if (remote) {
      const used = new Set(dnsPlan.servers.map((server) => String(server.tag ?? '')))
      globalDNSTag = uniqueTag('remote-global', used)
      dnsPlan.servers.push({
        ...remote,
        tag: globalDNSTag,
        detour: globalProxyTag,
      })
    }
  }

  // 远程规则集：只引用 sing-box 自己的 source JSON / SRS。
  const remoteRuleSetDefs: Record<string, unknown>[] = []
  const dnsRuleSetDefs: Record<string, unknown>[] = []
  const dnsRuleSetTags = new Map<string, string>()
  const ruleSetTags = new Map<string, string>()
  for (const rule of filteredRules) {
    if (rule.type !== 'RULE-SET' || !rule.value) continue
    if (!supportsRuleSetReference(rule, 'json', options.target)) continue
    const format = ruleSetFormatOfRule(rule)
    if (!format) continue
    let tag = ruleSetTags.get(rule.value)
    if (!tag) {
      tag = `tower-rule-set-${remoteRuleSetDefs.length + 1}`
      remoteRuleSetDefs.push({
        type: 'remote',
        tag,
        format: format === 'singbox-binary' ? 'binary' : 'source',
        url: rule.value,
        update_interval: '1d',
      })
      ruleSetTags.set(rule.value, tag)
    }
    // DNS 规则不能引用含 IP 条件的 SRS；用同一列表的 domain-only 版本。
    if (rule.ruleSetDNSURL
      && options.target === 'sing-box'
      && dnsProxyGroup
      && protection !== 'follow-scheme'
      && !dnsRuleSetTags.has(rule.value)) {
      const dnsTag = `tower-rule-set-dns-${dnsRuleSetDefs.length + 1}`
      dnsRuleSetDefs.push({
        type: 'remote',
        tag: dnsTag,
        format: 'binary',
        url: rule.ruleSetDNSURL,
        update_interval: '1d',
      })
      dnsRuleSetTags.set(rule.value, dnsTag)
    }
  }

  // 路由规则必须保持源方案里的先后顺序：sing-box 是第一条命中即生效。
  // 只合并“连续且同一策略”的规则（同一规则内 domain/ip 条件本来就是 OR），
  // 不能按策略组全局分桶，否则 A/B/A 这类交错规则会被改成 A/A/B。
  const rules: Record<string, unknown>[] = []
  const finalRule = filteredRules.find((r) => r.type === 'FINAL')
  const rejectAll = finalRule?.group === 'REJECT'
  const finalGroup = rejectAll
    ? 'DIRECT'
    : finalRule?.group ?? resolved[0]?.group.name ?? 'DIRECT'
  let pending: { key: string; rule: Record<string, unknown> } | undefined
  const flushPending = () => {
    if (!pending) return
    rules.push(pending.rule)
    pending = undefined
  }
  for (const rule of filteredRules) {
    if (rule.type === 'FINAL') continue
    if (rule.type === 'RULE-SET') {
      if (!rule.value) continue
      const tag = ruleSetTags.get(rule.value)
      if (!tag) continue
      flushPending()
      rules.push(rule.group.toUpperCase() === 'REJECT'
        ? { rule_set: [tag], action: 'reject' }
        : { rule_set: [tag], outbound: rule.group })
      continue
    }
    if (!rule.value) continue
    // sing-box 1.12 移除了 route 规则里的 geoip 字段（要用 rule_set）。
    // 离线生成的配置没有 GeoIP 库，跳过而不是让整份配置被内核拒绝。
    if (rule.type === 'GEOIP') continue
    const field = rule.type === 'DOMAIN' ? 'domain'
      : rule.type === 'DOMAIN-SUFFIX' ? 'domain_suffix'
        : rule.type === 'DOMAIN-KEYWORD' ? 'domain_keyword'
          : rule.type === 'DOMAIN-REGEX' ? 'domain_regex'
            : rule.type === 'IP-CIDR' || rule.type === 'IP-CIDR6' ? 'ip_cidr'
              : undefined
    if (!field) continue
    const reject = rule.group.toUpperCase() === 'REJECT'
    const key = reject ? 'reject' : `route:${rule.group}`
    if (!pending || pending.key !== key) {
      flushPending()
      pending = {
        key,
        // 拦截规则用动作表达，DIRECT 走内置 direct 出站。
        rule: reject ? { action: 'reject' } : { outbound: rule.group },
      }
    }
    const list = pending.rule[field]
    if (Array.isArray(list)) list.push(rule.value)
    else pending.rule[field] = [rule.value]
  }
  flushPending()
  if (rejectAll) rules.push({ action: 'reject' })

  const directFinal = defaultsToDirect(finalGroup, definitions)
  if (protection !== 'strict' && directFinal) {
    dnsPlan.final = dnsPlan.domesticTag
  }
  // 官方 sing-box 1.14 才有 evaluate + match_response；Hiddify 的 1.13 不加 ECS 提示。
  const ecs = options.target === 'sing-box'
    && protection !== 'follow-scheme'
    && !!dnsProxyGroup
    && dnsPlan.final === dnsPlan.remoteTag
    ? chinaECSServer(network, dnsProxyGroup, dnsPlan.servers, dnsPlan.localTag)
    : undefined
  if (ecs) dnsPlan.servers.push(ecs.server)
  const dnsRules: Record<string, unknown>[] = []
  if (options.target === 'sing-box') {
    dnsRules.push({ clash_mode: '直接连接', action: 'route', server: dnsPlan.localTag })
    dnsRules.push(globalDNSTag
      ? { clash_mode: '全局代理', action: 'route', server: globalDNSTag }
      : { clash_mode: '全局代理', action: 'reject' })
  }
  if (dnsProxyGroup && protection !== 'follow-scheme') {
    dnsRules.push(...projectedDNSRules(
      filteredRules,
      definitions,
      protection,
      dnsPlan.domesticTag,
      dnsPlan.remoteTag,
      ecs?.tag,
      ruleSetTags,
      dnsRuleSetTags,
    ))
  }
  if (ecs) {
    dnsRules.push({
      query_type: ['A', 'AAAA'],
      action: 'evaluate',
      server: ecs.tag,
      client_subnet: CHINA_CLIENT_SUBNET,
    })
    dnsRules.push({
      match_response: true,
      rule_set: [CHINA_RULE_SET_TAG],
      action: 'respond',
    })
  }
  const localRuleSetDefs = ecs
    ? [{
        type: 'inline',
        tag: CHINA_RULE_SET_TAG,
        rules: [{ ip_cidr: CHINA_IP_CIDRS }],
      }]
    : []

  // Hiddify 的 1.13 没有 http_clients；给远程规则集下载指定一个代理出站，
  // 否则在中国网络里直连 raw.githubusercontent.com 很容易失败。
  if (options.target === 'hiddify' && remoteRuleSetDefs.length) {
    let detour: string | undefined
    if (!['DIRECT', 'REJECT'].includes(finalGroup.toUpperCase())
      && resolved.some(({ group }) => group.name === finalGroup)) {
      detour = finalGroup
    } else {
      detour = resolved.find(({ members }) => members.length)?.group.name
        ?? (emittedNodes[0] ? displayName(emittedNodes[0]) : undefined)
    }
    if (detour) for (const definition of remoteRuleSetDefs) definition.download_detour = detour
  }

  const modeRulesStart = options.target === 'sing-box'
    ? [
        globalProxyTag
          ? { clash_mode: '全局代理', action: 'route', outbound: globalProxyTag }
          : { clash_mode: '全局代理', action: 'reject' },
        { clash_mode: '直接连接', action: 'route', outbound: 'direct' },
      ]
    : []
  const modeRulesEnd = options.target === 'sing-box'
    ? [{ clash_mode: '规则判定', action: 'route', outbound: finalGroup }]
    : []
  const route: Record<string, unknown> = {
    rules: [...modeRulesStart, ...rules, ...modeRulesEnd],
    final: finalGroup,
    // 1.12 起引导解析出站服务器域名必须显式指定解析器，否则 1.14 直接拒绝启动。
    default_domain_resolver: dnsPlan.localTag,
    auto_detect_interface: true,
  }
  if (remoteRuleSetDefs.length || dnsRuleSetDefs.length || localRuleSetDefs.length) {
    route.rule_set = [...remoteRuleSetDefs, ...dnsRuleSetDefs, ...localRuleSetDefs]
  }
  const config: Record<string, unknown> = {
    log: { level: 'info' },
    dns: {
      servers: dnsPlan.servers,
      final: dnsPlan.final,
      ...(dnsRules.length ? { rules: dnsRules } : {}),
      reverse_mapping: true,
      ...(network.ipv6Enabled === false ? { strategy: 'ipv4_only' } : {}),
    },
    inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: 7890 }],
    outbounds: [
      ...groupTags,
      ...outbounds,
      { type: 'direct', tag: 'direct' },
    ],
    ...(endpoints.length ? { endpoints } : {}),
    route,
    ...(options.target === 'sing-box'
      ? { experimental: { clash_api: { default_mode: '规则判定' } } }
      : {}),
  }
  // sing-box 1.14 不再使用隐式下载器；独立 sing-box 目标显式提供 Go HTTP 客户端。
  // Hiddify 内嵌的 1.13 不认识这个顶层字段，因此不写。
  if (options.target === 'sing-box' && remoteRuleSetDefs.length) {
    config.http_clients = [{
      tag: 'tower-rule-set',
      engine: 'go',
      domain_resolver: dnsPlan.localTag,
    }]
    route.default_http_client = 'tower-rule-set'
  }
  // DIRECT 选项在 outbounds 里引用内置 `direct` 标签。
  const text = JSON.stringify(config, (_key, value) => (value === 'DIRECT' ? 'direct' : value), 2)
  return { text: text + '\n', skipped }
}
