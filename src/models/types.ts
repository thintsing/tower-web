// Domain models ported from Tower iOS (Tower/Models/DomainModels.swift).
// Field semantics and comments are kept faithful to the original.

export type ProxyKind =
  | 'ss'
  | 'ssr'
  | 'vmess'
  | 'vless'
  | 'trojan'
  | 'hysteria'
  | 'hysteria2'
  | 'tuic'
  | 'masque'
  | 'wireguard'
  | 'anytls'
  | 'snell'
  | 'socks5'
  | 'http'
  | 'ssh'
  | 'trusttunnel'
  | 'unknown'

export const PROXY_KIND_TITLES: Record<ProxyKind, string> = {
  ss: 'Shadowsocks',
  ssr: 'ShadowsocksR',
  vmess: 'VMess',
  vless: 'VLESS',
  trojan: 'Trojan',
  hysteria: 'Hysteria',
  hysteria2: 'Hysteria 2',
  tuic: 'TUIC',
  masque: 'MASQUE',
  wireguard: 'WireGuard',
  anytls: 'AnyTLS',
  snell: 'Snell',
  socks5: 'SOCKS5',
  http: 'HTTP',
  ssh: 'SSH',
  trusttunnel: 'TrustTunnel',
  unknown: '未知协议',
}

export interface ShadowTLSOptions {
  version: number
  host: string
  password: string
  skipCertificateVerification?: boolean
}

/** SSH 登录材料；Web 目前只导出密码登录，密钥登录保留在导入模型里。 */
export interface SSHOptions {
  privateKey?: string
  privateKeyPassphrase?: string
  hostKeys?: string[]
  hostKeyAlgorithms?: string[]
}

/** TrustTunnel 默认 HTTP/2 + TLS；`quic` 选择 HTTP/3。 */
export interface TrustTunnelOptions {
  quic: boolean
}

/** MASQUE 的两套不兼容方言：mihomo 的密钥 CONNECT-IP 与 sing-box 的 basic CONNECT-IP。 */
export interface MASQUEOptions {
  mode: 'keyConnectIP' | 'basicConnectIP'
  /** keyConnectIP（mihomo / Shadowrocket） */
  privateKey?: string
  publicKey?: string
  ipv4?: string
  ipv6?: string
  network?: string
  /** basicConnectIP（sing-box masque-client） */
  httpVersion?: number
  disableVersionFallback?: boolean
  headers?: Record<string, string>
  certificate?: string[]
  mtu?: number
  dns?: string[]
  remoteDNSResolve?: boolean
}

export interface ProxyNode {
  id: string
  sourceID?: string
  kind: ProxyKind
  name: string
  server: string
  port: number
  cipher?: string
  password?: string
  uuid?: string
  username?: string
  transport?: string // ws / grpc / h2 / xhttp / tcp ...
  transportMode?: string
  /** SIP003 plugin for Shadowsocks (obfs / v2ray-plugin). */
  plugin?: string
  pluginMux?: boolean
  shadowTLS?: ShadowTLSOptions
  ssh?: SSHOptions
  trustTunnel?: TrustTunnelOptions
  masque?: MASQUEOptions
  tls: boolean
  sni?: string
  hostHeader?: string
  path?: string
  alpn?: string
  realityPublicKey?: string
  realityShortID?: string
  certificateFingerprint?: string
  /** uTLS ClientHello fingerprint name (chrome, safari, ...). */
  fingerprint?: string
  flow?: string
  vlessEncryption?: string
  skipCertificateVerification: boolean
  alterID?: number
  /** SSR protocol / obfs family. */
  protocolName?: string
  protocolParam?: string
  obfs?: string
  obfsParam?: string
  idleSessionCheckInterval?: number
  idleSessionTimeout?: number
  minIdleSession?: number
  /** Snell protocol version. */
  version?: number
  /** TUIC QUIC tuning. */
  congestionControl?: string
  udpRelayMode?: string
  udpRelayEnabled?: boolean
  /** Alternate QUIC destination ports ("ports"/"mport"/"port-hopping"). */
  portHopping?: string
  /** Hysteria 1 bandwidth budget in Mbps. */
  upMbps?: number
  downMbps?: number
  wireGuardPrivateKey?: string
  wireGuardPublicKey?: string
  wireGuardPreSharedKey?: string
  wireGuardIPv4?: string
  wireGuardIPv6?: string
  wireGuardAllowedIPs?: string
  wireGuardReserved?: string
  wireGuardMTU?: number
  wireGuardPersistentKeepalive?: number
  wireGuardDNS?: string
  rawURI: string
  /** Quota / expiry / announcement pseudo-nodes from the provider. */
  isSubscriptionMetadata?: boolean
  /** User-selected region override (ISO code). */
  countryOverride?: string
  /** Offline IP lookup result, used only when the node name gives no region. */
  detectedCountry?: string
  /** 用户手动添加的自有节点；不随订阅刷新，删除订阅也不会移除。 */
  isManual?: boolean
  /** 自有节点是否进入导出；未设置按启用处理，兼容旧数据。 */
  isEnabled?: boolean
}

export interface SubscriptionUsage {
  upload?: number
  download?: number
  total?: number
  expire?: number // unix seconds
}

export interface SubscriptionSource {
  id: string
  name: string
  url: string
  updatedAt?: number
  usage?: SubscriptionUsage
  /** Airport announcements parsed from metadata pseudo nodes. */
  notices?: string[]
  /** 订阅是否启用；旧快照没有这个字段时按启用处理。 */
  isEnabled?: boolean
  /** 仅对这个订阅生效的请求身份与加密解析地址。 */
  userAgent?: string
  dnsOverHTTPSURL?: string
  /** Node ids the user unchecked; carried over across refreshes. */
  excludedNodeKeys: string[]
}

/** 订阅请求的进阶选项（只作用于该订阅的抓取请求）。 */
export interface SubscriptionRequestOptions {
  userAgent?: string
  dnsOverHTTPSURL?: string
}

/** A node the user added by hand (no subscription). */
export interface LocalNode {
  node: ProxyNode
}

// ---------- Rules ----------

/** A single routing rule in a scheme, in matching order. */
export interface RoutingRule {
  /** DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / IP-CIDR6 / GEOIP / FINAL / RULE-SET / AND / OR / NOT ... */
  type: string
  value?: string
  noResolve?: boolean
  /** 原规则里的附加选项（extended-matching、pre-matching、dns-failed …）。 */
  options?: string[]
  /** 逻辑规则等无法结构化表示的原始行；生成时追加策略名后原样写回。 */
  raw?: string
  /** Name of the policy group this rule belongs to. */
  group: string
  /** 来源规则集名称，仅用于界面区分，不写入客户端配置。 */
  sourceName?: string
  /** 这条 RULE-SET 原始资源使用的格式；导出其他客户端时据此决定能否直接引用。 */
  ruleSetFormat?: RuleSetFormat
  /** Clash MRS provider 的 behavior（domain / ipcidr）。 */
  ruleSetBehavior?: string
  /** 本地规则集写成客户端内联规则集时的元数据；只存在于导出准备结果。 */
  inlineSet?: InlineRuleSetMeta
}

export type InlineRuleSetBehavior = 'domain' | 'ipcidr' | 'classical'

export interface InlineRuleSetMeta {
  id: string
  name: string
  behavior: InlineRuleSetBehavior
  noResolve: boolean
}

/** 远程规则集资源的方言。 */
export type RuleSetFormat =
  | 'classical'
  | 'yaml'
  | 'mrs'
  | 'quanx'
  | 'egern'
  | 'singbox'
  | 'singbox-binary'

export type PolicyGroupType =
  | 'select'
  | 'url-test'
  | 'smart'
  | 'fallback'
  | 'load-balance'
  | 'conditional'
  | 'relay'
  | 'unsupported'

export interface PolicyGroup {
  name: string
  type: PolicyGroupType
  /** References to other group names, 'DIRECT', 'REJECT'. */
  options: string[]
  /** Regex filtering nodes into this group (ACL4SSR `.*` style). */
  nodeFilter?: string
  url?: string
  interval?: number
  tolerance?: number
  /** 负载均衡算法（random / hash / round-robin / consistent-hashing …）。 */
  algorithm?: string
  /** 导入方案保留的客户端专属组参数（conditional rules、priorities 等）。 */
  parameters?: Record<string, string>
  /** 生成配置时由界面选择注入的首选成员（组名、DIRECT/REJECT 或节点名）。 */
  selected?: string
  /** 导出准备阶段写入的策略组图标 URL；只在支持图标的客户端出现。 */
  icon?: string
}

export type RuleSchemeDNSProtectionMode = 'follow-scheme' | 'standard' | 'strict'

/** 规则方案自带的 DNS 与网络设置；缺省时各生成器使用安全默认值。 */
export interface RuleSchemeNetworkSettings {
  /** 不填表示跟随客户端/平台默认。 */
  ipv6Enabled?: boolean
  /** 普通 DNS，只允许 IP 字面量；用于解析加密 DNS 和节点域名。 */
  dnsServers: string[]
  /** 国内加密 DNS，直连解析国内域名。 */
  encryptedDNSServers: string[]
  /** 远程加密 DNS，只经代理访问。 */
  remoteDNSServers: string[]
  /** 延迟测试地址；留空使用生成器默认值。 */
  proxyTestURLString?: string
  dnsProtectionMode: RuleSchemeDNSProtectionMode
}

export type RuleSchemeSource = 'url' | 'paste' | 'file' | 'copy'
export type RuleSchemeFormat = 'ini' | 'clash' | 'surge' | 'egern' | 'singbox'
export type RuleSetSource = 'library' | 'local' | 'url'

/** 已加入方案的规则集快照；修改本地规则集不会回头改动已加入的方案。 */
export interface SchemeRuleSet {
  id: string
  name: string
  group: string
  rules: RoutingRule[]
  sourceKind: RuleSetSource
  /** 规则库文件、本地规则集 ID 或远程 URL，用于去重和替换。 */
  sourceRef?: string
  /** 可远程下载时的资源方言；用于判断各客户端能否直接引用。 */
  format?: RuleSetFormat
  /** Clash MRS provider 的 behavior（domain / ipcidr）。 */
  ruleSetBehavior?: string
  /** 在线规则集最近一次抓取/解析时间。 */
  updatedAt?: number
}

/** 用户保存在本机的规则集，尚未指定策略组。 */
export interface LocalRuleSet {
  id: string
  name: string
  rules: Omit<RoutingRule, 'group'>[]
  updatedAt: number
  /** 在线规则集订阅地址；有值时加入方案会保留远程引用。 */
  sourceURL?: string
  /** 在线资源方言，刷新时随内容更新。 */
  format?: RuleSetFormat
  /** 最近一次自动/手动刷新的错误，成功后清空。 */
  lastError?: string
  /** 暂停自动刷新；手动刷新和加入方案仍可用。 */
  paused?: boolean
}

export interface RuleScheme {
  id: string
  name: string
  description: string
  groups: PolicyGroup[]
  /** Rules in matching order; each points at a group by name. */
  rules: RoutingRule[]
  /** 用户自己添加的规则，优先于方案自带规则。 */
  customRules?: RoutingRule[]
  /** 拖动策略组后调整的规则匹配顺序；缺省保持原规则顺序。 */
  matchingOrder?: string[]
  /** 从规则库 / 本地规则集加入的整组规则，排在自定义规则之后、方案规则之前。 */
  ruleSets?: SchemeRuleSet[]
  /** 自定义方案的导入来源，用于刷新；内置方案没有这个字段。 */
  sourceKind?: RuleSchemeSource
  sourceFormat?: RuleSchemeFormat
  sourceURL?: string
  /** Original imported text, used by the full-text scheme editor. */
  rawConfigurationText?: string
  /** DNS / IPv6 / 延迟测试等网络设置。 */
  networkSettings?: RuleSchemeNetworkSettings
  updatedAt?: number
}

// ---------- Clients ----------

export type ClientTarget =
  | 'surge'
  | 'surge-mac'
  | 'clash' // Stash
  | 'clash-apple'
  | 'clash-verge'
  | 'clashmac'
  | 'flclash'
  | 'mihomo-party'
  | 'clash-mi'
  | 'karing'
  | 'shadowrocket'
  | 'loon'
  | 'quanx'
  | 'hiddify'
  | 'egern'
  | 'v2box'
  | 'anywhere'
  | 'sing-box'

export interface ClientInfo {
  target: ClientTarget
  name: string
  subtitle: string
  /** 客户端图标文件名，放在 /client-icons/ 下 */
  icon: string
  /** 客户端品牌色（用于图标 tile 背景或 accent） */
  color: string
  /** 'full' config with rules, or node-only subscription. */
  contentMode: 'full' | 'nodes'
  format: 'yaml' | 'ini' | 'json' | 'base64'
  /** URL scheme for one-click import, if the client supports it.
   *  Returns undefined when that client cannot take the current content mode. */
  importScheme?: (url: string, name: string, mode?: ExportContentMode) => string | undefined
  /** Content modes that have a one-click handoff. Defaults to full config. */
  importModes?: ExportContentMode[]
}

const enc = encodeURIComponent

/** Whether a client can take the given content mode through a URL scheme. */
export function clientSupportsImport(client: ClientInfo, mode: ExportContentMode): boolean {
  return !!client.importScheme && (client.importModes ?? ['full']).includes(mode)
}

/** Karing silently skips a URL it already has, so make each import unique. */
function karingImportScheme(url: string, name: string): string {
  try {
    const parsed = new URL(url)
    parsed.searchParams.set('tower-import', String(Date.now()))
    const stamp = new Date().toISOString().slice(11, 19)
    return `karing://install-config?url=${enc(parsed.href)}&name=${enc(`${name} ${stamp}`)}`
  } catch {
    return `karing://install-config?url=${enc(url)}&name=${enc(name)}`
  }
}

/** QuanX imports a nodes-only list as a `server_remote` resource. */
function quanxNodeResource(url: string, name: string): string {
  const tag = name.replace(/,/g, ' ').trim() || 'tower'
  return JSON.stringify({ server_remote: [`${url}, tag=${tag}, as-policy=static`] })
}

/** 订阅载体：服务端 /api/sub/:token?format=… 按此分发。 */
export type SubFormat = 'yaml' | 'surge' | 'loon' | 'quanx' | 'json' | 'base64' | 'egern'

/** 导出内容模式：完整配置（节点+策略组+规则）或仅节点。 */
export type ExportContentMode = 'full' | 'nodes'

/** 测速方式：自动优先 ICMP、失败回退 TCP；或强制指定。 */
export type LatencyTestMode = 'automatic' | 'icmp' | 'tcp'
export type LatencyTestMethod = 'icmp' | 'tcp'

/** 全局节点名称筛选；关键词按行分隔，也可切换为正则。 */
export interface NodeNameFilterSettings {
  include: string
  exclude: string
  useRegex: boolean
  caseSensitive: boolean
}

/** 代理集合：把原始订阅地址写入支持它的客户端配置。 */
export interface RemoteSubscriptionEntry {
  id: string
  name: string
  url: string
  userAgent?: string
}

/**
 * 客户端 → 订阅载体。
 * 注意 Loon / QuanX 与 Surge 同属 ini 文件，但语法互不兼容，必须分开。
 */
export function subFormatFor(client: ClientInfo): SubFormat {
  switch (client.target) {
    case 'surge':
    case 'surge-mac':
      return 'surge'
    case 'loon':
      return 'loon'
    case 'quanx':
      return 'quanx'
    case 'sing-box':
    case 'hiddify':
      return 'json'
    case 'egern':
      return 'egern'
    case 'shadowrocket':
      // Shadowrocket accepts full Clash YAML, including policy groups and rules.
      return 'yaml'
    case 'v2box':
    case 'anywhere':
      return 'base64'
    default:
      return 'yaml'
  }
}

/** Tower Web 客户端导出目标，与 iOS Tower ClientTarget 对齐。
 *  图标从 iOS Assets.xcassets/Client*.imageset 搬到 public/client-icons/ */
export const CLIENTS: ClientInfo[] = [
  // —— Clash / mihomo 系 ——
  {
    target: 'clash-verge',
    name: 'Clash Verge',
    subtitle: 'Clash / mihomo YAML',
    icon: 'clash-verge.png', color: '#2F82F7',
    contentMode: 'full', format: 'yaml',
    importScheme: (url) => `clash-verge://install-config?url=${enc(url)}`,
  },
  {
    target: 'mihomo-party',
    name: 'Mihomo Party',
    subtitle: 'Clash / mihomo YAML',
    icon: 'mihomo-party.png', color: '#2F82F7',
    contentMode: 'full', format: 'yaml',
    importScheme: (url, name) => `mihomo://install-config?url=${enc(url)}&name=${enc(name)}`,
  },
  {
    target: 'flclash',
    name: 'FlClash',
    subtitle: 'Clash YAML',
    icon: 'flclash.png', color: '#2F82F7',
    contentMode: 'full', format: 'yaml',
    importScheme: (url) => `flclash://install-config?url=${enc(url)}`,
  },
  {
    target: 'clash-mi',
    name: 'Clash Mi',
    subtitle: 'Mihomo YAML',
    icon: 'clash-mi.jpg', color: '#224D7A',
    contentMode: 'full', format: 'yaml',
    importScheme: (url, name) => `clashmi://install-config?url=${enc(url)}&name=${enc(name)}`,
  },
  {
    target: 'clash-apple',
    name: 'Clash',
    subtitle: 'Clash YAML',
    icon: 'clash-apple.png', color: '#2F82F7',
    contentMode: 'full', format: 'yaml',
    importScheme: (url) => `clashmeta://install-config?url=${enc(url)}`,
  },
  {
    target: 'clashmac',
    name: 'ClashMac',
    subtitle: 'Clash YAML',
    icon: 'clashmac.png', color: '#2F82F7',
    contentMode: 'full', format: 'yaml',
  },
  {
    target: 'clash',
    name: 'Stash',
    subtitle: 'Clash YAML',
    icon: 'clash.jpg', color: '#1473E6',
    contentMode: 'full', format: 'yaml',
    importScheme: (url, name) => `stash://install-config?url=${enc(url)}&name=${enc(name)}`,
  },
  {
    target: 'karing',
    name: 'Karing',
    subtitle: 'Clash YAML',
    icon: 'karing.jpg', color: '#5367F7',
    contentMode: 'full', format: 'yaml',
    importScheme: karingImportScheme,
  },
  // —— Surge 系 ——
  {
    target: 'surge',
    name: 'Surge',
    subtitle: '完整配置',
    icon: 'surge.jpg', color: '#3157D5',
    contentMode: 'full', format: 'ini',
    importScheme: (url) => `surge:///install-config?url=${enc(url)}`,
  },
  {
    target: 'surge-mac',
    name: 'Surge Mac',
    subtitle: '完整配置',
    icon: 'surge-mac.png', color: '#3157D5',
    contentMode: 'full', format: 'ini',
    importScheme: (url) => `surgeconfig:///install-config?url=${enc(url)}`,
  },
  // —— sing-box 系 ——
  {
    target: 'sing-box',
    name: 'sing-box MT',
    subtitle: 'sing-box JSON',
    icon: 'sing-box.png', color: '#334854',
    contentMode: 'full', format: 'json',
    importScheme: (url, name) => `sing-box://import-remote-profile?url=${enc(url)}#${enc(name)}`,
  },
  {
    target: 'hiddify',
    name: 'Hiddify',
    subtitle: 'sing-box JSON',
    icon: 'hiddify.jpg', color: '#6047D9',
    contentMode: 'full', format: 'json',
    importScheme: (url) => `hiddify://import/${url}`,
    importModes: ['full', 'nodes'],
  },
  // —— Loon / QuanX ——
  {
    target: 'loon',
    name: 'Loon',
    subtitle: '完整配置',
    icon: 'loon.jpg', color: '#6B45D8',
    contentMode: 'full', format: 'ini',
    importScheme: (url, _name, mode) => mode === 'nodes'
      ? `loon://import?nodelist=${enc(url)}`
      : `loon://import?sub=${enc(url)}`,
    importModes: ['full', 'nodes'],
  },
  {
    target: 'quanx',
    name: 'Quantumult X',
    subtitle: '完整配置',
    icon: 'quanx.jpg', color: '#14A69A',
    contentMode: 'full', format: 'ini',
    importScheme: (url, name) => `quantumult-x:///add-resource?remote-resource=${enc(quanxNodeResource(url, name))}`,
    importModes: ['nodes'],
  },
  // —— 手机订阅 / 轻量 ——
  {
    target: 'shadowrocket',
    name: 'Shadowrocket',
    subtitle: 'Clash YAML / 完整配置',
    icon: 'shadowrocket.jpg', color: '#1B98F5',
    contentMode: 'full', format: 'yaml',
    importScheme: (url, _name, mode) => mode === 'nodes'
      ? `shadowrocket://add/${url}`
      : `shadowrocket://config/add/${url}`,
    importModes: ['full', 'nodes'],
  },
  {
    target: 'egern',
    name: 'Egern',
    subtitle: 'Egern YAML',
    icon: 'egern.jpg', color: '#F08A2B',
    contentMode: 'full', format: 'yaml',
    importScheme: (url, name) => `egern:/profiles/new?url=${enc(url)}&name=${enc(name)}`,
  },
  {
    target: 'v2box',
    name: 'V2Box',
    subtitle: '节点订阅',
    icon: 'v2box.jpg', color: '#246BFD',
    contentMode: 'nodes', format: 'base64',
    importScheme: (url, name) => `v2box://install-sub?url=${enc(url)}&name=${enc(name)}`,
    importModes: ['nodes'],
  },
  {
    target: 'anywhere',
    name: 'Anywhere',
    subtitle: '节点链接',
    icon: 'anywhere.png', color: '#286BF5',
    contentMode: 'nodes', format: 'base64',
    importScheme: (url) => `anywhere://add-proxy?link=${enc(url)}`,
    importModes: ['nodes'],
  },
]

// ---------- App snapshot (localStorage) ----------

export interface TailnetConnection {
  id: string
  /** Shown in the client as the policy name. */
  name: string
  /** Empty or absent means the official Tailscale control server. */
  controlURLString?: string
  /** Prefix of the machine name each client registers as. */
  deviceName?: string
  /** LAN ranges behind a subnet router, e.g. the home network. */
  subnets: string[]
  /** MagicDNS domain, e.g. tail1234.ts.net. */
  magicDNSSuffix?: string
  isEnabled: boolean
}

/** One enabled tailnet plus the auth key this browser holds for it. */
export interface TailnetExport {
  connection: TailnetConnection
  authKey?: string
}

export interface AppState {
  sources: SubscriptionSource[]
  nodes: ProxyNode[]
  /** Ids of enabled (checked) nodes are NOT stored; exclusions live on source. */
  selectedSchemeID: string
  /** group name -> chosen policy (group name / DIRECT / REJECT / node name). */
  policySelections: Record<string, string>
}
