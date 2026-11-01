// Clash / mihomo YAML subscription parsing. Uses the `yaml` package and maps
// each proxy to the shared ProxyNode model, mirroring Tower iOS
// parseClashYAML semantics (field names, plugin handling, rejections).
import { parse as parseYAML } from 'yaml'
import type { MASQUEOptions, ProxyKind, ProxyNode, ShadowTLSOptions } from '../models/types'
import { boolString, mbps, nextNodeID, normalizedHost, normalizedName, normalizedTransport } from './util'

const CLASH_KINDS: Record<string, ProxyKind> = {
  ss: 'ss',
  ssr: 'ssr',
  vmess: 'vmess',
  vless: 'vless',
  trojan: 'trojan',
  hysteria2: 'hysteria2',
  hy2: 'hysteria2',
  hysteria: 'hysteria',
  tuic: 'tuic',
  wireguard: 'wireguard',
  wg: 'wireguard',
  anytls: 'anytls',
  snell: 'snell',
  socks5: 'socks5',
  http: 'http',
  ssh: 'ssh',
  trusttunnel: 'trusttunnel',
  'trust-tunnel': 'trusttunnel',
  masque: 'masque',
}

const AMNEZIA_KEYS = new Set(['jc', 'jmin', 'jmax', 's1', 's2', 'h1', 'h2', 'h3', 'h4'])

export interface ClashParseResult {
  nodes: ProxyNode[]
  rejected: number
}

export function parseClashYAML(text: string, sourceID?: string): ClashParseResult {
  let doc: unknown
  try {
    doc = parseYAML(text, { strict: false, uniqueKeys: false, logLevel: 'silent' })
  } catch {
    return { nodes: [], rejected: 1 }
  }
  const proxies = (doc as Record<string, unknown> | null)?.['proxies']
  if (!Array.isArray(proxies)) return { nodes: [], rejected: 1 }

  const nodes: ProxyNode[] = []
  let rejected = 0
  for (const entry of proxies) {
    const node = clashProxy(entry, sourceID)
    if (node) nodes.push(node)
    else rejected += 1
  }
  return { nodes, rejected: proxies.length === 0 ? 1 : rejected }
}

function clashProxy(entry: unknown, sourceID?: string): ProxyNode | undefined {
  if (typeof entry !== 'object' || entry === null) return undefined
  const d = flattenRecord(entry as Record<string, unknown>)
  const type = str(d['type'])?.toLowerCase()
  if (!type) return undefined
  const kind = CLASH_KINDS[type]
  if (!kind) return undefined
  const rawServer = str(d['server'])
  const port = Number(str(d['port']))
  if (!rawServer || !Number.isInteger(port) || port < 1 || port > 65535) return undefined

  // AmneziaWG changes the handshake; as plain WireGuard the node would
  // import cleanly and never connect.
  if (kind === 'wireguard' && Object.keys(d).some((k) => AMNEZIA_KEYS.has(k))) return undefined
  if (kind === 'ssh') {
    const username = str(d['username'])
    const password = str(d['password'])
    const privateKey = str(d['private-key'])
    if (!username || (!password && !privateKey)) return undefined
  }
  if (kind === 'trusttunnel' && (!str(d['username']) || !str(d['password']))) return undefined
  const masque = kind === 'masque' ? masqueOptions(d) : undefined
  if (kind === 'masque' && !masque) return undefined

  // SIP003 plugins. Unsupported plugins are rejected, never flattened into
  // plain SS (constraint #12).
  let obfsMode = str(d['obfs'])
  let sip003Plugin: string | undefined
  let pluginTransport: string | undefined
  let pluginPath: string | undefined
  let pluginTLS = false
  let pluginMux: boolean | undefined
  let shadowTLS: (ShadowTLSOptions & { skipCertificateVerification?: boolean }) | undefined
  let obfsHost = str(d['obfs-param']) ?? str(d['obfs-password']) ?? str(d['obfs_password'])

  if (kind === 'snell') {
    const options = subRecord(d, 'obfs-opts')
    const mode = str(options?.['mode'])
    if (mode) {
      obfsMode = mode
      obfsHost = str(options?.['host'])
    }
  }

  if (kind === 'ss') {
    const plugin = str(d['plugin'])?.toLowerCase()
    if (plugin) {
      const options = subRecord(d, 'plugin-opts') ?? {}
      if (plugin === 'shadow-tls') {
        if (boolString(str(d['udp-over-tcp']))) return undefined
        const version = Number(str(options['version']))
        const host = str(options['host'])
        if (!Number.isInteger(version) || !host) return undefined
        shadowTLS = {
          version,
          host,
          password: str(options['password']) ?? '',
          skipCertificateVerification: boolString(str(options['skip-cert-verify'])),
        }
        sip003Plugin = 'shadow-tls'
      } else if (plugin === 'obfs' || plugin === 'obfs-local' || plugin === 'simple-obfs') {
        obfsMode = str(options['mode']) ?? 'http'
        obfsHost = str(options['host'])
      } else if (plugin === 'v2ray-plugin') {
        const mode = (str(options['mode']) ?? 'websocket').toLowerCase()
        if (mode !== 'websocket' && mode !== 'ws') return undefined
        sip003Plugin = 'v2ray-plugin'
        pluginTransport = 'ws'
        pluginPath = str(options['path'])
        pluginTLS = boolString(str(options['tls']))
        if (options['mux'] !== undefined) pluginMux = boolString(str(options['mux']))
        obfsHost = str(options['host'])
      } else {
        return undefined
      }
    }
  }

  const server = normalizedHost(rawServer)
  // Only treat `public-key` as REALITY when it came from `reality-opts`.
  const realityOpts = subRecord(d, 'reality-opts')
  const hasRealityOptions = !!realityOptions(d) || str(d['security'])?.toLowerCase() === 'reality'

  const transport = kind === 'masque' ? undefined : pluginTransport ?? normalizedTransport(str(d['network']))
  const node: ProxyNode = {
    id: nextNodeID(),
    sourceID,
    kind,
    name: normalizedName(str(d['name']), server),
    server,
    port,
    cipher: str(d['cipher']),
    // Hysteria 1 calls it `auth-str`; Snell calls it `psk`.
    password: str(d['password']) ?? str(d['auth-str']) ?? str(d['auth_str']) ?? str(d['auth']) ?? str(d['psk']),
    uuid: str(d['uuid']),
    username: str(d['username']),
    transport,
    transportMode: transport === 'xhttp' ? str(d['mode']) : undefined,
    plugin: sip003Plugin,
    pluginMux,
    shadowTLS,
    // TLS is part of Trojan / TrustTunnel / key-MASQUE themselves.
    tls: kind === 'trojan' || kind === 'trusttunnel' || kind === 'masque'
      || pluginTLS || boolString(str(d['tls'])),
    sni: str(d['servername']) ?? str(d['sni']),
    hostHeader:
      sip003Plugin === 'v2ray-plugin' ? obfsHost : str(d['authority']) ?? str(d['host']),
    path:
      pluginPath ??
      (transport === 'grpc'
        ? str(d['grpc-service-name']) ?? str(d['service-name']) ?? str(d['path'])
        : str(d['path'])),
    alpn: alpnValue(d['alpn']),
    realityPublicKey: hasRealityOptions
      ? str(realityOpts?.['public-key']) ?? str(realityOpts?.['pbk'])
      : undefined,
    realityShortID: hasRealityOptions
      ? scalarish(str(realityOpts?.['short-id']) ?? str(realityOpts?.['sid']))
      : undefined,
    certificateFingerprint:
      str(d['server-cert-fingerprint']) ?? str(d['tls-fingerprint']) ?? str(d['fingerprint']),
    fingerprint: str(d['client-fingerprint']) ?? str(d['fp']),
    flow: str(d['flow']),
    skipCertificateVerification: boolString(str(d['skip-cert-verify'])),
    alterID: intOrUndefined(str(d['alterid']) ?? str(d['alter-id'])),
    protocolName: str(d['protocol']),
    protocolParam: str(d['protocol-param']),
    obfs: obfsMode,
    obfsParam: sip003Plugin == null ? obfsHost : undefined,
    version: intOrUndefined(str(d['version'])),
    congestionControl: str(d['congestion-controller']) ?? str(d['congestion_control']),
    udpRelayMode: str(d['udp-relay-mode']),
    udpRelayEnabled: kind === 'ss' || kind === 'trusttunnel' || kind === 'masque'
      ? boolOrUndefined(d['udp'])
      : undefined,
    portHopping: str(d['ports']) ?? str(d['mport']) ?? str(d['server-ports']) ?? str(d['port-hopping']),
    upMbps: kind === 'hysteria' ? mbps(str(d['up']) ?? str(d['up-speed'])) : undefined,
    downMbps: kind === 'hysteria' ? mbps(str(d['down']) ?? str(d['down-speed'])) : undefined,
    wireGuardPrivateKey: kind === 'wireguard' ? str(d['private-key']) : undefined,
    wireGuardPublicKey: kind === 'wireguard' ? str(d['public-key']) : undefined,
    wireGuardPreSharedKey:
      kind === 'wireguard' ? str(d['pre-shared-key']) ?? str(d['preshared-key']) : undefined,
    wireGuardIPv4: kind === 'wireguard' ? str(d['ip']) : undefined,
    wireGuardIPv6: kind === 'wireguard' ? str(d['ipv6']) : undefined,
    wireGuardAllowedIPs:
      kind === 'wireguard'
        ? csv(d['allowed-ips'] ?? '0.0.0.0/0,::/0').join(',')
        : undefined,
    wireGuardReserved: kind === 'wireguard' ? csv(d['reserved']).join(',') || undefined : undefined,
    wireGuardMTU: kind === 'wireguard' ? intOrUndefined(str(d['mtu'])) : undefined,
    wireGuardDNS: kind === 'wireguard' ? csv(d['dns']).join(',') || undefined : undefined,
    ssh: kind === 'ssh' ? {
      privateKey: str(d['private-key']),
      privateKeyPassphrase: str(d['private-key-passphrase']),
      hostKeys: csv(d['host-key']),
      hostKeyAlgorithms: csv(d['host-key-algorithms']),
    } : undefined,
    trustTunnel: kind === 'trusttunnel' ? { quic: boolString(str(d['quic'])) } : undefined,
    masque: kind === 'masque' ? masque : undefined,
    rawURI: `clash://local/${nextNodeID()}`,
    vlessEncryption: kind === 'vless' ? vlessEncryption(str(d['encryption'])) : undefined,
  }
  return node
}

function vlessEncryption(value: string | undefined): string | undefined {
  const v = value?.trim()
  if (!v || v.toLowerCase() === 'none') return undefined
  return v
}

/** Nested maps like `plugin-opts: { mode: … }` stay records; lookup helper. */
function subRecord(d: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  const value = d[key]
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  return undefined
}

function realityOptions(d: Record<string, unknown>): boolean {
  return 'reality-opts' in d
}

/** A REALITY short id serialized as a one-element YAML array. */
function scalarish(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  const trimmed = value.trim().replace(/^["']|["']$/g, '')
  return trimmed === '' ? undefined : trimmed
}

function alpnValue(value: unknown): string | undefined {
  if (Array.isArray(value)) {
    const items = value.map((v) => str(v)).filter((v): v is string => !!v)
    return items.length ? items.join(',') : undefined
  }
  const s = str(value)
  if (!s) return undefined
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1)
    const items = inner.split(',').map((x) => x.trim()).filter(Boolean)
    return items.length ? items.join(',') : undefined
  }
  return s
}

function csv(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((v) => str(v)).filter((v): v is string => !!v)
  const s = str(value)
  if (!s) return []
  if (s.startsWith('[') && s.endsWith(']')) {
    return s
      .slice(1, -1)
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean)
  }
  return s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
}

/** Flatten one level of dotted keys producers sometimes emit. */
function flattenRecord(input: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...input }
  for (const [k, v] of Object.entries(input)) {
    if (typeof v === 'object' && v !== null && !Array.isArray(v)) continue
    out[k] = v
  }
  return out
}

function masqueOptions(d: Record<string, unknown>): MASQUEOptions | undefined {
  const privateKey = str(d['private-key'])?.trim()
  const publicKey = str(d['public-key'])?.trim()
  if (!privateKey || !publicKey) return undefined
  const ipv4 = str(d['ip'])?.trim() || undefined
  const ipv6 = str(d['ipv6'])?.trim() || undefined
  if (!ipv4 && !ipv6) return undefined
  const network = str(d['network'])?.trim().toLowerCase()
  if (network && !['quic', 'h3', 'h2'].includes(network)) return undefined
  const mtu = intOrUndefined(str(d['mtu']))
  if (mtu !== undefined && (mtu < 1280 || mtu > 1500)) return undefined
  if (str(d['username']) || str(d['password']) || alpnValue(d['alpn'])) return undefined
  const dns = csv(d['dns'])
  return {
    mode: 'keyConnectIP',
    privateKey,
    publicKey,
    ipv4,
    ipv6,
    network: network || undefined,
    mtu,
    dns: dns.length > 0 ? dns : undefined,
    remoteDNSResolve: d['remote-dns-resolve'] === undefined
      ? undefined
      : boolString(str(d['remote-dns-resolve'])),
  }
}

function str(value: unknown): string | undefined {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return undefined
}

function intOrUndefined(value: string | undefined): number | undefined {
  if (!value) return undefined
  const n = Number(value)
  return Number.isInteger(n) ? n : undefined
}

function boolOrUndefined(value: unknown): boolean | undefined {
  if (value === undefined) return undefined
  if (typeof value === 'boolean') return value
  return boolString(str(value))
}
