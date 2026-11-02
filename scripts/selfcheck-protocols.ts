// 自检：TrustTunnel / SSH / MASQUE / WireGuard / AnyTLS 的解析与跨客户端降级。
// 用法：npm run selfcheck:protocols
import assert from 'node:assert/strict'
import type { ProxyNode, RuleScheme } from '../src/models/types'
import { parse } from '../src/parser'
import { encodeBase64String, decodeBase64String } from '../src/parser/util'
import { clashSkippedCount, generateClashYAML } from '../src/generator/clashYaml'
import { generateEgern } from '../src/generator/egern'
import { generateLoon } from '../src/generator/loon'
import { generateQuanX } from '../src/generator/quanx'
import { generateSingBox } from '../src/generator/singbox'
import { generateSurge } from '../src/generator/surge'
import { generateBase64Subscription } from '../src/generator/base64Sub'
import { nodeShareText } from '../src/generator/shareLink'

let failures = 0

function check(label: string, run: () => void): void {
  try {
    run()
    console.log(`✓ ${label}`)
  } catch (error) {
    failures += 1
    console.error(`✗ ${label}`)
    console.error(`  ${error instanceof Error ? error.message : String(error)}`)
  }
}

const CLASH = `
proxies:
  - name: TT-H2
    type: trusttunnel
    server: tt-h2.example.com
    port: 443
    username: tt-user
    password: tt-pass
    sni: tt-h2.example.com
    skip-cert-verify: false
    quic: false
  - name: TT-H3
    type: trust-tunnel
    server: tt-h3.example.com
    port: 443
    username: tt-user
    password: tt-pass
    sni: tt-h3.example.com
    skip-cert-verify: true
    quic: true
    udp: true
  - name: SSH-Password
    type: ssh
    server: ssh.example.com
    port: 22
    username: ssh-user
    password: ssh-pass
    host-key: [ssh-ed25519 AAAA-test]
  - name: SSH-Key
    type: ssh
    server: ssh-key.example.com
    port: 22
    username: ssh-user
    private-key: |
      -----BEGIN OPENSSH PRIVATE KEY-----
      test
      -----END OPENSSH PRIVATE KEY-----
    private-key-passphrase: demo-passphrase
  - name: Surge AnyTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: any-pass
    sni: anytls.example.com
  - name: MASQUE Key
    type: masque
    server: masque.example.com
    port: 443
    private-key: demo-private-key
    public-key: demo-public-key
    ip: 172.16.0.2/32
    mtu: 1400
    network: h3
    sni: masque.example.com
    remote-dns-resolve: true
    dns: [1.1.1.1, 8.8.8.8]
    udp: true
`

const scheme: RuleScheme = {
  id: 'test',
  name: 'test',
  description: '',
  groups: [{ name: '节点选择', type: 'select', options: [] }],
  rules: [{ type: 'FINAL', value: '', group: '节点选择' }],
}

const MASQUE_BASIC = {
  type: 'masque-client',
  tag: 'MASQUE Basic',
  server: 'masque-basic.example.com',
  server_port: 443,
  username: 'basic-user',
  password: 'basic-pass',
  path: '/connect',
  version: 2,
  mtu: 1400,
  headers: { 'X-Test': 'demo' },
  disable_version_fallback: true,
  tls: {
    enabled: true,
    server_name: 'masque-basic.example.com',
    insecure: true,
    alpn: ['h2'],
    certificate: ['-----BEGIN CERTIFICATE-----demo'],
  },
}

const SINGBOX_ENDPOINTS = JSON.stringify({
  endpoints: [MASQUE_BASIC],
  outbounds: [{ type: 'direct', tag: 'direct' }],
}, null, 2)

const WIREGUARD: ProxyNode = {
  id: 'wg-node',
  kind: 'wireguard',
  name: 'WG 节点',
  server: 'wg.example.com',
  port: 51820,
  wireGuardPrivateKey: 'wg-private',
  wireGuardPublicKey: 'wg-public',
  wireGuardPreSharedKey: 'wg-psk',
  wireGuardIPv4: '10.0.0.2',
  wireGuardIPv6: 'fd00::2',
  wireGuardAllowedIPs: '0.0.0.0/0,::/0',
  wireGuardReserved: '1,2,3',
  wireGuardMTU: 1420,
  wireGuardPersistentKeepalive: 30,
  tls: false,
  skipCertificateVerification: false,
  rawURI: '',
}

const SURGE_MASQUE = `
[Proxy]
Surge MASQUE = masque, masque-surge.example.com, 443, username=surge-user, password=surge-pass, sni=masque-surge.example.com, alpn=h2, skip-cert-verify=true, server-cert-fingerprint-sha256=${'a'.repeat(64)}
`

const SNELL: ProxyNode = {
  id: 'snell-node',
  kind: 'snell',
  name: 'Snell 节点',
  server: 'snell.example.com',
  port: 8443,
  password: 'snell-psk',
  version: 4,
  obfs: 'http',
  obfsParam: 'obfs.example.com',
  tls: false,
  skipCertificateVerification: false,
  rawURI: '',
}

const SHADOW_TLS: ProxyNode = {
  id: 'shadowtls-node',
  kind: 'ss',
  name: 'ShadowTLS 节点',
  server: 'stls.example.com',
  port: 443,
  cipher: 'aes-128-gcm',
  password: 'inner-password',
  plugin: 'shadow-tls',
  shadowTLS: { version: 3, host: 'front.example.com', password: 'outer-password' },
  tls: false,
  skipCertificateVerification: false,
  rawURI: '',
}

const V2RAY_PLUGIN: ProxyNode = {
  id: 'v2ray-node',
  kind: 'ss',
  name: 'v2ray-plugin 节点',
  server: 'v2ray.example.com',
  port: 443,
  cipher: 'aes-128-gcm',
  password: 'v2-pass',
  plugin: 'v2ray-plugin',
  pluginMux: false,
  transport: 'ws',
  tls: true,
  hostHeader: 'cdn.example.com',
  path: '/ws',
  skipCertificateVerification: false,
  rawURI: '',
}

const SS_TLS: ProxyNode = {
  id: 'ss-tls-node',
  kind: 'ss',
  name: 'SS TLS 节点',
  server: 'ss-tls.example.com',
  port: 443,
  cipher: 'aes-256-gcm',
  password: 'tls-pass',
  tls: true,
  sni: 'ss-tls.example.com',
  skipCertificateVerification: true,
  rawURI: '',
}

const HYSTERIA1: ProxyNode = {
  id: 'hy1-node',
  kind: 'hysteria',
  name: 'HY1 节点',
  server: 'hy1.example.com',
  port: 8443,
  password: 'hy1-pass',
  obfs: 'salamander',
  upMbps: 50,
  downMbps: 100,
  tls: true,
  skipCertificateVerification: false,
  rawURI: '',
}

function parsedNodes(): ProxyNode[] {
  const parsed = parse(CLASH)
  assert.equal(parsed.rejectedLineCount, 0)
  assert.equal(parsed.nodes.length, 6)
  return parsed.nodes
}

function main(): void {
  const nodes = parsedNodes()

  check('Clash YAML 可解析 TrustTunnel / SSH / AnyTLS / MASQUE', () => {
    const tt = nodes.find((node) => node.name === 'TT-H2')
    assert.ok(tt)
    assert.equal(tt.kind, 'trusttunnel')
    assert.equal(tt.tls, true)
    assert.equal(tt.username, 'tt-user')
    assert.equal(tt.password, 'tt-pass')
    assert.equal(tt.trustTunnel?.quic, false)

    const tt3 = nodes.find((node) => node.name === 'TT-H3')
    assert.ok(tt3)
    assert.equal(tt3.trustTunnel?.quic, true)
    assert.equal(tt3.udpRelayEnabled, true)

    const ssh = nodes.find((node) => node.name === 'SSH-Password')
    assert.ok(ssh)
    assert.equal(ssh.kind, 'ssh')
    assert.equal(ssh.username, 'ssh-user')
    assert.deepEqual(ssh.ssh?.hostKeys, ['ssh-ed25519 AAAA-test'])

    const sshKey = nodes.find((node) => node.name === 'SSH-Key')
    assert.ok(sshKey)
    assert.ok(sshKey.ssh?.privateKey?.includes('BEGIN OPENSSH PRIVATE KEY'))
    assert.equal(sshKey.ssh?.privateKeyPassphrase, 'demo-passphrase')

    const masque = nodes.find((node) => node.name === 'MASQUE Key')
    assert.ok(masque)
    assert.equal(masque.kind, 'masque')
    assert.equal(masque.masque?.mode, 'keyConnectIP')
    assert.equal(masque.masque?.ipv4, '172.16.0.2/32')
    assert.equal(masque.masque?.mtu, 1400)
    assert.equal(masque.masque?.network, 'h3')
    assert.equal(masque.udpRelayEnabled, true)
  })

  check('Mihomo YAML 写出 TrustTunnel / SSH / MASQUE', () => {
    const text = generateClashYAML(nodes, scheme, { target: 'clash-verge' })
    assert.ok(text.includes('type: trusttunnel'))
    assert.ok(text.includes('username: "tt-user"'))
    assert.ok(text.includes('password: "tt-pass"'))
    assert.ok(text.includes('quic: true'))
    assert.ok(text.includes('udp: true'))
    assert.ok(text.includes('type: ssh'))
    assert.ok(text.includes('host-key: ["ssh-ed25519 AAAA-test"]'))
    assert.ok(text.includes('type: masque'))
    assert.ok(text.includes('private-key: "demo-private-key"'))
    assert.ok(text.includes('network: "quic"'))
    assert.ok(text.includes('remote-dns-resolve: true'))
    assert.ok(text.includes('dns: ["1.1.1.1", "8.8.8.8"]'))
    assert.ok(text.includes('SSH-Key'))
    assert.ok(text.includes('private-key: "-----BEGIN OPENSSH PRIVATE KEY-----\\ntest\\n-----END OPENSSH PRIVATE KEY-----"'))
    assert.ok(text.includes('private-key-passphrase: "demo-passphrase"'))
  })

  check('Stash 跳过 host-key SSH，但写出私钥登录', () => {
    const text = generateClashYAML(nodes, scheme, { target: 'clash' })
    assert.ok(!text.includes('TT-H2'))
    assert.ok(text.includes('TT-H3'))
    assert.ok(!text.includes('SSH-Password'))
    assert.ok(text.includes('SSH-Key'))
    assert.ok(text.includes('user: "ssh-user"'))
    assert.ok(text.includes('private-key: "-----BEGIN OPENSSH PRIVATE KEY-----\\ntest'))
    assert.ok(!text.includes('type: masque'))
  })

  check('Karing 不写 TrustTunnel', () => {
    const text = generateClashYAML(nodes, scheme, { target: 'karing' })
    assert.ok(!text.includes('type: trusttunnel'))
    assert.ok(text.includes('type: anytls'))
    assert.equal(clashSkippedCount(nodes, 'karing'), 3)
  })

  check('Surge 写出 trust-tunnel / ssh / anytls', () => {
    const result = generateSurge(nodes, scheme)
    assert.ok(result.text.includes('= trust-tunnel,'))
    assert.ok(result.text.includes('h3=true'))
    assert.ok(result.text.includes('= ssh,'))
    assert.ok(result.text.includes('server-fingerprint="ssh-ed25519 AAAA-test"'))
    assert.ok(result.text.includes('= anytls,'))
    assert.equal(result.skipped, 2) // SSH-Key 需要 [Keystore]，MASQUE 非 Surge 类型
  })

  check('Surge 写出 WireGuard section', () => {
    const result = generateSurge([WIREGUARD], scheme, { target: 'surge' })
    assert.equal(result.skipped, 0)
    assert.ok(result.text.includes('= wireguard, section-name=tower-wg-node'))
    assert.ok(result.text.includes('[WireGuard tower-wg-node]'))
    assert.ok(result.text.includes('private-key = wg-private'))
    assert.ok(result.text.includes('self-ip = 10.0.0.2'))
    assert.ok(result.text.includes('self-ip-v6 = fd00::2'))
    assert.ok(result.text.includes('mtu = 1420'))
    assert.ok(result.text.includes('peer = (public-key = wg-public, allowed-ips = "0.0.0.0/0,::/0", endpoint = wg.example.com:51820, preshared-key = wg-psk, keepalive = 30, client-id = 1/2/3)'))
  })

  check('Loon 写出 WireGuard peers', () => {
    const result = generateLoon([WIREGUARD], scheme, { target: 'loon' })
    assert.equal(result.skipped, 0)
    assert.ok(result.text.includes('= wireguard, interface-ip=10.0.0.2'))
    assert.ok(result.text.includes('private-key="wg-private"'))
    assert.ok(result.text.includes('peers=[{public-key="wg-public",allowed-ips="0.0.0.0/0,::/0",endpoint=wg.example.com:51820,reserved=[1,2,3],preshared-key="wg-psk"}]'))
    assert.ok(result.text.includes('udp=true'))
  })

  check('Base64 订阅跳过没有 URI 的 TrustTunnel / SSH / MASQUE', () => {
    const result = generateBase64Subscription(nodes)
    assert.equal(result.skipped, 5) // TrustTunnel × 2 + SSH × 2 + MASQUE，AnyTLS 可写
    assert.ok(result.text.length > 0)
  })

  check('Egern 写出 SSH host key，跳过带口令的私钥', () => {
    const result = generateEgern(nodes, scheme)
    assert.equal(result.skipped, 4) // TrustTunnel × 2 + 带口令私钥 + MASQUE
    assert.ok(result.text.includes('type: ssh') || result.text.includes('  - ssh:'))
    assert.ok(result.text.includes('host_keys: ["ssh-ed25519 AAAA-test"]'))
    assert.ok(!result.text.includes('SSH-Key'))
  })

  check('V2Box 写出 WireGuard URI，Anywhere 跳过', () => {
    const v2box = generateBase64Subscription([WIREGUARD], { target: 'v2box' })
    assert.equal(v2box.skipped, 0)
    const link = new URL(decodeBase64String(v2box.text)!)
    assert.equal(link.protocol, 'wireguard:')
    assert.equal(link.username, 'wg-private')
    assert.equal(link.hostname, 'wg.example.com')
    assert.equal(link.port, '51820')
    assert.equal(link.searchParams.get('publickey'), 'wg-public')
    assert.equal(link.searchParams.get('address'), '10.0.0.2,fd00::2')
    assert.equal(link.searchParams.get('reserved'), '1,2,3')
    assert.equal(link.searchParams.get('mtu'), '1420')
    assert.equal(link.searchParams.get('keepalive'), '30')

    const anywhere = generateBase64Subscription([WIREGUARD], { target: 'anywhere' })
    assert.equal(anywhere.skipped, 1)
  })

  check('Anywhere 过滤节点并转换 URI 方言', () => {
    const sample = (id: string, kind: ProxyNode['kind']): ProxyNode => ({
      id,
      kind,
      name: id,
      server: `${id}.example.com`,
      port: 443,
      tls: true,
      skipCertificateVerification: false,
      rawURI: '',
    })
    const vless: ProxyNode = {
      ...sample('vless', 'vless'),
      uuid: '11111111-1111-1111-1111-111111111111',
      transport: 'grpc',
      hostHeader: 'grpc.example.com',
      path: 'svc',
      sni: 'vless.example.com',
      fingerprint: 'chrome',
      flow: 'xtls-rprx-vision',
      udpRelayEnabled: true,
    }
    const anytls: ProxyNode = {
      ...sample('anytls', 'anytls'),
      password: 'any-pass',
      sni: 'anytls.example.com',
      idleSessionCheckInterval: 30,
      idleSessionTimeout: 60,
      minIdleSession: 2,
      udpRelayEnabled: true,
    }
    const result = generateBase64Subscription([vless, anytls], { target: 'anywhere' })
    assert.equal(result.skipped, 0)
    const links = decodeBase64String(result.text)!.split('\n').map((uri) => new URL(uri))
    assert.equal(links[0].searchParams.get('fp'), 'chrome_133')
    assert.equal(links[0].searchParams.get('authority'), 'grpc.example.com')
    assert.equal(links[0].searchParams.get('flow'), 'xtls-rprx-vision')
    assert.equal(links[1].searchParams.get('ici'), '30')
    assert.equal(links[1].searchParams.get('it'), '60')
    assert.equal(links[1].searchParams.get('mis'), '2')

    const insecure = { ...vless, id: 'insecure', skipCertificateVerification: true }
    assert.equal(generateBase64Subscription([insecure], { target: 'anywhere' }).skipped, 1)
  })

  check('sing-box 写出 WireGuard endpoint / SSH / AnyTLS / Snell / Hysteria 1', () => {
    const all = [...nodes, WIREGUARD, SNELL, HYSTERIA1]
    const result = generateSingBox(all, scheme, { target: 'sing-box' })
    assert.equal(result.skipped, 3) // TrustTunnel × 2 + key MASQUE
    const config = JSON.parse(result.text)
    assert.equal(config.endpoints.length, 1)
    const endpoint = config.endpoints[0]
    assert.equal(endpoint.type, 'wireguard')
    assert.deepEqual(endpoint.address, ['10.0.0.2/32', 'fd00::2/128'])
    assert.equal(endpoint.private_key, 'wg-private')
    assert.equal(endpoint.mtu, 1420)
    assert.deepEqual(endpoint.peers[0], {
      address: 'wg.example.com',
      port: 51820,
      public_key: 'wg-public',
      allowed_ips: ['0.0.0.0/0', '::/0'],
      pre_shared_key: 'wg-psk',
      reserved: [1, 2, 3],
      persistent_keepalive_interval: 30,
    })
    assert.ok(!config.outbounds.some((item: { type?: string }) => item.type === 'wireguard'))
    assert.ok(config.outbounds.some((item: { type?: string }) => item.type === 'anytls'))
    assert.ok(config.outbounds.some((item: { type?: string }) => item.type === 'snell' && item.psk === 'snell-psk' && item.version === 4))
    assert.ok(config.outbounds.some((item: { type?: string }) => item.type === 'hysteria' && item.auth_str === 'hy1-pass'))
    const keySsh = config.outbounds.find((item: { type?: string; private_key?: string }) =>
      item.type === 'ssh' && item.private_key)
    assert.ok(keySsh)
    assert.ok(keySsh.private_key.includes('BEGIN OPENSSH PRIVATE KEY'))
    assert.equal(keySsh.private_key_passphrase, 'demo-passphrase')
    assert.ok(config.outbounds.some((item: { type?: string; host_key?: string[] }) =>
      item.type === 'ssh' && item.host_key?.[0] === 'ssh-ed25519 AAAA-test'))
  })

  check('Hiddify 使用旧式 WireGuard outbound，并跳过 Snell', () => {
    const all = [...nodes, WIREGUARD, SNELL, HYSTERIA1]
    const result = generateSingBox(all, scheme, { target: 'hiddify' })
    assert.equal(result.skipped, 4) // TrustTunnel × 2 + MASQUE + Snell
    const config = JSON.parse(result.text)
    assert.ok(!config.endpoints)
    const wireguard = config.outbounds.find((item: { type?: string }) => item.type === 'wireguard')
    assert.ok(wireguard)
    assert.deepEqual(wireguard.local_address, ['10.0.0.2/32', 'fd00::2/128'])
    assert.equal(wireguard.peer_public_key, 'wg-public')
    assert.deepEqual(wireguard.reserved, [1, 2, 3])
    assert.ok(config.outbounds.some((item: { type?: string }) => item.type === 'anytls'))
    assert.ok(config.outbounds.some((item: { type?: string }) => item.type === 'ssh'))
    assert.ok(config.outbounds.some((item: { type?: string }) => item.type === 'hysteria'))
    assert.ok(!config.outbounds.some((item: { type?: string }) => item.type === 'snell'))
  })

  check('Surge masque Basic-auth CONNECT 可导入并写回', () => {
    const parsed = parse(SURGE_MASQUE)
    assert.equal(parsed.rejectedLineCount, 0)
    assert.equal(parsed.nodes.length, 1)
    const node = parsed.nodes[0]
    assert.equal(node.kind, 'masque')
    assert.equal(node.masque, undefined)
    assert.equal(node.username, 'surge-user')
    assert.equal(node.password, 'surge-pass')
    assert.equal(node.sni, 'masque-surge.example.com')
    assert.equal(node.alpn, 'h2')
    assert.equal(node.skipCertificateVerification, true)
    assert.equal(node.certificateFingerprint, 'a'.repeat(64))

    const surge = generateSurge([node], scheme)
    assert.equal(surge.skipped, 0)
    assert.ok(surge.text.includes('= masque,'))
    assert.ok(surge.text.includes('username=surge-user'))
    assert.ok(surge.text.includes('alpn=h2'))
    assert.ok(surge.text.includes(`server-cert-fingerprint-sha256=${'a'.repeat(64)}`))

    const clash = generateClashYAML([node], scheme, { target: 'clash-verge' })
    assert.ok(!clash.includes('Surge MASQUE'))
    const singbox = generateSingBox([node], scheme, { target: 'sing-box' })
    assert.equal(singbox.skipped, 1)
    assert.ok(!JSON.parse(singbox.text).endpoints)
    const b64 = generateBase64Subscription([node])
    assert.equal(b64.skipped, 1)
  })

  check('非法 Surge masque 字段不会被静默丢弃', () => {
    const parsed = parse('[Proxy]\nBad MASQUE = masque, bad.example.com, 443, unknown=value\n')
    assert.equal(parsed.nodes.length, 0)
    assert.equal(parsed.rejectedLineCount, 1)
  })

  check('sing-box masque-client 可导入为 basic CONNECT-IP', () => {
    const parsed = parse(SINGBOX_ENDPOINTS)
    assert.equal(parsed.rejectedLineCount, 0)
    assert.equal(parsed.nodes.length, 1)
    const node = parsed.nodes[0]
    assert.equal(node.kind, 'masque')
    assert.equal(node.name, 'MASQUE Basic')
    assert.equal(node.server, 'masque-basic.example.com')
    assert.equal(node.port, 443)
    assert.equal(node.username, 'basic-user')
    assert.equal(node.password, 'basic-pass')
    assert.equal(node.path, '/connect')
    assert.equal(node.tls, true)
    assert.equal(node.sni, 'masque-basic.example.com')
    assert.equal(node.alpn, 'h2')
    assert.equal(node.skipCertificateVerification, true)
    assert.equal(node.masque?.mode, 'basicConnectIP')
    assert.equal(node.masque?.httpVersion, 2)
    assert.equal(node.masque?.mtu, 1400)
    assert.deepEqual(node.masque?.headers, { 'X-Test': 'demo' })
    assert.equal(node.masque?.disableVersionFallback, true)
    assert.deepEqual(node.masque?.certificate, ['-----BEGIN CERTIFICATE-----demo'])
  })

  check('Base64 包装的 masque-client JSON 也能导入', () => {
    const parsed = parse(encodeBase64String(SINGBOX_ENDPOINTS))
    assert.equal(parsed.nodes.length, 1)
    assert.equal(parsed.nodes[0].masque?.mode, 'basicConnectIP')
  })

  check('sing-box MT 把 basic MASQUE 写成 endpoints', () => {
    const node = parse(SINGBOX_ENDPOINTS).nodes[0]
    const result = generateSingBox([node], scheme, { target: 'sing-box' })
    assert.equal(result.skipped, 0)
    const config = JSON.parse(result.text)
    assert.equal(config.endpoints.length, 1)
    const endpoint = config.endpoints[0]
    assert.equal(endpoint.type, 'masque-client')
    assert.equal(endpoint.tag, 'MASQUE Basic')
    assert.equal(endpoint.server, 'masque-basic.example.com')
    assert.equal(endpoint.server_port, 443)
    assert.equal(endpoint.username, 'basic-user')
    assert.equal(endpoint.password, 'basic-pass')
    assert.equal(endpoint.path, '/connect')
    assert.equal(endpoint.version, 2)
    assert.equal(endpoint.mtu, 1400)
    assert.deepEqual(endpoint.headers, { 'X-Test': 'demo' })
    assert.equal(endpoint.disable_version_fallback, true)
    assert.deepEqual(endpoint.tls, {
      enabled: true,
      insecure: true,
      server_name: 'masque-basic.example.com',
      certificate: ['-----BEGIN CERTIFICATE-----demo'],
      alpn: ['h2'],
    })
    assert.ok(!config.outbounds.some((item: { tag?: string }) => item.tag === 'MASQUE Basic'))
  })

  check('basic MASQUE 不写入 mihomo 或 Hiddify', () => {
    const node = parse(SINGBOX_ENDPOINTS).nodes[0]
    assert.equal(clashSkippedCount([node], 'clash-verge'), 1)
    const clash = generateClashYAML([node], scheme, { target: 'clash-verge' })
    assert.ok(!clash.includes('MASQUE Basic'))
    const hiddify = generateSingBox([node], scheme, { target: 'hiddify' })
    assert.equal(hiddify.skipped, 1)
    assert.ok(!JSON.parse(hiddify.text).endpoints)
  })

  check('非法或未支持的 masque-client 字段不会被静默降级', () => {
    const bad = JSON.stringify({
      endpoints: [
        { ...MASQUE_BASIC, system: true },
        { ...MASQUE_BASIC, 'unknown-field': true },
        { ...MASQUE_BASIC, version: 1, tls: { enabled: false } },
      ],
    })
    const parsed = parse(bad)
    assert.equal(parsed.nodes.length, 0)
    assert.equal(parsed.rejectedLineCount, 3)
  })

  check('ShadowTLS：Surge / Loon / sing-box / Hiddify 写出，QuanX 跳过', () => {
    const surge = generateSurge([SHADOW_TLS], scheme)
    assert.equal(surge.skipped, 0)
    assert.ok(surge.text.includes('shadow-tls-password=outer-password'))
    assert.ok(surge.text.includes('shadow-tls-sni=front.example.com'))
    assert.ok(surge.text.includes('shadow-tls-version=3'))

    const loon = generateLoon([SHADOW_TLS], scheme, { target: 'loon' })
    assert.equal(loon.skipped, 0)
    assert.ok(loon.text.includes('shadow-tls-password=outer-password'))

    const singbox = generateSingBox([SHADOW_TLS], scheme, { target: 'sing-box' })
    assert.equal(singbox.skipped, 0)
    const config = JSON.parse(singbox.text)
    const helper = config.outbounds.find((item: { type?: string }) => item.type === 'shadowtls')
    assert.ok(helper)
    assert.equal(helper.version, 3)
    assert.equal(helper.tls.server_name, 'front.example.com')
    const inner = config.outbounds.find((item: { tag?: string }) => item.tag === 'ShadowTLS 节点')
    assert.equal(inner.detour, helper.tag)
    assert.equal(inner.network, 'tcp')

    const hiddify = generateSingBox([SHADOW_TLS], scheme, { target: 'hiddify' })
    assert.equal(hiddify.skipped, 0)
    assert.ok(JSON.parse(hiddify.text).outbounds.some((item: { tag?: string }) =>
      String(item.tag).startsWith('§hide§tower-shadowtls-')))

    const quanx = generateQuanX([SHADOW_TLS], scheme)
    assert.equal(quanx.skipped, 1)
  })

  check('v2ray-plugin：不支持的目标跳过，支持的写出插件', () => {
    for (const result of [
      generateSurge([V2RAY_PLUGIN], scheme),
      generateLoon([V2RAY_PLUGIN], scheme, { target: 'loon' }),
      generateEgern([V2RAY_PLUGIN], scheme),
    ]) {
      assert.equal(result.skipped, 1)
      assert.ok(!result.text.includes('v2ray-plugin 节点'))
    }

    const quanx = generateQuanX([V2RAY_PLUGIN], scheme)
    assert.equal(quanx.skipped, 0)
    assert.ok(quanx.text.includes('obfs=wss'))
    assert.ok(quanx.text.includes('obfs-host=cdn.example.com'))
    assert.ok(quanx.text.includes('obfs-uri=/ws'))

    const singbox = generateSingBox([V2RAY_PLUGIN], scheme, { target: 'sing-box' })
    assert.equal(singbox.skipped, 0)
    const ss = JSON.parse(singbox.text).outbounds.find((item: { type?: string }) =>
      item.type === 'shadowsocks')
    assert.equal(ss.plugin, 'v2ray-plugin')
    assert.match(ss.plugin_opts, /mode=websocket/)
    assert.match(ss.plugin_opts, /mux=0/)
    assert.match(ss.plugin_opts, /host=cdn\.example\.com/)
    assert.match(ss.plugin_opts, /path=\/ws/)

    const clash = generateClashYAML([V2RAY_PLUGIN], scheme, { target: 'clash-verge' })
    assert.ok(clash.includes('plugin: v2ray-plugin'))
    assert.ok(clash.includes('mode: websocket'))
    assert.equal(generateBase64Subscription([V2RAY_PLUGIN]).skipped, 1)
  })

  check('SS cipher / Snell 版本 / VLESS encryption 按目标限制', () => {
    const chacha2022: ProxyNode = { ...SS_TLS, id: 'chacha', tls: false, sni: undefined, cipher: '2022-blake3-chacha20-poly1305' }
    assert.equal(generateSurge([chacha2022], scheme).skipped, 1)
    assert.equal(generateLoon([chacha2022], scheme, { target: 'loon' }).skipped, 1)
    assert.equal(generateQuanX([chacha2022], scheme).skipped, 1)
    assert.equal(clashSkippedCount([chacha2022], 'clash'), 1)
    assert.equal(clashSkippedCount([chacha2022], 'clash-verge'), 0)

    const snellV5: ProxyNode = { ...SNELL, id: 'snell-v5', version: 5 }
    assert.equal(clashSkippedCount([snellV5], 'clash'), 1)
    assert.equal(clashSkippedCount([snellV5], 'clash-verge'), 0)
    const snellBox = generateSingBox([snellV5], scheme, { target: 'sing-box' })
    assert.equal(snellBox.skipped, 0)
    assert.ok(JSON.parse(snellBox.text).outbounds.some((item: { version?: number }) => item.version === 4))

    const vlessEncrypted: ProxyNode = {
      ...SS_TLS,
      id: 'vless-encrypted',
      kind: 'vless',
      uuid: '11111111-1111-1111-1111-111111111111',
      cipher: undefined,
      password: undefined,
      vlessEncryption: 'mlkem768x25519plus',
    }
    assert.equal(clashSkippedCount([vlessEncrypted], 'clash'), 1)
    const mihomo = generateClashYAML([vlessEncrypted], scheme, { target: 'clash-verge' })
    assert.ok(mihomo.includes('encryption: "mlkem768x25519plus"'))
    assert.equal(generateSingBox([vlessEncrypted], scheme, { target: 'sing-box' }).skipped, 1)
  })

  check('Stash 证书 pin 字段与原生 SS TLS', () => {
    const pinned: ProxyNode = {
      ...SS_TLS,
      kind: 'trojan',
      cipher: undefined,
      password: 'trojan-pass',
      certificateFingerprint: 'aa'.repeat(32),
    }
    const stash = generateClashYAML([pinned], scheme, { target: 'clash' })
    assert.ok(stash.includes(`server-cert-fingerprint: "${'aa'.repeat(32)}"`))
    assert.ok(!/\n    fingerprint:/.test(stash))
    const mihomo = generateClashYAML([pinned], scheme, { target: 'clash-verge' })
    assert.ok(mihomo.includes(`fingerprint: "${'aa'.repeat(32)}"`))

    const karing = generateClashYAML([SS_TLS], scheme, { target: 'karing' })
    assert.ok(karing.includes('tls: true'))
    assert.ok(karing.includes('servername: "ss-tls.example.com"'))
    const shadowrocket = generateClashYAML([SS_TLS], scheme, { target: 'shadowrocket' })
    assert.ok(shadowrocket.includes('tls: true'))
    assert.equal(generateSurge([SS_TLS], scheme).skipped, 1)
    assert.equal(generateLoon([SS_TLS], scheme, { target: 'loon' }).skipped, 1)
    assert.equal(clashSkippedCount([SS_TLS], 'clash-verge'), 1)
    const quanx = generateQuanX([SS_TLS], scheme)
    assert.equal(quanx.skipped, 0)
    assert.ok(quanx.text.includes('obfs=over-tls'))
  })

  check('节点分享：标准 URI 与特殊协议的可移植片段', () => {
    const tt = nodes.find((node) => node.name === 'TT-H2')!
    const ssh = nodes.find((node) => node.name === 'SSH-Password')!
    const masque = nodes.find((node) => node.name === 'MASQUE Key')!
    assert.ok(nodeShareText(tt)?.includes('type: trusttunnel'))
    assert.ok(nodeShareText(ssh)?.includes('type: ssh'))
    assert.ok(nodeShareText(masque)?.includes('type: masque'))
    assert.ok(nodeShareText(SNELL)?.includes('= snell,'))
    assert.ok(nodeShareText(SHADOW_TLS)?.includes('plugin=shadow-tls'))
    assert.ok(nodeShareText(V2RAY_PLUGIN)?.includes('plugin=v2ray-plugin'))
    assert.match(nodeShareText(SS_TLS) ?? '', /^ss:\/\/[A-Za-z0-9_-]+@ss-tls\.example\.com:443/)

    const basic = parse(SINGBOX_ENDPOINTS).nodes[0]
    const shared = nodeShareText(basic)
    assert.ok(shared)
    assert.equal(JSON.parse(shared).endpoints[0].type, 'masque-client')
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部协议补全检查通过')
}

main()
