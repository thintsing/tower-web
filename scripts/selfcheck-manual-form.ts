// 自检：手动节点表单的校验、逐协议映射与编辑回填。
// 用法：npm run selfcheck:manual-form
import assert from 'node:assert/strict'
import {
  applyManualKind,
  buildManualNode,
  emptyManualDraft,
  manualDraftFromNode,
} from '../src/manualNodeForm'

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

function main(): void {
  check('Shadowsocks 表单生成完整节点', () => {
    const draft = {
      ...emptyManualDraft('ss'),
      name: '表单 SS',
      server: 'form.example.com',
      port: '8388',
      secret: 'form-pass',
      obfs: 'http',
      obfsParam: 'cdn.example.com',
    }
    const node = buildManualNode(draft)
    assert.equal(node.kind, 'ss')
    assert.equal(node.server, 'form.example.com')
    assert.equal(node.port, 8388)
    assert.equal(node.cipher, 'aes-256-gcm')
    assert.equal(node.password, 'form-pass')
    assert.equal(node.obfs, 'http')
    assert.equal(node.obfsParam, 'cdn.example.com')
    assert.equal(node.isManual, true)
    assert.equal(node.isEnabled, true)
  })

  check('服务器和端口非法时拒绝保存', () => {
    const draft = { ...emptyManualDraft('ss'), server: 'https://bad.example.com', port: '8388', secret: 'x' }
    assert.throws(() => buildManualNode(draft), /服务器/)
    const badPort = { ...draft, server: 'ok.example.com', port: '70000' }
    assert.throws(() => buildManualNode(badPort), /端口/)
  })

  check('VMess 缺少 UUID 时拒绝保存', () => {
    const draft = { ...emptyManualDraft('vmess'), server: 'vm.example.com', port: '443' }
    assert.throws(() => buildManualNode(draft), /UUID/)
  })

  check('TrustTunnel 写出用户名、H3 与 UDP', () => {
    const draft = {
      ...emptyManualDraft('trusttunnel'),
      server: 'tt.example.com',
      port: '443',
      username: 'tt-user',
      password: 'tt-pass',
      quic: true,
      udpRelayEnabled: true,
    }
    const node = buildManualNode(draft)
    assert.equal(node.kind, 'trusttunnel')
    assert.equal(node.username, 'tt-user')
    assert.equal(node.password, 'tt-pass')
    assert.equal(node.trustTunnel?.quic, true)
    assert.equal(node.udpRelayEnabled, true)
    assert.equal(node.tls, true)
  })

  check('WireGuard 缺少密钥或本机地址时拒绝保存', () => {
    const draft = {
      ...emptyManualDraft('wireguard'),
      server: 'wg.example.com',
      port: '51820',
      wireGuardPrivateKey: 'private',
      wireGuardPublicKey: 'public',
      wireGuardAllowedIPs: '0.0.0.0/0,::/0',
    }
    assert.throws(() => buildManualNode(draft), /IPv4/)
    const complete = { ...draft, wireGuardIPv4: '10.0.0.2/32' }
    const node = buildManualNode(complete)
    assert.equal(node.kind, 'wireguard')
    assert.equal(node.wireGuardMTU, 1280)
  })

  check('编辑回填后仍保留原 id，切换协议保留公共字段', () => {
    const original = buildManualNode({
      ...emptyManualDraft('ss'),
      server: 'keep.example.com',
      port: '8388',
      secret: 'pass',
    })
    const draft = manualDraftFromNode(original)
    const edited = buildManualNode({ ...draft, name: '改名', secret: 'new-pass' }, original)
    assert.equal(edited.id, original.id)
    assert.equal(edited.name, '改名')
    assert.equal(edited.password, 'new-pass')

    const switched = applyManualKind(draft, 'trojan')
    assert.equal(switched.server, 'keep.example.com')
    assert.equal(switched.port, '8388')
    assert.equal(switched.tls, true)
  })

  check('MASQUE basic CONNECT-IP 写出 HTTP/3、请求头与 DNS', () => {
    const draft = {
      ...emptyManualDraft('masque'),
      server: 'masque.example.com',
      port: '443',
      masqueMode: 'basicConnectIP' as const,
      masqueHTTPVersion: '3',
      masqueMTU: '1400',
      masqueDNS: '1.1.1.1, 8.8.8.8',
      masqueHeaders: '{"User-Agent":"tower"}',
      masqueDisableVersionFallback: true,
      username: 'user',
      password: 'pass',
    }
    const node = buildManualNode(draft)
    assert.equal(node.kind, 'masque')
    assert.equal(node.masque?.mode, 'basicConnectIP')
    assert.equal(node.masque?.httpVersion, 3)
    assert.equal(node.masque?.mtu, 1400)
    assert.deepEqual(node.masque?.dns, ['1.1.1.1', '8.8.8.8'])
    assert.deepEqual(node.masque?.headers, { 'User-Agent': 'tower' })
    assert.equal(node.masque?.disableVersionFallback, true)
    assert.equal(node.username, 'user')
    assert.equal(node.password, 'pass')
  })

  check('MASQUE basic 的 HTTP/2 必须启用 TLS，请求头必须是 JSON 对象', () => {
    const draft = {
      ...emptyManualDraft('masque'),
      server: 'masque.example.com',
      port: '443',
      masqueMode: 'basicConnectIP' as const,
      masqueHTTPVersion: '2',
    }
    assert.throws(() => buildManualNode(draft), /TLS/)
    const withTls = buildManualNode({ ...draft, tls: true })
    assert.equal(withTls.tls, true)
    assert.throws(
      () => buildManualNode({ ...draft, tls: true, masqueHeaders: '[]' }),
      /JSON/,
    )
  })

  check('MASQUE 密钥模式校验密钥与本机地址', () => {
    const base = {
      ...emptyManualDraft('masque'),
      server: 'masque.example.com',
      port: '443',
      masqueMode: 'keyConnectIP' as const,
      masqueMTU: '1280',
    }
    assert.throws(() => buildManualNode(base), /私钥/)
    assert.throws(
      () => buildManualNode({ ...base, masquePrivateKey: 'priv', masquePublicKey: 'pub' }),
      /IPv4/,
    )
    const node = buildManualNode({
      ...base,
      masquePrivateKey: 'priv',
      masquePublicKey: 'pub',
      masqueIPv4: '10.0.0.2',
      masqueNetwork: 'quic',
    })
    assert.equal(node.masque?.mode, 'keyConnectIP')
    assert.equal(node.masque?.privateKey, 'priv')
    assert.equal(node.masque?.publicKey, 'pub')
    assert.equal(node.masque?.ipv4, '10.0.0.2')
    assert.equal(node.masque?.network, 'quic')
    assert.equal(node.username, undefined)
    assert.equal(node.password, undefined)
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部手动节点表单检查通过')
}

main()
