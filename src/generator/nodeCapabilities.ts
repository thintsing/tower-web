// Target-specific node capabilities ported from the iOS app's
// ConfigurationGenerator.swift. These checks keep Tower from emitting a
// configuration that a client accepts but can never connect with.
import type { ClientTarget, ProxyNode } from '../models/types'

const MIHOMO_TARGETS = new Set<ClientTarget>([
  'clash-verge', 'clashmac', 'flclash', 'mihomo-party', 'clash-mi', 'clash-apple',
])

const SHADOWROCKET_TARGETS = new Set<ClientTarget>(['shadowrocket', 'karing'])

const V2RAY_PLUGIN_TARGETS = new Set<ClientTarget>([
  'clash', 'clash-verge', 'clashmac', 'flclash', 'mihomo-party', 'clash-mi',
  'clash-apple', 'karing', 'shadowrocket', 'quanx', 'hiddify', 'sing-box',
])

const MIHOMO_LEGACY = [
  'rc4', 'rc4-md5', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
  'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'salsa20', 'chacha20', 'chacha20-ietf',
]
const LOON_EXTRA_LEGACY = [
  'bf-cfb', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
  'cast5-cfb', 'des-cfb', 'idea-cfb', 'rc2-cfb', 'seed-cfb',
]
const AEAD = [
  'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
  'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
]
const AES_2022 = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm']

const SHADOWSOCKS_CIPHERS: Partial<Record<ClientTarget, Set<string>>> = {
  surge: new Set([...MIHOMO_LEGACY, ...AEAD, ...AES_2022, 'none']),
  'surge-mac': new Set([...MIHOMO_LEGACY, ...AEAD, ...AES_2022, 'none']),
  loon: new Set([...MIHOMO_LEGACY, ...LOON_EXTRA_LEGACY, ...AEAD, ...AES_2022]),
  quanx: new Set([
    ...MIHOMO_LEGACY, ...AEAD, ...AES_2022,
    'none', 'rc4-md5-6', 'bf-cfb', 'cast5-cfb', 'des-cfb', 'rc2-cfb',
  ]),
  egern: new Set([
    ...MIHOMO_LEGACY, ...LOON_EXTRA_LEGACY, ...AES_2022,
    '2022-blake3-chacha20-poly1305', 'aes-128-gcm', 'aes-256-gcm',
    'chacha20-ietf-poly1305', 'chacha20-poly1305', 'none', 'table',
  ]),
  clash: new Set([
    ...AEAD, ...AES_2022, 'rc4-md5', 'chacha20-ietf', 'xchacha20',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
  ]),
}

export function mihomoTarget(target: ClientTarget | undefined): boolean {
  return !!target && MIHOMO_TARGETS.has(target)
}

function normalizedCipher(node: ProxyNode): string {
  return (node.cipher ?? '').trim().toLowerCase()
}

/** Empty cipher is written as aes-256-gcm, which every target supports. */
export function shadowsocksCipherSupported(node: ProxyNode, target?: ClientTarget): boolean {
  if (node.kind !== 'ss' || !target) return true
  const allowed = SHADOWSOCKS_CIPHERS[target]
  if (!allowed) return true
  const cipher = normalizedCipher(node)
  return !cipher || allowed.has(cipher)
}

/** Stash v1–3, mihomo v1–5, sing-box 4/5 with no unsupported obfs. */
export function snellVersionSupported(node: ProxyNode, target?: ClientTarget): boolean {
  if (node.kind !== 'snell') return true
  const version = node.version ?? (target === 'clash' ? 1 : 4)
  if (target === 'clash') return version >= 1 && version <= 3
  if (target && MIHOMO_TARGETS.has(target)) return version >= 1 && version <= 5
  if (target === 'sing-box') {
    if (![4, 5].includes(version)) return false
    const obfs = (node.obfs ?? '').toLowerCase()
    return !obfs || obfs === 'none' || obfs === 'http'
  }
  return true
}

/** Xray VLESS encryption is only verified on mihomo-family targets. */
export function vlessEncryptionSupported(node: ProxyNode, target?: ClientTarget): boolean {
  if (node.kind !== 'vless' || !node.vlessEncryption) return true
  return !target || MIHOMO_TARGETS.has(target)
}

function hasShadowTLS(node: ProxyNode): boolean {
  return !!node.shadowTLS || node.plugin === 'shadow-tls'
}

/** Ordinary SS-over-TLS is only expressible by Shadowrocket/Karing/QuanX. */
export function nativeShadowsocksTLSSupported(node: ProxyNode, target?: ClientTarget): boolean {
  if (node.kind !== 'ss' || !node.tls) return true
  if (node.plugin || node.obfs) return true
  return !!target && (SHADOWROCKET_TARGETS.has(target) || target === 'quanx')
}

const LOON_DELIMITERS = /[\s,\"'\\#;]/

export function hysteria2ObfsType(node: ProxyNode): { type: string; password: string } | undefined {
  if (node.kind !== 'hysteria2' || !node.obfs) return undefined
  return { type: node.obfs.toLowerCase(), password: node.obfsParam ?? '' }
}

/**
 * Surge/Loon/Shadowrocket only expose Salamander by name. Writing an unknown
 * obfuscator as Salamander would hand the password to the wrong protocol.
 */
export function hysteria2ObfsSupported(node: ProxyNode, target?: ClientTarget): boolean {
  if (node.kind !== 'hysteria2') return true
  const obfs = hysteria2ObfsType(node)
  if (!obfs) return true
  if (target && ['surge', 'surge-mac', 'shadowrocket', 'loon'].includes(target)) {
    if (obfs.type !== 'salamander') return false
    if (target === 'loon' && LOON_DELIMITERS.test(obfs.password)) return false
  }
  return true
}

/** Official sing-box/Hiddify SOCKS has no TLS field; dropping TLS changes the protocol. */
export function socksTLSSupported(node: ProxyNode, target?: ClientTarget): boolean {
  if (node.kind !== 'socks5') return true
  if (!node.tls && !node.realityPublicKey) return true
  return target !== 'sing-box' && target !== 'hiddify'
}

/**
 * ShadowTLS is a two-layer protocol: outer SS password plus inner TLS
 * credentials. Every target below can carry it, but each has a different
 * version / pin / credential constraint.
 */
export function shadowTLSSupported(node: ProxyNode, target?: ClientTarget): boolean {
  if (!hasShadowTLS(node)) return true
  const options = node.shadowTLS
  if (node.kind !== 'ss' || node.plugin !== 'shadow-tls' || !options) return false
  if (options.version < 1 || options.version > 3) return false
  if (!options.host || /[\s,]/.test(options.host)) return false
  if (options.version !== 1 && !options.password) return false
  if (node.obfs || node.transport || node.tls) return false
  if (node.certificateFingerprint) return false
  if (!target) return false
  if (MIHOMO_TARGETS.has(target)) return !options.skipCertificateVerification
  if (target === 'clash') return options.version >= 2 && !node.fingerprint
  if (target === 'surge' || target === 'surge-mac') {
    return options.version >= 2
      && !options.skipCertificateVerification
      && !node.fingerprint
      && normalizedCipher(node) !== '2022-blake3-chacha20-poly1305'
  }
  if (target === 'shadowrocket') {
    return options.version === 3
      && !options.skipCertificateVerification
      && !node.fingerprint
  }
  if (target === 'loon') {
    return options.version >= 2
      && !options.skipCertificateVerification
      && !node.fingerprint
      && !LOON_DELIMITERS.test(options.password)
      && !LOON_DELIMITERS.test(options.host)
  }
  if (target === 'egern') {
    return options.version === 3
      && !options.skipCertificateVerification
      && !node.fingerprint
  }
  if (target === 'sing-box' || target === 'hiddify') return node.udpRelayEnabled !== true
  return false
}

/** Only WebSocket mode is modelled; other plugins must be skipped, not flattened. */
export function v2rayPluginSupported(node: ProxyNode, target?: ClientTarget): boolean {
  if (node.plugin !== 'v2ray-plugin') return true
  if (!target || (node.transport ?? 'tcp').toLowerCase() !== 'ws') return false
  if (!V2RAY_PLUGIN_TARGETS.has(target)) return false
  if (target === 'quanx' && node.pluginMux !== false) return false
  return true
}

/**
 * Common gate used by every text / sing-box writer. It covers the checks that
 * are independent of a client's transport/format implementation.
 */
export function nodeSupportedForTarget(node: ProxyNode, target?: ClientTarget): boolean {
  return shadowsocksCipherSupported(node, target)
    && snellVersionSupported(node, target)
    && vlessEncryptionSupported(node, target)
    && nativeShadowsocksTLSSupported(node, target)
    && shadowTLSSupported(node, target)
    && v2rayPluginSupported(node, target)
    && hysteria2ObfsSupported(node, target)
    && socksTLSSupported(node, target)
}
