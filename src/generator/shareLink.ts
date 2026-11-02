// Portable share text for node types that have no URI scheme. The iOS app
// emits a mihomo proxies snippet for SSH / TrustTunnel / key-mode MASQUE,
// a sing-box endpoints JSON for basic MASQUE, and a Surge proxy line for Snell.
import type { ProxyNode, RuleScheme } from '../models/types'
import { canonicalNodeURI } from './base64Sub'
import { generateClashYAML } from './clashYaml'
import { generateSingBox } from './singbox'
import { generateSurge } from './surge'

const SHARE_SCHEME: RuleScheme = {
  id: 'share',
  name: 'share',
  description: '',
  groups: [{ name: '节点选择', type: 'select', options: ['DIRECT'] }],
  rules: [{ type: 'FINAL', value: '', group: '节点选择' }],
}

const URI_RE = /^(ss|ssr|vmess|vless|trojan|anytls|hysteria2?|hy2?|tuic|wireguard|wg|snell|ssh|socks5|http|https):\/\/\S+/i

function reusableURI(node: ProxyNode): string | undefined {
  const uri = node.rawURI?.trim()
  if (!uri || uri.toLowerCase().startsWith('clash://local/')) return undefined
  return URI_RE.test(uri) ? uri : undefined
}

function nodesOnlyClash(node: ProxyNode): string | undefined {
  const text = generateClashYAML([node], SHARE_SCHEME, {
    contentMode: 'nodes',
    target: 'clash-verge',
  }).trim()
  return text && !text.endsWith('proxies: []') ? text : undefined
}

function nodesOnlySurge(node: ProxyNode): string | undefined {
  const result = generateSurge([node], SHARE_SCHEME, { contentMode: 'nodes' })
  const text = result.text.trim()
  return result.skipped === 0 && text ? text : undefined
}

function nodesOnlySingBox(node: ProxyNode): string | undefined {
  const result = generateSingBox([node], SHARE_SCHEME, {
    contentMode: 'nodes',
    target: 'sing-box',
  })
  return result.skipped === 0 ? result.text.trim() : undefined
}

/**
 * Prefer the provider's original link. When it is missing or only a private
 * placeholder, fall back to the same portable snippet the native app shares.
 */
export function nodeShareText(node: ProxyNode): string | undefined {
  const original = reusableURI(node)
  if (original) return original

  switch (node.kind) {
    case 'snell':
      return nodesOnlySurge(node) ?? original
    case 'ssh':
    case 'trusttunnel':
      return nodesOnlyClash(node) ?? original
    case 'masque':
      // Basic CONNECT-IP exists only as a sing-box endpoint; key mode is a
      // mihomo proxy entry. Surge's local MASQUE line has no portable URI form.
      return (node.masque?.mode === 'basicConnectIP'
        ? nodesOnlySingBox(node)
        : nodesOnlyClash(node)) ?? original
    default:
      return canonicalNodeURI(node) ?? original
  }
}
