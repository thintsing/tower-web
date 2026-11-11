// Tailnet connections are policies that let a proxy client reach a Tailscale
// network while it is handling other traffic. They are deliberately not nodes:
// a destination outside the tailnet fails through them instead of falling back.
import type { TailnetConnection } from './types'
import { newID } from '../util/browser'

export const TAILNET_DEFAULT_NAME = 'Tailscale'
export const TAILNET_DEFAULT_DEVICE_NAME = 'tower'
export const TAILNET_IPV4_RANGE = '100.64.0.0/10'
export const TAILNET_IPV6_RANGE = 'fd7a:115c:a1e0::/48'

export type TailnetValidationField = 'controlURL' | 'subnet' | 'magicDNSSuffix' | 'authKey'

export class TailnetValidationError extends Error {
  constructor(
    public readonly field: TailnetValidationField,
    public readonly value = '',
  ) {
    super(field)
    this.name = 'TailnetValidationError'
  }
}

export function defaultTailnetConnection(): TailnetConnection {
  return {
    id: newID(),
    name: TAILNET_DEFAULT_NAME,
    subnets: [],
    isEnabled: true,
  }
}

function parseIPv4(value: string): number[] | undefined {
  const parts = value.split('.')
  if (parts.length !== 4) return undefined
  const bytes: number[] = []
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined
    const byte = Number(part)
    if (byte < 0 || byte > 255) return undefined
    bytes.push(byte)
  }
  return bytes
}

function maskIPv4(bytes: number[], prefix: number): number[] {
  return bytes.map((byte, index) => {
    const bits = Math.max(0, Math.min(8, prefix - index * 8))
    return bits === 0 ? 0 : byte & (0xff << (8 - bits))
  })
}

function parseIPv6(value: string): number[] | undefined {
  const lower = value.toLowerCase()
  if (!/^[0-9a-f:]+$/.test(lower)) return undefined
  const pieces = lower.split('::')
  if (pieces.length > 2) return undefined
  const left = pieces[0] ? pieces[0].split(':') : []
  const right = pieces.length === 2 && pieces[1] ? pieces[1].split(':') : []
  if (pieces.length === 1 && left.length !== 8) return undefined
  if (pieces.length === 2 && left.length + right.length > 7) return undefined
  const group = (part: string) => /^[0-9a-f]{1,4}$/.test(part) ? parseInt(part, 16) : undefined
  const groups: number[] = []
  for (const part of left) {
    const value = group(part)
    if (value === undefined) return undefined
    groups.push(value)
  }
  const zeros = 8 - left.length - right.length
  for (let index = 0; index < zeros; index += 1) groups.push(0)
  for (const part of right) {
    const value = group(part)
    if (value === undefined) return undefined
    groups.push(value)
  }
  return groups.length === 8 ? groups : undefined
}

function maskIPv6(groups: number[], prefix: number): number[] {
  return groups.map((group, index) => {
    const bits = Math.max(0, Math.min(16, prefix - index * 16))
    return bits === 0 ? 0 : group & ((0xffff << (16 - bits)) & 0xffff)
  })
}

function formatIPv6(groups: number[]): string {
  const parts = groups.map((group) => group.toString(16))
  let bestStart = -1
  let bestLength = 0
  for (let start = 0; start < parts.length; start += 1) {
    if (groups[start] !== 0) continue
    let end = start
    while (end < groups.length && groups[end] === 0) end += 1
    if (end - start > bestLength) {
      bestStart = start
      bestLength = end - start
    }
    start = end - 1
  }
  if (bestLength < 2) return parts.join(':')
  const head = parts.slice(0, bestStart).join(':')
  const tail = parts.slice(bestStart + bestLength).join(':')
  if (!head && !tail) return '::'
  if (!head) return `::${tail}`
  if (!tail) return `${head}::`
  return `${head}::${tail}`
}

/** One CIDR, normalized to network address form and canonical spelling. */
export function normalizeCIDR(value: string): string | undefined {
  const pieces = value.trim().split('/')
  if (pieces.length !== 2) return undefined
  const prefix = Number(pieces[1])
  const address = pieces[0]
  if (!Number.isInteger(prefix)) return undefined
  if (address.includes(':')) {
    if (prefix < 0 || prefix > 128) return undefined
    const groups = parseIPv6(address)
    if (!groups) return undefined
    return `${formatIPv6(maskIPv6(groups, prefix))}/${prefix}`
  }
  if (prefix < 0 || prefix > 32) return undefined
  const bytes = parseIPv4(address)
  if (!bytes) return undefined
  return `${maskIPv4(bytes, prefix).join('.')}/${prefix}`
}

/** Accepts one CIDR per line or separated by commas / spaces. */
export function normalizeTailnetSubnets(text: string): string[] {
  const parts = text.split(/[\s,，]+/).map((part) => part.trim()).filter(Boolean)
  const seen = new Set<string>()
  const result: string[] = []
  for (const part of parts) {
    const cidr = normalizeCIDR(part)
    if (!cidr) throw new TailnetValidationError('subnet', part)
    if (!seen.has(cidr)) {
      seen.add(cidr)
      result.push(cidr)
    }
  }
  return result
}

export function normalizeTailnetControlURL(value: string): string | undefined {
  const trimmed = value.trim()
  if (!trimmed) return undefined
  if (trimmed.length > 2048) throw new TailnetValidationError('controlURL')
  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch {
    throw new TailnetValidationError('controlURL')
  }
  if (parsed.protocol !== 'https:' || !parsed.hostname) throw new TailnetValidationError('controlURL')
  if (/[\s,"]/.test(trimmed)) throw new TailnetValidationError('controlURL')
  return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed
}

export function normalizeTailnetMagicDNSSuffix(value: string): string | undefined {
  const trimmed = value.trim().toLowerCase().replace(/^\.+|\.+$/g, '')
  if (!trimmed) return undefined
  if (trimmed.length > 253) throw new TailnetValidationError('magicDNSSuffix')
  const labels = trimmed.split('.')
  const valid = labels.length >= 2 && labels.every((label) =>
    label.length > 0 && label.length <= 63 && !label.startsWith('-') && !label.endsWith('-')
      && /^[a-z0-9-]+$/.test(label),
  )
  if (!valid) throw new TailnetValidationError('magicDNSSuffix')
  return trimmed
}

/** Lowercase letters, digits and hyphens; empty means the default name. */
export function normalizeTailnetDeviceName(value: string): string | undefined {
  const normalized = value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '')
  if (!normalized) return undefined
  return normalized.slice(0, 40).replace(/-$/g, '') || undefined
}

/** Empty keys are removed. Whitespace, quotes, commas and backslashes break config lines. */
export function normalizeTailnetAuthKey(value: string): string | undefined {
  const trimmed = value.trim()
  if (!trimmed) return undefined
  if (trimmed.length > 512 || /[\s"',\\]/.test(trimmed)) throw new TailnetValidationError('authKey')
  return trimmed
}

/** The same escaping used for node policy names. */
export function tailnetPolicyName(connection: TailnetConnection): string {
  const cleaned = connection.name
    .replace(/\r\n/g, ' ')
    .replace(/[\r\n\u2028\u2029]/g, ' ')
    .replace(/=/g, '-')
    .replace(/,/g, '，')
    .replace(/#/g, '＃')
    .replace(/;/g, '；')
    .replace(/\[/g, '［')
    .replace(/\]/g, '］')
    .replace(/"/g, '＂')
    .trim()
  return cleaned ? cleaned.slice(0, 80) : TAILNET_DEFAULT_NAME
}

/** Stable across exports: changing it would register a new device every import. */
export function tailnetStableSlug(connection: TailnetConnection): string {
  const prefix = connection.id.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8).toLowerCase()
  return `tower-tailnet-${prefix || 'local'}`
}

export function tailnetHostname(connection: TailnetConnection, clientSlug: string): string {
  const base = normalizeTailnetDeviceName(connection.deviceName ?? '') ?? TAILNET_DEFAULT_DEVICE_NAME
  return `${base}-${clientSlug}`.slice(0, 63)
}

export function isIPv6CIDR(cidr: string): boolean {
  return cidr.includes(':')
}
