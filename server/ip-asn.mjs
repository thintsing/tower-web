// Offline IP ASN / organization lookup (sapics/ip-location-db, PDDL-1.0).
// Fixed-size sorted range records + shared UTF-8 name pool, same binary layout
// as Tower iOS IPASNDatabase.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { isIP } from 'node:net'

export function loadIPASNData(dir) {
  try {
    return {
      v4: readFileSync(join(dir, 'IPASNIPv4.bin')),
      v6: readFileSync(join(dir, 'IPASNIPv6.bin')),
      names: readFileSync(join(dir, 'IPASNNames.bin')),
    }
  } catch {
    return null
  }
}

function ipv4Value(address) {
  const parts = address.split('.')
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    const n = Number(part)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    value = value * 256 + n
  }
  return value >>> 0
}

function ipv6Bytes(address) {
  const [head, tail] = address.toLowerCase().split('::')
  if (tail === undefined && head.split(':').length !== 8) return null
  const left = head ? head.split(':') : []
  const right = tail ? tail.split(':') : []
  const missing = 8 - left.length - right.length
  if (missing < 0) return null
  const groups = [...left, ...Array(missing).fill('0'), ...right]
  if (groups.length !== 8) return null
  const buffer = Buffer.alloc(16)
  for (let i = 0; i < 8; i++) {
    const value = parseInt(groups[i], 16)
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) return null
    buffer.writeUInt16BE(value, i * 2)
  }
  return buffer
}

function nameAt(names, offset, length) {
  if (offset < 0 || length <= 0 || offset + length > names.length) return ''
  try {
    return names.toString('utf8', offset, offset + length)
  } catch {
    return ''
  }
}

function readOrganization(records, names, offset, width) {
  const metadata = offset + width * 2
  const asn = records.readUInt32BE(metadata)
  const nameOffset = records.readUInt32BE(metadata + 4)
  const length = records.readUInt16BE(metadata + 8)
  const organization = nameAt(names, nameOffset, length)
  if (!asn || !organization) return null
  return { asn, organization }
}

/**
 * @param {{v4: Buffer, v6: Buffer, names: Buffer} | null} data
 * @param {string} rawAddress
 * @returns {{asn: number, organization: string} | null}
 */
export function organizationForAddress(data, rawAddress) {
  if (!data) return null
  const address = String(rawAddress ?? '').trim().replace(/^\[|\]$/g, '')
  const family = isIP(address)
  if (family === 4) {
    const value = ipv4Value(address)
    if (value === null || data.v4.length % 18 !== 0) return null
    let low = 0
    let high = data.v4.length / 18 - 1
    while (low <= high) {
      const record = low + Math.floor((high - low) / 2)
      const offset = record * 18
      const start = data.v4.readUInt32BE(offset)
      const end = data.v4.readUInt32BE(offset + 4)
      if (value < start) high = record - 1
      else if (value > end) low = record + 1
      else return readOrganization(data.v4, data.names, offset, 4)
    }
    return null
  }
  if (family === 6) {
    const bytes = ipv6Bytes(address)
    if (!bytes || data.v6.length % 42 !== 0) return null
    let low = 0
    let high = data.v6.length / 42 - 1
    while (low <= high) {
      const record = low + Math.floor((high - low) / 2)
      const offset = record * 42
      const start = data.v6.subarray(offset, offset + 16)
      const end = data.v6.subarray(offset + 16, offset + 32)
      if (bytes.compare(start) < 0) high = record - 1
      else if (bytes.compare(end) > 0) low = record + 1
      else return readOrganization(data.v6, data.names, offset, 16)
    }
  }
  return null
}
