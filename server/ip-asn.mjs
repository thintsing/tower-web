// Offline IP ASN / organization lookup (sapics/ip-location-db, PDDL-1.0).
// Fixed-size sorted range records + shared UTF-8 name pool, same binary layout
// as Tower iOS IPASNDatabase.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { isIP } from 'node:net'
import { cidrsForRange, mergeRanges } from './ip-country.mjs'

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
 * 某个 ASN 的全部 CIDR；数据库里没有该 ASN 时返回空数组。
 * 供 sing-box / Hiddify 把 IP-ASN 规则写成可下载的 IP 规则集
 * （1.12 起内核不再接受 route 规则里的 asn 字段）。
 * 调用方应缓存结果：全表扫描在冷启动时只发生一次。
 * @param {{v4: Buffer, v6: Buffer, names: Buffer} | null} data
 * @param {number} rawASN
 * @returns {string[]}
 */
export function asnCIDRs(data, rawASN) {
  if (!data) return []
  const asn = Number(rawASN)
  // BGP 的 ASN 是 32 位整数；0 在表里表示未知，不能作为查询条件。
  if (!Number.isInteger(asn) || asn <= 0 || asn > 0xffffffff) return []
  const v4 = []
  if (data.v4.length % 18 === 0) {
    for (let offset = 0; offset < data.v4.length; offset += 18) {
      if (data.v4.readUInt32BE(offset + 8) !== asn) continue
      v4.push({
        start: BigInt(data.v4.readUInt32BE(offset)),
        end: BigInt(data.v4.readUInt32BE(offset + 4)),
      })
    }
  }
  const v6 = []
  if (data.v6.length % 42 === 0) {
    for (let offset = 0; offset < data.v6.length; offset += 42) {
      if (data.v6.readUInt32BE(offset + 32) !== asn) continue
      v6.push({
        start: data.v6.readBigUInt64BE(offset) << 64n | data.v6.readBigUInt64BE(offset + 8),
        end: data.v6.readBigUInt64BE(offset + 16) << 64n | data.v6.readBigUInt64BE(offset + 24),
      })
    }
  }
  const result = []
  for (const range of mergeRanges(v4)) {
    result.push(...cidrsForRange(range.start, range.end, 32))
  }
  for (const range of mergeRanges(v6)) {
    result.push(...cidrsForRange(range.start, range.end, 128))
  }
  return result
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
