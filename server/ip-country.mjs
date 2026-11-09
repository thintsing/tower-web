// 离线 IP → 国家表（sapics/ip-location-db，PDDL-1.0）。
// 固定长度、按起始地址排序的范围记录；这里额外提供「国家 → CIDR」，
// 供 sing-box / Hiddify 把 GEOIP 规则写成可下载的本地规则集。
// 二进制布局见 ip-country/NOTICE.txt：
//   IPv4：4 字节起始 + 4 字节结束 + 2 字节国家码（10 字节）
//   IPv6：16 字节起始 + 16 字节结束 + 2 字节国家码（34 字节）
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

export function loadIPCountryData(dir) {
  try {
    return {
      v4: readFileSync(join(dir, 'IPCountryIPv4.bin')),
      v6: readFileSync(join(dir, 'IPCountryIPv6.bin')),
    }
  } catch {
    return null
  }
}

function formatIPv4(value) {
  const n = Number(value)
  return [n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.')
}

function formatIPv6(value) {
  const groups = []
  let current = value
  for (let index = 0; index < 8; index += 1) {
    groups.unshift((current & 0xffffn).toString(16))
    current >>= 16n
  }
  return groups.join(':')
}

/**
 * 把一个 [start, end] 范围拆成尽量少的 CIDR 块。
 * 结果与 mihomo / sing-box 的 IP 集合语义一致，不依赖压缩写法。
 */
export function cidrsForRange(start, end, bits) {
  const result = []
  const limit = 1n << BigInt(bits)
  if (start < 0n || end >= limit || start > end) return result
  let current = start
  while (current <= end) {
    // 当前地址能对齐到的最大块：0 对齐到整个地址空间，其余看末尾 0 的个数。
    let prefix = bits
    if (current !== 0n) {
      let trailing = 0
      let probe = current
      while ((probe & 1n) === 0n) {
        probe >>= 1n
        trailing += 1
      }
      prefix = bits - trailing
    } else {
      prefix = 0
    }
    let size = 1n << BigInt(bits - prefix)
    // 块不能越过范围终点，超出就减半。
    while (current + size - 1n > end) {
      prefix += 1
      size >>= 1n
    }
    const address = bits === 32 ? formatIPv4(current) : formatIPv6(current)
    result.push(`${address}/${prefix}`)
    current += size
  }
  return result
}

export function mergeRanges(ranges) {
  if (!ranges.length) return ranges
  ranges.sort((left, right) => left.start < right.start ? -1 : left.start > right.start ? 1 : 0)
  const merged = [ranges[0]]
  for (let index = 1; index < ranges.length; index += 1) {
    const range = ranges[index]
    const last = merged[merged.length - 1]
    if (range.start <= last.end + 1n) {
      if (range.end > last.end) last.end = range.end
    } else {
      merged.push({ ...range })
    }
  }
  return merged
}

/**
 * 某个两位国家码的全部 CIDR；数据库里没有该国家时返回空数组。
 * 先合并相邻网段再拆 CIDR，避免同一国家被拆成十几万个碎片。
 * 调用方应缓存结果：全表扫描在冷启动时只发生一次。
 */
export function countryCIDRs(data, rawCode) {
  if (!data) return []
  const code = String(rawCode ?? '').trim().toUpperCase()
  if (!/^[A-Z]{2}$/.test(code)) return []
  const v4 = []
  const v6 = []
  for (let offset = 0; offset + 10 <= data.v4.length; offset += 10) {
    if (data.v4.toString('ascii', offset + 8, offset + 10) !== code) continue
    v4.push({
      start: BigInt(data.v4.readUInt32BE(offset)),
      end: BigInt(data.v4.readUInt32BE(offset + 4)),
    })
  }
  for (let offset = 0; offset + 34 <= data.v6.length; offset += 34) {
    if (data.v6.toString('ascii', offset + 32, offset + 34) !== code) continue
    v6.push({
      start: data.v6.readBigUInt64BE(offset) << 64n | data.v6.readBigUInt64BE(offset + 8),
      end: data.v6.readBigUInt64BE(offset + 16) << 64n | data.v6.readBigUInt64BE(offset + 24),
    })
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
