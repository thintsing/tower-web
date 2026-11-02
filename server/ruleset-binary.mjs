// Binary rule-set encoders shared by /api/ruleset.
// The layouts follow mihomo's MRSv1 and sing-box's SRS v2 writers:
// - MRS: zstd(MRS magic + behavior + count + trie/CIDR payload)
// - SRS: "SRS" + version + zlib(rule count + headless rules)
// Only the string/trie/CIDR subsets Tower can reproduce faithfully are written;
// callers keep every other rule inline.
import { constants, deflateSync, zstdCompressSync } from 'node:zlib'

const DOMAIN_TYPES = new Set(['DOMAIN', 'DOMAIN-SUFFIX'])
const IP_TYPES = new Set(['IP-CIDR', 'IP-CIDR6', 'IP6-CIDR'])
const SRS_STRING_TYPES = new Set(['DOMAIN-KEYWORD', 'DOMAIN-REGEX'])
const MAX_ZSTD_BLOCK = 128 * 1024

export class BinaryRuleSetError extends Error {
  constructor(message) {
    super(message)
    this.name = 'BinaryRuleSetError'
  }
}

function plainDomain(value) {
  const domain = String(value ?? '').trim().toLowerCase()
  if (!domain || domain.length > 253 || domain.startsWith('.') || domain.includes('*')) return undefined
  if (!domain.split('.').every((label) =>
    /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/i.test(label),
  )) return undefined
  return domain
}

function parseIPv4(value) {
  const parts = String(value).split('.')
  if (parts.length !== 4) return undefined
  let result = 0n
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined
    const octet = Number(part)
    if (octet > 255) return undefined
    result = (result << 8n) | BigInt(octet)
  }
  return result
}

function parseIPv6(value) {
  let text = String(value).toLowerCase()
  // Embedded IPv4 (::ffff:1.2.3.4) becomes two hexadecimal groups.
  if (text.includes('.')) {
    const colon = text.lastIndexOf(':')
    if (colon < 0) return undefined
    const v4 = parseIPv4(text.slice(colon + 1))
    if (v4 === undefined) return undefined
    text = `${text.slice(0, colon + 1)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`
  }
  const halves = text.split('::')
  if (halves.length > 2) return undefined
  const left = halves[0] ? halves[0].split(':') : []
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const missing = 8 - left.length - right.length
  if (halves.length === 1) {
    if (left.length !== 8) return undefined
  } else if (missing < 1) {
    return undefined
  }
  const groups = halves.length === 2
    ? [...left, ...Array(missing).fill('0'), ...right]
    : left
  let result = 0n
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return undefined
    result = (result << 16n) | BigInt(parseInt(group, 16))
  }
  return result
}

function parsePrefix(value) {
  const text = String(value ?? '').trim()
  const slash = text.lastIndexOf('/')
  if (slash <= 0) return undefined
  const address = text.slice(0, slash)
  const prefixLength = Number(text.slice(slash + 1))
  const ipv4 = !address.includes(':')
  const bits = ipv4 ? 32 : 128
  if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > bits) return undefined
  const startAddress = ipv4 ? parseIPv4(address) : parseIPv6(address)
  if (startAddress === undefined) return undefined
  const hostBits = BigInt(bits - prefixLength)
  const full = (1n << BigInt(bits)) - 1n
  const start = startAddress & (full ^ ((1n << hostBits) - 1n))
  return { bits, start, end: start | ((1n << hostBits) - 1n) }
}

/** 合并重叠和相邻的网段；mihomo / sing-box 解码后都会按这个方式归一化。 */
function mergeRanges(prefixes) {
  const groups = { 32: [], 128: [] }
  for (const prefix of prefixes) groups[prefix.bits].push(prefix)
  for (const list of Object.values(groups)) {
    list.sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0)
  }
  const merged = []
  for (const bits of [32, 128]) {
    const out = []
    for (const range of groups[bits]) {
      const last = out[out.length - 1]
      if (last && range.start <= last.end + 1n) {
        if (range.end > last.end) last.end = range.end
      } else {
        out.push({ bits, start: range.start, end: range.end })
      }
    }
    merged.push(...out)
  }
  return merged
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'))
}

/** 按码点反转域名，与 mihomo / sing-box 的 reverseDomain 一致。 */
function reverseKey(value) {
  return [...value].reverse().join('')
}

function setBit(words, index, bit) {
  const word = index >> 6
  while (word >= words.length) words.push(0n)
  words[word] |= BigInt(bit) << BigInt(index & 63)
}

/**
 * BFS 构造 succinct set：labels 按层排列，labelBitmap 在每个节点的子边之后
 * 写一个 1，leaves 标记终止节点。mihomo MRS 与 sing-box domain matcher 共用。
 */
function buildSuccinctSet(keys) {
  const sorted = [...new Set(keys)].sort(compareUtf8)
  if (!sorted.length) throw new BinaryRuleSetError('没有可编码的域名')
  const bytes = sorted.map((key) => Buffer.from(key, 'utf8'))
  const leaves = []
  const labelBitmap = []
  const labels = []
  let labelIndex = 0
  let nodeId = 0
  let queue = [{ start: 0, end: bytes.length }]
  let next = []
  for (let column = 0; queue.length > 0; column += 1) {
    for (const element of queue) {
      if (column === bytes[element.start].length) {
        element.start += 1
        setBit(leaves, nodeId, 1)
      }
      let index = element.start
      while (index < element.end) {
        const first = index
        while (index < element.end && bytes[index][column] === bytes[first][column]) index += 1
        next.push({ start: first, end: index })
        labels.push(bytes[first][column])
        setBit(labelBitmap, labelIndex, 0)
        labelIndex += 1
      }
      setBit(labelBitmap, labelIndex, 1)
      labelIndex += 1
      nodeId += 1
    }
    queue = next
    next = []
  }
  return { leaves, labelBitmap, labels }
}

function writeUint64(value) {
  const buffer = Buffer.alloc(8)
  buffer.writeBigUInt64BE(BigInt(value))
  return buffer
}

function writeInt64(value) {
  const buffer = Buffer.alloc(8)
  buffer.writeBigInt64BE(BigInt(value))
  return buffer
}

function writeUvarint(value) {
  const bytes = []
  let current = BigInt(value)
  while (current >= 128n) {
    bytes.push(Number((current & 127n) | 128n))
    current >>= 7n
  }
  bytes.push(Number(current))
  return Buffer.from(bytes)
}

/** mihomo DomainSet.WriteBin。 */
function writeDomainSet(set) {
  const parts = [Buffer.from([1]), writeInt64(set.leaves.length)]
  for (const word of set.leaves) parts.push(writeUint64(word))
  parts.push(writeInt64(set.labelBitmap.length))
  for (const word of set.labelBitmap) parts.push(writeUint64(word))
  parts.push(writeInt64(set.labels.length), Buffer.from(set.labels))
  return Buffer.concat(parts)
}

/** sing-box succinctSet.Write：uvarint 长度 + 大端 uint64 数组。 */
function writeSingBoxSet(set) {
  const uint64s = (values) => Buffer.concat([
    writeUvarint(values.length),
    ...values.map(writeUint64),
  ])
  return Buffer.concat([
    Buffer.from([0]),
    uint64s(set.leaves),
    uint64s(set.labelBitmap),
    writeUvarint(set.labels.length),
    Buffer.from(set.labels),
  ])
}

function ipv4Bytes(value) {
  const buffer = Buffer.alloc(4)
  buffer.writeUInt32BE(Number(value & 0xffffffffn))
  return buffer
}

/** mihomo 用 As16 写入，IPv4 变成 ::ffff:a.b.c.d。 */
function ipv4MappedBytes(value) {
  const buffer = Buffer.alloc(16)
  buffer[10] = 0xff
  buffer[11] = 0xff
  buffer.writeUInt32BE(Number(value & 0xffffffffn), 12)
  return buffer
}

function ipv6Bytes(value) {
  const buffer = Buffer.alloc(16)
  let current = value
  for (let index = 15; index >= 0; index -= 1) {
    buffer[index] = Number(current & 255n)
    current >>= 8n
  }
  return buffer
}

/** mihomo IpCidrSet.WriteBin。 */
function writeMihomoCIDR(ranges) {
  const parts = [Buffer.from([1]), writeInt64(ranges.length)]
  for (const range of ranges) {
    if (range.bits === 32) {
      parts.push(ipv4MappedBytes(range.start), ipv4MappedBytes(range.end))
    } else {
      parts.push(ipv6Bytes(range.start), ipv6Bytes(range.end))
    }
  }
  return Buffer.concat(parts)
}

/** sing-box writeIPSet：IPv4 写 4 字节，IPv6 写 16 字节。 */
function writeSingBoxCIDR(ranges) {
  const parts = [
    Buffer.from([1]),
    writeUint64(ranges.length),
  ]
  for (const range of ranges) {
    if (range.bits === 32) {
      const start = ipv4Bytes(range.start)
      const end = ipv4Bytes(range.end)
      parts.push(writeUvarint(4), start, writeUvarint(4), end)
    } else {
      const start = ipv6Bytes(range.start)
      const end = ipv6Bytes(range.end)
      parts.push(writeUvarint(16), start, writeUvarint(16), end)
    }
  }
  return Buffer.concat(parts)
}

/** 无 zstd 的 Node 20 也能生成合法帧：仅使用 raw block，不压缩。 */
function zstdStoreFrame(input) {
  const parts = [Buffer.from([0x28, 0xb5, 0x2f, 0xfd]), Buffer.from([0xa0])]
  const size = Buffer.alloc(4)
  size.writeUInt32LE(input.length)
  parts.push(size)
  if (input.length === 0) {
    parts.push(Buffer.from([1, 0, 0]))
    return Buffer.concat(parts)
  }
  for (let offset = 0; offset < input.length; offset += MAX_ZSTD_BLOCK) {
    const chunk = input.subarray(offset, Math.min(offset + MAX_ZSTD_BLOCK, input.length))
    const last = offset + chunk.length >= input.length
    const value = (last ? 1 : 0) | (chunk.length << 3)
    parts.push(Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff]), chunk)
  }
  return Buffer.concat(parts)
}

function compressZstd(input) {
  return typeof zstdCompressSync === 'function' ? zstdCompressSync(input) : zstdStoreFrame(input)
}

function normalizedRules(rules, types) {
  return rules
    .map((rule) => ({
      type: String(rule.type ?? '').toUpperCase(),
      value: String(rule.value ?? '').trim(),
      options: Array.isArray(rule.options) ? rule.options : [],
    }))
    .filter((rule) => types.has(rule.type))
}

function noResolveOptions(options) {
  return options.every((option) => String(option).toLowerCase() === 'no-resolve')
}

/**
 * 生成 MRS。domain 只收 DOMAIN / DOMAIN-SUFFIX；ipcidr 只收 IP-CIDR / IP-CIDR6。
 * 无法编码的行由调用方保持逐条内联，不在这里报错。
 */
export function encodeMihomoRuleSet(rules, behavior) {
  if (behavior === 'domain') {
    const keys = []
    let count = 0
    for (const rule of normalizedRules(rules, DOMAIN_TYPES)) {
      const domain = plainDomain(rule.value)
      if (!domain || !noResolveOptions(rule.options)) continue
      count += 1
      keys.push(reverseKey(domain))
      if (rule.type === 'DOMAIN-SUFFIX') keys.push(reverseKey(`+.${domain}`))
    }
    if (!keys.length) throw new BinaryRuleSetError('没有可编码为 MRS domain 的规则')
    const payload = Buffer.concat([
      Buffer.from([0x4d, 0x52, 0x53, 0x01]), // MRSv1
      Buffer.from([0]),
      writeInt64(count),
      writeInt64(0),
      writeDomainSet(buildSuccinctSet(keys)),
    ])
    return { body: compressZstd(payload), ruleCount: count }
  }

  if (behavior === 'ipcidr') {
    const prefixes = []
    let count = 0
    for (const rule of normalizedRules(rules, IP_TYPES)) {
      const prefix = parsePrefix(rule.value)
      if (!prefix || !noResolveOptions(rule.options)) continue
      count += 1
      prefixes.push(prefix)
    }
    if (!prefixes.length) throw new BinaryRuleSetError('没有可编码为 MRS ipcidr 的规则')
    const ranges = mergeRanges(prefixes)
    const payload = Buffer.concat([
      Buffer.from([0x4d, 0x52, 0x53, 0x01]),
      Buffer.from([1]),
      writeInt64(count),
      writeInt64(0),
      writeMihomoCIDR(ranges),
    ])
    return { body: compressZstd(payload), ruleCount: count }
  }

  throw new BinaryRuleSetError('MRS behavior 必须是 domain 或 ipcidr')
}

/** 生成 SRS v2；域名 / 关键字 / 正则 / IP 放进同一条 headless 规则（OR 语义）。 */
export function encodeSingBoxRuleSet(rules) {
  const domains = []
  const suffixes = []
  const keywords = []
  const regexes = []
  const prefixes = []
  let count = 0
  for (const rule of rules) {
    const type = String(rule.type ?? '').toUpperCase()
    const value = String(rule.value ?? '').trim()
    if (!value) continue
    const options = Array.isArray(rule.options) ? rule.options : []
    if (DOMAIN_TYPES.has(type)) {
      const domain = plainDomain(value)
      if (!domain || !noResolveOptions(options)) continue
      if (type === 'DOMAIN') domains.push(domain)
      else suffixes.push(domain)
      count += 1
    } else if (SRS_STRING_TYPES.has(type)) {
      if (options.length) continue
      if (type === 'DOMAIN-KEYWORD') keywords.push(value.toLowerCase())
      else regexes.push(value)
      count += 1
    } else if (IP_TYPES.has(type)) {
      const prefix = parsePrefix(value)
      if (!prefix || !noResolveOptions(options)) continue
      prefixes.push(prefix)
      count += 1
    }
  }
  if (!count) throw new BinaryRuleSetError('没有可编码为 SRS 的规则')

  const items = [Buffer.from([0])] // default rule
  if (domains.length || suffixes.length) {
    items.push(Buffer.from([2]))
    const keys = [
      ...domains.map(reverseKey),
      ...suffixes.map((domain) => reverseKey(`\n${domain}`)),
    ]
    items.push(writeSingBoxSet(buildSuccinctSet(keys)))
  }
  for (const [itemType, values] of [[3, keywords], [4, regexes]]) {
    if (!values.length) continue
    items.push(Buffer.from([itemType]), writeUvarint(values.length))
    for (const value of values) {
      const bytes = Buffer.from(value, 'utf8')
      items.push(writeUvarint(bytes.length), bytes)
    }
  }
  if (prefixes.length) {
    items.push(Buffer.from([6]), writeSingBoxCIDR(mergeRanges(prefixes)))
  }
  items.push(Buffer.from([0xff, 0])) // final item + invert=false
  const plain = Buffer.concat([writeUvarint(1), ...items])
  return {
    body: Buffer.concat([
      Buffer.from([0x53, 0x52, 0x53]), // SRS
      Buffer.from([2]),
      deflateSync(plain, { level: constants.Z_BEST_COMPRESSION }),
    ]),
    ruleCount: count,
  }
}
