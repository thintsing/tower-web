// 自检：规则集方言转换与塔台托管产物 URL。
// 用法：npm run selfcheck:rulesets
import assert from 'node:assert/strict'
import { inflateSync, zstdDecompressSync } from 'node:zlib'
// @ts-expect-error server converter is plain ESM and not part of the src tsconfig
import { convertRuleSet, RuleSetConversionError } from '../server/ruleset-convert.mjs'
import type { RoutingRule, SchemeRuleSet } from '../src/models/types'
import { mihomoBinaryPlan, singBoxBinaryPlan } from '../src/rules/binaryRuleSets'
import {
  hostedRuleSetURL,
  ruleSetRulesFitDialect,
} from '../src/rules/remoteFormats'
import {
  detectRuleSetFormat,
  parseRuleSetText,
  RULE_SET_FORMAT_TITLES,
} from '../src/rules/ruleSets'
import { normalizeRemoteTextURL } from '../src/util/remoteURL'

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

const DOMAIN_AND_IP = `
# 测试规则集
DOMAIN,example.com
DOMAIN-SUFFIX,foo.com
DOMAIN-KEYWORD,keyword
IP-CIDR,1.2.3.0/24,no-resolve
GEOIP,CN
`

const WITHOUT_GEOIP = `
DOMAIN,example.com
DOMAIN-SUFFIX,foo.com
DOMAIN-KEYWORD,keyword
IP-CIDR,1.2.3.0/24,no-resolve
`

const MIXED_NO_RESOLVE = `
IP-CIDR,1.2.3.0/24
IP-CIDR,2.2.2.0/24,no-resolve
`

const UNSUPPORTED = `
DOMAIN,example.com
PROCESS-NAME,curl
`

const rule = (type: string, value?: string, extra: Partial<RoutingRule> = {}): RoutingRule => ({
  type,
  value,
  group: '节点选择',
  ...extra,
})

/** 读取 MRS / SRS 的 succinct set，还原其中的域名模式，便于验证编码结果。 */
function decodeSuccinct(
  buffer: Buffer,
  start: number,
  lengths: 'int64' | 'uvarint',
): { version: number; keys: string[]; next: number } {
  let position = start
  const version = buffer[position++]
  const readLength = (): number => {
    if (lengths === 'int64') {
      const value = buffer.readBigInt64BE(position)
      position += 8
      return Number(value)
    }
    let value = 0
    let shift = 0
    for (;;) {
      const byte = buffer[position++]
      value |= (byte & 0x7f) << shift
      if (!(byte & 0x80)) return value
      shift += 7
    }
  }
  const readWords = () => {
    const count = readLength()
    const words: bigint[] = []
    for (let index = 0; index < count; index += 1) {
      words.push(buffer.readBigUInt64BE(position))
      position += 8
    }
    return words
  }
  const leaves = readWords()
  const labelBitmap = readWords()
  const labelCount = readLength()
  const labels = buffer.subarray(position, position + labelCount)
  position += labelCount

  const bit = (words: bigint[], index: number) =>
    Number((words[index >> 6] ?? 0n) >> BigInt(index & 63)) & 1
  const onesBefore = (words: bigint[], end: number) => {
    let total = 0
    for (let index = 0; index < end; index += 1) total += bit(words, index)
    return total
  }
  const countZeros = (words: bigint[], end: number) => end - onesBefore(words, end)
  const selectIthOne = (words: bigint[], target: number) => {
    let seen = 0
    for (let index = 0; index < words.length * 64; index += 1) {
      if (!bit(words, index)) continue
      if (seen === target) return index
      seen += 1
    }
    return words.length * 64
  }

  const keys: string[] = []
  const traverse = (nodeId: number, bitmapIndex: number, bytes: number[]) => {
    if (bit(leaves, nodeId)) {
      const key = Buffer.from(bytes).toString('utf8')
      keys.push([...key].reverse().join(''))
    }
    let cursor = bitmapIndex
    for (;;) {
      if (bit(labelBitmap, cursor)) return
      const label = labels[cursor - nodeId]
      const nextNodeId = countZeros(labelBitmap, cursor + 1)
      const nextBitmapIndex = selectIthOne(labelBitmap, nextNodeId - 1) + 1
      traverse(nextNodeId, nextBitmapIndex, [...bytes, label])
      cursor += 1
    }
  }
  traverse(0, 0, [])
  return { version, keys, next: position }
}

const makeSet = (overrides: Partial<SchemeRuleSet> = {}): SchemeRuleSet => ({
  id: 'set-1',
  name: '测试规则集',
  group: '节点选择',
  rules: [rule('DOMAIN-SUFFIX', 'ads.example')],
  sourceKind: 'library',
  sourceRef: 'ACL4SSR_BanAD.list',
  format: 'classical',
  ...overrides,
})

function main(): void {
  check('QuanX：输出 host / ip-cidr / geoip，丢弃 no-resolve', () => {
    const output = convertRuleSet(DOMAIN_AND_IP, 'quanx').text
    assert.match(output, /^host, example\.com, proxy$/m)
    assert.match(output, /host-suffix, foo\.com, proxy/)
    assert.match(output, /ip-cidr, 1\.2\.3\.0\/24, proxy/)
    assert.match(output, /geoip, CN, proxy/)
    assert.doesNotMatch(output, /no-resolve/)
  })

  check('Egern：统一 no_resolve 并生成集合键', () => {
    const output = convertRuleSet(DOMAIN_AND_IP, 'egern').text
    assert.match(output, /^no_resolve: true$/m)
    assert.match(output, /^domain_set:$/m)
    assert.match(output, /^domain_suffix_set:$/m)
    assert.match(output, /^ip_cidr_set:$/m)
    assert.match(output, /^geoip_set:$/m)
    assert.equal((output.match(/"example\.com"/g) ?? []).length, 1)
  })

  check('sing-box：生成 source format v2 JSON', () => {
    const output = convertRuleSet(WITHOUT_GEOIP, 'singbox').text
    const payload = JSON.parse(output)
    assert.equal(payload.version, 2)
    assert.equal(Array.isArray(payload.rules), true)
    assert.match(output, /"domain"/)
    assert.match(output, /"domain_suffix"/)
    assert.match(output, /"domain_keyword"/)
    assert.match(output, /"ip_cidr"/)
  })

  check('MRS domain：编码可解码回域名模式', () => {
    const output = convertRuleSet(DOMAIN_AND_IP, 'mrs', { behavior: 'domain' })
    assert.ok(Buffer.isBuffer(output.text))
    const raw = zstdDecompressSync(output.text)
    assert.equal(raw.subarray(0, 5).toString('hex'), '4d52530100')
    assert.equal(Number(raw.readBigInt64BE(5)), 2)
    assert.equal(Number(raw.readBigInt64BE(13)), 0)
    const set = decodeSuccinct(raw, 21, 'int64')
    assert.equal(set.version, 1)
    assert.deepEqual(
      set.keys.sort(),
      ['+.foo.com', 'example.com', 'foo.com'].sort(),
    )
  })

  check('MRS ipcidr：编码 IPv4 网段', () => {
    const output = convertRuleSet(DOMAIN_AND_IP, 'mrs', { behavior: 'ipcidr' })
    const raw = zstdDecompressSync(output.text)
    assert.equal(raw.subarray(0, 5).toString('hex'), '4d52530101')
    assert.equal(Number(raw.readBigInt64BE(5)), 1)
    const from = raw.subarray(30, 46)
    const to = raw.subarray(46, 62)
    assert.equal(from.subarray(0, 10).toString('hex'), '00000000000000000000')
    assert.equal(from.subarray(10, 16).toString('hex'), 'ffff01020300')
    assert.equal(to.subarray(10, 16).toString('hex'), 'ffff010203ff')
  })

  check('SRS domain：DNS 专用列表只编码域名与关键词', () => {
    const output = convertRuleSet(DOMAIN_AND_IP, 'srs-domain')
    assert.ok(Buffer.isBuffer(output.text))
    assert.equal(output.text.subarray(0, 4).toString('hex'), '53525302')
    assert.equal(output.ruleCount, 3)
    const plain = inflateSync(output.text.subarray(4))
    let position = 0
    const readUvarint = (): number => {
      let value = 0
      let shift = 0
      for (;;) {
        const byte = plain[position++]
        value |= (byte & 0x7f) << shift
        if (!(byte & 0x80)) return value
        shift += 7
      }
    }
    assert.equal(readUvarint(), 1)
    assert.equal(plain[position++], 0)
    assert.equal(plain[position++], 2)
    const matcher = decodeSuccinct(plain, position, 'uvarint')
    position = matcher.next
    assert.deepEqual(matcher.keys.sort(), ['\nfoo.com', 'example.com'].sort())
    assert.equal(plain[position++], 3)
    assert.equal(readUvarint(), 1)
    const keywordLength = readUvarint()
    assert.equal(plain.subarray(position, position + keywordLength).toString(), 'keyword')
    position += keywordLength
    assert.equal(plain[position++], 0xff)
    assert.equal(plain[position++], 0)
    assert.equal(position, plain.length)
  })

  check('SRS domain：没有域名规则时报错', () => {
    assert.throws(
      () => convertRuleSet('IP-CIDR,1.2.3.0/24\nPROCESS-NAME,curl', 'srs-domain'),
      /没有可编码/,
    )
  })
  check('SRS：生成 sing-box binary v2', () => {
    const output = convertRuleSet(WITHOUT_GEOIP, 'srs')
    assert.ok(Buffer.isBuffer(output.text))
    assert.equal(output.text.subarray(0, 4).toString('hex'), '53525302')
    const plain = inflateSync(output.text.subarray(4))
    let position = 0
    const readUvarint = (): number => {
      let value = 0
      let shift = 0
      for (;;) {
        const byte = plain[position++]
        value |= (byte & 0x7f) << shift
        if (!(byte & 0x80)) return value
        shift += 7
      }
    }
    assert.equal(readUvarint(), 1)
    assert.equal(plain[position++], 0)
    assert.equal(plain[position++], 2)
    const matcher = decodeSuccinct(plain, position, 'uvarint')
    position = matcher.next
    assert.deepEqual(matcher.keys.sort(), ['\nfoo.com', 'example.com'].sort())
    assert.equal(plain[position++], 3)
    assert.equal(readUvarint(), 1)
    const keywordLength = readUvarint()
    assert.equal(plain.subarray(position, position + keywordLength).toString(), 'keyword')
    position += keywordLength
    assert.equal(plain[position++], 6)
    assert.equal(plain[position++], 1)
    assert.equal(Number(plain.readBigUInt64BE(position)), 1)
    position += 8
    assert.equal(readUvarint(), 4)
    assert.equal(plain.readUInt32BE(position), 0x01020300)
    position += 4
    assert.equal(readUvarint(), 4)
    assert.equal(plain.readUInt32BE(position), 0x010203ff)
    position += 4
    assert.equal(plain[position++], 0xff)
    assert.equal(plain[position++], 0)
    assert.equal(position, plain.length)
  })

  check('二进制编码：缺少 behavior 或可编码规则时报错', () => {
    assert.throws(() => convertRuleSet(DOMAIN_AND_IP, 'mrs'), /behavior/)
    assert.throws(
      () => convertRuleSet('IP-CIDR,1.2.3.0/24', 'mrs', { behavior: 'domain' }),
      /没有可编码/,
    )
    assert.throws(
      () => convertRuleSet('PROCESS-NAME,curl', 'srs'),
      /没有可编码/,
    )
  })

  check('前端：MRS / SRS 二进制规划保留无法编码的规则', () => {
    const rules: RoutingRule[] = [
      rule('DOMAIN-SUFFIX', 'ads.example'),
      rule('DOMAIN-KEYWORD', 'adkw'),
      rule('IP-CIDR', '1.2.3.0/24', { options: ['no-resolve'], noResolve: true }),
      rule('GEOIP', 'CN'),
    ]
    const mrs = mihomoBinaryPlan(rules)
    assert.ok(mrs)
    assert.equal(mrs.domain.length, 1)
    assert.equal(mrs.ipcidr.length, 1)
    assert.equal(mrs.residual.length, 2)
    assert.equal(mrs.ipNoResolve, true)
    assert.equal(mihomoBinaryPlan([
      rule('IP-CIDR', '1.2.3.0/24'),
      rule('IP-CIDR', '2.2.2.0/24', { options: ['no-resolve'], noResolve: true }),
    ]), undefined)
    const srs = singBoxBinaryPlan(rules)
    assert.ok(srs)
    assert.equal(srs.covered.length, 3)
    assert.equal(srs.residual.length, 1)
  })

  check('无法无损转换时拒绝整份规则集', () => {
    for (const format of ['quanx', 'egern', 'singbox']) {
      assert.throws(
        () => convertRuleSet(UNSUPPORTED, format),
        (error) => error instanceof RuleSetConversionError,
        format,
      )
    }
    assert.throws(
      () => convertRuleSet(MIXED_NO_RESOLVE, 'egern'),
      /no-resolve/,
    )
  })

  check('前端：可转换类型与 no-resolve 约束', () => {
    const compatible = [
      rule('DOMAIN', 'example.com'),
      rule('DOMAIN-SUFFIX', 'foo.com'),
      rule('IP-CIDR', '1.2.3.0/24', { options: ['no-resolve'], noResolve: true }),
    ]
    for (const dialect of ['quanx', 'egern', 'singbox'] as const) {
      assert.equal(ruleSetRulesFitDialect(compatible, dialect), true, dialect)
    }
    assert.equal(ruleSetRulesFitDialect([rule('PROCESS-NAME', 'curl')], 'quanx'), false)
    assert.equal(ruleSetRulesFitDialect([rule('PROCESS-NAME', 'curl')], 'singbox'), false)
    assert.equal(ruleSetRulesFitDialect([
      rule('IP-CIDR', '1.2.3.0/24'),
      rule('IP-CIDR', '2.2.2.0/24', { options: ['no-resolve'], noResolve: true }),
    ], 'egern'), false)
  })

  check('规则集导入：经典列表 / provider YAML / QuanX / Egern / sing-box', () => {
    const classic = parseRuleSetText('DOMAIN-SUFFIX,ads.example\nIP-CIDR,1.2.3.0/24,no-resolve')
    assert.equal(classic.format, 'classical')
    assert.equal(classic.rules.length, 2)
    const provider = parseRuleSetText('payload:\n  - DOMAIN,foo.example\n  - DOMAIN-SUFFIX,bar.example')
    assert.equal(provider.format, 'yaml')
    assert.equal(provider.rules.length, 2)
    const quanx = parseRuleSetText('host, example.com, proxy\nhost-suffix, foo.com, proxy')
    assert.equal(quanx.format, 'quanx')
    assert.equal(quanx.rules[0].type, 'DOMAIN')
    assert.equal(quanx.rules[1].type, 'DOMAIN-SUFFIX')
    const egern = parseRuleSetText([
      'no_resolve: true',
      'domain_set:',
      '  - example.com',
      'ip_cidr_set:',
      '  - 1.2.3.0/24',
    ].join('\n'))
    assert.equal(egern.format, 'egern')
    assert.equal(egern.rules[1].noResolve, true)
    const singbox = parseRuleSetText(JSON.stringify({
      version: 2,
      rules: [
        { domain_suffix: ['a.example'] },
        { domain: 'foo.example', ip_cidr: ['1.2.3.0/24'] },
      ],
    }))
    assert.equal(singbox.format, 'singbox')
    assert.equal(singbox.rules[0].type, 'DOMAIN-SUFFIX')
    // domain 与 ip_cidr 在 sing-box 里属于同一个 OR 组，拆成两条规则才等价。
    assert.equal(singbox.rules[1].type, 'DOMAIN')
    assert.equal(singbox.rules[1].value, 'foo.example')
    assert.equal(singbox.rules[2].type, 'IP-CIDR')
    assert.equal(singbox.rules[2].value, '1.2.3.0/24')
    assert.equal(singbox.rules.length, 3)
  })

  check('规则集导入：自动识别与 FINAL 拒绝', () => {
    assert.equal(detectRuleSetFormat('host, example.com, proxy'), 'quanx')
    assert.equal(detectRuleSetFormat('payload:\n  - DOMAIN,foo'), 'yaml')
    assert.equal(detectRuleSetFormat('domain_set:\n  - foo.com'), 'egern')
    assert.equal(detectRuleSetFormat(JSON.stringify({ version: 2, rules: [] })), 'singbox')
    assert.equal(RULE_SET_FORMAT_TITLES.quanx, 'Quantumult X filter')
    assert.throws(
      () => parseRuleSetText('DOMAIN,foo\nFINAL'),
      /FINAL/,
    )
    assert.throws(
      () => parseRuleSetText('not a rule set', 'singbox-binary'),
      /二进制/,
    )
  })

  check('GitHub / Gitee 网页地址转换为 raw 地址', () => {
    assert.equal(
      normalizeRemoteTextURL('https://github.com/acl4ssr/ACL4SSR/blob/master/Clash/ACL4SSR_Online.ini'),
      'https://raw.githubusercontent.com/acl4ssr/ACL4SSR/master/Clash/ACL4SSR_Online.ini',
    )
    assert.equal(
      normalizeRemoteTextURL('https://gitee.com/acl4ssr/ACL4SSR/blob/master/Clash/ACL4SSR_Online.ini'),
      'https://gitee.com/acl4ssr/ACL4SSR/raw/master/Clash/ACL4SSR_Online.ini',
    )
    assert.equal(
      normalizeRemoteTextURL('https://raw.githubusercontent.com/acl4ssr/ACL4SSR/master/Clash/ACL4SSR_Online.ini'),
      'https://raw.githubusercontent.com/acl4ssr/ACL4SSR/master/Clash/ACL4SSR_Online.ini',
    )
  })

  check('托管产物 URL：内置文件与在线地址', () => {
    const library = hostedRuleSetURL(makeSet(), 'quanx')
    assert.ok(library?.startsWith('/api/ruleset?') || library?.includes('/api/ruleset?'))
    assert.ok(library?.includes('format=quanx'))
    assert.ok(library?.includes('file=ACL4SSR_BanAD.list'))
    const remote = hostedRuleSetURL(makeSet({
      sourceKind: 'url',
      sourceRef: 'https://rules.example/ads.list?token=abc',
    }), 'egern')
    assert.match(remote ?? '', /\/api\/ruleset\?format=egern&url=https%3A%2F%2Frules\.example%2Fads\.list%3Ftoken%3Dabc/)
    const mrs = hostedRuleSetURL(makeSet({ sourceKind: 'url', sourceRef: 'https://rules.example/ads.list' }), 'mrs-domain')
    assert.match(mrs ?? '', /format=mrs/)
    assert.match(mrs ?? '', /behavior=domain/)
    const srs = hostedRuleSetURL(makeSet({ sourceKind: 'url', sourceRef: 'https://rules.example/ads.list' }), 'srs')
    assert.match(srs ?? '', /format=srs/)
    const srsDomain = hostedRuleSetURL(makeSet({ sourceKind: 'url', sourceRef: 'https://rules.example/ads.list' }), 'srs-domain')
    assert.match(srsDomain ?? '', /format=srs-domain/)
    const local = makeSet({ sourceKind: 'local', sourceRef: 'local-1' })
    assert.equal(hostedRuleSetURL(local, 'singbox'), undefined)
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部规则集转换检查通过')
}

main()
