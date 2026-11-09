// 自检：规则集方言转换与塔台托管产物 URL。
// 用法：npm run selfcheck:rulesets
import assert from 'node:assert/strict'
import { inflateSync, zstdDecompressSync } from 'node:zlib'
import { fileURLToPath } from 'node:url'
// @ts-expect-error server converter is plain ESM and not part of the src tsconfig
import { convertRuleSet, RuleSetConversionError } from '../server/ruleset-convert.mjs'
// @ts-expect-error server module is plain ESM and not part of the src tsconfig
import { cidrsForRange, countryCIDRs, loadIPCountryData } from '../server/ip-country.mjs'
import type { RoutingRule, SchemeRuleSet } from '../src/models/types'
import { mihomoBinaryPlan, singBoxBinaryPlan } from '../src/rules/binaryRuleSets'
import {
  hostedRuleSetURL,
  ruleSetRulesFitDialect,
} from '../src/rules/remoteFormats'
import {
  describeRuleSetParse,
  detectRuleSetFormat,
  parseRuleSetText,
  RULE_SET_FORMAT_TITLES,
} from '../src/rules/ruleSets'
import { normalizeRemoteTextURL, remoteRuleSetNameFromURL, splitRemoteTextURLs } from '../src/util/remoteURL'
import { diffRules, diffTotal } from '../src/rules/ruleDiff'
import { ruleSetRefreshFailure, ruleSetRefreshSuccess, sumRuleSetDiffs, summarizeRuleSetRefresh } from '../src/rules/ruleSetRefresh'
import {
  clearRuleSetHistory,
  digestRules,
  historySetIDs,
  previousRuleSetSnapshot,
  readRuleSetHistory,
  recordRuleSetSnapshot,
} from '../src/rules/ruleSetHistory'

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

const AT = 1_700_000_000_000

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

  check('托管转换：provider domain 严格校验域名 label', () => {
    const convertDomain = (value: string) =>
      convertRuleSet(`payload:\n  - "${value}"\n`, 'classic', { provider: 'yaml', behavior: 'domain' })
    // 允许 *. / +. / . 前缀；剥掉后必须仍然是合法域名。
    for (const value of ['+.example.com', '*.example.com', '.example.com', 'example.com', 'foo-bar.com']) {
      assert.doesNotThrow(() => convertDomain(value), value)
    }
    // *、_ 与首尾连字符都不是合法 DNS label；无法识别时 fail-closed 返回 422。
    for (const value of ['*example.com', 'foo_bar.com', '-bad.com', 'bad-.com', 'bad..com']) {
      assert.throws(
        () => convertDomain(value),
        (error) => error instanceof RuleSetConversionError && error.status === 422,
        value,
      )
    }
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

  check('在线规则集：多地址输入拆分、去重与命名', () => {
    const blizzard = 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Blizzard/Blizzard.yaml'
    const game = 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Game/Game.yaml'
    // 换行 / 空格 / 逗号混排都能识别，重复地址只保留一次。
    const mixed = splitRemoteTextURLs(`${blizzard}\n${game}  ${blizzard}，https://example.com/ads.list;`)
    assert.deepEqual(mixed, [blizzard, game, 'https://example.com/ads.list'])
    // GitHub 网页地址会归一成 raw 地址，并按归一后的地址去重。
    assert.deepEqual(
      splitRemoteTextURLs([
        'https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Clash/Game/Game.yaml',
        blizzard,
        'https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Clash/Game/Game.yaml',
      ].join(' ')),
      ['https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Game/Game.yaml', blizzard],
    )
    // 非地址文本（例如粘贴时夹带的说明）直接忽略，不会拼成非法 URL 去请求。
    assert.deepEqual(splitRemoteTextURLs('规则集在这里：见下方，暂无'), [])
    assert.deepEqual(splitRemoteTextURLs('https://rules.example/a.list https://rules.example/b.yaml').length, 2)
    assert.equal(remoteRuleSetNameFromURL(blizzard), 'Blizzard')
    assert.equal(remoteRuleSetNameFromURL('https://rules.example/a.yaml?token=1'), 'a')
    assert.equal(remoteRuleSetNameFromURL('https://rules.example/'), 'rules.example')
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

  check('规则集 diff：顺序变化不产生噪音', () => {
    const before = [rule('DOMAIN', 'b.example'), rule('DOMAIN', 'a.example'), rule('DOMAIN-SUFFIX', 'example.com')]
    const after = [rule('DOMAIN-SUFFIX', 'example.com'), rule('DOMAIN', 'a.example'), rule('DOMAIN', 'b.example')]
    const result = diffRules(before, after)
    assert.equal(diffTotal(result), 0)
    assert.equal(result.unchanged, 3)
  })

  check('规则集 diff：新增 / 删除 / 修改分类正确', () => {
    const before = [rule('DOMAIN', 'old.example'), rule('DOMAIN', 'same.example')]
    const after = [rule('DOMAIN', 'new.example'), rule('DOMAIN', 'same.example'), rule('DOMAIN-SUFFIX', 'old.example')]
    const result = diffRules(before, after)
    assert.deepEqual(result.added.map((line) => line.text), ['DOMAIN,new.example'])
    assert.equal(result.removed.length, 0)
    assert.equal(result.modified.length, 1)
    assert.equal(result.modified[0].before?.type, 'DOMAIN')
    assert.equal(result.modified[0].after?.type, 'DOMAIN-SUFFIX')
    assert.equal(result.unchanged, 1)
  })

  check('规则集 diff：重复条目去重且结果稳定', () => {
    const before = [rule('DOMAIN', 'dup.example'), rule('DOMAIN', 'dup.example'), rule('DOMAIN', 'a.example')]
    const after = [rule('DOMAIN', 'a.example'), rule('DOMAIN', 'dup.example')]
    assert.equal(diffTotal(diffRules(before, after)), 0)
    assert.equal(diffRules(before, after).unchanged, 2)
    const first = diffRules(before, after)
    const second = diffRules([...before].reverse(), [...after].reverse())
    assert.deepEqual(first, second)
  })

  check('规则集 diff：正则大小写变化不再被当作未变化', () => {
    const result = diffRules([rule('DOMAIN-REGEX', '^Example')], [rule('DOMAIN-REGEX', '^example')])
    assert.equal(result.added.length, 1)
    assert.equal(result.removed.length, 1)
    assert.equal(result.unchanged, 0)
    assert.equal(result.added[0].after?.value, '^example')
  })

  check('规则集摘要与顺序无关', () => {
    const rules = [rule('DOMAIN', 'b.example'), rule('DOMAIN', 'a.example'), rule('DOMAIN-SUFFIX', 'example.com')]
    assert.equal(digestRules(rules), digestRules([...rules].reverse()))
  })

  check('在线规则集刷新摘要：无变化时三个数都是 0（按归一化口径）', () => {
    const before = [
      rule('DOMAIN-SUFFIX', 'Example.COM'),
      rule('IP-CIDR', '1.2.3.0/24', { noResolve: true }),
    ]
    const after = [
      rule('IP-CIDR', '1.2.3.0/24', { options: ['no-resolve'] }),
      rule('DOMAIN-SUFFIX', '.example.com.'),
    ]
    const diff = summarizeRuleSetRefresh(before, after, AT)
    assert.deepEqual({ added: diff.added, removed: diff.removed, modified: diff.modified }, { added: 0, removed: 0, modified: 0 })
    assert.deepEqual(diff.samples, [])
    assert.equal(diff.hidden, 0)
    assert.equal(diff.checkedAt, AT)
  })

  check('在线规则集刷新摘要：只有新增 / 只有删除 / 只有修改', () => {
    const base = [rule('DOMAIN', 'a.example'), rule('DOMAIN', 'b.example')]
    const added = summarizeRuleSetRefresh(base, [...base, rule('DOMAIN', 'c.example')], AT)
    assert.deepEqual({ added: added.added, removed: added.removed, modified: added.modified }, { added: 1, removed: 0, modified: 0 })
    assert.equal(added.samples[0]?.kind, 'added')
    assert.equal(added.samples[0]?.text, 'DOMAIN,c.example')

    const removed = summarizeRuleSetRefresh(base, [rule('DOMAIN', 'a.example')], AT)
    assert.deepEqual({ added: removed.added, removed: removed.removed, modified: removed.modified }, { added: 0, removed: 1, modified: 0 })
    assert.equal(removed.samples[0]?.kind, 'removed')

    // 同值同选项但大小写不同算未变化；类型变化才算修改，并保留修改前的值。
    const unchanged = summarizeRuleSetRefresh([rule('DOMAIN', 'Case.Example')], [rule('DOMAIN', 'case.example')], AT)
    assert.equal(unchanged.modified, 0)
    const modified = summarizeRuleSetRefresh([rule('DOMAIN', 'x.example')], [rule('DOMAIN-SUFFIX', 'x.example')], AT)
    assert.deepEqual({ added: modified.added, removed: modified.removed, modified: modified.modified }, { added: 0, removed: 0, modified: 1 })
    assert.equal(modified.samples[0]?.kind, 'modified')
    assert.equal(modified.samples[0]?.previous, 'DOMAIN,x.example')
    assert.equal(modified.samples[0]?.text, 'DOMAIN-SUFFIX,x.example')
  })

  check('在线规则集刷新摘要：超过上限折叠，刷新全部可汇总', () => {
    const many = Array.from({ length: 20 }, (_, index) => rule('DOMAIN', `d${index}.example`))
    const one = summarizeRuleSetRefresh([], many, AT)
    assert.equal(one.added, 20)
    assert.equal(one.samples.length, 12)
    assert.equal(one.hidden, 8)
    const totals = sumRuleSetDiffs([
      one,
      summarizeRuleSetRefresh([rule('DOMAIN', 'gone.example')], [], AT),
      undefined,
    ])
    assert.deepEqual(totals, { added: 20, removed: 1, modified: 0 })
  })

  check('在线规则集刷新：成功清错误并记录摘要，失败保留旧摘要', () => {
    const oldSummary = summarizeRuleSetRefresh([rule('DOMAIN', 'a.example')], [rule('DOMAIN', 'a.example'), rule('DOMAIN', 'b.example')], AT - 1000)
    const existing = {
      id: 'set-1',
      name: '示例',
      rules: [rule('DOMAIN', 'a.example')],
      updatedAt: AT - 1000,
      lastError: '旧错误',
      lastDiff: oldSummary,
    }
    const failed = ruleSetRefreshFailure(existing, 'HTTP 500')
    assert.equal(failed.lastError, 'HTTP 500')
    assert.deepEqual(failed.lastDiff, oldSummary)
    assert.deepEqual(failed.rules, existing.rules)

    const success = ruleSetRefreshSuccess(existing, [rule('DOMAIN', 'a.example'), rule('DOMAIN', 'b.example')], AT)
    assert.equal(success.lastError, undefined)
    assert.equal(success.updatedAt, AT)
    assert.equal(success.lastDiff?.added, 1)
    assert.equal(success.lastDiff?.checkedAt, AT)
  })

  check('规则集历史：特殊 setID 可保存、清理，损坏明细退化为摘要', () => {
    const data = new Map<string, string>()
    const fakeStorage = {
      getItem: (key: string) => data.get(key) ?? null,
      setItem: (key: string, value: string) => { data.set(key, value) },
      removeItem: (key: string) => { data.delete(key) },
      clear: () => { data.clear() },
      key: (index: number) => [...data.keys()][index] ?? null,
      get length() { return data.size },
    }
    const original = (globalThis as { window?: unknown }).window
    ;(globalThis as { window?: unknown }).window = { localStorage: fakeStorage }
    try {
      recordRuleSetSnapshot('__proto__', [rule('DOMAIN', 'a.example')])
      assert.equal(readRuleSetHistory()['__proto__']?.previous?.count, 1)
      assert.equal(previousRuleSetSnapshot('__proto__')?.digest, digestRules([rule('DOMAIN', 'a.example')]))
      assert.deepEqual(historySetIDs(), ['__proto__'])
      clearRuleSetHistory('__proto__')
      assert.equal(previousRuleSetSnapshot('__proto__'), undefined)

      recordRuleSetSnapshot('set-1', [rule('DOMAIN', 'a.example')])
      assert.equal(previousRuleSetSnapshot('set-1')?.count, 1)
      clearRuleSetHistory()
      assert.deepEqual(historySetIDs(), [])

      // 超过 5000 条时只保留摘要，不写明细。
      const huge = Array.from({ length: 5001 }, (_, index) => rule('DOMAIN', `d${index}.example`))
      recordRuleSetSnapshot('big', huge)
      assert.equal(previousRuleSetSnapshot('big')?.truncated, true)
      assert.equal(previousRuleSetSnapshot('big')?.rules, undefined)

      // 明细里混入损坏条目时丢弃整份明细，只保留摘要，diff 面板不会读到坏数据。
      fakeStorage.setItem('tower-web-ruleset-history-v1', JSON.stringify({
        bad: { previous: { at: 1, count: 1, digest: 'deadbeef', rules: [{ value: 'no-type' }] } },
      }))
      const broken = readRuleSetHistory().bad?.previous
      assert.equal(broken?.rules, undefined)
      assert.equal(broken?.truncated, true)
    } finally {
      ;(globalThis as { window?: unknown }).window = original
    }
  })

  check('规则集导入：纯域名列表统一导出 DOMAIN-SUFFIX', () => {
    const parsed = parseRuleSetText('\uFEFF +.Foo.COM\r\n.example.com\r\n  sub.domain.example  \r\n\'quoted.example\'\r\n')
    assert.equal(parsed.format, 'classical')
    assert.deepEqual(parsed.rules.map((rule) => `${rule.type},${rule.value}`), [
      'DOMAIN-SUFFIX,foo.com',
      'DOMAIN-SUFFIX,example.com',
      'DOMAIN-SUFFIX,sub.domain.example',
      'DOMAIN-SUFFIX,quoted.example',
    ])
    assert.equal(parsed.skippedLines, 0)
  })

  check('规则集导入：通配 / IP 行不写成非法 DOMAIN-SUFFIX', () => {
    const parsed = parseRuleSetText('*.foo.com\n1.2.3.4\nfoo*bar.com\n10.0.0.1\n')
    assert.deepEqual(parsed.rules.map((rule) => `${rule.type},${rule.value}`), [
      'DOMAIN-SUFFIX,foo.com',
      'IP-CIDR,1.2.3.4/32',
      'IP-CIDR,10.0.0.1/32',
    ])
    assert.equal(parsed.skippedLines, 1)
    assert.deepEqual(parsed.skippedSamples, ['foo*bar.com'])
  })

  check('规则集导入：真实 gfw 形态的 provider YAML', () => {
    const parsed = parseRuleSetText("payload:\n  - '+.000webhost.com'\n  - '+.0rz.tw'\n  - '+.zyxel.com'\n")
    assert.equal(parsed.format, 'yaml')
    assert.deepEqual(parsed.rules.map((rule) => `${rule.type},${rule.value}`), [
      'DOMAIN-SUFFIX,000webhost.com',
      'DOMAIN-SUFFIX,0rz.tw',
      'DOMAIN-SUFFIX,zyxel.com',
    ])
    assert.equal(parsed.skippedLines, 0)
  })

  check('规则集导入：单行坏行跳过并汇总，不中断整批', () => {
    const parsed = parseRuleSetText('+.good.example\n???\n+.also-good.example\n')
    assert.equal(parsed.rules.length, 2)
    assert.equal(parsed.skippedLines, 1)
    assert.deepEqual(parsed.skippedSamples, ['???'])
    assert.match(describeRuleSetParse(parsed), /识别为「Clash 经典列表」，跳过 1 行/)
  })

  check('规则集导入：全部不可识别时报错且含格式 / 跳过 / 建议三段', () => {
    assert.throws(
      () => parseRuleSetText('<<<bad>>>\n???'),
      (error: unknown) => {
        const message = error instanceof Error ? error.message : String(error)
        assert.match(message, /识别为/)
        assert.match(message, /跳过 2 行/)
        assert.match(message, /建议/)
        return true
      },
    )
  })

  check('规则集导入：HTML 错误页不当作规则', () => {
    assert.throws(
      () => parseRuleSetText('<!DOCTYPE html><html><body><h1>404</h1></body></html>'),
      /HTML/,
    )
  })

  check('规则集导入：可同时解释为 text / YAML 时优先 text', () => {
    const parsed = parseRuleSetText('- foo.example\n- bar.example')
    assert.equal(parsed.format, 'classical')
    assert.deepEqual(parsed.rules.map((rule) => rule.type), ['DOMAIN-SUFFIX', 'DOMAIN-SUFFIX'])
    assert.equal(parsed.rules[0].value, 'foo.example')
    assert.equal(parsed.skippedLines, 0)
  })

  check('规则集导入：真 YAML 仍走 YAML，且大小写与空白归一', () => {
    assert.equal(detectRuleSetFormat('payload:\n  - DOMAIN,foo'), 'yaml')
    const parsed = parseRuleSetText('payload:\n  - "  +.Mixed.Case.EXAMPLE  "')
    assert.equal(parsed.format, 'yaml')
    assert.equal(parsed.rules[0].type, 'DOMAIN-SUFFIX')
    assert.equal(parsed.rules[0].value, 'mixed.case.example')
  })

  check('GEOIP：离线国家表可拆成 CIDR 并编码为 SRS', () => {
    assert.deepEqual(cidrsForRange(0n, 255n, 32), ['0.0.0.0/24'])
    assert.deepEqual(cidrsForRange(1n, 2n, 32), ['0.0.0.1/32', '0.0.0.2/32'])
    const data = loadIPCountryData(fileURLToPath(new URL('../server/ip-country', import.meta.url)))
    assert.ok(data, '离线国家表应随仓库提供')
    const cn = countryCIDRs(data, 'CN')
    assert.ok(cn.length > 1000, `CN CIDR 数量应足够多，实际 ${cn.length}`)
    assert.ok(cn.includes('1.0.1.0/24'))
    assert.deepEqual(countryCIDRs(data, 'ZZ'), [])
    const srs = convertRuleSet(
      cn.slice(0, 5).map((cidr: string) => `IP-CIDR,${cidr},no-resolve`).join('\n'),
      'srs',
    )
    assert.ok(Buffer.isBuffer(srs.text))
    assert.equal(srs.text.subarray(0, 4).toString('hex'), '53525302')
    assert.equal(srs.ruleCount, 5)
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部规则集转换检查通过')
}

main()
