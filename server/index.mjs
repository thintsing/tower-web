// Tower Web local companion server.
// - GET  /api/fetch?url=…[&ua=…][&doh=…]  subscription fetch proxy (solves CORS);
//                           custom per-subscription UA / DoH, content never leaves
//                           this machine.
// - POST /api/share         store generated config, returns a token.
// - GET  /api/s/:token      one-shot 3-minute temporary import link.
// - GET  /*                 serves dist/ in production mode.
import { createServer, request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect, isIP } from 'node:net'
import { execFile } from 'node:child_process'
import { lookup } from 'node:dns/promises'
import { networkInterfaces } from 'node:os'
import { readFile, rename, writeFile } from 'node:fs/promises'
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { join, dirname, extname, normalize, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { brotliDecompressSync, gunzipSync, inflateSync } from 'node:zlib'
import { convertRuleSet, RuleSetConversionError } from './ruleset-convert.mjs'
import { asnCIDRs, loadIPASNData, organizationForAddress } from './ip-asn.mjs'
import { countryCIDRs, loadIPCountryData } from './ip-country.mjs'
import { createUpstreamChecker } from './upstream-status.mjs'
import { BUILTIN_PROGRAMMATIC_SCHEMES, BUILTIN_SCHEME_COUNT, BUILTIN_SCHEME_FILES } from './builtin-scheme-counts.mjs'
import { WORKSPACE_MAX_BYTES } from './workspace-limits.mjs'

const rawPort = String(process.env.PORT ?? '').trim()
const parsedPort = rawPort ? Number(rawPort) : 8787
// 非法 PORT 直接传给 listen 会抛 ERR_SOCKET_BAD_PORT（没有可读提示），这里回退默认值。
const PORT = Number.isInteger(parsedPort) && parsedPort >= 0 && parsedPort <= 65535 ? parsedPort : 8787
if (rawPort && PORT !== parsedPort) {
  console.warn(`[tower] PORT=${rawPort} 无效（应为 0–65535 的整数），已改用 ${PORT}`)
}
// 默认监听所有网卡，手机 / 局域网其它机器才能打开订阅页与订阅链接。
// 只想本机使用时启动加 `HOST=127.0.0.1`。
const HOST = process.env.HOST || '0.0.0.0'
/**
 * Docker 容器内看到的网卡地址不是宿主机地址；服务器模式下它也作为固定订阅地址前缀。
 * 非法值不能静默丢掉，否则用户会以为已经配置成功、实际仍按访问地址生成。
 */
function parsePublicURL(value) {
  const original = String(value ?? '')
  if (!original) return { url: '', error: '' }
  // 环境变量里的首尾空格同样视为配置错误，避免“看起来配了、实际被截断后生效”。
  if (/[\s\x00-\x1f\x7f]/.test(original)) return { url: '', error: '不能包含空白或控制字符' }
  const raw = original
  let parsed
  try {
    parsed = new URL(raw)
  } catch {
    return { url: '', error: '必须是完整的 http:// 或 https:// 地址' }
  }
  if (!/^http:$/i.test(parsed.protocol) && !/^https:$/i.test(parsed.protocol)) {
    return { url: '', error: '只支持 http:// 或 https://' }
  }
  if (!parsed.hostname) return { url: '', error: '缺少主机名' }
  if (parsed.username || parsed.password) return { url: '', error: '不能包含用户名或密码' }
  if (parsed.search || parsed.hash) return { url: '', error: '不能包含查询参数或片段' }
  // 托管规则集要由手机 / 其他设备直接访问；回环地址只有本机可达，
  // 等于把不可达地址写进客户端配置，必须当作配置错误。
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  const loopback = host === 'localhost'
    || host.endsWith('.localhost')
    || (isIP(host) === 4 && (host.startsWith('127.') || host === '0.0.0.0'))
    || (isIP(host) === 6 && (host === '::1' || host === '::'))
  if (loopback) {
    return { url: '', error: '不能使用本机回环地址（localhost / 127.x / 0.0.0.0 / ::1）' }
  }
  return { url: raw.replace(/\/+$/, ''), error: '' }
}
const publicURLConfig = parsePublicURL(process.env.TOWER_PUBLIC_URL)
const PUBLIC_URL = publicURLConfig.url
const PUBLIC_URL_ERROR = publicURLConfig.error
if (PUBLIC_URL_ERROR) {
  console.error(`[tower] TOWER_PUBLIC_URL 无效：${PUBLIC_URL_ERROR}（已按未配置处理）`)
}
const distDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist')
const publicRulesetsDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'rulesets')
const distRulesetsDir = join(distDir, 'rulesets')

// 单次订阅响应的上限（解压后）。没有上限时一个超大响应就能把进程内存吃光。
const MAX_FETCH_BYTES = 32 * 1024 * 1024
const MAX_FETCH_LABEL = '32MB'
// 订阅抓取与规则集抓取共用同一个跳数上限：机场 / CDN 的正常重定向通常 1–2 跳，
// 5 跳足够；再多基本是循环或恶意链。
const MAX_REDIRECT_HOPS = 5

/** 虚拟网卡（VMware / VirtualBox / Hyper-V / Tailscale …）排在真实网卡之后。 */
const VIRTUAL_IFACE = /(vmware|virtualbox|vethernet|hyper-v|wsl|docker|tailscale|zerotier|loopback)/i

function lanUrls(port) {
  const found = []
  for (const [name, addrs] of Object.entries(networkInterfaces())) {
    for (const addr of addrs ?? []) {
      if (addr.family !== 'IPv4' || addr.internal) continue
      found.push({ score: VIRTUAL_IFACE.test(name) ? 0 : 1, url: `http://${addr.address}:${port}` })
    }
  }
  return found.sort((a, b) => b.score - a.score).map((x) => x.url)
}

/** token -> { body, contentType, expiresAt, used } */
const shares = new Map()
const SHARE_TTL_MS = 3 * 60 * 1000

/** token -> { formats, updatedAt, title } */
const subscriptions = new Map()

/** 转换后的规则集产物：key -> { body, contentType, ruleCount, updatedAt } */
const rulesetArtifacts = new Map()
const RULESET_CACHE_MS = 60 * 60 * 1000
const RULESET_CACHE_MAX = 128

function cachedRuleSet(key) {
  const hit = rulesetArtifacts.get(key)
  if (!hit) return undefined
  if (Date.now() - hit.updatedAt > RULESET_CACHE_MS) {
    rulesetArtifacts.delete(key)
    return undefined
  }
  return hit
}

function cacheRuleSet(key, artifact) {
  while (rulesetArtifacts.size >= RULESET_CACHE_MAX) {
    const oldest = rulesetArtifacts.keys().next().value
    if (!oldest) break
    rulesetArtifacts.delete(oldest)
  }
  rulesetArtifacts.set(key, { ...artifact, updatedAt: Date.now() })
}

/** asn 参数：返回规范化后的 AS 号；非法值带 error。缺省时 value 为 0。 */
function parseASN(raw) {
  const value = String(raw ?? '').trim()
  if (!value) return { value: 0 }
  if (!/^\d{1,10}$/.test(value)) return { value: 0, error: 'asn 需要十进制 AS 号，例如 13335' }
  const asn = Number(value)
  if (!Number.isSafeInteger(asn) || asn <= 0 || asn > 0xffffffff) {
    return { value: 0, error: 'asn 需要 1–4294967295 之间的 AS 号' }
  }
  return { value: asn }
}

/**
 * 查询侧与写入侧必须用同一个函数生成缓存键，否则 provider 这类新参数
 * 会让写入键与查询键不一致，缓存永远 miss。
 */
function ruleSetCacheKey(query) {
  const format = String(query.get('format') ?? '').toLowerCase()
  const behavior = String(query.get('behavior') ?? '').toLowerCase()
  const provider = String(query.get('provider') ?? '').toLowerCase()
  const file = query.get('file')
  const remote = query.get('url')
  const geoip = String(query.get('geoip') ?? '').trim().toUpperCase()
  const asn = parseASN(query.get('asn')).value
  if (!format) return ''
  if (!file && !remote && !geoip && !asn) return ''
  const source = geoip
    ? `geoip:${geoip}`
    : asn
      ? `asn:${asn}`
      : file
        ? `file:${file}`
        : `url:${remote}`
  return `${format}|${behavior}|${provider}|${source}`
}

/**
 * 云元数据 / 链路本地 / 组播 / 保留地址不可能是合法订阅或规则集来源。
 * `/api/ruleset` 与 `/api/fetch` 是免密钥端点（客户端要直接拉取），因此在这里
 * 共用同一套判断；局域网 NAS 等私网地址仍然允许。
 */
const BLOCKED_TARGET_MESSAGE = '地址不能指向链路本地、云元数据、组播或保留地址'
const BLOCKED_RULESET_HOSTS = new Set([
  '169.254.169.254',
  '100.100.100.200',
  'fd00:ec2::254',
  'metadata',
  'metadata.google.internal',
  'metadata.tencentyun.com',
])

function isBlockedRuleSetTarget(target) {
  const host = target.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  return BLOCKED_RULESET_HOSTS.has(host)
    || blockedRuleSetAddress(host)
    || host.endsWith('.metadata.google.internal')
}

/** 初始地址和每一跳跳转都走这里：命中直接抛错，调用方负责带上第几跳。 */
function assertAllowedTarget(target) {
  if (isBlockedRuleSetTarget(target)) throw new Error(BLOCKED_TARGET_MESSAGE)
}

/**
 * IPv4-mapped（::ffff:0:0/96）和 NAT64（64:ff9b::/96）都能携带任意 IPv4。
 * URL 会把点分形式规范化成十六进制（::ffff:a9fe:a9fe），只剥前缀再判 isIP
 * 会整条跳过 IPv4 分支，云元数据地址因此可达。这里统一还原成点分四段。
 */
function embeddedIPv4(ip) {
  const match = ip.match(/^(?:::ffff:|64:ff9b::)(.+)$/)
  if (!match) return undefined
  const tail = match[1]
  if (isIP(tail) === 4) return tail
  const hex = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/)
  if (!hex) return undefined
  const high = parseInt(hex[1], 16)
  const low = parseInt(hex[2], 16)
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`
}

/**
 * 解析结果也要校验：只按域名挡，A 记录指向 169.254.169.254 的域名仍能绕过。
 * 私网（10/8、172.16/12、192.168/16）与回环地址按原有设计放行，
 * 只拦截链路本地、云元数据、组播和保留地址。
 */
function blockedRuleSetAddress(address) {
  const ip = String(address).trim().toLowerCase()
  const v4 = isIP(ip) === 4 ? ip : embeddedIPv4(ip)
  if (v4) {
    const [first, second] = v4.split('.').map(Number)
    return (first === 169 && second === 254)   // 169.254.0.0/16 链路本地
      || v4 === '100.100.100.200'              // 阿里云元数据
      || first === 0                           // 0.0.0.0/8 本网络
      || first >= 224                          // 224.0.0.0/4 组播 + 240.0.0.0/4 保留（含广播）
  }
  return /^fe80:/.test(ip)                     // IPv6 链路本地
    || ip === '::'                             // IPv6 未指定地址
    || /^ff[0-9a-f]{2}:/.test(ip)              // IPv6 组播
    || /^fd00:ec2::/.test(ip)                  // AWS 元数据
}

/** 读取内置规则文件或抓取远程列表，再转换成目标客户端方言。 */
async function buildRuleSetArtifact(query) {
  const format = String(query.get('format') ?? '').toLowerCase()
  if (!['classic', 'quanx', 'egern', 'singbox', 'sing-box', 'mrs', 'srs', 'srs-domain'].includes(format)) {
    throw new RuleSetConversionError('format 必须是 classic / quanx / egern / singbox / mrs / srs / srs-domain')
  }
  const behavior = String(query.get('behavior') ?? '').toLowerCase()
  if (format === 'mrs' && behavior !== 'domain' && behavior !== 'ipcidr') {
    throw new RuleSetConversionError('MRS 需要 behavior=domain 或 behavior=ipcidr', 400)
  }
  // provider=yaml：源文件是 Clash provider 的 `payload:`，必须先按 behavior 解开。
  const provider = String(query.get('provider') ?? '').toLowerCase()
  if (provider && provider !== 'yaml') {
    throw new RuleSetConversionError('provider 只支持 yaml', 400)
  }
  if (provider && !['domain', 'ipcidr', 'classical'].includes(behavior)) {
    throw new RuleSetConversionError('provider YAML 需要 behavior=domain / ipcidr / classical', 400)
  }
  const file = query.get('file')
  const remote = query.get('url')
  // geoip=CN：从随包离线国家表生成 CIDR 列表，供 sing-box / Hiddify
  // 把 GEOIP 规则写成可下载的本地规则集（1.12 起内核不再接受 geoip 字段）。
  const geoipParam = String(query.get('geoip') ?? '').trim()
  const geoip = geoipParam.toUpperCase()
  if (geoip && !/^[A-Z]{2}$/.test(geoip)) {
    throw new RuleSetConversionError('geoip 需要两位国家或地区代码，例如 CN', 400)
  }
  // asn=13335：同样从随包离线 ASN 表生成 CIDR 列表，承接 IP-ASN 规则。
  const asnParam = parseASN(query.get('asn'))
  if (asnParam.error) throw new RuleSetConversionError(asnParam.error, 400)
  const asn = asnParam.value
  if ((geoip && (file || remote)) || (asn && (file || remote || geoip))) {
    throw new RuleSetConversionError('geoip / asn 与 file / url 只能四选一', 400)
  }
  if (!file && !remote && !geoip && !asn) {
    throw new RuleSetConversionError('缺少 file / url / geoip / asn 参数')
  }
  if (file && remote) throw new RuleSetConversionError('file 与 url 只能二选一')
  let sourceText
  if (geoip || asn) {
    if (format === 'srs-domain') {
      throw new RuleSetConversionError(`srs-domain 只接受域名规则，不支持 ${geoip ? 'geoip' : 'asn'}`, 400)
    }
    const cidrs = geoip ? geoipCidrs(geoip) : asnCidrs(asn)
    if (!cidrs.length) {
      // 离线表里没有该代码：SRS 仍返回一份零规则产物，让客户端配置里的远程
      // 规则集能正常下载（只是永不命中），而不是每天报一次 404。
      // 其他文本格式没有「空规则集」的合法表达，继续如实返回 404。
      if (format !== 'srs') {
        throw new RuleSetConversionError(
          geoip ? `离线国家表里没有 ${geoip} 的 IP 段` : `离线 ASN 表里没有 AS${asn} 的 IP 段`,
          404,
        )
      }
      console.warn(`[tower] 离线表里没有 ${geoip || `AS${asn}`} 的 IP 段，返回空规则集`)
    }
    sourceText = cidrs.map((cidr) => `IP-CIDR,${cidr},no-resolve`).join('\n')
  } else if (file) {
    const safeName = String(file)
    if (!/^[A-Za-z0-9_.-]+\.list$/.test(safeName) || safeName.includes('..')) {
      throw new RuleSetConversionError('规则集文件名无效', 400)
    }
    try {
      sourceText = await readFile(join(publicRulesetsDir, safeName), 'utf8')
    } catch {
      try {
        sourceText = await readFile(join(distRulesetsDir, safeName), 'utf8')
      } catch {
        throw new RuleSetConversionError('内置规则集不存在', 404)
      }
    }
  } else {
    let target
    try {
      target = new URL(String(remote))
    } catch {
      throw new RuleSetConversionError('规则集地址无效', 400)
    }
    if (target.protocol !== 'http:' && target.protocol !== 'https:') {
      throw new RuleSetConversionError('只支持 http/https 规则集地址', 400)
    }
    if (isBlockedRuleSetTarget(target)) {
      throw new RuleSetConversionError(`规则集地址被拦截：${BLOCKED_TARGET_MESSAGE}`, 400)
    }
    let response
    try {
      response = await fetchWithDoH(target, 'clash-verge/v2.4.2', undefined, false, assertAllowedTarget)
    } catch (error) {
      throw new RuleSetConversionError(`规则集抓取失败：${error.message}`, 502)
    }
    if (response.status < 200 || response.status >= 300) {
      throw new RuleSetConversionError(`规则集返回 HTTP ${response.status}`, 502)
    }
    if (response.body.length > 8 * 1024 * 1024) {
      throw new RuleSetConversionError('规则集内容过大', 422)
    }
    sourceText = response.body.toString('utf8')
  }
  const artifact = convertRuleSet(sourceText, format, {
    behavior,
    provider,
    // 美国等国家的离线表、大型运营商的 ASN 拆出来可超过 8MB；
    // 本地生成不受远程抓取的上限约束。
    maxSourceBytes: geoip || asn ? 64 * 1024 * 1024 : undefined,
    // geoip / asn 查不到时返回零规则 SRS，而不是让客户端反复下载 404。
    allowEmpty: geoip || asn ? true : undefined,
  })
  return {
    // 与缓存查询复用同一个键构造函数，避免两侧再次漂移。
    key: ruleSetCacheKey(query),
    body: artifact.text,
    contentType: artifact.contentType,
    ruleCount: artifact.ruleCount,
  }
}
// 订阅落盘，服务端重启后仍可用（本地文件，不出本机）。
// Docker 部署通过 TOWER_DATA_DIR 指向挂载卷；普通运行仍写 server/subscriptions.json。
// 容器内的网卡地址不是宿主机地址，TOWER_PUBLIC_URL 用于覆盖 /api/network 的局域网地址。
const DATA_DIR = process.env.TOWER_DATA_DIR || dirname(fileURLToPath(import.meta.url))
const SUBS_FILE = join(DATA_DIR, 'subscriptions.json')
const SETTINGS_FILE = join(DATA_DIR, 'settings.json')

// 服务器版：订阅源、节点、规则方案等整个工作区存在服务端 workspace.json，
// 任何设备打开都是同一份数据。默认 local，保持原有 localStorage 行为。
const SERVER_MODE = String(process.env.TOWER_MODE ?? '').trim().toLowerCase() === 'server'
const WORKSPACE_FILE = join(DATA_DIR, 'workspace.json')

// ---------- 工作区历史 ----------
// 每次覆盖前把即将被替换的版本存到这里。目录与工作区同级，Docker 挂载卷会一起持久化。
const HISTORY_DIR = join(DATA_DIR, 'history')
const HISTORY_MAX_ENTRIES = 10
const HISTORY_MAX_BYTES = 50 * 1024 * 1024
/** v<版本号>-<UTC 时间戳>，例如 v12-20261107T123456789Z。 */
const HISTORY_ID_RE = /^v\d+-\d{8}T\d{9}Z$/

function objectField(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function arrayField(value) {
  return Array.isArray(value) ? value : []
}

function schemeRuleCount(scheme) {
  const value = objectField(scheme)
  let count = arrayField(value.rules).length + arrayField(value.customRules).length
  for (const ruleSet of arrayField(value.ruleSets)) {
    count += arrayField(objectField(ruleSet).rules).length
  }
  return count
}

/**
 * 历史差异只用服务端已有的数据统计。内置方案的原厂规则在客户端代码里，
 * 但同样打包在 public/rulesets 下；服务端按同一份 INI + 列表文件统计，
 * 这样回滚确认里的规则数不会把「内置方案有 3529 条」误报成 0。
 * 文件清单与程序化方案计数在 builtin-scheme-counts.mjs，前端一致性由
 * selfcheck:provider-rulesets 断言。
 */
const builtinSchemeCountsCache = new Map()

function readRulesetFile(name) {
  try {
    return readFileSync(join(publicRulesetsDir, name), 'utf8')
  } catch {
    try {
      return readFileSync(join(distRulesetsDir, name), 'utf8')
    } catch {
      return ''
    }
  }
}

function countRuleListLines(text) {
  let count = 0
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#') || line === 'payload:') continue
    const body = line.startsWith('- ') ? line.slice(2).trim() : line
    // 列表里每行一条规则；排除 payload 头、空行和注释即可。
    if (/^[A-Za-z][A-Za-z0-9-]*(?:,|$)/.test(body)) count += 1
  }
  return count
}

/** 读取内置方案 INI 与它引用的本地列表，统计规则数 / 策略组数（进程内缓存）。 */
function builtinSchemeCounts(id) {
  const programmatic = BUILTIN_PROGRAMMATIC_SCHEMES[id]
  if (programmatic) return programmatic
  const file = BUILTIN_SCHEME_FILES[id]
  if (!file) return null
  const cached = builtinSchemeCountsCache.get(id)
  if (cached) return cached
  let index = {}
  try {
    index = JSON.parse(readRulesetFile('index.json'))
  } catch {
    index = {}
  }
  const ini = readRulesetFile(file)
  if (!ini) return null
  let rules = 0
  let groups = 0
  const fileCounts = new Map()
  for (const rawLine of ini.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith(';') || line.startsWith('#') || line.startsWith('[')) continue
    if (line.startsWith('ruleset=')) {
      const body = line.slice('ruleset='.length)
      const comma = body.indexOf(',')
      if (comma < 0) continue
      const target = body.slice(comma + 1).trim()
      if (target.startsWith('[]')) {
        rules += 1
        continue
      }
      const marker = target.indexOf('/Clash/')
      if (marker < 0) continue
      const localFile = index[target.slice(marker + 1)]
      if (!localFile) continue
      if (!fileCounts.has(localFile)) fileCounts.set(localFile, countRuleListLines(readRulesetFile(localFile)))
      rules += fileCounts.get(localFile)
      continue
    }
    if (line.startsWith('custom_proxy_group=')) groups += 1
  }
  const result = { rules, groups }
  builtinSchemeCountsCache.set(id, result)
  return result
}

function workspaceCounts(raw) {
  const data = objectField(raw)
  const customSchemes = arrayField(data.customSchemes)
  const selected = typeof data.selectedSchemeID === 'string' ? data.selectedSchemeID : ''
  const customScheme = customSchemes.find((scheme) => objectField(scheme).id === selected)
  let rules = 0
  let groups = 0
  if (customScheme) {
    rules = schemeRuleCount(customScheme)
    groups = arrayField(objectField(customScheme).groups).length
  } else {
    // 内置方案：优先使用固化快照的正文，否则按打包的 INI / 列表统计。
    const pointer = objectField(objectField(data.builtinSchemeOverrides)[selected])
    if (Number.isInteger(pointer.snapshotId)) {
      const snapshot = objectField(objectField(data.schemeSnapshots)[String(pointer.snapshotId)])
      const scheme = objectField(snapshot.scheme)
      if (Object.keys(scheme).length > 0) {
        rules = schemeRuleCount(scheme)
        groups = arrayField(scheme.groups).length
      }
    } else {
      const builtin = builtinSchemeCounts(selected)
      if (builtin) {
        rules = builtin.rules
        groups = builtin.groups
      }
    }
  }
  return {
    subscriptions: arrayField(data.sources).length,
    nodes: arrayField(data.nodes).length,
    rules,
    schemes: BUILTIN_SCHEME_COUNT + customSchemes.length,
    groups,
  }
}

function countDiff(before, after) {
  const diff = {}
  for (const key of ['rules', 'subscriptions', 'nodes', 'schemes', 'groups']) {
    diff[key] = { before: before[key], after: after[key] }
  }
  return diff
}

function normalizeCounts(value) {
  const raw = objectField(value)
  return {
    subscriptions: Number.isInteger(raw.subscriptions) ? raw.subscriptions : 0,
    nodes: Number.isInteger(raw.nodes) ? raw.nodes : 0,
    rules: Number.isInteger(raw.rules) ? raw.rules : 0,
    schemes: Number.isInteger(raw.schemes) ? raw.schemes : 0,
    groups: Number.isInteger(raw.groups) ? raw.groups : 0,
  }
}

function normalizeDiff(value) {
  if (!value || typeof value !== 'object') return null
  const diff = {}
  for (const key of ['rules', 'subscriptions', 'nodes', 'schemes', 'groups']) {
    const item = value[key]
    if (!item || !Number.isInteger(item.before) || !Number.isInteger(item.after)) return null
    diff[key] = { before: item.before, after: item.after }
  }
  return diff
}

function historyTimestamp(now = Date.now()) {
  const date = new Date(now)
  const pad = (value, width = 2) => String(value).padStart(width, '0')
  return `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}`
    + `T${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}${pad(date.getUTCMilliseconds(), 3)}Z`
}

function historyBodyPath(id) {
  return join(HISTORY_DIR, `${id}.json`)
}

function historyMetaPath(id) {
  return join(HISTORY_DIR, `${id}.meta.json`)
}

function historyIdVersion(id) {
  const match = /^v(\d+)-/.exec(id)
  return match ? Number(match[1]) : -1
}

/** 最多 10 个元数据文件，同步读取不会拖慢正常写入路径。 */
function listHistoryMetadata() {
  let names
  try {
    names = readdirSync(HISTORY_DIR)
  } catch {
    return []
  }
  const entries = []
  for (const name of names) {
    if (!name.endsWith('.json') || name.endsWith('.meta.json')) continue
    const id = name.slice(0, -'.json'.length)
    if (!HISTORY_ID_RE.test(id)) continue
    const entry = readHistoryMetadata(id)
    if (entry) entries.push(entry)
  }
  entries.sort((a, b) => b.version - a.version || b.archivedAt - a.archivedAt)
  return entries
}

function readHistoryMetadata(id) {
  let size
  try {
    size = statSync(historyBodyPath(id)).size
  } catch {
    return null
  }
  let meta = {}
  try {
    meta = JSON.parse(readFileSync(historyMetaPath(id), 'utf8'))
  } catch {
    // 元数据损坏或缺失时仍能列出正文；回滚所需的正文不受影响。
    meta = {}
  }
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) meta = {}
  return {
    id,
    version: Number.isInteger(meta.version) && meta.version >= 0 ? meta.version : historyIdVersion(id),
    updatedAt: Number(meta.updatedAt) || 0,
    archivedAt: Number(meta.archivedAt) || 0,
    bytes: Number.isInteger(meta.bytes) && meta.bytes >= 0 ? meta.bytes : size,
    trigger: meta.trigger === 'restore' ? 'restore' : 'write',
    source: {
      ip: typeof meta.source?.ip === 'string' ? meta.source.ip : '',
      ua: typeof meta.source?.ua === 'string' ? meta.source.ua : '',
    },
    counts: normalizeCounts(meta.counts),
    diff: normalizeDiff(meta.diff),
  }
}

function findHistoryByVersion(version) {
  try {
    const name = readdirSync(HISTORY_DIR).find((item) => item.startsWith(`v${version}-`)
      && item.endsWith('.json') && !item.endsWith('.meta.json'))
    if (!name) return null
    const id = name.slice(0, -'.json'.length)
    return { id, version, bytes: statSync(historyBodyPath(id)).size }
  } catch {
    return null
  }
}

/** 历史文件损坏 / 目录不可写只记日志，绝不阻断当前工作区写入。 */
async function archiveWorkspace(snapshot, afterData, source, trigger, restoredFrom) {
  if (!SERVER_MODE || snapshot.version <= 0) return null
  try {
    mkdirSync(HISTORY_DIR, { recursive: true })
    // 同版本只留一份：上一次写入失败后重试时不再重复归档。
    const existing = findHistoryByVersion(snapshot.version)
    if (existing) return existing
    const id = `v${snapshot.version}-${historyTimestamp()}`
    const body = JSON.stringify(snapshot)
    const bytes = Buffer.byteLength(body)
    const counts = workspaceCounts(snapshot.data)
    const meta = {
      id,
      version: snapshot.version,
      updatedAt: snapshot.updatedAt,
      archivedAt: Date.now(),
      bytes,
      trigger,
      source,
      counts,
      diff: countDiff(counts, workspaceCounts(afterData)),
      ...(restoredFrom ? { restoredFrom } : {}),
    }
    const bodyPath = historyBodyPath(id)
    const metaPath = historyMetaPath(id)
    await writeFile(`${bodyPath}.tmp`, body, 'utf8')
    await rename(`${bodyPath}.tmp`, bodyPath)
    await writeFile(`${metaPath}.tmp`, JSON.stringify(meta), 'utf8')
    await rename(`${metaPath}.tmp`, metaPath)
    return { id, version: snapshot.version, bytes }
  } catch (error) {
    console.warn('[tower] 工作区历史备份失败（已跳过，不影响本次写入）:', error?.message ?? error)
    return null
  }
}

/**
 * 保留最近 10 版、总量不超过 50MB。当前版的前一版永远不删，
 * 否则刚发生误覆盖时最需要的那一份会被容量策略先清掉。
 */
function pruneWorkspaceHistory(protectedVersion) {
  let entries
  try {
    entries = listHistoryMetadata()
  } catch (error) {
    console.warn('[tower] 工作区历史清理读取失败:', error?.message ?? error)
    return
  }
  let total = entries.reduce((sum, entry) => sum + entry.bytes, 0)
  let count = entries.length
  if (count <= HISTORY_MAX_ENTRIES && total <= HISTORY_MAX_BYTES) return
  const oldestFirst = [...entries].sort((a, b) => a.version - b.version || a.archivedAt - b.archivedAt)
  for (const entry of oldestFirst) {
    if (count <= HISTORY_MAX_ENTRIES && total <= HISTORY_MAX_BYTES) break
    if (entry.version === protectedVersion) continue
    try {
      unlinkSync(historyBodyPath(entry.id))
      try {
        unlinkSync(historyMetaPath(entry.id))
      } catch {
        // 元数据缺失不影响正文删除。
      }
      count -= 1
      total -= entry.bytes
    } catch (error) {
      console.warn(`[tower] 删除旧工作区历史 ${entry.id} 失败:`, error?.message ?? error)
    }
  }
}

async function readHistoryBody(id) {
  const parsed = parseWorkspaceFile(await readFile(historyBodyPath(id), 'utf8'))
  if (parsed.version !== historyIdVersion(id)) {
    throw new Error('历史版本的版本号与文件名不一致')
  }
  return parsed
}

function requestSource(req) {
  return {
    ip: normalizedRemoteAddress(req),
    ua: String(req.headers['user-agent'] ?? '').slice(0, 200),
  }
}

function expectedRestoreVersion(req, payload) {
  const header = req.headers['if-match']
  if (header) {
    for (const part of String(header).split(',')) {
      const token = part.trim()
      if (token === '*') return workspace.version
      const match = /^(?:W\/)?"?v(\d+)"?$/.exec(token)
      if (match) return Number(match[1])
    }
    return null
  }
  if (Number.isInteger(payload?.version) && payload.version >= 0) return payload.version
  return null
}

/**
 * 数据目录是否可写。Docker 里 bind mount 的宿主机目录常由 root 创建，
 * 容器内的 node 用户（UID 1000）写不进去，工作区就会永远停在 v0。
 * 页面需要这个信号，否则用户只会看到一份空白工作区。
 * 真正写一个小文件再删掉，而不是只看权限位：root、ACL、只读挂载都更可靠。
 */
function probeDataDirWritable() {
  try {
    mkdirSync(DATA_DIR, { recursive: true })
    const marker = join(DATA_DIR, `.tower-write-probe-${process.pid}`)
    writeFileSync(marker, 'ok')
    unlinkSync(marker)
    return true
  } catch {
    return false
  }
}

// 健康检查每 30 秒一次，不必每次都落盘；10 秒内的结果直接复用。
// 修复权限后最多 10 秒恢复 healthy，不需要重启容器。
const DATA_PROBE_TTL_MS = 10_000
let dataProbe = { at: Number.NEGATIVE_INFINITY, value: true }

function dataDirWritable() {
  const now = Date.now()
  if (now - dataProbe.at < DATA_PROBE_TTL_MS) return dataProbe.value
  const value = probeDataDirWritable()
  dataProbe = { at: now, value }
  return value
}

const DEFAULT_SERVER_SETTINGS = Object.freeze({
  /** 关闭后，非本机请求不能使用塔台 API / 订阅 / 规则集。 */
  lanSharing: true,
  /** 非空时，局域网设备必须带此密钥才能调用管理 API。 */
  apiToken: '',
  /** 服务器模式下按工作区固定的订阅 token；本地模式不使用。 */
  subscriptionToken: '',
})

let serverSettings = { ...DEFAULT_SERVER_SETTINGS }

/** 固定订阅 token 只接受足够强的格式；迁移时不把历史弱 token 提升为规范链接。 */
function normalizeWorkspaceSubscriptionToken(value) {
  const token = String(value ?? '').trim()
  return /^[A-Za-z0-9_-]{16,128}$/.test(token) ? token : ''
}

function normalizeAPIToken(value) {
  const token = String(value ?? '').trim()
  if (SERVER_MODE) {
    // 服务器版允许任意长度的短密钥（1 字符也可），但必须是非空、不含空白 /
    // 换行 / 控制字符。短密钥的风险见 SECURITY.md。
    return /^[^\s\x00-\x1f\x7f]{1,128}$/.test(token) ? token : ''
  }
  return /^[A-Za-z0-9_-]{16,128}$/.test(token) ? token : ''
}

function loadServerSettings() {
  try {
    const data = JSON.parse(readFileSync(SETTINGS_FILE, 'utf8'))
    serverSettings = {
      lanSharing: data?.lanSharing !== false,
      apiToken: normalizeAPIToken(data?.apiToken),
      subscriptionToken: normalizeWorkspaceSubscriptionToken(data?.subscriptionToken),
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      console.error('[tower] 服务端设置读取失败，使用默认值:', error?.message ?? error)
    }
  }
  // 容器部署可由启动参数提供初始密钥，避免只能依赖可伪造的 Host 头
  // 来识别宿主机页面。显式环境变量优先于 settings.json。
  const envTokenRaw = String(process.env.TOWER_API_TOKEN ?? '').trim()
  if (envTokenRaw) {
    const envToken = normalizeAPIToken(envTokenRaw)
    if (envToken) serverSettings.apiToken = envToken
    else console.warn(`[tower] TOWER_API_TOKEN 格式无效（${SERVER_MODE ? '需 1–128 个不含空白 / 控制字符的字符' : '需 16–128 位 A-Z/a-z/0-9/_/-'}），已忽略`)
  }
}

function persistServerSettings() {
  try {
    mkdirSync(DATA_DIR, { recursive: true })
    const temp = `${SETTINGS_FILE}.tmp`
    writeFileSync(temp, JSON.stringify(serverSettings), 'utf8')
    renameSync(temp, SETTINGS_FILE)
  } catch (error) {
    console.error('[tower] 服务端设置保存失败:', error?.message ?? error)
  }
}

function normalizedRemoteAddress(req) {
  return String(req.socket?.remoteAddress ?? '').toLowerCase().replace(/^::ffff:/, '')
}

function isLoopbackAddress(address) {
  // 只把标准回环地址视为本机；127.0.0.2 等其他回环别名可以用来自验证局域网逻辑。
  return address === '::1' || address === '127.0.0.1'
}

function isLoopbackRequest(req) {
  return isLoopbackAddress(normalizedRemoteAddress(req))
}

/** 容器内看到的宿主机访问常是 172.x；用 Host 头区分宿主机浏览器。 */
function isContainerHostLocalRequest(req) {
  return process.env.TOWER_CONTAINER === '1'
    && isPrivateAddress(normalizedRemoteAddress(req))
    && ['localhost', '::1', '127.0.0.1'].includes(requestHostname(req))
}

function requestHostname(req) {
  const raw = String(req.headers.host ?? '').trim()
  if (!raw) return ''
  try {
    return new URL(`http://${raw}`).hostname.toLowerCase().replace(/^\[|\]$/g, '')
  } catch {
    return ''
  }
}

function isPrivateAddress(address) {
  if (!address) return false
  if (address.startsWith('10.') || address.startsWith('192.168.') || address.startsWith('169.254.')) return true
  if (address.startsWith('172.')) {
    const second = Number(address.split('.')[1])
    return second >= 16 && second <= 31
  }
  return address.startsWith('fc') || address.startsWith('fd') || address.startsWith('fe80:')
}

/**
 * 设置接口允许本机直连；Docker 宿主机通过 Host 头识别，但一旦启用管理密钥，
 * 仍必须带上正确密钥。否则局域网里的任意客户端都能伪造 `Host: localhost`
 * 读取 settings.json 里的密钥。
 */
function canManageSettings(req, url, action = 'write') {
  if (isLoopbackRequest(req)) return true
  if (!isContainerHostLocalRequest(req)) return false
  // 容器内只能看到「私有地址 + Host: localhost」，局域网客户端可以伪造
  // Host。没有管理密钥时，不能仅凭 Host 头创建/轮换密钥，否则任何局域网
  // 用户都能先设置密钥并接管实例。首次密钥请用 TOWER_API_TOKEN 或容器内
  // 回环请求创建。
  if (action === 'token' && !serverSettings.apiToken) return false
  return apiTokenMatches(presentedAPIToken(req, url))
}

function cookieValue(req, name) {
  for (const part of String(req.headers.cookie ?? '').split(';')) {
    const separator = part.indexOf('=')
    if (separator < 0) continue
    if (part.slice(0, separator).trim() !== name) continue
    try {
      return decodeURIComponent(part.slice(separator + 1).trim())
    } catch {
      return part.slice(separator + 1).trim()
    }
  }
  return ''
}

function presentedAPIToken(req, url) {
  const header = String(req.headers['x-tower-key'] ?? '').trim()
  if (header) return header
  const authorization = String(req.headers.authorization ?? '').trim()
  if (/^bearer\s/i.test(authorization)) return authorization.slice(7).trim()
  const query = url.searchParams.get('key')
  if (query) return query.trim()
  return cookieValue(req, 'tower_key')
}

function apiTokenMatches(presented) {
  const expected = serverSettings.apiToken
  if (!expected) return true
  if (!presented || presented.length !== expected.length) return false
  try {
    return timingSafeEqual(Buffer.from(presented), Buffer.from(expected))
  } catch {
    return false
  }
}

function rememberAPIToken(res) {
  if (!serverSettings.apiToken) return
  res.setHeader(
    'set-cookie',
    `tower_key=${encodeURIComponent(serverSettings.apiToken)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`,
  )
}

/**
 * 订阅 / 一次性分享链接本身是不可猜测的凭证，托管规则集只输出公开规则；
 * 这些 GET 请求不要求再带管理 API 密钥，否则订阅持有者会从配置里拿到密钥。
 */
function apiAuthExempt(url, method) {
  if (url.pathname === '/api/auth-status' || url.pathname === '/api/health') return true
  if (method === 'GET' && url.pathname === '/api/ruleset') return true
  if (method === 'GET' && /^\/api\/sub\/[A-Za-z0-9_-]+$/.test(url.pathname)) return true
  if (method === 'GET' && /^\/api\/s\/[A-Za-z0-9_-]+$/.test(url.pathname)) return true
  return false
}

function authStatus(req, url) {
  // 容器宿主机通过 Host: localhost 识别；但只有没有管理密钥（或已经带对
  // 密钥）时才把 local 报给页面，避免局域网伪造 Host 后绕过访问门。
  const presented = presentedAPIToken(req, url)
  const tokenMatches = apiTokenMatches(presented)
  // 状态接口本身免节流（页面无密钥时也要能判断模式），但它会返回 valid，
  // 不能让这里变成不限次数的密钥试错 oracle：带了错误密钥就计入失败。
  if (presented && !tokenMatches) recordAuthFailure(req)
  else if (tokenMatches && presented) resetAuthFailures(req)
  const local = isLoopbackRequest(req)
    || (isContainerHostLocalRequest(req) && tokenMatches)
  return {
    mode: SERVER_MODE ? 'server' : 'local',
    lanSharing: serverSettings.lanSharing,
    requiresAuth: !!serverSettings.apiToken,
    local,
    // 服务器模式没有本机豁免：回环地址也必须带对密钥才算 valid。
    valid: SERVER_MODE ? (!!serverSettings.apiToken && tokenMatches) : (local || tokenMatches),
    // 服务器模式下数据目录不可写 = 任何设备都存不了工作区，页面据此给出明确提示。
    dataWritable: SERVER_MODE ? dataDirWritable() : true,
  }
}

// 认证失败节流：同一 IP 连续 10 次失败后冷却 60 秒。计数只在内存里，
// 服务端重启即清空；只防暴力猜密钥，不做持久封禁。
const AUTH_FAILURE_LIMIT = 10
const AUTH_COOLDOWN_MS = 60 * 1000
const authFailures = new Map()

function requestIP(req) {
  return normalizedRemoteAddress(req) || 'unknown'
}

function authCooldownRemaining(req) {
  const record = authFailures.get(requestIP(req))
  if (!record?.blockedUntil) return 0
  return Math.max(0, record.blockedUntil - Date.now())
}

function recordAuthFailure(req) {
  const ip = requestIP(req)
  const record = authFailures.get(ip) ?? { count: 0, blockedUntil: 0 }
  if (record.blockedUntil && record.blockedUntil <= Date.now()) {
    record.count = 0
    record.blockedUntil = 0
  }
  record.count += 1
  if (record.count >= AUTH_FAILURE_LIMIT) {
    record.count = 0
    record.blockedUntil = Date.now() + AUTH_COOLDOWN_MS
    console.warn(`[tower] ${ip} 连续认证失败，冷却 60 秒`)
  }
  authFailures.set(ip, record)
  // 简单上限，避免长期运行后 Map 无限增长。
  if (authFailures.size > 1024) {
    for (const [key, value] of authFailures) {
      if (!value.blockedUntil || value.blockedUntil <= Date.now()) authFailures.delete(key)
    }
  }
}

function resetAuthFailures(req) {
  authFailures.delete(requestIP(req))
}

function settingsPayload() {
  const lan = PUBLIC_URL ? [PUBLIC_URL] : (HOST === '0.0.0.0' ? lanUrls(PORT) : [])
  const mobileBase = lan[0]
  const mobileURL = mobileBase
    ? `${mobileBase}/${serverSettings.apiToken ? `?key=${encodeURIComponent(serverSettings.apiToken)}` : ''}`
    : undefined
  return {
    lanSharing: serverSettings.lanSharing,
    requiresAuth: !!serverSettings.apiToken,
    apiToken: serverSettings.apiToken,
    mobileURL,
  }
}

loadServerSettings()

function loadSubscriptions() {
  try {
    const data = JSON.parse(readFileSync(SUBS_FILE, 'utf8'))
    for (const [token, rec] of Object.entries(data)) {
      if (rec && typeof rec === 'object' && rec.formats) subscriptions.set(token, rec)
    }
    console.log(`[tower] 已载入 ${subscriptions.size} 个持久订阅`)
  } catch (err) {
    // 首次运行没有文件是正常情况。文件损坏时先备份，避免下一次发布覆盖掉
    // 还能人工恢复的旧订阅。
    if (err?.code !== 'ENOENT') {
      const backup = `${SUBS_FILE}.corrupt-${Date.now()}`
      try {
        renameSync(SUBS_FILE, backup)
        console.error(`[tower] 订阅文件损坏，已备份为 ${backup}:`, err?.message ?? err)
      } catch {
        console.error('[tower] 订阅文件读取失败，且无法备份:', err?.message ?? err)
      }
    }
  }
}

let persistRunning = false
let persistAgain = false

/**
 * Windows 上杀毒/备份工具会短暂占用 subscriptions.json，此时 rename 会抛
 * EPERM/EBUSY/EACCES。重试几次比直接放弃更安全，否则磁盘上会停留在旧版本。
 */
async function replaceFile(temp, target) {
  let lastError
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      await rename(temp, target)
      return
    } catch (err) {
      lastError = err
      if (!['EPERM', 'EBUSY', 'EACCES'].includes(err.code)) break
      await new Promise((resolve) => setTimeout(resolve, 30 * (attempt + 1)))
    }
  }
  throw lastError
}

async function persistSubscriptions() {
  // 10MB 级的 subscriptions.json 同步 stringify + writeFileSync 会阻塞事件
  // 循环约 40ms；改成串行异步落盘，发布请求立即返回，合并并发写入。
  if (persistRunning) {
    persistAgain = true
    return
  }
  persistRunning = true
  try {
    do {
      persistAgain = false
      try {
        mkdirSync(DATA_DIR, { recursive: true })
        // 先写临时文件再替换，避免进程在写入中途退出时留下半截 JSON。
        const temp = `${SUBS_FILE}.tmp`
        await writeFile(temp, JSON.stringify(Object.fromEntries(subscriptions)), 'utf8')
        await replaceFile(temp, SUBS_FILE)
      } catch (err) {
        console.error('[tower] 订阅落盘失败:', err.message)
      }
    } while (persistAgain)
  } finally {
    persistRunning = false
  }
}

/**
 * 服务器模式启动时把订阅 token 固定到工作区。
 * 迁移策略：优先沿用最近一次发布的强 token，减少客户端重新导入；找不到才新发。
 * 旧记录一条都不删，只把规范链接指向选中的 token。
 */
function ensureWorkspaceSubscriptionToken() {
  if (!SERVER_MODE || serverSettings.subscriptionToken) return
  let newest = -1
  let candidate = ''
  for (const [token, record] of subscriptions) {
    if (!normalizeWorkspaceSubscriptionToken(token)) continue
    const updatedAt = Number(record?.updatedAt) || 0
    if (updatedAt > newest) {
      newest = updatedAt
      candidate = token
    }
  }
  const token = candidate || randomBytes(16).toString('base64url')
  serverSettings.subscriptionToken = token
  persistServerSettings()
  if (candidate) {
    console.log('[tower] 服务器版沿用最近发布的订阅 token 作为固定链接')
  } else {
    console.log('[tower] 服务器版已生成固定订阅 token')
  }
}

/** 退出前把待写内容同步落盘，避免刚发布就丢。 */
function flushSubscriptionsSync() {
  try {
    mkdirSync(DATA_DIR, { recursive: true })
    const temp = `${SUBS_FILE}.tmp`
    writeFileSync(temp, JSON.stringify(Object.fromEntries(subscriptions)), 'utf8')
    renameSync(temp, SUBS_FILE)
  } catch (err) {
    console.error('[tower] 订阅落盘失败:', err.message)
  }
}

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.once(signal, () => {
    flushSubscriptionsSync()
    process.exit(0)
  })
}

// ---------- 服务器版工作区 ----------
// 单用户、单进程：整个工作区（订阅源、节点、规则方案 / 规则集、当前选择、
// Tailscale 连接与 Auth Key）保存在一个 JSON 文件里。写入走串行队列，
// 先落临时文件再原子替换；版本号用于检测多设备并发修改。

let workspace = { version: 0, updatedAt: 0, data: {} }
/** 非空表示启动时文件已损坏并改名保留，所有工作区接口返回明确错误。 */
let workspaceCorrupt = ''
let workspaceQueue = Promise.resolve()

function workspaceHasData() {
  return workspace.version > 0
}

async function writeWorkspaceFile(next) {
  mkdirSync(DATA_DIR, { recursive: true })
  const temp = `${WORKSPACE_FILE}.tmp`
  await writeFile(temp, JSON.stringify(next), 'utf8')
  // 覆盖前留一份上一版，误覆盖或恢复备份后还能找回。
  if (existsSync(WORKSPACE_FILE)) {
    try {
      copyFileSync(WORKSPACE_FILE, `${WORKSPACE_FILE}.bak`)
    } catch (error) {
      console.warn('[tower] 工作区 .bak 写入失败:', error?.message ?? error)
    }
  }
  await replaceFile(temp, WORKSPACE_FILE)
}

function commitWorkspace(payload, options = {}) {
  // 版本比较、落盘和内存更新都排在同一条 Promise 链上，避免并发写同一文件。
  const run = workspaceQueue.then(async () => {
    if (workspaceCorrupt) return { corrupt: true }
    if (payload.version !== workspace.version) return { conflict: true }
    // version=0 只用于「服务端还没有任何工作区」时的首次创建；
    // 已有数据时客户端必须显式按当前版本覆盖，不能静默回到 0。
    if (payload.version === 0 && workspaceHasData()) return { conflict: true }
    // 先归档即将被替换的这一版，再写新文件；归档失败不阻断写入。
    const previous = await archiveWorkspace(
      { version: workspace.version, updatedAt: workspace.updatedAt, data: workspace.data },
      payload.data,
      options.source ?? { ip: '', ua: '' },
      options.trigger === 'restore' ? 'restore' : 'write',
      options.restoredFrom,
    )
    const next = {
      version: workspace.version + 1,
      updatedAt: Date.now(),
      data: payload.data,
    }
    try {
      await writeWorkspaceFile(next)
    } catch (error) {
      return { failure: String(error?.message ?? error) }
    }
    workspace = next
    // 当前版的前一版（next.version - 1）受保护，容量策略不能删它。
    pruneWorkspaceHistory(next.version - 1)
    return { version: next.version, updatedAt: next.updatedAt, previous }
  })
  workspaceQueue = run.then(() => undefined, () => undefined)
  return run
}

function parseWorkspaceFile(text) {
  const raw = JSON.parse(text)
  if (!raw || typeof raw !== 'object'
    || !Number.isInteger(raw.version) || raw.version < 0
    || !raw.data || typeof raw.data !== 'object' || Array.isArray(raw.data)) {
    throw new Error('结构无效：需要 { version: 非负整数, updatedAt: 数字, data: 对象 }')
  }
  // 服务端不会写出 version=0 且带数据的文件；手工编辑可能制造这种状态。
  // 把它当成 v1 继续用，否则 version=0 的写入会被当作首次创建而互相覆盖。
  const version = raw.version === 0 && Object.keys(raw.data).length > 0 ? 1 : raw.version
  return {
    version,
    updatedAt: Number(raw.updatedAt) || 0,
    data: raw.data,
    normalized: version !== raw.version,
  }
}

function loadWorkspace() {
  if (!SERVER_MODE) return
  let loaded
  let error
  try {
    loaded = parseWorkspaceFile(readFileSync(WORKSPACE_FILE, 'utf8'))
  } catch (err) {
    error = err
    if (err?.code === 'ENOENT') return
  }
  if (!loaded) {
    // 坏文件绝不能当成空工作区继续跑，否则下一次写入会覆盖现场。
    const broken = `${WORKSPACE_FILE}.broken-${Date.now()}`
    try {
      renameSync(WORKSPACE_FILE, broken)
    } catch {
      // 改名失败也保留原文件，不覆盖。
    }
    // 每次成功写入前都会把上一版复制成 .bak，因此主文件损坏时还有一份
    // 可用的备份。恢复后版本可能回退一版，客户端轮询会自己拉回最新。
    try {
      const backup = parseWorkspaceFile(readFileSync(`${WORKSPACE_FILE}.bak`, 'utf8'))
      writeFileSync(WORKSPACE_FILE, JSON.stringify({
        version: backup.version,
        updatedAt: backup.updatedAt,
        data: backup.data,
      }), 'utf8')
      workspace = { version: backup.version, updatedAt: backup.updatedAt, data: backup.data }
      console.warn(`[tower] 主工作区损坏（已保留 ${broken}），已从 .bak 恢复 v${backup.version}`)
      return
    } catch (backupError) {
      workspaceCorrupt = `服务器工作区文件损坏，已保留现场为 ${broken}`
      console.error('[tower]', workspaceCorrupt, ':', error?.message ?? error, '；.bak 也不可用:', backupError?.message ?? backupError)
      return
    }
  }
  workspace = {
    version: loaded.version,
    updatedAt: loaded.updatedAt,
    data: loaded.data,
  }
  if (loaded.normalized) {
    try {
      writeFileSync(WORKSPACE_FILE, JSON.stringify({
        version: loaded.version,
        updatedAt: loaded.updatedAt,
        data: loaded.data,
      }), 'utf8')
      console.warn(`[tower] workspace.json 的 version=0 但已有数据，已按 v${loaded.version} 继续`)
    } catch (err) {
      console.warn('[tower] 修正 version=0 的 workspace.json 失败:', err?.message ?? err)
    }
  }
  try {
    copyFileSync(WORKSPACE_FILE, `${WORKSPACE_FILE}.bak`)
  } catch (err) {
    console.warn('[tower] 工作区 .bak 写入失败:', err?.message ?? err)
  }
  console.log(`[tower] 已载入服务器工作区 v${workspace.version}`)
}

function workspaceETag() {
  return `"v${workspace.version}"`
}

function etagMatches(header, etag) {
  if (!header) return false
  return String(header)
    .split(',')
    .map((value) => value.trim())
    .some((value) => value === '*' || value === etag || value === `W/${etag}`)
}

function workspaceJSON(res, status, value, headers = {}) {
  return send(res, status, JSON.stringify(value), {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...headers,
  })
}

async function handleWorkspace(url, req, res) {
  if (workspaceCorrupt) {
    return workspaceJSON(res, 500, { error: workspaceCorrupt, code: 'workspace_corrupt' })
  }
  const etag = workspaceETag()
  if (url.pathname === '/api/workspace/version') {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return workspaceJSON(res, 405, { error: '只支持 GET' }, { allow: 'GET' })
    }
    return workspaceJSON(res, 200, { version: workspace.version }, { etag })
  }
  if (req.method === 'GET') {
    const requested = url.searchParams.get('version')
    if (etagMatches(req.headers['if-none-match'], etag)
      || (requested !== null && Number(requested) === workspace.version)) {
      res.writeHead(304, { etag, 'cache-control': 'no-store' })
      res.end()
      return
    }
    return workspaceJSON(res, 200, {
      version: workspace.version,
      updatedAt: workspace.updatedAt,
      data: workspace.data,
    }, { etag })
  }
  if (req.method === 'PUT') {
    // 超过上限时 readBody 会抛 413，外层统一转成 JSON 错误。
    const raw = await readBody(req, WORKSPACE_MAX_BYTES)
    let payload
    try {
      payload = JSON.parse(raw.toString('utf8'))
    } catch {
      return workspaceJSON(res, 400, { error: '请求内容不是 JSON', code: 'bad_json' })
    }
    if (!payload || typeof payload !== 'object'
      || !Number.isInteger(payload.version) || payload.version < 0
      || !payload.data || typeof payload.data !== 'object' || Array.isArray(payload.data)) {
      return workspaceJSON(res, 400, {
        error: 'PUT 需要 { version: 非负整数, data: 对象 }',
        code: 'bad_payload',
      })
    }
    const result = await commitWorkspace(payload, { source: requestSource(req) })
    if (result.corrupt) {
      return workspaceJSON(res, 500, { error: workspaceCorrupt, code: 'workspace_corrupt' })
    }
    if (result.conflict) {
      return workspaceJSON(res, 409, {
        error: '工作区已被其他设备修改，请先拉取最新版本',
        code: 'version_conflict',
        version: workspace.version,
      })
    }
    if (result.failure) {
      return workspaceJSON(res, 500, {
        error: `工作区写入失败：${result.failure}`,
        code: 'workspace_write_failed',
        version: workspace.version,
      })
    }
    return workspaceJSON(res, 200, {
      version: result.version,
      updatedAt: result.updatedAt,
    }, { etag: `"v${result.version}"` })
  }
  return workspaceJSON(res, 405, { error: '只支持 GET / PUT' }, { allow: 'GET, PUT' })
}

/** 列表不带正文；当前版单独给出，历史里只放已被替换的版本。 */
function workspaceHistoryPayload() {
  const entries = listHistoryMetadata()
  let bytes = 0
  try {
    bytes = statSync(WORKSPACE_FILE).size
  } catch {
    // 工作区尚未创建时没有文件；体积记为 0。
  }
  return {
    current: {
      version: workspace.version,
      updatedAt: workspace.updatedAt,
      bytes,
      counts: workspaceCounts(workspace.data),
    },
    entries,
    totalBytes: entries.reduce((sum, entry) => sum + entry.bytes, 0),
    limits: { entries: HISTORY_MAX_ENTRIES, bytes: HISTORY_MAX_BYTES },
  }
}

async function restoreHistoryEntry(id, req, res) {
  const raw = await readBody(req)
  let payload = {}
  if (raw.length > 0) {
    try {
      payload = JSON.parse(raw.toString('utf8'))
    } catch {
      return workspaceJSON(res, 400, { error: '请求内容不是 JSON', code: 'bad_json' })
    }
  }
  const expected = expectedRestoreVersion(req, payload)
  if (expected === null) {
    return workspaceJSON(res, 400, {
      error: '回滚请求必须带 If-Match 或当前 version',
      code: 'missing_version',
    })
  }
  if (expected !== workspace.version) {
    return workspaceJSON(res, 409, {
      error: '工作区已被其他设备修改，请先拉取最新版本',
      code: 'version_conflict',
      version: workspace.version,
    })
  }
  let parsed
  try {
    parsed = await readHistoryBody(id)
  } catch (error) {
    return workspaceJSON(res, 422, {
      error: `历史版本无法读取：${error?.message ?? error}`,
      code: 'history_corrupt',
    })
  }
  const result = await commitWorkspace(
    { version: expected, data: parsed.data },
    {
      source: requestSource(req),
      trigger: 'restore',
      restoredFrom: { id, version: parsed.version },
    },
  )
  if (result.corrupt) {
    return workspaceJSON(res, 500, { error: workspaceCorrupt, code: 'workspace_corrupt' })
  }
  if (result.conflict) {
    return workspaceJSON(res, 409, {
      error: '工作区已被其他设备修改，请先拉取最新版本',
      code: 'version_conflict',
      version: workspace.version,
    })
  }
  if (result.failure) {
    return workspaceJSON(res, 500, {
      error: `工作区写入失败：${result.failure}`,
      code: 'workspace_write_failed',
      version: workspace.version,
    })
  }
  return workspaceJSON(res, 200, {
    version: result.version,
    updatedAt: result.updatedAt,
    restoredFrom: { id, version: parsed.version },
    // 回滚前已自动归档当前版；客户端可直接用它提供「撤销回滚」。
    previous: result.previous,
  }, { etag: `"v${result.version}"` })
}

async function handleWorkspaceHistory(url, req, res) {
  if (workspaceCorrupt) {
    return workspaceJSON(res, 500, { error: workspaceCorrupt, code: 'workspace_corrupt' })
  }
  if (url.pathname === '/api/workspace/history') {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return workspaceJSON(res, 405, { error: '只支持 GET' }, { allow: 'GET' })
    }
    return workspaceJSON(res, 200, workspaceHistoryPayload(), { etag: workspaceETag() })
  }
  const match = /^\/api\/workspace\/history\/([^/]+)(?:\/(restore))?$/.exec(url.pathname)
  let id = ''
  try {
    id = match ? decodeURIComponent(match[1]) : ''
  } catch {
    return workspaceJSON(res, 404, { error: '历史版本不存在', code: 'history_not_found' })
  }
  if (!HISTORY_ID_RE.test(id)) {
    return workspaceJSON(res, 404, { error: '历史版本不存在', code: 'history_not_found' })
  }
  if (match?.[2] === 'restore') {
    if (req.method !== 'POST') {
      return workspaceJSON(res, 405, { error: '只支持 POST' }, { allow: 'POST' })
    }
    return restoreHistoryEntry(id, req, res)
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return workspaceJSON(res, 405, { error: '只支持 GET' }, { allow: 'GET' })
  }
  let parsed
  try {
    parsed = await readHistoryBody(id)
  } catch (error) {
    return workspaceJSON(res, 422, {
      error: `历史版本无法读取：${error?.message ?? error}`,
      code: 'history_corrupt',
    })
  }
  return workspaceJSON(res, 200, {
    ...(readHistoryMetadata(id) ?? { id }),
    id,
    version: parsed.version,
    updatedAt: parsed.updatedAt,
    // 元数据损坏时仍然用正文重算，回滚确认里的数量不会变成 0。
    counts: workspaceCounts(parsed.data),
    data: parsed.data,
  })
}

// ---------- 上游定时检查 ----------
// 只读取 workspace 里的覆盖层指针与快照 source，用于和上游 commit 比对。
// 检查结果写独立文件；绝不调用 commitWorkspace，工作区版本号不会变化。
const UPSTREAM_CHECK_TIMEOUT_MS = 15_000
const UPSTREAM_CHECK_MAX_BYTES = 8 * 1024 * 1024

async function upstreamFetchText(url) {
  const response = await fetch(url, {
    headers: {
      'user-agent': 'tower-web-upstream-check',
      accept: 'application/json, text/plain, */*',
    },
    signal: AbortSignal.timeout(UPSTREAM_CHECK_TIMEOUT_MS),
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  const buffer = Buffer.from(await response.arrayBuffer())
  if (buffer.length > UPSTREAM_CHECK_MAX_BYTES) throw new Error('上游响应超过 8MB 上限')
  return {
    text: buffer.toString('utf8'),
    etag: response.headers.get('etag') ?? undefined,
    contentType: response.headers.get('content-type') ?? undefined,
    contentLength: buffer.length,
    status: response.status,
  }
}

async function upstreamFetchHeaders(url) {
  const response = await fetch(url, {
    method: 'HEAD',
    headers: { 'user-agent': 'tower-web-upstream-check' },
    signal: AbortSignal.timeout(UPSTREAM_CHECK_TIMEOUT_MS),
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  return { etag: response.headers.get('etag') ?? undefined }
}

const upstreamChecker = SERVER_MODE
  ? createUpstreamChecker({
    dataDir: DATA_DIR,
    getWorkspaceData: () => workspace.data,
    fetchText: upstreamFetchText,
    fetchHeaders: upstreamFetchHeaders,
  })
  : null

async function handleUpstreamStatus(url, req, res) {
  if (!SERVER_MODE || !upstreamChecker) {
    return workspaceJSON(res, 404, {
      error: '服务器版未启用（TOWER_MODE=server）',
      code: 'workspace_disabled',
    })
  }
  if (url.pathname === '/api/upstream-status') {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return workspaceJSON(res, 405, { error: '只支持 GET' }, { allow: 'GET' })
    }
    return workspaceJSON(res, 200, upstreamChecker.getPayload())
  }
  if (url.pathname === '/api/upstream-status/check') {
    if (req.method !== 'POST') {
      return workspaceJSON(res, 405, { error: '只支持 POST' }, { allow: 'POST' })
    }
    const result = upstreamChecker.checkNow()
    if (result.disabled) {
      return workspaceJSON(res, 409, {
        error: '服务端上游定时检查已关闭（TOWER_UPSTREAM_CHECK=off）',
        code: 'upstream_check_disabled',
      })
    }
    return workspaceJSON(res, 202, { checking: true })
  }
  return workspaceJSON(res, 404, { error: '接口不存在', code: 'not_found' })
}

loadWorkspace()
loadSubscriptions()
ensureWorkspaceSubscriptionToken()

setInterval(() => {
  const now = Date.now()
  for (const [token, share] of shares) {
    if (share.used || share.expiresAt < now) shares.delete(token)
  }
}, 30_000).unref()

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.yaml': 'text/yaml; charset=utf-8',
  '.list': 'text/plain; charset=utf-8',
  '.ini': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
}

// 订阅支持的载体格式：同一 token 下按客户端取对应格式。
// surge / loon / quanx 三者同为 ini 文件但语法互不兼容，必须各自独立。
const SUB_FORMATS = ['yaml', 'egern', 'surge', 'loon', 'quanx', 'json', 'base64']
// 兼容旧链接 / 旧请求里的简写
const SUB_ALIAS = {
  ini: 'surge',
  singbox: 'json',
  clash: 'yaml',
  surfboard: 'surge',
  stash: 'yaml',
}
const SUB_TARGET_FORMAT = {
  clash: 'yaml',
  'clash-apple': 'yaml',
  'clash-mi': 'yaml',
  clashmi: 'yaml',
  karing: 'yaml',
  'clash-verge': 'yaml',
  clashverge: 'yaml',
  clashmac: 'yaml',
  flclash: 'yaml',
  'mihomo-party': 'yaml',
  openclash: 'yaml',
  nikki: 'yaml',
  mihomo: 'yaml',
  stash: 'yaml',
  egern: 'egern',
  surge: 'surge',
  'surge-mac': 'surge',
  surfboard: 'surge',
  shadowrocket: 'yaml',
  'shadow-rocket': 'yaml',
  v2box: 'base64',
  anywhere: 'base64',
  loon: 'loon',
  quanx: 'quanx',
  quantumult: 'quanx',
  'quantumult-x': 'quanx',
  quantumultx: 'quanx',
  hiddify: 'json',
  'sing-box': 'json',
  singbox: 'json',
}

/** 客户端 target → 订阅里可选的目标专属变体 key。 */
const SUB_TARGET_CANONICAL = {
  surge: 'surge',
  'surge-mac': 'surge-mac',
  clash: 'clash',
  stash: 'clash',
  'clash-apple': 'clash-apple',
  'clash-verge': 'clash-verge',
  clashverge: 'clash-verge',
  clashmac: 'clashmac',
  flclash: 'flclash',
  'mihomo-party': 'mihomo-party',
  'clash-mi': 'clash-mi',
  clashmi: 'clash-mi',
  karing: 'karing',
  shadowrocket: 'shadowrocket',
  'shadow-rocket': 'shadowrocket',
  v2box: 'v2box',
  anywhere: 'anywhere',
  loon: 'loon',
  quanx: 'quanx',
  quantumult: 'quanx',
  'quantumult-x': 'quanx',
  quantumultx: 'quanx',
  hiddify: 'hiddify',
  'sing-box': 'sing-box',
  singbox: 'sing-box',
  egern: 'egern',
}

function canonicalSubTarget(value) {
  const key = String(value ?? '').trim().toLowerCase()
  return key && key !== 'auto' ? SUB_TARGET_CANONICAL[key] ?? null : null
}

/** User-Agent 只用来挑选目标专属变体；格式仍由 resolveSubFormat 决定。 */
function subTargetFromUserAgent(userAgent) {
  const agent = String(userAgent ?? '').toLowerCase()
  if (!agent) return null
  if (agent.includes('shadowrocket')) return 'shadowrocket'
  if (agent.includes('quantumult') || agent.includes('quanx')) return 'quanx'
  if (agent.includes('hiddify')) return 'hiddify'
  if (agent.includes('sing-box') || agent.includes('singbox')) return 'sing-box'
  if (agent.includes('stash')) return 'clash'
  if (agent.includes('karing')) return 'karing'
  if (agent.includes('egern')) return 'egern'
  if (agent.includes('surfboard')) return 'surge'
  if (agent.includes('surge')) return 'surge'
  if (agent.includes('loon')) return 'loon'
  return null
}

/** 局域网通用订阅：显式 format > target > User-Agent。 */
function resolveSubFormat(formatParam, targetParam, userAgent) {
  const format = String(formatParam ?? '').trim().toLowerCase()
  if (format) return SUB_FORMATS.includes(format) ? format : SUB_ALIAS[format] ?? 'base64'
  const target = String(targetParam ?? '').trim().toLowerCase()
  if (target && target !== 'auto') {
    return SUB_TARGET_FORMAT[target] ?? null
  }
  const canonical = subTargetFromUserAgent(userAgent)
  if (canonical) return SUB_TARGET_FORMAT[canonical]
  const agent = String(userAgent ?? '').toLowerCase()
  if (!agent) return 'base64'
  if (agent.includes('openclash') || agent.includes('nikki') || agent.includes('clash') || agent.includes('mihomo')) return 'yaml'
  return 'base64'
}
const SUB_MIME = {
  yaml: 'text/yaml; charset=utf-8',
  egern: 'text/yaml; charset=utf-8',
  surge: 'text/plain; charset=utf-8',
  loon: 'text/plain; charset=utf-8',
  quanx: 'text/plain; charset=utf-8',
  json: 'application/json; charset=utf-8',
  base64: 'text/plain; charset=utf-8',
}
const SUB_EXT = { yaml: 'yaml', egern: 'yaml', surge: 'conf', loon: 'conf', quanx: 'conf', json: 'json', base64: 'txt' }

/** 标题会进入响应头与客户端 profile 名，限制长度并去掉换行。 */
function normalizeSubscriptionTitle(value, fallback = 'tower') {
  const text = String(value ?? '').replace(/[\r\n]/g, ' ').trim().slice(0, 96)
  return text || fallback
}

// ---------- offline IP country database (sapics/ip-location-db, PDDL-1.0) ----------
const IP_COUNTRY_DIR = join(dirname(fileURLToPath(import.meta.url)), 'ip-country')
const IP_ASN_DIR = join(dirname(fileURLToPath(import.meta.url)), 'ip-asn')
let ipASNData
function loadIPASNDatabase() {
  if (ipASNData !== undefined) return ipASNData
  ipASNData = loadIPASNData(IP_ASN_DIR)
  return ipASNData
}
let ipCountryData
function loadIPCountryDatabase() {
  if (ipCountryData !== undefined) return ipCountryData
  ipCountryData = loadIPCountryData(IP_COUNTRY_DIR)
  return ipCountryData
}

/** 国家码 → CIDR 列表；同一国家只扫描一次二进制表。 */
const geoipCidrCache = new Map()
function geoipCidrs(code) {
  const normalized = String(code ?? '').trim().toUpperCase()
  if (!/^[A-Z]{2}$/.test(normalized)) return []
  if (geoipCidrCache.has(normalized)) return geoipCidrCache.get(normalized)
  const cidrs = countryCIDRs(loadIPCountryDatabase(), normalized)
  if (geoipCidrCache.size >= 256) geoipCidrCache.clear()
  geoipCidrCache.set(normalized, cidrs)
  return cidrs
}

/** AS 号 → CIDR 列表；大型运营商可拆出十几万条，必须缓存。 */
const asnCidrCache = new Map()
function asnCidrs(asn) {
  if (!Number.isInteger(asn) || asn <= 0) return []
  if (asnCidrCache.has(asn)) return asnCidrCache.get(asn)
  const cidrs = asnCIDRs(loadIPASNDatabase(), asn)
  if (asnCidrCache.size >= 256) asnCidrCache.clear()
  asnCidrCache.set(asn, cidrs)
  return cidrs
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
  return value
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

function countryCodeForAddress(address) {
  const data = loadIPCountryDatabase()
  if (!data) return null
  if (isIP(address) === 4) {
    const value = ipv4Value(address)
    if (value === null) return null
    let low = 0
    let high = data.v4.length / 10 - 1
    while (low <= high) {
      const record = low + Math.floor((high - low) / 2)
      const offset = record * 10
      const start = data.v4.readUInt32BE(offset)
      const end = data.v4.readUInt32BE(offset + 4)
      if (value < start) high = record - 1
      else if (value > end) low = record + 1
      else return data.v4.toString('ascii', offset + 8, offset + 10)
    }
    return null
  }
  if (isIP(address) === 6) {
    const bytes = ipv6Bytes(address)
    if (!bytes) return null
    let low = 0
    let high = data.v6.length / 34 - 1
    while (low <= high) {
      const record = low + Math.floor((high - low) / 2)
      const offset = record * 34
      const start = data.v6.subarray(offset, offset + 16)
      const end = data.v6.subarray(offset + 16, offset + 32)
      if (bytes.compare(start) < 0) high = record - 1
      else if (bytes.compare(end) > 0) low = record + 1
      else return data.v6.toString('ascii', offset + 32, offset + 34)
    }
  }
  return null
}

const ipCountryCache = new Map()
async function handleIPCountry(url, res) {
  const rawHost = url.searchParams.get('host')?.trim()
  if (!rawHost) return json(res, 400, { error: '缺少 host 参数' })
  if (rawHost.length > 2048) return json(res, 400, { error: 'host 过长' })
  const cached = ipCountryCache.get(rawHost)
  if (cached && Date.now() - cached.at < 24 * 60 * 60 * 1000) {
    return json(res, 200, {
      country: cached.country,
      address: cached.address,
      asn: cached.asn,
      organization: cached.organization,
      cached: true,
    })
  }
  const host = rawHost.replace(/^\[|\]$/g, '')
  let address = isIP(host) ? host : null
  if (!address) {
    try {
      address = (await lookup(host, { verbatim: true })).address
    } catch {
      address = null
    }
  }
  const country = address ? countryCodeForAddress(address) : null
  const network = address ? organizationForAddress(loadIPASNDatabase(), address) : null
  if (address) {
    ipCountryCache.set(rawHost, {
      country,
      address,
      asn: network?.asn,
      organization: network?.organization,
      at: Date.now(),
    })
  }
  return json(res, 200, {
    country,
    address,
    asn: network?.asn ?? null,
    organization: network?.organization ?? null,
  })
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'x-content-type-options': 'nosniff', ...headers })
  res.end(body)
}

/**
 * 上游和分享者可控的 Content-Type 必须收敛到白名单：text/html 或 SVG 会让浏览器
 * 在塔台自己的源上执行脚本，读走 localStorage 里的管理密钥和整份工作区。
 * 原始类型另存 x-upstream-content-type，上游漂移检测仍按真实类型判断。
 */
const PASSTHROUGH_CONTENT_TYPES = new Set([
  'text/plain',
  'text/yaml',
  'application/yaml',
  'application/x-yaml',
  'text/x-yaml',
  'application/json',
  'text/json',
  'application/octet-stream',
  'application/base64',
])

function safeContentType(value) {
  const raw = String(value ?? '').trim()
  const essence = raw.split(';')[0].trim().toLowerCase()
  return PASSTHROUGH_CONTENT_TYPES.has(essence) ? raw : 'text/plain; charset=utf-8'
}

/** 订阅文本里的托管规则集地址跟随请求的局域网/域名 origin。 */
function rewriteRuleSetOrigins(payload, origin) {
  if (typeof payload !== 'string' || !origin) return payload
  return payload.replace(
    /(?:https?:\/\/[^/\s"']+)?(\/api\/ruleset\?[^\s"',]+)/g,
    `${origin}$1`,
  )
}

function json(res, status, value) {
  send(res, status, JSON.stringify(value), {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
}

function sanitizeUserAgent(value) {
  return String(value ?? '').replace(/[\r\n]/g, '').trim().slice(0, 400)
}

/** 订阅可选 DoH：只接受 https 地址，避免把本机变成任意协议转发器。 */
function validatedDoHURL(value) {
  const raw = String(value ?? '').trim()
  if (!raw) return null
  let endpoint
  try {
    endpoint = new URL(raw)
  } catch {
    throw new Error('DoH 地址无效，应填写 https://…/dns-query 形式的地址')
  }
  if (endpoint.protocol !== 'https:' || !endpoint.hostname || endpoint.username || endpoint.password) {
    throw new Error('DoH 地址必须使用 https://，且不能包含账号密码')
  }
  return endpoint
}

/** RFC 8484 的 JSON 接口（Cloudflare / NextDNS 等公共 DoH 均支持）。 */
async function resolveViaDoH(hostname, endpoint) {
  const query = new URL(endpoint.href)
  query.searchParams.set('name', hostname)
  const response = await fetch(query, {
    headers: { accept: 'application/dns-json' },
    signal: AbortSignal.timeout(8000),
  })
  if (!response.ok) throw new Error(`DoH 返回 HTTP ${response.status}`)
  const payload = await response.json()
  if (payload?.Status !== undefined && payload.Status !== 0) {
    throw new Error(`DoH 解析失败（Status ${payload.Status}）`)
  }
  const addresses = []
  const seen = new Set()
  for (const answer of Array.isArray(payload?.Answer) ? payload.Answer : []) {
    if ((answer?.type !== 1 && answer?.type !== 28) || typeof answer.data !== 'string') continue
    if (seen.has(answer.data)) continue
    seen.add(answer.data)
    addresses.push({ address: answer.data, family: answer.type === 1 ? 4 : 6 })
  }
  if (addresses.length === 0) throw new Error(`DoH 未返回 ${hostname} 的地址`)
  // 优先 IPv4，避免只有 AAAA 记录时在 IPv4-only 网络里直接失败。
  addresses.sort((a, b) => a.family - b.family)
  return addresses
}

/** 给 http(s).request 注入自定义 DNS，证书校验和 SNI 仍按原始域名。 */
function dohLookup(endpoint) {
  return (hostname, options, callback) => {
    const literal = isIP(hostname)
    if (literal) {
      if (typeof options === 'object' && options.all) {
        callback(null, [{ address: hostname, family: literal }])
      } else {
        callback(null, hostname, literal)
      }
      return
    }
    const family = typeof options === 'object' ? Number(options.family || 0) : 0
    const all = typeof options === 'object' && options.all
    resolveViaDoH(hostname, endpoint).then((addresses) => {
      const candidates = family ? addresses.filter((a) => a.family === family) : addresses
      if (candidates.length === 0) throw new Error(`DoH 没有 ${hostname} 的 IPv${family} 地址`)
      if (all) callback(null, candidates)
      else callback(null, candidates[0].address, candidates[0].family)
    }).catch((error) => callback(error))
  }
}

/** 没有 DoH 时的系统解析，签名与 dohLookup 保持一致。 */
function systemLookup(hostname, options, callback) {
  const all = typeof options === 'object' && options.all
  const family = typeof options === 'object' ? Number(options.family || 0) : 0
  lookup(hostname, { all: true, verbatim: true })
    .then((addresses) => {
      const list = family ? addresses.filter((item) => item.family === family) : addresses
      if (!list.length) throw new Error(`没有 ${hostname} 的可用解析地址`)
      if (all) callback(null, list)
      else callback(null, list[0].address, list[0].family)
    })
    .catch((error) => callback(error))
}

/**
 * 需要逐跳安全检查时使用：解析出的地址命中链路本地 / 云元数据就直接拒绝，
 * 避免域名指向内网地址绕过只按 hostname 的拦截。
 */
function lookupWithGuard(endpoint) {
  const base = endpoint ? dohLookup(endpoint) : systemLookup
  return (hostname, options, callback) => {
    base(hostname, options, (error, address, family) => {
      if (error) return callback(error)
      const list = Array.isArray(address) ? address : [{ address, family }]
      if (list.some((item) => blockedRuleSetAddress(item.address))) {
        callback(new Error('规则集地址不能指向链路本地或云元数据服务'))
        return
      }
      callback(null, address, family)
    })
  }
}

function headerValue(headers, name) {
  if (!headers) return null
  if (typeof headers.get === 'function') return headers.get(name)
  const value = headers[name.toLowerCase()]
  return Array.isArray(value) ? value[0] : (value ?? null)
}

function requestOnce(target, userAgent, dohEndpoint, headersOnly = false, guard = undefined) {
  return new Promise((resolve, reject) => {
    const transport = target.protocol === 'https:' ? httpsRequest : httpRequest
    const req = transport({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      path: `${target.pathname}${target.search}`,
      method: 'GET',
      agent: false,
      lookup: guard
        ? lookupWithGuard(dohEndpoint)
        : (dohEndpoint ? dohLookup(dohEndpoint) : undefined),
      headers: {
        // Airports switch payloads on the UA; ask for the raw subscription.
        'user-agent': userAgent || 'clash-verge/v2.4.2',
        accept: '*/*',
        'accept-encoding': 'gzip, deflate, br',
      },
    }, (upstream) => {
      if (headersOnly) {
        // 只读响应头时立刻断开，避免把几 MB 的订阅正文完整下载下来。
        upstream.on('error', () => {})
        upstream.destroy()
        resolve({ status: upstream.statusCode ?? 0, headers: upstream.headers, body: Buffer.alloc(0) })
        return
      }
      const declared = Number(headerValue(upstream.headers, 'content-length') ?? 0)
      if (Number.isFinite(declared) && declared > MAX_FETCH_BYTES) {
        upstream.destroy(new Error(`订阅内容超过 ${MAX_FETCH_LABEL} 上限`))
        return
      }
      const chunks = []
      let size = 0
      upstream.on('data', (chunk) => {
        size += chunk.length
        // 不设上限时一个恶意/异常订阅就能把进程内存吃光。
        if (size > MAX_FETCH_BYTES) {
          upstream.destroy(new Error(`订阅内容超过 ${MAX_FETCH_LABEL} 上限`))
          return
        }
        chunks.push(chunk)
      })
      upstream.on('error', reject)
      upstream.on('end', () => {
        let body = Buffer.concat(chunks)
        try {
          const encoding = String(headerValue(upstream.headers, 'content-encoding') ?? '').toLowerCase()
          if (encoding.includes('br')) body = brotliDecompressSync(body, { maxOutputLength: MAX_FETCH_BYTES })
          else if (encoding.includes('gzip')) body = gunzipSync(body, { maxOutputLength: MAX_FETCH_BYTES })
          else if (encoding.includes('deflate')) body = inflateSync(body, { maxOutputLength: MAX_FETCH_BYTES })
        } catch (error) {
          reject(new Error(`订阅响应解压失败：${error.message}`))
          return
        }
        resolve({ status: upstream.statusCode ?? 0, headers: upstream.headers, body })
      })
    })
    req.setTimeout(30_000, () => req.destroy(new Error('订阅地址响应超时')))
    req.on('error', reject)
    req.end()
  })
}

/**
 * 手工跟随重定向：每一跳都校验 hostname 与 DNS 解析结果，避免 302 指向
 * 链路本地 / 云元数据。相对 Location 按当前地址解析；最多 5 跳。
 * 返回的是最终那一跳的响应，`subscription-userinfo` 等头自然来自最终响应。
 */
async function fetchWithDoH(target, userAgent, dohEndpoint, headersOnly = false, guard = undefined) {
  let current = target
  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
    let result
    try {
      result = await requestOnce(current, userAgent, dohEndpoint, headersOnly, guard)
    } catch (error) {
      if (hop === 0) throw error
      throw new Error(`第 ${hop} 次跳转（${current.href}）失败：${error?.message ?? '网络错误'}`)
    }
    const location = headerValue(result.headers, 'location')
    if (![301, 302, 303, 307, 308].includes(result.status) || !location) {
      return result
    }
    let next
    try {
      next = new URL(location, current)
    } catch {
      throw new Error(`第 ${hop + 1} 跳的 Location 无效：${location}`)
    }
    if (next.protocol !== 'http:' && next.protocol !== 'https:') {
      throw new Error(`第 ${hop + 1} 跳重定向到了不支持的协议（${next.protocol}）：${location}`)
    }
    try {
      guard?.(next)
    } catch (error) {
      throw new Error(`第 ${hop + 1} 跳（${next.href}）被拦截：${error?.message ?? '目标地址不被允许'}`)
    }
    current = next
  }
  throw new Error(`订阅地址重定向超过 ${MAX_REDIRECT_HOPS} 跳，已停止`)
}

async function handleFetch(url, options, res) {
  let target
  try {
    target = new URL(url)
  } catch {
    return json(res, 400, { error: '订阅地址无效' })
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return json(res, 400, { error: '只支持 http/https 订阅地址' })
  }
  try {
    assertAllowedTarget(target)
  } catch (error) {
    return json(res, 400, { error: `订阅地址被拦截：${error?.message ?? BLOCKED_TARGET_MESSAGE}` })
  }

  const userAgent = sanitizeUserAgent(options?.userAgent) || 'clash-verge/v2.4.2'
  // 配额探测只需要响应头；提前断开上游正文，避免每次刷新都下载整份订阅。
  const headersOnly = options?.headersOnly === true
  let dohEndpoint
  try {
    dohEndpoint = validatedDoHURL(options?.doh)
  } catch (error) {
    return json(res, 400, { error: error.message })
  }

  let upstream
  // 有 DoH 时用 http(s).request + 自定义 lookup（Node 的 fetch 不暴露 DNS）；
  // 没有 DoH 也走同一条路径，这样重定向策略、逐跳守卫和体积上限只有一份实现。
  try {
    upstream = await fetchWithDoH(target, userAgent, dohEndpoint, headersOnly, assertAllowedTarget)
  } catch (error) {
    return json(res, 502, { error: `订阅服务器无法访问：${error?.message ?? '网络错误'}` })
  }

  if (upstream.status < 200 || upstream.status >= 300) {
    return json(res, 502, { error: `订阅服务器返回 HTTP ${upstream.status}` })
  }
  const upstreamContentType = headerValue(upstream.headers, 'content-type')
  const headers = {
    'content-type': safeContentType(upstreamContentType ?? 'text/plain; charset=utf-8'),
  }
  if (upstreamContentType) headers['x-upstream-content-type'] = upstreamContentType
  const userinfo = headerValue(upstream.headers, 'subscription-userinfo')
  if (userinfo) headers['x-subscription-userinfo'] = userinfo
  const title = headerValue(upstream.headers, 'profile-title')
  if (title) headers['x-profile-title'] = title
  const interval = headerValue(upstream.headers, 'profile-update-interval')
  if (interval) headers['x-profile-update-interval'] = interval
  // 上游 ETag / Last-Modified：内置方案「是否有更新」只靠这两个响应头判断，
  // 不下载正文；上游没给时客户端会退回「URL + 拉取时间」。
  const etag = headerValue(upstream.headers, 'etag')
  if (etag) headers['x-upstream-etag'] = etag
  const lastModified = headerValue(upstream.headers, 'last-modified')
  if (lastModified) headers['x-upstream-last-modified'] = lastModified
  send(res, 200, upstream.body, headers)
}

/** TCP handshake latency. Abortable; default timeout 5s (cold DNS + 专线首包常 >2s). */
function probeTCP(host, port, timeoutMs = 5000, signal) {
  return new Promise((resolve) => {
    if (!host || !port) return resolve({ ok: false, error: 'invalid' })
    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      resolve(value)
    }
    const start = performance.now()
    const sock = connect(port, host, () => {
      const ms = Math.max(1, Math.round(performance.now() - start))
      sock.destroy()
      finish({ ok: true, ms })
    })
    const onAbort = () => { sock.destroy(new Error('aborted')) }
    signal?.addEventListener('abort', onAbort)
    sock.setTimeout(timeoutMs, () => { sock.destroy(new Error('timeout')) })
    sock.on('error', (err) => finish({ ok: false, error: err.code ?? err.message }))
    sock.on('close', () => {
      signal?.removeEventListener('abort', onAbort)
      // If we got here without settling, treat as unreachable.
      if (!settled) finish({ ok: false, error: 'closed' })
    })
  })
}

/** ICMP 通过系统 ping；无权限或命令不可用时由调用方回退 TCP。 */
function probeICMP(host, timeoutMs = 1200) {
  return new Promise((resolve) => {
    if (!host || !/^[A-Za-z0-9._:-]+$/.test(host)) return resolve({ ok: false, error: 'invalid' })
    const args = process.platform === 'win32'
      ? ['-n', '1', '-w', String(timeoutMs), host]
      : process.platform === 'darwin'
        ? ['-c', '1', '-W', String(timeoutMs), host]
        : ['-c', '1', '-W', String(Math.max(1, Math.ceil(timeoutMs / 1000))), host]
    execFile('ping', args, { timeout: timeoutMs + 300, windowsHide: true }, (err, stdout) => {
      if (err) return resolve({ ok: false, error: 'icmp_timeout' })
      const match = String(stdout).match(/(\d+(?:\.\d+)?)\s*ms/i)
      if (!match) return resolve({ ok: false, error: 'icmp_timeout' })
      resolve({ ok: true, ms: Math.max(1, Math.round(Number(match[1]))), method: 'icmp' })
    })
  })
}

// 首次探测常碰上 DNS 冷解析 / 运营商首包丢包，重试一次能把误判降下来。
const RETRYABLE_PROBE_ERRORS = new Set(['timeout', 'ETIMEDOUT', 'ENOTFOUND', 'ESERVFAIL', 'ECONNRESET', 'closed'])

async function probeOnce(host, port, timeout, signal) {
  try {
    return await Promise.race([
      probeTCP(host, port, timeout, signal),
      new Promise((r) => setTimeout(() => r({ ok: false, error: 'timeout' }), timeout + 200)),
    ])
  } catch (err) {
    return { ok: false, error: String(err?.message ?? err) }
  }
}

async function handleProbe(url, res) {
  const host = url.searchParams.get('host')?.trim()
  const portText = url.searchParams.get('port')
  const requested = Number(url.searchParams.get('timeout') ?? 5000) || 5000
  const timeout = Math.min(Math.max(requested, 1000), 10000)
  const port = Number(portText)
  const mode = (url.searchParams.get('mode') ?? 'tcp').toLowerCase()
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    return json(res, 400, { ok: false, error: 'host/port 无效' })
  }
  try {
    if (mode === 'icmp') {
      const result = await probeICMP(host, Math.min(timeout, 1500))
      return result.ok
        ? json(res, 200, { ok: true, ms: result.ms, method: 'icmp', attempts: 1 })
        : json(res, 200, { ok: false, error: result.error, attempts: 1 })
    }
    let attempts = 0
    if (mode === 'automatic') {
      const icmp = await probeICMP(host, Math.min(timeout, 1500))
      if (icmp.ok) return json(res, 200, { ok: true, ms: icmp.ms, method: 'icmp', attempts: 1 })
      attempts = 1
    }
    // TCP：先按正常阈值；失败且属可重试错误时放宽阈值再探一次。
    let result = await probeOnce(host, port, timeout, res.destroyed ? AbortSignal.timeout(0) : undefined)
    attempts += 1
    if (!result.ok && RETRYABLE_PROBE_ERRORS.has(result.error) && !res.destroyed) {
      attempts += 1
      result = await probeOnce(host, port, Math.min(timeout * 2, 10000), undefined)
    }
    if (result.ok) {
      json(res, 200, { ok: true, ms: result.ms, method: 'tcp', attempts })
    } else {
      json(res, 200, { ok: false, error: result.error, attempts })
    }
  } catch (err) {
    json(res, 200, { ok: false, error: String(err?.message ?? err) })
  }
}

class RequestError extends Error {
  constructor(message, status = 400) {
    super(message)
    this.status = status
  }
}

async function readBody(req, maxBytes = 8 * 1024 * 1024) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > maxBytes) throw new RequestError('内容过大', 413)
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
}

const server = createServer(async (req, res) => {
  try {
    // Host / 请求目标都来自外部输入；畸形 Host（例如单个 `%`）会让 new URL
    // 抛出，而 async 监听器里的异常不会经过下面的响应逻辑，会直接终止进程。
    // 这里先兜底成 400，避免一条坏请求把整个本地服务打掉。
    let url
    try {
      url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    } catch {
      return send(res, 400, 'bad request', {
        'content-type': 'text/plain; charset=utf-8',
      })
    }
    const loopbackRequest = isLoopbackRequest(req)
    const containerHostRequest = isContainerHostLocalRequest(req)
    // 带正确密钥的请求顺手种下 cookie，让局域网里打开的页面后续 fetch 自动带上密钥。
    if (!loopbackRequest && serverSettings.apiToken && apiTokenMatches(presentedAPIToken(req, url))) {
      rememberAPIToken(res)
    }
    if (url.pathname.startsWith('/api/')) {
      // 工作区接口永远需要密钥：服务器模式下 127.0.0.1 也不例外，
      // 否则局域网客户端伪造 Host 就能读写整份工作区。
      const workspacePath = url.pathname === '/api/workspace'
        || url.pathname === '/api/workspace/version'
        || url.pathname === '/api/workspace/history'
        || url.pathname.startsWith('/api/workspace/history/')
        // 上游状态来自工作区快照指针，和读工作区一样需要密钥。
        || url.pathname === '/api/upstream-status'
        || url.pathname === '/api/upstream-status/check'
      const authExempt = apiAuthExempt(url, req.method)
      // 同一 IP 连续认证失败后先冷却，连正确密钥也会短暂被拒。
      const cooldown = authExempt ? 0 : authCooldownRemaining(req)
      if (cooldown > 0) {
        const retryAfter = Math.ceil(cooldown / 1000)
        return send(res, 429, JSON.stringify({
          error: `认证失败次数过多，请 ${retryAfter} 秒后再试`,
          code: 'too_many_attempts',
        }), {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
          'retry-after': String(retryAfter),
        })
      }
      // 容器宿主机与局域网客户端都可能表现为「私有地址 + Host: localhost」。
      // 关闭共享时只给它保留恢复设置所需的端点；订阅、规则集、代理等数据/代理
      // 端点不能因为伪造 Host 继续可用。
      const containerHostRecoveryPath = url.pathname === '/api/settings'
        || url.pathname === '/api/auth-status'
        || url.pathname === '/api/health'
      if (!loopbackRequest
        && !serverSettings.lanSharing
        && url.pathname !== '/api/auth-status'
        && url.pathname !== '/api/health'
        && !(containerHostRequest && containerHostRecoveryPath)) {
        return json(res, 403, { error: '局域网共享已关闭', code: 'lan_disabled' })
      }
      if (workspacePath) {
        if (!SERVER_MODE) {
          return json(res, 404, {
            error: '服务器版未启用（TOWER_MODE=server）',
            code: 'workspace_disabled',
          })
        }
        if (!serverSettings.apiToken) {
          return json(res, 401, {
            error: '服务器模式必须设置访问密钥（TOWER_API_TOKEN）',
            code: 'workspace_key_required',
          })
        }
        if (!apiTokenMatches(presentedAPIToken(req, url))) {
          recordAuthFailure(req)
          return json(res, 401, { error: '访问密钥无效', code: 'auth_required' })
        }
        resetAuthFailures(req)
      } else if (serverSettings.apiToken
        && !authExempt
        && !loopbackRequest
        && !apiTokenMatches(presentedAPIToken(req, url))) {
        // 容器内 Host: localhost 只能用来识别宿主机页面，不能代替管理密钥；
        // 否则局域网客户端伪造 Host 就能读取 settings.json 里的密钥。
        recordAuthFailure(req)
        return json(res, 401, { error: '需要访问密钥', code: 'auth_required' })
      }
    }

    if (url.pathname === '/api/workspace' || url.pathname === '/api/workspace/version') {
      return await handleWorkspace(url, req, res)
    }

    if (url.pathname === '/api/workspace/history' || url.pathname.startsWith('/api/workspace/history/')) {
      return await handleWorkspaceHistory(url, req, res)
    }

    if (url.pathname === '/api/upstream-status' || url.pathname === '/api/upstream-status/check') {
      return await handleUpstreamStatus(url, req, res)
    }

    if (url.pathname === '/api/auth-status') {
      return json(res, 200, authStatus(req, url))
    }

    if (url.pathname.startsWith('/api/settings')) {
      const settingsAction = url.pathname === '/api/settings/token' ? 'token' : req.method === 'GET' ? 'read' : 'write'
      if (!canManageSettings(req, url, settingsAction)) {
        return json(res, 403, { error: '访问密钥设置只能在服务端本机修改', code: 'local_only' })
      }
      if (url.pathname === '/api/settings' && req.method === 'GET') {
        return json(res, 200, { ...settingsPayload(), local: true })
      }
      if (url.pathname === '/api/settings' && req.method === 'PUT') {
        const raw = await readBody(req)
        let payload
        try {
          payload = JSON.parse(raw.toString('utf8') || '{}')
        } catch {
          return json(res, 400, { error: '请求内容不是 JSON' })
        }
        if (typeof payload?.lanSharing !== 'boolean') {
          return json(res, 400, { error: 'lanSharing 必须是布尔值' })
        }
        serverSettings.lanSharing = payload.lanSharing
        persistServerSettings()
        return json(res, 200, { ...settingsPayload(), local: true })
      }
      if (url.pathname === '/api/settings/token' && req.method === 'POST') {
        serverSettings.apiToken = randomBytes(24).toString('base64url')
        persistServerSettings()
        return json(res, 200, { ...settingsPayload(), local: true })
      }
      if (url.pathname === '/api/settings/token' && req.method === 'DELETE') {
        serverSettings.apiToken = ''
        persistServerSettings()
        return json(res, 200, { ...settingsPayload(), local: true })
      }
    }

    if (url.pathname === '/api/fetch' && req.method === 'GET') {
      const target = url.searchParams.get('url')
      if (!target) return json(res, 400, { error: '缺少 url 参数' })
      return await handleFetch(target, {
        userAgent: url.searchParams.get('ua') ?? '',
        doh: url.searchParams.get('doh') ?? '',
        headersOnly: url.searchParams.get('headers') === '1',
      }, res)
    }

    // 规则集转换：把经典 Clash 列表托管成 QuanX / Egern / sing-box source 方言。
    // 客户端配置里的 RULE-SET 地址指向这里，因此不需要安装额外的转换服务。
    if (url.pathname === '/api/ruleset' && req.method === 'GET') {
      try {
        const cacheKey = ruleSetCacheKey(url.searchParams)
        let artifact = cacheKey ? cachedRuleSet(cacheKey) : undefined
        // 自检与线上排查都依赖这个头确认缓存键是否真正命中。
        const cacheState = artifact ? 'hit' : 'miss'
        if (!artifact) {
          artifact = await buildRuleSetArtifact(url.searchParams)
          cacheRuleSet(artifact.key, artifact)
        }
        return send(res, 200, artifact.body, {
          'content-type': artifact.contentType,
          'cache-control': 'public, max-age=3600',
          'x-tower-ruleset-format': url.searchParams.get('format') ?? '',
          'x-tower-ruleset-rules': String(artifact.ruleCount),
          'x-tower-ruleset-cache': cacheState,
        })
      } catch (error) {
        const status = error instanceof RuleSetConversionError ? error.status : 500
        return send(res, status, String(error?.message ?? error), {
          'content-type': 'text/plain; charset=utf-8',
          'cache-control': 'no-store',
        })
      }
    }

    if (url.pathname === '/api/probe' && req.method === 'GET') {
      return await handleProbe(url, res)
    }

    if (url.pathname === '/api/ip-country' && req.method === 'GET') {
      return await handleIPCountry(url, res)
    }

    if (url.pathname === '/api/share' && req.method === 'POST') {
      const body = await readBody(req)
      if (body.length === 0) return json(res, 400, { error: '内容为空' })
      const token = randomBytes(12).toString('base64url')
      shares.set(token, {
        body,
        contentType: req.headers['content-type'] ?? 'text/plain; charset=utf-8',
        expiresAt: Date.now() + SHARE_TTL_MS,
        used: false,
      })
      const name = normalizeSubscriptionTitle(url.searchParams.get('name'), '')
      return json(res, 200, {
        token,
        url: `/api/s/${token}${name ? `?name=${encodeURIComponent(name)}` : ''}`,
        expiresIn: 180,
      })
    }

    const shareMatch = url.pathname.match(/^\/api\/s\/([A-Za-z0-9_-]+)$/)
    if (shareMatch && req.method === 'GET') {
      const share = shares.get(shareMatch[1])
      if (!share || share.used || share.expiresAt < Date.now()) {
        return send(res, 410, '链接已失效（临时导入链接 3 分钟内有效，且只能使用一次）', {
          'content-type': 'text/plain; charset=utf-8',
        })
      }
      share.used = true
      return send(res, 200, share.body, {
        'content-type': safeContentType(share.contentType),
        'cache-control': 'no-store',
      })
    }

    if (url.pathname === '/api/health') {
      // 进程活着但数据目录不可写时返回 503：Docker 会显示 unhealthy，
      // 让「healthy 但工作区永远为空」这类部署事故在 docker ps 就看得见。
      const dataWritable = dataDirWritable()
      return json(res, dataWritable ? 200 : 503, {
        ok: dataWritable,
        dataWritable,
        formats: SUB_FORMATS,
        subscriptions: subscriptions.size,
        uptimeSec: Math.round(process.uptime()),
      })
    }

    // 供前端把「手机可用的订阅地址」显示出来：列出真实网卡的局域网地址。
    if (url.pathname === '/api/network') {
      const lan = []
      if (PUBLIC_URL) lan.push(PUBLIC_URL)
      if (HOST === '0.0.0.0') lan.push(...lanUrls(PORT))
      return json(res, 200, {
        host: HOST,
        port: PORT,
        lan,
        local: `http://127.0.0.1:${PORT}`,
        // 服务器模式下订阅地址以 publicUrl 为准；为空时前端会明确提示配置。
        publicUrl: PUBLIC_URL,
        publicUrlConfigured: !!PUBLIC_URL,
        publicUrlError: PUBLIC_URL_ERROR,
        lanSharing: serverSettings.lanSharing,
        requiresAuth: !!serverSettings.apiToken,
      })
    }

    // --- Persistent subscription URL: browser POSTs current node list,
    // returns a durable URL any proxy client can import. Everything stays local;
    // subscriptions are persisted to server/subscriptions.json so a restart
    // does not invalidate links clients already saved.
    if (url.pathname === '/api/subscribe' && req.method === 'POST') {
      const raw = await readBody(req, 16 * 1024 * 1024)
      if (raw.length === 0) return json(res, 400, { error: '内容为空' })
      const contentType = String(req.headers['content-type'] ?? '')
      let title = normalizeSubscriptionTitle(url.searchParams.get('title'))
      let formats
      let targets = {}
      if (contentType.includes('application/json')) {
        let parsed
        try {
          parsed = JSON.parse(raw.toString('utf8'))
        } catch {
          return json(res, 400, { error: 'JSON 解析失败' })
        }
        if (typeof parsed?.title === 'string' && parsed.title) {
          title = normalizeSubscriptionTitle(parsed.title)
        }
        const src = parsed?.formats ?? {}
        formats = {}
        for (const key of SUB_FORMATS) {
          if (typeof src[key] === 'string' && src[key].length > 0) formats[key] = src[key]
        }
        if (Object.keys(formats).length === 0) return json(res, 400, { error: '没有可用格式' })
        // 目标专属变体（Stash / Surge Mac / 不支持 Tailscale 的客户端）。
        const srcTargets = parsed?.targets
        if (srcTargets && typeof srcTargets === 'object' && !Array.isArray(srcTargets)) {
          for (const [rawKey, value] of Object.entries(srcTargets)) {
            const key = canonicalSubTarget(rawKey)
            if (key && typeof value === 'string' && value.length > 0) targets[key] = value
          }
        }
      } else {
        // 兼容旧客户端：纯文本 body 视为 base64 节点列表
        formats = { base64: raw.toString('utf8') }
      }
      let token
      let isRefresh
      if (SERVER_MODE) {
        // 服务器模式只有一个规范订阅链接：忽略客户端传来的 token，
        // 所有设备发布都写到同一个 slot，避免一个工作区散出多条地址。
        token = serverSettings.subscriptionToken
        if (!token) {
          ensureWorkspaceSubscriptionToken()
          token = serverSettings.subscriptionToken
        }
        isRefresh = subscriptions.has(token)
      } else {
        token = String(url.searchParams.get('token') ?? '').trim()
        if (token && !normalizeAPIToken(token)) {
          return json(res, 400, { error: '订阅 token 无效' })
        }
        isRefresh = !!token
        if (!token) token = randomBytes(16).toString('base64url')
      }
      subscriptions.set(token, {
        formats,
        targets,
        updatedAt: Date.now(),
        title,
      })
      persistSubscriptions()
      const path = `/api/sub/${token}?name=${encodeURIComponent(title)}`
      return json(res, 200, {
        token,
        // 服务器模式尽量返回绝对规范地址；未配置 TOWER_PUBLIC_URL 时退回相对路径，
        // 由前端用当前 origin 兜底并给出明确提示。
        url: SERVER_MODE && PUBLIC_URL ? `${PUBLIC_URL}${path}` : path,
        ...(SERVER_MODE ? { publicUrl: PUBLIC_URL, publicUrlError: PUBLIC_URL_ERROR } : {}),
        formats: Object.keys(formats),
        refreshed: isRefresh,
      })
    }

    const subMatch = url.pathname.match(/^\/api\/sub\/([A-Za-z0-9_-]+)$/)
    if (subMatch && req.method === 'GET') {
      const sub = subscriptions.get(subMatch[1])
      if (!sub) {
        return send(res, 404, '订阅地址无效。请到塔台 Tower Web 重新生成订阅链接。', {
          'content-type': 'text/plain; charset=utf-8',
        })
      }
      const fmt = resolveSubFormat(
        url.searchParams.get('format'),
        url.searchParams.get('target'),
        req.headers['user-agent'],
      )
      if (!fmt) {
        return send(res, 400, '无法识别客户端。请在链接中使用 target=clash、surge、surfboard、loon、quanx、shadowrocket、sing-box、hiddify 或 egern。', {
          'content-type': 'text/plain; charset=utf-8',
        })
      }
      // 明确请求了某个格式却没有该载体时返回 406，而不是悄悄给 base64
      // （Clash 收到 base64 会报“订阅创建失败”，错误信息反而不如 406 清楚）。
      const requestedTarget = canonicalSubTarget(url.searchParams.get('target'))
        ?? subTargetFromUserAgent(req.headers['user-agent'])
      const variant = requestedTarget && SUB_TARGET_FORMAT[requestedTarget] === fmt
        ? sub.targets?.[requestedTarget]
        : undefined
      // 旧版 Egern 链接请求的是 yaml，新链接请求 egern；旧发布记录没有
      // egern 载体时回退到 yaml，避免升级后旧链接直接 406。
      let payload = variant ?? sub.formats[fmt]
      let servedFormat = fmt
      if (!payload && fmt === 'egern' && sub.formats.yaml) {
        payload = sub.formats.yaml
        servedFormat = 'yaml'
      }
      if (!payload) {
        return send(res, 406, `该订阅不包含 ${fmt} 格式，可用：${Object.keys(sub.formats).join(', ') || '无'}`, {
          'content-type': 'text/plain; charset=utf-8',
        })
      }
      const name = normalizeSubscriptionTitle(url.searchParams.get('name') ?? sub.title)
      // HTTP 头只接受 latin1；中文标题会触发 ERR_INVALID_CHAR，这里做 ASCII 兜底。
      const asciiName = String(name).replace(/[^\x20-\x7E]/g, '').trim() || 'tower'
      // 服务器模式的规范地址固定为 TOWER_PUBLIC_URL；否则订阅正文里的规则集
      // 地址仍会跟随请求 Host，同一个 token 从不同入口拉取会得到不同配置。
      const ruleSetOrigin = SERVER_MODE && PUBLIC_URL ? PUBLIC_URL : url.origin
      return send(res, 200, rewriteRuleSetOrigins(payload, ruleSetOrigin), {
        'content-type': SUB_MIME[servedFormat],
        'cache-control': 'no-store',
        'x-tower-format': servedFormat,
        'profile-title': asciiName,
        'profile-update-interval': '24',
        // 让客户端识别这是订阅而非普通文本
        'content-disposition': `attachment; filename="${encodeURIComponent(name)}.${SUB_EXT[servedFormat]}"`,
      })
    }

    const subDeleteMatch = url.pathname.match(/^\/api\/sub\/([A-Za-z0-9_-]+)$/)
    if (subDeleteMatch && req.method === 'DELETE') {
      const requested = subDeleteMatch[1]
      if (SERVER_MODE) {
        // 服务器模式的“撤销”是重置工作区链接：旧 canonical 立即失效，
        // 新 token 接管同一份已发布内容，所有设备下次同步都会落到新地址。
        // 不按路径里的 token 判断：设备本地可能还存着升级前的旧 token。
        const previous = serverSettings.subscriptionToken
        const current = subscriptions.get(previous)
        const next = randomBytes(16).toString('base64url')
        if (current) {
          subscriptions.set(next, { ...current, updatedAt: Date.now() })
          subscriptions.delete(previous)
        }
        serverSettings.subscriptionToken = next
        persistServerSettings()
        persistSubscriptions()
        const title = normalizeSubscriptionTitle(current?.title)
        const path = `/api/sub/${next}?name=${encodeURIComponent(title)}`
        return json(res, 200, {
          ok: true,
          reset: true,
          token: next,
          url: PUBLIC_URL ? `${PUBLIC_URL}${path}` : path,
          publicUrl: PUBLIC_URL,
          publicUrlError: PUBLIC_URL_ERROR,
        })
      }
      subscriptions.delete(requested)
      persistSubscriptions()
      return json(res, 200, { ok: true })
    }

    // 未匹配的 /api/* 一律返回 JSON 404，绝不能回落成 index.html
    // （否则客户端拿到 HTML 会报「订阅创建失败」，且难以排查）
    if (url.pathname.startsWith('/api/')) {
      return json(res, 404, { error: '接口不存在', path: url.pathname })
    }

    // Static files (production build).
    if (existsSync(distDir)) {
      let filePath = normalize(join(distDir, decodeURIComponent(url.pathname)))
      // 使用 sep 校验，避免 dist-evil 之类的同前缀兄弟目录被误判为 dist 内部。
      if (filePath !== distDir && !filePath.startsWith(distDir + sep)) {
        return send(res, 403, 'forbidden')
      }
      if (!existsSync(filePath) || url.pathname === '/' || url.pathname.endsWith('/')) {
        filePath = join(distDir, 'index.html')
      }
      try {
        const content = await readFile(filePath)
        const isIndex = extname(filePath) === '.html'
        // 只有 Vite 生成的 /assets/* 带内容哈希；logo / 客户端图标等可能被替换，
        // 不能用 immutable 缓存，否则用户换图后一年都看不到新文件。
        const isHashedAsset = url.pathname.startsWith('/assets/')
        return send(res, 200, content, {
          'content-type': MIME[extname(filePath)] ?? 'application/octet-stream',
          'cache-control': isIndex || !isHashedAsset
            ? 'no-cache, must-revalidate'
            : 'public, max-age=31536000, immutable',
        })
      } catch {
        return send(res, 404, 'not found')
      }
    }

    json(res, 404, { error: 'not found' })
  } catch (error) {
    // 已经写出响应头后不能再写 JSON；直接断开连接，避免二次 writeHead
    // 在 catch 里再次抛出、变成未处理的 Promise 拒绝。
    if (res.headersSent || res.writableEnded) {
      res.destroy()
      return
    }
    try {
      const status = error instanceof RequestError ? error.status : 500
      json(res, status, { error: String(error?.message ?? error) })
    } catch {
      res.destroy()
    }
  }
})

server.listen(PORT, HOST, () => {
  // PORT=0 时由系统分配端口，日志必须用实际监听端口。
  const bound = server.address()
  const actualPort = bound && typeof bound === 'object' ? bound.port : PORT
  console.log(`[tower-web] companion server on http://127.0.0.1:${actualPort}`)
  if (SERVER_MODE) {
    console.log(`[tower-web] 服务器模式：工作区保存在 ${WORKSPACE_FILE}`)
    if (!dataDirWritable()) {
      console.warn(
        `[tower-web] 数据目录不可写（${DATA_DIR}）：工作区改动会全部失败。`
        + ' Docker 中请确认挂载目录对容器内 node 用户可写，例如宿主机执行 chown -R 1000:1000 <挂载目录>。',
      )
    }
    if (!serverSettings.apiToken) {
      console.warn('[tower-web] 服务器模式必须设置访问密钥（TOWER_API_TOKEN），否则 /api/workspace 会拒绝所有请求')
    }
    if (PUBLIC_URL) {
      console.log(`[tower-web] 固定订阅地址前缀：${PUBLIC_URL}`)
    } else if (PUBLIC_URL_ERROR) {
      console.warn(`[tower-web] TOWER_PUBLIC_URL 无效（${PUBLIC_URL_ERROR}）：不同设备仍可能得到不同订阅地址`)
    } else {
      console.warn('[tower-web] 未配置 TOWER_PUBLIC_URL：不同设备打开时订阅地址的 host 可能不同，建议配置为对外访问地址')
    }
    // 只安排定时器；重启后至少等 TOWER_UPSTREAM_CHECK_INITIAL_DELAY_MS 才检查。
    upstreamChecker?.start()
  }
  if (HOST === '0.0.0.0') {
    for (const u of lanUrls(actualPort)) console.log(`[tower-web] 局域网可访问: ${u}`)
    console.log(`[tower-web] 局域网共享：${serverSettings.lanSharing ? '开启' : '关闭'} · API 密钥：${serverSettings.apiToken ? '已启用' : '未启用'}`)
    if (!serverSettings.apiToken) {
      console.log('[tower-web] 可在「订阅设置 → 局域网与访问密钥」生成密钥；不需要局域网时也可用 HOST=127.0.0.1 启动')
    }
  } else {
    console.log('[tower-web] 仅本机可访问（HOST=0.0.0.0 可开放局域网）')
  }
})
