// 自检：把生成的配置交给真实内核校验，而不只是校验结构长得对。
// 用法：npx tsx scripts/selfcheck-kernels.ts
//
// 二进制来源按优先级：SING_BOX_BIN / MIHOMO_BIN 环境变量 → PATH → .kernel-cache/。
// Linux（CI）上找不到时自动下载；GitHub Actions 下两个内核都必须就位，
// 其他环境没有二进制时明确跳过。
//
// 刻意不含 GEOIP / GEOSITE 和远程 rule-set：内核校验它们需要地理数据库或联网，
// 会让离线自检变成不确定测试。这里覆盖的是代理、策略组、DNS 和内联规则语法。
import { execFileSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { gunzipSync } from 'node:zlib'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { generateConfig } from '../src/generator'
import { CLIENTS, type ClientTarget, type ProxyNode, type RuleScheme } from '../src/models/types'

const MIHOMO_VERSION = '1.19.31'
const SING_BOX_VERSION = '1.14.2'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const outDir = join(root, '.tmp-kernels')
const cacheDir = join(root, '.kernel-cache')
mkdirSync(outDir, { recursive: true })

const base = { tls: false, skipCertificateVerification: false, rawURI: '' } as const

const SAMPLE: ProxyNode[] = [
  { ...base, id: 'ss1', kind: 'ss', name: '样例 SS', server: 'ss.example.com', port: 8388, cipher: 'aes-256-gcm', password: 'p1' },
  { ...base, id: 'vm1', kind: 'vmess', name: '样例 VMess', server: 'vm.example.com', port: 443, uuid: '11111111-2222-3333-4444-555555555555', alterID: 0, cipher: 'auto', tls: true, sni: 'vm.example.com', transport: 'ws', path: '/ws', hostHeader: 'vm.example.com' },
  { ...base, id: 'tr1', kind: 'trojan', name: '样例 Trojan', server: 'tr.example.com', port: 443, password: 'p2', tls: true, sni: 'tr.example.com' },
  { ...base, id: 'hy1', kind: 'hysteria2', name: '样例 HY2', server: 'hy.example.com', port: 8443, password: 'p3', tls: true, sni: 'hy.example.com' },
]

const scheme: RuleScheme = {
  id: 'kernels',
  name: 'kernels',
  description: '',
  groups: [
    { name: '🚀 节点选择', type: 'select', options: ['DIRECT', '♻️ 自动选择'], nodeFilter: '.*' },
    { name: '♻️ 自动选择', type: 'url-test', options: [], nodeFilter: '.*' },
  ],
  rules: [
    { type: 'DOMAIN-SUFFIX', value: 'google.com', group: '🚀 节点选择' },
    { type: 'DOMAIN', value: 'example.com', group: 'DIRECT' },
    { type: 'IP-CIDR', value: '10.0.0.0/8', group: 'DIRECT', noResolve: true },
    { type: 'FINAL', group: '🚀 节点选择' },
  ] as RuleScheme['rules'],
  networkSettings: {
    ipv6Enabled: false,
    dnsServers: ['10.0.0.1'],
    encryptedDNSServers: ['https://dns.example/dns-query'],
    remoteDNSServers: ['https://8.8.4.4/dns-query'],
    proxyTestURLString: 'https://probe.example/204',
    dnsProtectionMode: 'standard',
  },
}

const client = (target: ClientTarget) => CLIENTS.find((item) => item.target === target)!

/** sing-box 系内核吃 JSON，mihomo 系吃 Clash YAML。 */
const SING_BOX_TARGETS: ClientTarget[] = ['sing-box', 'hiddify']
// 命名陷阱：'clash' 是 Stash，'clash-apple' 才是 Apple 上的 Clash。
const MIHOMO_TARGETS: ClientTarget[] = ['clash-verge', 'mihomo-party', 'clash', 'clash-apple']

let failures = 0
function check(label: string, run: () => void) {
  try {
    run()
    console.log(`  ✓ ${label}`)
  } catch (error) {
    failures += 1
    console.error(`  ✗ ${label}\n    ${error instanceof Error ? error.message : String(error)}`)
  }
}

function which(name: string): string | undefined {
  const probe = process.platform === 'win32' ? 'where' : 'which'
  try {
    const out = execFileSync(probe, [name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
    return out.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)[0]
  } catch {
    return undefined
  }
}

function download(url: string): Buffer {
  const res = execFileSync('curl', ['-fsSL', '--max-time', '180', url], { maxBuffer: 256 * 1024 * 1024 })
  return res
}

/** 只在 Linux 上自动取二进制：CI 是 ubuntu，其他平台请用环境变量指定。 */
function provisionLinux(kind: 'mihomo' | 'sing-box'): string | undefined {
  const arch = process.arch === 'arm64' ? 'arm64' : 'amd64'
  const dir = join(cacheDir, `${kind}-${kind === 'mihomo' ? MIHOMO_VERSION : SING_BOX_VERSION}-${arch}`)
  const bin = join(dir, kind === 'mihomo' ? 'mihomo' : 'sing-box')
  if (existsSync(bin)) return bin
  mkdirSync(dir, { recursive: true })
  if (kind === 'mihomo') {
    const url = `https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VERSION}/mihomo-linux-${arch}-v${MIHOMO_VERSION}.gz`
    writeFileSync(bin, gunzipSync(download(url)))
  } else {
    const url = `https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${arch}.tar.gz`
    const archive = join(dir, 'sing-box.tar.gz')
    writeFileSync(archive, download(url))
    // 官方 tar 里是 sing-box-<ver>-linux-<arch>/ 子目录，不剥掉这一层
    // 后面的 chmod / check 会指向不存在的路径。
    execFileSync('tar', ['-xzf', archive, '-C', dir, '--strip-components=1'], { stdio: 'ignore' })
  }
  if (!existsSync(bin)) return undefined
  chmodSync(bin, 0o755)
  return bin
}

function resolveBinary(kind: 'mihomo' | 'sing-box'): string | undefined {
  const envName = kind === 'mihomo' ? 'MIHOMO_BIN' : 'SING_BOX_BIN'
  const fromEnv = process.env[envName]?.trim()
  if (fromEnv) {
    if (!existsSync(fromEnv)) throw new Error(`${envName} 指向的文件不存在：${fromEnv}`)
    return fromEnv
  }
  const fromPath = which(kind)
  if (fromPath) return fromPath
  if (process.platform === 'linux') return provisionLinux(kind)
  return undefined
}

function runKernel(bin: string, args: string[], label: string) {
  try {
    execFileSync(bin, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000 })
  } catch (error) {
    const err = error as { stdout?: string; stderr?: string; message?: string }
    const detail = [err.stderr, err.stdout].filter(Boolean).join('\n').trim()
    throw new Error(`${label} 拒绝该配置\n${detail || err.message || '未知错误'}`)
  }
}

interface Artifact {
  target: string
  file: string
  kernel: 'sing-box' | 'mihomo'
  label: string
}

/** 先生成并落盘全部产物：即使没有内核，这些文件也能手工喂给客户端排查。 */
function buildArtifacts(): Artifact[] {
  const artifacts: Artifact[] = []
  for (const target of SING_BOX_TARGETS) {
    const file = join(outDir, `${target}.json`)
    writeFileSync(file, generateConfig(client(target), SAMPLE, scheme, { contentMode: 'full' }).text, 'utf8')
    artifacts.push({ target, file, kernel: 'sing-box', label: `sing-box check · ${target}` })
  }
  for (const target of MIHOMO_TARGETS) {
    const file = join(outDir, `${target}.yaml`)
    writeFileSync(file, generateConfig(client(target), SAMPLE, scheme, { contentMode: 'full' }).text, 'utf8')
    artifacts.push({ target, file, kernel: 'mihomo', label: `mihomo -t · ${target}` })
  }
  const nodesOnly = join(outDir, 'sing-box-nodes.json')
  writeFileSync(nodesOnly, generateConfig(client('sing-box'), SAMPLE, scheme, { contentMode: 'nodes' }).text, 'utf8')
  artifacts.push({ target: 'sing-box-nodes', file: nodesOnly, kernel: 'sing-box', label: 'sing-box check · 仅节点' })
  return artifacts
}

console.log('内核校验：sing-box / mihomo 真实解析生成产物')
const artifacts = buildArtifacts()
console.log(`  已生成 ${artifacts.length} 份产物 → .tmp-kernels/`)

const singBoxBin = resolveBinary('sing-box')
const mihomoBin = resolveBinary('mihomo')
// 只把 GitHub Actions 当作强制校验环境：本机即使设置了 CI=true 也允许跳过，
// 但 CI 里缺任何一个内核都算失败，不能只校验一半。
const REQUIRE_KERNELS = process.env.GITHUB_ACTIONS === 'true'
const missingHint = (kind: string, envName: string) =>
  `未找到 ${kind}。设置 ${envName}，或在 Linux 上运行以自动下载。`

if (!singBoxBin && !mihomoBin) {
  const message = missingHint('sing-box / mihomo', 'SING_BOX_BIN / MIHOMO_BIN')
  if (REQUIRE_KERNELS) throw new Error(`CI 必须执行内核校验：${message}`)
  console.log(`  SKIP ${message}`)
  process.exit(0)
}

for (const artifact of artifacts) {
  const bin = artifact.kernel === 'sing-box' ? singBoxBin : mihomoBin
  if (!bin) {
    if (REQUIRE_KERNELS) {
      const envName = artifact.kernel === 'sing-box' ? 'SING_BOX_BIN' : 'MIHOMO_BIN'
      throw new Error(`CI 必须执行内核校验：${missingHint(artifact.kernel, envName)}`)
    }
    console.log(`  SKIP ${artifact.label}（${artifact.kernel} 未找到）`)
    continue
  }
  const args = artifact.kernel === 'sing-box'
    ? ['check', '-c', artifact.file]
    : ['-t', '-d', outDir, '-f', artifact.file]
  check(artifact.label, () => runKernel(bin, args, artifact.kernel))
}

if (failures > 0) {
  console.error(`\n内核校验失败 ${failures} 项`)
  process.exit(1)
}
console.log('\n内核校验全部通过')