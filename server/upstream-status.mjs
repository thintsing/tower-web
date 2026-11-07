// 服务端定时检查 ACL4SSR 内置方案的上游版本。
//
// 硬约束：
// - 检查结果只写 $TOWER_DATA_DIR/upstream-status.json，绝不写 workspace.json。
//   否则每次检查都会让工作区版本号 +1，所有设备都会被唤醒拉一遍数据。
// - 只检查，不固化。发现新版本只更新状态，用户仍然自己在规则页点「更新并固化」。
// - 失败后至少隔 6 小时再试，避免限流时形成重试风暴。
// - 进程重启后先等 initialDelay，不当场全量检查；已到期的 nextCheckAt 会被尊重。

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  ACL4SSR_PIN_COMMIT,
  checkUpstreamBaseline,
  commitsBehind,
} from './upstream-check.mjs'

export const UPSTREAM_STATUS_FILE = 'upstream-status.json'
export const DEFAULT_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000
export const FAILURE_BACKOFF_MS = 6 * 60 * 60 * 1000
export const DEFAULT_INITIAL_DELAY_MS = 5 * 60 * 1000
/** 与 src/rules/scheme.ts 的 BUILTIN_SCHEMES 同步。 */
export const BUILTIN_UPSTREAM_SCHEMES = [
  { id: 'acl4ssr-online', name: 'ACL4SSR 在线版', file: 'ACL4SSR_Online.ini' },
  { id: 'acl4ssr-mini', name: 'ACL4SSR 精简版', file: 'ACL4SSR_Online_Mini.ini' },
  { id: 'acl4ssr-full', name: 'ACL4SSR 全分组版', file: 'ACL4SSR_Online_Full.ini' },
]

function isRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value)
}

function positiveInteger(value, fallback) {
  const number = Number(value)
  return Number.isInteger(number) && number > 0 ? number : fallback
}

/** 环境变量：TOWER_UPSTREAM_CHECK=off 关闭；间隔/启动延迟均可用毫秒覆盖。 */
export function upstreamCheckSettings(env = process.env) {
  const flag = String(env.TOWER_UPSTREAM_CHECK ?? '').trim().toLowerCase()
  const disabled = ['off', '0', 'false', 'no', 'disabled'].includes(flag)
  return {
    disabled,
    intervalMs: positiveInteger(env.TOWER_UPSTREAM_CHECK_INTERVAL_MS, DEFAULT_CHECK_INTERVAL_MS),
    initialDelayMs: positiveInteger(env.TOWER_UPSTREAM_CHECK_INITIAL_DELAY_MS, DEFAULT_INITIAL_DELAY_MS),
  }
}

/** 只保留已知内置方案与白名单字段；损坏的条目直接丢弃，不阻断服务启动。 */
function normalizeSchemeResult(meta, raw, fallbackCheckedAt) {
  const value = isRecord(raw) ? raw : {}
  const status = ['update', 'current', 'error'].includes(value.status) ? value.status : 'unknown'
  const commit = typeof value.commit === 'string' && /^[0-9a-f]{7,40}$/i.test(value.commit)
    ? value.commit
    : null
  const baseline = isRecord(value.baseline) ? value.baseline : {}
  return {
    id: meta.id,
    name: meta.name,
    status,
    frozen: value.frozen === true,
    baseline: {
      kind: baseline.kind === 'snapshot' ? 'snapshot' : 'pin',
      commitShort: typeof baseline.commitShort === 'string' ? baseline.commitShort.slice(0, 7) : '',
    },
    commit,
    commitShort: commit ? commit.slice(0, 7) : null,
    behindBy: Number.isInteger(value.behindBy) && value.behindBy >= 0 ? value.behindBy : null,
    method: value.method === 'head' ? 'head' : value.method === 'trees' ? 'trees' : null,
    changedFiles: Array.isArray(value.changedFiles)
      ? value.changedFiles.filter((item) => typeof item === 'string').slice(0, 64)
      : [],
    error: typeof value.error === 'string' ? value.error.slice(0, 500) : '',
    checkedAt: Number.isFinite(value.checkedAt) ? Number(value.checkedAt) : (fallbackCheckedAt ?? null),
  }
}

export function normalizeUpstreamStatus(raw) {
  const value = isRecord(raw) ? raw : {}
  const results = {}
  const rawResults = isRecord(value.results) ? value.results : {}
  for (const meta of BUILTIN_UPSTREAM_SCHEMES) {
    results[meta.id] = normalizeSchemeResult(meta, rawResults[meta.id], Number(value.checkedAt) || null)
  }
  return {
    checkedAt: Number.isFinite(value.checkedAt) ? Number(value.checkedAt) : null,
    nextCheckAt: Number.isFinite(value.nextCheckAt) ? Number(value.nextCheckAt) : null,
    trigger: typeof value.trigger === 'string' ? value.trigger : '',
    lastError: typeof value.lastError === 'string' ? value.lastError.slice(0, 500) : '',
    results,
  }
}

/** 读取结果文件；不存在返回空状态，损坏返回 corrupt=true（调用方只记日志）。 */
export function readUpstreamStatusFile(dataDir) {
  const path = join(dataDir, UPSTREAM_STATUS_FILE)
  let raw
  try {
    raw = readFileSync(path, 'utf8')
  } catch {
    return { status: null, corrupt: false, path }
  }
  try {
    const parsed = JSON.parse(raw)
    if (!isRecord(parsed)) throw new Error('顶层不是对象')
    return { status: normalizeUpstreamStatus(parsed), corrupt: false, path }
  } catch {
    return { status: null, corrupt: true, path }
  }
}

/** 原子写（.tmp + rename）；失败只返回 false，绝不阻断检查之外的服务。 */
export function writeUpstreamStatusFile(dataDir, status) {
  const path = join(dataDir, UPSTREAM_STATUS_FILE)
  try {
    mkdirSync(dataDir, { recursive: true })
    const body = JSON.stringify({ version: 1, ...status })
    writeFileSync(`${path}.tmp`, body, 'utf8')
    renameSync(`${path}.tmp`, path)
    return true
  } catch {
    return false
  }
}

/**
 * 已固化过：与快照 source 的 commit / blob sha 比；
 * 从未固化：与构建时内置快照的 pin commit 比（让用户知道自带版本落后多少）。
 */
export function resolveUpstreamBaseline(workspaceData, schemeID) {
  const data = isRecord(workspaceData) ? workspaceData : {}
  const overrides = isRecord(data.builtinSchemeOverrides) ? data.builtinSchemeOverrides : {}
  const snapshots = isRecord(data.schemeSnapshots) ? data.schemeSnapshots : {}
  const ref = isRecord(overrides[schemeID]) ? overrides[schemeID] : null
  const snapshotId = ref && (typeof ref.snapshotId === 'number' || typeof ref.snapshotId === 'string')
    ? String(ref.snapshotId)
    : ''
  const snapshot = snapshotId ? snapshots[snapshotId] : null
  const source = isRecord(snapshot) && isRecord(snapshot.source) ? snapshot.source : null
  if (source && typeof source.commitSha === 'string' && /^[0-9a-f]{7,40}$/i.test(source.commitSha)) {
    return {
      kind: 'snapshot',
      commitSha: source.commitSha,
      files: Array.isArray(source.files)
        ? source.files
          .filter((file) => isRecord(file) && typeof file.path === 'string' && typeof file.blobSha === 'string')
          .map((file) => ({
            path: file.path,
            blobSha: file.blobSha,
            ...(typeof file.etag === 'string' ? { etag: file.etag } : {}),
          }))
        : [],
    }
  }
  return { kind: 'pin', commitSha: ACL4SSR_PIN_COMMIT, files: [] }
}

/** 只读工作区、只发版本比对请求；任何情况下都不调用 commitWorkspace。 */
export async function checkBuiltinSchemes(options) {
  const {
    workspaceData,
    fetchText,
    fetchHeaders,
    now = Date.now(),
    behindCache,
  } = options
  const results = {}
  for (const meta of BUILTIN_UPSTREAM_SCHEMES) {
    const baseline = resolveUpstreamBaseline(workspaceData, meta.id)
    let outcome
    try {
      outcome = await checkUpstreamBaseline(
        { commitSha: baseline.commitSha, files: baseline.files },
        { fetchText, fetchHeaders },
      )
    } catch (error) {
      outcome = {
        checked: false,
        updateAvailable: false,
        method: 'trees',
        changedFiles: [],
        error: error?.message ?? String(error),
      }
    }
    let status = 'unknown'
    if (!outcome.checked) status = 'error'
    else if (outcome.updateAvailable) status = 'update'
    else if (outcome.error) status = 'error'
    else status = 'current'

    let behindBy = null
    if (baseline.kind === 'pin' && outcome.updateAvailable && outcome.commitSha) {
      behindBy = await commitsBehind(fetchText, baseline.commitSha, behindCache)
    }

    results[meta.id] = {
      id: meta.id,
      name: meta.name,
      status,
      frozen: baseline.kind === 'snapshot',
      baseline: { kind: baseline.kind, commitShort: baseline.commitSha.slice(0, 7) },
      commit: outcome.commitSha ?? null,
      commitShort: outcome.commitSha ? outcome.commitSha.slice(0, 7) : null,
      behindBy,
      method: outcome.method ?? null,
      changedFiles: Array.isArray(outcome.changedFiles) ? outcome.changedFiles : [],
      error: typeof outcome.error === 'string' ? outcome.error : '',
      checkedAt: now,
    }
  }
  return results
}

/**
 * 定时器与状态文件的组合。start() 只安排下一次，不会当场检查；
 * runNow() 供手动入口与自检使用。
 */
export function createUpstreamChecker(options) {
  const {
    dataDir,
    getWorkspaceData,
    fetchText,
    fetchHeaders,
    env = process.env,
    logger = console,
    now = () => Date.now(),
    setTimer = (fn, ms) => setTimeout(fn, ms),
    clearTimer = (id) => clearTimeout(id),
  } = options
  const settings = upstreamCheckSettings(env)
  let status = {
    checkedAt: null,
    nextCheckAt: null,
    trigger: '',
    lastError: '',
    results: {},
  }
  let timer = null
  let running = null
  let started = false
  let stopped = false

  function load() {
    const loaded = readUpstreamStatusFile(dataDir)
    if (loaded.corrupt) {
      logger.warn?.(`[tower] 上游检查结果文件损坏，已忽略并重新开始：${loaded.path}`)
    }
    if (loaded.status) status = loaded.status
  }

  function persist(next) {
    if (!writeUpstreamStatusFile(dataDir, next)) {
      logger.warn?.('[tower] 上游检查结果写入失败（不影响正常服务）')
    }
  }

  function scheduleAt(nextCheckAt) {
    if (stopped || settings.disabled) return
    if (timer !== null) clearTimer(timer)
    const delay = Math.max(0, nextCheckAt - now())
    timer = setTimer(() => {
      timer = null
      void run('timer')
    }, delay)
    timer?.unref?.()
  }

  async function run(trigger) {
    if (settings.disabled) return { disabled: true, checking: false, status }
    if (running) return running
    const startedAt = now()
    running = (async () => {
      let results = {}
      let failure = ''
      try {
        results = await checkBuiltinSchemes({
          workspaceData: getWorkspaceData(),
          fetchText,
          fetchHeaders,
          now: startedAt,
          behindCache: new Map(),
        })
      } catch (error) {
        failure = error?.message ?? String(error)
      }
      const hasError = !!failure || Object.values(results).some((item) => item?.status === 'error')
      const next = {
        checkedAt: startedAt,
        nextCheckAt: startedAt + (hasError ? FAILURE_BACKOFF_MS : settings.intervalMs),
        trigger,
        lastError: failure || (hasError ? '部分内置方案检查失败（查不到上游状态，不等于没有更新）' : ''),
        results,
      }
      status = next
      persist(next)
      scheduleAt(next.nextCheckAt)
      return { disabled: false, checking: false, status: next }
    })()
    try {
      return await running
    } finally {
      running = null
    }
  }

  function start() {
    if (started) return
    started = true
    load()
    if (settings.disabled) {
      logger.log?.('[tower] 上游定时检查已关闭（TOWER_UPSTREAM_CHECK=off）')
      return
    }
    // 重启后不立刻全量检查：已排定的未来时间照旧，否则至少等 initialDelay。
    const nextCheckAt = status.nextCheckAt && status.nextCheckAt > now()
      ? status.nextCheckAt
      : now() + settings.initialDelayMs
    scheduleAt(nextCheckAt)
  }

  function stop() {
    stopped = true
    if (timer !== null) clearTimer(timer)
    timer = null
  }

  function getPayload() {
    return {
      enabled: !settings.disabled,
      intervalMs: settings.intervalMs,
      initialDelayMs: settings.initialDelayMs,
      checkedAt: status.checkedAt,
      nextCheckAt: status.nextCheckAt,
      trigger: status.trigger,
      lastError: status.lastError,
      checking: !!running,
      schemes: BUILTIN_UPSTREAM_SCHEMES.map((meta) =>
        normalizeSchemeResult(meta, status.results?.[meta.id], status.checkedAt)),
    }
  }

  /** 手动入口：异步触发，HTTP 立即返回，前端轮询 checking。 */
  function checkNow() {
    if (settings.disabled) return { disabled: true, checking: false }
    if (running) return { disabled: false, checking: true }
    void run('manual')
    return { disabled: false, checking: true }
  }

  return { start, stop, getPayload, checkNow, runNow: run }
}
