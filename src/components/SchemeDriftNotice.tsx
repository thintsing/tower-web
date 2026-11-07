// 内置方案上游漂移提示：展示 +N / −M / ~K，只有点「吸收」才更新，
// 「忽略」记住当前 commit，上游再次变化后重新提示。
import { useEffect, useState } from 'react'
import type { BuiltinSchemeOverrideRef, BuiltinSchemeSnapshot } from '../models/types'
import { loadScheme, type SchemeMeta } from '../rules/scheme'
import {
  DRIFT_STATUS_LABELS,
  ignoreDriftVersion,
  ignoredDriftVersion,
  loadSchemeDrift,
  shouldPromptDrift,
  type SchemeDrift,
} from '../rules/schemeDrift'
import { fetchUpstreamScheme } from '../rules/upstreamScheme'

type DriftState =
  | { kind: 'loading' }
  | { kind: 'ready'; drift: SchemeDrift }
  | { kind: 'error'; message: string }
  | { kind: 'ignored' }

const SAMPLE_KIND_TITLES = { added: '新增', removed: '删除', modified: '修改' } as const

export function SchemeDriftNotice({
  meta,
  version,
  overrides,
  snapshots,
  readOnly,
  busy,
  onAbsorb,
}: {
  meta: SchemeMeta
  version: string
  overrides: Record<string, BuiltinSchemeOverrideRef>
  snapshots: Record<string, BuiltinSchemeSnapshot>
  readOnly: boolean
  busy: boolean
  onAbsorb: () => void
}) {
  const [state, setState] = useState<DriftState>({ kind: 'loading' })

  useEffect(() => {
    let cancelled = false
    if (!shouldPromptDrift(version, ignoredDriftVersion(meta.id))) {
      setState({ kind: 'ignored' })
      return
    }
    setState({ kind: 'loading' })
    loadSchemeDrift(meta, version, {
      loadCurrent: () => loadScheme(meta, overrides, snapshots),
      fetchUpstream: async (target) => (await fetchUpstreamScheme(target)).scheme,
    })
      .then((drift) => {
        if (!cancelled) setState({ kind: 'ready', drift })
      })
      .catch((error) => {
        if (!cancelled) {
          setState({ kind: 'error', message: error instanceof Error ? error.message : String(error) })
        }
      })
    return () => { cancelled = true }
  }, [meta, version, overrides, snapshots])

  if (state.kind === 'ignored') return null

  if (state.kind === 'loading') {
    return <div className="drift-note">{DRIFT_STATUS_LABELS.update}，正在对比上游规则…</div>
  }

  if (state.kind === 'error') {
    return (
      <div className="drift-note drift-error">
        查不到上游变化（这不等于没有更新）：{state.message}
      </div>
    )
  }

  const { drift } = state
  const counts = `+${drift.added} / −${drift.removed} / ~${drift.modified}`
  return (
    <div className="drift-note" data-drift="update">
      <div className="drift-head">
        <strong>{DRIFT_STATUS_LABELS.update}</strong>
        <span>{drift.total > 0 ? `上游有 ${drift.total} 条变化` : '上游有新版本，但规则内容无差异'}</span>
        <span className="drift-counts">{counts}</span>
      </div>
      {drift.samples.length > 0 && (
        <details className="drift-samples">
          <summary>
            查看变更条目（{drift.samples.length} 条
            {drift.hidden > 0 ? `，另有 ${drift.hidden} 条未列出` : ''}）
          </summary>
          <ul>
            {drift.samples.map((sample, index) => (
              <li key={`${sample.kind}-${index}-${sample.text}`} data-kind={sample.kind}>
                <span className="drift-kind">{SAMPLE_KIND_TITLES[sample.kind]}</span>
                <code>{sample.text}</code>
                {sample.previous && <span className="drift-previous">原：{sample.previous}</span>}
              </li>
            ))}
          </ul>
        </details>
      )}
      <div className="drift-actions">
        <button
          type="button"
          className="btn ghost"
          disabled={busy || readOnly}
          title={readOnly ? '工作区只读，无法吸收上游更新' : undefined}
          onClick={onAbsorb}
        >
          吸收
        </button>
        <button
          type="button"
          className="btn ghost"
          disabled={!version}
          title={!version ? '没有拿到上游 commit，无法精确忽略' : '忽略到该 commit，上游再变时重新提示'}
          onClick={() => {
            ignoreDriftVersion(meta.id, version)
            setState({ kind: 'ignored' })
          }}
        >
          忽略此版本
        </button>
      </div>
    </div>
  )
}
