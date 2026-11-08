// 服务器版状态横幅：离线 / 密钥无效 / 文件损坏时提示只读；同步成功时
// 短暂提示「已上传本机工作区」「另一台设备刚改过」等结果。
// 服务端工作区有字段损坏或旧结构升级时，逐条列出键名和原因，不能只说「数据有误」。
import { useEffect, useState } from 'react'
import { getWorkspaceStatus, subscribeWorkspaceStatus } from '../workspaceSync'
import type { WorkspaceIssue } from '../workspaceValidation'

function titleFor(state: string): string {
  if (state === 'offline') return '服务端离线，当前只读'
  if (state === 'unauthorized') return '访问密钥无效'
  if (state === 'blocked') return '服务端拒绝请求'
  return '服务端工作区不可用'
}

function severityBadge(severity: WorkspaceIssue['severity']): string {
  if (severity === 'dropped') return '已跳过'
  if (severity === 'fallback') return '已回退'
  return '已升级'
}

function IssueList({ issues }: { issues: WorkspaceIssue[] }) {
  return (
    <ul className="workspace-issue-list">
      {issues.map((item, index) => (
        <li key={`${item.key}-${item.label}-${index}`}>
          <span className={`workspace-issue-badge ${item.severity}`}>{severityBadge(item.severity)}</span>
          <span className="workspace-issue-key">{item.keyLabel}</span>
          {item.label !== item.keyLabel && (
            <span className="workspace-issue-label">{item.label}</span>
          )}
          <small>{item.reason}</small>
        </li>
      ))}
    </ul>
  )
}

function IssueHelp() {
  return (
    <small className="workspace-issue-help">
      被丢弃的内容通常还能在「订阅设置 → 工作区历史」找回上一版；
      若服务端 workspace.json 整体无法解析，数据目录里会保留 .broken-* 原始文件。
    </small>
  )
}

export function WorkspaceStatusBanner() {
  const [status, setStatus] = useState(getWorkspaceStatus)
  const [dismissed, setDismissed] = useState('')

  useEffect(() => subscribeWorkspaceStatus(() => setStatus(getWorkspaceStatus())), [])

  // local 模式不提示；unknown（首次探测失败）必须提示，否则空白页面看起来像数据丢了。
  if (status.mode === 'local') return null

  if (status.state === 'unsaved') {
    // 保存失败不能用「知道了」压掉：改动仍在内存里，刷新就会丢。
    // 同一错误再次出现时继续显示，直到重试成功或用户真的离开页面。
    return (
      <div className="workspace-alert issues" role="alert">
        <div className="workspace-alert-head">
          <strong>工作区未保存</strong>
          <span>{status.message}</span>
        </div>
        <small className="workspace-issue-help">
          本地改动仍在内存中，正在自动重试保存；离开页面前会再次确认。
        </small>
      </div>
    )
  }

  const issues = status.issues
  const dropped = issues.filter((item) => item.severity === 'dropped')
  const fallback = issues.filter((item) => item.severity === 'fallback')
  const migrated = issues.filter((item) => item.severity === 'migrated')
  // 用内容签名判断「这一批问题是否已被用户看过」，新问题出现时重新提示。
  const issueSignature = `${issues.length}:${issues.map((item) => `${item.key}:${item.label}:${item.severity}`).join('|')}`

  if (status.readOnly) {
    return (
      <div className="workspace-alert issues" role="alert">
        <div className="workspace-alert-head">
          <strong>{titleFor(status.state)}</strong>
          <span>
            仅本地缓存，改动不会保存。
            {status.message ? ` ${status.message}` : ''}
          </span>
        </div>
        {issues.length > 0 && <IssueList issues={issues} />}
        {issues.length > 0 && <IssueHelp />}
      </div>
    )
  }

  const hasLoss = dropped.length > 0 || fallback.length > 0
  // 用户已经看过这一批问题：不要再把同一条汇总（status.message）弹一次。
  if (issues.length > 0 && issueSignature === dismissed) return null
  if (hasLoss) {
    const head = dropped.length > 0
      ? `服务端工作区有 ${dropped.length} 项内容无法读取`
      : `服务端工作区有 ${fallback.length} 项内容已回退`
    const sub = dropped.some((item) => item.wholeKey)
      ? '整块损坏的字段已保留本机原值，保存时会把服务端原内容原样写回，不会用空值覆盖；其余字段正常加载，明细如下。'
      : '已跳过损坏的条目，其余内容正常加载；明细如下。'
    return (
      <div className="workspace-alert issues" role="alert">
        <div className="workspace-alert-head">
          <strong>{head}</strong>
          <span>{sub}</span>
          <button
            className="storage-alert-close"
            type="button"
            onClick={() => setDismissed(issueSignature)}
          >知道了</button>
        </div>
        <IssueList issues={issues} />
        <IssueHelp />
      </div>
    )
  }

  if (migrated.length > 0 && issueSignature !== dismissed) {
    return (
      <div className="workspace-alert issues info" role="status">
        <div className="workspace-alert-head">
          <strong>工作区已从旧版本升级</strong>
          <span>共 {migrated.length} 项字段按新结构读取，原有规则和规则集没有被重置。</span>
          <button
            className="storage-alert-close"
            type="button"
            onClick={() => setDismissed(issueSignature)}
          >知道了</button>
        </div>
        <IssueList issues={issues} />
      </div>
    )
  }

  if (!status.message || status.message === dismissed) return null
  return (
    <div className="workspace-alert info" role="status">
      <strong>{status.mode === 'server' ? '服务器工作区' : '塔台服务端'}</strong>
      <span>{status.message}</span>
      <button
        className="storage-alert-close"
        type="button"
        onClick={() => setDismissed(status.message)}
      >知道了</button>
    </div>
  )
}
