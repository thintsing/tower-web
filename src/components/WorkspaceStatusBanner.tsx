// 服务器版状态横幅：离线 / 密钥无效 / 文件损坏时提示只读；同步成功时
// 短暂提示「已上传本机工作区」「另一台设备刚改过」等结果。
import { useEffect, useState } from 'react'
import { getWorkspaceStatus, subscribeWorkspaceStatus } from '../workspaceSync'

function titleFor(state: string): string {
  if (state === 'offline') return '服务端离线，当前只读'
  if (state === 'unauthorized') return '访问密钥无效'
  return '服务端工作区不可用'
}

export function WorkspaceStatusBanner() {
  const [status, setStatus] = useState(getWorkspaceStatus)
  const [dismissed, setDismissed] = useState('')

  useEffect(() => subscribeWorkspaceStatus(() => setStatus(getWorkspaceStatus())), [])

  if (status.mode !== 'server') return null
  if (!status.readOnly) {
    if (!status.message || status.message === dismissed) return null
    return (
      <div className="workspace-alert info" role="status">
        <strong>服务器工作区</strong>
        <span>{status.message}</span>
        <button
          className="storage-alert-close"
          type="button"
          onClick={() => setDismissed(status.message)}
        >知道了</button>
      </div>
    )
  }
  return (
    <div className="workspace-alert" role="alert">
      <strong>{titleFor(status.state)}</strong>
      <span>
        仅本地缓存，改动不会保存。
        {status.message ? ` ${status.message}` : ''}
      </span>
    </div>
  )
}
