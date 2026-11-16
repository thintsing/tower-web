// 导入规则方案：URL、粘贴内容或选择文件；导入前可先命名。
import { useRef } from 'react'
import { RULE_SCHEME_FORMAT_TITLES } from '../../rules/importers'
import { READONLY_NOTE } from '../../util/readOnlyUi'

export function SchemeImportCard({
  readOnly,
  name,
  url,
  text,
  fileName,
  error,
  loading,
  onNameChange,
  onURLChange,
  onTextChange,
  onReadFile,
  onImportURL,
  onImportText,
  onImportSelfConfiguration,
  onCancel,
}: {
  readOnly: boolean
  name: string
  url: string
  text: string
  fileName: string
  error: string | null
  loading: boolean
  onNameChange: (value: string) => void
  onURLChange: (value: string) => void
  onTextChange: (value: string) => void
  onReadFile: (file?: File) => void
  onImportURL: () => void
  onImportText: () => void
  onImportSelfConfiguration: () => void
  onCancel: () => void
}) {
  const fileInputRef = useRef<HTMLInputElement>(null)

  return (
    <div className="card">
      <h3 style={{ marginBottom: 14 }}>导入规则方案</h3>
      <div className="field">
        <label>方案名称</label>
        <input className="input" value={name} onChange={(e) => onNameChange(e.target.value)} placeholder="例如：ACL4SSR 精简自定义" />
      </div>
      <div className="field">
        <label>URL（方案地址）</label>
        <input className="input" value={url} onChange={(e) => onURLChange(e.target.value)} placeholder="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ACL4SSR_Online.ini" />
        <div className="hint">自动识别 subconverter INI、Clash / mihomo YAML、Surge、Egern YAML 和 sing-box JSON；也可以直接粘贴内容到下方。</div>
      </div>
      <div className="field">
        <label>粘贴方案内容（可选）</label>
        <textarea className="field" value={text} onChange={(e) => onTextChange(e.target.value)} rows={6} placeholder="ruleset=广告,https://...&#10;custom_proxy_group=节点选择`select`[]DIRECT&#10;或粘贴 proxy-groups / policy_groups / route.rules / [Proxy Group]" />
        <div className="row scheme-file-row">
          <button type="button" className="btn ghost" onClick={() => fileInputRef.current?.click()}>选择方案文件</button>
          {fileName && <span className="hint">已读取：{fileName}</span>}
          <input
            ref={fileInputRef}
            type="file"
            accept=".ini,.txt,.conf,.yaml,.yml,.json"
            style={{ display: 'none' }}
            onChange={(e) => {
              const file = e.target.files?.[0]
              e.target.value = ''
              onReadFile(file)
            }}
          />
        </div>
        <div className="hint">支持的格式：{Object.values(RULE_SCHEME_FORMAT_TITLES).join(' · ')}</div>
      </div>
      {error && <div className="error">{error}</div>}
      <div className="row" style={{ gap: 8, marginTop: 8 }}>
        <button className="btn primary" disabled={loading || !url.trim() || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={onImportURL}>
          {loading ? '处理中…' : '从 URL 导入'}
        </button>
        <button className="btn" disabled={loading || !text.trim() || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={onImportText}>
          {loading ? '处理中…' : fileName ? '导入文件内容' : '粘贴导入'}
        </button>
        <button className="btn ghost" disabled={loading || readOnly} title={readOnly ? READONLY_NOTE : undefined} onClick={onImportSelfConfiguration}>
          Self-Configuration 预设
        </button>
        <button className="btn ghost" onClick={onCancel}>取消</button>
      </div>
    </div>
  )
}
