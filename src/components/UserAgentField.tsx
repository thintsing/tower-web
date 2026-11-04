// 订阅的 User-Agent 选择。机场常按 UA 决定是否返回套餐用量
// （subscription-userinfo），所以给常用 UA 一个下拉，避免用户手写。
import { useState } from 'react'

const PRESETS = [
  { value: '', label: '默认（clash-verge/v2.4.2）' },
  { value: 'clash.meta', label: 'clash.meta' },
  { value: 'clash-verge/v2.5.8', label: 'clash-verge/v2.5.8' },
  { value: 'ClashforWindows/0.20.39', label: 'ClashforWindows' },
]

export function UserAgentField({
  value,
  onChange,
  disabled = false,
}: {
  value: string
  onChange: (value: string) => void
  disabled?: boolean
}) {
  const preset = PRESETS.find((item) => item.value === value.trim())
  const [custom, setCustom] = useState(!preset && value.trim() !== '')
  const mode = custom ? '__custom__' : (preset?.value ?? '')

  return (
    <>
      <div className="field">
        <label>User-Agent（影响机场是否下发套餐用量）</label>
        <select
          className="field"
          disabled={disabled}
          value={mode}
          onChange={(e) => {
            const next = e.target.value
            setCustom(next === '__custom__')
            onChange(next === '__custom__' ? '' : next)
          }}
        >
          {PRESETS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
          <option value="__custom__">自定义…</option>
        </select>
      </div>
      {custom && (
        <div className="field">
          <label>自定义 User-Agent</label>
          <input
            type="text"
            className="field"
            disabled={disabled}
            placeholder="例如 clash-verge/v2.5.8"
            value={value}
            onChange={(e) => onChange(e.target.value)}
          />
        </div>
      )}
      <div className="hint">
        留空跟随后端默认；改用 Clash 系 UA 常能让机场返回流量与到期信息。
        有些机场只在 Clash 版链接（如带 <code>?flag=clash</code>、<code>?clash=1</code> 或 <code>/clash</code> 路径）上下发用量。
      </div>
    </>
  )
}
