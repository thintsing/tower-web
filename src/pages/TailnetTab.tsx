// Tailscale 内网工作区：列表、编辑弹窗和导出规则说明。
import { useEffect, useRef, useState } from 'react'
import type { TailnetConnection } from '../models/types'
import {
  defaultTailnetConnection,
  normalizeTailnetAuthKey,
  normalizeTailnetControlURL,
  normalizeTailnetDeviceName,
  normalizeTailnetMagicDNSSuffix,
  normalizeTailnetSubnets,
  tailnetPolicyName,
  TailnetValidationError,
} from '../models/tailnet'
import { useStore } from '../store'
import { useWorkspaceStatus } from '../workspaceSync'
import { writeGuard } from '../util/readOnlyUi'
import { Icon } from '../components/Icon'
import { TailnetIllustration } from '../components/TailnetIllustration'

function TailnetRow({
  connection,
  onEdit,
}: {
  connection: TailnetConnection
  onEdit: () => void
}) {
  const tailnetAuthKeys = useStore((s) => s.tailnetAuthKeys)
  const setTailnetEnabled = useStore((s) => s.setTailnetEnabled)
  const readOnly = useWorkspaceStatus().readOnly
  const detail = [
    connection.magicDNSSuffix ?? (connection.controlURLString ? '自建控制服务器' : '官方 Tailscale'),
    connection.subnets.length > 0 ? `${connection.subnets.length} 个子网` : '',
    tailnetAuthKeys[connection.id] ? '已保存 Auth Key' : '',
  ].filter(Boolean).join(' · ')

  return (
    <div className={`tailnet-row${connection.isEnabled ? '' : ' is-off'}`}>
      <span className="tailnet-mark" aria-hidden="true"><Icon.Network /></span>
      <div className="tailnet-main">
        <div className="tailnet-name">{tailnetPolicyName(connection)}</div>
        <div className="tailnet-detail">{detail}</div>
      </div>
      <button type="button" className="btn ghost" {...writeGuard(readOnly)} onClick={onEdit}>编辑</button>
      <label className="tailnet-switch">
        <input
          type="checkbox"
          checked={connection.isEnabled}
          {...writeGuard(readOnly)}
          onChange={(e) => setTailnetEnabled(connection.id, e.target.checked)}
          aria-label={`启用 ${tailnetPolicyName(connection)}`}
        />
        <span>{connection.isEnabled ? '已启用' : '已停用'}</span>
      </label>
    </div>
  )
}

function TailnetEditorDialog({
  item,
  onClose,
}: {
  item: { connection: TailnetConnection; isNew: boolean }
  onClose: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const tailnets = useStore((s) => s.tailnets)
  const tailnetAuthKeys = useStore((s) => s.tailnetAuthKeys)
  const addTailnet = useStore((s) => s.addTailnet)
  const updateTailnet = useStore((s) => s.updateTailnet)
  const deleteTailnet = useStore((s) => s.deleteTailnet)
  const setTailnetAuthKey = useStore((s) => s.setTailnetAuthKey)
  const readOnly = useWorkspaceStatus().readOnly
  const savedAuthKey = tailnetAuthKeys[item.connection.id] ?? ''
  const [name, setName] = useState(item.connection.name)
  const [controlURL, setControlURL] = useState(item.connection.controlURLString ?? '')
  const [authKey, setAuthKey] = useState(savedAuthKey)
  const [revealKey, setRevealKey] = useState(false)
  const [subnets, setSubnets] = useState(item.connection.subnets.join('\n'))
  const [magicDNS, setMagicDNS] = useState(item.connection.magicDNSSuffix ?? '')
  const [deviceName, setDeviceName] = useState(item.connection.deviceName ?? '')
  const [error, setError] = useState('')
  const [confirmDelete, setConfirmDelete] = useState(false)

  useEffect(() => {
    const dialog = ref.current
    dialog?.showModal()
    return () => dialog?.close()
  }, [])

  const save = () => {
    setError('')
    try {
      const connection: TailnetConnection = {
        ...item.connection,
        name: (name.trim() || 'Tailscale').slice(0, 80),
        controlURLString: normalizeTailnetControlURL(controlURL),
        subnets: normalizeTailnetSubnets(subnets),
        magicDNSSuffix: normalizeTailnetMagicDNSSuffix(magicDNS),
        deviceName: normalizeTailnetDeviceName(deviceName),
      }
      const key = normalizeTailnetAuthKey(authKey)
      if (item.isNew) addTailnet(connection)
      else updateTailnet(connection)
      if (key !== (savedAuthKey || undefined)) setTailnetAuthKey(connection.id, key)
      onClose()
    } catch (e) {
      const message = e instanceof TailnetValidationError
        ? e.field === 'controlURL'
          ? '控制服务器必须是 HTTPS 地址。'
          : e.field === 'subnet'
            ? `无法识别的子网“${e.value}”，请用 192.168.1.0/24 这样的格式。`
            : e.field === 'magicDNSSuffix'
              ? 'MagicDNS 后缀格式不对，例如 tail1234.ts.net。'
              : 'Auth Key 不能包含空格、引号或逗号。'
        : '保存失败，请重试。'
      setError(message)
    }
  }

  const rows = tailnets.filter((connection) => connection.id !== item.connection.id).map((connection) => connection.name).join('、')

  return (
    <dialog ref={ref} onClose={onClose} className="tailnet-dialog">
      <h3>{item.isNew ? '添加 Tailscale 内网' : '编辑 Tailscale 内网'}</h3>
      <div className="settings-body">
        <div className="tailnet-field-grid">
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label htmlFor="tailnet-name">名称</label>
            <input
              id="tailnet-name"
              className="input"
              value={name}
              maxLength={80}
              onChange={(e) => setName(e.target.value)}
              placeholder="例如 家里"
            />
            <div className="hint">导出后在客户端里显示的策略名；不会加入任何策略组。</div>
          </div>
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label htmlFor="tailnet-control">控制服务器（留空为官方 Tailscale）</label>
            <input
              id="tailnet-control"
              className="input"
              value={controlURL}
              maxLength={2048}
              onChange={(e) => setControlURL(e.target.value)}
              placeholder="https://headscale.example.com"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <div className="hint">自建 Headscale 时填写它的 HTTPS 地址。</div>
          </div>
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label htmlFor="tailnet-auth-key">Auth Key（可选）</label>
            <div className="secret-row">
              <input
                id="tailnet-auth-key"
                className="input"
                type={revealKey ? 'text' : 'password'}
                value={authKey}
                maxLength={512}
                onChange={(e) => setAuthKey(e.target.value)}
                placeholder="tskey-auth-…"
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
              />
              {authKey && (
                <button type="button" className="btn ghost" onClick={() => setRevealKey((v) => !v)}>
                  {revealKey ? '隐藏' : '显示'}
                </button>
              )}
            </div>
            <div className="hint">
              Stash 可留空，在客户端打开节点 → Tailscale → 开始认证；Clash / mihomo 和 sing-box 需要它。
              Surge 在客户端里登录，不写 Key。生成时打开 Reusable，设备加入后关闭 Key Expiry；只保存本机，不同步。
            </div>
          </div>
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label htmlFor="tailnet-subnets">家里子网（可选）</label>
            <textarea
              id="tailnet-subnets"
              className="input"
              rows={3}
              value={subnets}
              onChange={(e) => setSubnets(e.target.value)}
              placeholder={'例如 192.168.1.0/24\nfd00:1::/64'}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <div className="hint">每行一个 CIDR；需家里设备在 Tailscale 发布并批准该子网。</div>
          </div>
          <div className="field">
            <label htmlFor="tailnet-magic-dns">MagicDNS 后缀</label>
            <input
              id="tailnet-magic-dns"
              className="input"
              value={magicDNS}
              maxLength={253}
              onChange={(e) => setMagicDNS(e.target.value)}
              placeholder="tail1234.ts.net"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <div className="hint">在 Tailscale DNS 页面查看；Stash 必填。</div>
          </div>
          <div className="field">
            <label htmlFor="tailnet-device-name">设备名</label>
            <input
              id="tailnet-device-name"
              className="input"
              value={deviceName}
              maxLength={40}
              onChange={(e) => setDeviceName(e.target.value)}
              placeholder="tower"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <div className="hint">每个客户端会注册成单独设备，例如 tower-stash。</div>
          </div>
        </div>
        <div className="local-note">
          <i aria-hidden="true" />
          Auth Key 只存本机，会写入配置（预览打码）。修改或删除后请回导出页同步订阅。
        </div>
        {rows && <div className="hint">其他内网：{rows}。每份各写一条策略。</div>}
        {error && <div className="form-error" role="alert">{error}</div>}
        {!item.isNew && (
          <div className="tailnet-delete">
            {confirmDelete ? (
              <>
                <span>删除后这份内网与本机 Auth Key 都会移除；已发布订阅需回导出页同步，才会去掉旧 Key。</span>
                <button
                  type="button"
                  className="btn danger"
                  {...writeGuard(readOnly)}
                  onClick={() => {
                    deleteTailnet(item.connection.id)
                    onClose()
                  }}
                >
                  确认删除
                </button>
                <button type="button" className="btn ghost" onClick={() => setConfirmDelete(false)}>取消删除</button>
              </>
            ) : (
              <button type="button" className="btn ghost" {...writeGuard(readOnly)} onClick={() => setConfirmDelete(true)}>删除这个内网</button>
            )}
          </div>
        )}
      </div>
      <div className="actions">
        <button type="button" className="btn primary" {...writeGuard(readOnly)} onClick={save}>保存</button>
        <button type="button" className="btn ghost" onClick={onClose}>取消</button>
      </div>
    </dialog>
  )
}

export function TailnetTab() {
  const tailnets = useStore((s) => s.tailnets)
  const tailnetAuthKeys = useStore((s) => s.tailnetAuthKeys)
  const readOnly = useWorkspaceStatus().readOnly
  const [editing, setEditing] = useState<{ connection: TailnetConnection; isNew: boolean } | null>(null)
  const enabledCount = tailnets.filter((connection) => connection.isEnabled).length
  const keyCount = tailnets.filter((connection) => tailnetAuthKeys[connection.id]).length

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">内网连接 · 02</div>
          <h1>Tailscale 内网</h1>
          <div className="sub">开着代理时，也能按规则访问家里设备和子网。</div>
        </div>
        <div className="row page-actions" style={{ gap: 8 }}>
          <button className="btn primary" {...writeGuard(readOnly)} onClick={() => setEditing({ connection: defaultTailnetConnection(), isNew: true })}>
            + 添加内网
          </button>
        </div>
      </div>

      <div className="card tailnet-intro">
        <div className="card-head">
          <h3>它是什么</h3>
          <span className="meta">不是节点 · 不加入策略组</span>
        </div>
        <div className="tailnet-intro-body">
          <div className="tailnet-copy">
            <p className="tailnet-lead">把 Tailscale 当成一条独立出口。</p>
            <ul className="tailnet-points">
              <li><b>独立策略</b>：不进入节点选择、自动选择或测速。</li>
              <li><b>只走内网</b>：置顶写 Tailscale 地址段、MagicDNS 与家里子网规则。</li>
              <li><b>不回退直连</b>：不在内网的目标直接失败，不会绕回普通节点。</li>
            </ul>
            <details className="tailnet-details">
              <summary>支持的客户端与注意事项</summary>
              <ul>
                <li>支持 Surge（iOS 5.21 / Mac 6.8 起）、Stash 3.4 起、Clash / mihomo（内核 1.19.25 起）和 sing-box MT。</li>
                <li>其余客户端（Shadowrocket、Loon、QuanX、Egern、Hiddify、Karing）会跳过并提示。</li>
                <li>只写「完整配置」，「仅节点」不含它。</li>
              </ul>
            </details>
          </div>
          <div className="tailnet-visual">
            <TailnetIllustration />
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>已添加的内网</h3>
          <span className="meta">
            {tailnets.length === 0 ? '尚未添加' : `${enabledCount} 个已启用 · ${keyCount} 个已保存 Auth Key`}
          </span>
        </div>
        {tailnets.length === 0 ? (
          <div className="preview-empty tailnet-empty">
            <strong>还没有 Tailscale 内网</strong>
            <span>添加后只在「完整配置」中写入受支持的客户端。</span>
          </div>
        ) : (
          <div className="tailnet-list">
            {tailnets.map((connection) => (
              <TailnetRow
                key={connection.id}
                connection={connection}
                onEdit={() => setEditing({ connection, isNew: false })}
              />
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <h3>导出规则</h3>
          <span className="meta">置顶写入</span>
        </div>
        <div className="tailnet-routes">
          <span><b>DOMAIN-SUFFIX</b> MagicDNS 后缀，填了才写</span>
          <span><b>IP-CIDR</b> 100.64.0.0/10</span>
          <span><b>IP-CIDR6</b> fd7a:115c:a1e0::/48</span>
          <span><b>IP-CIDR</b> 你填写的家里子网</span>
        </div>
        <p className="tailnet-lead">只写完整配置，排在其他规则之前；不进节点组或测速。</p>
        <details className="tailnet-details">
          <summary>自动路由与 Stash 注意事项</summary>
          <p>
            Surge 5.21+ / Stash 3.6+ 会自动路由，重复规则无害；Stash 3.4、mihomo 和 sing-box 仍依赖它们。
            Stash 默认跳过 Tailscale 与局域网网段，建议用 MagicDNS 设备名访问。
          </p>
        </details>
      </div>

      {editing && (
        <TailnetEditorDialog
          key={`${editing.connection.id}-${editing.isNew ? 'new' : 'edit'}`}
          item={editing}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  )
}
