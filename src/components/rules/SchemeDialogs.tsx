// 方案编辑弹窗：方案名称 / 全文、添加自定义规则、DNS 与网络设置。
import { useEffect, useRef, useState } from 'react'
import type { RoutingRule, RuleScheme } from '../../models/types'
import {
  DNS_MODE_SUMMARIES,
  DNS_MODE_TITLES,
  NetworkSettingsError,
  networkSettingsDraft,
  validateNetworkSettingsDraft,
  type NetworkSettingsDraft,
} from '../../models/networkSettings'
import { analyzeRuleImpact, ruleImpactText } from '../../rules/ruleImpact'
import { READONLY_NOTE, writeGuard } from '../../util/readOnlyUi'
import { useWorkspaceStatus } from '../../workspaceSync'
import { groupDisplayName } from '../GroupIcon'

const RULE_TYPE_OPTIONS: { value: string; label: string; placeholder: string; ip?: boolean }[] = [
  { value: 'DOMAIN', label: '完整域名', placeholder: 'example.com' },
  { value: 'DOMAIN-SUFFIX', label: '域名后缀', placeholder: 'example.com' },
  { value: 'DOMAIN-KEYWORD', label: '域名关键词', placeholder: 'youtube' },
  { value: 'IP-CIDR', label: 'IPv4 网段', placeholder: '192.168.1.0/24', ip: true },
  { value: 'IP-CIDR6', label: 'IPv6 网段', placeholder: '2001:db8::/32', ip: true },
  { value: 'GEOIP', label: '国家 / 地区代码', placeholder: 'CN' },
]

export function SchemeEditDialog({
  scheme,
  onClose,
  onSave,
}: {
  scheme: RuleScheme
  onClose: () => void
  onSave: (next: RuleScheme) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const readOnly = useWorkspaceStatus().readOnly
  const [name, setName] = useState(scheme.name)
  const [description, setDescription] = useState(scheme.description)
  const [error, setError] = useState('')

  useEffect(() => { ref.current?.showModal() }, [])

  const save = () => {
    if (!name.trim()) {
      setError('请填写方案名称')
      return
    }
    onSave({ ...scheme, name: name.trim(), description: description.trim() })
    ref.current?.close()
  }

  return (
    <dialog ref={ref} onClose={onClose}>
      <h3>编辑规则方案</h3>
      <form className="dialog-form" onSubmit={(e) => { e.preventDefault(); save() }}>
        <div className="field">
          <label>方案名称</label>
          <input type="text" className="field" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </div>
        <div className="field">
          <label>说明</label>
          <textarea className="field" rows={3} value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        {scheme.sourceURL && (
          <div className="hint">来源地址：<span className="mono">{scheme.sourceURL}</span></div>
        )}
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          <button type="submit" className="btn primary" {...writeGuard(readOnly)}>保存</button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

export function SchemeTextDialog({
  scheme,
  onClose,
  onSave,
}: {
  scheme: RuleScheme
  onClose: () => void
  onSave: (text: string) => Promise<string | undefined>
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const readOnly = useWorkspaceStatus().readOnly
  const [text, setText] = useState(scheme.rawConfigurationText ?? '')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => { ref.current?.showModal() }, [])

  const save = async () => {
    setBusy(true)
    setError('')
    const message = await onSave(text)
    setBusy(false)
    if (message) setError(message)
    else ref.current?.close()
  }

  return (
    <dialog ref={ref} className="scheme-text-dialog" onClose={onClose}>
      <h3>编辑方案全文</h3>
      <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); void save() }}>
        <div className="hint">
          文本来自最近一次导入或刷新。保存会按文本重建策略组和方案规则，自定义规则与已加入的规则集会尽量保留。
          如果之后在表单里改过策略组，文本可能尚未同步。
        </div>
        <textarea
          className="field mono scheme-text-area"
          rows={18}
          value={text}
          onChange={(event) => { setText(event.target.value); setError('') }}
          spellCheck={false}
        />
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy || !text.trim() || readOnly} title={readOnly ? READONLY_NOTE : undefined}>
            {busy ? '解析中…' : '保存全文'}
          </button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

export function AddCustomRuleDialog({
  scheme,
  initialGroup,
  onClose,
  onSave,
}: {
  scheme: RuleScheme
  initialGroup?: string
  onClose: () => void
  onSave: (rule: RoutingRule) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const firstGroup = scheme.groups.find((g) => g.name === initialGroup)?.name ?? scheme.groups[0]?.name ?? ''
  const [group, setGroup] = useState(firstGroup)
  const [type, setType] = useState('DOMAIN-SUFFIX')
  const [value, setValue] = useState('')
  const [noResolve, setNoResolve] = useState(false)
  const [error, setError] = useState('')
  const readOnly = useWorkspaceStatus().readOnly
  const typeInfo = RULE_TYPE_OPTIONS.find((t) => t.value === type) ?? RULE_TYPE_OPTIONS[0]
  const impactPreview = value.trim()
    ? analyzeRuleImpact(
        scheme,
        { type, value: value.trim(), group, ...(typeInfo.ip && noResolve ? { noResolve: true } : {}) },
        { includeCandidate: true },
      )
    : null

  useEffect(() => { ref.current?.showModal() }, [])

  const save = () => {
    if (!group) { setError('方案里没有可用的策略组'); return }
    let normalized = value.trim()
    if (!normalized) { setError('请填写规则内容'); return }

    if (/^https?:\/\//i.test(normalized)) {
      try { normalized = new URL(normalized).hostname } catch { /* 保留原文本，让下面的格式校验给出错误 */ }
    }
    if (type === 'DOMAIN' || type === 'DOMAIN-SUFFIX') {
      normalized = normalized.toLowerCase()
      if (!/^[a-z0-9._-]+$/.test(normalized)) {
        setError('域名只能包含字母、数字、点、下划线和连字符')
        return
      }
    } else if (type === 'GEOIP') {
      normalized = normalized.toUpperCase()
      if (!/^[A-Z]{2}$/.test(normalized)) {
        setError('GEOIP 需要两位国家或地区代码，例如 CN')
        return
      }
    } else if (type === 'IP-CIDR' || type === 'IP-CIDR6') {
      const v4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
      const v6 = /^[0-9a-f:]+(\/\d{1,3})?$/i
      const octetsValid = type === 'IP-CIDR'
        ? normalized.split('/')[0].split('.').map(Number).every((n) => n >= 0 && n <= 255)
        : true
      if (type === 'IP-CIDR' ? (!v4.test(normalized) || !octetsValid) : (!v6.test(normalized) || !normalized.includes(':'))) {
        setError(type === 'IP-CIDR' ? '请输入有效的 IPv4 地址或 CIDR 网段' : '请输入有效的 IPv6 地址或 CIDR 网段')
        return
      }
      const prefix = normalized.includes('/') ? Number(normalized.split('/')[1]) : (type === 'IP-CIDR' ? 32 : 128)
      if ((type === 'IP-CIDR' && prefix > 32) || (type === 'IP-CIDR6' && prefix > 128)) {
        setError('CIDR 前缀长度超出范围')
        return
      }
    }

    const duplicate = (scheme.customRules ?? []).some(
      (r) => r.group === group && r.type === type && (r.value ?? '').toLowerCase() === normalized.toLowerCase(),
    )
    if (duplicate) {
      setError('这个策略组里已经有相同的自定义规则')
      return
    }

    onSave({
      type,
      value: normalized,
      group,
      ...(typeInfo.ip && noResolve ? { noResolve: true } : {}),
    })
    ref.current?.close()
  }

  return (
    <dialog ref={ref} onClose={onClose}>
      <h3>添加自定义规则</h3>
      <form className="dialog-form" onSubmit={(e) => { e.preventDefault(); save() }}>
        <div className="field">
          <label>策略组</label>
          <select className="input" value={group} onChange={(e) => setGroup(e.target.value)}>
            {scheme.groups.map((g) => <option key={g.name} value={g.name}>{groupDisplayName(g.name)}</option>)}
          </select>
        </div>
        <div className="field">
          <label>匹配方式</label>
          <select className="input" value={type} onChange={(e) => { setType(e.target.value); setNoResolve(false) }}>
            {RULE_TYPE_OPTIONS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        </div>
        <div className="field">
          <label>规则内容</label>
          <input
            type="text"
            className="field mono"
            value={value}
            placeholder={typeInfo.placeholder}
            onChange={(e) => setValue(e.target.value)}
            autoFocus
          />
          {(type === 'DOMAIN' || type === 'DOMAIN-SUFFIX') && <div className="hint">可以直接粘贴网址，会自动取出域名。</div>}
        </div>
        {typeInfo.ip && (
          <label className="check-line">
            <input type="checkbox" checked={noResolve} onChange={(e) => setNoResolve(e.target.checked)} />
            不解析 DNS（no-resolve）
          </label>
        )}
        <div className="local-note">
          <i aria-hidden="true" />
          自定义规则会排在方案自带规则最前，优先匹配。
        </div>
        {impactPreview && (
          <div className="rule-impact" role="status">
            <strong>影响面预览（保存后）</strong>
            <small>{ruleImpactText(impactPreview)}</small>
          </div>
        )}
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions">
          <button type="submit" className="btn primary" {...writeGuard(readOnly)}>添加规则</button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

export function NetworkSettingsDialog({
  scheme,
  onClose,
  onSave,
}: {
  scheme: RuleScheme
  onClose: () => void
  onSave: (next: RuleScheme) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const readOnly = useWorkspaceStatus().readOnly
  const [draft, setDraft] = useState<NetworkSettingsDraft>(() => networkSettingsDraft(scheme.networkSettings))
  const [error, setError] = useState('')
  useEffect(() => { ref.current?.showModal() }, [])

  const save = () => {
    try {
      const networkSettings = validateNetworkSettingsDraft(draft)
      onSave({ ...scheme, networkSettings })
      ref.current?.close()
    } catch (e) {
      setError(e instanceof NetworkSettingsError ? e.message : 'DNS 设置无法保存')
    }
  }

  const text = (values: string[]) => values.join('\n')
  const lines = (value: string) => value.split('\n')

  return (
    <dialog ref={ref} className="dns-dialog" onClose={onClose}>
      <h3>DNS 与网络</h3>
      <form className="dialog-form" onSubmit={(e) => { e.preventDefault(); save() }}>
        <div className="field">
          <label>DNS 保护模式</label>
          <select
            className="input"
            value={draft.dnsProtectionMode}
            onChange={(e) => setDraft({ ...draft, dnsProtectionMode: e.target.value as NetworkSettingsDraft['dnsProtectionMode'] })}
          >
            {Object.entries(DNS_MODE_TITLES).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
          <div className="hint">{DNS_MODE_SUMMARIES[draft.dnsProtectionMode]}</div>
          {draft.dnsProtectionMode === 'strict' && (
            <div className="dns-warning">严格保护可能影响局域网、公共网络认证和使用域名的代理节点。</div>
          )}
        </div>

        <div className="field">
          <label>IPv6</label>
          <select
            className="input"
            value={draft.ipv6Enabled === undefined ? 'default' : draft.ipv6Enabled ? 'on' : 'off'}
            onChange={(e) => setDraft({
              ...draft,
              ipv6Enabled: e.target.value === 'default' ? undefined : e.target.value === 'on',
            })}
          >
            <option value="default">跟随客户端默认</option>
            <option value="on">开启</option>
            <option value="off">关闭</option>
          </select>
        </div>

        <div className="dns-grid">
          <div className="field">
            <label>普通 DNS（每行一个 IP）</label>
            <textarea
              className="field mono"
              rows={3}
              value={text(draft.dnsServers)}
              onChange={(e) => setDraft({ ...draft, dnsServers: lines(e.target.value) })}
              placeholder={'223.5.5.5\n119.29.29.29'}
            />
            <div className="hint">只接受 IPv4 / IPv6 字面量，用于解析加密 DNS 和代理节点域名。</div>
          </div>
          <div className="field">
            <label>国内 DNS（直连）</label>
            <textarea
              className="field mono"
              rows={3}
              value={text(draft.encryptedDNSServers)}
              onChange={(e) => setDraft({ ...draft, encryptedDNSServers: lines(e.target.value) })}
              placeholder={'https://223.5.5.5/dns-query\nhttps://doh.pub/dns-query'}
            />
            <div className="hint">支持 https / h3 / tls / quic 地址，用于国内和直连解析。</div>
          </div>
          <div className="field">
            <label>远程 DNS（经代理）</label>
            <textarea
              className="field mono"
              rows={3}
              value={text(draft.remoteDNSServers)}
              onChange={(e) => setDraft({ ...draft, remoteDNSServers: lines(e.target.value) })}
              placeholder={'https://8.8.8.8/dns-query\nhttps://1.1.1.1/dns-query'}
            />
            <div className="hint">只经代理访问，用于 sing-box 和 mihomo 系客户端。</div>
          </div>
        </div>

        <div className="field">
          <label>延迟测试地址</label>
          <input
            className="input mono"
            value={draft.proxyTestURLString}
            onChange={(e) => setDraft({ ...draft, proxyTestURLString: e.target.value })}
            placeholder="http://www.gstatic.com/generate_204"
          />
          <div className="hint">URL 测速组未单独填写地址时使用；支持 http / https。</div>
        </div>

        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="actions dns-actions">
          <button type="submit" className="btn primary" {...writeGuard(readOnly)}>保存</button>
          <button type="button" className="btn" onClick={() => setDraft(networkSettingsDraft(undefined))}>
            填入默认值
          </button>
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>取消</button>
        </div>
      </form>
    </dialog>
  )
}

