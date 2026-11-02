// 手动新建 / 编辑自有节点。字段由协议决定，保存前统一走 buildManualNode 校验。
import { useEffect, useRef, useState, type ReactNode } from 'react'
import type { ProxyKind, ProxyNode } from '../models/types'
import { PROXY_KIND_TITLES } from '../models/types'
import { useStore } from '../store'
import {
  applyManualKind,
  buildManualNode,
  emptyManualDraft,
  MANUAL_FORM_KINDS,
  manualDraftFromNode,
  type ManualNodeDraft,
} from '../manualNodeForm'

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="field">
      <label>{label}</label>
      {children}
      {hint && <div className="hint">{hint}</div>}
    </div>
  )
}

export function ManualNodeEditorDialog({
  node,
  onClose,
  onSaved,
}: {
  node?: ProxyNode
  onClose: () => void
  onSaved?: (message: string) => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const saveManualNode = useStore((s) => s.saveManualNode)
  const [draft, setDraft] = useState<ManualNodeDraft>(() =>
    node ? manualDraftFromNode(node) : emptyManualDraft())
  const [error, setError] = useState('')

  useEffect(() => {
    ref.current?.showModal()
  }, [])

  const patch = (values: Partial<ManualNodeDraft>) =>
    setDraft((current) => ({ ...current, ...values }))
  const setKind = (kind: ProxyKind) =>
    setDraft((current) => applyManualKind(current, kind))

  const kind = draft.kind
  const hasTransport = ['vmess', 'vless', 'trojan'].includes(kind)
  const tlsOptional = ['vmess', 'vless', 'socks5', 'http', 'masque'].includes(kind)
  const tlsAlways = ['trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'trusttunnel'].includes(kind)
  const hasTls = tlsAlways || draft.tls
  const keyMasque = kind === 'masque' && draft.masqueMode === 'keyConnectIP'
  const usesSecret = ['ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'snell'].includes(kind)
  const usesPassword = ['trusttunnel', 'ssh', 'socks5', 'http', 'masque'].includes(kind) && !keyMasque
  const secretLabel = kind === 'vmess' || kind === 'vless' || kind === 'tuic'
    ? 'UUID'
    : kind === 'snell' ? 'PSK' : '密码'

  const submit = () => {
    setError('')
    try {
      const next = buildManualNode(draft, node)
      saveManualNode(next)
      onSaved?.(node ? `已更新自有节点「${next.name}」。` : `已创建自有节点「${next.name}」。`)
      onClose()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <dialog ref={ref} onClose={onClose} className="manual-node-dialog">
      <h3>{node ? '编辑自有节点' : '新建自有节点'}</h3>
      <form
        className="dialog-form"
        onSubmit={(event) => {
          event.preventDefault()
          submit()
        }}
      >
        <div className="manual-form-grid">
          <Field label="协议">
            <select
              className="input"
              value={kind}
              onChange={(event) => setKind(event.target.value as ProxyKind)}
            >
              {MANUAL_FORM_KINDS.map((item) => (
                <option key={item} value={item}>{PROXY_KIND_TITLES[item]}</option>
              ))}
            </select>
          </Field>
          <Field label="名称（可选）">
            <input
              className="input"
              value={draft.name}
              placeholder={`${PROXY_KIND_TITLES[kind]} · 服务器`}
              onChange={(event) => patch({ name: event.target.value })}
            />
          </Field>
          <Field label="服务器">
            <input
              className="input"
              value={draft.server}
              placeholder="example.com"
              autoFocus
              onChange={(event) => patch({ server: event.target.value })}
            />
          </Field>
          <Field label="端口">
            <input
              className="input"
              type="number"
              min={1}
              max={65535}
              value={draft.port}
              onChange={(event) => patch({ port: event.target.value })}
            />
          </Field>
        </div>

        {kind === 'ss' || kind === 'ssr' ? (
          <div className="manual-form-grid">
            <Field label="加密方式">
              <input
                className="input"
                value={draft.cipher}
                placeholder={kind === 'ss' ? 'aes-256-gcm' : 'aes-256-cfb'}
                onChange={(event) => patch({ cipher: event.target.value })}
              />
            </Field>
            <Field label="密码">
              <input
                className="input"
                type="password"
                value={draft.secret}
                onChange={(event) => patch({ secret: event.target.value })}
              />
            </Field>
            {kind === 'ss' && (
              <>
                <Field label="混淆（可选）">
                  <select className="input" value={draft.obfs} onChange={(event) => patch({ obfs: event.target.value })}>
                    <option value="">关闭</option>
                    <option value="http">HTTP</option>
                    <option value="tls">TLS</option>
                  </select>
                </Field>
                <Field label="混淆 Host（可选）">
                  <input className="input" value={draft.obfsParam} onChange={(event) => patch({ obfsParam: event.target.value })} />
                </Field>
              </>
            )}
            {kind === 'ssr' && (
              <>
                <Field label="SSR 协议">
                  <input className="input" value={draft.protocolName} onChange={(event) => patch({ protocolName: event.target.value })} />
                </Field>
                <Field label="SSR 参数（可选）">
                  <input className="input" value={draft.protocolParam} onChange={(event) => patch({ protocolParam: event.target.value })} />
                </Field>
                <Field label="SSR 混淆">
                  <input className="input" value={draft.obfs} onChange={(event) => patch({ obfs: event.target.value })} />
                </Field>
                <Field label="SSR 混淆参数（可选）">
                  <input className="input" value={draft.obfsParam} onChange={(event) => patch({ obfsParam: event.target.value })} />
                </Field>
              </>
            )}
          </div>
        ) : null}

        {usesSecret && kind !== 'ss' && kind !== 'ssr' && (
          <div className="manual-form-grid">
            <Field label={secretLabel}>
              <input
                className="input"
                type={kind === 'vmess' || kind === 'vless' || kind === 'tuic' ? 'text' : 'password'}
                value={draft.secret}
                onChange={(event) => patch({ secret: event.target.value })}
              />
            </Field>
            {kind === 'tuic' && (
              <Field label="密码">
                <input className="input" type="password" value={draft.password} onChange={(event) => patch({ password: event.target.value })} />
              </Field>
            )}
            {kind === 'vmess' && (
              <>
                <Field label="加密方式">
                  <input className="input" value={draft.cipher} onChange={(event) => patch({ cipher: event.target.value })} />
                </Field>
                <Field label="Alter ID">
                  <input className="input" type="number" min={0} max={65535} value={draft.alterID} onChange={(event) => patch({ alterID: event.target.value })} />
                </Field>
              </>
            )}
            {kind === 'hysteria' && (
              <>
                <Field label="上行 Mbps">
                  <input className="input" type="number" min={1} value={draft.upMbps} onChange={(event) => patch({ upMbps: event.target.value })} />
                </Field>
                <Field label="下行 Mbps">
                  <input className="input" type="number" min={1} value={draft.downMbps} onChange={(event) => patch({ downMbps: event.target.value })} />
                </Field>
                <Field label="传输协议">
                  <select className="input" value={draft.protocolName} onChange={(event) => patch({ protocolName: event.target.value })}>
                    <option value="udp">UDP</option>
                    <option value="wechat-video">wechat-video</option>
                    <option value="faketcp">faketcp</option>
                  </select>
                </Field>
                <Field label="混淆字符串（可选）">
                  <input className="input" value={draft.obfs} onChange={(event) => patch({ obfs: event.target.value })} />
                </Field>
              </>
            )}
            {kind === 'hysteria2' && (
              <>
                <Field label="混淆方式">
                  <select className="input" value={draft.obfs} onChange={(event) => patch({ obfs: event.target.value })}>
                    <option value="">关闭</option>
                    <option value="salamander">Salamander</option>
                  </select>
                </Field>
                <Field label="混淆密码（可选）">
                  <input className="input" type="password" value={draft.obfsParam} onChange={(event) => patch({ obfsParam: event.target.value })} />
                </Field>
                <Field label="端口跳跃（可选）">
                  <input className="input" placeholder="443,8443-9443" value={draft.portHopping} onChange={(event) => patch({ portHopping: event.target.value })} />
                </Field>
              </>
            )}
            {kind === 'snell' && (
              <>
                <Field label="版本">
                  <select className="input" value={draft.version} onChange={(event) => patch({ version: event.target.value })}>
                    {[1, 2, 3, 4, 5, 6].map((version) => (
                      <option key={version} value={String(version)}>v{version}</option>
                    ))}
                  </select>
                </Field>
                <Field label="混淆（可选）">
                  <select className="input" value={draft.obfs} onChange={(event) => patch({ obfs: event.target.value })}>
                    <option value="">关闭</option>
                    <option value="http">HTTP</option>
                    <option value="tls">TLS</option>
                  </select>
                </Field>
                <Field label="混淆 Host（可选）">
                  <input className="input" value={draft.obfsParam} onChange={(event) => patch({ obfsParam: event.target.value })} />
                </Field>
              </>
            )}
            {kind === 'tuic' && (
              <>
                <Field label="拥塞控制">
                  <select className="input" value={draft.congestionControl} onChange={(event) => patch({ congestionControl: event.target.value })}>
                    <option value="">默认</option>
                    <option value="bbr">BBR</option>
                    <option value="cubic">Cubic</option>
                    <option value="new_reno">New Reno</option>
                  </select>
                </Field>
                <Field label="UDP 中继">
                  <select className="input" value={draft.udpRelayMode} onChange={(event) => patch({ udpRelayMode: event.target.value })}>
                    <option value="">默认</option>
                    <option value="native">native</option>
                    <option value="quic">quic</option>
                  </select>
                </Field>
              </>
            )}
            {kind === 'anytls' && (
              <>
                <Field label="会话检查间隔">
                  <input className="input" type="number" min={0} value={draft.idleSessionCheckInterval} onChange={(event) => patch({ idleSessionCheckInterval: event.target.value })} />
                </Field>
                <Field label="会话超时">
                  <input className="input" type="number" min={0} value={draft.idleSessionTimeout} onChange={(event) => patch({ idleSessionTimeout: event.target.value })} />
                </Field>
                <Field label="最小空闲会话">
                  <input className="input" type="number" min={0} value={draft.minIdleSession} onChange={(event) => patch({ minIdleSession: event.target.value })} />
                </Field>
              </>
            )}
          </div>
        )}

        {usesPassword && (
          <div className="manual-form-grid">
            {['trusttunnel', 'ssh', 'socks5', 'http', 'masque'].includes(kind) && (
              <Field label="用户名">
                <input className="input" value={draft.username} onChange={(event) => patch({ username: event.target.value })} />
              </Field>
            )}
            <Field label="密码">
              <input className="input" type="password" value={draft.password} onChange={(event) => patch({ password: event.target.value })} />
            </Field>
            {kind === 'trusttunnel' && (
              <Field label="协议版本">
                <select className="input" value={draft.quic ? 'h3' : 'h2'} onChange={(event) => patch({ quic: event.target.value === 'h3' })}>
                  <option value="h2">HTTP/2 + TLS</option>
                  <option value="h3">HTTP/3 · QUIC</option>
                </select>
              </Field>
            )}
            {kind === 'ssh' && (
              <Field label="Host Key（可选，每行一个）" hint="当前只导出密码登录；host-key 会用于固定服务器身份。">
                <textarea className="input mono" rows={2} value={draft.sshHostKeys} onChange={(event) => patch({ sshHostKeys: event.target.value })} />
              </Field>
            )}
            {kind === 'trusttunnel' && (
              <label className="manual-check">
                <input type="checkbox" checked={draft.udpRelayEnabled} onChange={(event) => patch({ udpRelayEnabled: event.target.checked })} />
                启用 UDP
              </label>
            )}
          </div>
        )}

        {hasTransport && (
          <div className="manual-form-grid">
            <Field label="传输方式">
              <select className="input" value={draft.transport} onChange={(event) => patch({ transport: event.target.value })}>
                <option value="tcp">TCP</option>
                <option value="ws">WebSocket</option>
                <option value="grpc">gRPC</option>
                <option value="h2">HTTP/2</option>
                <option value="xhttp">XHTTP</option>
              </select>
            </Field>
            <Field label="Host / Authority（可选）">
              <input className="input" value={draft.hostHeader} onChange={(event) => patch({ hostHeader: event.target.value })} />
            </Field>
            <Field label="Path / Service（可选）">
              <input className="input" value={draft.path} placeholder="/" onChange={(event) => patch({ path: event.target.value })} />
            </Field>
          </div>
        )}

        {kind === 'masque' && (
          <div className="manual-form-grid">
            <Field label="CONNECT-IP 方言">
              <select className="input" value={draft.masqueMode} onChange={(event) => patch({ masqueMode: event.target.value as ManualNodeDraft['masqueMode'] })}>
                <option value="basicConnectIP">basic（sing-box / Hiddify）</option>
                <option value="keyConnectIP">密钥（mihomo / Shadowrocket）</option>
              </select>
            </Field>
            {draft.masqueMode === 'keyConnectIP' ? (
              <>
                <Field label="客户端私钥" hint="mihomo 的 MASQUE key CONNECT-IP。">
                  <input className="input mono" value={draft.masquePrivateKey} onChange={(event) => patch({ masquePrivateKey: event.target.value })} />
                </Field>
                <Field label="服务器公钥">
                  <input className="input mono" value={draft.masquePublicKey} onChange={(event) => patch({ masquePublicKey: event.target.value })} />
                </Field>
                <Field label="本机 IPv4">
                  <input className="input" placeholder="10.0.0.2" value={draft.masqueIPv4} onChange={(event) => patch({ masqueIPv4: event.target.value })} />
                </Field>
                <Field label="本机 IPv6（可选）">
                  <input className="input" placeholder="fd00::2" value={draft.masqueIPv6} onChange={(event) => patch({ masqueIPv6: event.target.value })} />
                </Field>
                <Field label="网络">
                  <select className="input" value={draft.masqueNetwork} onChange={(event) => patch({ masqueNetwork: event.target.value })}>
                    <option value="">默认（quic）</option>
                    <option value="quic">QUIC</option>
                    <option value="h3">HTTP/3</option>
                    <option value="h2">HTTP/2</option>
                  </select>
                </Field>
              </>
            ) : (
              <>
                <Field label="HTTP 版本">
                  <select className="input" value={draft.masqueHTTPVersion} onChange={(event) => patch({ masqueHTTPVersion: event.target.value })}>
                    <option value="3">HTTP/3 · QUIC</option>
                    <option value="2">HTTP/2 + TLS</option>
                    <option value="1">HTTP/1.1 + TLS</option>
                  </select>
                </Field>
                <Field label="MTU">
                  <input className="input" type="number" min={1280} max={1500} value={draft.masqueMTU} onChange={(event) => patch({ masqueMTU: event.target.value })} />
                </Field>
                <Field label="DNS（可选，逗号分隔）">
                  <input className="input" placeholder="1.1.1.1, 8.8.8.8" value={draft.masqueDNS} onChange={(event) => patch({ masqueDNS: event.target.value })} />
                </Field>
                <Field label="请求头 JSON（可选）">
                  <input className="input mono" placeholder='{"User-Agent":"tower"}' value={draft.masqueHeaders} onChange={(event) => patch({ masqueHeaders: event.target.value })} />
                </Field>
                <Field label="证书（可选，每行一个）" hint="PEM 证书链，固定服务器身份。">
                  <textarea className="input mono" rows={2} value={draft.masqueCertificate} onChange={(event) => patch({ masqueCertificate: event.target.value })} />
                </Field>
                <label className="manual-check">
                  <input type="checkbox" checked={draft.masqueDisableVersionFallback} onChange={(event) => patch({ masqueDisableVersionFallback: event.target.checked })} />
                  禁用 HTTP 版本回退
                </label>
              </>
            )}
            <label className="manual-check">
              <input type="checkbox" checked={draft.masqueRemoteDNSResolve} onChange={(event) => patch({ masqueRemoteDNSResolve: event.target.checked })} />
              远程 DNS 解析
            </label>
          </div>
        )}

        {(tlsAlways || (tlsOptional && !keyMasque)) ? (
          <div className="manual-form-grid">
            {tlsOptional ? (
              <label className="manual-check">
                <input type="checkbox" checked={draft.tls} onChange={(event) => patch({ tls: event.target.checked })} />
                启用 TLS
              </label>
            ) : (
              <div className="hint">{PROXY_KIND_TITLES[kind]} 固定使用 TLS。</div>
            )}
            {hasTls && (
              <>
                <Field label="SNI（可选）">
                  <input className="input" value={draft.sni} onChange={(event) => patch({ sni: event.target.value })} />
                </Field>
                <Field label="ALPN（可选）">
                  <input className="input" placeholder="h2,http/1.1" value={draft.alpn} onChange={(event) => patch({ alpn: event.target.value })} />
                </Field>
                <Field label="证书指纹（可选）">
                  <input className="input" placeholder="SHA-256" value={draft.certificateFingerprint} onChange={(event) => patch({ certificateFingerprint: event.target.value })} />
                </Field>
                <label className="manual-check">
                  <input type="checkbox" checked={draft.skipCertificateVerification} onChange={(event) => patch({ skipCertificateVerification: event.target.checked })} />
                  跳过证书校验
                </label>
              </>
            )}
          </div>
        ) : null}

        {['vmess', 'vless'].includes(kind) && (
          <div className="manual-form-grid">
            <Field label="uTLS 指纹（可选）">
              <input className="input" placeholder="chrome" value={draft.fingerprint} onChange={(event) => patch({ fingerprint: event.target.value })} />
            </Field>
            {kind === 'vless' && (
              <>
                <Field label="Flow（可选）">
                  <input className="input" placeholder="xtls-rprx-vision" value={draft.flow} onChange={(event) => patch({ flow: event.target.value })} />
                </Field>
                <Field label="VLESS Encryption（可选）">
                  <input className="input" value={draft.vlessEncryption} onChange={(event) => patch({ vlessEncryption: event.target.value })} />
                </Field>
                <Field label="REALITY 公钥（可选）">
                  <input className="input" value={draft.realityPublicKey} onChange={(event) => patch({ realityPublicKey: event.target.value })} />
                </Field>
                <Field label="REALITY Short ID（可选）">
                  <input className="input" value={draft.realityShortID} onChange={(event) => patch({ realityShortID: event.target.value })} />
                </Field>
              </>
            )}
          </div>
        )}

        {kind === 'wireguard' && (
          <div className="manual-form-grid">
            <Field label="客户端私钥">
              <input className="input mono" value={draft.wireGuardPrivateKey} onChange={(event) => patch({ wireGuardPrivateKey: event.target.value })} />
            </Field>
            <Field label="服务器公钥">
              <input className="input mono" value={draft.wireGuardPublicKey} onChange={(event) => patch({ wireGuardPublicKey: event.target.value })} />
            </Field>
            <Field label="预共享密钥（可选）">
              <input className="input mono" value={draft.wireGuardPreSharedKey} onChange={(event) => patch({ wireGuardPreSharedKey: event.target.value })} />
            </Field>
            <Field label="本机 IPv4（可选）">
              <input className="input" placeholder="10.0.0.2/32" value={draft.wireGuardIPv4} onChange={(event) => patch({ wireGuardIPv4: event.target.value })} />
            </Field>
            <Field label="本机 IPv6（可选）">
              <input className="input" placeholder="fd00::2/128" value={draft.wireGuardIPv6} onChange={(event) => patch({ wireGuardIPv6: event.target.value })} />
            </Field>
            <Field label="允许的网段">
              <input className="input" value={draft.wireGuardAllowedIPs} onChange={(event) => patch({ wireGuardAllowedIPs: event.target.value })} />
            </Field>
            <Field label="Reserved（可选）">
              <input className="input" placeholder="1,2,3" value={draft.wireGuardReserved} onChange={(event) => patch({ wireGuardReserved: event.target.value })} />
            </Field>
            <Field label="MTU">
              <input className="input" type="number" value={draft.wireGuardMTU} onChange={(event) => patch({ wireGuardMTU: event.target.value })} />
            </Field>
            <Field label="Persistent Keepalive">
              <input className="input" type="number" min={0} value={draft.wireGuardPersistentKeepalive} onChange={(event) => patch({ wireGuardPersistentKeepalive: event.target.value })} />
            </Field>
            <Field label="DNS（可选）">
              <input className="input" placeholder="1.1.1.1" value={draft.wireGuardDNS} onChange={(event) => patch({ wireGuardDNS: event.target.value })} />
            </Field>
          </div>
        )}

        {usesPassword && kind === 'ssh' && (
          <div className="hint">SSH 当前只导出密码登录；私钥登录需要客户端密钥库，暂未在 Web 表单中提供。</div>
        )}

        <div className="hint">
          手动创建的节点保存在本机，不随订阅刷新。保存后可在节点详情里查看字段，并在导出时按客户端能力写入。
        </div>
        {error && <div className="form-error" role="alert"><strong>无法保存</strong><span>{error}</span></div>}
        <div className="actions">
          <button type="submit" className="btn primary">{node ? '保存修改' : '创建节点'}</button>
          <button type="button" className="btn ghost" onClick={onClose}>取消</button>
        </div>
      </form>
    </dialog>
  )
}
