// 订阅二维码弹窗：本地渲染 SVG，可复制订阅地址。
import { useEffect, useMemo, useRef, useState } from 'react'
import { renderSVG } from 'uqr'
import { copyToClipboard } from '../util/browser'

export function QRCodeDialog({
  open,
  url,
  title,
  hint,
  onClose,
}: {
  open: boolean
  url: string
  title: string
  hint: string
  onClose: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (open) ref.current?.showModal()
    else ref.current?.close()
  }, [open])
  useEffect(() => {
    if (!open) setCopied(false)
  }, [open])
  const svg = useMemo(() => {
    if (!open || !url) return ''
    try {
      return renderSVG(url, {
        ecc: 'M',
        border: 2,
        pixelSize: 4,
        blackColor: '#141815',
        whiteColor: '#ffffff',
      })
    } catch {
      return ''
    }
  }, [open, url])
  const copy = async () => {
    if (await copyToClipboard(url)) {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    }
  }
  return (
    <dialog ref={ref} className="qr-dialog" onClose={onClose}>
      <h3>{title} · 扫码导入</h3>
      {svg ? (
        <div className="qr-code" dangerouslySetInnerHTML={{ __html: svg }} />
      ) : (
        <div className="hint">二维码生成失败，请直接复制订阅地址。</div>
      )}
      <div className="qr-hint">{hint}</div>
      <input
        readOnly
        className="input qr-url"
        value={url}
        aria-label="二维码对应的订阅地址"
        onFocus={(e) => e.currentTarget.select()}
      />
      <div className="actions">
        <button className="btn primary" onClick={copy}>{copied ? '已复制' : '复制链接'}</button>
        <button className="btn ghost" onClick={onClose}>关闭</button>
      </div>
    </dialog>
  )
}
