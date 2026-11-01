// 二维码扫码：相机帧和本地图片都只在本机解码，识别后交给添加订阅弹窗。
import { useEffect, useRef, useState } from 'react'
import { decodeQrFile, decodeQrPixels } from '../util/qrScan'

export function QrScanner({ onDecoded }: { onDecoded: (value: string) => void }) {
  const videoRef = useRef<HTMLVideoElement>(null)
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const streamRef = useRef<MediaStream | null>(null)
  const timerRef = useRef<number | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const [cameraActive, setCameraActive] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const stopCamera = () => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
    for (const track of streamRef.current?.getTracks() ?? []) track.stop()
    streamRef.current = null
    if (videoRef.current) videoRef.current.srcObject = null
    setCameraActive(false)
  }

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) window.clearTimeout(timerRef.current)
      for (const track of streamRef.current?.getTracks() ?? []) track.stop()
      streamRef.current = null
    }
  }, [])

  const scanFrame = () => {
    const video = videoRef.current
    if (!video) return
    if (video.readyState >= 2 && video.videoWidth > 0 && video.videoHeight > 0) {
      const maxSide = 960
      const scale = Math.min(1, maxSide / Math.max(video.videoWidth, video.videoHeight))
      const width = Math.max(1, Math.round(video.videoWidth * scale))
      const height = Math.max(1, Math.round(video.videoHeight * scale))
      const canvas = canvasRef.current ?? document.createElement('canvas')
      canvasRef.current = canvas
      canvas.width = width
      canvas.height = height
      const context = canvas.getContext('2d', { willReadFrequently: true })
      if (context) {
        context.drawImage(video, 0, 0, width, height)
        const data = context.getImageData(0, 0, width, height)
        const value = decodeQrPixels(data.data, width, height)
        if (value) {
          stopCamera()
          onDecoded(value)
          return
        }
      }
    }
    timerRef.current = window.setTimeout(scanFrame, 300)
  }

  const startCamera = async () => {
    setError('')
    if (!window.isSecureContext) {
      setError('当前页面不是 HTTPS 或 localhost，浏览器不会允许相机；请改用「选择二维码图片」。')
      return
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      setError('当前浏览器不支持相机扫码；请改用「选择二维码图片」。')
      return
    }
    setBusy(true)
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' } },
        audio: false,
      })
      streamRef.current = stream
      const video = videoRef.current
      if (!video) throw new Error('相机预览没有准备好')
      video.srcObject = stream
      await video.play()
      setCameraActive(true)
      scanFrame()
    } catch (e) {
      stopCamera()
      setError(`无法打开相机：${(e as Error).message}`)
    } finally {
      setBusy(false)
    }
  }

  const readFile = async (file: File | undefined) => {
    if (!file) return
    setBusy(true)
    setError('')
    try {
      const value = await decodeQrFile(file)
      if (!value) throw new Error('图片里没有识别到二维码')
      stopCamera()
      onDecoded(value)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="qr-scanner">
      <div className="qr-video-wrap">
        <video
          ref={videoRef}
          className={`qr-video${cameraActive ? ' is-active' : ''}`}
          muted
          playsInline
        />
        {!cameraActive && (
          <div className="qr-placeholder">
            <strong>二维码扫码</strong>
            <span>开启相机，或选择本地二维码图片</span>
          </div>
        )}
      </div>
      <div className="row qr-actions">
        <button
          type="button"
          className="btn"
          disabled={busy || cameraActive}
          onClick={() => void startCamera()}
        >开启相机</button>
        {cameraActive && (
          <button type="button" className="btn ghost" onClick={stopCamera}>停止相机</button>
        )}
        <button
          type="button"
          className="btn ghost"
          disabled={busy}
          onClick={() => fileRef.current?.click()}
        >选择二维码图片</button>
        <input
          ref={fileRef}
          className="qr-scan-input"
          type="file"
          accept="image/*,.svg"
          style={{ display: 'none' }}
          onChange={(event) => {
            const file = event.target.files?.[0]
            event.target.value = ''
            void readFile(file)
          }}
        />
      </div>
      {busy && (
        <div className="form-progress" role="status" aria-live="polite">
          <span className="spinner" aria-hidden="true" />
          正在读取二维码…
        </div>
      )}
      {error && <div className="form-error" role="alert"><span>{error}</span></div>}
      <div className="hint">
        相机需要 HTTPS 或 localhost；通过局域网 HTTP 打开时请先保存二维码图片再上传。识别结果只留在本机。
      </div>
    </div>
  )
}
