// 二维码解码：相机帧和本地图片都先画到 canvas，再交给 jsQR。
// 不请求第三方二维码服务，图片和像素只在本机内存里处理。
import jsQR from 'jsqr'

export function decodeQrPixels(
  pixels: Uint8ClampedArray,
  width: number,
  height: number,
): string | undefined {
  if (width <= 0 || height <= 0 || pixels.length < width * height * 4) return undefined
  const result = jsQR(pixels, width, height, { inversionAttempts: 'attemptBoth' })
  const value = result?.data?.trim()
  return value || undefined
}

function loadImage(url: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const image = new Image()
    image.onload = () => resolve(image)
    image.onerror = () => reject(new Error('无法读取这张图片'))
    image.src = url
  })
}

/** 读取本地二维码图片；限制画布尺寸，避免超大照片占用过多内存。 */
export async function decodeQrFile(file: File): Promise<string | undefined> {
  const objectURL = URL.createObjectURL(file)
  try {
    const image = await loadImage(objectURL)
    const naturalWidth = image.naturalWidth || image.width || 512
    const naturalHeight = image.naturalHeight || image.height || 512
    const maxSide = 1600
    const scale = Math.min(1, maxSide / Math.max(naturalWidth, naturalHeight))
    const width = Math.max(1, Math.round(naturalWidth * scale))
    const height = Math.max(1, Math.round(naturalHeight * scale))
    const canvas = document.createElement('canvas')
    canvas.width = width
    canvas.height = height
    const context = canvas.getContext('2d', { willReadFrequently: true })
    if (!context) throw new Error('浏览器无法创建图片画布')
    context.fillStyle = '#ffffff'
    context.fillRect(0, 0, width, height)
    context.drawImage(image, 0, 0, width, height)
    const data = context.getImageData(0, 0, width, height)
    return decodeQrPixels(data.data, width, height)
  } finally {
    URL.revokeObjectURL(objectURL)
  }
}
