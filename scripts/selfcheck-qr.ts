// 自检：二维码像素解码（与浏览器相机的 jsQR 路径一致）。
// 用法：npm run selfcheck:qr
import assert from 'node:assert/strict'
import { encode } from 'uqr'
import { decodeQrPixels } from '../src/util/qrScan'

let failures = 0

function check(label: string, run: () => void): void {
  try {
    run()
    console.log(`✓ ${label}`)
  } catch (error) {
    failures += 1
    console.error(`✗ ${label}`)
    console.error(`  ${error instanceof Error ? error.message : String(error)}`)
  }
}

function qrPixels(text: string, scale = 6): { pixels: Uint8ClampedArray; width: number; height: number } {
  const { data, size } = encode(text, { ecc: 'M', border: 4 })
  const width = size * scale
  const height = size * scale
  const pixels = new Uint8ClampedArray(width * height * 4)
  pixels.fill(255)
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      if (!data[y][x]) continue
      for (let dy = 0; dy < scale; dy += 1) {
        for (let dx = 0; dx < scale; dx += 1) {
          const offset = ((y * scale + dy) * width + x * scale + dx) * 4
          pixels[offset] = 0
          pixels[offset + 1] = 0
          pixels[offset + 2] = 0
          pixels[offset + 3] = 255
        }
      }
    }
  }
  return { pixels, width, height }
}

function main(): void {
  check('解码订阅地址二维码', () => {
    const url = 'https://sub.example.com/a?token=demo'
    const image = qrPixels(url)
    assert.equal(decodeQrPixels(image.pixels, image.width, image.height), url)
  })

  check('解码节点 URI 二维码', () => {
    const uri = 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@ss.example.com:8388#QR'
    const image = qrPixels(uri)
    assert.equal(decodeQrPixels(image.pixels, image.width, image.height), uri)
  })

  check('空像素安全返回 undefined', () => {
    assert.equal(decodeQrPixels(new Uint8ClampedArray(4), 1, 1), undefined)
    const blank = new Uint8ClampedArray(64 * 64 * 4)
    blank.fill(255)
    assert.equal(decodeQrPixels(blank, 64, 64), undefined)
  })

  if (failures) {
    console.error(`\n${failures} 项检查失败`)
    process.exit(1)
  }
  console.log('\n全部二维码解码检查通过')
}

main()
