// 地图主题：延迟色阶与色调类名。
// 具体颜色全部在 map-theme.css 的 --wm-* 自定义属性里，TSX 不写死任何 hex，
// 这样浅色 / 深色只需切换 CSS 变量。

export interface LatencyBand {
  max: number
  label: string
  tone: string
}

/** 与 Tower iOS 一致：≤100 / ≤200 / ≤350 / >350ms。 */
export const LATENCY_BANDS: LatencyBand[] = [
  { max: 100, label: '很快 ≤100ms', tone: 'wm-tone-0' },
  { max: 200, label: '正常 101–200ms', tone: 'wm-tone-1' },
  { max: 350, label: '偏慢 201–350ms', tone: 'wm-tone-2' },
  { max: Infinity, label: '很慢 >350ms', tone: 'wm-tone-3' },
]

export const TONE_NO_NODES = 'wm-tone-none'
export const TONE_UNTESTED = 'wm-tone-untested'
export const TONE_UNREACHABLE = 'wm-tone-unreach'

/** 全部不可达时的节点 / 聚合圆透明度。 */
export const UNREACHABLE_OPACITY = 0.55

/** 平均延迟落到的色调类名。 */
export function toneForLatency(latency: number): string {
  const band = LATENCY_BANDS.find((item) => latency < item.max) ?? LATENCY_BANDS[LATENCY_BANDS.length - 1]
  return band.tone
}
