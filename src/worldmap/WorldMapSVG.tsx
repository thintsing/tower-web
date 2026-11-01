// Tower Web 全球节点分布图 — SVG + react-simple-maps + world-atlas
// 与 framed-sheet 设计对齐：equalEarth 投影 + graticule faint + latency band 国家染色 + 首都 marker。
// 所有数据均从本地构建资产获取，不联网第三方。
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ComposableMap, Geographies, Geography, Graticule, Marker } from 'react-simple-maps'
import { geoEqualEarth, type GeoProjection } from 'd3-geo'
import type { ProxyNode } from '../models/types'
import { regionForNode, type NodeRegion } from '../models/region'

// world-atlas 110m countries — 与 dist 一起打包到 public/。
const GEO_URL = '/world-atlas.json'

// world-atlas v2 TopoJSON 只有 numeric ISO id (如 "840" for USA)，我们 regions.ts 用 ISO_A3。
// 从 curated regions 反推的常用 numeric → A3 映射；缺失项 fallback 为 code itself。
const NUMERIC_TO_A3: Record<string, string> = {
  '004': 'AFG', '008': 'ALB', '012': 'DZA', '024': 'AGO', '032': 'ARG', '036': 'AUS', '040': 'AUT',
  '044': 'BHS', '048': 'BHR', '050': 'BGD', '051': 'ARM', '052': 'BRB', '056': 'BEL', '064': 'BTN',
  '068': 'BOL', '070': 'BIH', '072': 'BWA', '076': 'BRA', '084': 'BLZ', '096': 'BRN', '100': 'BGR',
  '104': 'MMR', '108': 'BDI', '112': 'BLR', '116': 'KHM', '120': 'CMR', '124': 'CAN', '140': 'CAF',
  '144': 'LKA', '148': 'TCD', '152': 'CHL', '156': 'CHN', '158': 'TWN', '170': 'COL', '174': 'COM',
  '178': 'COG', '180': 'COD', '188': 'CRI', '191': 'HRV', '192': 'CUB', '196': 'CYP', '203': 'CZE',
  '204': 'BEN', '208': 'DNK', '214': 'DOM', '218': 'ECU', '222': 'SLV', '226': 'GNQ', '231': 'ETH',
  '232': 'ERI', '233': 'EST', '242': 'FJI', '246': 'FIN', '250': 'FRA', '254': 'GUF', '260': 'ATF',
  '262': 'DJI', '266': 'GAB', '268': 'GEO', '270': 'GMB', '275': 'PSE', '276': 'DEU', '288': 'GHA',
  '292': 'GIB', '296': 'GRD', '300': 'GRC', '304': 'GRL', '308': 'GRP', '320': 'GTM', '324': 'GIN',
  '328': 'GUY', '332': 'HTI', '340': 'HND', '344': 'HKG', '348': 'HUN', '352': 'ISL', '356': 'IND',
  '360': 'IDN', '364': 'IRN', '368': 'IRQ', '372': 'IRL', '376': 'ISR', '380': 'ITA', '384': 'CIV',
  '388': 'JAM', '392': 'JPN', '398': 'KAZ', '400': 'JOR', '404': 'KEN', '408': 'PRK', '410': 'KOR',
  '414': 'KWT', '417': 'KGZ', '418': 'LAO', '422': 'LBN', '426': 'LSO', '428': 'LVA', '430': 'LBR',
  '434': 'LBY', '438': 'LIE', '440': 'LTU', '442': 'LUX', '450': 'MDG', '454': 'MWI', '458': 'MYS',
  '462': 'MDV', '466': 'MLI', '470': 'MLT', '474': 'MTQ', '478': 'MRT', '484': 'MEX', '496': 'MNG',
  '498': 'MDA', '499': 'MNE', '504': 'MAR', '508': 'MOZ', '512': 'OMN', '516': 'NAM', '520': 'NRU',
  '524': 'NPL', '528': 'NLD', '540': 'NCL', '548': 'VUT', '554': 'NZL', '558': 'NIC', '562': 'NER',
  '566': 'NGA', '578': 'NOR', '586': 'PAK', '591': 'PAN', '598': 'PNG', '600': 'PRY', '604': 'PER',
  '608': 'PHL', '616': 'POL', '620': 'PRT', '624': 'GNB', '626': 'TLS', '630': 'PRI', '634': 'QAT',
  '642': 'ROU', '643': 'RUS', '646': 'RWA', '682': 'SAU', '686': 'SEN', '688': 'SRB', '694': 'SLE',
  '702': 'SGP', '703': 'SVK', '704': 'VNM', '705': 'SVN', '706': 'SOM', '710': 'ZAF', '716': 'ZWE',
  '724': 'ESP', '728': 'SSD', '729': 'SDN', '732': 'ESH', '740': 'SUR', '748': 'SWZ', '752': 'SWE',
  '756': 'CHE', '760': 'SYR', '762': 'TJK', '764': 'THA', '768': 'TGO', '776': 'TON', '780': 'TTO',
  '784': 'ARE', '788': 'TUN', '792': 'TUR', '795': 'TKM', '796': 'TUV', '800': 'UGA', '804': 'UKR',
  '807': 'MKD', '818': 'EGY', '826': 'GBR', '834': 'TZA', '840': 'USA', '850': 'VIR', '854': 'BFA',
  '858': 'URY', '860': 'UZB', '862': 'VEN', '882': 'WSM', '887': 'YEM', '894': 'ZMB',
}

function toISO3(code: string): string {
  const c = code.toUpperCase().trim()
  if (c.length === 3) return c // 已经是 A3
  // ISO 3166-1 alpha-2 → alpha-3 常见映射 (我们 curated regions.ts 里用到的)
  const ISO2_A3: Record<string, string> = {
    CN: 'CHN', JP: 'JPN', KR: 'KOR', HK: 'HKG', TW: 'TWN',
    US: 'USA', CA: 'CAN', GB: 'GBR', DE: 'DEU', FR: 'FRA', IT: 'ITA', ES: 'ESP',
    NL: 'NLD', BE: 'BEL', CH: 'CHE', SE: 'SWE', NO: 'NOR', FI: 'FIN', DK: 'DNK',
    RU: 'RUS', UA: 'UKR', PL: 'POL', AU: 'AUS', NZ: 'NZL', IN: 'IND', ID: 'IDN',
    TH: 'THA', SG: 'SGP', VN: 'VNM', MY: 'MYS', PH: 'PHL', TR: 'TUR', BR: 'BRA',
    MX: 'MEX', AR: 'ARG', EG: 'EGY', AE: 'ARE', SA: 'SAU', IL: 'ISR', ZA: 'ZAF',
  }
  return ISO2_A3[c] ?? c
}

function toNumeric(code: string): string | undefined {
  const a3 = toISO3(code)
  for (const [num, a3c] of Object.entries(NUMERIC_TO_A3)) {
    if (a3c === a3) return num.padStart(3, '0') // TopoJSON ids are "004", "156"
  }
  return undefined
}

/** Latency color bands — 与节点列表的三档语义保持一致：良好 / 一般 / 较差。 */
const BANDS: { max: number; fill: string }[] = [
  { max: 100, fill: '#1f7a52' },      // 良好 <100ms（--positive）
  { max: 300, fill: '#9a671f' },      // 一般 100–299ms（--warning）
  { max: Infinity, fill: '#b13a32' }, // 较差 ≥300ms（--negative）
]
const UNREACHABLE_FILL = '#b13a32'
const HAS_NODES_UNTESTED = '#c8ccc4'
const NO_NODES = '#ffffff'
const BORDER = '#dfe2da'
const BAND_UNREACHABLE_OPAQ = 0.55

/** 国家统计：节点数、平均 latency、是否全部不可达。 */
interface CountryStat {
  iso3: string
  code: string // 我们的 2 字母
  region?: NodeRegion
  count: number
  latencies: number[]
  unreachableCount: number
  get avgLatency(): number
  get allUnreachable(): boolean
}

function computeCountryStats(
  nodes: ProxyNode[],
  latencyByNodeId: Map<string, number | null>,
): Map<string, CountryStat> {
  const m = new Map<string, CountryStat>()
  for (const n of nodes) {
    if (n.isSubscriptionMetadata) continue
    const region = regionForNode(n)
    if (!region) continue
    // world-atlas v2 TopoJSON 用 numeric ISO 做 feature id (如 "840" for USA)。
    // 我们的 stats Map 也 key 成 numeric ISO，这样 Geography lookup 是 O(1)。
    const numeric = toNumeric(region.code) ?? toISO3(region.code)
    const iso3 = toISO3(region.code)
    const ms = latencyByNodeId.get(n.id)
    let stat = m.get(numeric)
    if (!stat) {
      stat = {
        iso3,
        code: region.code,
        region,
        count: 0,
        latencies: [],
        unreachableCount: 0,
        get avgLatency() { return this.latencies.length ? this.latencies.reduce((a, b) => a + b, 0) / this.latencies.length : Infinity },
        get allUnreachable() { return this.count > 0 && this.unreachableCount === this.count },
      }
      m.set(numeric, stat)
    }
    stat.count++
    if (ms === null) {
      stat.unreachableCount++
    } else if (ms !== undefined) {
      stat.latencies.push(ms)
    }
  }
  return m
}

function countryFill(stat: CountryStat | undefined): string {
  if (!stat) return NO_NODES
  if (stat.count === 0) return NO_NODES
  if (stat.allUnreachable) {
    return UNREACHABLE_FILL
  }
  if (stat.latencies.length === 0) return HAS_NODES_UNTESTED
  const avg = stat.avgLatency
  const band = BANDS.find((b) => avg < b.max) ?? BANDS.at(-1)!
  return band.fill
}

export interface WorldMapSVGProps {
  nodes: ProxyNode[]
  latencyByNodeId: Map<string, number | null>
  selectedCode: string | null
  onSelect: (code: string | null) => void
}

export function WorldMapSVG({ nodes, latencyByNodeId, selectedCode, onSelect }: WorldMapSVGProps) {
  const [geo, setGeo] = useState<unknown>(null)
  const [geoFailed, setGeoFailed] = useState(false)
  const [hover, setHover] = useState<{ key: string; code: string; x: number; y: number } | null>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  // 自己维护 d3 projection — react-simple-maps 3.x 不再暴露 onProjectionReady。
  const projection = useMemo<GeoProjection>(() => geoEqualEarth().fitSize([960, 500], { type: 'Sphere' }), [])

  useEffect(() => {
    fetch(GEO_URL)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then((d) => setGeo(d))
      .catch(() => setGeoFailed(true))
  }, [])

  const countryStats = useMemo(() => computeCountryStats(nodes, latencyByNodeId), [nodes, latencyByNodeId])

  const handleClick = (numeric: string) => {
    const stat = countryStats.get(numeric)
    if (!stat) return
    onSelect(selectedCode === stat.code ? null : stat.code)
  }

  const tooltipContent = hover ? (() => {
    const stat = countryStats.get(hover.key)
    if (!stat) return null
    const avg = stat.latencies.length ? Math.round(stat.avgLatency) : undefined
    return (
      <div
        className="wm-tooltip"
        style={{ left: hover.x, top: hover.y + 12 }}
      >
        <div className="wm-t-title">{stat.region?.flag ?? ''} {stat.region?.name ?? stat.code}</div>
        <div className="wm-t-row">节点 <span className="num">{stat.count}</span></div>
        {stat.latencies.length > 0 && <div className="wm-t-row">平均延迟 <span className="num">{avg}ms</span></div>}
        {stat.allUnreachable && <div className="wm-t-row" style={{ color: 'var(--negative)' }}>全部不可达</div>}
        {stat.latencies.length === 0 && !stat.allUnreachable && <div className="wm-t-row" style={{ color: 'var(--muted)' }}>未测速</div>}
      </div>
    )
  })() : null

  const markers: ReactNode[] = []
  for (const stat of countryStats.values()) {
    if (!stat.region) continue
    const count = stat.count
    const r = Math.max(3, Math.min(10, 3 + Math.sqrt(count)))
    const selected = selectedCode === stat.code
    const allUnr = stat.allUnreachable
    const color = allUnr ? UNREACHABLE_FILL : (() => {
      if (stat.latencies.length === 0) return '#6a6d70'
      const avg = stat.avgLatency
      const band = BANDS.find((b) => avg < b.max) ?? BANDS.at(-1)!
      return band.fill
    })()
    markers.push(
      <g key={stat.iso3}>
        <Marker coordinates={[stat.region.lon, stat.region.lat]}>
          <circle
            r={r}
            fill={color}
            stroke={'#fffdf6'}
            strokeWidth={selected ? 1.5 : 1}
            style={{ cursor: 'pointer', opacity: allUnr ? BAND_UNREACHABLE_OPAQ : 1 }}
          />
          {selected && (
            <circle
              r={r + 4}
              fill="none"
              stroke="var(--text)"
              strokeWidth={1}
              opacity={0.7}
            />
          )}
        </Marker>
      </g>,
    )
  }

  if (!geo) {
    return (
      <div role="status" style={{ height: 360, display: 'grid', placeItems: 'center', color: 'var(--faint)' }}>
        {geoFailed ? '地图数据加载失败，请刷新页面重试' : '地图加载中…'}
      </div>
    )
  }

  return (
    <div
      ref={containerRef}
      className="wm-wrap"
      style={{ position: 'relative', borderRadius: 6, overflow: 'hidden', border: '1px solid var(--border)', background: '#f3f4ee' }}
    >
      <ComposableMap
        projection="geoEqualEarth"
        width={960}
        height={500}
        style={{ width: '100%', height: 'auto', display: 'block' }}
      >
        {/* 不用 ZoomableGroup：它自带一层透明捕获矩形，缩放后 tooltip 坐标也会错位。 */}
        <g>
          {/* 点击海洋 / 空白处取消地区筛选（文案「点击空白取消」的实际行为） */}
          <rect width={960} height={500} fill="#f3f4ee" onClick={() => onSelect(null)} />
          <Graticule stroke="#e3e5df" strokeWidth={0.5} strokeDasharray="2 3" />
          <Geographies geography={geo as any}>
            {({ geographies }) =>
              geographies.map((g: any) => {
                // world-atlas v2 TopoJSON: numeric ISO id on the feature itself, not in properties.
                const numeric: string = String(g.id ?? '')
                const stat = countryStats.get(numeric)
                const selected = !!selectedCode && stat?.code === selectedCode
                const fill = countryFill(stat)
                return (
                  <Geography
                    key={g.rsmKey}
                    geography={g}
                    fill={fill}
                    stroke={selected ? '#131416' : BORDER}
                    strokeWidth={selected ? 1.2 : 0.5}
                    style={{
                      default: { outline: 'none' },
                      hover: { outline: 'none', cursor: stat ? 'pointer' : 'default' },
                      pressed: { outline: 'none' },
                    } as any}
                    onClick={() => (stat ? handleClick(numeric) : onSelect(null))}
                    onMouseEnter={(evt) => {
                      if (!projection || !stat?.region) return
                      const xy = projection([stat.region.lon, stat.region.lat]) as [number, number] | null
                      if (!xy) return
                      const svg = (evt.currentTarget as SVGElement).ownerSVGElement
                      if (!svg) return
                      const svgRect = svg.getBoundingClientRect()
                      const wrapRect = containerRef.current?.getBoundingClientRect()
                      if (!wrapRect) return
                      const scale = svgRect.width / 960
                      const offsetX = svgRect.left - wrapRect.left
                      const offsetY = svgRect.top - wrapRect.top
                      // tooltip 绝对定位在 overflow:hidden 的地图容器内，靠边时向内收，
                      // 否则右侧 / 底部国家的浮层会被裁掉。
                      const x = Math.min(Math.max(8, xy[0] * scale + offsetX), Math.max(8, wrapRect.width - 232))
                      const y = Math.min(Math.max(8, xy[1] * scale + offsetY + 12), Math.max(8, wrapRect.height - 100))
                      setHover({ key: numeric, code: stat.code, x, y })
                    }}
                    onMouseLeave={() => setHover(null)}
                  />
                )
              })
            }
          </Geographies>
          {markers}
        </g>
      </ComposableMap>
      {tooltipContent}
      <WorldMapLegend />
    </div>
  )
}

function WorldMapLegend() {
  return (
    <div className="wm-legend">
      <span className="wm-lg"><span className="wm-sq" style={{ background: NO_NODES }} />无节点</span>
      <span className="wm-lg"><span className="wm-sq" style={{ background: HAS_NODES_UNTESTED }} />有节点（未测速）</span>
      {BANDS.map((b, i) => (
        <span key={i} className="wm-lg">
          <span className="wm-sq" style={{ background: b.fill }} />
          {i === 0 ? '良好 <100ms' : i === 1 ? '一般 100–299ms' : '较差 ≥300ms'}
        </span>
      ))}
      <span className="wm-lg"><span className="wm-sq" style={{ background: UNREACHABLE_FILL, opacity: BAND_UNREACHABLE_OPAQ }} />不可达</span>
    </div>
  )
}
