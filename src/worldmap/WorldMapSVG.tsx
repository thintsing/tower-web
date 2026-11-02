// Tower Web 全球节点分布图 — SVG + react-simple-maps + world-atlas
// 与 framed-sheet 设计对齐：equalEarth 投影 + graticule faint + latency band 国家染色 + 首都 marker。
// 交互：滚轮 / 按钮缩放、拖动平移、低倍率地区聚合、地区清单与节点列表。
// 所有数据均从本地构建资产获取，不联网第三方。
import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'
import { ComposableMap, Geographies, Geography, Graticule } from 'react-simple-maps'
import { geoEqualEarth, type GeoProjection } from 'd3-geo'
import { PROXY_KIND_TITLES, type ProxyNode } from '../models/types'
import { regionForNode, iso3ForRegionCode, type NodeRegion } from '../models/region'
import { nodeShareText } from '../generator/shareLink'
import { copyToClipboard } from '../util/browser'
import { clusterPoints, type ClusterGroup } from './clustering'
import { countryNumericCode } from './countryCodes'
import {
  BASE_MAP_VIEW,
  focusMapView,
  WORLD_MAP_HEIGHT,
  WORLD_MAP_MAX_ZOOM,
  WORLD_MAP_WIDTH,
  zoomMapView,
  type MapViewBox,
} from './viewport'

// world-atlas 110m countries — 与 dist 一起打包到 public/。
const GEO_URL = '/world-atlas.json'
const BASE_WIDTH = WORLD_MAP_WIDTH
const BASE_HEIGHT = WORLD_MAP_HEIGHT
const MAX_ZOOM = WORLD_MAP_MAX_ZOOM
const CLUSTER_RADIUS_PX = 26

/** Latency color bands —— 与 Tower iOS 一致：≤100 / ≤200 / ≤350 / >350ms。 */
const BANDS: { max: number; fill: string }[] = [
  { max: 100, fill: '#1f7a52' },      // 很快 ≤100ms
  { max: 200, fill: '#2f7f78' },      // 正常 101–200ms
  { max: 350, fill: '#9a671f' },      // 偏慢 201–350ms
  { max: Infinity, fill: '#b13a32' }, // 很慢 >350ms
]
const UNREACHABLE_FILL = '#b13a32'
const HAS_NODES_UNTESTED = '#c8ccc4'
const NO_NODES = '#ffffff'
const BORDER = '#dfe2da'
const BAND_UNREACHABLE_OPAQ = 0.55

interface CountryStat {
  numeric: string
  iso3: string
  code: string
  region: NodeRegion
  nodes: ProxyNode[]
  count: number
  latencies: number[]
  unreachableCount: number
  avgLatency: number
  medianLatency?: number
  allUnreachable: boolean
}

interface CountryMapData {
  stats: Map<string, CountryStat>
  unlocatedCount: number
}

function median(values: number[]): number | undefined {
  if (values.length === 0) return undefined
  const sorted = [...values].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 0
    ? Math.round((sorted[middle - 1] + sorted[middle]) / 2)
    : sorted[middle]
}

function computeCountryStats(
  nodes: ProxyNode[],
  latencyByNodeId: Map<string, number | null>,
): CountryMapData {
  const stats = new Map<string, CountryStat>()
  let unlocatedCount = 0
  for (const node of nodes) {
    if (node.isSubscriptionMetadata) continue
    const region = regionForNode(node)
    if (!region) { unlocatedCount += 1; continue }
    const iso3 = iso3ForRegionCode(region.code) ?? region.code.toUpperCase()
    const numeric = countryNumericCode(region.code) ?? iso3
    let stat = stats.get(numeric)
    if (!stat) {
      stat = {
        numeric,
        iso3,
        code: region.code,
        region,
        nodes: [],
        count: 0,
        latencies: [],
        unreachableCount: 0,
        avgLatency: Infinity,
        allUnreachable: false,
      }
      stats.set(numeric, stat)
    }
    stat.nodes.push(node)
    stat.count += 1
    const latency = latencyByNodeId.get(node.id)
    if (latency === null) stat.unreachableCount += 1
    else if (latency !== undefined) stat.latencies.push(latency)
  }
  for (const stat of stats.values()) {
    stat.avgLatency = stat.latencies.length
      ? stat.latencies.reduce((sum, value) => sum + value, 0) / stat.latencies.length
      : Infinity
    stat.medianLatency = median(stat.latencies)
    stat.allUnreachable = stat.count > 0 && stat.unreachableCount === stat.count
    stat.nodes.sort((a, b) => {
      const left = latencyByNodeId.get(a.id)
      const right = latencyByNodeId.get(b.id)
      const rank = (value: number | null | undefined) => value === undefined ? 1 : value === null ? 2 : 0
      const order = rank(left) - rank(right)
      if (order !== 0) return order
      if (typeof left === 'number' && typeof right === 'number' && left !== right) return left - right
      return a.name.localeCompare(b.name, 'zh-CN')
    })
  }
  return { stats, unlocatedCount }
}

function countryFill(stat: CountryStat | undefined): string {
  if (!stat || stat.count === 0) return NO_NODES
  if (stat.allUnreachable) return UNREACHABLE_FILL
  if (stat.latencies.length === 0) return HAS_NODES_UNTESTED
  const band = BANDS.find((item) => stat.avgLatency < item.max) ?? BANDS[BANDS.length - 1]
  return band.fill
}

function clusterFill(countries: CountryStat[]): string {
  const total = countries.reduce((sum, stat) => sum + stat.count, 0)
  const unreachable = countries.reduce((sum, stat) => sum + stat.unreachableCount, 0)
  if (total > 0 && unreachable === total) return UNREACHABLE_FILL
  const latencies = countries.flatMap((stat) => stat.latencies)
  if (latencies.length === 0) return HAS_NODES_UNTESTED
  const average = latencies.reduce((sum, value) => sum + value, 0) / latencies.length
  const band = BANDS.find((item) => average < item.max) ?? BANDS[BANDS.length - 1]
  return band.fill
}

function latencyTone(value: number | null | undefined): string {
  if (value === null) return 'negative'
  if (value === undefined) return 'muted'
  if (value < 100) return 'positive'
  if (value < 200) return 'normal'
  if (value < 350) return 'warning'
  return 'negative'
}

function latencyText(value: number | null | undefined): string {
  if (value === null) return '不可达'
  if (value === undefined) return '未测速'
  return `${value} ms`
}

type ViewBox = MapViewBox

interface MarkerPoint extends CountryStat {
  id: string
  x: number
  y: number
  weight: number
}

interface HoverInfo {
  countries: CountryStat[]
  x: number
  y: number
}

export interface WorldMapSVGProps {
  nodes: ProxyNode[]
  latencyByNodeId: Map<string, number | null>
  selectedCode: string | null
  onSelect: (code: string | null) => void
  /** 地图上的全部测速 / 取消按钮；不传时不显示。 */
  onTest?: () => void
  testing?: boolean
}

export function WorldMapSVG({
  nodes,
  latencyByNodeId,
  selectedCode,
  onSelect,
  onTest,
  testing = false,
}: WorldMapSVGProps) {
  const [geo, setGeo] = useState<unknown>(null)
  const [geoFailed, setGeoFailed] = useState(false)
  const [hover, setHover] = useState<HoverInfo | null>(null)
  const [copiedNodeID, setCopiedNodeID] = useState<string | null>(null)
  const [view, setView] = useState<ViewBox>(BASE_MAP_VIEW)
  const [dragging, setDragging] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const dragRef = useRef<{
    pointerId: number
    startX: number
    startY: number
    view: ViewBox
    moved: boolean
    captured: boolean
  } | null>(null)
  const suppressClickRef = useRef(false)
  const suppressTimer = useRef<number | undefined>(undefined)

  const projection = useMemo<GeoProjection>(
    () => geoEqualEarth().fitSize([BASE_WIDTH, BASE_HEIGHT], { type: 'Sphere' }),
    [],
  )
  const scale = BASE_WIDTH / view.w

  useEffect(() => {
    fetch(GEO_URL)
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        return response.json()
      })
      .then((data) => setGeo(data))
      .catch(() => setGeoFailed(true))
  }, [])

  const { stats, unlocatedCount } = useMemo(
    () => computeCountryStats(nodes, latencyByNodeId),
    [nodes, latencyByNodeId],
  )
  const statList = useMemo(
    () => [...stats.values()].sort((a, b) => b.count - a.count || a.code.localeCompare(b.code)),
    [stats],
  )

  const markerPoints = useMemo<MarkerPoint[]>(() => {
    const points: MarkerPoint[] = []
    for (const stat of stats.values()) {
      const point = projection([stat.region.lon, stat.region.lat])
      if (!point) continue
      points.push({
        ...stat,
        id: stat.numeric,
        x: point[0],
        y: point[1],
        weight: stat.count,
      })
    }
    return points
  }, [projection, stats])

  const selectedNumeric = useMemo(() => {
    if (!selectedCode) return undefined
    return [...stats.values()].find((stat) => stat.code === selectedCode)?.numeric
  }, [selectedCode, stats])

  const markerGroups = useMemo(
    () => clusterPoints(markerPoints, CLUSTER_RADIUS_PX * (view.w / BASE_WIDTH), selectedNumeric),
    [markerPoints, view.w, selectedNumeric],
  )

  // 选中的地区被删除 / 重新归类后，自动收起节点列表。
  useEffect(() => {
    if (selectedCode && !statList.some((stat) => stat.code === selectedCode)) onSelect(null)
  }, [onSelect, selectedCode, statList])

  const zoomAt = useCallback((factor: number, clientX?: number, clientY?: number) => {
    setHover(null)
    setView((current) => {
      let anchorX = current.x + current.w / 2
      let anchorY = current.y + current.h / 2
      const rect = containerRef.current?.getBoundingClientRect()
      if (rect && clientX !== undefined && clientY !== undefined) {
        anchorX = current.x + ((clientX - rect.left) / rect.width) * current.w
        anchorY = current.y + ((clientY - rect.top) / rect.height) * current.h
      }
      return zoomMapView(current, factor, anchorX, anchorY)
    })
  }, [])

  const focusOn = useCallback((x: number, y: number, targetScale: number) => {
    setHover(null)
    setView(focusMapView(x, y, targetScale))
  }, [])

  // Ctrl / ⌘ + 滚轮缩放；普通滚轮继续滚动页面，避免地图劫持整页滚动。
  useEffect(() => {
    const element = containerRef.current
    if (!element) return
    const onWheel = (event: WheelEvent) => {
      if (!event.ctrlKey && !event.metaKey) return
      event.preventDefault()
      zoomAt(event.deltaY < 0 ? 1.25 : 1 / 1.25, event.clientX, event.clientY)
    }
    element.addEventListener('wheel', onWheel, { passive: false })
    return () => element.removeEventListener('wheel', onWheel)
  }, [zoomAt])

  useEffect(() => () => {
    if (suppressTimer.current !== undefined) window.clearTimeout(suppressTimer.current)
  }, [])

  const clearSuppressSoon = () => {
    if (suppressTimer.current !== undefined) window.clearTimeout(suppressTimer.current)
    suppressTimer.current = window.setTimeout(() => { suppressClickRef.current = false }, 160)
  }

  const handlePointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.button !== 0 || scale <= 1.001) return
    if ((event.target as Element).closest('.wm-controls')) return
    dragRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      view,
      moved: false,
      captured: false,
    }
    setDragging(true)
    setHover(null)
  }

  const handlePointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current
    if (!drag || drag.pointerId !== event.pointerId) return
    const rect = containerRef.current?.getBoundingClientRect()
    if (!rect) return
    const movedX = event.clientX - drag.startX
    const movedY = event.clientY - drag.startY
    if (!drag.moved && Math.abs(movedX) + Math.abs(movedY) > 4) {
      drag.moved = true
      // 只有真正开始拖动才捕获指针：不拖动时保留国家点击，
      // 拖动时指针移出地图也能继续平移。
      try {
        event.currentTarget.setPointerCapture(event.pointerId)
        drag.captured = true
      } catch {
        drag.captured = false
      }
    }
    if (!drag.moved) return
    const mapX = movedX * drag.view.w / rect.width
    const mapY = movedY * drag.view.h / rect.height
    setView({
      ...drag.view,
      x: Math.min(Math.max(0, drag.view.x - mapX), BASE_WIDTH - drag.view.w),
      y: Math.min(Math.max(0, drag.view.y - mapY), BASE_HEIGHT - drag.view.h),
    })
  }

  const handlePointerUp = (event: ReactPointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current
    if (!drag || drag.pointerId !== event.pointerId) return
    if (drag.moved) {
      suppressClickRef.current = true
      clearSuppressSoon()
    }
    dragRef.current = null
    setDragging(false)
  }

  // 未捕获指针时，离开地图就结束本次手势，避免拖动状态残留。
  const handlePointerLeave = () => {
    if (!dragRef.current || dragRef.current.captured) return
    if (dragRef.current.moved) {
      suppressClickRef.current = true
      clearSuppressSoon()
    }
    dragRef.current = null
    setDragging(false)
  }

  const handleCountryClick = (stat: CountryStat) => {
    if (suppressClickRef.current) {
      suppressClickRef.current = false
      return
    }
    onSelect(selectedCode === stat.code ? null : stat.code)
  }

  const handleClusterClick = (group: ClusterGroup<MarkerPoint>) => {
    if (suppressClickRef.current) {
      suppressClickRef.current = false
      return
    }
    if (group.points.length === 1) {
      handleCountryClick(group.points[0])
      return
    }
    focusOn(group.x, group.y, Math.min(MAX_ZOOM, Math.max(1.8, scale * 1.5)))
  }

  const handleRegionChip = (stat: CountryStat) => {
    if (selectedCode === stat.code) {
      onSelect(null)
      return
    }
    onSelect(stat.code)
    const point = projection([stat.region.lon, stat.region.lat])
    if (point) focusOn(point[0], point[1], Math.max(1.8, scale))
  }

  const tooltipPosition = (mapX: number, mapY: number): { x: number; y: number } | null => {
    const wrap = containerRef.current
    if (!wrap) return null
    const wrapRect = wrap.getBoundingClientRect()
    const svg = wrap.querySelector('svg')
    if (!svg) return null
    const svgRect = svg.getBoundingClientRect()
    const x = (mapX - view.x) * (svgRect.width / view.w) + (svgRect.left - wrapRect.left)
    const y = (mapY - view.y) * (svgRect.height / view.h) + (svgRect.top - wrapRect.top)
    return {
      x: Math.min(Math.max(8, x), Math.max(8, wrapRect.width - 250)),
      y: Math.min(Math.max(8, y + 12), Math.max(8, wrapRect.height - 120)),
    }
  }

  const showHover = (countries: CountryStat[], mapX: number, mapY: number) => {
    const position = tooltipPosition(mapX, mapY)
    if (position) setHover({ countries, ...position })
  }

  const selectedStat = selectedCode
    ? statList.find((stat) => stat.code === selectedCode)
    : undefined
  const totalLocated = statList.reduce((sum, stat) => sum + stat.count, 0)

  if (!geo) {
    return (
      <div role="status" className="wm-loading">
        {geoFailed ? '地图数据加载失败，请刷新页面重试' : '地图加载中…'}
      </div>
    )
  }

  const screenScale = view.w / BASE_WIDTH

  return (
    <div className="wm-root">
      <div
        ref={containerRef}
        className="wm-wrap"
        style={{
          cursor: scale > 1.001 ? (dragging ? 'grabbing' : 'grab') : 'default',
          touchAction: scale > 1.001 ? 'none' : 'pan-y',
        }}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerCancel={handlePointerUp}
        onPointerLeave={handlePointerLeave}
      >
        <ComposableMap
          projection={projection as any}
          width={BASE_WIDTH}
          height={BASE_HEIGHT}
          viewBox={`${view.x} ${view.y} ${view.w} ${view.h}`}
          style={{ width: '100%', height: 'auto', display: 'block' }}
        >
          <g>
            {/* 点击海洋 / 空白处取消地区筛选（文案「点击空白取消」的实际行为） */}
            <rect
              width={BASE_WIDTH}
              height={BASE_HEIGHT}
              fill="#f3f4ee"
              onClick={() => {
                if (suppressClickRef.current) { suppressClickRef.current = false; return }
                onSelect(null)
              }}
            />
            <Graticule stroke="#e3e5df" strokeWidth={0.5} strokeDasharray="2 3" />
            <Geographies geography={geo as any}>
              {({ geographies }) =>
                geographies.map((geography: any) => {
                  const numeric: string = String(geography.id ?? '')
                  const stat = stats.get(numeric)
                  const selected = !!selectedCode && stat?.code === selectedCode
                  const fill = countryFill(stat)
                  return (
                    <Geography
                      key={geography.rsmKey}
                      geography={geography}
                      fill={fill}
                      stroke={selected ? '#131416' : BORDER}
                      strokeWidth={selected ? 1.2 : 0.5}
                      vectorEffect="non-scaling-stroke"
                      style={{
                        default: { outline: 'none' },
                        hover: { outline: 'none', cursor: stat ? (scale > 1.001 ? 'grab' : 'pointer') : 'default' },
                        pressed: { outline: 'none' },
                      } as any}
                      onClick={() => {
                        if (suppressClickRef.current) { suppressClickRef.current = false; return }
                        if (stat) handleCountryClick(stat)
                        else onSelect(null)
                      }}
                      onMouseEnter={() => {
                        if (!stat) return
                        const point = projection([stat.region.lon, stat.region.lat])
                        if (point) showHover([stat], point[0], point[1])
                      }}
                      onMouseLeave={() => setHover(null)}
                    />
                  )
                })
              }
            </Geographies>
            {markerGroups.map((group) => {
              const countries = group.points
              const total = countries.reduce((sum, stat) => sum + stat.count, 0)
              const selected = countries.some((stat) => stat.code === selectedCode)
              const clustered = countries.length > 1
              const fill = clusterFill(countries)
              const radius = Math.max(3, Math.min(clustered ? 12 : 10, 3 + Math.sqrt(total))) * screenScale
              const fontSize = 10 * screenScale
              return (
                <g
                  key={group.id}
                  transform={`translate(${group.x} ${group.y})`}
                  style={{ cursor: 'pointer' }}
                  onClick={(event) => {
                    event.stopPropagation()
                    handleClusterClick(group)
                  }}
                  onMouseEnter={() => showHover(countries, group.x, group.y)}
                  onMouseLeave={() => setHover(null)}
                >
                  <circle r={Math.max(radius, 12 * screenScale)} fill="transparent" />
                  <circle
                    r={radius}
                    fill={fill}
                    stroke="#fffdf6"
                    strokeWidth={selected ? 1.5 : 1}
                    vectorEffect="non-scaling-stroke"
                    opacity={countries.every((stat) => stat.allUnreachable) ? BAND_UNREACHABLE_OPAQ : 1}
                  />
                  {selected && (
                    <circle
                      r={radius + 4 * screenScale}
                      fill="none"
                      stroke="var(--text)"
                      strokeWidth={1}
                      vectorEffect="non-scaling-stroke"
                      opacity={0.7}
                    />
                  )}
                  {(clustered || total >= 2) && (
                    <text
                      y={0.5}
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fontSize={fontSize}
                      fontWeight={700}
                      fill="#ffffff"
                      style={{ pointerEvents: 'none', userSelect: 'none' }}
                    >
                      {total}
                    </text>
                  )}
                </g>
              )
            })}
          </g>
        </ComposableMap>
        {hover && <MapTooltip hover={hover} />}
        {onTest && (
          <button
            type="button"
            className="wm-test"
            onClick={onTest}
            aria-label={testing ? '取消地图测速' : '对地图中的节点全部测速'}
          >
            {testing ? '取消测速' : '全部测速'}
          </button>
        )}
        <div className="wm-controls" aria-label="地图缩放控制">
          <button
            type="button"
            className="wm-control"
            aria-label="放大地图"
            disabled={view.w <= BASE_WIDTH / MAX_ZOOM + 0.001}
            onClick={() => zoomAt(1.25)}
          >+</button>
          <button
            type="button"
            className="wm-control"
            aria-label="缩小地图"
            disabled={view.w >= BASE_WIDTH - 0.001}
            onClick={() => zoomAt(1 / 1.25)}
          >−</button>
          {(view.w < BASE_WIDTH - 0.001 || view.x > 0 || view.y > 0) && (
            <button
              type="button"
              className="wm-control wm-reset"
              aria-label="恢复默认视图"
              title="恢复默认视图"
              onClick={() => { setView(BASE_MAP_VIEW); setHover(null) }}
            >⤢</button>
          )}
          <span className="wm-zoom" aria-label={`当前缩放 ${Math.round(scale * 100)}%`}>
            {scale.toFixed(1)}×
          </span>
        </div>
        <WorldMapLegend />
      </div>

      <div className="wm-regions">
        <div className="wm-regions-head">
          <strong>地区聚合</strong>
          <span className="hint">
            {statList.length} 个地区 · {totalLocated} 个节点
            {unlocatedCount > 0 ? ` · ${unlocatedCount} 个未识别地区` : ''}
          </span>
        </div>
        {statList.length > 0 ? (
          <div className="wm-region-chips" role="group" aria-label="按地区筛选节点">
            {statList.map((stat) => (
              <button
                key={stat.numeric}
                type="button"
                className={`wm-region-chip${selectedCode === stat.code ? ' selected' : ''}`}
                aria-pressed={selectedCode === stat.code}
                onClick={() => handleRegionChip(stat)}
              >
                <span className="wm-chip-flag">{stat.region.flag}</span>
                <span className="wm-chip-name">{stat.region.name}</span>
                <span className="num">{stat.count}</span>
                {stat.medianLatency !== undefined && (
                  <span className={`wm-chip-lat ${latencyTone(stat.medianLatency)}`}>
                    {stat.medianLatency}ms
                  </span>
                )}
              </button>
            ))}
          </div>
        ) : (
          <div className="hint">还没有能定位到国家的节点。</div>
        )}
      </div>

      {selectedStat && (
        <div className="wm-selected">
          <div className="wm-selected-head">
            <span className="wm-chip-flag">{selectedStat.region.flag}</span>
            <div>
              <strong>{selectedStat.region.name}</strong>
              <small>
                {selectedStat.count} 个节点
                {selectedStat.medianLatency !== undefined ? ` · 中位延迟 ${selectedStat.medianLatency} ms` : ''}
              </small>
            </div>
            <button
              type="button"
              className="icon-btn"
              onClick={() => onSelect(null)}
              title="收起节点列表"
              aria-label={`收起 ${selectedStat.region.name} 的节点`}
            >×</button>
          </div>
          <ul className="wm-node-list">
            {selectedStat.nodes.map((node) => {
              const latency = latencyByNodeId.get(node.id)
              const share = nodeShareText(node)
              return (
                <li key={node.id}>
                  <span className="wm-node-name">{node.name}</span>
                  <span className="wm-node-protocol">{PROXY_KIND_TITLES[node.kind]}</span>
                  <span className={`wm-node-latency ${latencyTone(latency)}`}>{latencyText(latency)}</span>
                  {share && (
                    <button
                      type="button"
                      className="wm-node-share"
                      onClick={async () => {
                        if (!(await copyToClipboard(share))) return
                        setCopiedNodeID(node.id)
                        window.setTimeout(() => {
                          setCopiedNodeID((current) => current === node.id ? null : current)
                        }, 1600)
                      }}
                    >
                      {copiedNodeID === node.id ? '已复制' : '分享'}
                    </button>
                  )}
                </li>
              )
            })}
          </ul>
        </div>
      )}

      <div className="wm-hint">
        Ctrl / ⌘ + 滚轮缩放；放大后可拖动地图；点击聚合圆点继续放大，点击地区查看节点。
      </div>
    </div>
  )
}

function MapTooltip({ hover }: { hover: HoverInfo }) {
  const [first] = hover.countries
  if (!first) return null
  const total = hover.countries.reduce((sum, stat) => sum + stat.count, 0)
  const latencies = hover.countries.flatMap((stat) => stat.latencies)
  const average = latencies.length
    ? Math.round(latencies.reduce((sum, value) => sum + value, 0) / latencies.length)
    : undefined
  const allUnreachable = hover.countries.every((stat) => stat.allUnreachable)
  return (
    <div className="wm-tooltip" style={{ left: hover.x, top: hover.y }}>
      {hover.countries.length === 1 ? (
        <>
          <div className="wm-t-title">{first.region.flag} {first.region.name}</div>
          <div className="wm-t-row">节点 <span className="num">{first.count}</span></div>
          {first.medianLatency !== undefined && (
            <div className="wm-t-row">中位延迟 <span className="num">{first.medianLatency}ms</span></div>
          )}
          {allUnreachable && <div className="wm-t-row" style={{ color: 'var(--negative)' }}>全部不可达</div>}
          {first.latencies.length === 0 && !first.allUnreachable && (
            <div className="wm-t-row" style={{ color: 'var(--muted)' }}>未测速</div>
          )}
        </>
      ) : (
        <>
          <div className="wm-t-title">{hover.countries.length} 个地区 · {total} 个节点</div>
          {hover.countries.slice(0, 4).map((stat) => (
            <div className="wm-t-row" key={stat.numeric}>
              <span>{stat.region.flag} {stat.region.name}</span>
              <span className="num">{stat.count}</span>
            </div>
          ))}
          {hover.countries.length > 4 && <div className="wm-t-row">…</div>}
          {average !== undefined && <div className="wm-t-row">平均延迟 <span className="num">{average}ms</span></div>}
          {allUnreachable && <div className="wm-t-row" style={{ color: 'var(--negative)' }}>全部不可达</div>}
          <div className="wm-t-hint">点击聚合圆点放大</div>
        </>
      )}
    </div>
  )
}

function WorldMapLegend() {
  return (
    <div className="wm-legend">
      <span className="wm-lg"><span className="wm-sq" style={{ background: NO_NODES }} />无节点</span>
      <span className="wm-lg"><span className="wm-sq" style={{ background: HAS_NODES_UNTESTED }} />有节点（未测速）</span>
      {BANDS.map((band, index) => (
        <span key={index} className="wm-lg">
          <span className="wm-sq" style={{ background: band.fill }} />
          {index === 0 ? '很快 ≤100ms'
            : index === 1 ? '正常 101–200ms'
              : index === 2 ? '偏慢 201–350ms'
                : '很慢 >350ms'}
        </span>
      ))}
      <span className="wm-lg"><span className="wm-sq" style={{ background: UNREACHABLE_FILL, opacity: BAND_UNREACHABLE_OPAQ }} />不可达</span>
    </div>
  )
}
