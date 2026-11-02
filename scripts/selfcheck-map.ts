// 自检：地图地区聚合的贪心分组、加权中心和选中项独立显示。
// 用法：npm run selfcheck:map
import assert from 'node:assert/strict'
import { clusterPoints } from '../src/worldmap/clustering'
import {
  BASE_MAP_VIEW,
  clampMapView,
  focusMapView,
  zoomMapView,
  WORLD_MAP_HEIGHT,
  WORLD_MAP_MAX_ZOOM,
  WORLD_MAP_WIDTH,
} from '../src/worldmap/viewport'

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

const point = (id: string, x: number, y: number, weight: number) => ({ id, x, y, weight })

check('低倍率：邻近地区合并，远处地区保持独立', () => {
  const groups = clusterPoints([
    point('a', 0, 0, 5),
    point('b', 10, 0, 3),
    point('c', 100, 0, 4),
    point('d', 110, 0, 2),
  ], 30)
  assert.equal(groups.length, 2)
  assert.deepEqual(groups[0].points.map((item) => item.id), ['a', 'b'])
  assert.deepEqual(groups[1].points.map((item) => item.id), ['c', 'd'])
})

check('聚合圆点使用节点数加权中心', () => {
  const groups = clusterPoints([
    point('a', 0, 0, 1),
    point('b', 40, 20, 3),
  ], 60)
  assert.equal(groups.length, 1)
  assert.equal(groups[0].x, 30)
  assert.equal(groups[0].y, 15)
  assert.equal(groups[0].weight, 4)
})

check('高倍率：缩小半径后原本连成一片的地区拆开', () => {
  const groups = clusterPoints([
    point('a', 0, 0, 5),
    point('b', 10, 0, 3),
    point('c', 35, 0, 4),
    point('d', 45, 0, 2),
  ], 12)
  assert.equal(groups.length, 2)
  assert.deepEqual(groups.map((group) => group.id), ['a+b', 'c+d'])
})

check('选中的地区不进入聚合，始终单独显示', () => {
  const groups = clusterPoints([
    point('jp', 0, 0, 10),
    point('kr', 10, 0, 3),
    point('cn', 100, 0, 8),
  ], 30, 'jp')
  const selected = groups.find((group) => group.points.some((item) => item.id === 'jp'))
  assert.ok(selected)
  assert.deepEqual(selected.points.map((item) => item.id), ['jp'])
  assert.equal(selected.weight, 10)
  assert.equal(groups.length, 3)
})

check('空输入与单个地区安全返回', () => {
  assert.deepEqual(clusterPoints([], 30), [])
  const groups = clusterPoints([point('only', 12, 8, 2)], 30)
  assert.equal(groups.length, 1)
  assert.equal(groups[0].points[0].id, 'only')
})

check('缩放限制在 1×–4×，并保持画布比例', () => {
  const zoomed = zoomMapView(BASE_MAP_VIEW, 2)
  assert.equal(zoomed.w, WORLD_MAP_WIDTH / 2)
  assert.equal(zoomed.h, WORLD_MAP_HEIGHT / 2)
  assert.equal(zoomed.x, WORLD_MAP_WIDTH / 4)
  assert.equal(zoomed.y, WORLD_MAP_HEIGHT / 4)

  const maximum = zoomMapView(BASE_MAP_VIEW, 100)
  assert.equal(maximum.w, WORLD_MAP_WIDTH / WORLD_MAP_MAX_ZOOM)
  assert.equal(maximum.h, WORLD_MAP_HEIGHT / WORLD_MAP_MAX_ZOOM)

  const minimum = zoomMapView(zoomed, 0.01)
  assert.deepEqual(minimum, BASE_MAP_VIEW)
})

check('以指针位置缩放时，锚点保持相对位置', () => {
  const zoomed = zoomMapView(BASE_MAP_VIEW, 2, 100, 100)
  assert.equal(zoomed.x, 50)
  assert.equal(zoomed.y, 50)
  assert.equal((100 - zoomed.x) / zoomed.w, 100 / WORLD_MAP_WIDTH)
  assert.equal((100 - zoomed.y) / zoomed.h, 100 / WORLD_MAP_HEIGHT)
})

check('拖动视口会被夹在地图边界内', () => {
  const small = { x: 0, y: 0, w: WORLD_MAP_WIDTH / 2, h: WORLD_MAP_HEIGHT / 2 }
  assert.deepEqual(clampMapView({ ...small, x: -50, y: -80 }), small)
  assert.deepEqual(
    clampMapView({ ...small, x: 10_000, y: 10_000 }),
    { ...small, x: WORLD_MAP_WIDTH / 2, y: WORLD_MAP_HEIGHT / 2 },
  )
})

check('聚焦地区时居中并遵守最大倍率', () => {
  const focused = focusMapView(WORLD_MAP_WIDTH / 2, WORLD_MAP_HEIGHT / 2, 2)
  assert.equal(focused.w, WORLD_MAP_WIDTH / 2)
  assert.equal(focused.x, WORLD_MAP_WIDTH / 4)
  assert.equal(focused.y, WORLD_MAP_HEIGHT / 4)

  const extreme = focusMapView(0, 0, 100)
  assert.equal(extreme.w, WORLD_MAP_WIDTH / WORLD_MAP_MAX_ZOOM)
  assert.equal(extreme.x, 0)
  assert.equal(extreme.y, 0)
})

if (failures) {
  console.error(`\n${failures} 项检查失败`)
  process.exit(1)
}
console.log('\n全部地图聚合检查通过')
