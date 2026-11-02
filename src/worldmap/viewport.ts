// 世界地图的固定画布尺寸与缩放边界。地图组件的 viewBox 直接使用这些值，
// 纯函数放在这里方便自检，不依赖 React。
export const WORLD_MAP_WIDTH = 960
export const WORLD_MAP_HEIGHT = 500
export const WORLD_MAP_MAX_ZOOM = 4

export interface MapViewBox {
  x: number
  y: number
  w: number
  h: number
}

export const BASE_MAP_VIEW: MapViewBox = {
  x: 0,
  y: 0,
  w: WORLD_MAP_WIDTH,
  h: WORLD_MAP_HEIGHT,
}

/** 保持比例、限制最大倍率，并保证视口不越出地图。 */
export function clampMapView(view: MapViewBox): MapViewBox {
  const width = Math.min(WORLD_MAP_WIDTH, Math.max(WORLD_MAP_WIDTH / WORLD_MAP_MAX_ZOOM, view.w))
  const height = width * WORLD_MAP_HEIGHT / WORLD_MAP_WIDTH
  return {
    x: Math.min(Math.max(0, view.x), WORLD_MAP_WIDTH - width),
    y: Math.min(Math.max(0, view.y), WORLD_MAP_HEIGHT - height),
    w: width,
    h: height,
  }
}

/**
 * 以地图坐标中的 anchor 为中心缩放。anchor 缺省为当前视口中心；
 * 滚轮缩放时调用方传入指针位置换算后的地图坐标。
 */
export function zoomMapView(
  view: MapViewBox,
  factor: number,
  anchorX = view.x + view.w / 2,
  anchorY = view.y + view.h / 2,
): MapViewBox {
  const width = Math.min(
    WORLD_MAP_WIDTH,
    Math.max(WORLD_MAP_WIDTH / WORLD_MAP_MAX_ZOOM, view.w / factor),
  )
  const ratio = width / view.w
  return clampMapView({
    x: anchorX - (anchorX - view.x) * ratio,
    y: anchorY - (anchorY - view.y) * ratio,
    w: width,
    h: view.h * ratio,
  })
}

/** 把某个地区放到视口中心；倍率不高于上限，也不会比当前更远。 */
export function focusMapView(x: number, y: number, targetScale: number): MapViewBox {
  const width = Math.min(
    WORLD_MAP_WIDTH,
    Math.max(WORLD_MAP_WIDTH / WORLD_MAP_MAX_ZOOM, WORLD_MAP_WIDTH / targetScale),
  )
  const height = width * WORLD_MAP_HEIGHT / WORLD_MAP_WIDTH
  return clampMapView({
    x: x - width / 2,
    y: y - height / 2,
    w: width,
    h: height,
  })
}
