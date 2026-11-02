// Screen-independent marker grouping for the world map. Points are in map
// coordinates; callers shrink the radius as the viewport zooms in so nearby
// countries separate naturally.

export interface ClusterPoint {
  id: string
  x: number
  y: number
  weight: number
}

export interface ClusterGroup<T extends ClusterPoint> {
  id: string
  points: T[]
  x: number
  y: number
  weight: number
}

function weightedCenter<T extends ClusterPoint>(points: T[]): { x: number; y: number } {
  let total = 0
  let x = 0
  let y = 0
  for (const point of points) {
    const weight = Math.max(point.weight, 1)
    total += weight
    x += point.x * weight
    y += point.y * weight
  }
  return { x: x / total, y: y / total }
}

function makeGroup<T extends ClusterPoint>(points: T[]): ClusterGroup<T> {
  const center = weightedCenter(points)
  return {
    id: points.map((point) => point.id).sort().join('+'),
    points,
    ...center,
    weight: points.reduce((total, point) => total + Math.max(point.weight, 1), 0),
  }
}

/**
 * Greedy grouping by marker weight. The selected marker stays on its own so a
 * highlighted country never disappears inside a cluster. Points must use the
 * same coordinate space as `radius`.
 */
export function clusterPoints<T extends ClusterPoint>(
  points: T[],
  radius: number,
  keepSeparateID?: string,
): ClusterGroup<T>[] {
  const separate = keepSeparateID ? points.find((point) => point.id === keepSeparateID) : undefined
  const remaining = points
    .filter((point) => point.id !== keepSeparateID)
    .sort((a, b) => b.weight - a.weight || a.id.localeCompare(b.id))
  const groups: ClusterGroup<T>[] = []

  while (remaining.length > 0) {
    const seed = remaining.shift()!
    const members = [seed]
    for (let index = 0; index < remaining.length;) {
      const candidate = remaining[index]
      if (Math.hypot(candidate.x - seed.x, candidate.y - seed.y) <= radius) {
        members.push(candidate)
        remaining.splice(index, 1)
      } else {
        index += 1
      }
    }
    groups.push(makeGroup(members))
  }
  if (separate) groups.push(makeGroup([separate]))
  return groups
}
