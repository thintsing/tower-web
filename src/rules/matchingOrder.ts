// 拖动策略组后调整规则匹配顺序。移植自 Tower iOS：
// 只移动被拖动的组，尽量保留原来的相对顺序；规则里的 GEOIP 兜底不移动。
import type { RoutingRule } from '../models/types'

/** 规则实际触达的策略组，按匹配顺序去重。 */
export function matchingGroupNames(
  rules: RoutingRule[],
  knownGroups?: Set<string>,
): string[] {
  const seen = new Set<string>()
  const names: string[] = []
  for (const rule of rules) {
    const name = rule.group
    if (!name || seen.has(name)) continue
    if (knownGroups && !knownGroups.has(name)) continue
    seen.add(name)
    names.push(name)
  }
  return names
}

/**
 * 拖动后新的匹配顺序。往下拖过原本排在前面的组时，移到最后一个被越过组之后；
 * 往上拖时移到第一个被越过组之前。只调整被拖动的组。
 */
export function matchingOrderAfterDragging(
  name: string,
  previousDisplay: string[],
  displayOrder: string[],
  currentMatching: string[],
): string[] {
  const position = currentMatching.indexOf(name)
  const oldIndex = previousDisplay.indexOf(name)
  const newIndex = displayOrder.indexOf(name)
  if (position < 0 || oldIndex < 0 || newIndex < 0 || oldIndex === newIndex) {
    return currentMatching
  }
  const movedDown = newIndex > oldIndex
  const passed = new Set(
    (movedDown
      ? displayOrder.slice(oldIndex, newIndex)
      : displayOrder.slice(newIndex + 1, oldIndex + 1)
    ).filter((group) => group !== name),
  )
  const positions = [...passed]
    .map((group) => currentMatching.indexOf(group))
    .filter((index) => index >= 0)

  const order = [...currentMatching]
  if (movedDown) {
    const anchors = positions.filter((index) => index > position)
    if (!anchors.length) return currentMatching
    const anchor = Math.max(...anchors)
    const anchorName = currentMatching[anchor]
    order.splice(position, 1)
    order.splice(order.indexOf(anchorName) + 1, 0, name)
  } else {
    const anchors = positions.filter((index) => index < position)
    if (!anchors.length) return currentMatching
    const anchor = Math.min(...anchors)
    const anchorName = currentMatching[anchor]
    order.splice(position, 1)
    order.splice(Math.max(0, order.indexOf(anchorName)), 0, name)
  }
  return order
}

function longestIncreasingSubsequence(values: number[]): number[] {
  const tails: number[] = []
  const tailIndex: number[] = []
  const previous = Array<number>(values.length).fill(-1)
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index]
    let low = 0
    let high = tails.length
    while (low < high) {
      const middle = (low + high) >> 1
      if (tails[middle] < value) low = middle + 1
      else high = middle
    }
    if (low > 0) previous[index] = tailIndex[low - 1]
    tails[low] = value
    tailIndex[low] = index
  }
  const result: number[] = []
  let cursor = tailIndex[tails.length - 1]
  while (cursor !== undefined && cursor >= 0) {
    result.unshift(cursor)
    cursor = previous[cursor]
  }
  return result
}

function isAnchoredFallback(rule: RoutingRule): boolean {
  return rule.type === 'GEOIP' || /^GEOIP,/i.test((rule.raw ?? '').trim())
}

/**
 * 按 matchingOrder 重排规则：把被调整的组整块搬到目标位置。
 * 没有 matchingOrder 或顺序没有实际变化时原样返回。
 */
export function reorderRulesByMatchingOrder(
  rules: RoutingRule[],
  order: string[] | undefined,
): RoutingRule[] {
  if (!order?.length || rules.length < 2) return rules
  const sourceOrder = matchingGroupNames(rules)
  const rank = new Map(sourceOrder.map((name, index) => [name, index]))
  const seen = new Set<string>()
  const desired = order.filter((name) => {
    if (!rank.has(name) || seen.has(name)) return false
    seen.add(name)
    return true
  })
  if (desired.length < 2) return rules

  const kept = new Set(
    longestIncreasingSubsequence(desired.map((name) => rank.get(name) ?? 0))
      .map((index) => desired[index]),
  )
  const moved = new Set(desired.filter((name) => !kept.has(name)))
  if (!moved.size) return rules

  const lifts = (rule: RoutingRule) => moved.has(rule.group) && !isAnchoredFallback(rule)
  const blocks = new Map<string, RoutingRule[]>()
  for (const rule of rules) {
    if (!lifts(rule)) continue
    const block = blocks.get(rule.group) ?? []
    block.push(rule)
    blocks.set(rule.group, block)
  }

  const pending = new Map<string, RoutingRule[]>()
  let trailing: RoutingRule[] = []
  desired.forEach((name, index) => {
    if (!moved.has(name)) return
    const block = blocks.get(name) ?? []
    const anchor = desired.slice(index + 1).find((candidate) => kept.has(candidate))
    if (anchor) {
      pending.set(anchor, [...(pending.get(anchor) ?? []), ...block])
    } else {
      trailing = [...trailing, ...block]
    }
  })

  const result: RoutingRule[] = []
  for (const rule of rules) {
    if (lifts(rule)) continue
    const anchored = pending.get(rule.group)
    if (anchored) {
      result.push(...anchored)
      pending.delete(rule.group)
    }
    result.push(rule)
  }
  if (!trailing.length) return result

  const lastKept = [...desired].reverse().find((name) => kept.has(name))
  let insertion = result.length
  for (let index = result.length - 1; index >= 0; index -= 1) {
    if (result[index].group === lastKept && !isAnchoredFallback(result[index])) {
      insertion = index + 1
      break
    }
  }
  result.splice(insertion, 0, ...trailing)
  return result
}
