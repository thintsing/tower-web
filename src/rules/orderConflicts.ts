// Detect sites that change policy group after a drag. Clients match rules
// top-to-bottom, so moving a group past another can silently hand a domain
// from the first group to the second.
import type { RoutingRule, RuleScheme } from '../models/types'

export interface RuleOrderConflict {
  from: string
  to: string
  domains: string[]
}

type PatternKind = 'exact' | 'suffix' | 'keyword'

interface DomainPattern {
  kind: PatternKind
  value: string
}

function normalizeValue(value: string): string {
  return value.trim().toLowerCase().replace(/^\*\./, '').replace(/^\./, '')
}

function patternFor(rule: RoutingRule): DomainPattern | undefined {
  const value = normalizeValue(rule.value ?? '')
  if (!value) return undefined
  switch (rule.type.toUpperCase()) {
    case 'DOMAIN': return { kind: 'exact', value }
    case 'DOMAIN-SUFFIX': return { kind: 'suffix', value }
    case 'DOMAIN-KEYWORD': return { kind: 'keyword', value }
    default: return undefined
  }
}

function groupPatterns(scheme: RuleScheme): Map<string, DomainPattern[]> {
  const byGroup = new Map<string, DomainPattern[]>()
  const seen = new Map<string, Set<string>>()
  const add = (rule: RoutingRule, fallbackGroup?: string) => {
    const group = rule.group || fallbackGroup
    if (!group) return
    const pattern = patternFor(rule)
    if (!pattern) return
    const key = `${pattern.kind}:${pattern.value}`
    const groupSeen = seen.get(group) ?? new Set<string>()
    if (groupSeen.has(key)) return
    groupSeen.add(key)
    seen.set(group, groupSeen)
    byGroup.set(group, [...(byGroup.get(group) ?? []), pattern])
  }
  for (const rule of scheme.customRules ?? []) add(rule, rule.group)
  for (const rule of scheme.rules) add(rule, rule.group)
  for (const set of scheme.ruleSets ?? []) {
    for (const rule of set.rules) add(rule, set.group)
  }
  return byGroup
}

function matches(patterns: DomainPattern[], host: string): boolean {
  return patterns.some((pattern) => {
    if (pattern.kind === 'exact') return host === pattern.value
    if (pattern.kind === 'keyword') return host.includes(pattern.value)
    return host === pattern.value || host.endsWith(`.${pattern.value}`)
  })
}

function sharedDomains(from: DomainPattern[], to: DomainPattern[]): string[] {
  const domains: string[] = []
  for (const pattern of from) {
    if (!matches(to, pattern.value)) continue
    if (!domains.includes(pattern.value)) domains.push(pattern.value)
  }
  return domains.sort((a, b) => a.length - b.length).slice(0, 6)
}

/** Domains handed from one group to another by an order change. */
export function findRuleOrderConflicts(
  scheme: RuleScheme,
  oldOrder: string[],
  newOrder: string[],
): RuleOrderConflict[] {
  const newIndex = new Map(newOrder.map((name, index) => [name, index]))
  const flipped: Array<{ from: string; to: string }> = []
  for (let index = 0; index < oldOrder.length; index += 1) {
    const earlier = oldOrder[index]
    for (let laterIndex = index + 1; laterIndex < oldOrder.length; laterIndex += 1) {
      const later = oldOrder[laterIndex]
      const earlierIndex = newIndex.get(earlier)
      const laterPosition = newIndex.get(later)
      if (earlierIndex === undefined || laterPosition === undefined) continue
      // The group that used to win is now later, so the other group wins.
      if (laterPosition < earlierIndex) flipped.push({ from: earlier, to: later })
    }
  }
  if (!flipped.length) return []

  const patterns = groupPatterns(scheme)
  return flipped.flatMap(({ from, to }) => {
    const domains = sharedDomains(patterns.get(from) ?? [], patterns.get(to) ?? [])
    return domains.length ? [{ from, to, domains }] : []
  })
}
