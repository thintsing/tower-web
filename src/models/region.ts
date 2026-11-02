// Region resolver ported from Tower iOS (Tower/Services/NodeRegionResolver.swift).
// Matching order: flag emoji -> curated phrases/tokens -> cities -> country
// names -> capitalised ISO codes. Domain suffixes never locate a server.
import data from '../data/regions.json'
import type { ProxyNode } from './types'

export interface NodeRegion {
  code: string
  name: string
  flag: string
  lat: number
  lon: number
}

interface CountryEntry {
  cn: string
  en: string
  lat: number
  lon: number
  names: string[]
  codes: string[]
}

interface Definition {
  code: string
  name: string
  flag: string
  lat: number
  lon: number
  phrases: string[]
  tokens: string[]
  domainSuffixes: string[]
}

const countries = data.countries as Record<string, CountryEntry>
const definitions = data.definitions as Definition[]
const cities = data.cities as Record<string, string>
// Filter stray comment text the extractor may have captured ("129.29 GB").
const reservedTokens = new Set(
  (data.reservedTokens as string[]).filter((t) => /^[A-Z0-9]+$/.test(t)),
)
const caseSensitiveTokens = new Set(data.caseSensitiveTokens as string[])

const curatedRegions = new Map<string, NodeRegion>(
  definitions.map((d) => [
    d.code,
    { code: d.code, name: d.name, flag: d.flag, lat: d.lat, lon: d.lon },
  ]),
)

export function flagEmoji(countryCode: string): string {
  return [...countryCode.toUpperCase()]
    .map((c) => String.fromCodePoint(127397 + c.charCodeAt(0)))
    .join('')
}

export function regionByCode(countryCode: string): NodeRegion | undefined {
  let code = countryCode.trim().toUpperCase()
  if (code === 'UK') code = 'GB'
  const curated = curatedRegions.get(code)
  if (curated) return curated
  const entry = countries[code]
  if (!entry) return undefined
  return { code, name: entry.cn, flag: flagEmoji(code), lat: entry.lat, lon: entry.lon }
}

/** Regional-indicator pair the airport prefixed the name with, if any. */
function flaggedCountryCode(name: string): string | undefined {
  const indicators = [...name].filter((c) => {
    const v = c.codePointAt(0)!
    return v >= 0x1f1e6 && v <= 0x1f1ff
  })
  if (indicators.length < 2) return undefined
  return indicators
    .slice(0, 2)
    .map((c) => String.fromCharCode(c.codePointAt(0)! - 0x1f1e6 + 65))
    .join('')
}

// ---------- Index structures ----------

interface Match {
  code: string
  length: number
  isCurated: boolean
}

type PhraseForm = 'words' | 'unspaced' | 'capitalisedCode'

const wordIndex = new Map<string, Match[]>()
const multiWordIndex = new Map<string, { words: string[]; match: Match }[]>()
const unspacedIndex = new Map<string, { characters: string[]; match: Match }[]>()
const codeIndex = new Map<string, Match>()

function normalizedTokens(value: string): string[] {
  return value
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .split(/[^a-z0-9\u2f00-\u9fff\uf900-\ufaff]+/i)
    .filter(Boolean)
}

function formOf(text: string): PhraseForm {
  return [...text].some((c) => c.codePointAt(0)! > 0x2fff) ? 'unspaced' : 'words'
}

function add(text: string, code: string, form: PhraseForm, curated: boolean) {
  if (form === 'capitalisedCode') {
    const key = text.toUpperCase()
    if (!key) return
    const match: Match = { code, length: key.length, isCurated: curated }
    const existing = codeIndex.get(key)
    if (existing?.isCurated && !curated) return
    codeIndex.set(key, match)
  } else if (form === 'unspaced') {
    const characters = [...text.toLowerCase()]
    const first = characters[0]
    if (!first) return
    const match: Match = { code, length: characters.length, isCurated: curated }
    push(unspacedIndex, first, { characters, match })
  } else {
    const tokens = normalizedTokens(text)
    const first = tokens[0]
    if (!first) return
    const match: Match = { code, length: text.length, isCurated: curated }
    if (tokens.length === 1) push(wordIndex, first, match)
    else push(multiWordIndex, first, { words: tokens, match })
  }
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V) {
  const arr = map.get(key)
  if (arr) arr.push(value)
  else map.set(key, [value])
}

function isRegionalFlagString(value: string): boolean {
  return (
    value.length > 0 &&
    [...value].every((c) => {
      const v = c.codePointAt(0)!
      return v >= 0x1f1e6 && v <= 0x1f1ff
    })
  )
}

let indexesBuilt = false
function buildIndexes() {
  if (indexesBuilt) return
  indexesBuilt = true

  for (const def of definitions) {
    for (const phrase of def.phrases) {
      if (!isRegionalFlagString(phrase)) add(phrase, def.code, formOf(phrase), true)
    }
    for (const token of def.tokens) {
      // Airport codes like HKG read fine in any case; two-letter ordinary
      // words ("us", "in") need the capitals.
      const form = caseSensitiveTokens.has(token) ? 'capitalisedCode' : 'words'
      add(token, def.code, form, true)
    }
  }

  for (const [code, entry] of Object.entries(countries)) {
    for (const name of entry.names) add(name, code, formOf(name), false)
    for (const isoCode of entry.codes) {
      if (!reservedTokens.has(isoCode)) add(isoCode, code, 'capitalisedCode', false)
    }
    if (!reservedTokens.has(code)) add(code, code, 'capitalisedCode', false)
  }

  for (const [city, code] of Object.entries(cities)) add(city, code, formOf(city), false)

  // ISO country names in en / zh-Hans / zh-Hant via Intl.DisplayNames.
  const displayers = [new Intl.DisplayNames(['en'], { type: 'region' }),
    new Intl.DisplayNames(['zh-Hans'], { type: 'region' }),
    new Intl.DisplayNames(['zh-Hant'], { type: 'region' })]
  for (const code of Object.keys(countries)) {
    for (const dn of displayers) {
      try {
        const name = dn.of(code)
        if (name) {
          const normalized = normalizedTokens(name).join(' ')
          if (normalized) add(normalized, code, formOf(normalized), false)
        }
      } catch { /* unknown region */ }
    }
  }
}

function matchedCode(text: string, allowCodes = true): string | undefined {
  buildIndexes()
  let best: Match | undefined

  const consider = (candidate: Match) => {
    if (!best) {
      best = candidate
      return
    }
    if (candidate.length > best.length) {
      best = candidate
      return
    }
    if (candidate.length === best.length && candidate.isCurated && !best.isCurated) {
      best = candidate
    }
  }

  const tokens = normalizedTokens(text)
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]
    for (const match of wordIndex.get(token) ?? []) consider(match)
    for (const candidate of multiWordIndex.get(token) ?? []) {
      const words = candidate.words
      if (tokens.slice(i, i + words.length).join('') === words.join('') &&
          tokens.slice(i, i + words.length).every((w, j) => w === words[j])) {
        consider(candidate.match)
      }
    }
  }

  if (allowCodes) {
    for (const token of text.split(/[^A-Za-z0-9]+/)) {
      if (token && token === token.toUpperCase()) {
        const match = codeIndex.get(token)
        if (match) consider(match)
      }
    }
  }

  if ([...text].some((c) => c.codePointAt(0)! > 0x2fff)) {
    const characters = [...text.toLowerCase()]
    for (let i = 0; i < characters.length; i++) {
      for (const candidate of unspacedIndex.get(characters[i]) ?? []) {
        const chars = candidate.characters
        let ok = true
        for (let j = 0; j < chars.length; j++) {
          if (characters[i + j] !== chars[j]) {
            ok = false
            break
          }
        }
        if (ok) consider(candidate.match)
      }
    }
  }

  return best?.code
}

/** Where a node is, decided from what it is called. */
export function regionForName(name: string): NodeRegion | undefined {
  const flagged = flaggedCountryCode(name)
  if (flagged) {
    const region = regionByCode(flagged)
    if (region) return region
  }
  const code = matchedCode(name)
  return code ? regionByCode(code) : undefined
}

/** Manual override > name > offline IP lookup. */
export function regionForNode(node: ProxyNode): NodeRegion | undefined {
  if (node.countryOverride) {
    const region = regionByCode(node.countryOverride)
    if (region) return region
  }
  const named = regionForName(node.name)
  if (named) return named
  return node.detectedCountry ? regionByCode(node.detectedCountry) : undefined
}

/** 地区多选筛选；空数组表示全部，未识别地区的节点只在“全部”时保留。 */
export function filterNodesByRegionCodes(nodes: ProxyNode[], codes: string[]): ProxyNode[] {
  const selected = new Set(codes.map((code) => code.trim().toUpperCase()).filter(Boolean))
  if (!selected.size) return nodes
  return nodes.filter((node) => {
    const region = regionForNode(node)
    return !!region && selected.has(region.code)
  })
}

/** Every country available for manual overrides, including non-curated ones. */
export function allRegions(): NodeRegion[] {
  const merged = new Map<string, NodeRegion>(curatedRegions)
  for (const code of Object.keys(countries)) {
    const region = regionByCode(code)
    if (region && !merged.has(region.code)) merged.set(region.code, region)
  }
  return [...merged.values()].sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'))
}
