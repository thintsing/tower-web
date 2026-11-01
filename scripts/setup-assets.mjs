// Converts Tower iOS region data (CountryTable.swift + NodeRegionResolver.swift)
// into src/data/regions.json, and copies bundled ACL4SSR rule lists into
// public/rulesets/. Run once after cloning the iOS repo: `node scripts/setup-assets.mjs <tower-ios-dir>`
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const iosDir = process.argv[2] || join(root, '..', 'tower')

// ---------- 1. CountryTable.swift ----------
const countrySrc = readFileSync(join(iosDir, 'Tower/Services/CountryTable.swift'), 'utf8')
const countries = {}
const countryRe = /"([A-Z]{2})":\s*\.init\(chineseName:\s*"((?:[^"\\]|\\.)*)",\s*englishName:\s*"((?:[^"\\]|\\.)*)",\s*latitude:\s*(-?[\d.]+),\s*longitude:\s*(-?[\d.]+),\s*names:\s*\[([^\]]*)\],\s*codes:\s*\[([^\]]*)\]\)/g
let m
const strArr = (s) => [...s.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1])
while ((m = countryRe.exec(countrySrc))) {
  countries[m[1]] = {
    cn: m[2],
    en: m[3],
    lat: parseFloat(m[4]),
    lon: parseFloat(m[5]),
    names: strArray(m[6]),
    codes: strArray(m[7]),
  }
}
function strArray(s) {
  return [...s.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1])
}

// ---------- 2. NodeRegionResolver.swift: curated definitions + cities ----------
const resolverSrc = readFileSync(join(iosDir, 'Tower/Services/NodeRegionResolver.swift'), 'utf8')

// definitions: .init(\n region: .init(code: "HK", name: "香港", flag: "🇭🇰", latitude: N, longitude: N),\n phrases: [...], tokens: [...], domainSuffixes: [...])
const definitions = []
const defRe = /\.init\(\s*region:\s*\.init\(code:\s*"([A-Z]{2})",\s*name:\s*"((?:[^"\\]|\\.)*)",\s*flag:\s*"((?:[^"\\]|\\.)*)",\s*latitude:\s*(-?[\d.]+),\s*longitude:\s*(-?[\d.]+)\),\s*phrases:\s*\[([^\]]*)\],\s*tokens:\s*\[([^\]]*)\],\s*domainSuffixes:\s*\[([^\]]*)\]\s*\)/g
while ((m = defRe.exec(resolverSrc))) {
  definitions.push({
    code: m[1],
    name: m[2],
    flag: m[3],
    lat: parseFloat(m[4]),
    lon: parseFloat(m[5]),
    phrases: strArray(m[6]),
    tokens: strArray(m[7]),
    domainSuffixes: strArray(m[8]),
  })
}

// cities dictionary: private static let cities: [String: String] = [ ... ]
const cities = {}
const citiesBlock = resolverSrc.match(/private static let cities: \[String: String\] = \[([\s\S]*?)\n\s*\]/)
if (citiesBlock) {
  const cityRe = /"((?:[^"\\]|\\.)*)":\s*"([A-Z]{2})"/g
  while ((m = cityRe.exec(citiesBlock[1]))) cities[m[1]] = m[2]
}

const reserved = []
const reservedBlock = resolverSrc.match(/private static let reservedTokens: Set<String> = \[([\s\S]*?)\]/)
if (reservedBlock) reserved.push(...strArray(reservedBlock[1]))
const caseSensitive = []
const csBlock = resolverSrc.match(/private static let caseSensitiveTokens: Set<String> = \[([\s\S]*?)\]/)
if (csBlock) caseSensitive.push(...strArray(csBlock[1]))

const out = { countries, definitions, cities, reservedTokens: reserved, caseSensitiveTokens: caseSensitive }
mkdirSync(join(root, 'src/data'), { recursive: true })
writeFileSync(join(root, 'src/data/regions.json'), JSON.stringify(out))
console.log(`regions.json: ${Object.keys(countries).length} countries, ${definitions.length} definitions, ${Object.keys(cities).length} cities`)

// ---------- 3. Copy ACL4SSR lists ----------
const srcDir = join(iosDir, 'Tower/Resources/ACL4SSR')
const destDir = join(root, 'public/rulesets')
mkdirSync(destDir, { recursive: true })
const index = {}
for (const f of readdirSync(srcDir)) {
  if (!f.endsWith('.list') && !f.endsWith('.ini')) continue
  copyFileSync(join(srcDir, f), join(destDir, f))
  // Reconstruct the upstream ACL4SSR repo path for INI URL mapping.
  const bare = f.replace(/^ACL4SSR_/, '')
  const upstreamPath = bare.startsWith('Ruleset_')
    ? `Clash/Ruleset/${bare.replace('Ruleset_', '')}`
    : `Clash/${bare}`
  index[upstreamPath] = f
}
writeFileSync(join(destDir, 'index.json'), JSON.stringify(index, null, 1))
console.log(`rulesets: ${Object.keys(index).length} files copied`)
