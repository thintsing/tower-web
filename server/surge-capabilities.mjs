// Surge 测试版构建号门槛；与 src/generator/surgeCapabilities.ts 保持一致。
// 独立成 .mjs 是因为服务端入口不能在运行时导入 TypeScript。
export const SURGE_TIER_BUILDS = {
  ios: { vless: 4024, vlessExtensions: 4026, httpUpgrade: 4027 },
  mac: { vless: 12820, vlessExtensions: 12840, httpUpgrade: 12860 },
}

/** `Surge iOS/4027` / `Surge Mac/12860` → 平台与档位。 */
export function surgeTierFromUserAgent(userAgent) {
  const match = String(userAgent ?? '').match(/Surge (iOS|Mac)\/(\d+)/i)
  if (!match) return null
  const build = Number(match[2])
  if (!Number.isFinite(build)) return null
  const platform = match[1].toLowerCase() === 'ios' ? 'surge' : 'surge-mac'
  const thresholds = platform === 'surge' ? SURGE_TIER_BUILDS.ios : SURGE_TIER_BUILDS.mac
  if (build >= thresholds.httpUpgrade) return { platform, tier: 3 }
  if (build >= thresholds.vlessExtensions) return { platform, tier: 2 }
  if (build >= thresholds.vless) return { platform, tier: 1 }
  return null
}

/** 从已发布的档位表里选出请求方 UA 对应的一份；没有则返回 undefined。 */
export function surgeVariantFor(surgeTiers, userAgent) {
  const beta = surgeTierFromUserAgent(userAgent)
  if (!beta) return undefined
  return surgeTiers?.[beta.platform]?.[String(beta.tier)]
}

/** Anywhere 的 AJSON 请求头可以带多个逗号分隔的格式。 */
export function acceptsAnywhereAjson(header) {
  return String(header ?? '')
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .includes('ajson/1')
}
