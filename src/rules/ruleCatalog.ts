// 在线规则库目录：移植自 Tower iOS 的 RuleCatalog 索引（ACL4SSR + blackmatrix7）。
// 这里只保存列表路径、名称和来源地址；规则内容不随本项目分发，用户添加时
// 通过本机 /api/fetch 从上游读取。索引数据在 src/data/ruleCatalogIndex.ts。
import { ACL4SSR_LIST_PATHS, BLACKMATRIX7_LIST_PATHS } from '../data/ruleCatalogIndex'

export type RuleCatalogProvider = 'ACL4SSR' | 'blackmatrix7'

export interface OnlineRuleCatalogEntry {
  id: string
  title: string
  category: string
  provider: RuleCatalogProvider
  /** 加入方案后用于持续刷新的上游地址。 */
  sourceURL: string
  /** 上游路径，便于搜索和排查。 */
  path: string
  aliases: string[]
}

/** 与 Tower iOS RuleCatalog.swift 使用的 ACL4SSR 目录版本一致。 */
export const ACL4SSR_CATALOG_REVISION = '06ff293e02565adceef9aa92321efa2603f68f32'
const ACL4SSR_BASE = `https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/${ACL4SSR_CATALOG_REVISION}`
const BLACKMATRIX_BASE = 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master'

interface CuratedEntry {
  title?: string
  category?: string
  aliases?: string[]
}

/** 常用 blackmatrix7 列表的显示名、分类和中文别名，对齐 iOS 目录。 */
const BLACKMATRIX_CURATED: Record<string, CuratedEntry> = {
  OpenAI: { title: 'OpenAI', category: '媒体与服务', aliases: ['ChatGPT', 'GPT', '人工智能'] },
  Copilot: { title: 'Microsoft Copilot', category: '媒体与服务', aliases: ['Bing AI', '微软 AI'] },
  Gemini: { title: 'Google Gemini', category: '媒体与服务', aliases: ['Bard', '谷歌 AI'] },
  Netflix: { title: 'Netflix', category: '媒体与服务', aliases: ['奈飞', '网飞'] },
  YouTube: { title: 'YouTube', category: '媒体与服务', aliases: ['油管', 'YouTube Video'] },
  Disney: { title: 'Disney+', category: '媒体与服务', aliases: ['迪士尼', 'Disney Plus'] },
  Spotify: { title: 'Spotify', category: '媒体与服务', aliases: ['声田', '音乐'] },
  Telegram: { title: 'Telegram', category: '媒体与服务', aliases: ['电报', 'TG'] },
  Twitter: { title: 'X / Twitter', category: '媒体与服务', aliases: ['推特', 'X'] },
  Instagram: { title: 'Instagram', category: '媒体与服务', aliases: ['照片墙', 'IG'] },
  Facebook: { title: 'Facebook', category: '媒体与服务', aliases: ['脸书', 'Meta'] },
  GitHub: { title: 'GitHub', category: '厂商服务', aliases: ['代码托管', 'Git'] },
  Apple: { title: 'Apple', category: '厂商服务', aliases: ['苹果服务', 'iCloud', 'App Store'] },
  Google: { title: 'Google', category: '厂商服务', aliases: ['谷歌', 'Google Search'] },
  Microsoft: { title: 'Microsoft', category: '厂商服务', aliases: ['微软', 'Windows', 'Office'] },
  Steam: { title: 'Steam', category: '媒体与服务', aliases: ['游戏平台', '蒸汽平台'] },
  PlayStation: { title: 'PlayStation', category: '媒体与服务', aliases: ['PSN', '索尼'] },
  Nintendo: { title: 'Nintendo', category: '媒体与服务', aliases: ['任天堂', 'Switch'] },
  Advertising: { title: 'Advertising', category: '广告与净化', aliases: ['广告拦截', '去广告'] },
  AdvertisingLite: { title: 'Advertising Lite', category: '广告与净化', aliases: ['轻量广告拦截'] },
  ChinaMax: { title: 'China Max', category: '国内与直连', aliases: ['国内直连', '中国网站', 'China IP'] },
  Lan: { title: 'LAN', category: '国内与直连', aliases: ['局域网', '本地网络'] },
}

/** ACL4SSR 在线目录里不在内置快照中的常见列表。 */
const ACL_CURATED: Record<string, CuratedEntry> = {
  BanEasyList: { title: 'EasyList 广告拦截', category: '广告与净化', aliases: ['广告', 'EasyList'] },
  BanEasyListChina: { title: 'EasyList 国内广告', category: '广告与净化', aliases: ['国内广告'] },
  BanEasyPrivacy: { title: 'EasyPrivacy 隐私拦截', category: '广告与净化', aliases: ['隐私', '追踪器'] },
  ChinaIp: { title: '中国 IP', category: '国内与直连', aliases: ['国内 IP', 'China IP'] },
  ChinaIpV6: { title: '中国 IPv6', category: '国内与直连', aliases: ['国内 IPv6'] },
  ChinaMedia: { title: '国内媒体', category: '国内与直连', aliases: ['中国流媒体'] },
  ProxyMedia: { title: '国外媒体', category: '媒体与服务', aliases: ['国际流媒体', 'Global Media'] },
  ProxyLite: { title: '精简代理', category: '代理分流', aliases: ['常用代理', 'GFW Lite'] },
  ProxyGFWlist: { title: 'GFWList', category: '代理分流', aliases: ['国外流量', '代理列表'] },
  Download: { title: '下载服务', category: '国内与直连', aliases: ['BT', 'PT', '下载直连'] },
}

function inferCategory(text: string): string {
  const lower = text.toLowerCase()
  if (/\b(ad|ads|advert|banad|adblock|privacy)\b/.test(lower) || lower.includes('广告') || lower.includes('拦截')) {
    return '广告与净化'
  }
  if (/china|cn-|12306|alipay|taobao|wechat|tencent|baidu|jd\.?com|国内/.test(lower)) {
    return '国内与直连'
  }
  if (/apple|microsoft|google|github|cloudflare|amazon|aws|azure|icloud|onedrive/.test(lower)) {
    return '厂商服务'
  }
  if (/netflix|youtube|disney|spotify|telegram|twitter|instagram|facebook|steam|epic|nintendo|playstation|ai|openai|gemini|copilot/.test(lower)) {
    return '媒体与服务'
  }
  return '在线规则'
}

function titleFromPath(path: string): string {
  const base = path.split('/').filter(Boolean).at(-1) ?? path
  return base.replace(/\.list$/i, '')
}

function providerFolder(path: string): string {
  const parts = path.split('/').filter(Boolean)
  return parts.length >= 2 ? parts.at(-2) ?? titleFromPath(path) : titleFromPath(path)
}

function sourceURLFor(provider: RuleCatalogProvider, path: string): string {
  const base = provider === 'ACL4SSR' ? ACL4SSR_BASE : BLACKMATRIX_BASE
  return `${base}/${path.split('/').map((part) => encodeURIComponent(part)).join('/')}`
}

function buildProviderEntries(
  paths: readonly string[],
  provider: RuleCatalogProvider,
): OnlineRuleCatalogEntry[] {
  return paths
    .filter((path) => path.toLowerCase().endsWith('.list'))
    .map((path) => {
      const folder = providerFolder(path)
      const curated = provider === 'blackmatrix7'
        ? BLACKMATRIX_CURATED[folder]
        : ACL_CURATED[titleFromPath(path)]
      const title = curated?.title ?? (provider === 'ACL4SSR' ? titleFromPath(path) : folder)
      const category = curated?.category ?? inferCategory(`${folder} ${path}`)
      return {
        id: `${provider === 'ACL4SSR' ? 'acl4ssr' : 'blackmatrix7'}:${path}`,
        title,
        category,
        provider,
        sourceURL: sourceURLFor(provider, path),
        path,
        aliases: curated?.aliases ?? [],
      }
    })
}

export const ONLINE_RULE_CATALOG: OnlineRuleCatalogEntry[] = [
  ...buildProviderEntries(ACL4SSR_LIST_PATHS, 'ACL4SSR'),
  ...buildProviderEntries(BLACKMATRIX7_LIST_PATHS, 'blackmatrix7'),
].sort((a, b) => a.category.localeCompare(b.category, 'zh-CN') || a.title.localeCompare(b.title, 'zh-CN'))
