// Policy group icons for clients that render them, ported from Tower iOS
// PolicyGroupIcons.swift + PolicyGroupEmoji.swift. Images are linked from the
// pinned Fluent / flag-icons / Tower icon commits; nothing is rehosted here.
import type { ClientTarget, PolicyGroup, RoutingRule, RuleScheme } from '../models/types'
import { flagEmoji, regionForName } from '../models/region'
import { renameRuleOrderKeys } from '../rules/ruleOrder'

const FLUENT_BASE = 'https://cdn.jsdelivr.net/gh/microsoft/fluentui-emoji@1ffb34c752ecf5d402f04cfb4b392c77f57c54bc/'
const FLAG_BASE = 'https://cdn.jsdelivr.net/gh/pengchujin/tower@425b0a7acce67b19f442d01a0722c2ae4cf8a477/Rulesets/PolicyGroupIcons/ac7e0eb3259eb62aa6100c435607e2fe03896a97/'
const CIRCLE_BASE = 'https://raw.githubusercontent.com/pengchujin/tower/b1cfedcb29b4a6498a7331ebf5021fc0d84d57ad/Rulesets/PolicyGroupIcons/FluentCircle/'

/** Clients that accept a group icon field, and those known to draw it. */
const WRITES_ICONS = new Set<ClientTarget>([
  'surge', 'surge-mac', 'clash', 'clash-apple', 'clash-verge', 'clashmac',
  'flclash', 'mihomo-party', 'clash-mi', 'quanx', 'loon', 'egern',
])
const DRAWS_ICONS = new Set<ClientTarget>([
  'surge', 'surge-mac', 'clash', 'clash-verge', 'quanx', 'loon', 'egern',
])
const CIRCLE_ICONS = new Set<ClientTarget>(['quanx'])
/** Surge 会把组名开头的国旗画在图标位，再写一张国旗图标就重复了。 */
const REGION_FROM_NAME = new Set<ClientTarget>(['surge', 'surge-mac'])

interface EmojiEntry {
  emoji: string
  words: string[]
  phrases: string[]
  exact?: string[]
}

// Services and categories, specific before broad; checked before regions.
const TABLE: EmojiEntry[] = [
  { emoji: '🍃', words: [], phrases: ['应用净化'] },
  { emoji: '🛑', words: ['reject', 'adblock', 'ad block', 'ads', 'advertising', 'advertisement', 'blocklist'], phrases: ['广告拦截', '全球拦截', '拦截', '广告', '去广告'], exact: ['block'] },
  { emoji: '🐟', words: ['final', 'match', 'fallback rule'], phrases: ['漏网之鱼', '兜底', '其他流量', '其它流量', '剩余流量'], exact: ['others'] },
  { emoji: '🛡️', words: ['privacy', 'tracking', 'tracker', 'antitracking'], phrases: ['隐私', '追踪', '跟踪', '泄漏', '泄露'] },
  { emoji: '🌏', words: ['china media', 'asia media'], phrases: ['国内媒体', '国内视频', '国内影视', '港台媒体', '日韩媒体', '港澳台媒体', '亚洲媒体'] },
  { emoji: '🌍', words: ['global media', 'streaming', 'foreign media', 'international media'], phrases: ['国外媒体', '国际媒体', '海外媒体', '流媒体'] },
  { emoji: '🏠', words: ['lan', 'local area network', 'private network', 'intranet'], phrases: ['局域网', '内网', '私有网络'] },
  { emoji: '🌐', words: ['dns', 'httpdns', 'doh'], phrases: ['域名解析'] },
  { emoji: '📶', words: ['speedtest', 'speed test', 'network test'], phrases: ['测速工具', '测速网站', '网络测试'] },
  { emoji: '🔀', words: ['non standard port'], phrases: ['非标端口', '非标准端口'] },
  { emoji: '📢', words: ['fcm', 'google fcm'], phrases: ['谷歌fcm', '谷歌 fcm', '谷歌推送'] },
  { emoji: '📹', words: ['youtube', 'youtube music'], phrases: ['油管'] },
  { emoji: '🎥', words: ['netflix'], phrases: ['奈飞', '网飞'] },
  { emoji: '🧸', words: ['disney', 'disney plus', 'disneyplus'], phrases: ['迪士尼'] },
  { emoji: '🎬', words: ['hbo', 'hbo max', 'prime video', 'amazon prime', 'hulu', 'apple tv', 'appletv', 'paramount', 'peacock'], phrases: ['亚马逊视频'], exact: ['max'] },
  { emoji: '🍿', words: ['emby', 'jellyfin', 'plex'], phrases: [] },
  { emoji: '⚽', words: ['dazn', 'espn'], phrases: [] },
  { emoji: '📺', words: ['bilibili', 'bahamut', 'abema', 'abematv', 'iqiyi', 'youku', 'tvb', 'anime', 'twitch', 'niconico', 'viu', 'mytvsuper'], phrases: ['哔哩', '巴哈姆特', '爱奇艺', '优酷', '动漫', '番剧', '动画', '直播'] },
  { emoji: '🎵', words: ['tiktok', 'douyin', 'bytedance'], phrases: ['抖音', '字节跳动', '抖快'] },
  { emoji: '🎧', words: ['spotify', 'apple music', 'deezer', 'tidal', 'soundcloud', 'qobuz'], phrases: [] },
  { emoji: '🎶', words: ['netease music', 'music', 'kkbox', 'joox'], phrases: ['网易音乐', '网易云音乐', '音乐'] },
  { emoji: '📲', words: ['telegram'], phrases: ['电报'] },
  { emoji: '🤖', words: ['ai', 'aigc', 'openai', 'chatgpt', 'claude', 'anthropic', 'copilot', 'perplexity', 'grok', 'deepseek', 'midjourney'], phrases: ['ai平台', 'ai 平台', 'ai服务', '人工智能'] },
  { emoji: '🔷', words: ['gemini', 'bard'], phrases: [] },
  { emoji: '🐦', words: ['twitter'], phrases: ['推特'], exact: ['x', 'twitter x'] },
  { emoji: '♾️', words: ['facebook', 'instagram', 'meta', 'whatsapp', 'threads'], phrases: ['脸书'] },
  { emoji: '📣', words: ['weibo'], phrases: ['微博'] },
  { emoji: '🎙️', words: ['discord'], phrases: [] },
  { emoji: '👽', words: ['reddit'], phrases: [] },
  { emoji: '📕', words: ['xiaohongshu', 'rednote'], phrases: ['小红书'] },
  { emoji: '💬', words: ['wechat', 'line', 'signal', 'kakaotalk', 'messenger', 'im'], phrases: ['微信', '即时通讯', '通讯', '聊天'] },
  { emoji: '📞', words: ['talkatone', 'skype', 'zoom', 'voip'], phrases: ['通话', '电话'] },
  { emoji: '🐙', words: ['github', 'gitlab'], phrases: [] },
  { emoji: '🐳', words: ['docker'], phrases: [] },
  { emoji: '📝', words: ['notion', 'evernote', 'obsidian'], phrases: [] },
  { emoji: '📱', words: ['xiaomi', 'samsung'], phrases: ['小米', '三星'] },
  { emoji: '🔞', words: ['pornhub', 'ehentai', 'nsfw'], phrases: [] },
  { emoji: '🎨', words: ['pixiv', 'adobe', 'figma', 'canva'], phrases: [] },
  { emoji: '💳', words: ['paypal', 'stripe', 'visa', 'wise'], phrases: ['支付'] },
  { emoji: '🪙', words: ['binance', 'okx', 'crypto', 'coinbase', 'bybit'], phrases: ['加密货币', '货币', '币安'] },
  { emoji: '🛒', words: ['amazon', 'ebay', 'shopee', 'shopping', 'shop'], phrases: ['购物', '电商', '亚马逊', '淘宝', '京东', '阿里巴巴'] },
  { emoji: '☁️', words: ['google cloud', 'azure'], phrases: [] },
  { emoji: 'Ⓜ️', words: ['microsoft', 'bing', 'onedrive', 'office', 'outlook', 'office365', 'windows', 'teams'], phrases: ['微软'] },
  { emoji: '🍎', words: ['apple', 'icloud', 'app store', 'appstore', 'testflight', 'itunes'], phrases: ['苹果'] },
  { emoji: '🔍', words: ['google', 'gmail'], phrases: ['谷歌'] },
  { emoji: '☁️', words: ['cloudflare', 'aws', 'azure', 'google cloud', 'oracle cloud', 'pikpak', 'dropbox', 'mega'], phrases: ['网盘', '云盘'] },
  { emoji: '🎮', words: ['game', 'games', 'gaming', 'steam', 'epic', 'playstation', 'xbox', 'nintendo', 'blizzard', 'videogame'], phrases: ['游戏'] },
  { emoji: '🎓', words: ['scholar', 'academic', 'education'], phrases: ['学术', '教育', '论文'] },
  { emoji: '📰', words: ['news'], phrases: ['新闻', '资讯'] },
  { emoji: '📧', words: ['mail', 'email'], phrases: ['邮件', '邮箱'] },
  { emoji: '🏦', words: ['bank', 'banking', 'finance'], phrases: ['银行', '金融'] },
  { emoji: '⚽', words: ['sport', 'sports'], phrases: ['体育'] },
  { emoji: '👥', words: ['social'], phrases: ['社交'] },
  { emoji: '📥', words: ['download', 'downloads', 'p2p', 'bt', 'torrent'], phrases: ['下载', 'pt站'] },
  { emoji: '🎬', words: ['video', 'videos', 'movie', 'movies', 'film', 'films'], phrases: ['影视', '视频', '电影', '剧集', '追剧'] },
  { emoji: '🎯', words: ['direct', 'global direct', 'domestic'], phrases: ['全球直连', '直连', '直接连接', '国内', '大陆'], exact: ['mainland'] },
]

// What the group does, checked after regions so "香港自动" keeps the flag.
const ROLES: EmojiEntry[] = [
  { emoji: '🔁', words: ['fallback', 'failover', 'backup'], phrases: ['故障转移', '故障切换', '故转', '备用', '容灾'] },
  { emoji: '⚖️', words: ['load balance', 'loadbalance', 'balance', 'round robin'], phrases: ['负载均衡', '均衡', '轮询'] },
  { emoji: '♻️', words: ['auto', 'auto select', 'url test', 'automatic', 'best', 'lowest latency'], phrases: ['自动', '优选', '延迟最低', '最低延迟', '低延迟'] },
  { emoji: '📶', words: [], phrases: ['测速'] },
  { emoji: '🎛️', words: ['manual', 'manual select', 'manual switch'], phrases: ['手动', '手选', '自选', '策略选择', '选择地区'], exact: ['select', 'selector'] },
  { emoji: '🏡', words: ['residential', 'home broadband'], phrases: ['家宽', '家庭宽带', '原生'] },
  { emoji: '💰', words: ['cheap', 'budget'], phrases: ['便宜', '低价', '低倍率', '省流'] },
  { emoji: '⭐', words: ['premium', 'vip', 'iplc', 'iepl'], phrases: ['高级', '优质', '精品', '高速', '专线'] },
  { emoji: '🛠️', words: ['self hosted', 'selfhosted'], phrases: ['自建'] },
  { emoji: '🌍', words: ['foreign', 'overseas', 'international', 'outside'], phrases: ['国外', '国际', '海外', '境外'] },
  { emoji: '🗺️', words: ['other', 'others', 'other regions'], phrases: ['其他', '其它'] },
  { emoji: '🌐', words: ['all', 'proxies'], phrases: ['全部', '所有'] },
  { emoji: '🚀', words: ['proxy', 'proxy select', 'node select', 'node selection', 'nodes', 'node', 'default'], phrases: ['节点选择', '代理', '节点', '加速', '默认'] },
  { emoji: '🌐', words: ['global'], phrases: ['全球'] },
]

// Rule list names that are neither services nor roles.
const RULE_LISTS: EmojiEntry[] = [
  { emoji: '🎯', words: ['china domain', 'china ip', 'china company', 'china media', 'local area network'], phrases: [], exact: ['china', 'cn', 'chinadomain', 'chinaip', 'chinamax', 'direct', 'gfw direct'] },
  { emoji: '🚀', words: ['gfw', 'gfwlist', 'proxy gfwlist', 'proxy lite', 'proxy media', 'global'], phrases: [], exact: ['proxy', 'proxylite'] },
  { emoji: '🛑', words: ['ban ad', 'ban program ad', 'ban easylist', 'reject'], phrases: [] },
]

const STREAMING = new Set(['🎥', '📹', '🧸', '🎬', '📺', '🍿', '🎵'])

// 187 面圆形国旗；不在表里的旗帜不写图标，避免 404。
const FLAG_CODES = new Set(('AD AE AF AL AM AO AQ AR AT AU AZ BA BD BE BF BG BH BI BJ BN BO BR BS BT BW BY BZ '
  + 'CA CD CF CG CH CI CL CM CN CO CR CU CY CZ DE DJ DK DO DZ EC EE EG EH ER ES ET FI FJ FK FR GA GB GE GH GI GL GM GN GQ GR '
  + 'GT GW GY HK HN HR HT HU ID IE IL IN IQ IR IS IT JM JO JP KE KG KH KP KR KW KZ LA LB LI LK LR LS LT LU LV LY MA MC MD ME MG MK ML MM MN MO MR MT MU MW MX MY '
  + 'MZ NA NC NE NG NI NL NO NP NZ OM PA PE PG PH PK PL PR PS PT PY QA RO RS RU RW SA SB SC SD SE SG SI SK SL SM SN SO SR SS SV SY SZ TD TF TG TH TJ TL TM TN TR TT TW TZ '
  + 'UA UG US UY UZ VE VN VU XK YE ZA ZM ZW').split(' '))

const FLUENT_PATHS: Record<string, string> = {
  '⚽': 'assets/Soccer ball/3D/soccer_ball_3d.png',
  '☁': 'assets/Cloud/3D/cloud_3d.png',
  '♻': 'assets/Recycling symbol/3D/recycling_symbol_3d.png',
  '⚡': 'assets/High voltage/3D/high_voltage_3d.png',
  '♾': 'assets/Infinity/3D/infinity_3d.png',
  '⚖': 'assets/Balance scale/3D/balance_scale_3d.png',
  'Ⓜ': 'assets/Circled m/3D/circled_m_3d.png',
  '⭐': 'assets/Star/3D/star_3d.png',
  '🌍': 'assets/Globe showing europe-africa/3D/globe_showing_europe-africa_3d.png',
  '🌏': 'assets/Globe showing asia-australia/3D/globe_showing_asia-australia_3d.png',
  '🌐': 'assets/Globe with meridians/3D/globe_with_meridians_3d.png',
  '🍃': 'assets/Leaf fluttering in wind/3D/leaf_fluttering_in_wind_3d.png',
  '🍎': 'assets/Red apple/3D/red_apple_3d.png',
  '🍿': 'assets/Popcorn/3D/popcorn_3d.png',
  '🎓': 'assets/Graduation cap/3D/graduation_cap_3d.png',
  '🎙': 'assets/Studio microphone/3D/studio_microphone_3d.png',
  '🎛': 'assets/Control knobs/3D/control_knobs_3d.png',
  '🎥': 'assets/Movie camera/3D/movie_camera_3d.png',
  '🎧': 'assets/Headphone/3D/headphone_3d.png',
  '🎨': 'assets/Artist palette/3D/artist_palette_3d.png',
  '🎬': 'assets/Clapper board/3D/clapper_board_3d.png',
  '🎮': 'assets/Video game/3D/video_game_3d.png',
  '🎯': 'assets/Bullseye/3D/bullseye_3d.png',
  '🎵': 'assets/Musical note/3D/musical_note_3d.png',
  '🎶': 'assets/Musical notes/3D/musical_notes_3d.png',
  '🏠': 'assets/House/3D/house_3d.png',
  '🏡': 'assets/House with garden/3D/house_with_garden_3d.png',
  '🏦': 'assets/Bank/3D/bank_3d.png',
  '🐙': 'assets/Octopus/3D/octopus_3d.png',
  '🐟': 'assets/Fish/3D/fish_3d.png',
  '🐦': 'assets/Bird/3D/bird_3d.png',
  '🐳': 'assets/Spouting whale/3D/spouting_whale_3d.png',
  '👥': 'assets/Busts in silhouette/3D/busts_in_silhouette_3d.png',
  '👽': 'assets/Alien/3D/alien_3d.png',
  '💬': 'assets/Speech balloon/3D/speech_balloon_3d.png',
  '💰': 'assets/Money bag/3D/money_bag_3d.png',
  '💳': 'assets/Credit card/3D/credit_card_3d.png',
  '📕': 'assets/Closed book/3D/closed_book_3d.png',
  '📝': 'assets/Memo/3D/memo_3d.png',
  '📞': 'assets/Telephone receiver/3D/telephone_receiver_3d.png',
  '📢': 'assets/Loudspeaker/3D/loudspeaker_3d.png',
  '📣': 'assets/Megaphone/3D/megaphone_3d.png',
  '📥': 'assets/Inbox tray/3D/inbox_tray_3d.png',
  '📧': 'assets/E-mail/3D/e-mail_3d.png',
  '📰': 'assets/Newspaper/3D/newspaper_3d.png',
  '📱': 'assets/Mobile phone/3D/mobile_phone_3d.png',
  '📲': 'assets/Mobile phone with arrow/3D/mobile_phone_with_arrow_3d.png',
  '📶': 'assets/Antenna bars/3D/antenna_bars_3d.png',
  '📹': 'assets/Video camera/3D/video_camera_3d.png',
  '📺': 'assets/Television/3D/television_3d.png',
  '🔀': 'assets/Shuffle tracks button/3D/shuffle_tracks_button_3d.png',
  '🔁': 'assets/Repeat button/3D/repeat_button_3d.png',
  '🔍': 'assets/Magnifying glass tilted left/3D/magnifying_glass_tilted_left_3d.png',
  '🔞': 'assets/No one under eighteen/3D/no_one_under_eighteen_3d.png',
  '🔷': 'assets/Large blue diamond/3D/large_blue_diamond_3d.png',
  '🗺': 'assets/World map/3D/world_map_3d.png',
  '🚀': 'assets/Rocket/3D/rocket_3d.png',
  '🛑': 'assets/Stop sign/3D/stop_sign_3d.png',
  '🛒': 'assets/Shopping cart/3D/shopping_cart_3d.png',
  '🛠': 'assets/Hammer and wrench/3D/hammer_and_wrench_3d.png',
  '🛡': 'assets/Shield/3D/shield_3d.png',
  '🤖': 'assets/Robot/3D/robot_3d.png',
  '🧸': 'assets/Teddy bear/3D/teddy_bear_3d.png',
  '🪙': 'assets/Coin/3D/coin_3d.png',
}

const stripVariation = (value: string) => value.replace(/[\uFE0F\uFE0E]/g, '')

function tokens(name: string): string[] {
  const words: string[] = []
  let current = ''
  const chars = [...name]
  for (let index = 0; index < chars.length; index += 1) {
    const char = chars[index]
    if (!/[A-Za-z0-9]/.test(char)) {
      if (current) { words.push(current); current = '' }
      continue
    }
    if (current) {
      const previous = current[current.length - 1]
      const next = chars[index + 1]
      const lowerToUpper = previous >= 'a' && previous <= 'z' && char >= 'A' && char <= 'Z'
      const acronymEnd = previous >= 'A' && previous <= 'Z'
        && char >= 'A' && char <= 'Z' && !!next && next >= 'a' && next <= 'z'
      const letterToDigit = /[A-Za-z]/.test(previous) && /[0-9]/.test(char)
      if (lowerToUpper || acronymEnd || letterToDigit) {
        words.push(current)
        current = ''
      }
    }
    current += char
  }
  if (current) words.push(current)
  return words.map((word) => word.toLowerCase())
}

function onlyAsciiText(name: string): boolean {
  return [...name].every((char) => char.charCodeAt(0) < 128 || !/\p{L}/u.test(char))
}

function entryMatches(entry: EmojiEntry, name: string, nameWords: string[], lowered: string): boolean {
  if (entry.phrases.some((phrase) => lowered.includes(phrase))) return true
  if (entry.exact?.length && onlyAsciiText(name) && entry.exact.includes(nameWords.join(' '))) {
    return true
  }
  const spellings = new Set(nameWords)
  for (let length = 2; length <= 3; length += 1) {
    if (nameWords.length < length) continue
    for (let start = 0; start <= nameWords.length - length; start += 1) {
      spellings.add(nameWords.slice(start, start + length).join(''))
    }
  }
  return entry.words.some((keyword) => {
    const parts = keyword.split(' ')
    if (spellings.has(parts.join(''))) return true
    if (parts.length < 2 || parts.length > nameWords.length) return false
    for (let start = 0; start <= nameWords.length - parts.length; start += 1) {
      if (nameWords.slice(start, start + parts.length).join(' ') === parts.join(' ')) return true
    }
    return false
  })
}

function firstEntry(entries: EmojiEntry[], name: string): string | undefined {
  const nameWords = tokens(name)
  const lowered = name.toLowerCase()
  return entries.find((entry) => entryMatches(entry, name, nameWords, lowered))?.emoji
}

function recognized(name: string, regions = true): string | undefined {
  const fromTable = firstEntry(TABLE, name)
  if (fromTable) return fromTable
  if (regions) {
    const region = regionForName(name)
    if (region) return region.flag
  }
  return firstEntry(ROLES, name)
}

const LEADING_EMOJI = /^((?:\p{Extended_Pictographic}|\u{1F1E6}-\u{1F1FF}|\uFE0F|\u200D|\u20E3)+)\s*/u

function leadingEmoji(name: string): string | undefined {
  return name.trim().match(LEADING_EMOJI)?.[1]
}

function stripLeadingEmoji(name: string): string {
  const trimmed = name.trim()
  const leading = trimmed.match(LEADING_EMOJI)
  const stripped = leading ? trimmed.slice(leading[0].length).trim() : trimmed
  return stripped || name
}

function flagCode(emoji: string): string | undefined {
  const characters = [...emoji].filter((char) => char.charCodeAt(0) !== 0xFE0F)
  if (characters.length !== 2) return undefined
  const points = characters.map((char) => char.codePointAt(0)!)
  if (!points.every((point) => point >= 0x1F1E6 && point <= 0x1F1FF)) return undefined
  return points.map((point) => String.fromCharCode(point - 0x1F1E6 + 65)).join('')
}

/** ACL4SSR writes the US as 🇺🇲, which flag-icons has no file for. */
function canonicalEmoji(emoji: string): string {
  const code = flagCode(emoji)
  return code === 'UM' ? flagEmoji('US') : emoji
}

function iconEmojiForRuleSets(groupName: string, scheme: RuleScheme): string | undefined {
  const matches: string[] = []
  for (const set of scheme.ruleSets ?? []) {
    if (set.group !== groupName) continue
    const fromName = firstEntry(RULE_LISTS, set.name) ?? recognized(set.name, false)
    if (fromName) matches.push(fromName)
    for (const rule of set.rules) {
      const type = rule.type.toUpperCase()
      if (type === 'FINAL' || type === 'MATCH') matches.push('🐟')
      else if (type === 'GEOIP' && rule.value?.toUpperCase() === 'CN') matches.push('🎯')
      else if (type === 'GEOIP' && ['LAN', 'PRIVATE'].includes(rule.value?.toUpperCase() ?? '')) matches.push('🏠')
    }
  }
  if (!matches.length) return undefined
  if (matches.length > 1 && matches.every((emoji) => STREAMING.has(emoji))) return '🎬'
  const counts = new Map<string, number>()
  let best = matches[0]
  for (const emoji of matches) {
    const count = (counts.get(emoji) ?? 0) + 1
    counts.set(emoji, count)
    if (count > (counts.get(best) ?? 0)) best = emoji
  }
  return best
}

function emojiFromMembers(group: PolicyGroup): string | undefined {
  const references = group.options.map((option) => option.toUpperCase())
  if (references.length === 1 && references[0] === 'DIRECT') return '🎯'
  if (references.length > 0 && references.every((option) => option.startsWith('REJECT'))) return '🛑'
  return undefined
}

function fallbackEmoji(type: PolicyGroup['type']): string {
  if (type === 'url-test') return '⚡️'
  if (type === 'fallback') return '🔁'
  if (type === 'load-balance') return '⚖️'
  return '🌐'
}

function resolvedEmoji(group: PolicyGroup, scheme: RuleScheme): string {
  return leadingEmoji(group.name)
    ?? recognized(group.name)
    ?? iconEmojiForRuleSets(group.name, scheme)
    ?? emojiFromMembers(group)
    ?? fallbackEmoji(group.type)
}

export interface EmojiAutofillResult {
  scheme: RuleScheme
  renamed: Array<[string, string]>
}

/**
 * Prefix groups that do not start with an emoji. References in options,
 * rules, rule-set snapshots and matchingOrder follow the rename.
 */
export function autoFillGroupEmojis(source: RuleScheme): EmojiAutofillResult {
  const used = new Set(source.groups.map((group) => group.name))
  const renames = new Map<string, string>()
  for (const group of source.groups) {
    if (leadingEmoji(group.name)) continue
    const candidate = `${resolvedEmoji(group, source)} ${group.name}`.trim()
    if (used.has(candidate)) continue
    used.add(candidate)
    renames.set(group.name, candidate)
  }
  if (!renames.size) return { scheme: source, renamed: [] }

  const mapName = (name: string) => renames.get(name) ?? name
  return {
    scheme: {
      ...source,
      groups: source.groups.map((group) => ({
        ...group,
        name: mapName(group.name),
        options: group.options.map(mapName),
      })),
      rules: source.rules.map((rule) => ({ ...rule, group: mapName(rule.group) })),
      customRules: (source.customRules ?? []).map((rule) => ({ ...rule, group: mapName(rule.group) })),
      ruleSets: (source.ruleSets ?? []).map((set) => ({
        ...set,
        group: mapName(set.group),
        rules: set.rules.map((rule) => ({ ...rule, group: mapName(rule.group) })),
      })),
      matchingOrder: source.matchingOrder?.map(mapName),
      ruleOrder: renameRuleOrderKeys(source.ruleOrder, renames),
      rawConfigurationText: undefined,
      updatedAt: Date.now(),
    },
    renamed: [...renames.entries()],
  }
}

function encodePath(path: string): string {
  return path.split('/').map(encodeURIComponent).join('/')
}

function circleURL(emoji: string): string {
  const key = stripVariation(emoji)
  const stem = [...key].map((char) => char.codePointAt(0)!.toString(16)).join('-')
  return `${CIRCLE_BASE}${stem}.png`
}

/** The image URL for one emoji on a client that renders policy icons. */
function iconURL(emoji: string, target: ClientTarget): string | undefined {
  const canonical = canonicalEmoji(stripVariation(emoji))
  const code = flagCode(canonical)
  if (code) {
    if (!FLAG_CODES.has(code)) return undefined
    if (CIRCLE_ICONS.has(target)) return circleURL(canonical)
    return `${FLAG_BASE}${code.toLowerCase()}.png`
  }
  const path = FLUENT_PATHS[canonical]
  if (!path) return undefined
  if (CIRCLE_ICONS.has(target)) return circleURL(canonical)
  return `${FLUENT_BASE}${encodePath(path)}`
}

/**
 * Attach an icon URL to each group that can have one. For clients that draw
 * icons, also drop the leading emoji from group names and update every rule,
 * option and rule-set reference so the generated profile stays consistent.
 */
export function withPolicyGroupIcons(
  scheme: RuleScheme,
  target: ClientTarget | undefined,
): RuleScheme {
  if (!target || !WRITES_ICONS.has(target)) return scheme

  const icons = new Map<string, string>()
  const regionGroups = new Set<string>()
  for (const group of scheme.groups) {
    if (group.type === 'conditional' || group.type === 'relay' || group.type === 'unsupported') continue
    const emoji = resolvedEmoji(group, scheme)
    const isRegion = !!flagCode(canonicalEmoji(stripVariation(emoji)))
    if (isRegion) {
      if (REGION_FROM_NAME.has(target)) continue
      regionGroups.add(group.name)
    }
    const url = iconURL(emoji, target)
    if (url) icons.set(group.name, url)
  }
  if (icons.size === 0) return scheme

  let renamed: Map<string, string> | undefined
  if (DRAWS_ICONS.has(target)) {
    const candidates = scheme.groups.map((group) => [group.name, stripLeadingEmoji(group.name)] as const)
    const counts = new Map<string, number>()
    for (const [, candidate] of candidates) counts.set(candidate, (counts.get(candidate) ?? 0) + 1)
    renamed = new Map()
    for (const [original, candidate] of candidates) {
      if (!icons.has(original) || regionGroups.has(original)) continue
      if (candidate !== original && counts.get(candidate) === 1) renamed.set(original, candidate)
    }
  }

  const rename = (name: string) => renamed?.get(name) ?? name
  const renameRule = (rule: RoutingRule): RoutingRule => ({ ...rule, group: rename(rule.group) })
  return {
    ...scheme,
    groups: scheme.groups.map((group) => ({
      ...group,
      name: rename(group.name),
      options: group.options.map(rename),
      selected: group.selected ? rename(group.selected) : group.selected,
      icon: icons.get(group.name),
    })),
    rules: scheme.rules.map(renameRule),
    customRules: scheme.customRules?.map(renameRule),
    ruleSets: scheme.ruleSets?.map((set) => ({
      ...set,
      group: rename(set.group),
      rules: set.rules.map(renameRule),
    })),
  }
}
