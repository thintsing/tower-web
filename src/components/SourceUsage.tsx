// 订阅套餐行。机场不给配套信息时也必须占位，否则用户分不清“机场没返回”
// 和“塔台没有这个功能”。
import type { SubscriptionHealthLevel, SubscriptionUsageSummary } from '../models/types'

const HEALTH_TITLES: Record<SubscriptionHealthLevel, string> = {
  unknown: '数据未知',
  normal: '正常',
  attention: '注意',
  urgent: '紧急',
  expired: '已过期',
}

/** 颜色之外再用不同符号：色盲用户也能区分档位。 */
const HEALTH_ICONS: Record<SubscriptionHealthLevel, string> = {
  unknown: '—',
  normal: '✓',
  attention: '△',
  urgent: '▲',
  expired: '✕',
}

const HEALTH_TIPS: Record<SubscriptionHealthLevel, string> = {
  unknown: '机场没有返回足够数据，不做预警',
  normal: '到期时间与流量余量都正常',
  attention: '接近到期或流量余量偏低',
  urgent: '很快到期或流量即将用尽',
  expired: '订阅已过期，需要续费',
}

/** 订阅健康度徽标：首页订阅卡与订阅设置共用。 */
export function UsageHealthBadge({ summary }: { summary: SubscriptionUsageSummary }) {
  const level = summary.health
  return (
    <span
      className={`usage-health ${level}`}
      data-health={level}
      title={summary.healthReasons.length ? summary.healthReasons.join('；') : HEALTH_TIPS[level]}
    >
      <span aria-hidden="true">{HEALTH_ICONS[level]}</span>
      {HEALTH_TITLES[level]}
    </span>
  )
}

/** 流量未知时显示「—」，不要用 0 冒充真实值。 */
export function formatBytes(bytes?: number): string {
  if (bytes === undefined || !Number.isFinite(bytes)) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let v = Math.max(0, bytes)
  let i = 0
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  // 四舍五入可能把 1023.6 KB 显示成「1024 KB」；此时再进一位才是正确量级。
  const digits = () => (v >= 100 || i === 0 ? 0 : 1)
  let text = v.toFixed(digits())
  if (Number(text) >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
    text = v.toFixed(digits())
  }
  return `${text} ${units[i]}`
}

/** 到期日期按浏览器本地时区展示。 */
export function formatExpiryDate(ts: number): string {
  return new Date(ts).toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

/**
 * 只有带订阅地址的来源才可能从上游拿到套餐用量。
 * 粘贴内容 / 手动单节点来源没有地址，不要显示这套「流量 / 到期」块。
 */
export function shouldShowSourceUsage(source: { url?: string }): boolean {
  return String(source.url ?? '').trim().length > 0
}

export function SourceUsage({ summary }: { summary: SubscriptionUsageSummary }) {
  const total = summary.totalBytes
  const used = summary.usedBytes
  const unlimited = summary.unlimited === true
  const expireAt = summary.expireAt
  const trafficUnknown = !unlimited && total === undefined && used === undefined
  const expiryUnknown = expireAt === undefined
  const allUnknown = trafficUnknown && expiryUnknown

  // 三种状态都要读得通：未知（—）/ 不限量 / 有上限（已用 + 共）。
  const trafficLabel = (() => {
    if (unlimited) {
      return used !== undefined ? `已用 ${formatBytes(used)} · 不限量` : '不限量'
    }
    if (total !== undefined) {
      return used !== undefined
        ? `已用 ${formatBytes(used)} / 共 ${formatBytes(total)}`
        : `共 ${formatBytes(total)} · 未提供已用`
    }
    if (used !== undefined) {
      return `已用 ${formatBytes(used)} · 总量未知`
    }
    return '流量 —'
  })()

  return (
    <div className="usage" data-usage={allUnknown ? 'unknown' : 'known'}>
      <UsageHealthBadge summary={summary} />
      {/* 不限量与有上限都属于“已知”，只有真正三无时才提示机场没返回。 */}
      {unlimited ? (
        <span
          className="usage-item"
          title="机场把流量标记为不限量（total=0），已用流量仍会累计"
        >{trafficLabel}</span>
      ) : trafficUnknown ? (
        <span
          className="usage-item unknown"
          title="该订阅没有返回流量信息（响应头 subscription-userinfo）"
        >流量 —</span>
      ) : total !== undefined ? (
        <span
          className={`usage-item${summary.lowTraffic ? ' warn' : ''}`}
          title={used !== undefined
            ? `已用 ${formatBytes(used)}${summary.remainingRatio !== undefined
              ? ` · 剩余 ${Math.round(Math.max(0, summary.remainingRatio) * 100)}%`
              : ''}`
            : '机场只返回了套餐总量，没有提供已用流量'}
        >{trafficLabel}</span>
      ) : (
        <span className="usage-item" title="该订阅只返回了已用流量">已用 {formatBytes(used)}（总量未知）</span>
      )}
      {expiryUnknown ? (
        <span
          className="usage-item unknown"
          title="该订阅没有返回到期时间（响应头 subscription-userinfo）"
        >到期 —</span>
      ) : (
        <span
          className={`usage-item${summary.expired
            ? ' expired'
            : summary.daysUntilExpiry !== undefined && summary.daysUntilExpiry <= 7 ? ' warn' : ''}`}
          title={summary.longTerm
            ? '订阅未设置到期时间'
            : `到期日期 ${formatExpiryDate(expireAt)}（按本地时区）`}
        >
          {summary.longTerm
            ? '长期有效'
            : summary.expired
              ? `已过期 · ${formatExpiryDate(expireAt)}`
              : `还有 ${summary.daysUntilExpiry} 天到期 · ${formatExpiryDate(expireAt)}`}
        </span>
      )}
      {allUnknown && (
        <span className="usage-item note">
          机场未返回用量信息 · 可在订阅卡「⋯ → 编辑订阅 → 高级请求设置」里改用 Clash 系 UA，并确认地址是 Clash 版链接（常见 ?flag=clash 或 ?clash=1）后刷新
        </span>
      )}
    </div>
  )
}
