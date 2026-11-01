import type { ReactNode } from 'react'

/** 内网页示意图：客户端 → Tailscale → 家庭设备，只有 tailnet 流量走这条路径。 */
export function TailnetIllustration({ className }: { className?: string }): ReactNode {
  return (
    <svg
      className={`tailnet-illustration${className ? ` ${className}` : ''}`}
      viewBox="0 0 400 220"
      role="img"
      aria-label="示意图：客户端通过 Tailscale 访问家庭设备，只有 Tailscale 地址段和家庭子网流量走这条路径"
    >
      <g className="tn-grid" aria-hidden="true">
        <path d="M24 50h352M24 104h352M24 158h352" />
        <path d="M96 28v164M200 28v164M304 28v164" />
      </g>

      <g aria-hidden="true">
        <path className="tn-path-base" d="M88 104h68" />
        <path className="tn-path-base" d="M244 104h42" />
        <path className="tn-path-active" d="M88 104h68" />
        <path className="tn-path-active" d="M244 104h42" />
      </g>

      <g aria-hidden="true">
        <rect className="tn-glyph" x="46" y="88" width="34" height="23" rx="3" />
        <path className="tn-glyph" d="M40 116h46M58 112h10" />
      </g>

      <g className="tn-mesh" aria-hidden="true">
        <circle cx="200" cy="104" r="30" className="tn-halo" />
        <path d="M187 95 200 113 213 95Z" />
        <circle cx="187" cy="95" r="4.5" />
        <circle cx="213" cy="95" r="4.5" />
        <circle cx="200" cy="113" r="4.5" className="tn-core" />
      </g>

      <g aria-hidden="true">
        <path className="tn-glyph" d="M286 112l22-19 22 19v27h-44Z" />
        <path className="tn-glyph" d="M300 139v-13h10v13" />
      </g>

      <text x="63" y="154" textAnchor="middle" className="tn-label">客户端</text>
      <text x="200" y="154" textAnchor="middle" className="tn-label tn-label-strong">Tailscale</text>
      <text x="308" y="154" textAnchor="middle" className="tn-label">家庭设备</text>
      <text x="24" y="30" className="tn-caption">示意图 · 只有 tailnet 流量走这里</text>
    </svg>
  )
}
