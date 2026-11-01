import type { ReactNode } from 'react'

/** Decorative first-use route illustration: subscription → local parsing → nodes → export. */
export function RouteIllustration({ className }: { className?: string }): ReactNode {
  return (
    <svg
      className={`route-illustration${className ? ` ${className}` : ''}`}
      viewBox="0 0 540 320"
      role="img"
      aria-label="示意图：订阅源经本地解析进入节点池，再导出到客户端；这里使用占位节点，不是真实数据"
    >
      <g className="route-grid" aria-hidden="true">
        <path d="M40 40h460M40 100h460M40 160h460M40 220h460M40 280h460" />
        <path d="M100 40v240M220 40v240M340 40v240M460 40v240" />
      </g>

      <g className="route-base" aria-hidden="true">
        <path d="M92 236C168 218 192 132 300 116S420 84 472 68" />
        <path d="M300 116c58 20 96 56 148 94" />
        <path d="M92 236c52 26 128 34 196 18" />
      </g>
      <path
        className="route-active"
        d="M92 236C168 218 192 132 300 116"
        aria-hidden="true"
      />

      <g className="route-origin" aria-hidden="true">
        <circle cx="92" cy="236" r="22" className="route-ring" />
        <circle cx="92" cy="236" r="14" className="route-ring" />
        <circle cx="92" cy="236" r="6" />
        <path d="M92 246v10M86 256h12" />
        <text x="92" y="286" textAnchor="middle" className="route-label">订阅源</text>
      </g>

      <g className="route-node active" aria-hidden="true">
        <circle cx="300" cy="116" r="8" />
        <text x="300" y="96" textAnchor="middle" className="route-label">节点 1</text>
      </g>
      <g className="route-node export" aria-hidden="true">
        <circle cx="472" cy="68" r="6" />
        <text x="472" y="48" textAnchor="middle" className="route-label">导出</text>
      </g>
      <g className="route-node" aria-hidden="true">
        <circle cx="448" cy="210" r="6" />
        <text x="448" y="232" textAnchor="middle" className="route-label">节点 2</text>
      </g>
      <g className="route-node" aria-hidden="true">
        <circle cx="288" cy="254" r="6" />
        <text x="288" y="276" textAnchor="middle" className="route-label">节点 3</text>
      </g>

      <text x="40" y="28" className="route-label route-caption">示意图 · 非真实节点</text>
    </svg>
  )
}
