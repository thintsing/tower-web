import type { ReactNode } from 'react'

/**
 * ACL4SSR 的策略组名以彩色 emoji 开头（🚀、🍎、🌍…）。
 * 这些字符只用于展示，配置里仍保留原名，避免规则引用失配。
 */
export function groupDisplayName(name: string, showEmoji = false): string {
  if (showEmoji) return name.trim() || name
  const stripped = name
    .replace(/^[\p{Extended_Pictographic}\uFE0F\u200D\u20E3]+\s*/u, '')
    .trim()
  return stripped || name
}

type GroupIconKind =
  | 'rocket'
  | 'cycle'
  | 'globe'
  | 'send'
  | 'windows'
  | 'apple'
  | 'bell'
  | 'arrow'
  | 'ban'
  | 'shield'
  | 'filter'
  | 'nodes'

const GROUP_ICON_RULES: Array<[RegExp, GroupIconKind]> = [
  [/自动|测速|test|auto/i, 'cycle'],
  [/电报|telegram/i, 'send'],
  [/苹果|apple/i, 'apple'],
  [/微软|microsoft|windows/i, 'windows'],
  [/谷歌|google|fcm/i, 'bell'],
  [/媒体|global|globe/i, 'globe'],
  [/直连|direct/i, 'arrow'],
  [/拦截|reject|广告|ad/i, 'ban'],
  [/净化|应用|shield/i, 'shield'],
  [/漏网|final|filter/i, 'filter'],
  [/节点|proxy|select/i, 'rocket'],
]

function iconKindFor(name: string): GroupIconKind {
  const display = groupDisplayName(name)
  for (const [pattern, kind] of GROUP_ICON_RULES) {
    if (pattern.test(display)) return kind
  }
  return 'nodes'
}

function Glyph({ kind }: { kind: GroupIconKind }): ReactNode {
  switch (kind) {
    case 'rocket':
      return (
        <>
          <path d="M13.8 4.4c2.7.5 4.9 2.7 5.4 5.4-.7 3.7-3.6 7.1-8.4 8.8L7 14.8c1.7-4.8 5.1-7.7 6.8-10.4Z" />
          <circle cx="15" cy="9" r="1.4" />
          <path d="M8 15.5 5 18.5M10.5 17l-1.2 2.4M4.2 19.8h2.4" />
        </>
      )
    case 'cycle':
      return (
        <>
          <path d="M20 10.5a8 8 0 0 0-13.6-4.8L4 8" />
          <path d="M4 4v4h4" />
          <path d="M4 13.5a8 8 0 0 0 13.6 4.8L20 16" />
          <path d="M20 20v-4h-4" />
        </>
      )
    case 'globe':
      return (
        <>
          <circle cx="12" cy="12" r="8" />
          <path d="M4 12h16" />
          <path d="M12 4c2.2 2.4 3.4 5.2 3.4 8s-1.2 5.6-3.4 8c-2.2-2.4-3.4-5.2-3.4-8S9.8 6.4 12 4Z" />
        </>
      )
    case 'send':
      return (
        <>
          <path d="M21 3 3 10.4l7 2.6 2.6 7L21 3Z" />
          <path d="m10 13 4.2-4.2" />
        </>
      )
    case 'windows':
      return (
        <>
          <rect x="4" y="4" width="6.5" height="6.5" rx="0.5" />
          <rect x="13.5" y="4" width="6.5" height="6.5" rx="0.5" />
          <rect x="4" y="13.5" width="6.5" height="6.5" rx="0.5" />
          <rect x="13.5" y="13.5" width="6.5" height="6.5" rx="0.5" />
        </>
      )
    case 'apple':
      return (
        <>
          <path d="M12.2 8.3c-1.2-2.5-4.4-2.2-5.3-.3-1.2 2.4.2 7.1 2.5 9.4 1 1 2.1.9 2.8.2.7.7 1.8.8 2.8-.2 2.3-2.3 3.7-7 2.5-9.4-.9-1.9-4.1-2.2-5.3.3Z" />
          <path d="M12.2 8.3c-.1-2.2 1.2-3.8 3.1-4.3" />
        </>
      )
    case 'bell':
      return (
        <>
          <path d="M18 9a6 6 0 0 0-12 0c0 6.5-2.5 7-2.5 8.5h17C20.5 16 18 15.5 18 9Z" />
          <path d="M9.8 20a2.4 2.4 0 0 0 4.4 0" />
        </>
      )
    case 'arrow':
      return (
        <>
          <path d="M4 12h15" />
          <path d="m14 7 5 5-5 5" />
        </>
      )
    case 'ban':
      return (
        <>
          <circle cx="12" cy="12" r="8" />
          <path d="m6.4 6.4 11.2 11.2" />
        </>
      )
    case 'shield':
      return (
        <>
          <path d="M12 3.5 19 6v5.6c0 4.3-3 7.5-7 8.9-4-1.4-7-4.6-7-8.9V6l7-2.5Z" />
          <path d="m9 11.8 2 2 4-4.2" />
        </>
      )
    case 'filter':
      return (
        <>
          <path d="M4 5h16l-6.2 7.2v6.3L10.2 20v-7.8L4 5Z" />
        </>
      )
    default:
      return (
        <>
          <circle cx="7" cy="7" r="2.5" />
          <circle cx="17" cy="7" r="2.5" />
          <circle cx="12" cy="17" r="2.5" />
          <path d="m9.4 8.1 1.4 6.3M14.6 8.1l-1.4 6.3M9.5 7h5" />
        </>
      )
  }
}

/** 与策略组名匹配的单色线条图标；颜色只由外部 CSS 控制。 */
export function GroupIcon({ name }: { name: string }): ReactNode {
  return (
    <svg
      className="group-icon"
      viewBox="0 0 24 24"
      aria-hidden="true"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <Glyph kind={iconKindFor(name)} />
    </svg>
  )
}
