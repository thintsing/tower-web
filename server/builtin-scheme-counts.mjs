// 内置方案的服务端计数元数据。
// - 规则数只含方案自身的本地方案规则；provider 引用不保存正文，不计入。
// - 与前端 src/rules/scheme.ts / loyalsoldierScheme.ts 的一致性由
//   selfcheck:provider-rulesets 显式断言，增删 provider 时不会静默不同步。
export const BUILTIN_SCHEME_FILES = {
  'acl4ssr-online': 'ACL4SSR_Online.ini',
  'acl4ssr-mini': 'ACL4SSR_Online_Mini.ini',
  'acl4ssr-full': 'ACL4SSR_Online_Full.ini',
}

export const BUILTIN_PROGRAMMATIC_SCHEMES = {
  'loyalsoldier-clash-rules': { rules: 1, groups: 7 },
}

export const BUILTIN_SCHEME_COUNT = Object.keys(BUILTIN_SCHEME_FILES).length
  + Object.keys(BUILTIN_PROGRAMMATIC_SCHEMES).length
