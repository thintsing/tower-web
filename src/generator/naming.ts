// Untrusted node-name escaping, ported from ConfigurationGenerator.swift.
// Node names come from subscription remarks; every output path must pass
// through one of these (product constraint #9).

function collapsingLineBreaks(value: string): string {
  return value.replace(/[\r\n]+/g, ' ')
}

/**
 * YAML 双引号标量只能直接包含可打印字符；订阅备注里的 C0 控制字符
 * （例如 \u0007）会让 mihomo / Go YAML 解析器判定整份配置非法。
 * 统一转成 `\xNN` 转义，保持原值又保证语法合法。
 */
function escapeControlCharacters(value: string): string {
  return value.replace(
    /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g,
    (char) => `\\x${char.charCodeAt(0).toString(16).padStart(2, '0')}`,
  )
}

/** INI-style formats (Surge / Loon / QuanX / Shadowrocket). */
export function confName(value: string): string {
  return collapsingLineBreaks(value)
    .replace(/=/g, '-')
    .replace(/,/g, '，')
    .replace(/#/g, '＃')
    .replace(/;/g, '；')
    // Square brackets open a section in every INI-style config.
    .replace(/\[/g, '［')
    .replace(/\]/g, '］')
    .trim()
}

/** Clash YAML double-quoted scalar. */
export function yaml(value: string): string {
  const escaped = escapeControlCharacters(
    collapsingLineBreaks(value)
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"'),
  )
  return `"${escaped}"`
}

/** YAML scalar that keeps newlines as `\n` escapes (SSH / WireGuard keys). */
export function yamlMultiline(value: string): string {
  const escaped = escapeControlCharacters(
    value
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\t/g, '\\t'),
  )
  return `"${escaped}"`
}

/** sing-box / JSON string (JSON.stringify semantics minus outer quotes use). */
export function jsonString(value: string): string {
  return JSON.stringify(collapsingLineBreaks(value))
}
