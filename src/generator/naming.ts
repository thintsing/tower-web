// Untrusted node-name escaping, ported from ConfigurationGenerator.swift.
// Node names come from subscription remarks; every output path must pass
// through one of these (product constraint #9).

function collapsingLineBreaks(value: string): string {
  return value.replace(/[\r\n]+/g, ' ')
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
  const escaped = collapsingLineBreaks(value)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
  return `"${escaped}"`
}

/** YAML scalar that keeps newlines as `\n` escapes (SSH / WireGuard keys). */
export function yamlMultiline(value: string): string {
  const escaped = value
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\t/g, '\\t')
  return `"${escaped}"`
}

/** sing-box / JSON string (JSON.stringify semantics minus outer quotes use). */
export function jsonString(value: string): string {
  return JSON.stringify(collapsingLineBreaks(value))
}
