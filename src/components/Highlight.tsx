/** 搜索结果高亮：命中片段用浅色底标出，其余文字不变。 */
export function Highlight({ text, needle }: { text: string; needle: string }) {
  if (!needle) return <>{text}</>
  const at = text.toLowerCase().indexOf(needle.toLowerCase())
  if (at < 0) return <>{text}</>
  return (
    <>
      {text.slice(0, at)}
      <mark>{text.slice(at, at + needle.length)}</mark>
      {text.slice(at + needle.length)}
    </>
  )
}
