// 当前选中的规则方案：自定义方案直接读 store，内置方案异步加载快照。
import { useEffect, useState } from 'react'
import type { RuleScheme } from '../models/types'
import { useStore } from '../store'
import { BUILTIN_SCHEMES, loadScheme } from './scheme'

export function useScheme(): RuleScheme | undefined {
  const selectedSchemeID = useStore((s) => s.selectedSchemeID)
  const customSchemes = useStore((s) => s.customSchemes)
  const builtinSchemeOverrides = useStore((s) => s.builtinSchemeOverrides)
  const schemeSnapshots = useStore((s) => s.schemeSnapshots)
  const [scheme, setScheme] = useState<RuleScheme | undefined>()
  useEffect(() => {
    const custom = customSchemes.find((c) => c.id === selectedSchemeID)
    if (custom) { setScheme(custom); return }
    // 切换方案时先清空，避免旧方案的预览继续显示。
    setScheme(undefined)
    const meta = BUILTIN_SCHEMES.find((m) => m.id === selectedSchemeID) ?? BUILTIN_SCHEMES[0]
    let cancelled = false
    // 覆盖层优先（固化后的版本），没有再读 public/rulesets 原厂快照。
    loadScheme(meta, builtinSchemeOverrides, schemeSnapshots)
      .then((s) => { if (!cancelled) setScheme(s) })
      .catch(() => { if (!cancelled) setScheme(undefined) })
    return () => { cancelled = true }
  }, [selectedSchemeID, customSchemes, builtinSchemeOverrides, schemeSnapshots])
  return scheme
}
