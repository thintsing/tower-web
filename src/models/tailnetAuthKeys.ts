// Auth keys live outside the persisted snapshot, mirroring the iOS Keychain
// layout: the connections can be inspected and edited, while the credential
// stays in one local storage record. Nothing here is uploaded or synced.

const STORAGE_KEY = 'tower-web-tailnet-auth-keys'

export function loadTailnetAuthKeys(): Record<string, string> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return {}
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
    const keys: Record<string, string> = {}
    for (const [id, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof value === 'string' && value.trim() && value.length <= 512) keys[id] = value
    }
    return keys
  } catch {
    return {}
  }
}

export function persistTailnetAuthKeys(keys: Record<string, string>): void {
  try {
    if (Object.keys(keys).length === 0) localStorage.removeItem(STORAGE_KEY)
    else localStorage.setItem(STORAGE_KEY, JSON.stringify(keys))
  } catch {
    // localStorage can be unavailable or full; the caller still gets the
    // in-memory value for this session.
  }
}

/** Drop keys whose connection was deleted from the snapshot. */
export function pruneTailnetAuthKeys(
  keys: Record<string, string>,
  validIds: Set<string>,
): Record<string, string> {
  const pruned: Record<string, string> = {}
  for (const [id, value] of Object.entries(keys)) {
    if (validIds.has(id)) pruned[id] = value
  }
  return pruned
}
