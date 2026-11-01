// GitHub link shown at the bottom of the sidebar (repository or profile).
// VITE_GITHUB_REPO_URL in `.env.local` overrides this fallback.
// Leave the fallback empty to keep the icon as a non-clickable placeholder.
const FALLBACK_GITHUB_REPO_URL = 'https://github.com/thintsing'

function normalizeRepoURL(raw: string | undefined): string {
  const value = (raw ?? '').trim()
  return /^https?:\/\/\S+$/i.test(value) ? value : ''
}

export const GITHUB_REPO_URL = normalizeRepoURL(
  import.meta.env.VITE_GITHUB_REPO_URL ?? FALLBACK_GITHUB_REPO_URL,
)
