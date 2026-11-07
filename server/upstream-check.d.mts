// server/upstream-check.mjs 的类型声明；前端 TS 通过这里复用同一套比对算法。

export interface UpstreamTextResultLike {
  text: string
  etag?: string
  contentType?: string
  contentLength?: number
  status?: number
}

export interface UpstreamBaselineFile {
  path: string
  blobSha: string
  etag?: string
}

export interface UpstreamBaseline {
  commitSha?: string
  files?: UpstreamBaselineFile[]
}

export interface UpstreamBaselineCheck {
  checked: boolean
  updateAvailable: boolean
  method: 'trees' | 'head'
  changedFiles: string[]
  commitSha?: string
  error?: string
}

export const ACL4SSR_REPO: string
export const ACL4SSR_BRANCH: string
export const ACL4SSR_RAW_BASE: string
export const ACL4SSR_API_BASE: string
export const ACL4SSR_PIN_COMMIT: string

export function upstreamRawURL(path: string, commitSha: string): string
export function fetchUpstreamTree(
  fetchText: (url: string) => Promise<string | UpstreamTextResultLike>,
): Promise<{ commitSha: string; blobs: Map<string, string> }>
export function checkUpstreamBaseline(
  previous: UpstreamBaseline | undefined,
  options: {
    fetchText?: (url: string) => Promise<string | UpstreamTextResultLike>
    fetchHeaders?: (url: string) => Promise<{ etag?: string }>
  },
): Promise<UpstreamBaselineCheck>
export function commitsBehind(
  fetchText: (url: string) => Promise<string | UpstreamTextResultLike>,
  fromCommit: string,
  cache?: Map<string, Promise<number | null>>,
): Promise<number | null>
