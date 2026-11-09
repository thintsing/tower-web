// 共享的 /api/network 读取。导出页、规则解释与流程 lint 必须用同一份
// 托管地址解析结果，否则静态部署下会出现「检查面板没问题、导出页阻断」。
import { useEffect, useState } from 'react'
import { apiFetch } from './apiAuth'

export interface NetworkInfo {
  host: string
  lan: string[]
  publicUrl: string
  publicUrlError: string
}

let cached: NetworkInfo | null = null
let pending: Promise<NetworkInfo> | null = null

function readNetworkInfo(): Promise<NetworkInfo> {
  if (cached) return Promise.resolve(cached)
  if (!pending) {
    pending = apiFetch('/api/network')
      .then((response) => response.json())
      .then((data) => {
        cached = {
          host: String(data?.host ?? ''),
          lan: Array.isArray(data?.lan) ? data.lan.map(String) : [],
          publicUrl: String(data?.publicUrl ?? ''),
          publicUrlError: String(data?.publicUrlError ?? ''),
        }
        return cached
      })
      // 静态部署没有伴生服务：返回空地址，交给导出侧按「无法托管」硬阻断，
      // 而不是退回 localhost 产出手机不可达的配置。
      .catch((): NetworkInfo => ({ host: '', lan: [], publicUrl: '', publicUrlError: '' }))
      .finally(() => { pending = null })
  }
  return pending
}

/** 读取 /api/network；同一页面生命周期内只请求一次，失败结果也会共享。 */
export function useNetworkInfo(): NetworkInfo | null {
  const [info, setInfo] = useState<NetworkInfo | null>(cached)
  useEffect(() => {
    if (info) return
    let alive = true
    readNetworkInfo().then((value) => { if (alive) setInfo(value) })
    return () => { alive = false }
  }, [info])
  return info
}

/** 当前页面是否从本机回环地址打开；局域网 / 公网地址不算。 */
export function isLoopbackHost(): boolean {
  return ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(window.location.hostname)
}
