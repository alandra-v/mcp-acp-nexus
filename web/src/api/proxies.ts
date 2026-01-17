import { apiGet } from './client'
import type { Proxy } from '@/types/api'

export async function getProxies(): Promise<Proxy[]> {
  return apiGet<Proxy[]>('/proxies')
}

export async function getProxy(id: string): Promise<Proxy> {
  return apiGet<Proxy>(`/proxies/${id}`)
}
