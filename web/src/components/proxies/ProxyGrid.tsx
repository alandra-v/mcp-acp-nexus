import { ProxyCard } from './ProxyCard'
import type { Proxy } from '@/types/api'

interface ProxyGridProps {
  proxies: Proxy[]
}

export function ProxyGrid({ proxies }: ProxyGridProps) {
  if (proxies.length === 0) {
    return (
      <div className="text-center py-16 text-muted-foreground">
        No proxies found
      </div>
    )
  }

  return (
    <div className="grid grid-cols-[repeat(auto-fill,minmax(340px,1fr))] gap-5">
      {proxies.map((proxy) => (
        <ProxyCard key={proxy.proxy_name} proxy={proxy} />
      ))}
    </div>
  )
}
