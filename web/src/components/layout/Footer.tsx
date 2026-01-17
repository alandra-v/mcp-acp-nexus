import { useRef, useCallback } from 'react'

export function Footer() {
  const containerRef = useRef<HTMLDivElement>(null)
  const glowRef = useRef<HTMLDivElement>(null)

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!containerRef.current || !glowRef.current) return

    const rect = containerRef.current.getBoundingClientRect()
    const x = e.clientX - rect.left
    const y = e.clientY - rect.top

    glowRef.current.style.setProperty('--mouse-x', `${x}px`)
    glowRef.current.style.setProperty('--mouse-y', `${y}px`)
  }, [])

  return (
    <footer className="mt-20 border-t border-[var(--border-subtle)] text-center">
      <div className="relative">
        <div
          ref={containerRef}
          className="relative inline-block cursor-default group"
          onMouseMove={handleMouseMove}
        >
          <div className="font-brand text-[clamp(100px,15vw,180px)] font-bold tracking-[0.04em] text-transparent bg-gradient-to-b from-base-950 to-base-950 bg-clip-text select-none leading-none pt-6 whitespace-nowrap">
            MCP ACP
          </div>
          <div
            ref={glowRef}
            className="absolute inset-0 font-brand text-[clamp(100px,15vw,180px)] font-bold tracking-[0.02em] text-transparent bg-clip-text pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-200 leading-none pt-6 whitespace-nowrap"
            style={{
              background: `radial-gradient(circle 90px at var(--mouse-x, 50%) var(--mouse-y, 50%), var(--base-800) 0%, var(--base-900) 35%, var(--base-950) 60%, transparent 100%)`,
              WebkitBackgroundClip: 'text',
              backgroundClip: 'text',
            }}
            aria-hidden="true"
          >
            0 TRUST
          </div>
        </div>
      </div>
      <div className="py-24 text-sm text-base-700 tracking-wide">
        Model Context Protocol Access Control Proxy
      </div>
    </footer>
  )
}
