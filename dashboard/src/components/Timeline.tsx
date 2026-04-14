import { useEffect, useRef } from 'react'
import type { BehavioralEvent } from '../App'

interface Props {
  events: BehavioralEvent[]
  categoryColor: (cat: string) => string
  severityBg: (sev: string) => string
}

const CATEGORY_ICON: Record<string, string> = {
  process: '🔴',
  network: '🟠',
  file: '🟡',
  memory: '🟢',
  system: '🔵',
  unknown: '⚪',
}

export default function Timeline({ events, categoryColor, severityBg }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to bottom on new events
  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events.length])

  // Category filter
  const [filter, setFilter] = useState<string>('all')

  const filtered = filter === 'all' ? events : events.filter(e => e.category === filter)

  return (
    <div className="h-full flex flex-col">
      {/* Filter bar */}
      <div className="flex items-center gap-2 mb-3">
        <span className="text-xs text-[#6a6a7a]">Filter:</span>
        {['all', 'process', 'network', 'file', 'memory', 'system'].map(cat => (
          <button
            key={cat}
            onClick={() => setFilter(cat)}
            className={`text-xs px-2 py-1 rounded transition-colors ${
              filter === cat ? 'bg-[#ff6b35]/20 text-[#ff6b35]' : 'text-[#6a6a7a] hover:text-[#e0e0e0]'
            }`}
          >
            {cat === 'all' ? 'All' : `${CATEGORY_ICON[cat] ?? ''} ${cat}`}
          </button>
        ))}
        <span className="text-xs text-[#4a4a5a] ml-auto">{filtered.length} events</span>
      </div>

      {/* Event stream */}
      <div ref={containerRef} className="flex-1 overflow-auto bg-[#0a0a0f] rounded border border-[#2a2a3a] font-mono text-xs">
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[#4a4a5a]">
            Waiting for behavioral events...
          </div>
        ) : (
          <table className="w-full">
            <thead className="sticky top-0 bg-[#13131a] z-10">
              <tr className="text-[#6a6a7a]">
                <th className="text-left px-3 py-1.5 w-8">#</th>
                <th className="text-left px-3 py-1.5 w-24">Time</th>
                <th className="text-left px-3 py-1.5 w-12">PID</th>
                <th className="text-left px-3 py-1.5 w-8"></th>
                <th className="text-left px-3 py-1.5 w-28">Syscall</th>
                <th className="text-left px-3 py-1.5">Arguments</th>
                <th className="text-left px-3 py-1.5 w-20">Return</th>
                <th className="text-left px-3 py-1.5 w-16">Severity</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((event, i) => (
                <tr
                  key={event.id}
                  className={`border-t border-[#1a1a24] hover:bg-[#1a1a24] transition-colors ${i >= filtered.length - 3 ? 'event-flash' : ''}`}
                >
                  <td className="px-3 py-1 text-[#4a4a5a]">{i + 1}</td>
                  <td className="px-3 py-1 text-[#6a6a7a]">{event.timestamp.split('T')[1]?.slice(0, 12) ?? event.timestamp}</td>
                  <td className="px-3 py-1 text-[#00aaff]">{event.pid}</td>
                  <td className="px-3 py-1">{CATEGORY_ICON[event.category] ?? '⚪'}</td>
                  <td className={`px-3 py-1 font-bold ${categoryColor(event.category)}`}>
                    {event.syscall_name}
                  </td>
                  <td className="px-3 py-1 text-[#e0e0e0] truncate max-w-[400px]" title={event.args}>
                    {truncateArgs(event.args)}
                  </td>
                  <td className={`px-3 py-1 ${event.return_value === '-1' ? 'text-[#ff3366]' : 'text-[#6a6a7a]'}`}>
                    {event.return_value}
                  </td>
                  <td className="px-3 py-1">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] border ${severityBg(event.severity)}`}>
                      {event.severity}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

import { useState } from 'react'

function truncateArgs(args: string): string {
  if (!args || args === '{}') return '—'
  try {
    const parsed = JSON.parse(args)
    const entries = Object.entries(parsed).slice(0, 3)
    return entries.map(([k, v]) => `${k}=${typeof v === 'string' ? v.slice(0, 40) : v}`).join(', ')
  } catch {
    return args.slice(0, 60)
  }
}