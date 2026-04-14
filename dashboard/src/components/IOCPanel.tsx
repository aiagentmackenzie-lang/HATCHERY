import { useState } from 'react'
import type { IOCEntry } from '../App'

interface Props {
  iocs: IOCEntry[]
}

const IOC_ICONS: Record<string, string> = {
  ip: '🌐',
  domain: '🔗',
  url: '📍',
  email: '📧',
  hash: '🔐',
  registry_key: '🗄️',
  mutex: '🔒',
  file_path: '📁',
}

const SEV_COLORS: Record<string, string> = {
  critical: '#ff3366',
  high: '#ff6b35',
  medium: '#ffaa00',
  low: '#00aaff',
  info: '#6a6a7a',
}

export default function IOCPanel({ iocs }: Props) {
  const [copiedType, setCopiedType] = useState<string | null>(null)

  // Group by type
  const byType = new Map<string, IOCEntry[]>()
  for (const ioc of iocs) {
    const list = byType.get(ioc.ioc_type) ?? []
    list.push(ioc)
    byType.set(ioc.ioc_type, list)
  }

  const copyAll = (type: string) => {
    const entries = byType.get(type) ?? []
    const text = entries.map(e => e.value).join('\n')
    navigator.clipboard.writeText(text)
    setCopiedType(type)
    setTimeout(() => setCopiedType(null), 2000)
  }

  const copyAllIOCs = () => {
    const text = iocs.map(e => `[${e.severity.toUpperCase()}] ${e.ioc_type}: ${e.value}`).join('\n')
    navigator.clipboard.writeText(text)
    setCopiedType('all')
    setTimeout(() => setCopiedType(null), 2000)
  }

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h3 className="text-sm text-[#6a6a7a]">Indicators of Compromise</h3>
          <span className="text-lg font-bold text-[#ff6b35]">{iocs.length}</span>
          <span className="text-xs text-[#4a4a5a]">total</span>
        </div>
        <button
          onClick={copyAllIOCs}
          className="text-xs px-3 py-1.5 bg-[#13131a] border border-[#2a2a3a] rounded hover:border-[#ff6b35] hover:text-[#ff6b35] transition-colors"
        >
          {copiedType === 'all' ? '✅ Copied!' : '📋 Copy All'}
        </button>
      </div>

      {/* Type breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {Array.from(byType.entries()).map(([type, entries]) => (
          <div key={type} className="bg-[#13131a] rounded border border-[#2a2a3a] p-2.5">
            <div className="flex items-center justify-between">
              <span className="text-sm">{IOC_ICONS[type] ?? '📌'}</span>
              <button onClick={() => copyAll(type)} className="text-[10px] text-[#4a4a5a] hover:text-[#ff6b35]">
                {copiedType === type ? '✅' : '📋'}
              </button>
            </div>
            <div className="text-lg font-bold text-[#e0e0e0]">{entries.length}</div>
            <div className="text-[10px] text-[#6a6a7a] capitalize">{type.replace('_', ' ')}</div>
          </div>
        ))}
      </div>

      {/* IOC list */}
      <div className="bg-[#0a0a0f] rounded border border-[#2a2a3a] overflow-auto max-h-[400px]">
        {iocs.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-[#4a4a5a] text-sm">No IOCs extracted yet</div>
        ) : (
          <table className="w-full text-xs font-mono">
            <thead className="sticky top-0 bg-[#13131a]">
              <tr className="text-[#6a6a7a]">
                <th className="text-left px-3 py-1.5 w-8"></th>
                <th className="text-left px-3 py-1.5">Type</th>
                <th className="text-left px-3 py-1.5">Value</th>
                <th className="text-left px-3 py-1.5">Source</th>
                <th className="text-left px-3 py-1.5 w-16">Severity</th>
              </tr>
            </thead>
            <tbody>
              {iocs
                .sort((a, b) => {
                  const order = ['critical', 'high', 'medium', 'low', 'info']
                  return order.indexOf(a.severity) - order.indexOf(b.severity)
                })
                .map(ioc => (
                <tr key={ioc.id} className="border-t border-[#1a1a24] hover:bg-[#1a1a24]">
                  <td className="px-3 py-1">{IOC_ICONS[ioc.ioc_type] ?? '📌'}</td>
                  <td className="px-3 py-1 text-[#6a6a7a] capitalize">{ioc.ioc_type.replace('_', ' ')}</td>
                  <td className="px-3 py-1 text-[#e0e0e0] font-bold truncate max-w-[300px]" title={ioc.value}>
                    {ioc.value}
                  </td>
                  <td className="px-3 py-1 text-[#4a4a5a]">{ioc.source ?? '—'}</td>
                  <td className="px-3 py-1">
                    <span className="px-1.5 py-0.5 rounded text-[10px]" style={{ color: SEV_COLORS[ioc.severity] ?? '#6a6a7a' }}>
                      {ioc.severity.toUpperCase()}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* STIX export */}
      {iocs.length > 0 && (
        <div className="flex gap-2">
          <a
            href={`/api/tasks/${iocs[0]?.task_id}/iocs?format=stix`}
            target="_blank"
            className="text-xs px-3 py-1.5 bg-[#13131a] border border-[#2a2a3a] rounded hover:border-[#00ff9f] hover:text-[#00ff9f] transition-colors"
          >
            📦 Export STIX 2.1
          </a>
          <button
            onClick={copyAllIOCs}
            className="text-xs px-3 py-1.5 bg-[#13131a] border border-[#2a2a3a] rounded hover:border-[#00aaff] hover:text-[#00aaff] transition-colors"
          >
            📋 Copy as Text
          </button>
        </div>
      )}
    </div>
  )
}