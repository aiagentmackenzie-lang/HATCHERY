import type { BehavioralEvent } from '../App'

interface Props {
  events: BehavioralEvent[]
}

const FILE_SYSCALLS = ['open', 'openat', 'read', 'write', 'unlink', 'rename', 'chmod', 'mkdir', 'creat', 'mknod']

export default function FileSystemView({ events }: Props) {
  // Group events by file path (extracted from args)
  const fileMap = new Map<string, { reads: number; writes: number; deletes: number; creates: number; other: number; severity: string }>()

  for (const ev of events) {
    let path = 'unknown'
    try {
      const args = JSON.parse(ev.args ?? '{}')
      path = args.path ?? args.pathname ?? args.filename ?? args.dirfd ?? 'unknown'
      if (path === 'unknown' && ev.raw_line) {
        // Try extracting from raw strace line
        const match = ev.raw_line.match(/"([^"]+)"/)
        if (match) path = match[1]
      }
    } catch { /* use unknown */ }

    if (!fileMap.has(path)) {
      fileMap.set(path, { reads: 0, writes: 0, deletes: 0, creates: 0, other: 0, severity: 'info' })
    }
    const entry = fileMap.get(path)!

    if (ev.syscall_name === 'read') entry.reads++
    else if (['write', 'creat'].includes(ev.syscall_name)) entry.writes++
    else if (['unlink', 'rename'].includes(ev.syscall_name)) entry.deletes++
    else if (['mkdir', 'openat', 'open'].includes(ev.syscall_name)) entry.creates++
    else entry.other++

    // Upgrade severity
    const sevOrder = ['info', 'low', 'medium', 'high', 'critical']
    if (sevOrder.indexOf(ev.severity) > sevOrder.indexOf(entry.severity)) {
      entry.severity = ev.severity
    }
  }

  const files = Array.from(fileMap.entries()).sort((a, b) => {
    const sevOrder = ['critical', 'high', 'medium', 'low', 'info']
    return sevOrder.indexOf(a[1].severity) - sevOrder.indexOf(b[1].severity)
  })

  const suspiciousPaths = files.filter(([path]) =>
    path.startsWith('/tmp') ||
    path.startsWith('/dev/shm') ||
    path.includes('.bashrc') ||
    path.includes('.ssh') ||
    path.startsWith('.')
  )

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-4 gap-3">
        <StatBox label="Files Accessed" value={files.length} color="#ff6b35" />
        <StatBox label="Files Written" value={files.filter(([, e]) => e.writes > 0).length} color="#ffaa00" />
        <StatBox label="Files Deleted" value={files.filter(([, e]) => e.deletes > 0).length} color="#ff3366" />
        <StatBox label="Suspicious" value={suspiciousPaths.length} color="#ff3366" />
      </div>

      {/* Suspicious paths alert */}
      {suspiciousPaths.length > 0 && (
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/30 rounded p-3">
          <h4 className="text-xs font-bold text-[#ff3366] mb-2">⚠ Suspicious File Activity</h4>
          {suspiciousPaths.map(([path, entry]) => (
            <div key={path} className="text-xs font-mono text-[#e0e0e0] mb-1">
              <span className="text-[#ff3366]">●</span> {path}
              <span className="text-[#6a6a7a] ml-2">
                {entry.writes > 0 && `✏️${entry.writes}`} {entry.deletes > 0 && `🗑️${entry.deletes}`}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Full file table */}
      <div className="bg-[#0a0a0f] rounded border border-[#2a2a3a] overflow-auto max-h-[400px]">
        <table className="w-full text-xs font-mono">
          <thead className="sticky top-0 bg-[#13131a]">
            <tr className="text-[#6a6a7a]">
              <th className="text-left px-3 py-1.5">Path</th>
              <th className="text-center px-3 py-1.5">R</th>
              <th className="text-center px-3 py-1.5">W</th>
              <th className="text-center px-3 py-1.5">D</th>
              <th className="text-center px-3 py-1.5">C</th>
              <th className="text-left px-3 py-1.5">Severity</th>
            </tr>
          </thead>
          <tbody>
            {files.map(([path, entry]) => (
              <tr key={path} className="border-t border-[#1a1a24] hover:bg-[#1a1a24]">
                <td className="px-3 py-1 text-[#e0e0e0] truncate max-w-[400px]" title={path}>{path}</td>
                <td className="px-3 py-1 text-center text-[#6a6a7a]">{entry.reads || '—'}</td>
                <td className="px-3 py-1 text-center text-[#ffaa00]">{entry.writes || '—'}</td>
                <td className="px-3 py-1 text-center text-[#ff3366]">{entry.deletes || '—'}</td>
                <td className="px-3 py-1 text-center text-[#00ff9f]">{entry.creates || '—'}</td>
                <td className="px-3 py-1">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] border ${
                    entry.severity === 'high' || entry.severity === 'critical'
                      ? 'bg-[#ff3366]/20 border-[#ff3366] text-[#ff3366]'
                      : entry.severity === 'medium'
                        ? 'bg-[#ffaa00]/20 border-[#ffaa00] text-[#ffaa00]'
                        : 'bg-[#13131a] border-[#2a2a3a] text-[#6a6a7a]'
                  }`}>
                    {entry.severity}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function StatBox({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-[#13131a] rounded border border-[#2a2a3a] p-2.5 text-center">
      <div className="text-xl font-bold" style={{ color }}>{value}</div>
      <div className="text-[10px] text-[#6a6a7a] mt-0.5">{label}</div>
    </div>
  )
}