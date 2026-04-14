import type { BehavioralEvent } from '../App'

interface Props {
  events: BehavioralEvent[]
}

interface Connection {
  timestamp: string
  pid: number
  syscall: string
  dst: string
  port: number
  protocol: string
}

export default function NetworkPanel({ events }: Props) {
  const connections = extractConnections(events)
  const dnsQueries = events.filter(e => e.syscall_name === 'getaddrinfo' || e.args?.includes('53'))

  return (
    <div className="space-y-4">
      {/* Connection summary */}
      <div className="grid grid-cols-4 gap-3">
        <StatCard label="Connections" value={connections.length} color="#ffaa00" icon="🔗" />
        <StatCard label="Unique Dests" value={new Set(connections.map(c => c.dst)).size} color="#ff6b35" icon="🎯" />
        <StatCard label="DNS Queries" value={dnsQueries.length} color="#00aaff" icon="🔍" />
        <StatCard label="Data Exfil" value={connections.filter(c => c.syscall === 'sendto').length} color="#ff3366" icon="📤" />
      </div>

      {/* Connection log */}
      <div className="bg-[#0a0a0f] rounded border border-[#2a2a3a] overflow-auto max-h-[500px]">
        {connections.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-[#4a4a5a] text-sm">No network connections observed</div>
        ) : (
          <table className="w-full text-xs font-mono">
            <thead className="sticky top-0 bg-[#13131a]">
              <tr className="text-[#6a6a7a]">
                <th className="text-left px-3 py-1.5">Time</th>
                <th className="text-left px-3 py-1.5">PID</th>
                <th className="text-left px-3 py-1.5">Syscall</th>
                <th className="text-left px-3 py-1.5">Destination</th>
                <th className="text-left px-3 py-1.5">Port</th>
                <th className="text-left px-3 py-1.5">Protocol</th>
              </tr>
            </thead>
            <tbody>
              {connections.map((conn, i) => (
                <tr key={i} className="border-t border-[#1a1a24] hover:bg-[#1a1a24]">
                  <td className="px-3 py-1 text-[#6a6a7a]">{conn.timestamp.split('T')[1]?.slice(0, 12) ?? conn.timestamp}</td>
                  <td className="px-3 py-1 text-[#00aaff]">{conn.pid}</td>
                  <td className="px-3 py-1 text-[#ffaa00]">{conn.syscall}</td>
                  <td className="px-3 py-1 text-[#ff6b35] font-bold">{conn.dst}</td>
                  <td className="px-3 py-1 text-[#e0e0e0]">{conn.port}</td>
                  <td className="px-3 py-1 text-[#6a6a7a]">{conn.protocol}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* GHOSTWIRE integration notice */}
      {connections.length > 0 && (
        <div className="bg-[#13131a] rounded border border-[#2a2a3a] p-3 text-xs text-[#6a6a7a]">
          <span className="text-[#00ff9f]">GHOSTWIRE:</span> Connect PCAP to GHOSTWIRE engine for C2 beacon detection and JA4+ fingerprinting
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, color, icon }: { label: string; value: number; color: string; icon: string }) {
  return (
    <div className="bg-[#13131a] rounded border border-[#2a2a3a] p-3 text-center">
      <div className="text-lg mb-1">{icon}</div>
      <div className="text-2xl font-bold" style={{ color }}>{value}</div>
      <div className="text-xs text-[#6a6a7a] mt-0.5">{label}</div>
    </div>
  )
}

function extractConnections(events: BehavioralEvent[]): Connection[] {
  return events
    .filter(e => e.syscall_name === 'connect' || e.syscall_name === 'sendto')
    .map(e => {
      try {
        const args = JSON.parse(e.args ?? '{}')
        return {
          timestamp: e.timestamp,
          pid: e.pid,
          syscall: e.syscall_name,
          dst: args.addr ?? args.ip ?? args.dest ?? 'unknown',
          port: args.port ?? 0,
          protocol: args.protocol ?? 'tcp',
        }
      } catch {
        return {
          timestamp: e.timestamp,
          pid: e.pid,
          syscall: e.syscall_name,
          dst: 'parse_error',
          port: 0,
          protocol: 'unknown',
        }
      }
    })
}