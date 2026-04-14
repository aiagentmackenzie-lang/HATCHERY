import { useState, useCallback, useRef, useEffect } from 'react'
import SampleUpload from './components/SampleUpload'
import Timeline from './components/Timeline'
import ProcessTree from './components/ProcessTree'
import NetworkPanel from './components/NetworkPanel'
import FileSystemView from './components/FileSystemView'
import IOCPanel from './components/IOCPanel'
import YARAResults from './components/YARAResults'
import LiveIndicator from './components/LiveIndicator'

export interface TaskInfo {
  task_id: string
  file_name: string
  file_size: number
  md5: string | null
  sha256: string | null
  status: string
  static_done: number
  sandbox_done: number
  created_at: string
  completed_at: string | null
  error_message: string | null
}

export interface BehavioralEvent {
  id: number
  task_id: string
  timestamp: string
  pid: number
  syscall_name: string
  category: 'file' | 'network' | 'process' | 'memory' | 'system' | 'unknown'
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  args: string
  return_value: string
  raw_line: string
}

export interface IOCEntry {
  id: number
  task_id: string
  ioc_type: string
  value: string
  severity: string
  context: string | null
  source: string | null
}

export interface StaticResults {
  hashes_json: string | null
  strings_json: string | null
  pe_json: string | null
  elf_json: string | null
  yara_json: string | null
  capa_json: string | null
  packer_json: string | null
  ioc_json: string | null
  mitre_json: string | null
}

const API_BASE = '/api';

function App() {
  const [activeTask, setActiveTask] = useState<TaskInfo | null>(null)
  const [events, setEvents] = useState<BehavioralEvent[]>([])
  const [iocs, setIocs] = useState<IOCEntry[]>([])
  const [staticResults, setStaticResults] = useState<StaticResults | null>(null)
  const [isLive, setIsLive] = useState(false)
  const [activeTab, setActiveTab] = useState<'timeline' | 'process' | 'network' | 'files' | 'iocs' | 'yara'>('timeline')
  const wsRef = useRef<WebSocket | null>(null)

  // Connect to WebSocket for real-time events
  const connectWS = useCallback((taskId: string) => {
    if (wsRef.current) wsRef.current.close()

    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`)
    wsRef.current = ws

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'subscribe', task_id: taskId }))
      setIsLive(true)
    }

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.type === 'event') {
          setEvents(prev => [...prev, msg.event])
        } else if (msg.type === 'events_batch') {
          setEvents(msg.events)
        } else if (msg.type === 'ioc') {
          setIocs(prev => [...prev, msg.ioc])
        }
      } catch { /* ignore */ }
    }

    ws.onclose = () => setIsLive(false)
    ws.onerror = () => setIsLive(false)
  }, [])

  // Load task details when activeTask changes
  useEffect(() => {
    if (!activeTask) return

    const loadTaskData = async () => {
      try {
        // Fetch events
        const evRes = await fetch(`${API_BASE}/tasks/${activeTask.task_id}/events?limit=500`)
        if (evRes.ok) {
          const evData = await evRes.json()
          setEvents(evData.events ?? [])
        }

        // Fetch IOCs
        const iocRes = await fetch(`${API_BASE}/tasks/${activeTask.task_id}/iocs`)
        if (iocRes.ok) {
          const iocData = await iocRes.json()
          setIocs(iocData.iocs ?? [])
        }

        // Fetch full task data (includes static results)
        const taskRes = await fetch(`${API_BASE}/tasks/${activeTask.task_id}`)
        if (taskRes.ok) {
          const taskData = await taskRes.json()
          setStaticResults(taskData.static_results ?? null)
        }

        // Connect to WS for live events if task is running
        if (activeTask.status === 'running') {
          connectWS(activeTask.task_id)
        }
      } catch (e) {
        console.error('Failed to load task data:', e)
      }
    }

    loadTaskData()

    return () => {
      if (wsRef.current) wsRef.current.close()
    }
  }, [activeTask?.task_id])

  const handleTaskSubmitted = useCallback((task: TaskInfo) => {
    setActiveTask(task)
    setEvents([])
    setIocs([])
    setStaticResults(null)
    setActiveTab('timeline')
  }, [])

  const categoryColor = (cat: string) => {
    switch (cat) {
      case 'process': return 'text-[#ff3366]'
      case 'network': return 'text-[#ffaa00]'
      case 'file': return 'text-[#ff6b35]'
      case 'memory': return 'text-[#00ff9f]'
      case 'system': return 'text-[#00aaff]'
      default: return 'text-[#6a6a7a]'
    }
  }

  const severityBg = (sev: string) => {
    switch (sev) {
      case 'critical': return 'bg-[#ff3366]/20 border-[#ff3366]'
      case 'high': return 'bg-[#ff6b35]/20 border-[#ff6b35]'
      case 'medium': return 'bg-[#ffaa00]/20 border-[#ffaa00]'
      case 'low': return 'bg-[#00aaff]/20 border-[#00aaff]'
      default: return 'bg-[#13131a] border-[#2a2a3a]'
    }
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f]">
      {/* Header */}
      <header className="border-b border-[#2a2a3a] px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold">
            <span className="text-[#ff6b35]">HATCHERY</span>
            <span className="text-[#6a6a7a] text-sm ml-2">Malware Sandbox</span>
          </h1>
          {activeTask && <LiveIndicator isLive={isLive} />}
        </div>
        {activeTask && (
          <div className="flex items-center gap-4 text-sm">
            <span className="text-[#6a6a7a]">Task:</span>
            <span className="text-[#00aaff] font-mono">{activeTask.task_id}</span>
            <span className="text-[#6a6a7a]">|</span>
            <span className="text-[#e0e0e0]">{activeTask.file_name}</span>
            <span className={`px-2 py-0.5 rounded text-xs font-bold ${
              activeTask.status === 'completed' ? 'bg-[#00ff9f]/20 text-[#00ff9f]' :
              activeTask.status === 'running' ? 'bg-[#ff6b35]/20 text-[#ff6b35]' :
              activeTask.status === 'failed' ? 'bg-[#ff3366]/20 text-[#ff3366]' :
              'bg-[#13131a] text-[#6a6a7a]'
            }`}>
              {activeTask.status.toUpperCase()}
            </span>
          </div>
        )}
      </header>

      {/* Main content */}
      <div className="flex h-[calc(100vh-57px)]">
        {/* Left sidebar — Upload + Task list */}
        <aside className="w-80 border-r border-[#2a2a3a] bg-[#13131a] flex flex-col overflow-hidden">
          <div className="p-4">
            <SampleUpload onSubmitted={handleTaskSubmitted} apiBase={API_BASE} />
          </div>
          <TaskList activeTaskId={activeTask?.task_id} onSelect={setActiveTask} apiBase={API_BASE} />
        </aside>

        {/* Right — Main analysis view */}
        <main className="flex-1 flex flex-col overflow-hidden">
          {activeTask ? (
            <>
              {/* Tab bar */}
              <nav className="flex border-b border-[#2a2a3a] bg-[#13131a]">
                {(['timeline', 'process', 'network', 'files', 'iocs', 'yara'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-5 py-2.5 text-sm font-medium transition-colors border-b-2 ${
                      activeTab === tab
                        ? 'text-[#ff6b35] border-[#ff6b35]'
                        : 'text-[#6a6a7a] border-transparent hover:text-[#e0e0e0]'
                    }`}
                  >
                    {tab === 'timeline' && '🔴 Timeline'}
                    {tab === 'process' && '🌳 Process Tree'}
                    {tab === 'network' && '🌐 Network'}
                    {tab === 'files' && '📁 Filesystem'}
                    {tab === 'iocs' && '🎯 IOCs'}
                    {tab === 'yara' && '🔍 YARA / capa'}
                  </button>
                ))}
              </nav>

              {/* Tab content */}
              <div className="flex-1 overflow-auto p-4">
                {activeTab === 'timeline' && (
                  <Timeline events={events} categoryColor={categoryColor} severityBg={severityBg} />
                )}
                {activeTab === 'process' && (
                  <ProcessTree events={events} />
                )}
                {activeTab === 'network' && (
                  <NetworkPanel events={events.filter(e => e.category === 'network')} />
                )}
                {activeTab === 'files' && (
                  <FileSystemView events={events.filter(e => e.category === 'file')} />
                )}
                {activeTab === 'iocs' && (
                  <IOCPanel iocs={iocs} />
                )}
                {activeTab === 'yara' && (
                  <YARAResults staticResults={staticResults} />
                )}
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center">
                <div className="text-6xl mb-4">🔥</div>
                <p className="text-[#6a6a7a] text-lg">Submit a sample to begin analysis</p>
                <p className="text-[#4a4a5a] text-sm mt-2">Watch it hatch. Watch it burn.</p>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}

// Task list sidebar component
function TaskList({ activeTaskId, onSelect, apiBase }: {
  activeTaskId?: string
  onSelect: (t: TaskInfo) => void
  apiBase: string
}) {
  const [tasks, setTasks] = useState<TaskInfo[]>([])

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${apiBase}/tasks`)
        if (res.ok) {
          const data = await res.json()
          setTasks(data.tasks ?? [])
        }
      } catch { /* ignore */ }
    }
    load()
    const interval = setInterval(load, 5000)
    return () => clearInterval(interval)
  }, [apiBase])

  return (
    <div className="flex-1 overflow-auto px-2">
      <h3 className="text-xs text-[#6a6a7a] uppercase tracking-wider px-2 py-2">Recent Analyses</h3>
      {tasks.length === 0 && (
        <p className="text-[#4a4a5a] text-sm px-2">No analyses yet</p>
      )}
      {tasks.map(task => (
        <button
          key={task.task_id}
          onClick={() => onSelect(task)}
          className={`w-full text-left px-3 py-2 rounded mb-1 transition-colors ${
            activeTaskId === task.task_id
              ? 'bg-[#ff6b35]/10 border border-[#ff6b35]/30'
              : 'hover:bg-[#1a1a24] border border-transparent'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-sm text-[#e0e0e0] truncate">{task.file_name}</span>
            <span className={`text-xs px-1.5 py-0.5 rounded ${
              task.status === 'completed' ? 'bg-[#00ff9f]/10 text-[#00ff9f]' :
              task.status === 'running' ? 'bg-[#ff6b35]/10 text-[#ff6b35]' :
              task.status === 'failed' ? 'bg-[#ff3366]/10 text-[#ff3366]' :
              'text-[#6a6a7a]'
            }`}>
              {task.status}
            </span>
          </div>
          <div className="text-xs text-[#4a4a5a] mt-0.5 font-mono">{task.task_id}</div>
        </button>
      ))}
    </div>
  )
}

export default App