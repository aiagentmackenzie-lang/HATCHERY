import { useState, useCallback } from 'react'
import type { TaskInfo } from '../App'

interface Props {
  onSubmitted: (task: TaskInfo) => void
  apiBase: string
}

export default function SampleUpload({ onSubmitted, apiBase }: Props) {
  const [filePath, setFilePath] = useState('')
  const [timeout, setTimeout_] = useState(120)
  const [noSandbox, setNoSandbox] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)

  const submit = useCallback(async () => {
    if (!filePath.trim()) return
    setLoading(true)
    setError(null)

    try {
      const res = await fetch(`${apiBase}/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filePath: filePath.trim(), timeout, noSandbox }),
      })
      const data = await res.json()

      if (!res.ok) {
        setError(data.error ?? 'Submission failed')
        return
      }

      onSubmitted({
        task_id: data.task_id,
        file_name: data.file_name,
        file_size: data.file_size,
        md5: null,
        sha256: null,
        status: 'running',
        static_done: 0,
        sandbox_done: 0,
        created_at: new Date().toISOString(),
        completed_at: null,
        error_message: null,
      })

      setFilePath('')
    } catch (e: any) {
      setError('Failed to connect to HATCHERY API')
    } finally {
      setLoading(false)
    }
  }, [filePath, timeout, noSandbox, apiBase, onSubmitted])

  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-[#ff6b35] uppercase tracking-wider">Submit Sample</h2>

      {/* Drop zone */}
      <div
        onDragOver={e => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={e => {
          e.preventDefault()
          setDragOver(false)
          const file = e.dataTransfer.files[0]
          if (file) setFilePath(file.name)
        }}
        className={`border-2 border-dashed rounded-lg p-4 text-center transition-colors ${
          dragOver ? 'border-[#ff6b35] bg-[#ff6b35]/5' : 'border-[#2a2a3a] hover:border-[#4a4a5a]'
        }`}
      >
        <div className="text-2xl mb-1">📥</div>
        <p className="text-xs text-[#6a6a7a]">Drop file or enter path below</p>
      </div>

      {/* File path input */}
      <input
        type="text"
        value={filePath}
        onChange={e => setFilePath(e.target.value)}
        onKeyDown={e => e.key === 'Enter' && submit()}
        placeholder="/path/to/sample.exe"
        className="w-full bg-[#0a0a0f] border border-[#2a2a3a] rounded px-3 py-2 text-sm text-[#e0e0e0] placeholder-[#4a4a5a] focus:border-[#ff6b35] focus:outline-none"
      />

      {/* Options */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5">
          <label className="text-xs text-[#6a6a7a]">Timeout</label>
          <input
            type="number"
            value={timeout}
            onChange={e => setTimeout_(Number(e.target.value))}
            min={10}
            max={600}
            className="w-16 bg-[#0a0a0f] border border-[#2a2a3a] rounded px-2 py-1 text-xs text-[#e0e0e0] focus:border-[#ff6b35] focus:outline-none"
          />
          <span className="text-xs text-[#4a4a5a]">s</span>
        </div>
        <label className="flex items-center gap-1.5 text-xs text-[#6a6a7a] cursor-pointer">
          <input
            type="checkbox"
            checked={noSandbox}
            onChange={e => setNoSandbox(e.target.checked)}
            className="accent-[#ff6b35]"
          />
          Static only
        </label>
      </div>

      {/* Submit button */}
      <button
        onClick={submit}
        disabled={loading || !filePath.trim()}
        className="w-full bg-[#ff6b35] hover:bg-[#ff8855] disabled:bg-[#4a4a5a] disabled:cursor-not-allowed text-white font-bold py-2 rounded transition-colors text-sm"
      >
        {loading ? '⏳ Submitting...' : '🔥 DETONATE'}
      </button>

      {error && (
        <p className="text-[#ff3366] text-xs">{error}</p>
      )}
    </div>
  )
}