import { useEffect, useRef } from 'react'
import type { BehavioralEvent } from '../App'
import * as d3 from 'd3'

interface Props {
  events: BehavioralEvent[]
}

interface TreeNode {
  pid: number
  children: TreeNode[]
  syscalls: { name: string; count: number }[]
  totalEvents: number
}

export default function ProcessTree({ events }: Props) {
  const svgRef = useRef<SVGSVGElement>(null)

  useEffect(() => {
    if (!svgRef.current || events.length === 0) return

    const processEvents = events.filter(e => e.category === 'process' || e.category === 'system')
    const tree = buildTree(processEvents)
    renderTree(svgRef.current, tree)

  }, [events])

  if (events.length === 0) {
    return <div className="flex items-center justify-center h-64 text-[#4a4a5a]">No process events yet</div>
  }

  return (
    <div>
      <h3 className="text-sm text-[#6a6a7a] mb-3">Process Tree — parent→child relationships</h3>
      <svg ref={svgRef} className="w-full bg-[#0a0a0f] rounded border border-[#2a2a3a]" style={{ minHeight: 300 }} />
    </div>
  )
}

function buildTree(events: BehavioralEvent[]): TreeNode {
  const procs = new Map<number, TreeNode>()
  const parentChild = new Map<number, number[]>() // parentPid -> [childPids...]
  let rootPid = 0

  for (const ev of events) {
    if (!procs.has(ev.pid)) {
      procs.set(ev.pid, { pid: ev.pid, children: [], syscalls: [], totalEvents: 0 })
    }
    const node = procs.get(ev.pid)!
    node.totalEvents++

    // Track syscall counts
    const existing = node.syscalls.find(s => s.name === ev.syscall_name)
    if (existing) existing.count++
    else node.syscalls.push({ name: ev.syscall_name, count: 1 })

    if (rootPid === 0) rootPid = ev.pid

    // Detect child processes from clone/fork
    if (ev.syscall_name === 'clone' || ev.syscall_name === 'fork' || ev.syscall_name === 'vfork') {
      try {
        const args = JSON.parse(ev.args ?? '{}')
        const childPid = args.child_pid ?? args.pid
        if (childPid && childPid !== ev.pid) {
          if (!parentChild.has(ev.pid)) parentChild.set(ev.pid, [])
          parentChild.get(ev.pid)!.push(childPid)
        }
      } catch { /* ignore */ }
    }
  }

  // Wire up children
  for (const [parentPid, childPids] of parentChild) {
    const parent = procs.get(parentPid)
    if (!parent) continue
    for (const cpid of childPids) {
      const child = procs.get(cpid)
      if (child) parent.children.push(child)
    }
  }

  return procs.get(rootPid) ?? { pid: 0, children: [], syscalls: [], totalEvents: 0 }
}

function renderTree(svg: SVGSVGElement, root: TreeNode) {
  d3.select(svg).selectAll('*').remove()

  const width = 900
  const marginTop = 30
  const marginHorizontal = 40

  // Create d3 hierarchy
  const hierarchy = d3.hierarchy(root, d => d.children)
  const treeLayout = d3.tree<TreeNode>().size([width - marginHorizontal * 2, 250])
  treeLayout(hierarchy)

  const svgEl = d3.select(svg)
    .attr('width', width)
    .attr('height', 320)

  const g = svgEl.append('g')
    .attr('transform', `translate(${marginHorizontal}, ${marginTop})`)

  // Links
  g.selectAll('.link')
    .data(hierarchy.links())
    .join('path')
    .attr('class', 'link')
    .attr('fill', 'none')
    .attr('stroke', '#2a2a3a')
    .attr('stroke-width', 1.5)
    .attr('d', d3.linkVertical()
      .x((d: any) => d.x)
      .y((d: any) => d.y) as any)

  // Nodes
  const nodes = g.selectAll('.node')
    .data(hierarchy.descendants())
    .join('g')
    .attr('class', 'node')
    .attr('transform', d => `translate(${d.x}, ${d.y})`)

  // Node circle — size based on event count
  nodes.append('circle')
    .attr('r', d => Math.max(8, Math.min(20, Math.sqrt(d.data.totalEvents) * 3)))
    .attr('fill', d => {
      // Color by threat: more syscalls = more suspicious
      const count = d.data.totalEvents
      if (count > 50) return '#ff3366'
      if (count > 20) return '#ff6b35'
      if (count > 5) return '#ffaa00'
      return '#00ff9f'
    })
    .attr('stroke', '#0a0a0f')
    .attr('stroke-width', 2)
    .attr('opacity', 0.85)

  // PID label
  nodes.append('text')
    .attr('dy', '0.35em')
    .attr('text-anchor', 'middle')
    .attr('fill', '#0a0a0f')
    .attr('font-size', '9px')
    .attr('font-weight', 'bold')
    .text(d => d.data.pid)

  // Label below
  nodes.append('text')
    .attr('dy', '2.2em')
    .attr('text-anchor', 'middle')
    .attr('fill', '#6a6a7a')
    .attr('font-size', '9px')
    .text(d => `PID ${d.data.pid} (${d.data.totalEvents})`)
}