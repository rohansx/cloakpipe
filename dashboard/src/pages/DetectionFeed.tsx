import { Eye } from 'lucide-react'
import { useQuery } from '@powersync/react'
import { format } from 'date-fns'
import { useState } from 'react'

const categoryColors: Record<string, string> = {
  Email: 'text-teal-400 bg-teal-400/10',
  Amount: 'text-green-400 bg-green-400/10',
  Secret: 'text-red-400 bg-red-400/10',
  Person: 'text-cyan-400 bg-cyan-400/10',
  Organization: 'text-purple-400 bg-purple-400/10',
  Date: 'text-amber-400 bg-amber-400/10',
  Phone: 'text-teal-400 bg-teal-400/10',
  IP: 'text-orange-400 bg-orange-400/10',
}

export function DetectionFeed() {
  const [categoryFilter, setCategoryFilter] = useState<string>('all')

  const { data: categories } = useQuery<{ category: string }>(
    `SELECT DISTINCT category FROM detections ORDER BY category ASC`
  )

  const { data: detections } = useQuery<{
    id: string; category: string; token: string; source: string; timestamp: string; instance_name: string
  }>(
    categoryFilter === 'all'
      ? `SELECT d.id, d.category, d.token, d.source, d.timestamp, i.name as instance_name FROM detections d LEFT JOIN instances i ON d.instance_id = i.id ORDER BY d.timestamp DESC LIMIT 100`
      : `SELECT d.id, d.category, d.token, d.source, d.timestamp, i.name as instance_name FROM detections d LEFT JOIN instances i ON d.instance_id = i.id WHERE d.category = '${categoryFilter}' ORDER BY d.timestamp DESC LIMIT 100`
  )

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-lg font-semibold">Detection Feed</h1>
          <p className="text-xs text-[var(--muted-foreground)] mt-0.5">Real-time entity detection log across all instances</p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-2 py-1 bg-[var(--secondary)] border border-[var(--border)] text-xs text-[var(--foreground)] font-mono"
          >
            <option value="all">All Categories</option>
            {(categories || []).map(c => (
              <option key={c.category} value={c.category}>{c.category}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="mb-4 px-3 py-2 bg-[var(--secondary)] border border-[var(--border)]">
        <div className="flex items-center gap-2 text-xs">
          <Eye className="w-3.5 h-3.5 text-[var(--primary)]" />
          <span className="text-[var(--muted-foreground)]">
            Original values are never stored or displayed. Only metadata and tokens are shown.
          </span>
        </div>
      </div>

      <div className="bg-[var(--card)] border border-[var(--border)]">
        <table className="w-full text-[13px]">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Timestamp</th>
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Category</th>
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Token</th>
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Instance</th>
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Source</th>
            </tr>
          </thead>
          <tbody>
            {(detections || []).map((d, i) => (
              <tr key={d.id} className={`border-b border-[var(--border)] hover:bg-[var(--secondary)] ${i % 2 === 0 ? '' : 'bg-[#0e0e10]'}`}>
                <td className="px-4 py-2 font-mono text-xs text-[var(--muted-foreground)]">
                  {format(new Date(d.timestamp), 'MMM d, HH:mm:ss')}
                </td>
                <td className="px-4 py-2">
                  <span className={`px-1.5 py-0.5 text-[11px] font-mono ${categoryColors[d.category] || 'text-gray-400 bg-gray-400/10'}`}>
                    {d.category}
                  </span>
                </td>
                <td className="px-4 py-2 font-mono text-xs text-[var(--primary)]">{d.token}</td>
                <td className="px-4 py-2 text-xs text-[var(--muted-foreground)]">{d.instance_name}</td>
                <td className="px-4 py-2 text-xs text-[var(--muted-foreground)] font-mono">{d.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
