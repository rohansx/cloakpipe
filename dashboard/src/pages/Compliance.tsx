import { FileCheck, Download } from 'lucide-react'
import { useQuery } from '@powersync/react'
import { usePowerSync } from '@powersync/react'
import { format } from 'date-fns'

export function Compliance() {
  const db = usePowerSync()

  const { data: auditLog } = useQuery<{
    id: string; action: string; resource_type: string; resource_id: string; timestamp: string
  }>(`SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 50`)

  const { data: detectionSummary } = useQuery<{ category: string; count: number }>(
    `SELECT category, COUNT(*) as count FROM detections GROUP BY category ORDER BY count DESC`
  )

  const { data: totalStats } = useQuery<{ total_detections: number; total_requests: number }>(
    `SELECT
      (SELECT COUNT(*) FROM detections) as total_detections,
      (SELECT COALESCE(SUM(requests), 0) FROM usage_stats) as total_requests`
  )

  const { data: instanceStats } = useQuery<{ total: number; active: number }>(
    `SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active
    FROM instances`
  )

  async function exportCSV() {
    const rows = await db.getAll<{
      id: string; action: string; resource_type: string; resource_id: string; timestamp: string
    }>('SELECT * FROM audit_log ORDER BY timestamp DESC')

    const csv = [
      'id,action,resource_type,resource_id,timestamp',
      ...rows.map(r => `${r.id},${r.action},${r.resource_type},${r.resource_id || ''},${r.timestamp}`)
    ].join('\n')

    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `cloakpipe-audit-${format(new Date(), 'yyyy-MM-dd')}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  async function exportJSON() {
    const rows = await db.getAll('SELECT * FROM audit_log ORDER BY timestamp DESC')
    const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `cloakpipe-audit-${format(new Date(), 'yyyy-MM-dd')}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const stats = totalStats?.[0]
  const instStats = instanceStats?.[0]

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-lg font-semibold">Compliance</h1>
          <p className="text-xs text-[var(--muted-foreground)] mt-0.5">Audit trail, reports, and compliance exports</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={exportCSV} className="flex items-center gap-1.5 px-3 py-1.5 border border-[var(--border)] text-xs text-[var(--muted-foreground)] hover:text-[var(--foreground)]">
            <Download className="w-3 h-3" />
            Export CSV
          </button>
          <button onClick={exportJSON} className="flex items-center gap-1.5 px-3 py-1.5 border border-[var(--border)] text-xs text-[var(--muted-foreground)] hover:text-[var(--foreground)]">
            <Download className="w-3 h-3" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Compliance summary cards */}
      <div className="grid grid-cols-3 gap-3 mb-6">
        <div className="bg-[var(--card)] border border-[var(--border)] p-4">
          <h3 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)] mb-2">SOC2 Summary</h3>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-[var(--muted-foreground)]">Total entities anonymized</span>
              <span className="font-mono tabular-nums">{(stats?.total_detections || 0).toLocaleString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--muted-foreground)]">Total requests intercepted</span>
              <span className="font-mono tabular-nums">{(stats?.total_requests || 0).toLocaleString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--muted-foreground)]">Data leaked to LLM providers</span>
              <span className="font-mono tabular-nums text-[var(--success)]">0</span>
            </div>
          </div>
        </div>

        <div className="bg-[var(--card)] border border-[var(--border)] p-4">
          <h3 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)] mb-2">Infrastructure</h3>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-[var(--muted-foreground)]">Instances registered</span>
              <span className="font-mono tabular-nums">{instStats?.total || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--muted-foreground)]">Instances active</span>
              <span className="font-mono tabular-nums text-[var(--success)]">{instStats?.active || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--muted-foreground)]">Encryption</span>
              <span className="font-mono tabular-nums">AES-256-GCM</span>
            </div>
          </div>
        </div>

        <div className="bg-[var(--card)] border border-[var(--border)] p-4">
          <h3 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)] mb-2">Detection Breakdown</h3>
          <div className="space-y-1.5 text-xs">
            {(detectionSummary || []).slice(0, 5).map(d => (
              <div key={d.category} className="flex justify-between">
                <span className="text-[var(--muted-foreground)]">{d.category}</span>
                <span className="font-mono tabular-nums">{d.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Audit log */}
      <div className="bg-[var(--card)] border border-[var(--border)]">
        <div className="px-4 py-3 border-b border-[var(--border)] flex items-center gap-2">
          <FileCheck className="w-3.5 h-3.5 text-[var(--muted-foreground)]" />
          <h2 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)]">Audit Log</h2>
        </div>
        <table className="w-full text-[13px]">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Timestamp</th>
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Action</th>
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Resource</th>
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Resource ID</th>
            </tr>
          </thead>
          <tbody>
            {(auditLog || []).map((entry, i) => (
              <tr key={entry.id} className={`border-b border-[var(--border)] ${i % 2 === 0 ? '' : 'bg-[#0e0e10]'}`}>
                <td className="px-4 py-2 font-mono text-xs text-[var(--muted-foreground)]">
                  {format(new Date(entry.timestamp), 'MMM d, HH:mm:ss')}
                </td>
                <td className="px-4 py-2 text-xs">{entry.action}</td>
                <td className="px-4 py-2 text-xs text-[var(--muted-foreground)] font-mono">{entry.resource_type}</td>
                <td className="px-4 py-2 text-xs text-[var(--muted-foreground)] font-mono">{entry.resource_id || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
