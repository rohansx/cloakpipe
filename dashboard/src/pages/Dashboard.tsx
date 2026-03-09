import { Shield, Server, Eye, SlidersHorizontal } from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts'
import { StatCard } from '../components/StatCard'
import { useQuery } from '@powersync/react'
import { format } from 'date-fns'

const tooltipStyle = {
  background: 'var(--card)',
  border: '1px solid var(--border)',
  borderRadius: '0px',
  color: 'var(--foreground)',
  fontSize: '12px',
}

export function Dashboard() {
  const { data: instanceCount } = useQuery<{ cnt: number }>(
    `SELECT COUNT(*) as cnt FROM instances WHERE status = 'active'`
  )
  const { data: totalDetections } = useQuery<{ cnt: number }>(
    `SELECT COUNT(*) as cnt FROM detections`
  )
  const { data: totalRequests } = useQuery<{ total: number }>(
    `SELECT COALESCE(SUM(requests), 0) as total FROM usage_stats`
  )
  const { data: policyCount } = useQuery<{ cnt: number }>(
    `SELECT COUNT(*) as cnt FROM policies`
  )
  const { data: volumeData } = useQuery<{ date: string; requests: number; detections: number }>(
    `SELECT date, SUM(requests) as requests, SUM(detections) as detections FROM usage_stats GROUP BY date ORDER BY date ASC`
  )
  const { data: categoryData } = useQuery<{ category: string; count: number }>(
    `SELECT category, COUNT(*) as count FROM detections GROUP BY category ORDER BY count DESC`
  )
  const { data: recentDetections } = useQuery<{
    id: string; category: string; token: string; source: string; timestamp: string; instance_name: string
  }>(
    `SELECT d.id, d.category, d.token, d.source, d.timestamp, i.name as instance_name FROM detections d LEFT JOIN instances i ON d.instance_id = i.id ORDER BY d.timestamp DESC LIMIT 8`
  )

  const chartVolume = (volumeData || []).map(d => ({
    date: format(new Date(d.date), 'MMM d'),
    requests: d.requests,
    detections: d.detections,
  }))

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-lg font-semibold">Overview</h1>
        <p className="text-xs text-[var(--muted-foreground)] mt-0.5">Real-time privacy proxy monitoring</p>
      </div>

      <div className="grid grid-cols-4 gap-3 mb-6">
        <StatCard
          title="Total Requests"
          value={(totalRequests?.[0]?.total || 0).toLocaleString()}
          icon={Shield}
        />
        <StatCard
          title="Entities Detected"
          value={(totalDetections?.[0]?.cnt || 0).toLocaleString()}
          icon={Eye}
        />
        <StatCard
          title="Active Instances"
          value={instanceCount?.[0]?.cnt || 0}
          icon={Server}
        />
        <StatCard
          title="Active Policies"
          value={policyCount?.[0]?.cnt || 0}
          icon={SlidersHorizontal}
        />
      </div>

      <div className="grid grid-cols-3 gap-3 mb-6">
        <div className="col-span-2 bg-[var(--card)] border border-[var(--border)] p-4">
          <h2 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)] mb-3">Request & Detection Volume</h2>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={chartVolume}>
              <defs>
                <linearGradient id="colorReq" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0d9488" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#0d9488" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorDet" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#16a34a" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#16a34a" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="date" tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }} />
              <YAxis tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area type="monotone" dataKey="requests" stroke="#0d9488" fill="url(#colorReq)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="detections" stroke="#16a34a" fill="url(#colorDet)" strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-[var(--card)] border border-[var(--border)] p-4">
          <h2 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)] mb-3">By Category</h2>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={categoryData || []} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis type="number" tick={{ fill: 'var(--muted-foreground)', fontSize: 10 }} />
              <YAxis dataKey="category" type="category" tick={{ fill: 'var(--muted-foreground)', fontSize: 10 }} width={80} />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="count" fill="#0d9488" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-[var(--card)] border border-[var(--border)]">
        <div className="px-4 py-3 border-b border-[var(--border)]">
          <h2 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)]">Recent Detections</h2>
        </div>
        <table className="w-full text-[13px]">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Time</th>
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Category</th>
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Token</th>
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Instance</th>
              <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Source</th>
            </tr>
          </thead>
          <tbody>
            {(recentDetections || []).map((d) => (
              <tr key={d.id} className="border-b border-[var(--border)] hover:bg-[var(--secondary)]">
                <td className="px-4 py-2 font-mono text-xs text-[var(--muted-foreground)]">
                  {format(new Date(d.timestamp), 'HH:mm:ss')}
                </td>
                <td className="px-4 py-2">
                  <span className="px-1.5 py-0.5 bg-[var(--secondary)] text-[11px] font-mono">
                    {d.category}
                  </span>
                </td>
                <td className="px-4 py-2 font-mono text-xs text-[var(--primary)]">{d.token}</td>
                <td className="px-4 py-2 text-xs text-[var(--muted-foreground)]">{d.instance_name}</td>
                <td className="px-4 py-2 text-xs text-[var(--muted-foreground)]">{d.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
