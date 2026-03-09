import type { LucideIcon } from 'lucide-react'

interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon: LucideIcon
  trend?: { value: number; label: string }
}

export function StatCard({ title, value, subtitle, icon: Icon, trend }: StatCardProps) {
  return (
    <div className="bg-[var(--card)] border border-[var(--border)] border-l-2 border-l-[var(--primary)] p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)]">{title}</span>
        <Icon className="w-3.5 h-3.5 text-[var(--muted-foreground)]" />
      </div>
      <div className="text-2xl font-semibold font-mono tabular-nums">{value}</div>
      {subtitle && (
        <p className="text-xs text-[var(--muted-foreground)] mt-1">{subtitle}</p>
      )}
      {trend && (
        <p className={`text-xs mt-1.5 font-mono ${trend.value >= 0 ? 'text-[var(--success)]' : 'text-[var(--destructive)]'}`}>
          {trend.value >= 0 ? '+' : ''}{trend.value}% {trend.label}
        </p>
      )}
    </div>
  )
}
