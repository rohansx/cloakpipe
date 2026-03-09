import { SlidersHorizontal, Plus, Check } from 'lucide-react'
import { useQuery } from '@powersync/react'

const profileColors: Record<string, string> = {
  general: 'text-teal-400 border-teal-400/30',
  legal: 'text-purple-400 border-purple-400/30',
  healthcare: 'text-green-400 border-green-400/30',
  fintech: 'text-amber-400 border-amber-400/30',
}

const allCategories = [
  { key: 'secrets', label: 'Secrets' },
  { key: 'financial', label: 'Financial' },
  { key: 'dates', label: 'Dates' },
  { key: 'emails', label: 'Emails' },
  { key: 'phone_numbers', label: 'Phone Numbers' },
  { key: 'ip_addresses', label: 'IP Addresses' },
  { key: 'urls_internal', label: 'Internal URLs' },
  { key: 'ner', label: 'NER (Names, Orgs)' },
]

export function Policies() {
  const { data: policies } = useQuery<{
    id: string; name: string; profile: string; categories: string; alert_rules: string; is_default: number; created_at: string
  }>(`SELECT * FROM policies ORDER BY is_default DESC, created_at ASC`)

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-lg font-semibold">Policies</h1>
          <p className="text-xs text-[var(--muted-foreground)] mt-0.5">Detection policies applied to proxy instances</p>
        </div>
        <button className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--primary)] text-white text-[13px] font-medium hover:opacity-90">
          <Plus className="w-3.5 h-3.5" />
          Create Policy
        </button>
      </div>

      <div className="space-y-3">
        {(policies || []).map((policy) => {
          const enabledCategories: string[] = JSON.parse(policy.categories || '[]')
          return (
            <div key={policy.id} className="bg-[var(--card)] border border-[var(--border)] p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <SlidersHorizontal className="w-3.5 h-3.5 text-[var(--muted-foreground)]" />
                  <span className="font-medium text-[13px]">{policy.name}</span>
                  <span className={`px-1.5 py-0.5 border text-[10px] font-mono uppercase ${profileColors[policy.profile] || 'text-gray-400 border-gray-400/30'}`}>
                    {policy.profile}
                  </span>
                  {policy.is_default === 1 && (
                    <span className="px-1.5 py-0.5 bg-[var(--primary)] text-white text-[10px] font-medium uppercase">
                      Default
                    </span>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-4 gap-2">
                {allCategories.map((cat) => {
                  const enabled = enabledCategories.includes(cat.key)
                  return (
                    <div
                      key={cat.key}
                      className={`flex items-center gap-2 px-2 py-1.5 text-xs border ${
                        enabled
                          ? 'border-[var(--primary)]/30 text-[var(--foreground)] bg-[var(--primary)]/5'
                          : 'border-[var(--border)] text-[var(--muted-foreground)]'
                      }`}
                    >
                      {enabled && <Check className="w-3 h-3 text-[var(--primary)]" />}
                      <span>{cat.label}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
