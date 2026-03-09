import { Server, Plus, Circle } from 'lucide-react'
import { useQuery } from '@powersync/react'
import { format } from 'date-fns'

const profileColors: Record<string, string> = {
  general: 'text-teal-400 border-teal-400/30',
  legal: 'text-purple-400 border-purple-400/30',
  healthcare: 'text-green-400 border-green-400/30',
  fintech: 'text-amber-400 border-amber-400/30',
}

const statusColors: Record<string, string> = {
  active: 'text-[var(--success)]',
  degraded: 'text-[var(--warning)]',
  offline: 'text-[var(--destructive)]',
}

export function Instances() {
  const { data: instances } = useQuery<{
    id: string; name: string; hostname: string; upstream: string; profile: string;
    listen_addr: string; status: string; version: string; last_heartbeat: string; created_at: string
  }>(`SELECT * FROM instances ORDER BY status ASC, name ASC`)

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-lg font-semibold">Instances</h1>
          <p className="text-xs text-[var(--muted-foreground)] mt-0.5">CloakPipe proxy instances across your organization</p>
        </div>
        <button className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--primary)] text-white text-[13px] font-medium hover:opacity-90">
          <Plus className="w-3.5 h-3.5" />
          Register Instance
        </button>
      </div>

      <div className="space-y-2">
        {(instances || []).map((inst) => (
          <div key={inst.id} className="bg-[var(--card)] border border-[var(--border)] p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Server className="w-4 h-4 text-[var(--muted-foreground)]" />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-[13px]">{inst.name}</span>
                    <span className={`px-1.5 py-0.5 border text-[10px] font-mono uppercase ${profileColors[inst.profile] || 'text-gray-400 border-gray-400/30'}`}>
                      {inst.profile}
                    </span>
                    {inst.version && (
                      <span className="px-1.5 py-0.5 bg-[var(--secondary)] text-[10px] font-mono text-[var(--muted-foreground)]">
                        {inst.version}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 mt-1 text-xs text-[var(--muted-foreground)] font-mono">
                    <span>{inst.hostname}</span>
                    <span className="text-[var(--border)]">|</span>
                    <span>{inst.upstream}</span>
                    <span className="text-[var(--border)]">|</span>
                    <span>{inst.listen_addr}</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <div className="text-right text-xs text-[var(--muted-foreground)]">
                  {inst.last_heartbeat && (
                    <span>Last heartbeat: {format(new Date(inst.last_heartbeat), 'HH:mm:ss')}</span>
                  )}
                </div>
                <div className={`flex items-center gap-1.5 text-xs font-medium ${statusColors[inst.status] || 'text-gray-400'}`}>
                  <Circle className="w-2 h-2 fill-current" />
                  <span className="uppercase tracking-wider text-[10px]">{inst.status}</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-6 bg-[var(--card)] border border-[var(--border)] p-4">
        <h2 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)] mb-3">Connect an Instance</h2>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-[11px] text-[var(--muted-foreground)] mb-1.5 uppercase tracking-wider">Python (OpenAI SDK)</p>
            <pre className="bg-[var(--background)] border border-[var(--border)] p-3 text-xs font-mono text-[var(--muted-foreground)] overflow-x-auto">
{`client = OpenAI(
    base_url="http://localhost:8900/v1",
    api_key=os.environ["OPENAI_API_KEY"]
)`}
            </pre>
          </div>
          <div>
            <p className="text-[11px] text-[var(--muted-foreground)] mb-1.5 uppercase tracking-wider">curl</p>
            <pre className="bg-[var(--background)] border border-[var(--border)] p-3 text-xs font-mono text-[var(--muted-foreground)] overflow-x-auto">
{`curl http://localhost:8900/v1/chat/completions \\
  -H "Authorization: Bearer $OPENAI_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"model":"gpt-4o","messages":[...]}'`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}
