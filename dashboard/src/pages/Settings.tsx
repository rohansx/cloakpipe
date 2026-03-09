import { Shield, Bell, Key, Copy, Trash2, Cpu, Eye, EyeOff } from 'lucide-react'
import { usePowerSync, useQuery } from '@powersync/react'
import { useState } from 'react'

export function Settings() {
  const db = usePowerSync()
  const [showKey, setShowKey] = useState(false)
  const [llmKey, setLlmKey] = useState('')
  const [llmProvider, setLlmProvider] = useState('openai')
  const [keySaved, setKeySaved] = useState(false)

  const { data: org } = useQuery<{ id: string; name: string; default_profile: string }>(
    `SELECT * FROM organizations LIMIT 1`
  )

  const { data: apiKeys } = useQuery<{
    id: string; name: string; key_prefix: string; requests: number; created_at: string; last_used: string
  }>(`SELECT * FROM api_keys ORDER BY created_at DESC`)

  const { data: existingLlmKeys } = useQuery<{ id: string; provider: string; api_key: string }>(
    `SELECT * FROM llm_keys ORDER BY created_at DESC LIMIT 1`
  )

  const savedKey = existingLlmKeys?.[0]

  async function saveLlmKey() {
    if (!llmKey.trim()) return
    const now = new Date().toISOString()
    if (savedKey) {
      await db.execute(
        `UPDATE llm_keys SET provider = ?, api_key = ?, created_at = ? WHERE id = ?`,
        [llmProvider, llmKey.trim(), now, savedKey.id]
      )
    } else {
      await db.execute(
        `INSERT INTO llm_keys (id, org_id, provider, api_key, created_at) VALUES (?, ?, ?, ?, ?)`,
        [crypto.randomUUID(), 'org-001', llmProvider, llmKey.trim(), now]
      )
    }
    setKeySaved(true)
    setTimeout(() => setKeySaved(false), 2000)
  }

  const currentOrg = org?.[0]

  return (
    <div className="p-6 max-w-3xl">
      <div className="mb-6">
        <h1 className="text-lg font-semibold">Settings</h1>
        <p className="text-xs text-[var(--muted-foreground)] mt-0.5">Organization and workspace configuration</p>
      </div>

      <div className="space-y-4">
        {/* Organization */}
        <section className="bg-[var(--card)] border border-[var(--border)] p-4">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-3.5 h-3.5 text-[var(--muted-foreground)]" />
            <h2 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)]">Organization</h2>
          </div>
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-[var(--muted-foreground)] mb-1">Workspace Name</label>
              <input
                type="text"
                defaultValue={currentOrg?.name || ''}
                className="w-full px-3 py-1.5 bg-[var(--background)] border border-[var(--border)] text-[13px] focus:outline-none focus:border-[var(--primary)]"
              />
            </div>
            <div>
              <label className="block text-xs text-[var(--muted-foreground)] mb-1">Default Industry Profile</label>
              <select
                defaultValue={currentOrg?.default_profile || 'general'}
                className="w-full px-3 py-1.5 bg-[var(--background)] border border-[var(--border)] text-[13px] focus:outline-none focus:border-[var(--primary)]"
              >
                <option value="general">General</option>
                <option value="legal">Legal</option>
                <option value="healthcare">Healthcare</option>
                <option value="fintech">Fintech</option>
              </select>
            </div>
          </div>
        </section>

        {/* LLM Provider */}
        <section className="bg-[var(--card)] border border-[var(--border)] p-4">
          <div className="flex items-center gap-2 mb-3">
            <Cpu className="w-3.5 h-3.5 text-[var(--muted-foreground)]" />
            <h2 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)]">LLM Provider</h2>
          </div>
          <p className="text-[11px] text-[var(--muted-foreground)] mb-3">
            API key used by CloakPipe Chat. Stored locally in your browser — never sent to our servers.
          </p>
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-[var(--muted-foreground)] mb-1">Provider</label>
              <select
                value={llmProvider}
                onChange={(e) => setLlmProvider(e.target.value)}
                className="w-full px-3 py-1.5 bg-[var(--background)] border border-[var(--border)] text-[13px] focus:outline-none focus:border-[var(--primary)]"
              >
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
                <option value="gemini">Google Gemini</option>
                <option value="glm">GLM (ZhipuAI)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-[var(--muted-foreground)] mb-1">API Key</label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <input
                    type={showKey ? 'text' : 'password'}
                    value={llmKey}
                    onChange={(e) => setLlmKey(e.target.value)}
                    placeholder={savedKey ? `${savedKey.api_key.slice(0, 7)}...${savedKey.api_key.slice(-4)}` : 'sk-...'}
                    className="w-full px-3 py-1.5 pr-8 bg-[var(--background)] border border-[var(--border)] text-[13px] font-mono focus:outline-none focus:border-[var(--primary)]"
                  />
                  <button
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                  >
                    {showKey ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <button
                  onClick={saveLlmKey}
                  className="px-3 py-1.5 bg-[var(--primary)] text-white text-[13px] font-medium hover:opacity-90"
                >
                  {keySaved ? 'Saved' : 'Save'}
                </button>
              </div>
              {savedKey && (
                <p className="text-[10px] text-[var(--success)] mt-1 font-mono">
                  {savedKey.provider} key configured ({savedKey.api_key.slice(0, 7)}...{savedKey.api_key.slice(-4)})
                </p>
              )}
            </div>
          </div>
        </section>

        {/* API Keys */}
        <section className="bg-[var(--card)] border border-[var(--border)]">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)]">
            <div className="flex items-center gap-2">
              <Key className="w-3.5 h-3.5 text-[var(--muted-foreground)]" />
              <h2 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)]">API Keys</h2>
            </div>
            <button className="px-2 py-1 bg-[var(--primary)] text-white text-[11px] font-medium hover:opacity-90">
              Create Key
            </button>
          </div>
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-b border-[var(--border)]">
                <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Name</th>
                <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Key</th>
                <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Requests</th>
                <th className="text-left px-4 py-2 text-[var(--muted-foreground)] font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {(apiKeys || []).map((key) => (
                <tr key={key.id} className="border-b border-[var(--border)]">
                  <td className="px-4 py-2 text-xs font-medium">{key.name}</td>
                  <td className="px-4 py-2 font-mono text-xs text-[var(--muted-foreground)]">{key.key_prefix}</td>
                  <td className="px-4 py-2 font-mono text-xs tabular-nums">{(key.requests as number).toLocaleString()}</td>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-1">
                      <button className="p-1 hover:bg-[var(--secondary)] text-[var(--muted-foreground)] hover:text-[var(--foreground)]">
                        <Copy className="w-3 h-3" />
                      </button>
                      <button className="p-1 hover:bg-red-500/10 text-[var(--muted-foreground)] hover:text-[var(--destructive)]">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* Alerts */}
        <section className="bg-[var(--card)] border border-[var(--border)] p-4">
          <div className="flex items-center gap-2 mb-3">
            <Bell className="w-3.5 h-3.5 text-[var(--muted-foreground)]" />
            <h2 className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)]">Alerts</h2>
          </div>
          <div className="space-y-2">
            <label className="flex items-center gap-2.5 px-2 py-1.5 hover:bg-[var(--secondary)] cursor-pointer">
              <input type="checkbox" defaultChecked className="w-3.5 h-3.5 accent-[var(--primary)]" />
              <div>
                <span className="text-xs">High-volume detection spike</span>
                <p className="text-[10px] text-[var(--muted-foreground)]">Alert when detection rate exceeds threshold</p>
              </div>
            </label>
            <label className="flex items-center gap-2.5 px-2 py-1.5 hover:bg-[var(--secondary)] cursor-pointer">
              <input type="checkbox" className="w-3.5 h-3.5 accent-[var(--primary)]" />
              <div>
                <span className="text-xs">Instance offline</span>
                <p className="text-[10px] text-[var(--muted-foreground)]">Alert when an instance stops sending heartbeats</p>
              </div>
            </label>
          </div>
        </section>

        <button className="w-full py-1.5 bg-[var(--primary)] text-white text-[13px] font-medium hover:opacity-90">
          Save Changes
        </button>
      </div>
    </div>
  )
}
