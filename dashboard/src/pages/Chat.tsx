import { useState, useRef, useEffect } from 'react'
import { Send, Plus, Shield, Eye, MessageSquare, ChevronRight, AlertCircle } from 'lucide-react'
import { usePowerSync, useQuery } from '@powersync/react'
import { pseudonymize, rehydrate, createVault, type TokenVault, type DetectedEntity } from '../lib/cloakpipe'

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  pseudonymizedContent?: string
  entitiesJson?: string
  entityCount: number
}

const MODELS = [
  { id: 'gpt-4o', label: 'GPT-4o', provider: 'openai' },
  { id: 'gpt-4o-mini', label: 'GPT-4o Mini', provider: 'openai' },
  { id: 'claude-sonnet-4-20250514', label: 'Claude Sonnet', provider: 'anthropic' },
  { id: 'gemini-2.0-flash', label: 'Gemini 2.0 Flash', provider: 'gemini' },
  { id: 'gemini-2.5-pro-preview-05-06', label: 'Gemini 2.5 Pro', provider: 'gemini' },
  { id: 'glm-4-flash', label: 'GLM-4 Flash', provider: 'glm' },
  { id: 'glm-4-air', label: 'GLM-4 Air', provider: 'glm' },
  { id: 'glm-4-plus', label: 'GLM-4 Plus', provider: 'glm' },
]

const PROVIDER_ENDPOINTS: Record<string, string> = {
  openai: 'https://api.openai.com/v1/chat/completions',
  gemini: 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions',
  glm: 'https://open.bigmodel.cn/api/paas/v4/chat/completions',
}

export function Chat() {
  const db = usePowerSync()
  const [conversationId, setConversationId] = useState<string | null>(null)
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  const [streamContent, setStreamContent] = useState('')
  const [model, setModel] = useState('gpt-4o')
  const [showShield, setShowShield] = useState(true)
  const [lastPseudonymized, setLastPseudonymized] = useState('')
  const [lastEntities, setLastEntities] = useState<DetectedEntity[]>([])
  const [liveEntities, setLiveEntities] = useState<DetectedEntity[]>([])
  const [livePseudonymized, setLivePseudonymized] = useState('')
  const [vault] = useState<TokenVault>(() => createVault())
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const { data: conversations } = useQuery<{
    id: string; title: string; model: string; updated_at: string
  }>(`SELECT * FROM conversations ORDER BY updated_at DESC`)

  const { data: messages } = useQuery<{
    id: string; role: string; content: string; pseudonymized_content: string; entities_json: string; entity_count: number
  }>(
    conversationId
      ? `SELECT * FROM chat_messages WHERE conversation_id = ? ORDER BY created_at ASC`
      : `SELECT * FROM chat_messages WHERE 1=0`,
    conversationId ? [conversationId] : []
  )

  const { data: llmKeys } = useQuery<{ provider: string; api_key: string }>(
    `SELECT provider, api_key FROM llm_keys ORDER BY created_at DESC LIMIT 1`
  )

  const apiKey = llmKeys?.[0]?.api_key || ''
  const savedProvider = llmKeys?.[0]?.provider || ''
  const availableModels = savedProvider ? MODELS.filter(m => m.provider === savedProvider) : MODELS

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, streamContent])

  // Auto-select first model when provider changes
  useEffect(() => {
    if (availableModels.length > 0 && !availableModels.find(m => m.id === model)) {
      setModel(availableModels[0].id)
    }
  }, [savedProvider])

  // Live detection as user types
  useEffect(() => {
    if (!input.trim()) {
      setLiveEntities([])
      setLivePseudonymized('')
      return
    }
    const { output, entities } = pseudonymize(input)
    setLiveEntities(entities)
    setLivePseudonymized(output)
  }, [input])

  async function createConversation(): Promise<string> {
    const id = crypto.randomUUID()
    const now = new Date().toISOString()
    await db.execute(
      `INSERT INTO conversations (id, org_id, user_id, title, model, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id, 'org-001', 'user-001', 'New Chat', model, now, now]
    )
    setConversationId(id)
    return id
  }

  async function saveMessage(convId: string, role: string, content: string, pseudonymized: string, entities: DetectedEntity[]) {
    const id = crypto.randomUUID()
    const now = new Date().toISOString()
    await db.execute(
      `INSERT INTO chat_messages (id, conversation_id, user_id, role, content, pseudonymized_content, entities_json, entity_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, convId, 'user-001', role, content, pseudonymized, JSON.stringify(entities), entities.length, now]
    )

    // Also record detections for the dashboard feed
    for (const entity of entities) {
      await db.execute(
        `INSERT INTO detections (id, org_id, instance_id, category, token, source, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [crypto.randomUUID(), 'org-001', 'chat', entity.category, entity.token, 'Chat', now]
      )
    }
  }

  async function updateConversationTitle(convId: string, firstMessage: string) {
    const title = firstMessage.slice(0, 50) + (firstMessage.length > 50 ? '...' : '')
    const now = new Date().toISOString()
    await db.execute(
      `UPDATE conversations SET title = ?, updated_at = ? WHERE id = ?`,
      [title, now, convId]
    )
  }

  async function handleSend() {
    if (!input.trim() || streaming) return
    if (!apiKey) return

    const userMessage = input.trim()
    setInput('')

    let convId = conversationId
    if (!convId) {
      convId = await createConversation()
      await updateConversationTitle(convId, userMessage)
    }

    // Pseudonymize the user message
    const { output: pseudonymized, entities } = pseudonymize(userMessage, vault)
    setLastPseudonymized(pseudonymized)
    setLastEntities(entities)

    // Save original message with pseudonymization metadata
    await saveMessage(convId, 'user', userMessage, pseudonymized, entities)

    // Build history using pseudonymized versions for the LLM
    const history = (messages || []).map(m => ({
      role: m.role as 'user' | 'assistant',
      content: m.role === 'user' && m.pseudonymized_content ? m.pseudonymized_content : m.content,
    }))
    history.push({ role: 'user', content: pseudonymized })

    setStreaming(true)
    setStreamContent('')

    const selectedModel = MODELS.find(m => m.id === model)

    try {
      let fullContent = ''

      if (selectedModel?.provider === 'anthropic') {
        // Anthropic API (non-streaming — their SSE format differs)
        const response = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
            'anthropic-dangerous-direct-browser-access': 'true',
          },
          body: JSON.stringify({
            model,
            max_tokens: 4096,
            messages: history,
          }),
        })

        if (!response.ok) {
          const errorText = await response.text()
          await saveMessage(convId, 'assistant', `Error: ${response.status} — ${errorText}`, '', [])
          setStreaming(false)
          return
        }

        const data = await response.json()
        fullContent = data.content?.[0]?.text || ''
        setStreamContent(fullContent)
      } else {
        // OpenAI-compatible streaming (works for OpenAI, Gemini, GLM)
        const endpoint = PROVIDER_ENDPOINTS[selectedModel?.provider || 'openai']
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`,
          },
          body: JSON.stringify({
            model,
            messages: history,
            stream: true,
          }),
        })

        if (!response.ok) {
          const errorText = await response.text()
          await saveMessage(convId, 'assistant', `Error: ${response.status} — ${errorText}`, '', [])
          setStreaming(false)
          return
        }

        const reader = response.body?.getReader()
        const decoder = new TextDecoder()

        if (reader) {
          while (true) {
            const { done, value } = await reader.read()
            if (done) break

            const chunk = decoder.decode(value)
            const lines = chunk.split('\n')

            for (const line of lines) {
              if (line.startsWith('data: ')) {
                const data = line.slice(6)
                if (data === '[DONE]') continue

                try {
                  const parsed = JSON.parse(data)
                  const delta = parsed.choices?.[0]?.delta?.content
                  if (delta) {
                    fullContent += delta
                    setStreamContent(rehydrate(fullContent, vault))
                  }
                } catch {
                  // skip malformed chunks
                }
              }
            }
          }
        }
      }

      // Rehydrate the response — replace tokens back with originals
      const rehydrated = rehydrate(fullContent, vault)

      await saveMessage(convId, 'assistant', rehydrated, fullContent, [])
      await db.execute(
        `UPDATE conversations SET updated_at = ? WHERE id = ?`,
        [new Date().toISOString(), convId]
      )
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Connection failed'
      await saveMessage(convId, 'assistant', `Error: ${errorMsg}`, '', [])
    } finally {
      setStreaming(false)
      setStreamContent('')
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const allMessages: Message[] = (messages || []).map(m => ({
    id: m.id,
    role: m.role as 'user' | 'assistant',
    content: m.content,
    pseudonymizedContent: m.pseudonymized_content,
    entitiesJson: m.entities_json,
    entityCount: m.entity_count,
  }))

  return (
    <div className="flex h-full">
      {/* Conversation sidebar */}
      <div className="w-52 border-r border-[var(--border)] bg-[var(--card)] flex flex-col">
        <div className="p-3 border-b border-[var(--border)]">
          <button
            onClick={() => { setConversationId(null) }}
            className="w-full flex items-center gap-1.5 px-2 py-1.5 bg-[var(--primary)] text-white text-[12px] font-medium hover:opacity-90"
          >
            <Plus className="w-3 h-3" />
            New Chat
          </button>
        </div>

        <div className="flex-1 overflow-auto p-2 space-y-0.5">
          {(conversations || []).map(conv => (
            <button
              key={conv.id}
              onClick={() => setConversationId(conv.id)}
              className={`w-full text-left px-2 py-1.5 text-[12px] truncate transition-colors ${
                conversationId === conv.id
                  ? 'bg-[var(--secondary)] text-[var(--foreground)]'
                  : 'text-[var(--muted-foreground)] hover:text-[var(--foreground)] hover:bg-[var(--secondary)]'
              }`}
            >
              <MessageSquare className="w-3 h-3 inline mr-1.5" />
              {conv.title}
            </button>
          ))}
        </div>

        <div className="p-3 border-t border-[var(--border)]">
          <select
            value={model}
            onChange={(e) => setModel(e.target.value)}
            className="w-full px-2 py-1 bg-[var(--background)] border border-[var(--border)] text-[11px] text-[var(--foreground)] font-mono"
          >
            {availableModels.map(m => (
              <option key={m.id} value={m.id}>{m.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Chat area */}
      <div className="flex-1 flex flex-col">
        {/* Messages */}
        <div className="flex-1 overflow-auto p-6">
          {!apiKey && (
            <div className="max-w-3xl mx-auto mb-4 px-3 py-2 bg-[var(--warning)]/10 border border-[var(--warning)]/30 flex items-center gap-2">
              <AlertCircle className="w-3.5 h-3.5 text-[var(--warning)]" />
              <span className="text-xs text-[var(--warning)]">
                No API key configured. Go to Settings to add your OpenAI or Anthropic key.
              </span>
            </div>
          )}

          {allMessages.length === 0 && !streaming && (
            <div className="flex flex-col items-center justify-center h-full text-center">
              <Shield className="w-8 h-8 text-[var(--primary)] mb-3" />
              <h2 className="text-lg font-semibold mb-1">CloakPipe Chat</h2>
              <p className="text-xs text-[var(--muted-foreground)] max-w-sm">
                Your messages are pseudonymized before reaching the LLM.
                The AI never sees your real data.
              </p>
              <p className="text-[10px] text-[var(--muted-foreground)] mt-2 font-mono">
                Built-in privacy engine — no proxy required
              </p>
            </div>
          )}

          <div className="max-w-3xl mx-auto space-y-4">
            {allMessages.map((msg) => (
              <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[80%] ${
                  msg.role === 'user'
                    ? 'bg-[var(--primary)] text-white px-3 py-2'
                    : 'bg-[var(--card)] border border-[var(--border)] px-4 py-3'
                }`}>
                  <div className="text-[13px] whitespace-pre-wrap">{msg.content}</div>
                  {msg.entityCount > 0 && (
                    <div className="mt-1.5 flex items-center gap-1 text-[10px] opacity-70">
                      <Eye className="w-2.5 h-2.5" />
                      {msg.entityCount} entities protected
                    </div>
                  )}
                </div>
              </div>
            ))}

            {streaming && streamContent && (
              <div className="flex justify-start">
                <div className="max-w-[80%] bg-[var(--card)] border border-[var(--border)] px-4 py-3">
                  <div className="text-[13px] whitespace-pre-wrap">{streamContent}</div>
                  <div className="mt-1 w-2 h-4 bg-[var(--primary)] animate-pulse inline-block" />
                </div>
              </div>
            )}

            {streaming && !streamContent && (
              <div className="flex justify-start">
                <div className="bg-[var(--card)] border border-[var(--border)] px-4 py-3">
                  <div className="flex items-center gap-2 text-xs text-[var(--muted-foreground)]">
                    <div className="w-1.5 h-1.5 bg-[var(--primary)] animate-pulse" />
                    <div className="w-1.5 h-1.5 bg-[var(--primary)] animate-pulse" style={{ animationDelay: '0.2s' }} />
                    <div className="w-1.5 h-1.5 bg-[var(--primary)] animate-pulse" style={{ animationDelay: '0.4s' }} />
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>
        </div>

        {/* Input */}
        <div className="border-t border-[var(--border)] p-4">
          <div className="max-w-3xl mx-auto flex gap-2">
            <textarea
              ref={textareaRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type a message... (Enter to send, Shift+Enter for newline)"
              rows={1}
              className="flex-1 px-3 py-2 bg-[var(--card)] border border-[var(--border)] text-[13px] resize-none focus:outline-none focus:border-[var(--primary)] placeholder:text-[var(--muted-foreground)]"
              style={{ minHeight: '40px', maxHeight: '120px' }}
            />
            <button
              onClick={handleSend}
              disabled={!input.trim() || streaming || !apiKey}
              className="px-3 py-2 bg-[var(--primary)] text-white hover:opacity-90 disabled:opacity-40"
            >
              <Send className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowShield(!showShield)}
              className={`px-3 py-2 border border-[var(--border)] ${showShield ? 'text-[var(--primary)] bg-[var(--primary)]/10' : 'text-[var(--muted-foreground)]'}`}
              title="Toggle Privacy Shield"
            >
              <Shield className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Privacy Shield panel */}
      {showShield && (
        <div className="w-72 border-l border-[var(--border)] bg-[var(--card)] flex flex-col">
          <div className="px-4 py-3 border-b border-[var(--border)] flex items-center gap-2">
            <Shield className="w-3.5 h-3.5 text-[var(--primary)]" />
            <span className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)]">Privacy Shield</span>
          </div>

          <div className="flex-1 overflow-auto p-3 space-y-3">
            {/* Live preview */}
            <div>
              <h3 className="text-[10px] uppercase tracking-wider text-[var(--muted-foreground)] mb-1.5">What you type</h3>
              <div className="bg-[var(--background)] border border-[var(--border)] p-2 text-[12px] min-h-[40px]">
                {input || <span className="text-[var(--muted-foreground)] italic">Start typing...</span>}
              </div>
            </div>

            <div className="flex items-center gap-1 text-[var(--muted-foreground)]">
              <ChevronRight className="w-3 h-3" />
              <span className="text-[10px] uppercase tracking-wider">CloakPipe engine</span>
              <ChevronRight className="w-3 h-3" />
            </div>

            <div>
              <h3 className="text-[10px] uppercase tracking-wider text-[var(--muted-foreground)] mb-1.5">What the LLM sees</h3>
              <div className="bg-[var(--background)] border border-[var(--border)] p-2 text-[12px] min-h-[40px] font-mono text-[var(--primary)]">
                {livePseudonymized || lastPseudonymized || <span className="text-[var(--muted-foreground)] italic font-sans">Pseudonymized output appears here</span>}
              </div>
            </div>

            {/* Live detected entities while typing */}
            {liveEntities.length > 0 && (
              <div>
                <h3 className="text-[10px] uppercase tracking-wider text-[var(--muted-foreground)] mb-1.5">
                  Detected ({liveEntities.length})
                </h3>
                <div className="space-y-1">
                  {liveEntities.map((entity, i) => (
                    <div key={i} className="flex items-center justify-between bg-[var(--background)] border border-[var(--border)] px-2 py-1">
                      <span className="text-[11px] text-[var(--destructive)] line-through">{entity.original}</span>
                      <span className="text-[11px] font-mono text-[var(--primary)]">{entity.token}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Last sent entities */}
            {liveEntities.length === 0 && lastEntities.length > 0 && (
              <div>
                <h3 className="text-[10px] uppercase tracking-wider text-[var(--muted-foreground)] mb-1.5">
                  Last Protected ({lastEntities.length})
                </h3>
                <div className="space-y-1">
                  {lastEntities.map((entity, i) => (
                    <div key={i} className="flex items-center justify-between bg-[var(--background)] border border-[var(--border)] px-2 py-1">
                      <span className="text-[11px] text-[var(--muted-foreground)]">{entity.original}</span>
                      <span className="text-[11px] font-mono text-[var(--primary)]">{entity.token}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Stats from current conversation */}
            {conversationId && (
              <ConversationStats conversationId={conversationId} />
            )}

            {/* How it works */}
            <div className="border-t border-[var(--border)] pt-3">
              <h3 className="text-[10px] uppercase tracking-wider text-[var(--muted-foreground)] mb-1.5">How it works</h3>
              <div className="space-y-1 text-[11px] text-[var(--muted-foreground)]">
                <p>1. You type a message with sensitive data</p>
                <p>2. CloakPipe detects PII in your browser</p>
                <p>3. Entities are replaced with tokens</p>
                <p>4. Sanitized text is sent to the LLM</p>
                <p>5. Response tokens are rehydrated back</p>
                <p className="text-[var(--success)] font-medium mt-1">The LLM never sees your real data.</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function ConversationStats({ conversationId }: { conversationId: string }) {
  const { data: stats } = useQuery<{ total_entities: number; total_messages: number }>(
    `SELECT COALESCE(SUM(entity_count), 0) as total_entities, COUNT(*) as total_messages FROM chat_messages WHERE conversation_id = ?`,
    [conversationId]
  )

  const s = stats?.[0]
  if (!s) return null

  return (
    <div className="border-t border-[var(--border)] pt-3">
      <h3 className="text-[10px] uppercase tracking-wider text-[var(--muted-foreground)] mb-1.5">Session Stats</h3>
      <div className="grid grid-cols-2 gap-2">
        <div className="bg-[var(--background)] border border-[var(--border)] p-2 text-center">
          <div className="text-lg font-mono tabular-nums font-semibold">{s.total_messages}</div>
          <div className="text-[10px] text-[var(--muted-foreground)]">Messages</div>
        </div>
        <div className="bg-[var(--background)] border border-[var(--border)] p-2 text-center">
          <div className="text-lg font-mono tabular-nums font-semibold text-[var(--primary)]">{s.total_entities}</div>
          <div className="text-[10px] text-[var(--muted-foreground)]">Protected</div>
        </div>
      </div>
    </div>
  )
}
