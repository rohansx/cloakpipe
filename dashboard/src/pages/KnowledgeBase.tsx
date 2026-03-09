import { useState, useRef, useCallback } from 'react'
import { Database, Plus, FileText, Upload, Trash2, Search, Eye, Shield, ChevronRight, X, File, FileType, Zap, AlertCircle } from 'lucide-react'
import { usePowerSync, useQuery } from '@powersync/react'
import { pseudonymize, createVault } from '../lib/cloakpipe'
import { chunkText, detectPages, generateEmbeddings, type EmbeddingConfig } from '../lib/retrieval'

interface KnowledgeBaseRow {
  id: string; name: string; description: string; document_count: number;
  chunk_count: number; total_detections: number; created_at: string; updated_at: string
}

interface DocumentRow {
  id: string; kb_id: string; name: string; file_type: string;
  size_bytes: number; chunk_count: number; detection_count: number; created_at: string
}

const FILE_ICONS: Record<string, typeof FileText> = {
  'text/plain': FileText,
  'text/markdown': FileType,
  'application/pdf': File,
}

export function KnowledgeBase() {
  const db = usePowerSync()
  const [selectedKb, setSelectedKb] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState('')
  const [uploadStep, setUploadStep] = useState<'idle' | 'reading' | 'chunking' | 'pii' | 'embedding' | 'saving'>('idle')
  const [searchQuery, setSearchQuery] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const { data: knowledgeBases } = useQuery<KnowledgeBaseRow>(
    `SELECT * FROM knowledge_bases WHERE org_id = ? ORDER BY updated_at DESC`,
    ['org-001']
  )

  const { data: documents } = useQuery<DocumentRow>(
    selectedKb
      ? `SELECT * FROM kb_documents WHERE kb_id = ? ORDER BY created_at DESC`
      : `SELECT * FROM kb_documents WHERE 1=0`,
    selectedKb ? [selectedKb] : []
  )

  const { data: chunkStats } = useQuery<{ total_chunks: number; total_entities: number }>(
    selectedKb
      ? `SELECT COUNT(*) as total_chunks, COALESCE(SUM(entity_count), 0) as total_entities FROM kb_chunks WHERE kb_id = ?`
      : `SELECT 0 as total_chunks, 0 as total_entities`,
    selectedKb ? [selectedKb] : []
  )

  const { data: embedKeyRows } = useQuery<{ provider: string; api_key: string; model: string }>(
    `SELECT provider, api_key, model FROM embedding_keys ORDER BY created_at DESC LIMIT 1`
  )

  const selectedKbData = (knowledgeBases || []).find(kb => kb.id === selectedKb)
  const stats = chunkStats?.[0]
  const embedConfig = embedKeyRows?.[0]
  const hasEmbeddings = !!embedConfig?.api_key
  const filteredKbs = searchQuery
    ? (knowledgeBases || []).filter(kb => kb.name.toLowerCase().includes(searchQuery.toLowerCase()))
    : (knowledgeBases || [])

  async function handleCreateKb() {
    if (!newName.trim()) return
    const id = crypto.randomUUID()
    const now = new Date().toISOString()
    await db.execute(
      `INSERT INTO knowledge_bases (id, org_id, name, description, document_count, chunk_count, total_detections, created_at, updated_at) VALUES (?, ?, ?, ?, 0, 0, 0, ?, ?)`,
      [id, 'org-001', newName.trim(), newDesc.trim(), now, now]
    )
    setNewName('')
    setNewDesc('')
    setShowCreate(false)
    setSelectedKb(id)
  }

  async function handleDeleteKb(kbId: string) {
    await db.execute(`DELETE FROM kb_chunks WHERE kb_id = ?`, [kbId])
    await db.execute(`DELETE FROM kb_documents WHERE kb_id = ?`, [kbId])
    await db.execute(`DELETE FROM knowledge_bases WHERE id = ?`, [kbId])
    if (selectedKb === kbId) setSelectedKb(null)
  }

  async function handleFileUpload(files: FileList | null) {
    if (!files || !selectedKb) return
    setUploading(true)

    for (const file of Array.from(files)) {
      // Step 1: Read file
      setUploadStep('reading')
      setUploadProgress(`Reading ${file.name}...`)
      const content = await file.text()

      // Step 2: Chunk
      setUploadStep('chunking')
      setUploadProgress(`Chunking ${file.name}...`)
      const pages = detectPages(content)
      const allChunks: { content: string; page: number; index: number }[] = []

      let globalIdx = 0
      for (const [pageNum, pageContent] of pages) {
        const chunks = chunkText(pageContent)
        for (const chunk of chunks) {
          allChunks.push({ content: chunk, page: pageNum, index: globalIdx++ })
        }
      }

      // Step 3: PII scan & pseudonymize
      setUploadStep('pii')
      setUploadProgress(`Scanning ${file.name} for PII (${allChunks.length} chunks)...`)
      const vault = createVault()
      const pseudonymizedChunks: { original: string; pseudonymized: string; entitiesJson: string; entityCount: number; page: number; index: number }[] = []
      let totalDetections = 0

      for (const chunk of allChunks) {
        const { output, entities } = pseudonymize(chunk.content, vault)
        totalDetections += entities.length
        pseudonymizedChunks.push({
          original: chunk.content,
          pseudonymized: output,
          entitiesJson: JSON.stringify(entities),
          entityCount: entities.length,
          page: chunk.page,
          index: chunk.index,
        })
      }

      // Step 4: Generate embeddings (on PSEUDONYMIZED content — PII never touches the API)
      let embeddings: number[][] | null = null
      if (hasEmbeddings) {
        setUploadStep('embedding')
        setUploadProgress(`Generating embeddings for ${file.name} (${pseudonymizedChunks.length} chunks)...`)
        try {
          const config: EmbeddingConfig = {
            provider: embedConfig!.provider as EmbeddingConfig['provider'],
            apiKey: embedConfig!.api_key,
            model: embedConfig!.model,
          }
          embeddings = await generateEmbeddings(
            pseudonymizedChunks.map(c => c.pseudonymized),
            config,
            (done, total) => setUploadProgress(`Embedding ${file.name}: ${done}/${total} chunks...`)
          )
        } catch (err) {
          console.error('Embedding error:', err)
          setUploadProgress(`Embedding failed, using keyword search for ${file.name}`)
          // Continue without embeddings — falls back to TF-IDF
        }
      }

      // Step 5: Save to database
      setUploadStep('saving')
      setUploadProgress(`Saving ${file.name}...`)
      const docId = crypto.randomUUID()
      const now = new Date().toISOString()

      for (let i = 0; i < pseudonymizedChunks.length; i++) {
        const chunk = pseudonymizedChunks[i]
        const embedding = embeddings?.[i] ? JSON.stringify(embeddings[i]) : null

        await db.execute(
          `INSERT INTO kb_chunks (id, doc_id, kb_id, content, pseudonymized_content, entities_json, entity_count, chunk_index, page_number, embedding) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [crypto.randomUUID(), docId, selectedKb, chunk.original, chunk.pseudonymized, chunk.entitiesJson, chunk.entityCount, chunk.index, chunk.page, embedding]
        )
      }

      await db.execute(
        `INSERT INTO kb_documents (id, kb_id, org_id, name, file_type, content, size_bytes, chunk_count, detection_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [docId, selectedKb, 'org-001', file.name, file.type || 'text/plain', content, file.size, allChunks.length, totalDetections, now]
      )

      await db.execute(
        `UPDATE knowledge_bases SET document_count = document_count + 1, chunk_count = chunk_count + ?, total_detections = total_detections + ?, updated_at = ? WHERE id = ?`,
        [allChunks.length, totalDetections, now, selectedKb]
      )
    }

    setUploading(false)
    setUploadProgress('')
    setUploadStep('idle')
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  async function handleDeleteDoc(doc: DocumentRow) {
    await db.execute(`DELETE FROM kb_chunks WHERE doc_id = ?`, [doc.id])
    await db.execute(`DELETE FROM kb_documents WHERE id = ?`, [doc.id])
    const now = new Date().toISOString()
    await db.execute(
      `UPDATE knowledge_bases SET document_count = document_count - 1, chunk_count = chunk_count - ?, total_detections = total_detections - ?, updated_at = ? WHERE id = ?`,
      [doc.chunk_count, doc.detection_count, now, doc.kb_id]
    )
  }

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    if (e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files)
    }
  }, [selectedKb, hasEmbeddings])

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const STEP_LABELS: Record<string, string> = {
    reading: 'Reading file',
    chunking: 'Splitting into chunks',
    pii: 'Scanning for PII',
    embedding: 'Generating embeddings',
    saving: 'Saving to database',
  }

  return (
    <div className="flex h-full">
      {/* KB List sidebar */}
      <div className="w-64 border-r border-[var(--border)] bg-[var(--card)] flex flex-col">
        <div className="p-3 border-b border-[var(--border)]">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-[var(--primary)]" />
              <span className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)]">Knowledge Bases</span>
            </div>
            <button
              onClick={() => setShowCreate(true)}
              className="p-1 text-[var(--primary)] hover:bg-[var(--secondary)]"
              title="Create Knowledge Base"
            >
              <Plus className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-[var(--muted-foreground)]" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search..."
              className="w-full pl-7 pr-2 py-1 bg-[var(--background)] border border-[var(--border)] text-[11px] focus:outline-none focus:border-[var(--primary)] placeholder:text-[var(--muted-foreground)]"
            />
          </div>
        </div>

        <div className="flex-1 overflow-auto p-2 space-y-1">
          {filteredKbs.map(kb => (
            <button
              key={kb.id}
              onClick={() => setSelectedKb(kb.id)}
              className={`w-full text-left px-3 py-2 transition-colors group ${
                selectedKb === kb.id
                  ? 'bg-[var(--secondary)] text-[var(--foreground)]'
                  : 'text-[var(--muted-foreground)] hover:text-[var(--foreground)] hover:bg-[var(--secondary)]'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[12px] font-medium truncate">{kb.name}</span>
                <button
                  onClick={(e) => { e.stopPropagation(); handleDeleteKb(kb.id) }}
                  className="opacity-0 group-hover:opacity-100 p-0.5 text-[var(--destructive)] hover:bg-[var(--destructive)]/10"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </div>
              <div className="flex items-center gap-2 mt-0.5 text-[10px] text-[var(--muted-foreground)]">
                <span>{kb.document_count} docs</span>
                <span className="text-[var(--border)]">|</span>
                <span>{kb.chunk_count} chunks</span>
                {kb.total_detections > 0 && (
                  <>
                    <span className="text-[var(--border)]">|</span>
                    <span className="text-[var(--primary)]">{kb.total_detections} PII</span>
                  </>
                )}
              </div>
            </button>
          ))}

          {filteredKbs.length === 0 && !showCreate && (
            <div className="text-center py-8 text-[var(--muted-foreground)]">
              <Database className="w-6 h-6 mx-auto mb-2 opacity-30" />
              <p className="text-[11px]">No knowledge bases yet</p>
              <button
                onClick={() => setShowCreate(true)}
                className="text-[11px] text-[var(--primary)] hover:underline mt-1"
              >
                Create one
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Create KB modal */}
        {showCreate && (
          <div className="absolute inset-0 bg-black/50 z-50 flex items-center justify-center">
            <div className="bg-[var(--card)] border border-[var(--border)] w-[420px] p-5">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold">Create Knowledge Base</h2>
                <button onClick={() => setShowCreate(false)} className="text-[var(--muted-foreground)] hover:text-[var(--foreground)]">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)] block mb-1">Name</label>
                  <input
                    type="text"
                    value={newName}
                    onChange={e => setNewName(e.target.value)}
                    placeholder="e.g. Legal Documents, HR Policies"
                    className="w-full px-3 py-1.5 bg-[var(--background)] border border-[var(--border)] text-[13px] focus:outline-none focus:border-[var(--primary)] placeholder:text-[var(--muted-foreground)]"
                    autoFocus
                    onKeyDown={e => e.key === 'Enter' && handleCreateKb()}
                  />
                </div>
                <div>
                  <label className="text-[11px] uppercase tracking-wider text-[var(--muted-foreground)] block mb-1">Description</label>
                  <textarea
                    value={newDesc}
                    onChange={e => setNewDesc(e.target.value)}
                    placeholder="What documents will this contain?"
                    rows={2}
                    className="w-full px-3 py-1.5 bg-[var(--background)] border border-[var(--border)] text-[13px] resize-none focus:outline-none focus:border-[var(--primary)] placeholder:text-[var(--muted-foreground)]"
                  />
                </div>
                <button
                  onClick={handleCreateKb}
                  disabled={!newName.trim()}
                  className="w-full py-1.5 bg-[var(--primary)] text-white text-[13px] font-medium hover:opacity-90 disabled:opacity-40"
                >
                  Create
                </button>
              </div>
            </div>
          </div>
        )}

        {selectedKbData ? (
          <>
            {/* KB header */}
            <div className="p-5 border-b border-[var(--border)]">
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-lg font-semibold">{selectedKbData.name}</h1>
                  {selectedKbData.description && (
                    <p className="text-xs text-[var(--muted-foreground)] mt-0.5">{selectedKbData.description}</p>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    accept=".txt,.md,.csv,.json,.log,.pdf"
                    onChange={e => handleFileUpload(e.target.files)}
                    className="hidden"
                  />
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    disabled={uploading}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--primary)] text-white text-[13px] font-medium hover:opacity-90 disabled:opacity-40"
                  >
                    <Upload className="w-3.5 h-3.5" />
                    {uploading ? 'Processing...' : 'Upload Documents'}
                  </button>
                </div>
              </div>

              {/* Stats bar */}
              <div className="flex items-center gap-4 mt-3">
                <div className="flex items-center gap-1.5 text-xs text-[var(--muted-foreground)]">
                  <FileText className="w-3 h-3" />
                  <span className="font-mono">{selectedKbData.document_count}</span> documents
                </div>
                <div className="flex items-center gap-1.5 text-xs text-[var(--muted-foreground)]">
                  <Database className="w-3 h-3" />
                  <span className="font-mono">{stats?.total_chunks || 0}</span> chunks indexed
                </div>
                <div className="flex items-center gap-1.5 text-xs text-[var(--primary)]">
                  <Shield className="w-3 h-3" />
                  <span className="font-mono">{stats?.total_entities || 0}</span> PII detected
                </div>
                <div className={`flex items-center gap-1.5 text-xs ${hasEmbeddings ? 'text-[var(--success)]' : 'text-[var(--muted-foreground)]'}`}>
                  <Zap className="w-3 h-3" />
                  {hasEmbeddings ? 'Vector search' : 'Keyword search'}
                </div>
              </div>

              {/* Upload progress */}
              {uploading && (
                <div className="mt-3 bg-[var(--background)] border border-[var(--border)] p-3">
                  <div className="flex items-center gap-2 text-xs text-[var(--muted-foreground)] mb-2">
                    <div className="w-2 h-2 bg-[var(--primary)] animate-pulse" />
                    {uploadProgress}
                  </div>
                  <div className="flex items-center gap-2">
                    {(['reading', 'chunking', 'pii', 'embedding', 'saving'] as const).map(step => (
                      <div key={step} className="flex items-center gap-1">
                        <div className={`w-1.5 h-1.5 ${
                          step === uploadStep ? 'bg-[var(--primary)] animate-pulse' :
                          (['reading', 'chunking', 'pii', 'embedding', 'saving'].indexOf(step) < ['reading', 'chunking', 'pii', 'embedding', 'saving'].indexOf(uploadStep)) ? 'bg-[var(--success)]' :
                          'bg-[var(--border)]'
                        }`} />
                        <span className={`text-[10px] ${step === uploadStep ? 'text-[var(--foreground)]' : 'text-[var(--muted-foreground)]'}`}>
                          {STEP_LABELS[step]}
                        </span>
                        {step !== 'saving' && <ChevronRight className="w-2.5 h-2.5 text-[var(--border)]" />}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Embedding notice */}
            {!hasEmbeddings && (
              <div className="mx-5 mt-4 px-3 py-2 bg-[var(--warning)]/10 border border-[var(--warning)]/20 flex items-center gap-2">
                <AlertCircle className="w-3.5 h-3.5 text-[var(--warning)] shrink-0" />
                <span className="text-[11px] text-[var(--muted-foreground)]">
                  No embedding API configured. Using keyword search (less accurate). Add an embedding key in <span className="text-[var(--foreground)]">Settings</span> for vector search.
                </span>
              </div>
            )}

            {/* Privacy notice */}
            <div className="mx-5 mt-3 px-3 py-2 bg-[var(--primary)]/5 border border-[var(--primary)]/20 flex items-center gap-2">
              <Shield className="w-3.5 h-3.5 text-[var(--primary)] shrink-0" />
              <span className="text-[11px] text-[var(--muted-foreground)]">
                Documents are <span className="text-[var(--primary)] font-medium">pseudonymized before embedding</span>. PII is replaced with tokens before any content reaches the embedding or LLM API.
              </span>
            </div>

            {/* Document list / Drop zone */}
            <div
              className="flex-1 overflow-auto p-5"
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
            >
              {dragOver && (
                <div className="absolute inset-0 z-40 bg-[var(--primary)]/5 border-2 border-dashed border-[var(--primary)] flex items-center justify-center m-5">
                  <div className="text-center">
                    <Upload className="w-8 h-8 text-[var(--primary)] mx-auto mb-2" />
                    <p className="text-sm text-[var(--primary)] font-medium">Drop files here</p>
                  </div>
                </div>
              )}

              {(documents || []).length === 0 ? (
                <div
                  className="flex flex-col items-center justify-center h-64 text-center border-2 border-dashed border-[var(--border)] cursor-pointer hover:border-[var(--primary)]/50 transition-colors"
                  onClick={() => fileInputRef.current?.click()}
                >
                  <Upload className="w-8 h-8 text-[var(--muted-foreground)] opacity-30 mb-3" />
                  <p className="text-sm text-[var(--muted-foreground)]">Drop files here or click to upload</p>
                  <p className="text-[11px] text-[var(--muted-foreground)] mt-1">
                    Supports .txt, .md, .csv, .json, .pdf
                  </p>
                  <div className="flex items-center gap-3 mt-3 text-[10px] text-[var(--muted-foreground)]">
                    <span className="px-2 py-0.5 bg-[var(--secondary)]">Upload</span>
                    <ChevronRight className="w-2.5 h-2.5" />
                    <span className="px-2 py-0.5 bg-[var(--secondary)]">Chunk</span>
                    <ChevronRight className="w-2.5 h-2.5" />
                    <span className="px-2 py-0.5 bg-[var(--primary)]/10 text-[var(--primary)]">PII Scan</span>
                    <ChevronRight className="w-2.5 h-2.5" />
                    <span className="px-2 py-0.5 bg-[var(--primary)]/10 text-[var(--primary)]">Embed</span>
                    <ChevronRight className="w-2.5 h-2.5" />
                    <span className="px-2 py-0.5 bg-[var(--secondary)]">Index</span>
                  </div>
                </div>
              ) : (
                <div className="space-y-1">
                  <div className="grid grid-cols-[1fr_80px_80px_80px_100px_40px] gap-3 px-3 py-1.5 text-[10px] uppercase tracking-wider text-[var(--muted-foreground)]">
                    <span>Name</span>
                    <span>Type</span>
                    <span>Size</span>
                    <span>Chunks</span>
                    <span>PII Found</span>
                    <span></span>
                  </div>
                  {(documents || []).map(doc => {
                    const Icon = FILE_ICONS[doc.file_type] || FileText
                    return (
                      <div key={doc.id} className="grid grid-cols-[1fr_80px_80px_80px_100px_40px] gap-3 items-center px-3 py-2 bg-[var(--card)] border border-[var(--border)] group">
                        <div className="flex items-center gap-2 min-w-0">
                          <Icon className="w-3.5 h-3.5 text-[var(--muted-foreground)] shrink-0" />
                          <span className="text-[12px] truncate">{doc.name}</span>
                        </div>
                        <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
                          {doc.file_type.split('/').pop()}
                        </span>
                        <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
                          {formatBytes(doc.size_bytes)}
                        </span>
                        <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
                          {doc.chunk_count}
                        </span>
                        <div className="flex items-center gap-1">
                          {doc.detection_count > 0 ? (
                            <span className="flex items-center gap-1 text-[11px] font-mono text-[var(--primary)]">
                              <Eye className="w-3 h-3" />
                              {doc.detection_count}
                            </span>
                          ) : (
                            <span className="text-[11px] text-[var(--muted-foreground)]">Clean</span>
                          )}
                        </div>
                        <button
                          onClick={() => handleDeleteDoc(doc)}
                          className="opacity-0 group-hover:opacity-100 p-1 text-[var(--destructive)] hover:bg-[var(--destructive)]/10"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    )
                  })}

                  {/* Drop zone below document list */}
                  <div
                    className="flex items-center justify-center py-4 border-2 border-dashed border-[var(--border)] cursor-pointer hover:border-[var(--primary)]/50 transition-colors mt-3"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    <div className="flex items-center gap-2 text-[11px] text-[var(--muted-foreground)]">
                      <Upload className="w-3.5 h-3.5" />
                      Drop more files here or click to upload
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* How it works footer */}
            <div className="px-5 pb-4">
              <div className="bg-[var(--card)] border border-[var(--border)] p-4">
                <h3 className="text-[10px] uppercase tracking-wider text-[var(--muted-foreground)] mb-2">Pipeline</h3>
                <div className="flex items-center gap-3 text-[11px] text-[var(--muted-foreground)]">
                  <span className="px-2 py-0.5 bg-[var(--secondary)]">Upload</span>
                  <ChevronRight className="w-3 h-3" />
                  <span className="px-2 py-0.5 bg-[var(--secondary)]">Chunk (512 chars)</span>
                  <ChevronRight className="w-3 h-3" />
                  <span className="px-2 py-0.5 bg-[var(--primary)]/10 text-[var(--primary)]">Pseudonymize PII</span>
                  <ChevronRight className="w-3 h-3" />
                  <span className={`px-2 py-0.5 ${hasEmbeddings ? 'bg-[var(--success)]/10 text-[var(--success)]' : 'bg-[var(--secondary)]'}`}>
                    {hasEmbeddings ? 'Embed (vector)' : 'TF-IDF (keyword)'}
                  </span>
                  <ChevronRight className="w-3 h-3" />
                  <span className="px-2 py-0.5 bg-[var(--secondary)]">Index</span>
                  <ChevronRight className="w-3 h-3" />
                  <span className="px-2 py-0.5 bg-[var(--primary)]/10 text-[var(--primary)]">Safe RAG</span>
                </div>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
            <Database className="w-10 h-10 text-[var(--primary)] mb-4 opacity-60" />
            <h2 className="text-lg font-semibold mb-1">Knowledge Base</h2>
            <p className="text-xs text-[var(--muted-foreground)] max-w-sm mb-1">
              Upload documents and build privacy-safe RAG chatbots.
              Every document is pseudonymized before embedding or LLM access.
            </p>
            <p className="text-[10px] text-[var(--muted-foreground)] font-mono mb-4">
              Supports .txt, .md, .csv, .json, .pdf
            </p>
            <button
              onClick={() => setShowCreate(true)}
              className="flex items-center gap-1.5 px-4 py-2 bg-[var(--primary)] text-white text-[13px] font-medium hover:opacity-90"
            >
              <Plus className="w-3.5 h-3.5" />
              Create Knowledge Base
            </button>

            {!hasEmbeddings && (
              <p className="text-[10px] text-[var(--warning)] mt-4">
                No embedding API configured — add one in Settings for vector search
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
