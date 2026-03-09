/**
 * Client-side document chunking and retrieval engine.
 * Supports both TF-IDF keyword search (fallback) and embedding-based vector search.
 * All content is pseudonymized BEFORE being sent to any embedding API.
 */

export interface Chunk {
  id: string
  docId: string
  content: string
  pseudonymizedContent: string
  chunkIndex: number
  pageNumber: number
  embedding?: number[]
}

export interface RetrievalResult {
  chunk: Chunk
  score: number
}

export interface EmbeddingConfig {
  provider: 'openai' | 'voyage' | 'gemini'
  apiKey: string
  model: string
}

// --- Embedding API ---

const EMBEDDING_ENDPOINTS: Record<string, string> = {
  openai: 'https://api.openai.com/v1/embeddings',
  voyage: 'https://api.voyageai.com/v1/embeddings',
  gemini: 'https://generativelanguage.googleapis.com/v1beta/openai/embeddings',
}

const DEFAULT_MODELS: Record<string, string> = {
  openai: 'text-embedding-3-small',
  voyage: 'voyage-3-lite',
  gemini: 'text-embedding-004',
}

/** Generate embeddings for an array of texts using the configured provider */
export async function generateEmbeddings(
  texts: string[],
  config: EmbeddingConfig,
  onProgress?: (done: number, total: number) => void
): Promise<number[][]> {
  const endpoint = EMBEDDING_ENDPOINTS[config.provider]
  if (!endpoint) throw new Error(`Unknown embedding provider: ${config.provider}`)

  const batchSize = config.provider === 'voyage' ? 128 : 100
  const allEmbeddings: number[][] = []
  let processed = 0

  for (let i = 0; i < texts.length; i += batchSize) {
    const batch = texts.slice(i, i + batchSize)

    const headers: Record<string, string> = { 'Content-Type': 'application/json' }

    if (config.provider === 'voyage') {
      headers['Authorization'] = `Bearer ${config.apiKey}`
    } else if (config.provider === 'gemini') {
      headers['Authorization'] = `Bearer ${config.apiKey}`
    } else {
      headers['Authorization'] = `Bearer ${config.apiKey}`
    }

    const body: Record<string, unknown> = {
      model: config.model || DEFAULT_MODELS[config.provider],
      input: batch,
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Embedding API error (${response.status}): ${error}`)
    }

    const data = await response.json()
    const embeddings = data.data
      .sort((a: { index: number }, b: { index: number }) => a.index - b.index)
      .map((d: { embedding: number[] }) => d.embedding)

    allEmbeddings.push(...embeddings)
    processed += batch.length
    onProgress?.(processed, texts.length)
  }

  return allEmbeddings
}

/** Generate embedding for a single query */
export async function embedQuery(text: string, config: EmbeddingConfig): Promise<number[]> {
  const [embedding] = await generateEmbeddings([text], config)
  return embedding
}

// --- Vector Search ---

/** Cosine similarity between two vectors */
function cosineSimilarity(a: number[], b: number[]): number {
  let dotProduct = 0
  let normA = 0
  let normB = 0
  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i]
    normA += a[i] * a[i]
    normB += b[i] * b[i]
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB)
  return denom === 0 ? 0 : dotProduct / denom
}

/** Vector similarity search using embeddings */
export function vectorSearch(queryEmbedding: number[], chunks: Chunk[], topK = 5): RetrievalResult[] {
  const results: RetrievalResult[] = chunks
    .filter(c => c.embedding && c.embedding.length > 0)
    .map(chunk => ({
      chunk,
      score: cosineSimilarity(queryEmbedding, chunk.embedding!),
    }))

  return results
    .sort((a, b) => b.score - a.score)
    .slice(0, topK)
    .filter(r => r.score > 0.3) // minimum similarity threshold
}

// --- TF-IDF Fallback ---

const CHUNK_SIZE = 512
const CHUNK_OVERLAP = 64
const STOP_WORDS = new Set([
  'a', 'an', 'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
  'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been',
  'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
  'could', 'should', 'may', 'might', 'shall', 'can', 'it', 'its', 'this',
  'that', 'these', 'those', 'i', 'me', 'my', 'we', 'our', 'you', 'your',
  'he', 'she', 'they', 'them', 'their', 'what', 'which', 'who', 'whom',
  'not', 'no', 'so', 'if', 'as', 'then', 'than', 'too', 'very',
])

/** Split text into overlapping chunks by character count, respecting sentence boundaries */
export function chunkText(text: string, chunkSize = CHUNK_SIZE, overlap = CHUNK_OVERLAP): string[] {
  if (text.length <= chunkSize) return [text.trim()].filter(Boolean)

  const chunks: string[] = []
  let start = 0

  while (start < text.length) {
    let end = Math.min(start + chunkSize, text.length)

    if (end < text.length) {
      const slice = text.slice(start, end)
      const lastPeriod = Math.max(slice.lastIndexOf('. '), slice.lastIndexOf('.\n'), slice.lastIndexOf('?\n'), slice.lastIndexOf('!\n'))
      if (lastPeriod > chunkSize * 0.3) {
        end = start + lastPeriod + 1
      }
    }

    const chunk = text.slice(start, end).trim()
    if (chunk) chunks.push(chunk)

    start = end - overlap
    if (start >= text.length) break
  }

  return chunks
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^\w\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 1 && !STOP_WORDS.has(w))
}

function termFrequency(terms: string[]): Map<string, number> {
  const tf = new Map<string, number>()
  for (const term of terms) {
    tf.set(term, (tf.get(term) || 0) + 1)
  }
  for (const [term, count] of tf) {
    tf.set(term, count / terms.length)
  }
  return tf
}

/** TF-IDF keyword search (used when no embedding API is configured) */
export function keywordSearch(query: string, chunks: Chunk[], topK = 5): RetrievalResult[] {
  const queryTerms = tokenize(query)
  if (queryTerms.length === 0) return []

  const docCount = chunks.length
  const docFreq = new Map<string, number>()

  const chunkTerms = chunks.map(c => {
    const terms = tokenize(c.pseudonymizedContent || c.content)
    for (const term of new Set(terms)) {
      docFreq.set(term, (docFreq.get(term) || 0) + 1)
    }
    return terms
  })

  const results: RetrievalResult[] = chunks.map((chunk, i) => {
    const tf = termFrequency(chunkTerms[i])
    let score = 0

    for (const qTerm of queryTerms) {
      const tfVal = tf.get(qTerm) || 0
      if (tfVal === 0) continue
      const df = docFreq.get(qTerm) || 1
      const idf = Math.log(1 + docCount / df)
      score += tfVal * idf
    }

    const lowerContent = (chunk.pseudonymizedContent || chunk.content).toLowerCase()
    if (lowerContent.includes(query.toLowerCase())) {
      score *= 2
    }

    return { chunk, score }
  })

  return results
    .filter(r => r.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, topK)
}

/** Unified search: uses vector search if embeddings available, falls back to keyword */
export function search(query: string, chunks: Chunk[], topK = 5, queryEmbedding?: number[]): RetrievalResult[] {
  const hasEmbeddings = chunks.some(c => c.embedding && c.embedding.length > 0)

  if (hasEmbeddings && queryEmbedding) {
    return vectorSearch(queryEmbedding, chunks, topK)
  }

  return keywordSearch(query, chunks, topK)
}

/** Parse page numbers from text content */
export function detectPages(text: string): Map<number, string> {
  const pages = new Map<number, string>()
  const parts = text.split(/(?:\f|--- ?Page \d+ ?---|\[Page \d+\])/i)
  parts.forEach((part, i) => {
    if (part.trim()) pages.set(i + 1, part.trim())
  })
  if (pages.size === 0) pages.set(1, text)
  return pages
}

/** Build context prompt from retrieved chunks */
export function buildContextPrompt(results: RetrievalResult[], query: string): string {
  if (results.length === 0) return query

  const context = results
    .map((r, i) => `[Source ${i + 1} | Page ${r.chunk.pageNumber}]\n${r.chunk.pseudonymizedContent || r.chunk.content}`)
    .join('\n\n')

  return `Use the following context to answer the question. If the answer isn't in the context, say so. Cite source numbers when possible.\n\n---\n${context}\n---\n\nQuestion: ${query}`
}
