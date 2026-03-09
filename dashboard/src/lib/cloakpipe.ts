/**
 * Client-side CloakPipe detection & pseudonymization engine.
 * Ports the core regex patterns from the Rust cloakpipe-core crate.
 */

export interface DetectedEntity {
  original: string
  token: string
  category: string
  start: number
  end: number
}

interface TokenVault {
  tokenToOriginal: Map<string, string>
  originalToToken: Map<string, string>
  counters: Map<string, number>
}

const PATTERNS: { category: string; prefix: string; regex: RegExp }[] = [
  // Secrets (API keys, tokens) — must come before generic patterns
  {
    category: 'Secret',
    prefix: 'SECRET',
    regex: /(?:sk|pk|api|key|token|secret|password|bearer|auth)[_-]?[a-zA-Z0-9]{20,}/gi,
  },
  // Emails
  {
    category: 'Email',
    prefix: 'EMAIL',
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  },
  // Phone numbers
  {
    category: 'Phone',
    prefix: 'PHONE',
    regex: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
  },
  // IP addresses
  {
    category: 'IP',
    prefix: 'IP',
    regex: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  },
  // Financial amounts
  {
    category: 'Amount',
    prefix: 'AMOUNT',
    regex: /\$[\d,]+(?:\.\d{2})?/g,
  },
  // Dates (various formats)
  {
    category: 'Date',
    prefix: 'DATE',
    regex: /\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s*\d{4})\b/gi,
  },
  // SSN
  {
    category: 'SSN',
    prefix: 'SSN',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  // Credit card numbers
  {
    category: 'CreditCard',
    prefix: 'CC',
    regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
  },
]

function createVault(): TokenVault {
  return {
    tokenToOriginal: new Map(),
    originalToToken: new Map(),
    counters: new Map(),
  }
}

function getOrCreateToken(vault: TokenVault, original: string, prefix: string): string {
  const existing = vault.originalToToken.get(original)
  if (existing) return existing

  const count = (vault.counters.get(prefix) || 0) + 1
  vault.counters.set(prefix, count)
  const token = `<${prefix}_${count}>`

  vault.tokenToOriginal.set(token, original)
  vault.originalToToken.set(original, token)
  return token
}

export function detect(text: string): DetectedEntity[] {
  const entities: DetectedEntity[] = []
  const seen = new Set<string>() // avoid overlapping matches

  for (const pattern of PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags)
    let match: RegExpExecArray | null

    while ((match = regex.exec(text)) !== null) {
      const start = match.index
      const end = start + match[0].length
      const key = `${start}:${end}`

      // Skip if overlaps with an already-detected entity
      let overlaps = false
      for (const s of seen) {
        const [es, ee] = s.split(':').map(Number)
        if (start < ee && end > es) { overlaps = true; break }
      }
      if (overlaps) continue

      seen.add(key)
      entities.push({
        original: match[0],
        token: '', // filled during pseudonymize
        category: pattern.category,
        start,
        end,
      })
    }
  }

  // Sort by position (descending) for safe replacement
  entities.sort((a, b) => b.start - a.start)
  return entities
}

export function pseudonymize(text: string, vault?: TokenVault): { output: string; entities: DetectedEntity[]; vault: TokenVault } {
  const v = vault || createVault()
  const entities = detect(text)

  let output = text
  for (const entity of entities) {
    const token = getOrCreateToken(v, entity.original, PATTERNS.find(p => p.category === entity.category)!.prefix)
    entity.token = token
    output = output.slice(0, entity.start) + token + output.slice(entity.end)
  }

  // Re-sort ascending for display
  entities.sort((a, b) => a.start - b.start)
  return { output, entities, vault: v }
}

export function rehydrate(text: string, vault: TokenVault): string {
  let output = text
  for (const [token, original] of vault.tokenToOriginal) {
    // Replace all occurrences of the token
    while (output.includes(token)) {
      output = output.replace(token, original)
    }
  }
  return output
}

export { createVault, type TokenVault }
