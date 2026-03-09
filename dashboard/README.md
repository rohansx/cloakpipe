# CloakPipe Dashboard

Admin dashboard and privacy-aware chat interface for CloakPipe. Built with React, TypeScript, Tailwind CSS, and [PowerSync](https://www.powersync.com/) for local-first SQLite sync.

## Features

- **Privacy Chat** — ChatGPT-like interface with built-in pseudonymization. PII is detected and replaced with tokens in your browser before reaching the LLM. The AI never sees your real data.
- **Real-time Privacy Shield** — See exactly what gets pseudonymized as you type, with live before/after preview.
- **Detection Feed** — Real-time entity detection log across all conversations.
- **Overview Dashboard** — Detection volume charts, category breakdowns, and usage stats.
- **Compliance & Audit** — SOC2 summary, audit trail, CSV/JSON export.
- **Policy Management** — Configure detection categories per industry profile.
- **Settings** — LLM API key management (stored locally), organization config, alerts.
- **Light/Dark Mode** — Enterprise teal theme with sharp corners.
- **Local-First** — All data lives in your browser's SQLite (via PowerSync OPFS). Works offline. Optional cloud sync via Supabase.

## Quick Start

```bash
cd dashboard
npm install
npm run dev
```

Opens at `http://localhost:5173`. Runs in **demo mode** by default — no backend needed. Demo data is auto-seeded on first load.

## Adding Your LLM API Key

1. Open the dashboard → **Settings**
2. Under **LLM Provider**, select OpenAI or Anthropic
3. Paste your API key and click **Save**
4. Go to **Chat** and start chatting — your messages are automatically pseudonymized

The API key is stored in your browser's local SQLite database. It never leaves your machine.

## How the Chat Works

```
You type:        "Send $1.2M to alice@acme.com by March 15, 2026"
                                    ↓
CloakPipe        Detects: $1.2M, alice@acme.com, March 15, 2026
Engine:          Replaces with tokens
                                    ↓
LLM sees:        "Send <AMOUNT_1> to <EMAIL_1> by <DATE_1>"
                                    ↓
Response:        "<AMOUNT_1> transfer to <EMAIL_1> scheduled for <DATE_1>"
                                    ↓
You see:         "$1.2M transfer to alice@acme.com scheduled for March 15, 2026"
```

The detection engine runs entirely in your browser — no proxy or server needed.

## Detection Categories

The built-in JS detection engine covers:

| Category | Examples |
|----------|----------|
| Emails | `alice@acme.com` |
| Phone Numbers | `(555) 123-4567`, `+1-555-123-4567` |
| IP Addresses | `192.168.1.1` |
| Financial Amounts | `$1.2M`, `$50,000.00` |
| Dates | `03/15/2026`, `March 15, 2026` |
| Secrets | `sk-proj-abc123...`, `AKIA...` |
| SSNs | `123-45-6789` |
| Credit Cards | `4111 1111 1111 1111` |

## Cloud Sync (Optional)

To enable cloud sync with Supabase + PowerSync:

```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-key
VITE_POWERSYNC_URL=https://your-instance.powersync.journeyapps.com
```

Without these variables, the dashboard runs in local-only demo mode.

## Tech Stack

- [React](https://react.dev/) + [TypeScript](https://www.typescriptlang.org/)
- [Tailwind CSS v4](https://tailwindcss.com/)
- [PowerSync](https://www.powersync.com/) — local-first SQLite (OPFS)
- [Vite](https://vite.dev/)
- [Recharts](https://recharts.org/) — charts
- [Lucide](https://lucide.dev/) — icons

## Project Structure

```
dashboard/
├── src/
│   ├── components/     # Layout, StatCard
│   ├── lib/
│   │   ├── cloakpipe.ts        # JS detection & pseudonymization engine
│   │   ├── powersync/           # PowerSync schema, provider, connector
│   │   └── supabase.ts          # Supabase client
│   └── pages/
│       ├── Chat.tsx             # Privacy chat interface
│       ├── Dashboard.tsx        # Overview with charts
│       ├── DetectionFeed.tsx    # Detection log
│       ├── Compliance.tsx       # Audit & compliance
│       ├── Instances.tsx        # Instance management
│       ├── Policies.tsx         # Detection policies
│       └── Settings.tsx         # API keys, org config
├── index.html
├── vite.config.ts
└── package.json
```
