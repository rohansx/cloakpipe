import { PowerSyncContext } from '@powersync/react';
import { PowerSyncDatabase } from '@powersync/web';
import { type ReactNode, useEffect, useState } from 'react';
import { AppSchema } from './schema';
import { SupabaseConnector } from './SupabaseConnector';

const DEMO_MODE = !import.meta.env.VITE_POWERSYNC_URL;

let db: PowerSyncDatabase | null = null;

function getDatabase(): PowerSyncDatabase {
  if (!db) {
    db = new PowerSyncDatabase({
      schema: AppSchema,
      database: { dbFilename: 'cloakpipe-admin.db' },
    });
  }
  return db;
}

export function PSProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [database] = useState(getDatabase);

  useEffect(() => {
    async function init() {
      if (!DEMO_MODE) {
        const connector = new SupabaseConnector();
        await database.connect(connector);
      } else {
        await database.init();
        await seedDemoData(database);
      }
      setReady(true);
    }
    init();
  }, [database]);

  if (!ready) {
    return (
      <div className="flex h-screen items-center justify-center bg-[var(--background)]">
        <div className="text-sm text-[var(--muted-foreground)]">Initializing database...</div>
      </div>
    );
  }

  return (
    <PowerSyncContext.Provider value={database}>
      {children}
    </PowerSyncContext.Provider>
  );
}

async function seedDemoData(db: PowerSyncDatabase) {
  const existing = await db.getAll('SELECT id FROM instances LIMIT 1');
  if (existing.length > 0) return;

  const orgId = 'org-001';
  const now = new Date().toISOString();

  await db.execute(
    `INSERT INTO organizations (id, name, default_profile, created_at) VALUES (?, ?, ?, ?)`,
    [orgId, 'Acme Corp', 'fintech', now]
  );

  const instances = [
    ['inst-001', 'prod-openai', 'api-srv-01.internal', 'https://api.openai.com', 'fintech', '0.0.0.0:8900', 'active', '0.6.0'],
    ['inst-002', 'prod-anthropic', 'api-srv-02.internal', 'https://api.anthropic.com', 'general', '0.0.0.0:8901', 'active', '0.6.0'],
    ['inst-003', 'staging', 'staging-01.internal', 'https://api.openai.com', 'healthcare', '0.0.0.0:8902', 'degraded', '0.5.0'],
  ];

  for (const [id, name, hostname, upstream, profile, listen, status, version] of instances) {
    await db.execute(
      `INSERT INTO instances (id, org_id, name, hostname, upstream, profile, listen_addr, status, version, last_heartbeat, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, orgId, name, hostname, upstream, profile, listen, status, version, now, now]
    );
  }

  const categories = ['Email', 'Amount', 'Secret', 'Person', 'Organization', 'Date', 'Phone', 'IP'];
  const sources = ['Regex', 'Financial', 'NER', 'Custom'];
  const instanceIds = ['inst-001', 'inst-002', 'inst-003'];

  for (let i = 0; i < 200; i++) {
    const cat = categories[i % categories.length];
    const src = sources[i % sources.length];
    const instId = instanceIds[i % instanceIds.length];
    const ts = new Date(Date.now() - i * 180000).toISOString();
    await db.execute(
      `INSERT INTO detections (id, org_id, instance_id, category, token, source, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [`det-${String(i).padStart(4, '0')}`, orgId, instId, cat, `${cat.toUpperCase()}_${i + 1}`, src, ts]
    );
  }

  for (let d = 0; d < 14; d++) {
    const date = new Date(Date.now() - d * 86400000).toISOString().split('T')[0];
    const reqs = 1200 + Math.floor(Math.random() * 900);
    const dets = reqs * 2 + Math.floor(Math.random() * 500);
    await db.execute(
      `INSERT INTO usage_stats (id, org_id, instance_id, date, requests, detections) VALUES (?, ?, ?, ?, ?, ?)`,
      [`stat-${d}`, orgId, null, date, reqs, dets]
    );
  }

  const policies = [
    ['pol-001', 'Default Policy', 'general', '["secrets","financial","dates","emails"]', '{}', 1],
    ['pol-002', 'Fintech Strict', 'fintech', '["secrets","financial","dates","emails","ip_addresses","urls_internal"]', '{"high_volume_threshold":100}', 0],
    ['pol-003', 'Healthcare HIPAA', 'healthcare', '["secrets","dates","emails","phone_numbers"]', '{}', 0],
  ];

  for (const [id, name, profile, cats, rules, isDefault] of policies) {
    await db.execute(
      `INSERT INTO policies (id, org_id, name, profile, categories, alert_rules, is_default, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, orgId, name, profile, cats, rules, isDefault, now]
    );
  }

  const auditActions = [
    ['Policy updated', 'policy', 'pol-001'],
    ['Instance registered', 'instance', 'inst-001'],
    ['API key created', 'api_key', 'key-001'],
    ['Detection policy changed', 'policy', 'pol-002'],
    ['Instance heartbeat missed', 'instance', 'inst-003'],
    ['Compliance report exported', 'report', null],
    ['User role updated', 'user', 'user-002'],
    ['Instance registered', 'instance', 'inst-002'],
  ];

  for (let i = 0; i < auditActions.length; i++) {
    const [action, resType, resId] = auditActions[i];
    const ts = new Date(Date.now() - i * 3600000).toISOString();
    await db.execute(
      `INSERT INTO audit_log (id, org_id, user_id, action, resource_type, resource_id, metadata, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [`audit-${i}`, orgId, 'user-001', action, resType, resId, '{}', ts]
    );
  }

  const apiKeysData = [
    ['key-001', 'Backend Service', 'cpk_live_abc1...', 842],
    ['key-002', 'RAG Pipeline', 'cpk_live_def2...', 321],
    ['key-003', 'Staging', 'cpk_test_ghi3...', 120],
  ];

  for (const [id, name, prefix, reqs] of apiKeysData) {
    await db.execute(
      `INSERT INTO api_keys (id, org_id, name, key_prefix, key_hash, created_by, last_used, requests, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, orgId, name, prefix, 'hash', 'user-001', now, reqs, now]
    );
  }
}
