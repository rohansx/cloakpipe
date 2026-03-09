import { column, Schema, Table } from '@powersync/web';

const organizations = new Table({
  name: column.text,
  default_profile: column.text,
  created_at: column.text,
});

const profiles = new Table({
  org_id: column.text,
  display_name: column.text,
  role: column.text,
  created_at: column.text,
});

const instances = new Table({
  org_id: column.text,
  name: column.text,
  hostname: column.text,
  upstream: column.text,
  profile: column.text,
  listen_addr: column.text,
  status: column.text,
  version: column.text,
  last_heartbeat: column.text,
  created_at: column.text,
});

const detections = new Table({
  org_id: column.text,
  instance_id: column.text,
  category: column.text,
  token: column.text,
  source: column.text,
  timestamp: column.text,
});

const usage_stats = new Table({
  org_id: column.text,
  instance_id: column.text,
  date: column.text,
  requests: column.integer,
  detections: column.integer,
});

const policies = new Table({
  org_id: column.text,
  name: column.text,
  profile: column.text,
  categories: column.text,
  alert_rules: column.text,
  is_default: column.integer,
  created_at: column.text,
});

const audit_log = new Table({
  org_id: column.text,
  user_id: column.text,
  action: column.text,
  resource_type: column.text,
  resource_id: column.text,
  metadata: column.text,
  timestamp: column.text,
});

const api_keys = new Table({
  org_id: column.text,
  name: column.text,
  key_prefix: column.text,
  key_hash: column.text,
  created_by: column.text,
  last_used: column.text,
  requests: column.integer,
  created_at: column.text,
});

const conversations = new Table({
  org_id: column.text,
  user_id: column.text,
  title: column.text,
  model: column.text,
  created_at: column.text,
  updated_at: column.text,
});

const llm_keys = new Table({
  org_id: column.text,
  provider: column.text,
  api_key: column.text,
  created_at: column.text,
});

const chat_messages = new Table({
  conversation_id: column.text,
  user_id: column.text,
  role: column.text,
  content: column.text,
  pseudonymized_content: column.text,
  entities_json: column.text,
  entity_count: column.integer,
  created_at: column.text,
});

const knowledge_bases = new Table({
  org_id: column.text,
  name: column.text,
  description: column.text,
  document_count: column.integer,
  chunk_count: column.integer,
  total_detections: column.integer,
  created_at: column.text,
  updated_at: column.text,
});

const kb_documents = new Table({
  kb_id: column.text,
  org_id: column.text,
  name: column.text,
  file_type: column.text,
  content: column.text,
  size_bytes: column.integer,
  chunk_count: column.integer,
  detection_count: column.integer,
  created_at: column.text,
});

const kb_chunks = new Table({
  doc_id: column.text,
  kb_id: column.text,
  content: column.text,
  pseudonymized_content: column.text,
  entities_json: column.text,
  entity_count: column.integer,
  chunk_index: column.integer,
  page_number: column.integer,
  embedding: column.text, // JSON float array from embedding API
});

const embedding_keys = new Table({
  org_id: column.text,
  provider: column.text, // openai, voyage, gemini
  api_key: column.text,
  model: column.text,
  created_at: column.text,
});

const chat_instances = new Table({
  org_id: column.text,
  name: column.text,
  description: column.text,
  kb_ids: column.text,
  model: column.text,
  system_prompt: column.text,
  temperature: column.real,
  max_tokens: column.integer,
  is_public: column.integer,
  share_token: column.text,
  created_at: column.text,
  updated_at: column.text,
});

export const AppSchema = new Schema({
  organizations,
  profiles,
  instances,
  detections,
  usage_stats,
  policies,
  audit_log,
  api_keys,
  llm_keys,
  conversations,
  chat_messages,
  knowledge_bases,
  kb_documents,
  kb_chunks,
  embedding_keys,
  chat_instances,
});

export type Database = (typeof AppSchema)['types'];
