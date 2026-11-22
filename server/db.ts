import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type {
  AuditLogEntry,
  FlowRecord,
  GatewaySettings,
  IncidentRecord,
  RagDocument,
  ScheduledReportEntry,
  Tier0Entry,
  Tier1Prototype,
} from '../src/types/soc.js';

const DB_PATH = path.resolve(process.cwd(), 'aegisflow_soc.db');

function removeDbFiles(basePath: string): void {
  for (const suffix of ['', '-wal', '-shm']) {
    const file = `${basePath}${suffix}`;
    try {
      if (fs.existsSync(file)) fs.unlinkSync(file);
    } catch {
      // Ignore cleanup race
    }
  }
}

function openHealthyDatabase(dbPath: string): Database.Database {
  const configure = (conn: Database.Database) => {
    conn.pragma('busy_timeout = 5000');
    conn.pragma('journal_mode = WAL');
    conn.pragma('synchronous = FULL');
    conn.pragma('wal_autocheckpoint = 200');
    conn.pragma('foreign_keys = ON');
  };

  try {
    const candidate = new Database(dbPath);
    configure(candidate);
    const check = candidate.pragma('quick_check', { simple: true });
    if (check !== 'ok') {
      candidate.close();
      throw new Error(`SQLite quick_check failed: ${String(check)}`);
    }
    return candidate;
  } catch (err) {
    console.warn(
      `[AegisFlow DB] Detected corrupted SQLite store (${err instanceof Error ? err.message : 'unknown error'}). Rebuilding clean database...`
    );
    removeDbFiles(dbPath);
    const fresh = new Database(dbPath);
    configure(fresh);
    return fresh;
  }
}

export const db = openHealthyDatabase(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY,
    timestamp_utc TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    simhash64 TEXT NOT NULL,
    zone TEXT NOT NULL,
    verdict TEXT NOT NULL,
    label TEXT NOT NULL,
    closed_nearest_class TEXT NOT NULL,
    confidence REAL NOT NULL,
    meta_ood_score REAL NOT NULL,
    tau_amber REAL NOT NULL,
    tau_red REAL NOT NULL,
    shannon_entropy REAL NOT NULL,
    epistemic_jsd REAL NOT NULL,
    bypass_stage TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    incident_id TEXT,
    cusum_drift REAL NOT NULL,
    hawkes_intensity REAL NOT NULL,
    martingale_value REAL NOT NULL,
    raw_features_json TEXT NOT NULL,
    embedding_json TEXT,
    xai_json TEXT,
    rag_json TEXT,
    llm_brief_json TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(timestamp_utc DESC);
  CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip, timestamp_utc DESC);
  CREATE INDEX IF NOT EXISTS idx_flows_zone ON flows(zone);
  CREATE INDEX IF NOT EXISTS idx_flows_simhash ON flows(simhash64);

  CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    created_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    simhash64 TEXT NOT NULL,
    zone TEXT NOT NULL,
    status TEXT NOT NULL,
    label TEXT NOT NULL,
    original_label TEXT NOT NULL,
    closed_nearest_class TEXT NOT NULL,
    repeat_hit_count INTEGER NOT NULL DEFAULT 1,
    polymorphic_count INTEGER NOT NULL DEFAULT 0,
    meta_ood_score REAL NOT NULL,
    confidence REAL NOT NULL,
    shannon_entropy REAL NOT NULL DEFAULT 0,
    epistemic_jsd REAL NOT NULL DEFAULT 0,
    cusum_drift REAL NOT NULL DEFAULT 0,
    hawkes_intensity REAL NOT NULL DEFAULT 0,
    martingale_value REAL NOT NULL DEFAULT 1,
    xai_json TEXT,
    rag_json TEXT,
    llm_brief_json TEXT,
    containment_rule TEXT NOT NULL DEFAULT '',
    gate_e9_json TEXT,
    rule_approved INTEGER NOT NULL DEFAULT 0,
    approved_by TEXT,
    approved_utc TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, last_seen_utc DESC);
  CREATE INDEX IF NOT EXISTS idx_incidents_simhash ON incidents(simhash64);

  CREATE TABLE IF NOT EXISTS tier0_cache (
    simhash64 TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    entry_type TEXT NOT NULL,
    label TEXT NOT NULL,
    incident_id TEXT,
    created_utc TEXT NOT NULL,
    last_hit_utc TEXT NOT NULL,
    expires_utc TEXT NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 0,
    max_rate_per_min INTEGER NOT NULL DEFAULT 30,
    source TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS tier1_prototypes (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    bank_type TEXT NOT NULL,
    label TEXT NOT NULL,
    incident_id TEXT,
    simhash64 TEXT NOT NULL,
    embedding_json TEXT NOT NULL,
    created_utc TEXT NOT NULL,
    source TEXT NOT NULL,
    sigma_local REAL NOT NULL DEFAULT 0.06,
    active INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS rag_kb (
    id TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    ref_id TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    content TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    port_hints_json TEXT NOT NULL,
    updated_utc TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    target_id TEXT NOT NULL,
    details_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS prompt_cache (
    cache_key TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_utc TEXT NOT NULL,
    expires_utc TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS scheduled_reports (
    id TEXT PRIMARY KEY,
    generated_utc TEXT NOT NULL,
    schedule_mode TEXT NOT NULL,
    window_preset TEXT NOT NULL,
    window_label TEXT NOT NULL,
    start_utc TEXT NOT NULL,
    end_utc TEXT NOT NULL,
    posture_score INTEGER NOT NULL,
    total_flows INTEGER NOT NULL,
    red_flows INTEGER NOT NULL,
    tier0_savings_pct REAL NOT NULL,
    trigger_source TEXT NOT NULL
  );
`);

export const DEFAULT_GATEWAY_SETTINGS: GatewaySettings = {
  inference_mode: 'BUILT_IN_SANDBOX_ENGINE',
  pytorch_engine_url: process.env.PYTORCH_ENGINE_URL || 'http://127.0.0.1:8001',
  active_profile: 'NF-BoT-IoT-v2',
  failover_order: ['GEMINI', 'OPENROUTER', 'HARBOR', 'OFFLINE'],
  gemini_fast_model: 'gemini-3.1-flash-lite',
  gemini_reasoning_model: 'gemini-4-hydrogen',
  openrouter_model: 'anthropic/claude-3.7-sonnet',
  harbor_model: 'qwen2.5-coder-32b-instruct',
  daily_budget_usd: 25.0,
  daily_spend_usd: 0.42,
  daily_tokens_used: 184200,
  auto_downgrade_pct: 80,
  semantic_cache_ttl_min: 15,
  report_auto_schedule: 'SHIFT_8H',
};

export function getGatewaySettings(): GatewaySettings {
  const row = db.prepare('SELECT value_json FROM settings WHERE key = ?').get('gateway') as
    | { value_json: string }
    | undefined;
  if (!row) {
    db.prepare('INSERT OR REPLACE INTO settings (key, value_json) VALUES (?, ?)').run(
      'gateway',
      JSON.stringify(DEFAULT_GATEWAY_SETTINGS)
    );
    return { ...DEFAULT_GATEWAY_SETTINGS };
  }
  try {
    return { ...DEFAULT_GATEWAY_SETTINGS, ...JSON.parse(row.value_json) };
  } catch {
    return { ...DEFAULT_GATEWAY_SETTINGS };
  }
}

export function saveGatewaySettings(patch: Partial<GatewaySettings>): GatewaySettings {
  const current = getGatewaySettings();
  const next: GatewaySettings = {
    ...current,
    ...patch,
  };
  db.prepare('INSERT OR REPLACE INTO settings (key, value_json) VALUES (?, ?)').run(
    'gateway',
    JSON.stringify(next)
  );
  return next;
}

export function appendAuditLog(
  actor: string,
  role: string,
  action: string,
  targetId: string,
  details: Record<string, unknown>
): AuditLogEntry {
  const last = db
    .prepare('SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1')
    .get() as { entry_hash: string } | undefined;
  const prevHash = last?.entry_hash ?? '0000000000000000000000000000000000000000000000000000000000000000';
  const timestampUtc = new Date().toISOString();
  const detailsJson = JSON.stringify(details);
  const payload = `${prevHash}|${timestampUtc}|${actor}|${role}|${action}|${targetId}|${detailsJson}`;
  const entryHash = crypto.createHash('sha256').update(payload).digest('hex');

  const info = db
    .prepare(
      `INSERT INTO audit_log (timestamp_utc, actor, role, action, target_id, details_json, prev_hash, entry_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(timestampUtc, actor, role, action, targetId, detailsJson, prevHash, entryHash);

  return {
    id: Number(info.lastInsertRowid),
    timestamp_utc: timestampUtc,
    actor,
    role,
    action,
    target_id: targetId,
    details,
    prev_hash: prevHash,
    entry_hash: entryHash,
  };
}

export function verifyAuditChain(): { valid: boolean; total_entries: number; broken_at_id: number | null } {
  const rows = db
    .prepare('SELECT * FROM audit_log ORDER BY id ASC')
    .all() as Array<{
    id: number;
    timestamp_utc: string;
    actor: string;
    role: string;
    action: string;
    target_id: string;
    details_json: string;
    prev_hash: string;
    entry_hash: string;
  }>;

  let expectedPrev = '0000000000000000000000000000000000000000000000000000000000000000';
  for (const r of rows) {
    if (r.prev_hash !== expectedPrev) {
      return { valid: false, total_entries: rows.length, broken_at_id: r.id };
    }
    const payload = `${r.prev_hash}|${r.timestamp_utc}|${r.actor}|${r.role}|${r.action}|${r.target_id}|${r.details_json}`;
    const expectedHash = crypto.createHash('sha256').update(payload).digest('hex');
    if (r.entry_hash !== expectedHash) {
      return { valid: false, total_entries: rows.length, broken_at_id: r.id };
    }
    expectedPrev = r.entry_hash;
  }
  return { valid: true, total_entries: rows.length, broken_at_id: null };
}

export function listAuditLog(limit = 100): AuditLogEntry[] {
  const rows = db
    .prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?')
    .all(limit) as Array<{
    id: number;
    timestamp_utc: string;
    actor: string;
    role: string;
    action: string;
    target_id: string;
    details_json: string;
    prev_hash: string;
    entry_hash: string;
  }>;
  return rows.map((r) => ({
    id: r.id,
    timestamp_utc: r.timestamp_utc,
    actor: r.actor,
    role: r.role,
    action: r.action,
    target_id: r.target_id,
    details: JSON.parse(r.details_json),
    prev_hash: r.prev_hash,
    entry_hash: r.entry_hash,
  }));
}

export function seedInitialRagKnowledgeBase(): void {
  const count = (db.prepare('SELECT COUNT(*) as c FROM rag_kb').get() as { c: number }).c;
  if (count > 0) return;

  const now = new Date().toISOString();
  const docs: RagDocument[] = [
    {
      id: 'rag-mitre-t1498',
      source_type: 'MITRE_ATTACK_V20_1',
      ref_id: 'T1498.001',
      title: 'Network Denial of Service: Direct Network Flood',
      summary: 'High-volume SYN/UDP/HTTP packet floods exhausting target bandwidth or state tables.',
      content: 'Adversaries send high packet-per-second bursts characterized by elevated IN_PKTS, NUM_PKTS_UP_TO_128_BYTES, low TCP_WIN_MAX_IN, and zero OUT_PKTS. Mitigate via upstream rate-limiting and nftables source drop rules.',
      tags: ['ddos', 'dos', 'syn_flood', 'udp_flood', 'mirai', 'volumetric', 'flood'],
      port_hints: [80, 443, 53, 8080],
      updated_utc: now,
    },
    {
      id: 'rag-mitre-t1046',
      source_type: 'MITRE_ATTACK_V20_1',
      ref_id: 'T1046',
      title: 'Network Service Discovery & Active Scanning',
      summary: 'Adversaries probe internal or external ports using micro-burst SYN/FIN flows.',
      content: 'Reconnaissance flows exhibit short FLOW_DURATION_MILLISECONDS, high SERVER_TCP_FLAGS RST responses, small packet lengths, and elevated NUM_PKTS_UP_TO_128_BYTES across sequential ports.',
      tags: ['reconnaissance', 'scanning', 'portscan', 'probe', 'discovery', 'ambiguous'],
      port_hints: [22, 23, 80, 443, 8080, 8443, 2323],
      updated_utc: now,
    },
    {
      id: 'rag-mitre-t1041',
      source_type: 'MITRE_ATTACK_V20_1',
      ref_id: 'T1041',
      title: 'Exfiltration Over Command and Control Channel (IoT/MQTT Data Theft)',
      summary: 'Out-of-class asymmetric outbound data staging and exfiltration over non-standard brokers.',
      content: 'Zero-day theft campaigns exhibit extreme OUT_BYTES / IN_BYTES asymmetry, sustained FLOW_DURATION_MILLISECONDS, and MTU-sized NUM_PKTS_1024_TO_1514_BYTES bursts over MQTT (1883/8883) or custom TLS tunnels.',
      tags: ['theft', 'zero_day', 'exfiltration', 'mqtt', 'unknown', 'c2', 'backdoor'],
      port_hints: [1883, 8883, 4444, 8443],
      updated_utc: now,
    },
    {
      id: 'rag-mitre-t1110',
      source_type: 'MITRE_ATTACK_V20_1',
      ref_id: 'T1110',
      title: 'Brute Force & Credential Stuffing (SSH/FTP/Web)',
      summary: 'Repeated authentication probes across SSH, FTP, or HTTP login surfaces.',
      content: 'Brute-force campaigns produce repetitive medium-size handshake bursts (NUM_PKTS_128_TO_256_BYTES) with rising Hawkes kill-chain intensity following reconnaissance.',
      tags: ['brute', 'password', 'ssh', 'ftp', 'credential', 'web'],
      port_hints: [21, 22, 80, 443, 8080],
      updated_utc: now,
    },
    {
      id: 'rag-mitre-t1021',
      source_type: 'MITRE_ATTACK_V20_1',
      ref_id: 'T1021',
      title: 'Remote Services & Low-and-Slow Lateral Movement (Infilteration)',
      summary: 'Stealthy multi-flow lateral movement blending into standard TCP telemetry.',
      content: 'Single-flow inspection often scores near baseline; ChronoGraph Page-Hinkley CUSUM drift and Vovk Conformal Martingale detect persistent low-rate staging across /24 internal subnets.',
      tags: ['infilteration', 'lateral', 'stealth', 'gray_zone', 'martingale', 'cusum'],
      port_hints: [445, 3389, 8443, 5985],
      updated_utc: now,
    },
    {
      id: 'rag-nist-contain',
      source_type: 'NIST_SP_800_61R3',
      ref_id: 'NIST-RS.MI-01',
      title: 'NIST SP 800-61r3 Incident Containment & Isolation Playbook',
      summary: 'CSF 2.0-aligned containment workflow with blast-radius verification and audit logging.',
      content: 'Verify host scope, simulate containment rules against benign production baseline (0.00% collateral requirement), isolate compromised IoT/edge endpoints via scoped nftables drop rules, and record human authorization.',
      tags: ['containment', 'nist', 'firewall', 'zero_day', 'ddos', 'theft', 'replay'],
      port_hints: [80, 443, 1883, 8080, 8443],
      updated_utc: now,
    },
    {
      id: 'rag-cisa-kev-1',
      source_type: 'CISA_KEV',
      ref_id: 'CVE-2024-3400',
      title: 'CISA KEV: Edge Gateway Command Injection & Unauthorized Data Egress',
      summary: 'Actively exploited remote command injection targeting network telemetry gateways.',
      content: 'Monitor unexpected outbound TLS/8443 and MQTT/1883 sessions originating from perimeter appliances with anomalous NUM_PKTS_128_TO_256_BYTES staging signatures.',
      tags: ['injection', 'exploits', 'zero_day', 'theft', 'kev', 'shellcode'],
      port_hints: [443, 8443, 1883, 8080],
      updated_utc: now,
    },
    {
      id: 'rag-cisa-kev-2',
      source_type: 'CISA_KEV',
      ref_id: 'CVE-2025-21590',
      title: 'CISA KEV: Embedded IoT Firmware Botnet Hijack & Replay Flooding',
      summary: 'Active Mirai/Gafgyt derivative exploiting embedded IoT services for volumetric floods.',
      content: 'Watch for sudden token-bucket velocity spikes on previously normal IoT telemetry hashes (VOLUMETRIC_REPLAY_ANOMALY) and Mirai UDP/SYN burst weights.',
      tags: ['mirai', 'gafgyt', 'iot', 'replay', 'ddos', 'bot', 'worms'],
      port_hints: [23, 2323, 53, 80, 1883],
      updated_utc: now,
    },
  ];

  const stmt = db.prepare(`
    INSERT INTO rag_kb (id, source_type, ref_id, title, summary, content, tags_json, port_hints_json, updated_utc)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const tx = db.transaction((items: RagDocument[]) => {
    for (const d of items) {
      stmt.run(
        d.id,
        d.source_type,
        d.ref_id,
        d.title,
        d.summary,
        d.content,
        JSON.stringify(d.tags),
        JSON.stringify(d.port_hints),
        d.updated_utc
      );
    }
  });
  tx(docs);
}

export function queryHybridRag(queryText: string, dstPort?: number, limit = 4): RagDocument[] {
  const rows = db.prepare('SELECT * FROM rag_kb ORDER BY updated_utc DESC').all() as Array<{
    id: string;
    source_type: RagDocument['source_type'];
    ref_id: string;
    title: string;
    summary: string;
    content: string;
    tags_json: string;
    port_hints_json: string;
    updated_utc: string;
  }>;

  const tokens = queryText
    .toLowerCase()
    .replace(/[^a-z0-9_.\s-]/g, ' ')
    .split(/\s+/)
    .filter((t) => t.length >= 2);

  const scored: RagDocument[] = rows.map((r) => {
    const tags: string[] = JSON.parse(r.tags_json);
    const portHints: number[] = JSON.parse(r.port_hints_json);
    const haystack = `${r.ref_id} ${r.title} ${r.summary} ${r.content} ${tags.join(' ')}`.toLowerCase();

    let score = 0;
    for (const tok of tokens) {
      if (tags.some((t) => t.includes(tok) || tok.includes(t))) score += 3.2;
      if (r.title.toLowerCase().includes(tok)) score += 2.0;
      if (haystack.includes(tok)) score += 1.0;
    }
    if (dstPort && portHints.includes(dstPort)) score += 2.8;
    if (r.source_type === 'SOC_MEMORY') score += 1.8;

    return {
      id: r.id,
      source_type: r.source_type,
      ref_id: r.ref_id,
      title: r.title,
      summary: r.summary,
      content: r.content,
      tags,
      port_hints: portHints,
      updated_utc: r.updated_utc,
      relevance_score: Number(Math.min(0.99, 0.42 + score * 0.065).toFixed(3)),
    };
  });

  scored.sort((a, b) => (b.relevance_score ?? 0) - (a.relevance_score ?? 0));
  return scored.slice(0, limit);
}

export function addSocMemoryRagEntry(
  incidentId: string,
  label: string,
  verdictNote: string,
  dstPort: number,
  topFeatures: string[]
): void {
  const id = `rag-soc-${incidentId}-${Date.now()}`;
  const now = new Date().toISOString();
  const title = `SOC Memory (${incidentId}): Confirmed ${label}`;
  const summary = `${verdictNote} Key drivers: ${topFeatures.slice(0, 3).join(', ')}.`;
  const tags = [
    label.toLowerCase(),
    ...topFeatures.slice(0, 4).map((f) => f.toLowerCase()),
    'soc_memory',
    'confirmed',
  ];

  db.prepare(`
    INSERT OR REPLACE INTO rag_kb (id, source_type, ref_id, title, summary, content, tags_json, port_hints_json, updated_utc)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    'SOC_MEMORY',
    incidentId,
    title,
    summary,
    `${summary} Port ${dstPort}. Indexed via Closed-Loop Organizational SOC Memory.`,
    JSON.stringify(tags),
    JSON.stringify([dstPort]),
    now
  );
}

export function parseFlowRow(row: Record<string, unknown>): FlowRecord {
  return {
    id: String(row.id),
    timestamp_utc: String(row.timestamp_utc),
    profile_id: String(row.profile_id),
    src_ip: String(row.src_ip),
    dst_ip: String(row.dst_ip),
    src_port: Number(row.src_port),
    dst_port: Number(row.dst_port),
    protocol: Number(row.protocol),
    simhash64: String(row.simhash64),
    zone: row.zone as FlowRecord['zone'],
    verdict: String(row.verdict),
    label: String(row.label),
    closed_nearest_class: String(row.closed_nearest_class),
    confidence: Number(row.confidence),
    meta_ood_score: Number(row.meta_ood_score),
    tau_amber: Number(row.tau_amber),
    tau_red: Number(row.tau_red),
    shannon_entropy: Number(row.shannon_entropy),
    epistemic_jsd: Number(row.epistemic_jsd),
    bypass_stage: row.bypass_stage as FlowRecord['bypass_stage'],
    latency_ms: Number(row.latency_ms),
    incident_id: row.incident_id ? String(row.incident_id) : null,
    cusum_drift: Number(row.cusum_drift),
    hawkes_intensity: Number(row.hawkes_intensity),
    martingale_value: Number(row.martingale_value),
    raw_features: row.raw_features_json ? JSON.parse(String(row.raw_features_json)) : {},
    xai: row.xai_json ? JSON.parse(String(row.xai_json)) : null,
    rag_matches: row.rag_json ? JSON.parse(String(row.rag_json)) : [],
    llm_brief: row.llm_brief_json ? JSON.parse(String(row.llm_brief_json)) : null,
  };
}

export function parseIncidentRow(row: Record<string, unknown>): IncidentRecord {
  return {
    id: String(row.id),
    created_utc: String(row.created_utc),
    last_seen_utc: String(row.last_seen_utc),
    profile_id: String(row.profile_id),
    src_ip: String(row.src_ip),
    dst_ip: String(row.dst_ip),
    dst_port: Number(row.dst_port),
    simhash64: String(row.simhash64),
    zone: row.zone as IncidentRecord['zone'],
    status: row.status as IncidentRecord['status'],
    label: String(row.label),
    original_label: String(row.original_label),
    closed_nearest_class: String(row.closed_nearest_class),
    repeat_hit_count: Number(row.repeat_hit_count),
    polymorphic_count: Number(row.polymorphic_count),
    meta_ood_score: Number(row.meta_ood_score),
    confidence: Number(row.confidence),
    shannon_entropy: Number(row.shannon_entropy),
    epistemic_jsd: Number(row.epistemic_jsd),
    cusum_drift: Number(row.cusum_drift),
    hawkes_intensity: Number(row.hawkes_intensity),
    martingale_value: Number(row.martingale_value),
    xai: row.xai_json ? JSON.parse(String(row.xai_json)) : null,
    rag_matches: row.rag_json ? JSON.parse(String(row.rag_json)) : [],
    llm_brief: row.llm_brief_json ? JSON.parse(String(row.llm_brief_json)) : null,
    containment_rule: String(row.containment_rule ?? ''),
    gate_e9: row.gate_e9_json ? JSON.parse(String(row.gate_e9_json)) : null,
    rule_approved: Boolean(row.rule_approved),
    approved_by: row.approved_by ? String(row.approved_by) : null,
    approved_utc: row.approved_utc ? String(row.approved_utc) : null,
  };
}

export function listTier0Entries(): Tier0Entry[] {
  const rows = db.prepare('SELECT * FROM tier0_cache ORDER BY active DESC, hit_count DESC, last_hit_utc DESC').all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    simhash64: String(r.simhash64),
    profile_id: String(r.profile_id),
    entry_type: r.entry_type as Tier0Entry['entry_type'],
    label: String(r.label),
    incident_id: r.incident_id ? String(r.incident_id) : null,
    created_utc: String(r.created_utc),
    last_hit_utc: String(r.last_hit_utc),
    expires_utc: String(r.expires_utc),
    hit_count: Number(r.hit_count),
    max_rate_per_min: Number(r.max_rate_per_min),
    source: r.source as Tier0Entry['source'],
    active: Boolean(r.active),
  }));
}

export function listTier1Prototypes(): Tier1Prototype[] {
  const rows = db.prepare('SELECT id, profile_id, bank_type, label, incident_id, simhash64, created_utc, source, sigma_local, active FROM tier1_prototypes ORDER BY active DESC, created_utc DESC').all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    profile_id: String(r.profile_id),
    bank_type: r.bank_type as Tier1Prototype['bank_type'],
    label: String(r.label),
    incident_id: r.incident_id ? String(r.incident_id) : null,
    simhash64: String(r.simhash64),
    created_utc: String(r.created_utc),
    source: String(r.source),
    sigma_local: Number(r.sigma_local),
    active: Boolean(r.active),
  }));
}

export function recordScheduledReport(entry: ScheduledReportEntry): void {
  db.prepare(`
    INSERT OR REPLACE INTO scheduled_reports (
      id, generated_utc, schedule_mode, window_preset, window_label, start_utc, end_utc,
      posture_score, total_flows, red_flows, tier0_savings_pct, trigger_source
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    entry.id,
    entry.generated_utc,
    entry.schedule_mode,
    entry.window_preset,
    entry.window_label,
    entry.start_utc,
    entry.end_utc,
    entry.posture_score,
    entry.total_flows,
    entry.red_flows,
    entry.tier0_savings_pct,
    entry.trigger_source
  );
}

export function listScheduledReports(limit = 20): ScheduledReportEntry[] {
  const rows = db
    .prepare('SELECT * FROM scheduled_reports ORDER BY generated_utc DESC LIMIT ?')
    .all(limit) as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    generated_utc: String(r.generated_utc),
    schedule_mode: r.schedule_mode as ScheduledReportEntry['schedule_mode'],
    window_preset: String(r.window_preset),
    window_label: String(r.window_label),
    start_utc: String(r.start_utc),
    end_utc: String(r.end_utc),
    posture_score: Number(r.posture_score),
    total_flows: Number(r.total_flows),
    red_flows: Number(r.red_flows),
    tier0_savings_pct: Number(r.tier0_savings_pct),
    trigger_source: r.trigger_source as ScheduledReportEntry['trigger_source'],
  }));
}

export function pruneOldFlows(maxGreen = 1800, maxTotal = 3800): number {
  let deleted = 0;
  const greenCount = (db.prepare("SELECT COUNT(*) as c FROM flows WHERE zone = 'GREEN'").get() as { c: number }).c;
  if (greenCount > maxGreen) {
    const excess = greenCount - maxGreen;
    const res = db
      .prepare(
        `DELETE FROM flows WHERE id IN (
          SELECT id FROM flows WHERE zone = 'GREEN' ORDER BY timestamp_utc ASC LIMIT ?
        )`
      )
      .run(excess);
    deleted += res.changes;
  }

  const totalCount = (db.prepare('SELECT COUNT(*) as c FROM flows').get() as { c: number }).c;
  if (totalCount > maxTotal) {
    const excess = totalCount - maxTotal;
    const res = db
      .prepare(
        `DELETE FROM flows WHERE id IN (
          SELECT id FROM flows ORDER BY timestamp_utc ASC LIMIT ?
        )`
      )
      .run(excess);
    deleted += res.changes;
  }

  if (deleted > 0) {
    try {
      db.pragma('wal_checkpoint(PASSIVE)');
    } catch {
      // Ignore checkpoint busy
    }
  }
  return deleted;
}

seedInitialRagKnowledgeBase();

