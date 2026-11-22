import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import http from 'node:http';
import path from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';
import { z } from 'zod';
import {
  appendAuditLog,
  db,
  getGatewaySettings,
  listAuditLog,
  listScheduledReports,
  listTier0Entries,
  listTier1Prototypes,
  parseFlowRow,
  parseIncidentRow,
  pruneOldFlows,
  queryHybridRag,
  recordScheduledReport,
  saveGatewaySettings,
  verifyAuditChain,
} from './server/db.js';
import {
  approveIncidentContainmentRule,
  checkPyTorchEngineHealth,
  confirmIncidentDecision,
  getChronoGraphForHost,
  ingestFlow,
  mutateFlowFeaturesForPolymorphic,
  seedInitialSocIfEmpty,
} from './server/idsEngine.js';
import { getProviderAvailability, runSocCopilotChat } from './server/llmGateway.js';
import { auditContainmentRuleGateE9 } from './server/privacyAndGateE9.js';
import { buildPresetFeatures, DATASET_PROFILES, type FlowPresetKind } from './server/profiles.js';
import {
  buildPeriodReportData,
  generateCsvLedger,
  generateDocxBuffer,
  generateHtmlReport,
  generatePdfBuffer,
  generateStix21Bundle,
} from './server/reportGenerator.js';
import type { DashboardMetrics, TriageZone } from './src/types/soc.js';

const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';

const app = express();
app.use(cors({ origin: false }));
app.use(express.json({ limit: '8mb' }));

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

function broadcastWs(type: string, payload: unknown): void {
  const msg = JSON.stringify({ type, payload, ts: Date.now() });
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(msg);
    }
  }
}

// =============================================================================
// 24/7 CONTINUOUS NETWORK MONITORING DAEMON (LIVE STREAM + RING BUFFER)
// =============================================================================
let sensorRunning = true;
let sensorRateFps = 1.5; // flows/sec when active
let sensorTimer: NodeJS.Timeout | null = null;
let lastPyTorchOnline = false;

const throughputHistory: DashboardMetrics['throughput_series'] = [];
let bucketCounts = { green: 0, yellow: 0, amber: 0, red: 0, tier0_bypass: 0 };

function pushThroughputTick(): void {
  const nowStr = new Date().toISOString().slice(11, 19);
  throughputHistory.push({
    time: nowStr,
    ...bucketCounts,
  });
  bucketCounts = { green: 0, yellow: 0, amber: 0, red: 0, tier0_bypass: 0 };
  if (throughputHistory.length > 24) throughputHistory.shift();
}

setInterval(() => {
  pushThroughputTick();
  broadcastWs('metrics:tick', computeDashboardMetrics());
}, 3500);

function recordFlowInBucket(zone: TriageZone, bypassStage: string): void {
  if (zone === 'GREEN') bucketCounts.green += 1;
  else if (zone === 'YELLOW') bucketCounts.yellow += 1;
  else if (zone === 'AMBER') bucketCounts.amber += 1;
  else if (zone === 'RED') bucketCounts.red += 1;
  if (bypassStage === 'TIER_0_ATTACK' || bypassStage === 'TIER_0_BENIGN_SUPPRESSED') {
    bucketCounts.tier0_bypass += 1;
  }
}

async function emitLiveSensorFlow(): Promise<void> {
  if (!sensorRunning) return;
  const settings = getGatewaySettings();
  const profileId = settings.active_profile;
  const r = Math.random();

  let presetKind: FlowPresetKind = 'BENIGN_NORMAL';
  let customIp: string | null = null;
  let applyPolymorphicJitter = false;

  if (r < 0.56) {
    presetKind = 'BENIGN_NORMAL';
    const hosts = ['10.20.14.22', '10.20.14.31', '10.20.14.45', '192.168.10.14', '10.20.88.12'];
    customIp = hosts[Math.floor(Math.random() * hosts.length)];
  } else if (r < 0.80) {
    // Repeat known DDoS or Zero-Day to exercise <0.05ms Tier-0 Reflex Cache!
    presetKind = Math.random() < 0.6 ? 'KNOWN_DDOS' : 'ZERO_DAY_THEFT';
  } else if (r < 0.85) {
    // Occasional slightly mutated attack variant to exercise Tier-1 192-D Polymorphic catch!
    presetKind = 'KNOWN_DDOS';
    applyPolymorphicJitter = true;
  } else if (r < 0.925) {
    presetKind = 'AMBIGUOUS_BOUNDARY';
  } else {
    presetKind = 'GRAY_ZONE_STEALTH';
  }

  const preset = buildPresetFeatures(profileId, presetKind);
  let flowFeatures = preset.features;
  if (presetKind === 'BENIGN_NORMAL') {
    const jitter = 0.94 + Math.random() * 0.12;
    for (const k of Object.keys(flowFeatures)) {
      if (k !== 'PROTOCOL' && k !== 'L4_DST_PORT' && k !== 'Protocol Type') {
        flowFeatures[k] = Number((flowFeatures[k] * jitter).toFixed(2));
      }
    }
    if (customIp) preset.socket.src_ip = customIp;
  } else if (applyPolymorphicJitter) {
    const driftPct = 2.5 + Math.random() * 4.5;
    flowFeatures = mutateFlowFeaturesForPolymorphic(profileId, flowFeatures, driftPct);
  }

  const result = await ingestFlow({
    profile_id: profileId,
    features: flowFeatures,
    socket: preset.socket,
    skipCloudLlm: true, // Fast async daemon path; cloud LLM runs on manual/interactive deep analysis
  });

  recordFlowInBucket(result.flow.zone, result.flow.bypass_stage);
  broadcastWs('flow:ingested', {
    flow: result.flow,
    incident: result.incident,
  });
}

function scheduleSensorLoop(): void {
  if (sensorTimer) {
    clearInterval(sensorTimer);
    sensorTimer = null;
  }
  if (!sensorRunning) return;
  const intervalMs = Math.max(250, Math.round(1000 / Math.max(0.25, sensorRateFps)));
  sensorTimer = setInterval(() => {
    void emitLiveSensorFlow().catch(() => {});
  }, intervalMs);
}

function computeDashboardMetrics(): DashboardMetrics {
  const settings = getGatewaySettings();
  const totalFlows = (db.prepare('SELECT COUNT(*) as c FROM flows').get() as { c: number }).c;
  const zoneRows = db
    .prepare('SELECT zone, COUNT(*) as c FROM flows GROUP BY zone')
    .all() as Array<{ zone: TriageZone; c: number }>;
  const zoneCounts: Record<TriageZone, number> = { GREEN: 0, YELLOW: 0, AMBER: 0, RED: 0 };
  for (const r of zoneRows) zoneCounts[r.zone] = r.c;

  const tier0Hits = (
    db
      .prepare("SELECT COUNT(*) as c FROM flows WHERE bypass_stage IN ('TIER_0_ATTACK', 'TIER_0_BENIGN_SUPPRESSED')")
      .get() as { c: number }
  ).c;
  const tier1Hits = (
    db.prepare("SELECT COUNT(*) as c FROM flows WHERE bypass_stage = 'TIER_1_POLYMORPHIC'").get() as { c: number }
  ).c;

  const activeP1P2 = (
    db.prepare("SELECT COUNT(*) as c FROM incidents WHERE zone = 'RED' AND status IN ('OPEN', 'CONFIRMED_ATTACK')").get() as {
      c: number;
    }
  ).c;
  const pendingClarifications = (
    db.prepare("SELECT COUNT(*) as c FROM incidents WHERE status = 'NEEDS_CLARIFICATION'").get() as { c: number }
  ).c;

  const avgModelRow = db
    .prepare("SELECT AVG(latency_ms) as avg_ms FROM flows WHERE bypass_stage = 'NONE'")
    .get() as { avg_ms: number | null };
  const avgTier0Row = db
    .prepare("SELECT AVG(latency_ms) as avg_ms FROM flows WHERE bypass_stage IN ('TIER_0_ATTACK', 'TIER_0_BENIGN_SUPPRESSED')")
    .get() as { avg_ms: number | null };

  const confirmedFp = (
    db.prepare("SELECT COUNT(*) as c FROM incidents WHERE status = 'CONFIRMED_NORMAL'").get() as { c: number }
  ).c;

  const benignFprPct =
    zoneCounts.GREEN + confirmedFp > 0
      ? Number(((confirmedFp / Math.max(1, zoneCounts.GREEN + confirmedFp)) * 100).toFixed(2))
      : DATASET_PROFILES[settings.active_profile]?.benchmark.open_benign_fpr ?? 0.78;

  const tier0SavingsPct = totalFlows > 0 ? Number(((tier0Hits / totalFlows) * 100).toFixed(1)) : 0;
  const estimatedApiDollarsSaved = Number(((tier0Hits + tier1Hits) * 0.0042).toFixed(3));

  return {
    total_flows: totalFlows,
    flows_per_sec: sensorRunning ? sensorRateFps : 0,
    active_p1_p2: activeP1P2,
    pending_clarifications: pendingClarifications,
    tier0_hits: tier0Hits,
    tier1_hits: tier1Hits,
    tier0_savings_pct: tier0SavingsPct,
    benign_fpr_pct: benignFprPct,
    estimated_api_dollars_saved: estimatedApiDollarsSaved,
    avg_model_latency_ms: Number((avgModelRow.avg_ms ?? 3.92).toFixed(2)),
    avg_tier0_latency_ms: Number((avgTier0Row.avg_ms ?? 0.032).toFixed(3)),
    zone_counts: zoneCounts,
    sensor_running: sensorRunning,
    sensor_rate_fps: sensorRateFps,
    active_profile: settings.active_profile,
    inference_mode: settings.inference_mode,
    pytorch_connected: lastPyTorchOnline,
    throughput_series: throughputHistory,
  };
}

wss.on('connection', (ws) => {
  ws.send(JSON.stringify({ type: 'metrics:tick', payload: computeDashboardMetrics(), ts: Date.now() }));
});

// =============================================================================
// REST API ENDPOINTS
// =============================================================================

app.get('/api/health', async (_req, res) => {
  const settings = getGatewaySettings();
  const pyHealth =
    settings.inference_mode === 'LIVE_PYTORCH_BRIDGE'
      ? await checkPyTorchEngineHealth(settings.pytorch_engine_url)
      : { online: false, profiles: [] };
  lastPyTorchOnline = pyHealth.online;
  res.json({
    status: 'ok',
    version: '8.1.0',
    inference_mode: settings.inference_mode,
    pytorch_bridge: pyHealth,
    providers: getProviderAvailability(),
  });
});

app.get('/api/profiles', (_req, res) => {
  res.json({
    profiles: Object.values(DATASET_PROFILES),
  });
});

app.get('/api/profiles/:id/preset/:kind', (req, res) => {
  const profileId = req.params.id;
  const kind = req.params.kind as FlowPresetKind;
  if (!DATASET_PROFILES[profileId]) {
    res.status(404).json({ error: 'Unknown dataset profile' });
    return;
  }
  const validKinds: FlowPresetKind[] = [
    'BENIGN_NORMAL',
    'KNOWN_DDOS',
    'ZERO_DAY_THEFT',
    'AMBIGUOUS_BOUNDARY',
    'GRAY_ZONE_STEALTH',
  ];
  const safeKind = validKinds.includes(kind) ? kind : 'BENIGN_NORMAL';
  res.json(buildPresetFeatures(profileId, safeKind));
});

app.get('/api/dashboard', (_req, res) => {
  const incidents = (
    db.prepare('SELECT * FROM incidents ORDER BY last_seen_utc DESC LIMIT 30').all() as Array<Record<string, unknown>>
  ).map(parseIncidentRow);
  const recentFlows = (
    db.prepare('SELECT * FROM flows ORDER BY timestamp_utc DESC LIMIT 25').all() as Array<Record<string, unknown>>
  ).map(parseFlowRow);

  res.json({
    metrics: computeDashboardMetrics(),
    incidents,
    recent_flows: recentFlows,
  });
});

app.post('/api/sensor/toggle', (req, res) => {
  const schema = z.object({
    running: z.boolean().optional(),
    rate_fps: z.number().min(0.25).max(5).optional(),
    active_profile: z.string().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid sensor control parameters' });
    return;
  }
  if (typeof parsed.data.running === 'boolean') sensorRunning = parsed.data.running;
  if (typeof parsed.data.rate_fps === 'number') sensorRateFps = parsed.data.rate_fps;
  if (parsed.data.active_profile && DATASET_PROFILES[parsed.data.active_profile]) {
    saveGatewaySettings({ active_profile: parsed.data.active_profile });
  }
  scheduleSensorLoop();
  const metrics = computeDashboardMetrics();
  broadcastWs('metrics:tick', metrics);
  res.json(metrics);
});

const ingestSchema = z.object({
  profile_id: z.string().optional(),
  features: z.record(z.number()),
  socket: z
    .object({
      src_ip: z.string().optional(),
      dst_ip: z.string().optional(),
      src_port: z.number().optional(),
      dst_port: z.number().optional(),
      protocol: z.number().optional(),
    })
    .optional(),
  use_cloud_llm: z.boolean().optional(),
});

app.post('/api/flows/ingest', async (req, res) => {
  const parsed = ingestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid flow payload', details: parsed.error.flatten() });
    return;
  }
  try {
    const result = await ingestFlow({
      profile_id: parsed.data.profile_id,
      features: parsed.data.features,
      socket: parsed.data.socket,
      skipCloudLlm: parsed.data.use_cloud_llm === false,
    });
    recordFlowInBucket(result.flow.zone, result.flow.bypass_stage);
    broadcastWs('flow:ingested', result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Flow ingestion failed' });
  }
});

// Repeat-Flow 50x Stress Test (proves < 0.05 ms Tier-0 bypass without touching neural model!)
app.post('/api/flows/repeat-test', async (req, res) => {
  const schema = ingestSchema.extend({
    count: z.number().int().min(2).max(100).default(50),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid repeat-test payload' });
    return;
  }

  let tier0Count = 0;
  let replayOverrides = 0;
  let totalTier0Latency = 0;
  let firstFlow = null;
  let lastFlow = null;
  let latestIncident = null;

  for (let i = 0; i < parsed.data.count; i++) {
    const r = await ingestFlow({
      profile_id: parsed.data.profile_id,
      features: parsed.data.features,
      socket: parsed.data.socket,
      skipCloudLlm: i > 0, // Only first miss could ever invoke LLM
    });
    recordFlowInBucket(r.flow.zone, r.flow.bypass_stage);
    if (i === 0) firstFlow = r.flow;
    lastFlow = r.flow;
    if (r.incident) latestIncident = r.incident;
    if (r.flow.bypass_stage === 'TIER_0_ATTACK' || r.flow.bypass_stage === 'TIER_0_BENIGN_SUPPRESSED') {
      tier0Count += 1;
      totalTier0Latency += r.flow.latency_ms;
    } else if (r.flow.bypass_stage === 'TIER_0_REPLAY_OVERRIDE') {
      replayOverrides += 1;
    }
  }

  broadcastWs('metrics:tick', computeDashboardMetrics());
  res.json({
    sent: parsed.data.count,
    tier0_bypassed: tier0Count,
    replay_overrides: replayOverrides,
    avg_tier0_latency_ms: tier0Count > 0 ? Number((totalTier0Latency / tier0Count).toFixed(4)) : 0,
    first_flow: firstFlow,
    last_flow: lastFlow,
    incident: latestIncident,
  });
});

// +3% Mutated Polymorphic Variant Test (proves Tier-1 192-D catch + auto-promotion to Tier-0!)
app.post('/api/flows/mutate-test', async (req, res) => {
  const schema = ingestSchema.extend({
    mutation_pct: z.number().min(0.5).max(12).default(3),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid mutate-test payload' });
    return;
  }

  const profileId = parsed.data.profile_id || getGatewaySettings().active_profile;
  const mutated = mutateFlowFeaturesForPolymorphic(
    profileId,
    parsed.data.features,
    parsed.data.mutation_pct
  );

  const firstMutated = await ingestFlow({
    profile_id: profileId,
    features: mutated,
    socket: parsed.data.socket,
    skipCloudLlm: true,
  });
  // Send the exact same mutated packet a second time to verify Tier-0 auto-promotion!
  const secondMutated = await ingestFlow({
    profile_id: parsed.data.profile_id,
    features: mutated,
    socket: parsed.data.socket,
    skipCloudLlm: true,
  });

  recordFlowInBucket(firstMutated.flow.zone, firstMutated.flow.bypass_stage);
  recordFlowInBucket(secondMutated.flow.zone, secondMutated.flow.bypass_stage);
  broadcastWs('flow:ingested', firstMutated);

  res.json({
    mutation_pct: parsed.data.mutation_pct,
    mutated_features: mutated,
    first_pass: firstMutated.flow,
    second_pass_tier0_verify: secondMutated.flow,
    incident: secondMutated.incident ?? firstMutated.incident,
  });
});

// Batch CSV/JSON Flow Uploader
app.post('/api/flows/batch', async (req, res) => {
  const schema = z.object({
    profile_id: z.string(),
    rows: z.array(z.record(z.unknown())).min(1).max(200),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid batch payload (1-200 rows required)' });
    return;
  }

  const summary = { processed: 0, tier0_bypassed: 0, tier1_caught: 0, zones: { GREEN: 0, YELLOW: 0, AMBER: 0, RED: 0 } };
  for (const rawRow of parsed.data.rows) {
    const features: Record<string, number> = {};
    for (const [k, v] of Object.entries(rawRow)) {
      const n = Number(v);
      if (Number.isFinite(n)) features[k] = n;
    }
    const socket = {
      src_ip: typeof rawRow.src_ip === 'string' ? rawRow.src_ip : undefined,
      dst_ip: typeof rawRow.dst_ip === 'string' ? rawRow.dst_ip : undefined,
      dst_port: Number.isFinite(Number(rawRow.dst_port)) ? Number(rawRow.dst_port) : undefined,
    };
    const r = await ingestFlow({
      profile_id: parsed.data.profile_id,
      features,
      socket,
      skipCloudLlm: true,
    });
    summary.processed += 1;
    summary.zones[r.flow.zone] += 1;
    if (r.flow.bypass_stage === 'TIER_0_ATTACK' || r.flow.bypass_stage === 'TIER_0_BENIGN_SUPPRESSED') {
      summary.tier0_bypassed += 1;
    } else if (r.flow.bypass_stage === 'TIER_1_POLYMORPHIC') {
      summary.tier1_caught += 1;
    }
  }
  broadcastWs('metrics:tick', computeDashboardMetrics());
  res.json(summary);
});

// Historical Flow Ledger with filtering
app.get('/api/flows', (req, res) => {
  const ip = typeof req.query.ip === 'string' ? req.query.ip.trim() : '';
  const zone = typeof req.query.zone === 'string' ? req.query.zone.trim().toUpperCase() : '';
  const label = typeof req.query.label === 'string' ? req.query.label.trim() : '';
  const simhash = typeof req.query.simhash === 'string' ? req.query.simhash.trim() : '';
  const limit = Math.min(250, Math.max(10, Number(req.query.limit) || 100));

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (ip) {
    conditions.push('(src_ip LIKE ? OR dst_ip LIKE ?)');
    params.push(`%${ip}%`, `%${ip}%`);
  }
  if (zone && ['GREEN', 'YELLOW', 'AMBER', 'RED'].includes(zone)) {
    conditions.push('zone = ?');
    params.push(zone);
  }
  if (label) {
    conditions.push('(label LIKE ? OR verdict LIKE ?)');
    params.push(`%${label}%`, `%${label}%`);
  }
  if (simhash) {
    conditions.push('simhash64 LIKE ?');
    params.push(`%${simhash}%`);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const rows = db
    .prepare(`SELECT * FROM flows ${where} ORDER BY timestamp_utc DESC LIMIT ?`)
    .all(...params, limit) as Array<Record<string, unknown>>;

  const distinctHosts = db
    .prepare(
      `SELECT src_ip, COUNT(*) as flow_count, MAX(martingale_value) as max_martingale, MAX(cusum_drift) as max_cusum
       FROM flows GROUP BY src_ip ORDER BY max_martingale DESC, flow_count DESC LIMIT 25`
    )
    .all();

  res.json({
    flows: rows.map(parseFlowRow),
    hosts: distinctHosts,
  });
});

app.get('/api/chronograph/:ip', (req, res) => {
  const ip = req.params.ip.trim();
  res.json(getChronoGraphForHost(ip));
});

app.get('/api/incidents', (req, res) => {
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  const rows = status
    ? (db.prepare('SELECT * FROM incidents WHERE status = ? ORDER BY last_seen_utc DESC LIMIT 100').all(status) as Array<Record<string, unknown>>)
    : (db.prepare('SELECT * FROM incidents ORDER BY last_seen_utc DESC LIMIT 100').all() as Array<Record<string, unknown>>);
  res.json({ incidents: rows.map(parseIncidentRow) });
});

app.get('/api/clarifications', (_req, res) => {
  const pending = (
    db
      .prepare("SELECT * FROM incidents WHERE status = 'NEEDS_CLARIFICATION' ORDER BY last_seen_utc DESC LIMIT 50")
      .all() as Array<Record<string, unknown>>
  ).map(parseIncidentRow);
  const resolved = (
    db
      .prepare("SELECT * FROM incidents WHERE status IN ('CONFIRMED_NORMAL', 'CONFIRMED_ATTACK') ORDER BY last_seen_utc DESC LIMIT 20")
      .all() as Array<Record<string, unknown>>
  ).map(parseIncidentRow);
  res.json({ pending, resolved });
});

app.post('/api/incidents/:id/confirm', (req, res) => {
  const schema = z.object({
    decision: z.enum(['NORMAL', 'ATTACK']),
    custom_label: z.string().max(80).optional(),
    actor: z.string().max(60).optional(),
    supervisor_override: z.boolean().optional(),
    max_rate_per_min: z.number().int().min(5).max(500).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid confirmation payload' });
    return;
  }
  try {
    const out = confirmIncidentDecision({
      incidentId: req.params.id,
      decision: parsed.data.decision,
      customLabel: parsed.data.custom_label,
      actor: parsed.data.actor,
      supervisorOverride: parsed.data.supervisor_override,
      maxRatePerMin: parsed.data.max_rate_per_min,
    });
    broadcastWs('incident:updated', out);
    res.json(out);
  } catch (err) {
    res.status(404).json({ error: err instanceof Error ? err.message : 'Confirmation failed' });
  }
});

app.post('/api/incidents/:id/approve-rule', (req, res) => {
  try {
    const actor = typeof req.body?.actor === 'string' ? req.body.actor.slice(0, 60) : 'Tier-3 SOC Supervisor';
    const updated = approveIncidentContainmentRule(req.params.id, actor);
    broadcastWs('incident:updated', { incident: updated });
    res.json({ incident: updated });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Approval failed' });
  }
});

// Gate E9 Live Simulator
app.post('/api/gate-e9/simulate', (req, res) => {
  const command = typeof req.body?.command === 'string' ? req.body.command : '';
  const benignSample = db
    .prepare("SELECT src_ip, dst_port, protocol FROM flows WHERE zone = 'GREEN' ORDER BY timestamp_utc DESC LIMIT 5000")
    .all() as Array<{ src_ip: string; dst_port: number; protocol: number }>;
  res.json(auditContainmentRuleGateE9(command, benignSample));
});

// Cloud AI SOC Co-Pilot Chat
app.post('/api/chat', async (req, res) => {
  const schema = z.object({
    message: z.string().min(1).max(4000),
    history: z
      .array(z.object({ role: z.enum(['user', 'assistant']), content: z.string() }))
      .default([]),
    incident_id: z.string().nullable().optional(),
    focus_ip: z.string().nullable().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid chat message' });
    return;
  }
  try {
    const result = await runSocCopilotChat({
      message: parsed.data.message,
      history: parsed.data.history,
      incidentId: parsed.data.incident_id,
      focusIp: parsed.data.focus_ip,
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Chat request failed' });
  }
});

// Hybrid RAG Knowledge Base & Live CISA KEV Sync
app.get('/api/rag', (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q : '';
  if (q.trim()) {
    res.json({ documents: queryHybridRag(q, undefined, 20) });
    return;
  }
  const rows = db.prepare('SELECT * FROM rag_kb ORDER BY updated_utc DESC LIMIT 50').all() as Array<Record<string, unknown>>;
  res.json({
    documents: rows.map((r) => ({
      id: r.id,
      source_type: r.source_type,
      ref_id: r.ref_id,
      title: r.title,
      summary: r.summary,
      content: r.content,
      tags: JSON.parse(String(r.tags_json)),
      port_hints: JSON.parse(String(r.port_hints_json)),
      updated_utc: r.updated_utc,
    })),
  });
});

app.post('/api/rag/sync', async (_req, res) => {
  const now = new Date().toISOString();
  let added = 0;
  let source = 'LIVE_CISA_KEV_FEED';

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { signal: controller.signal }
    );
    clearTimeout(timer);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = (await resp.json()) as {
      vulnerabilities?: Array<{
        cveID: string;
        vendorProject: string;
        product: string;
        vulnerabilityName: string;
        shortDescription: string;
        dateAdded: string;
      }>;
    };
    const latest = (data.vulnerabilities ?? []).slice(-6).reverse();
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO rag_kb (id, source_type, ref_id, title, summary, content, tags_json, port_hints_json, updated_utc)
      VALUES (?, 'CISA_KEV', ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const v of latest) {
      stmt.run(
        `rag-kev-${v.cveID}`,
        v.cveID,
        `${v.vendorProject} ${v.product}: ${v.vulnerabilityName}`,
        v.shortDescription.slice(0, 220),
        `${v.shortDescription} (CISA KEV Date Added: ${v.dateAdded})`,
        JSON.stringify([v.cveID.toLowerCase(), v.vendorProject.toLowerCase(), 'kev', 'exploits', 'zero_day']),
        JSON.stringify([80, 443, 8080, 8443]),
        now
      );
      added += 1;
    }
  } catch {
    source = 'OFFLINE_SNAPSHOT_REFRESH';
    const fallbackKev = [
      {
        id: 'rag-kev-CVE-2025-32433',
        ref: 'CVE-2025-32433',
        title: 'Erlang/OTP SSH Pre-Auth Remote Code Execution (CISA KEV)',
        summary: 'Active exploitation targeting edge telemetry and telecom SSH daemons.',
      },
      {
        id: 'rag-kev-CVE-2025-0282',
        ref: 'CVE-2025-0282',
        title: 'Perimeter VPN Appliance Stack Buffer Overflow (CISA KEV)',
        summary: 'Unauthenticated RCE exploited for lateral movement and staging.',
      },
    ];
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO rag_kb (id, source_type, ref_id, title, summary, content, tags_json, port_hints_json, updated_utc)
      VALUES (?, 'CISA_KEV', ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const k of fallbackKev) {
      stmt.run(
        k.id,
        k.ref,
        k.title,
        k.summary,
        `${k.summary} Refreshed from immutable local CISA KEV snapshot.`,
        JSON.stringify([k.ref.toLowerCase(), 'kev', 'rce', 'zero_day', 'lateral']),
        JSON.stringify([22, 443, 8443]),
        now
      );
      added += 1;
    }
  }

  appendAuditLog('Threat-Intel Sync Worker', 'SYSTEM', 'SYNC_HYBRID_RAG_CISA_KEV', source, { entries_synced: added });
  res.json({ synced: added, source, synced_utc: now });
});

// Period Report Studio (Preview + Scheduled Archive + Real PDF, DOCX, HTML, CSV, STIX 2.1 downloads)
function createScheduledReportSnapshot(triggerSource: 'AUTO_SCHEDULER' | 'MANUAL_SNAPSHOT') {
  const settings = getGatewaySettings();
  const windowMap: Record<string, string> = {
    OFF: '24h',
    HOURLY: '1h',
    SHIFT_8H: '8h',
    DAILY_24H: '24h',
    WEEKLY_7D: '7d',
  };
  const windowPreset = windowMap[settings.report_auto_schedule] ?? '8h';
  const { report } = buildPeriodReportData(windowPreset);
  const entry = {
    id: `RPT-${Date.now().toString(36).toUpperCase()}`,
    generated_utc: report.generated_utc,
    schedule_mode: settings.report_auto_schedule,
    window_preset: windowPreset,
    window_label: report.window_label,
    start_utc: report.start_utc,
    end_utc: report.end_utc,
    posture_score: report.posture_score,
    total_flows: report.total_flows,
    red_flows: report.zone_breakdown.RED,
    tier0_savings_pct: report.tier0_savings_pct,
    trigger_source: triggerSource,
  };
  recordScheduledReport(entry);
  appendAuditLog(
    triggerSource === 'AUTO_SCHEDULER' ? 'Report Scheduler' : 'SOC Analyst',
    triggerSource === 'AUTO_SCHEDULER' ? 'SYSTEM' : 'TIER2_ANALYST',
    'GENERATE_PERIOD_REPORT_DIGEST',
    entry.id,
    { window_preset: windowPreset, total_flows: entry.total_flows, posture_score: entry.posture_score }
  );
  return entry;
}

app.get('/api/reports/scheduled', (_req, res) => {
  res.json({
    schedule_mode: getGatewaySettings().report_auto_schedule,
    reports: listScheduledReports(15),
  });
});

app.post('/api/reports/scheduled/run', (_req, res) => {
  const entry = createScheduledReportSnapshot('MANUAL_SNAPSHOT');
  res.json({ created: entry, reports: listScheduledReports(15) });
});

app.get('/api/reports/preview', (req, res) => {
  const windowPreset = typeof req.query.window === 'string' ? req.query.window : '24h';
  const start = typeof req.query.start === 'string' ? req.query.start : undefined;
  const end = typeof req.query.end === 'string' ? req.query.end : undefined;
  const { report } = buildPeriodReportData(windowPreset, start, end);
  res.json(report);
});

app.get('/api/reports/export/:format', async (req, res) => {
  const format = req.params.format.toLowerCase();
  const windowPreset = typeof req.query.window === 'string' ? req.query.window : '24h';
  const start = typeof req.query.start === 'string' ? req.query.start : undefined;
  const end = typeof req.query.end === 'string' ? req.query.end : undefined;
  const { report, flows } = buildPeriodReportData(windowPreset, start, end);
  const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-');

  try {
    if (format === 'pdf') {
      const buf = await generatePdfBuffer(report);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="AegisFlow_SOC_Report_${windowPreset}_${stamp}.pdf"`);
      res.send(buf);
      return;
    }
    if (format === 'docx') {
      const buf = await generateDocxBuffer(report);
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      res.setHeader('Content-Disposition', `attachment; filename="AegisFlow_SOC_Report_${windowPreset}_${stamp}.docx"`);
      res.send(buf);
      return;
    }
    if (format === 'html') {
      const html = generateHtmlReport(report);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="AegisFlow_SOC_Report_${windowPreset}_${stamp}.html"`);
      res.send(html);
      return;
    }
    if (format === 'csv') {
      const csv = generateCsvLedger(flows);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="AegisFlow_Flow_Ledger_${windowPreset}_${stamp}.csv"`);
      res.send(csv);
      return;
    }
    if (format === 'stix') {
      const bundle = generateStix21Bundle(report);
      res.setHeader('Content-Type', 'application/stix+json; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="AegisFlow_STIX21_Bundle_${windowPreset}_${stamp}.json"`);
      res.send(JSON.stringify(bundle, null, 2));
      return;
    }
    res.status(400).json({ error: 'Unsupported report format' });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Report export failed' });
  }
});

// Governance: Gateway Settings, Provider Status, Tier-0/1 Caches, Hash-Chained Audit Log
app.get('/api/governance', async (_req, res) => {
  const settings = getGatewaySettings();
  const pyHealth = await checkPyTorchEngineHealth(settings.pytorch_engine_url);
  lastPyTorchOnline = pyHealth.online;
  const cacheStats = db
    .prepare('SELECT COUNT(*) as entries, COALESCE(SUM(hits), 0) as total_hits FROM prompt_cache')
    .get() as { entries: number; total_hits: number };

  res.json({
    settings,
    providers: getProviderAvailability(),
    pytorch_health: pyHealth,
    semantic_cache: cacheStats,
    tier0_entries: listTier0Entries(),
    tier1_prototypes: listTier1Prototypes(),
    audit_log: listAuditLog(80),
    audit_chain: verifyAuditChain(),
  });
});

app.post('/api/governance/settings', (req, res) => {
  const schema = z.object({
    inference_mode: z.enum(['BUILT_IN_SANDBOX_ENGINE', 'LIVE_PYTORCH_BRIDGE']).optional(),
    pytorch_engine_url: z.string().url().optional(),
    active_profile: z.string().optional(),
    failover_order: z.array(z.enum(['GEMINI', 'OPENROUTER', 'HARBOR', 'OFFLINE'])).length(4).optional(),
    gemini_fast_model: z.string().min(3).max(80).optional(),
    gemini_reasoning_model: z.string().min(3).max(80).optional(),
    openrouter_model: z.string().min(3).max(100).optional(),
    harbor_model: z.string().min(2).max(100).optional(),
    daily_budget_usd: z.number().min(1).max(5000).optional(),
    auto_downgrade_pct: z.number().min(20).max(99).optional(),
    semantic_cache_ttl_min: z.number().int().min(1).max(120).optional(),
    report_auto_schedule: z.enum(['OFF', 'HOURLY', 'SHIFT_8H', 'DAILY_24H', 'WEEKLY_7D']).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid governance settings', details: parsed.error.flatten() });
    return;
  }
  if (parsed.data.pytorch_engine_url) {
    try {
      const u = new URL(parsed.data.pytorch_engine_url);
      if (
        (u.protocol !== 'http:' && u.protocol !== 'https:') ||
        u.hostname === '169.254.169.254' ||
        u.hostname.startsWith('169.254.') ||
        u.hostname === 'metadata.google.internal'
      ) {
        res.status(400).json({ error: 'Disallowed PYTORCH_ENGINE_URL host or scheme.' });
        return;
      }
    } catch {
      res.status(400).json({ error: 'Invalid PYTORCH_ENGINE_URL' });
      return;
    }
  }
  const updated = saveGatewaySettings(parsed.data);
  appendAuditLog('SOC Administrator', 'TIER3_SUPERVISOR', 'UPDATE_GATEWAY_GOVERNANCE', 'GATEWAY_CONFIG', {
    inference_mode: updated.inference_mode,
    failover_order: updated.failover_order,
    daily_budget_usd: updated.daily_budget_usd,
    report_auto_schedule: updated.report_auto_schedule,
  });
  res.json({ settings: updated });
});

app.post('/api/governance/tier0/:hash/revoke', (req, res) => {
  const hash = req.params.hash;
  const active = req.body?.restore === true ? 1 : 0;
  db.prepare('UPDATE tier0_cache SET active = ? WHERE simhash64 = ?').run(active, hash);
  appendAuditLog(
    'SOC Administrator',
    'TIER3_SUPERVISOR',
    active ? 'RESTORE_TIER0_SIMHASH' : 'REVOKE_TIER0_SIMHASH',
    hash,
    { active: Boolean(active) }
  );
  res.json({ simhash64: hash, active: Boolean(active) });
});

app.post('/api/governance/tier1/:id/revoke', (req, res) => {
  const id = req.params.id;
  const active = req.body?.restore === true ? 1 : 0;
  db.prepare('UPDATE tier1_prototypes SET active = ? WHERE id = ?').run(active, id);
  appendAuditLog(
    'SOC Administrator',
    'TIER3_SUPERVISOR',
    active ? 'RESTORE_TIER1_PROTOTYPE' : 'REVOKE_TIER1_PROTOTYPE',
    id,
    { active: Boolean(active) }
  );
  res.json({ id, active: Boolean(active) });
});

app.get('/api/governance/audit/verify', (_req, res) => {
  res.json(verifyAuditChain());
});

// =============================================================================
// FRONTEND SERVING (VITE DEV MIDDLEWARE OR PRODUCTION DIST)
// =============================================================================
async function startServer() {
  await seedInitialSocIfEmpty();
  // Prime throughput chart with an initial point from seeded data
  const initialZones = db.prepare('SELECT zone, COUNT(*) as c FROM flows GROUP BY zone').all() as Array<{
    zone: TriageZone;
    c: number;
  }>;
  const initMap: Record<TriageZone, number> = { GREEN: 0, YELLOW: 0, AMBER: 0, RED: 0 };
  for (const r of initialZones) initMap[r.zone] = r.c;
  const initT0 = (
    db.prepare("SELECT COUNT(*) as c FROM flows WHERE bypass_stage IN ('TIER_0_ATTACK', 'TIER_0_BENIGN_SUPPRESSED')").get() as {
      c: number;
    }
  ).c;
  throughputHistory.push({
    time: new Date().toISOString().slice(11, 19),
    green: Math.min(20, initMap.GREEN),
    yellow: initMap.YELLOW,
    amber: initMap.AMBER,
    red: Math.min(25, initMap.RED),
    tier0_bypass: Math.min(25, initT0),
  });

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('/{*splat}', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[AegisFlow-OmniSOC v8.1] Server listening on http://0.0.0.0:${PORT}`);
    scheduleSensorLoop();

    // Seed initial scheduled shift digest if archive is empty
    if (listScheduledReports(1).length === 0) {
      createScheduledReportSnapshot('AUTO_SCHEDULER');
    }

    // Periodic DB retention pruning & automatic scheduled report check (every 60s)
    setInterval(() => {
      pruneOldFlows(1800, 3800);
      const settings = getGatewaySettings();
      if (settings.report_auto_schedule === 'OFF') return;
      const latest = listScheduledReports(1)[0];
      const intervalMsMap: Record<string, number> = {
        HOURLY: 3600_000,
        SHIFT_8H: 8 * 3600_000,
        DAILY_24H: 24 * 3600_000,
        WEEKLY_7D: 7 * 24 * 3600_000,
      };
      const dueMs = intervalMsMap[settings.report_auto_schedule] ?? 8 * 3600_000;
      const lastTs = latest ? new Date(latest.generated_utc).getTime() : 0;
      if (Date.now() - lastTs >= dueMs) {
        createScheduledReportSnapshot('AUTO_SCHEDULER');
      }
    }, 60_000);
  });
}

startServer().catch((err) => {
  console.error('Failed to start AegisFlow-OmniSOC server:', err);
  process.exit(1);
});
