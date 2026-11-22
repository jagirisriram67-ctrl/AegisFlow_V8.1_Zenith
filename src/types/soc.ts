export type TriageZone = 'GREEN' | 'YELLOW' | 'AMBER' | 'RED';

export type IncidentStatus =
  | 'OPEN'
  | 'NEEDS_CLARIFICATION'
  | 'CONFIRMED_ATTACK'
  | 'CONFIRMED_NORMAL'
  | 'CONTAINED';

export type BypassStage =
  | 'NONE'
  | 'TIER_0_ATTACK'
  | 'TIER_0_BENIGN_SUPPRESSED'
  | 'TIER_0_REPLAY_OVERRIDE'
  | 'TIER_1_POLYMORPHIC';

export type InferenceMode = 'BUILT_IN_SANDBOX_ENGINE' | 'LIVE_PYTORCH_BRIDGE';

export interface SocketContext {
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  timestamp_utc: string;
}

export interface DatasetBenchmark {
  total_classes: number;
  unique_rows: number;
  closed_macro_f1: number;
  closed_acc: number;
  closed_fpr: number;
  open_benign_fpr: number;
  ood_auroc_known: number;
  oscr: number;
  single_flow_ms: number;
  throughput_fps: number;
  ece_pct: number;
  evasion_auroc: number;
}

export interface DatasetProfile {
  id: string;
  display_name: string;
  family: 'NetFlow-v2' | 'CIC-IoT-2023' | 'N-BaIoT';
  feature_count: number;
  raw_feature_names: string[];
  known_classes: string[];
  zero_day_classes: string[];
  tau_amber: number;
  tau_red: number;
  benchmark: DatasetBenchmark;
  feature_baselines: Record<string, { mean: number; std: number; min: number; max: number; unit: string; desc: string }>;
}

export interface XaiFeatureRow {
  feature: string;
  value: number;
  baseline_normal: number;
  ig_shap: number;
  gpu_lime: number;
  lfg_gate: number;
  recon_mse: number;
  z_deviation: number;
  counterfactual_delta: number;
  semantics: string;
}

export interface OodPrimitives {
  energy: number;
  maha: number;
  vim: number;
  knn: number;
  inv_viol: number;
  fdbd_nci: number;
  tabm_epist: number;
  x_knn: number;
  msp: number;
}

export interface XaiCard {
  target_class: string;
  top_features: XaiFeatureRow[];
  ood_primitives: OodPrimitives;
  tabm_heads_flagging: number;
  anomaly_percentile: number;
  shap_lime_agreement: number;
  deletion_faithfulness: number;
  uncertainty_summary: string;
}

export interface RagDocument {
  id: string;
  source_type: 'MITRE_ATTACK_V20_1' | 'NIST_SP_800_61R3' | 'CISA_KEV' | 'NVD_CVE' | 'SOC_MEMORY';
  ref_id: string;
  title: string;
  summary: string;
  content: string;
  tags: string[];
  port_hints: number[];
  updated_utc: string;
  relevance_score?: number;
}

export interface GateE9Audit {
  command: string;
  passed: boolean;
  violations: string[];
  blast_radius_checked_flows: number;
  blast_radius_affected_flows: number;
  blast_radius_pct: number;
  verified_badge: string;
}

export interface LlmBrief {
  provider: string;
  model: string;
  cached: boolean;
  privacy_tokens_masked: number;
  summary: string;
  evidence_benign: string[];
  evidence_malicious: string[];
  recommended_action: string;
  suggested_firewall_rule: string;
  mitre_techniques: string[];
}

export interface FlowRecord {
  id: string;
  timestamp_utc: string;
  profile_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  simhash64: string;
  zone: TriageZone;
  verdict: string;
  label: string;
  closed_nearest_class: string;
  confidence: number;
  meta_ood_score: number;
  tau_amber: number;
  tau_red: number;
  shannon_entropy: number;
  epistemic_jsd: number;
  bypass_stage: BypassStage;
  latency_ms: number;
  incident_id: string | null;
  cusum_drift: number;
  hawkes_intensity: number;
  martingale_value: number;
  raw_features: Record<string, number>;
  xai?: XaiCard | null;
  rag_matches?: RagDocument[];
  llm_brief?: LlmBrief | null;
}

export interface IncidentRecord {
  id: string;
  created_utc: string;
  last_seen_utc: string;
  profile_id: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  simhash64: string;
  zone: TriageZone;
  status: IncidentStatus;
  label: string;
  original_label: string;
  closed_nearest_class: string;
  repeat_hit_count: number;
  polymorphic_count: number;
  meta_ood_score: number;
  confidence: number;
  shannon_entropy: number;
  epistemic_jsd: number;
  cusum_drift: number;
  hawkes_intensity: number;
  martingale_value: number;
  xai: XaiCard | null;
  rag_matches: RagDocument[];
  llm_brief: LlmBrief | null;
  containment_rule: string;
  gate_e9: GateE9Audit | null;
  rule_approved: boolean;
  approved_by?: string | null;
  approved_utc?: string | null;
}

export interface Tier0Entry {
  simhash64: string;
  profile_id: string;
  entry_type: 'ATTACK' | 'BENIGN';
  label: string;
  incident_id: string | null;
  created_utc: string;
  last_hit_utc: string;
  expires_utc: string;
  hit_count: number;
  max_rate_per_min: number;
  source: 'AUTO' | 'ANALYST' | 'TIER1_PROMOTED';
  active: boolean;
}

export interface Tier1Prototype {
  id: string;
  profile_id: string;
  bank_type: 'THREAT' | 'BENIGN_FP';
  label: string;
  incident_id: string | null;
  simhash64: string;
  created_utc: string;
  source: string;
  sigma_local: number;
  active: boolean;
}

export interface AuditLogEntry {
  id: number;
  timestamp_utc: string;
  actor: string;
  role: string;
  action: string;
  target_id: string;
  details: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
}

export interface GatewaySettings {
  inference_mode: InferenceMode;
  pytorch_engine_url: string;
  active_profile: string;
  failover_order: Array<'GEMINI' | 'OPENROUTER' | 'HARBOR' | 'OFFLINE'>;
  gemini_fast_model: string;
  gemini_reasoning_model: string;
  openrouter_model: string;
  harbor_model: string;
  daily_budget_usd: number;
  daily_spend_usd: number;
  daily_tokens_used: number;
  auto_downgrade_pct: number;
  semantic_cache_ttl_min: number;
  report_auto_schedule: 'OFF' | 'HOURLY' | 'SHIFT_8H' | 'DAILY_24H' | 'WEEKLY_7D';
}

export interface DashboardMetrics {
  total_flows: number;
  flows_per_sec: number;
  active_p1_p2: number;
  pending_clarifications: number;
  tier0_hits: number;
  tier1_hits: number;
  tier0_savings_pct: number;
  benign_fpr_pct: number;
  estimated_api_dollars_saved: number;
  avg_model_latency_ms: number;
  avg_tier0_latency_ms: number;
  zone_counts: Record<TriageZone, number>;
  sensor_running: boolean;
  sensor_rate_fps: number;
  active_profile: string;
  inference_mode: InferenceMode;
  pytorch_connected: boolean;
  throughput_series: Array<{
    time: string;
    green: number;
    yellow: number;
    amber: number;
    red: number;
    tier0_bypass: number;
  }>;
}

export interface ChronoGraphHostData {
  src_ip: string;
  subnet: string;
  total_flows: number;
  current_cusum: number;
  current_hawkes: number;
  current_martingale: number;
  risk_stage: string;
  kill_chain_stages: Array<{
    stage: string;
    timestamp_utc: string;
    label: string;
    zone: TriageZone;
    dst_ip: string;
    dst_port: number;
    meta_ood_score: number;
  }>;
  timeline: Array<{
    index: number;
    time: string;
    cusum: number;
    hawkes: number;
    martingale: number;
    meta_ood: number;
    zone: TriageZone;
    label: string;
  }>;
}

export interface PeriodReportData {
  generated_utc: string;
  window_label: string;
  start_utc: string;
  end_utc: string;
  executive_summary: string;
  posture_score: number;
  total_flows: number;
  zone_breakdown: Record<TriageZone, number>;
  tier0_blocked: number;
  tier1_caught: number;
  tier0_savings_pct: number;
  gpu_ms_saved: number;
  api_dollars_saved: number;
  avg_latency_ms: number;
  top_incidents: IncidentRecord[];
  clarification_audit: AuditLogEntry[];
  gate_e9_log: Array<{
    incident_id: string;
    label: string;
    src_ip: string;
    command: string;
    passed: boolean;
    blast_radius_pct: number;
    approved: boolean;
    approved_utc: string | null;
  }>;
  hardening_roadmap: Array<{
    priority: 'P1' | 'P2' | 'P3';
    nist_stage: string;
    title: string;
    rationale: string;
  }>;
}

export interface ScheduledReportEntry {
  id: string;
  generated_utc: string;
  schedule_mode: GatewaySettings['report_auto_schedule'];
  window_preset: string;
  window_label: string;
  start_utc: string;
  end_utc: string;
  posture_score: number;
  total_flows: number;
  red_flows: number;
  tier0_savings_pct: number;
  trigger_source: 'AUTO_SCHEDULER' | 'MANUAL_SNAPSHOT';
}

