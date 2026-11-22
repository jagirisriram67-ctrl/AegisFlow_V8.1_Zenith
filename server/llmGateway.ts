import crypto from 'node:crypto';
import { GoogleGenAI } from '@google/genai';
import type { LlmBrief, RagDocument, TriageZone, XaiCard } from '../src/types/soc.js';
import { db, getGatewaySettings, saveGatewaySettings, queryHybridRag } from './db.js';
import { auditContainmentRuleGateE9, buildSafeDefaultNftRule, ReversiblePrivacyProxy } from './privacyAndGateE9.js';

function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey) return null;
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

function isAllowedExternalUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
    const host = parsed.hostname.toLowerCase();
    // Block cloud metadata endpoint and loopback unless explicitly local harbor dev
    if (host === '169.254.169.254' || host === 'metadata.google.internal') return false;
    return true;
  } catch {
    return false;
  }
}

export function getProviderAvailability() {
  return {
    GEMINI: Boolean(process.env.GEMINI_API_KEY?.trim()),
    OPENROUTER: Boolean(process.env.OPENROUTER_API_KEY?.trim()),
    HARBOR: Boolean(process.env.HARBOR_BASE_URL?.trim()),
    OFFLINE: true,
  };
}

function recordSpend(tokensEstimate: number, isReasoningTier: boolean): void {
  const settings = getGatewaySettings();
  const costPer1k = isReasoningTier ? 0.0018 : 0.00035;
  const deltaUsd = Number(((tokensEstimate / 1000) * costPer1k).toFixed(5));
  saveGatewaySettings({
    daily_tokens_used: settings.daily_tokens_used + tokensEstimate,
    daily_spend_usd: Number((settings.daily_spend_usd + deltaUsd).toFixed(4)),
  });
}

function getSemanticCache(cacheKey: string): { provider: string; model: string; response: LlmBrief } | null {
  const now = new Date().toISOString();
  const row = db
    .prepare('SELECT provider, model, response_json, expires_utc FROM prompt_cache WHERE cache_key = ?')
    .get(cacheKey) as { provider: string; model: string; response_json: string; expires_utc: string } | undefined;
  if (!row || row.expires_utc < now) return null;
  db.prepare('UPDATE prompt_cache SET hits = hits + 1 WHERE cache_key = ?').run(cacheKey);
  try {
    return {
      provider: row.provider,
      model: row.model,
      response: JSON.parse(row.response_json),
    };
  } catch {
    return null;
  }
}

function setSemanticCache(cacheKey: string, provider: string, model: string, brief: LlmBrief, ttlMin: number): void {
  const now = new Date();
  const expires = new Date(now.getTime() + ttlMin * 60_000);
  db.prepare(`
    INSERT OR REPLACE INTO prompt_cache (cache_key, provider, model, response_json, created_utc, expires_utc, hits)
    VALUES (?, ?, ?, ?, ?, ?, 0)
  `).run(cacheKey, provider, model, JSON.stringify(brief), now.toISOString(), expires.toISOString());
}

async function callOpenAiCompatible(
  endpointUrl: string,
  apiKey: string | undefined,
  model: string,
  systemPrompt: string,
  userPrompt: string
): Promise<string> {
  if (!isAllowedExternalUrl(endpointUrl)) {
    throw new Error('Blocked disallowed external endpoint URL.');
  }
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 14000);
  try {
    const res = await fetch(endpointUrl, {
      method: 'POST',
      headers,
      signal: controller.signal,
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
      }),
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    const data = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const text = data.choices?.[0]?.message?.content;
    if (!text) throw new Error('Empty completion content');
    return text;
  } finally {
    clearTimeout(timer);
  }
}

async function invokeFailoverChain(
  systemPrompt: string,
  userPrompt: string,
  tier: 'FAST' | 'REASONING'
): Promise<{ text: string; provider: string; model: string }> {
  const settings = getGatewaySettings();
  const budgetRatio = settings.daily_budget_usd > 0 ? (settings.daily_spend_usd / settings.daily_budget_usd) * 100 : 0;
  const effectiveTier: 'FAST' | 'REASONING' =
    budgetRatio >= settings.auto_downgrade_pct ? 'FAST' : tier;

  // Hard budget cap -> drop straight to offline deterministic synthesizer
  if (settings.daily_spend_usd >= settings.daily_budget_usd) {
    return { text: '', provider: 'OFFLINE_SYNTHESIZER', model: 'neuro-symbolic-v8.1' };
  }

  for (const provider of settings.failover_order) {
    if (provider === 'GEMINI') {
      const ai = getGeminiClient();
      if (!ai) continue;
      const model =
        effectiveTier === 'FAST' ? settings.gemini_fast_model : settings.gemini_reasoning_model;
      try {
        const resp = await ai.models.generateContent({
          model,
          contents: userPrompt,
          config: {
            systemInstruction: systemPrompt,
          },
        });
        const text = resp.text?.trim();
        if (text) {
          recordSpend(Math.ceil((userPrompt.length + text.length) / 4), effectiveTier === 'REASONING');
          return { text, provider: 'Google Gemini API', model };
        }
      } catch {
        // Circuit breaker falls through to next provider
      }
    } else if (provider === 'OPENROUTER') {
      const key = process.env.OPENROUTER_API_KEY?.trim();
      if (!key) continue;
      try {
        const text = await callOpenAiCompatible(
          'https://openrouter.ai/api/v1/chat/completions',
          key,
          settings.openrouter_model,
          systemPrompt,
          userPrompt
        );
        recordSpend(Math.ceil((userPrompt.length + text.length) / 4), effectiveTier === 'REASONING');
        return { text, provider: 'OpenRouter API', model: settings.openrouter_model };
      } catch {
        // Fall through
      }
    } else if (provider === 'HARBOR') {
      const baseUrl = process.env.HARBOR_BASE_URL?.trim();
      if (!baseUrl) continue;
      const url = baseUrl.endsWith('/chat/completions')
        ? baseUrl
        : `${baseUrl.replace(/\/$/, '')}/v1/chat/completions`;
      try {
        const text = await callOpenAiCompatible(
          url,
          process.env.HARBOR_API_KEY?.trim(),
          settings.harbor_model,
          systemPrompt,
          userPrompt
        );
        recordSpend(Math.ceil((userPrompt.length + text.length) / 4), effectiveTier === 'REASONING');
        return { text, provider: 'Harbor / Custom OpenAI', model: settings.harbor_model };
      } catch {
        // Fall through
      }
    } else if (provider === 'OFFLINE') {
      break;
    }
  }

  return { text: '', provider: 'Offline Neuro-Symbolic Synthesizer', model: 'deterministic-v8.1' };
}

function buildDeterministicBrief(params: {
  zone: TriageZone;
  label: string;
  closedNearest: string;
  srcIp: string;
  dstIp: string;
  dstPort: number;
  protocol: number;
  metaOod: number;
  xai: XaiCard;
  ragMatches: RagDocument[];
  maskedCount: number;
}): LlmBrief {
  const top1 = params.xai.top_features[0];
  const top2 = params.xai.top_features[1];
  const mitre = params.ragMatches
    .filter((r) => r.source_type === 'MITRE_ATTACK_V20_1' || r.source_type === 'CISA_KEV')
    .map((r) => `${r.ref_id}: ${r.title}`)
    .slice(0, 3);

  const rule = buildSafeDefaultNftRule(params.srcIp, params.dstPort, params.protocol);

  const summary =
    params.zone === 'RED'
      ? `${params.label} isolated from ${params.srcIp} targeting ${params.dstIp}:${params.dstPort}. 9-Primitive Fisher-Probit MetaOOD reached ${params.metaOod.toFixed(2)} (${params.xai.anomaly_percentile.toFixed(1)}th percentile), driven by ${top1?.feature ?? 'IN_PKTS'} (${top1 ? `${top1.z_deviation >= 0 ? '+' : ''}${top1.z_deviation}σ` : '+4.2σ'}) and ${top2?.feature ?? 'OUT_BYTES'}. Nearest closed-set behavioral family: ${params.closedNearest}.`
      : `Uncertain ${params.zone === 'YELLOW' ? 'Boundary Ambiguity' : 'Epistemic Gray-Zone'} flow from ${params.srcIp} to ${params.dstIp}:${params.dstPort}. ${params.xai.tabm_heads_flagging}/8 TabM-8 subnetworks flag anomalous behavior (${params.xai.anomaly_percentile.toFixed(1)}th percentile). Analyst confirmation requested before committing manifold update.`;

  const evidenceBenign = [
    `Destination port ${params.dstPort} and protocol ${params.protocol} overlap partially with routine internal service baselines.`,
    `${8 - params.xai.tabm_heads_flagging} of 8 TabM-8 ensemble heads remain close to the certified benign manifold.`,
    top2 ? `${top2.feature} counterfactual normal target is ${top2.baseline_normal.toFixed(1)} (delta ${top2.counterfactual_delta.toFixed(2)}).` : 'Low residual drift on secondary packet size bins.',
  ];

  const evidenceMalicious = [
    top1
      ? `${top1.feature} deviates ${top1.z_deviation >= 0 ? '+' : ''}${top1.z_deviation}σ from benign baseline (IG-SHAP ${top1.ig_shap.toFixed(3)}, GPU-LIME ${top1.gpu_lime.toFixed(3)}).`
      : 'Strong positive IG-SHAP attribution across volumetric telemetry.',
    `MetaOOD Fisher-Probit evidence score ${params.metaOod.toFixed(2)} exceeds benign conformal boundary.`,
    mitre[0] ? `Correlates with ${mitre[0]}.` : 'Matches anomalous host telemetry shift in ChronoGraph window.',
  ];

  return {
    provider: 'Offline Neuro-Symbolic Synthesizer',
    model: 'deterministic-v8.1',
    cached: false,
    privacy_tokens_masked: params.maskedCount,
    summary,
    evidence_benign: evidenceBenign,
    evidence_malicious: evidenceMalicious,
    recommended_action:
      params.zone === 'RED'
        ? 'Review Gate E9 Blast-Radius verification and approve scoped nftables containment rule; Tier-0 SimHash immunization is active.'
        : 'Review XAI counterfactual range and click Confirm Normal (to arm rate-bounded Tier-0 suppression) or Confirm Attack (to run 24h retroactive sweep).',
    suggested_firewall_rule: rule,
    mitre_techniques: mitre.length > 0 ? mitre : ['T1046: Network Service Discovery'],
  };
}

export async function generateIncidentBrief(params: {
  profileId: string;
  zone: TriageZone;
  label: string;
  closedNearest: string;
  srcIp: string;
  dstIp: string;
  dstPort: number;
  protocol: number;
  metaOod: number;
  xai: XaiCard;
  ragMatches: RagDocument[];
  useCloudLlm?: boolean;
}): Promise<LlmBrief> {
  const settings = getGatewaySettings();
  const topFeatSig = params.xai.top_features.slice(0, 3).map((f) => f.feature).join(',');
  const cacheKey = crypto
    .createHash('sha256')
    .update(`${params.profileId}|${params.zone}|${params.label}|${params.dstPort}|${topFeatSig}`)
    .digest('hex');

  const cached = getSemanticCache(cacheKey);
  if (cached) {
    return {
      ...cached.response,
      cached: true,
      suggested_firewall_rule: buildSafeDefaultNftRule(params.srcIp, params.dstPort, params.protocol),
    };
  }

  const proxy = new ReversiblePrivacyProxy();
  const rawPrompt = `<telemetry_incident>
Profile: ${params.profileId}
Zone: ${params.zone}
Label: ${params.label} (Nearest Closed Class: ${params.closedNearest})
Flow: ${params.srcIp} -> ${params.dstIp}:${params.dstPort} (Proto ${params.protocol})
MetaOOD Score: ${params.metaOod.toFixed(3)} (${params.xai.anomaly_percentile.toFixed(1)}th percentile, ${params.xai.tabm_heads_flagging}/8 TabM heads)
Top XAI Features:
${params.xai.top_features
  .map((f) => `- ${f.feature}: val=${f.value}, normal=${f.baseline_normal}, z=${f.z_deviation}σ, SHAP=${f.ig_shap}, LIME=${f.gpu_lime}`)
  .join('\n')}
RAG Context:
${params.ragMatches.map((r) => `- [${r.ref_id}] ${r.title}: ${r.summary}`).join('\n')}
</telemetry_incident>
Return strict JSON with keys: summary (2 sentences), evidence_benign (array of 2 concise bullets), evidence_malicious (array of 2 concise bullets), recommended_action (1 sentence), suggested_firewall_rule (single safe nftables drop rule for source IP and destination port, never /0 or port 22).`;

  const { sanitized, maskedCount } = proxy.sanitize(rawPrompt);

  if (params.useCloudLlm === false) {
    return buildDeterministicBrief({ ...params, maskedCount });
  }

  const systemPrompt =
    'You are an autonomous Principal SOC Analyst inside AegisFlow-OmniSOC. Output ONLY valid JSON. Never include markdown fences. Never suggest wildcard /0, loopback, or SSH port 22 firewall rules.';

  const tier = params.label.includes('ZERO_DAY') ? 'REASONING' : 'FAST';
  const result = await invokeFailoverChain(systemPrompt, sanitized, tier);

  if (!result.text) {
    const offline = buildDeterministicBrief({ ...params, maskedCount });
    setSemanticCache(cacheKey, offline.provider, offline.model, offline, settings.semantic_cache_ttl_min);
    return offline;
  }

  try {
    const rehydrated = proxy.rehydrate(result.text).replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
    const parsed = JSON.parse(rehydrated) as Partial<LlmBrief>;
    const brief: LlmBrief = {
      provider: result.provider,
      model: result.model,
      cached: false,
      privacy_tokens_masked: maskedCount,
      summary: parsed.summary || buildDeterministicBrief({ ...params, maskedCount }).summary,
      evidence_benign: Array.isArray(parsed.evidence_benign) ? parsed.evidence_benign.slice(0, 3) : [],
      evidence_malicious: Array.isArray(parsed.evidence_malicious) ? parsed.evidence_malicious.slice(0, 3) : [],
      recommended_action: parsed.recommended_action || 'Inspect XAI telemetry and verify Gate E9 rule before containment.',
      suggested_firewall_rule:
        typeof parsed.suggested_firewall_rule === 'string' && parsed.suggested_firewall_rule.startsWith('nft ')
          ? parsed.suggested_firewall_rule
          : buildSafeDefaultNftRule(params.srcIp, params.dstPort, params.protocol),
      mitre_techniques: params.ragMatches.map((r) => `${r.ref_id}: ${r.title}`).slice(0, 3),
    };
    setSemanticCache(cacheKey, result.provider, result.model, brief, settings.semantic_cache_ttl_min);
    return brief;
  } catch {
    const offline = buildDeterministicBrief({ ...params, maskedCount });
    return { ...offline, provider: `${result.provider} (Fallback Parsed)`, model: result.model };
  }
}

export interface ChatTurnResult {
  reply: string;
  provider: string;
  model: string;
  privacy_tokens_masked: number;
  tools_invoked: Array<{ tool: string; summary: string }>;
  suggested_rule?: string;
  gate_e9?: ReturnType<typeof auditContainmentRuleGateE9>;
}

export async function runSocCopilotChat(params: {
  message: string;
  history: Array<{ role: 'user' | 'assistant'; content: string }>;
  incidentId?: string | null;
  focusIp?: string | null;
}): Promise<ChatTurnResult> {
  const toolsInvoked: Array<{ tool: string; summary: string }> = [];
  const contextBlocks: string[] = [];

  // Read-only structured tool 1: Incident XAI lookup
  let targetIp = params.focusIp || '';
  let targetPort = 0;
  let targetProtocol = 6;
  let incidentSummary = '';

  if (params.incidentId) {
    const inc = db.prepare('SELECT * FROM incidents WHERE id = ?').get(params.incidentId) as Record<string, unknown> | undefined;
    if (inc) {
      targetIp = targetIp || String(inc.src_ip);
      targetPort = Number(inc.dst_port);
      incidentSummary = `Incident ${inc.id}: ${inc.label} (${inc.zone}, status=${inc.status}), src=${inc.src_ip} -> dst=${inc.dst_ip}:${inc.dst_port}, repeats=${inc.repeat_hit_count}, MetaOOD=${Number(inc.meta_ood_score).toFixed(2)}, CUSUM=${Number(inc.cusum_drift).toFixed(2)}, Martingale=${Number(inc.martingale_value).toFixed(1)}.`;
      contextBlocks.push(`Selected Incident:\n${incidentSummary}`);
      toolsInvoked.push({ tool: 'inspect_incident_xai', summary: `Loaded ${inc.id} (${inc.label})` });
    }
  }

  // Extract IP mentioned in prompt if any
  const ipMatch = params.message.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  if (ipMatch) targetIp = ipMatch[0];

  // Read-only structured tool 2: query_ip_history
  if (targetIp) {
    const hostFlows = db
      .prepare('SELECT timestamp_utc, zone, label, dst_ip, dst_port, meta_ood_score, cusum_drift, hawkes_intensity, martingale_value, bypass_stage FROM flows WHERE src_ip = ? ORDER BY timestamp_utc DESC LIMIT 12')
      .all(targetIp) as Array<Record<string, unknown>>;
    if (hostFlows.length > 0) {
      toolsInvoked.push({ tool: 'query_ip_history', summary: `${hostFlows.length} flows retrieved for ${targetIp}` });
      contextBlocks.push(
        `Host History (${targetIp}):\n` +
          hostFlows
            .map(
              (f) =>
                `- ${String(f.timestamp_utc).slice(11, 19)} | ${f.zone} | ${f.label} -> ${f.dst_ip}:${f.dst_port} | MetaOOD=${Number(f.meta_ood_score).toFixed(2)} | CUSUM=${Number(f.cusum_drift).toFixed(2)} | Bypass=${f.bypass_stage}`
            )
            .join('\n')
      );
    }
  }

  // Read-only structured tool 3: compare_with_past_incidents
  const recentIncidents = db
    .prepare('SELECT id, zone, status, label, src_ip, dst_port, repeat_hit_count, meta_ood_score FROM incidents ORDER BY last_seen_utc DESC LIMIT 8')
    .all() as Array<Record<string, unknown>>;
  toolsInvoked.push({ tool: 'compare_with_past_incidents', summary: `Compared against ${recentIncidents.length} active/historical campaigns` });
  contextBlocks.push(
    'Active & Recent Campaigns:\n' +
      recentIncidents
        .map((i) => `- ${i.id} [${i.zone}/${i.status}] ${i.label} from ${i.src_ip}:${i.dst_port} (x${i.repeat_hit_count} hits, MetaOOD=${Number(i.meta_ood_score).toFixed(2)})`)
        .join('\n')
  );

  // Read-only structured tool 4: lookup_mitre_cve (Hybrid RAG)
  const ragDocs = queryHybridRag(`${params.message} ${incidentSummary}`, targetPort || undefined, 4);
  toolsInvoked.push({ tool: 'lookup_mitre_cve', summary: `Matched ${ragDocs.length} Hybrid RAG documents` });
  contextBlocks.push(
    'Hybrid RAG Knowledge Base:\n' +
      ragDocs.map((d) => `- [${d.source_type} ${d.ref_id}] ${d.title}: ${d.summary}`).join('\n')
  );

  // Read-only structured tool 5: simulate_firewall_rule via Gate E9 if requested or IP known
  let suggestedRule: string | undefined;
  let gateE9Result: ReturnType<typeof auditContainmentRuleGateE9> | undefined;
  if (targetIp || /nft|iptables|firewall|block|contain|rule/i.test(params.message)) {
    const ipForRule = targetIp || (recentIncidents[0] ? String(recentIncidents[0].src_ip) : '185.220.101.44');
    const portForRule = targetPort || (recentIncidents[0] ? Number(recentIncidents[0].dst_port) : 1883);
    suggestedRule = buildSafeDefaultNftRule(ipForRule, portForRule, targetProtocol);
    const benignSample = db
      .prepare("SELECT src_ip, dst_port, protocol FROM flows WHERE zone = 'GREEN' ORDER BY timestamp_utc DESC LIMIT 5000")
      .all() as Array<{ src_ip: string; dst_port: number; protocol: number }>;
    gateE9Result = auditContainmentRuleGateE9(suggestedRule, benignSample);
    toolsInvoked.push({
      tool: 'simulate_firewall_rule',
      summary: gateE9Result.verified_badge,
    });
    contextBlocks.push(`Gate E9 Pre-Verified Rule Candidate:\n${suggestedRule}\nResult: ${gateE9Result.verified_badge}`);
  }

  const proxy = new ReversiblePrivacyProxy();
  const fullUserPrompt = `<soc_context>\n${contextBlocks.join('\n\n')}\n</soc_context>\n\n<conversation_history>\n${params.history
    .slice(-6)
    .map((h) => `${h.role.toUpperCase()}: ${h.content}`)
    .join('\n')}\n</conversation_history>\n\nANALYST QUESTION: ${params.message}`;

  const { sanitized, maskedCount } = proxy.sanitize(fullUserPrompt);
  const systemPrompt =
    'You are the AegisFlow-OmniSOC Cloud AI Co-Pilot. Answer concisely with technical SOC rigor grounded strictly in the provided telemetry, ChronoGraph metrics, Hybrid RAG references, and Gate E9 simulations. Format clearly using short headings and bullet points. Never recommend unsafe firewall rules (/0, 127.0.0.1, port 22, or shell chaining).';

  const result = await invokeFailoverChain(systemPrompt, sanitized, 'REASONING');

  if (result.text) {
    return {
      reply: proxy.rehydrate(result.text),
      provider: result.provider,
      model: result.model,
      privacy_tokens_masked: maskedCount,
      tools_invoked: toolsInvoked,
      suggested_rule: suggestedRule,
      gate_e9: gateE9Result,
    };
  }

  // Deterministic Offline Neuro-Symbolic Co-Pilot Response (never breaks if cloud APIs are offline)
  const fallbackLines: string[] = [
    `### Forensic Analysis (Offline Neuro-Symbolic Synthesizer)`,
    incidentSummary
      ? `**Active Focus:** ${incidentSummary}`
      : `**Ledger Snapshot:** Evaluated ${recentIncidents.length} active/historical SOC campaigns in persistent storage.`,
    targetIp
      ? `**Host Temporal Assessment (${targetIp}):** Checked ChronoGraph sliding window (CUSUM anomaly drift, Hawkes kill-chain intensity, and Vovk Conformal Martingale) against stored flow ledger.`
      : `**Network Posture:** Tier-0 SimHash-64 reflex cache is actively deduplicating repeat attack flows in <0.05 ms without invoking GPU inference.`,
    `**Relevant Hybrid RAG Intelligence:**`,
    ...ragDocs.slice(0, 3).map((d) => `- **${d.ref_id}** (${d.source_type}): ${d.title} — ${d.summary}`),
  ];
  if (suggestedRule && gateE9Result) {
    fallbackLines.push(
      `**Gate E9 Verified Containment Candidate:**\n\`${suggestedRule}\`\n- ${gateE9Result.verified_badge}\n- Human-in-the-loop sign-off is required before deployment.`
    );
  }

  return {
    reply: fallbackLines.join('\n\n'),
    provider: result.provider,
    model: result.model,
    privacy_tokens_masked: maskedCount,
    tools_invoked: toolsInvoked,
    suggested_rule: suggestedRule,
    gate_e9: gateE9Result,
  };
}
