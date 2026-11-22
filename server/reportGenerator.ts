import PDFDocument from 'pdfkit';
import {
  AlignmentType,
  BorderStyle,
  Document,
  HeadingLevel,
  Packer,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} from 'docx';
import crypto from 'node:crypto';
import type { FlowRecord, IncidentRecord, PeriodReportData, TriageZone } from '../src/types/soc.js';
import { db, listAuditLog, parseFlowRow, parseIncidentRow } from './db.js';

export function resolveReportWindow(windowPreset: string, customStart?: string, customEnd?: string): {
  label: string;
  startUtc: string;
  endUtc: string;
} {
  const now = new Date();
  if (windowPreset === 'custom' && customStart && customEnd) {
    return {
      label: `Custom Range (${customStart.slice(0, 16)} -> ${customEnd.slice(0, 16)} UTC)`,
      startUtc: new Date(customStart).toISOString(),
      endUtc: new Date(customEnd).toISOString(),
    };
  }
  const hoursMap: Record<string, { hours: number; label: string }> = {
    '1h': { hours: 1, label: 'Last 1 Hour' },
    '8h': { hours: 8, label: 'Last 8 Hours (SOC Shift)' },
    '24h': { hours: 24, label: 'Last 24 Hours (Daily)' },
    '7d': { hours: 24 * 7, label: 'Last 7 Days (Weekly)' },
  };
  const cfg = hoursMap[windowPreset] ?? hoursMap['24h'];
  const start = new Date(now.getTime() - cfg.hours * 3600_000);
  return {
    label: cfg.label,
    startUtc: start.toISOString(),
    endUtc: now.toISOString(),
  };
}

export function buildPeriodReportData(windowPreset: string, customStart?: string, customEnd?: string): {
  report: PeriodReportData;
  flows: FlowRecord[];
} {
  const { label, startUtc, endUtc } = resolveReportWindow(windowPreset, customStart, customEnd);

  const flowRows = db
    .prepare('SELECT * FROM flows WHERE timestamp_utc >= ? AND timestamp_utc <= ? ORDER BY timestamp_utc DESC')
    .all(startUtc, endUtc) as Array<Record<string, unknown>>;
  const flows = flowRows.map(parseFlowRow);

  const incRows = db
    .prepare('SELECT * FROM incidents WHERE last_seen_utc >= ? AND created_utc <= ? ORDER BY repeat_hit_count DESC, last_seen_utc DESC')
    .all(startUtc, endUtc) as Array<Record<string, unknown>>;
  const incidents: IncidentRecord[] = incRows.map(parseIncidentRow);

  const zoneBreakdown: Record<TriageZone, number> = { GREEN: 0, YELLOW: 0, AMBER: 0, RED: 0 };
  let tier0Blocked = 0;
  let tier1Caught = 0;
  let latencySum = 0;

  for (const f of flows) {
    zoneBreakdown[f.zone] = (zoneBreakdown[f.zone] ?? 0) + 1;
    if (f.bypass_stage === 'TIER_0_ATTACK' || f.bypass_stage === 'TIER_0_BENIGN_SUPPRESSED') {
      tier0Blocked += 1;
    } else if (f.bypass_stage === 'TIER_1_POLYMORPHIC') {
      tier1Caught += 1;
    }
    latencySum += f.latency_ms;
  }

  const totalFlows = flows.length;
  const nonBenignTotal = Math.max(1, zoneBreakdown.RED + zoneBreakdown.AMBER + zoneBreakdown.YELLOW);
  const tier0SavingsPct = totalFlows > 0 ? Number(((tier0Blocked / totalFlows) * 100).toFixed(1)) : 0;
  const gpuMsSaved = Number((tier0Blocked * 3.92).toFixed(1));
  const apiDollarsSaved = Number(((tier0Blocked + tier1Caught) * 0.0042).toFixed(3));
  const avgLatencyMs = totalFlows > 0 ? Number((latencySum / totalFlows).toFixed(3)) : 0;

  const auditEntries = listAuditLog(100).filter(
    (a) => a.timestamp_utc >= startUtc && a.timestamp_utc <= endUtc
  );

  const gateE9Log = incidents
    .filter((i) => i.containment_rule)
    .map((i) => ({
      incident_id: i.id,
      label: i.label,
      src_ip: i.src_ip,
      command: i.containment_rule,
      passed: Boolean(i.gate_e9?.passed),
      blast_radius_pct: i.gate_e9?.blast_radius_pct ?? 0,
      approved: i.rule_approved,
      approved_utc: i.approved_utc ?? null,
    }));

  const pendingClarifications = incidents.filter((i) => i.status === 'NEEDS_CLARIFICATION').length;
  const redOpen = incidents.filter((i) => i.zone === 'RED' && !i.rule_approved).length;
  const postureScore = Math.max(
    45,
    Math.min(99, Math.round(98 - redOpen * 7 - pendingClarifications * 3 + Math.min(12, tier0SavingsPct * 0.15)))
  );

  const executiveSummary =
    `During ${label}, AegisFlow-OmniSOC (v8.1) inspected ${totalFlows.toLocaleString()} network flows across certified profiles, isolating ${zoneBreakdown.RED} Zone 3 critical/zero-day flows and queuing ${pendingClarifications} uncertain campaign(s) for analyst clarification. Tier-0 SimHash-64 reflex caching short-circuited ${tier0Blocked.toLocaleString()} repeat flows (${tier0SavingsPct}% of total volume) in <0.05 ms without invoking GPU neural inference, conserving ${gpuMsSaved.toLocaleString()} ms of GPU compute and ~$${apiDollarsSaved.toFixed(3)} in Cloud LLM API overhead. Average end-to-end processing latency remained ${avgLatencyMs} ms with ${gateE9Log.filter((g) => g.passed).length}/${gateE9Log.length} containment rules passing Gate E9 0.00% benign blast-radius verification.`;

  const hardeningRoadmap: PeriodReportData['hardening_roadmap'] = [
    {
      priority: 'P1',
      nist_stage: 'RS.MI-01 (Contain)',
      title: `Approve pending Gate E9 nftables rules for ${redOpen} uncontained Zone 3 campaign(s)`,
      rationale: 'Eliminates persistent zero-day exfiltration and volumetric DDoS sources verified at 0.00% benign collateral.',
    },
    {
      priority: 'P1',
      nist_stage: 'DE.AE-06 (Analyze)',
      title: `Resolve ${pendingClarifications} Yellow/Amber Clarification Inbox item(s)`,
      rationale: 'Arms rate-bounded Tier-0 suppression or triggers 24-hour retroactive ledger sweeps before Conformal Martingale auto-escalation.',
    },
    {
      priority: 'P2',
      nist_stage: 'PR.IR-01 (Protect)',
      title: 'Segment IoT MQTT (1883/8883) and management ports (8443) behind strict egress allowlists',
      rationale: 'Mitigates MITRE ATT&CK T1041 zero-day outbound theft patterns observed in ChronoGraph timelines.',
    },
    {
      priority: 'P3',
      nist_stage: 'ID.RA-01 (Govern)',
      title: 'Review Tier-0/Tier-1 cache TTL governance and verify SHA-256 audit log chain integrity',
      rationale: 'Maintains zero catastrophic forgetting and compliance-grade tamper evidence across shifts.',
    },
  ];

  const report: PeriodReportData = {
    generated_utc: new Date().toISOString(),
    window_label: label,
    start_utc: startUtc,
    end_utc: endUtc,
    executive_summary: executiveSummary,
    posture_score: postureScore,
    total_flows: totalFlows,
    zone_breakdown: zoneBreakdown,
    tier0_blocked: tier0Blocked,
    tier1_caught: tier1Caught,
    tier0_savings_pct: tier0SavingsPct,
    gpu_ms_saved: gpuMsSaved,
    api_dollars_saved: apiDollarsSaved,
    avg_latency_ms: avgLatencyMs,
    top_incidents: incidents.slice(0, 12),
    clarification_audit: auditEntries.slice(0, 25),
    gate_e9_log: gateE9Log,
    hardening_roadmap: hardeningRoadmap,
  };

  void nonBenignTotal;
  return { report, flows };
}

export async function generatePdfBuffer(report: PeriodReportData): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 44, size: 'A4', bufferPages: true });
    const chunks: Buffer[] = [];
    doc.on('data', (c: Buffer) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // Header Banner
    doc.rect(0, 0, doc.page.width, 86).fill('#0F172A');
    doc.fillColor('#F8FAFC').fontSize(18).font('Helvetica-Bold').text('AEGISFLOW-OMNISOC (v8.1) — SECURITY PERIOD REPORT', 44, 24);
    doc.fillColor('#94A3B8').fontSize(9.5).font('Helvetica').text(
      `Period: ${report.window_label}  |  Range: ${report.start_utc.slice(0, 19)}Z to ${report.end_utc.slice(0, 19)}Z  |  Generated: ${report.generated_utc.slice(0, 19)}Z`,
      44,
      50
    );

    doc.y = 104;

    // Section 1: Executive Security Posture
    doc.fillColor('#0F172A').fontSize(13).font('Helvetica-Bold').text('1. Executive Security Posture & Risk Delta');
    doc.moveDown(0.35);
    doc.fillColor('#334155').fontSize(9.5).font('Helvetica').text(report.executive_summary, { lineGap: 3 });
    doc.moveDown(0.7);

    // KPI Row
    const kpis = [
      { label: 'TOTAL FLOWS', value: report.total_flows.toLocaleString() },
      { label: 'POSTURE INDEX', value: `${report.posture_score}/100` },
      { label: 'TIER-0 BYPASSED', value: `${report.tier0_blocked} (${report.tier0_savings_pct}%)` },
      { label: 'AVG LATENCY', value: `${report.avg_latency_ms} ms` },
    ];
    const boxW = (doc.page.width - 88 - 24) / 4;
    const kpiY = doc.y;
    kpis.forEach((k, idx) => {
      const x = 44 + idx * (boxW + 8);
      doc.roundedRect(x, kpiY, boxW, 44, 4).fillAndStroke('#F8FAFC', '#CBD5E1');
      doc.fillColor('#64748B').fontSize(7.5).font('Helvetica-Bold').text(k.label, x + 8, kpiY + 8, { width: boxW - 16 });
      doc.fillColor('#0F172A').fontSize(12).font('Helvetica-Bold').text(k.value, x + 8, kpiY + 21, { width: boxW - 16 });
    });
    doc.y = kpiY + 58;

    // Section 2: 4-Zone Conformal Breakdown with Vector Bar Chart
    doc.fillColor('#0F172A').fontSize(13).font('Helvetica-Bold').text('2. 4-Zone Conformal Traffic Breakdown & Tier-0/1 Savings');
    doc.moveDown(0.4);
    const maxZone = Math.max(1, ...Object.values(report.zone_breakdown));
    const zones: Array<{ key: TriageZone; label: string; color: string }> = [
      { key: 'GREEN', label: 'Zone 1 — Certified Benign', color: '#10B981' },
      { key: 'YELLOW', label: 'Zone 2A — Boundary Ambiguity', color: '#EAB308' },
      { key: 'AMBER', label: 'Zone 2B — Epistemic Gray-Zone', color: '#F59E0B' },
      { key: 'RED', label: 'Zone 3 — Confirmed Attack / Zero-Day', color: '#EF4444' },
    ];
    for (const z of zones) {
      const cnt = report.zone_breakdown[z.key];
      const barY = doc.y;
      doc.fillColor('#1E293B').fontSize(9).font('Helvetica').text(`${z.label}`, 44, barY, { width: 195 });
      const barMaxW = 240;
      const w = Math.max(4, (cnt / maxZone) * barMaxW);
      doc.rect(245, barY + 1, barMaxW, 10).fill('#E2E8F0');
      doc.rect(245, barY + 1, w, 10).fill(z.color);
      doc.fillColor('#0F172A').fontSize(9).font('Helvetica-Bold').text(`${cnt}`, 495, barY, { width: 55, align: 'right' });
      doc.y = barY + 17;
    }
    doc.moveDown(0.4);
    doc.fillColor('#334155').fontSize(9).font('Helvetica').text(
      `Tier-0 Repeat Bypass Saved: ${report.tier0_blocked} flows (${report.gpu_ms_saved} ms GPU compute, ~$${report.api_dollars_saved.toFixed(3)} Cloud API cost)  |  Tier-1 Polymorphic Variants Caught: ${report.tier1_caught}`
    );
    doc.moveDown(0.8);

    // Section 3: Critical Incidents & Zero-Day Forensics
    doc.fillColor('#0F172A').fontSize(13).font('Helvetica-Bold').text('3. Critical Incidents & Zero-Day Forensics');
    doc.moveDown(0.35);
    if (report.top_incidents.length === 0) {
      doc.fillColor('#64748B').fontSize(9).text('No incidents recorded in the selected window.');
    } else {
      for (const inc of report.top_incidents.slice(0, 8)) {
        if (doc.y > 700) doc.addPage();
        doc.fillColor('#0F172A').fontSize(9.5).font('Helvetica-Bold').text(
          `${inc.id} [${inc.zone} / ${inc.status}] ${inc.label} — ${inc.src_ip} -> ${inc.dst_ip}:${inc.dst_port} (x${inc.repeat_hit_count} hits, MetaOOD ${inc.meta_ood_score.toFixed(2)})`
        );
        doc.fillColor('#475569').fontSize(8.5).font('Helvetica').text(
          inc.llm_brief?.summary || `SimHash-64: ${inc.simhash64} | Nearest Class: ${inc.closed_nearest_class}`,
          { indent: 10 }
        );
        doc.moveDown(0.3);
      }
    }

    // Section 4: Gate E9 Containment & Safety Verification Log
    if (doc.y > 650) doc.addPage();
    doc.moveDown(0.5);
    doc.fillColor('#0F172A').fontSize(13).font('Helvetica-Bold').text('4. Gate E9 Containment & Blast-Radius Verification Log');
    doc.moveDown(0.3);
    for (const g of report.gate_e9_log.slice(0, 8)) {
      doc.fillColor('#0F172A').fontSize(8.5).font('Helvetica-Bold').text(
        `${g.incident_id} (${g.label}) — ${g.passed ? 'PASSED' : 'BLOCKED'} | Blast Radius: ${g.blast_radius_pct.toFixed(2)}% | ${g.approved ? 'APPROVED' : 'PENDING SIGN-OFF'}`
      );
      doc.fillColor('#334155').fontSize(8).font('Courier').text(`  ${g.command}`);
      doc.moveDown(0.25);
    }

    // Section 5: Clarification Audit Log
    if (doc.y > 650) doc.addPage();
    doc.moveDown(0.5);
    doc.fillColor('#0F172A').fontSize(13).font('Helvetica-Bold').text('5. Human-in-the-Loop Clarification & Governance Audit Log');
    doc.moveDown(0.3);
    for (const a of report.clarification_audit.slice(0, 10)) {
      doc.fillColor('#334155').fontSize(8.5).font('Helvetica').text(
        `${a.timestamp_utc.slice(0, 19)}Z | ${a.actor} (${a.role}) | ${a.action} -> ${a.target_id} | SHA256:${a.entry_hash.slice(0, 12)}`
      );
    }

    // Section 6: NIST SP 800-61r3 Hardening Roadmap
    if (doc.y > 650) doc.addPage();
    doc.moveDown(0.6);
    doc.fillColor('#0F172A').fontSize(13).font('Helvetica-Bold').text('6. Prioritized Hardening Roadmap (NIST SP 800-61 Rev. 3)');
    doc.moveDown(0.3);
    for (const item of report.hardening_roadmap) {
      doc.fillColor('#0F172A').fontSize(9).font('Helvetica-Bold').text(`[${item.priority} · ${item.nist_stage}] ${item.title}`);
      doc.fillColor('#475569').fontSize(8.5).font('Helvetica').text(item.rationale, { indent: 12 });
      doc.moveDown(0.25);
    }

    // Page footers
    const range = doc.bufferedPageRange();
    for (let i = 0; i < range.count; i++) {
      doc.switchToPage(i);
      doc.fillColor('#94A3B8').fontSize(8).text(
        `AegisFlow-OmniSOC v8.1 Enterprise Edition  |  Confidential SOC Forensic Artifact  |  Page ${i + 1} of ${range.count}`,
        44,
        doc.page.height - 32,
        { align: 'center', width: doc.page.width - 88 }
      );
    }

    doc.end();
  });
}

export async function generateDocxBuffer(report: PeriodReportData): Promise<Buffer> {
  const makeCell = (text: string, header = false) =>
    new TableCell({
      shading: header ? { type: ShadingType.CLEAR, fill: '0F172A', color: 'auto' } : undefined,
      margins: { top: 80, bottom: 80, left: 100, right: 100 },
      children: [
        new Paragraph({
          children: [
            new TextRun({
              text,
              bold: header,
              color: header ? 'F8FAFC' : '1E293B',
              size: header ? 18 : 17,
              font: 'Calibri',
            }),
          ],
        }),
      ],
    });

  const incidentRows = [
    new TableRow({
      tableHeader: true,
      children: [
        makeCell('Incident ID', true),
        makeCell('Zone / Status', true),
        makeCell('Classification', true),
        makeCell('Source -> Target', true),
        makeCell('Repeats', true),
        makeCell('MetaOOD', true),
      ],
    }),
    ...report.top_incidents.map(
      (inc) =>
        new TableRow({
          children: [
            makeCell(inc.id),
            makeCell(`${inc.zone} (${inc.status})`),
            makeCell(inc.label),
            makeCell(`${inc.src_ip} -> ${inc.dst_ip}:${inc.dst_port}`),
            makeCell(`${inc.repeat_hit_count}x (+${inc.polymorphic_count} poly)`),
            makeCell(inc.meta_ood_score.toFixed(2)),
          ],
        })
    ),
  ];

  const gateRows = [
    new TableRow({
      tableHeader: true,
      children: [
        makeCell('Incident', true),
        makeCell('Proposed Containment Rule', true),
        makeCell('Blast Radius', true),
        makeCell('Sign-Off', true),
      ],
    }),
    ...report.gate_e9_log.map(
      (g) =>
        new TableRow({
          children: [
            makeCell(`${g.incident_id} (${g.label})`),
            makeCell(g.command),
            makeCell(`${g.blast_radius_pct.toFixed(2)}%`),
            makeCell(g.approved ? 'Approved' : g.passed ? 'Gate E9 Verified (Pending)' : 'Blocked'),
          ],
        })
    ),
  ];

  const doc = new Document({
    sections: [
      {
        properties: {},
        children: [
          new Paragraph({
            heading: HeadingLevel.TITLE,
            alignment: AlignmentType.LEFT,
            children: [
              new TextRun({
                text: 'AegisFlow-OmniSOC (v8.1) — Security Operations Period Report',
                bold: true,
                color: '0F172A',
              }),
            ],
          }),
          new Paragraph({
            spacing: { after: 200 },
            children: [
              new TextRun({
                text: `Reporting Window: ${report.window_label} (${report.start_utc} to ${report.end_utc})`,
                color: '475569',
                size: 20,
              }),
            ],
          }),
          new Paragraph({ heading: HeadingLevel.HEADING_1, text: '1. Executive Security Posture & Risk Delta' }),
          new Paragraph({ spacing: { after: 180 }, text: report.executive_summary }),

          new Paragraph({ heading: HeadingLevel.HEADING_1, text: '2. 4-Zone Breakdown & Tier-0 Immunological Savings' }),
          new Paragraph({
            text: `Total Flows: ${report.total_flows} | GREEN Benign: ${report.zone_breakdown.GREEN} | YELLOW Boundary: ${report.zone_breakdown.YELLOW} | AMBER Gray-Zone: ${report.zone_breakdown.AMBER} | RED Critical/Zero-Day: ${report.zone_breakdown.RED}`,
          }),
          new Paragraph({
            spacing: { after: 180 },
            text: `Tier-0 SimHash Bypassed: ${report.tier0_blocked} flows (${report.tier0_savings_pct}%) | Tier-1 Polymorphic Variants: ${report.tier1_caught} | GPU Compute Saved: ${report.gpu_ms_saved} ms | Est. API Cost Saved: $${report.api_dollars_saved.toFixed(3)}`,
          }),

          new Paragraph({ heading: HeadingLevel.HEADING_1, text: '3. Critical Incidents & Zero-Day Forensics' }),
          new Table({
            width: { size: 100, type: WidthType.PERCENTAGE },
            borders: {
              top: { style: BorderStyle.SINGLE, size: 1, color: 'CBD5E1' },
              bottom: { style: BorderStyle.SINGLE, size: 1, color: 'CBD5E1' },
              insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: 'E2E8F0' },
            },
            rows: incidentRows,
          }),

          new Paragraph({ spacing: { before: 220 }, heading: HeadingLevel.HEADING_1, text: '4. Gate E9 Containment & Safety Verification Log' }),
          new Table({
            width: { size: 100, type: WidthType.PERCENTAGE },
            rows: gateRows,
          }),

          new Paragraph({ spacing: { before: 220 }, heading: HeadingLevel.HEADING_1, text: '5. Prioritized Hardening Roadmap (NIST SP 800-61r3)' }),
          ...report.hardening_roadmap.map(
            (r) =>
              new Paragraph({
                spacing: { after: 100 },
                children: [
                  new TextRun({ text: `[${r.priority} · ${r.nist_stage}] ${r.title}: `, bold: true }),
                  new TextRun({ text: r.rationale }),
                ],
              })
          ),

          new Paragraph({
            spacing: { before: 260 },
            children: [
              new TextRun({
                text: `SOC Supervisor Sign-Off: ____________________________   Date (UTC): ${report.generated_utc.slice(0, 10)}`,
                italics: true,
                color: '475569',
              }),
            ],
          }),
        ],
      },
    ],
  });

  return Packer.toBuffer(doc);
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function generateHtmlReport(report: PeriodReportData): string {
  const maxZ = Math.max(1, ...Object.values(report.zone_breakdown));
  const bar = (val: number, color: string) =>
    `<div style="background:#1e293b;border-radius:4px;height:10px;width:100%;overflow:hidden"><div style="background:${color};height:10px;width:${Math.max(2, Math.round((val / maxZ) * 100))}%"></div></div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>AegisFlow-OmniSOC Report — ${escapeHtml(report.window_label)}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#090d16; color:#e2e8f0; margin:0; padding:32px; line-height:1.55; }
  .wrap { max-width:1040px; margin:0 auto; }
  h1,h2 { color:#f8fafc; margin-top:28px; }
  .meta { color:#94a3b8; font-size:13px; margin-bottom:24px; }
  .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:20px 0; }
  .card { background:#0f1623; border:1px solid #1e293b; border-radius:8px; padding:14px 16px; }
  .kpi-l { color:#94a3b8; font-size:12px; }
  .kpi-v { font-family:monospace; font-size:22px; font-weight:700; color:#f8fafc; margin-top:4px; }
  table { width:100%; border-collapse:collapse; margin-top:12px; font-size:13px; }
  th, td { text-align:left; padding:10px 12px; border-bottom:1px solid #1e293b; }
  th { color:#94a3b8; background:#0f1623; }
  code { font-family:monospace; background:#161f30; padding:2px 6px; border-radius:4px; font-size:12px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>AegisFlow-OmniSOC (v8.1) — Executive Security Report</h1>
  <div class="meta">${escapeHtml(report.window_label)} · ${escapeHtml(report.start_utc)} to ${escapeHtml(report.end_utc)}</div>
  <p>${escapeHtml(report.executive_summary)}</p>
  <div class="grid">
    <div class="card"><div class="kpi-l">Total Flows</div><div class="kpi-v">${report.total_flows.toLocaleString()}</div></div>
    <div class="card"><div class="kpi-l">Posture Index</div><div class="kpi-v">${report.posture_score}/100</div></div>
    <div class="card"><div class="kpi-l">Tier-0 Bypassed</div><div class="kpi-v">${report.tier0_blocked} (${report.tier0_savings_pct}%)</div></div>
    <div class="card"><div class="kpi-l">API Cost Saved</div><div class="kpi-v">$${report.api_dollars_saved.toFixed(3)}</div></div>
  </div>
  <h2>4-Zone Conformal Distribution</h2>
  <table>
    <tr><td>Zone 1 · Certified Benign</td><td style="width:55%">${bar(report.zone_breakdown.GREEN, '#10b981')}</td><td><strong>${report.zone_breakdown.GREEN}</strong></td></tr>
    <tr><td>Zone 2A · Boundary Ambiguity</td><td>${bar(report.zone_breakdown.YELLOW, '#eab308')}</td><td><strong>${report.zone_breakdown.YELLOW}</strong></td></tr>
    <tr><td>Zone 2B · Epistemic Gray-Zone</td><td>${bar(report.zone_breakdown.AMBER, '#f59e0b')}</td><td><strong>${report.zone_breakdown.AMBER}</strong></td></tr>
    <tr><td>Zone 3 · Critical / Zero-Day</td><td>${bar(report.zone_breakdown.RED, '#ef4444')}</td><td><strong>${report.zone_breakdown.RED}</strong></td></tr>
  </table>
  <h2>Critical Incidents &amp; Zero-Day Forensics</h2>
  <table>
    <thead><tr><th>ID</th><th>Zone</th><th>Label</th><th>Source → Target</th><th>Repeats</th><th>MetaOOD</th></tr></thead>
    <tbody>
      ${report.top_incidents
        .map(
          (i) =>
            `<tr><td><code>${escapeHtml(i.id)}</code></td><td>${escapeHtml(i.zone)}</td><td>${escapeHtml(i.label)}</td><td><code>${escapeHtml(i.src_ip)} → ${escapeHtml(i.dst_ip)}:${i.dst_port}</code></td><td>${i.repeat_hit_count}x</td><td>${i.meta_ood_score.toFixed(2)}</td></tr>`
        )
        .join('')}
    </tbody>
  </table>
  <h2>Gate E9 Containment Verification Log</h2>
  <table>
    <thead><tr><th>Incident</th><th>Command</th><th>Blast Radius</th><th>Status</th></tr></thead>
    <tbody>
      ${report.gate_e9_log
        .map(
          (g) =>
            `<tr><td>${escapeHtml(g.incident_id)}</td><td><code>${escapeHtml(g.command)}</code></td><td>${g.blast_radius_pct.toFixed(2)}%</td><td>${g.approved ? 'Approved' : g.passed ? 'Verified (Pending)' : 'Blocked'}</td></tr>`
        )
        .join('')}
    </tbody>
  </table>
  <h2>NIST SP 800-61 Rev. 3 Hardening Roadmap</h2>
  <ul>
    ${report.hardening_roadmap
      .map((r) => `<li><strong>[${escapeHtml(r.priority)} · ${escapeHtml(r.nist_stage)}] ${escapeHtml(r.title)}</strong> — ${escapeHtml(r.rationale)}</li>`)
      .join('')}
  </ul>
</div>
</body>
</html>`;
}

export function generateCsvLedger(flows: FlowRecord[]): string {
  const headers = [
    'id', 'timestamp_utc', 'profile_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
    'protocol', 'simhash64', 'zone', 'verdict', 'label', 'closed_nearest_class',
    'confidence', 'meta_ood_score', 'shannon_entropy', 'epistemic_jsd',
    'bypass_stage', 'latency_ms', 'incident_id', 'cusum_drift', 'hawkes_intensity', 'martingale_value',
  ];
  const esc = (v: unknown) => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [headers.join(',')];
  for (const f of flows) {
    lines.push(
      [
        f.id, f.timestamp_utc, f.profile_id, f.src_ip, f.dst_ip, f.src_port, f.dst_port,
        f.protocol, f.simhash64, f.zone, f.verdict, f.label, f.closed_nearest_class,
        f.confidence, f.meta_ood_score, f.shannon_entropy, f.epistemic_jsd,
        f.bypass_stage, f.latency_ms, f.incident_id ?? '', f.cusum_drift, f.hawkes_intensity, f.martingale_value,
      ]
        .map(esc)
        .join(',')
    );
  }
  return lines.join('\n');
}

export function generateStix21Bundle(report: PeriodReportData): Record<string, unknown> {
  const identityId = 'identity--aegisflow-omnisoc-v81-000000000001';
  const objects: Array<Record<string, unknown>> = [
    {
      type: 'identity',
      spec_version: '2.1',
      id: identityId,
      created: report.generated_utc,
      modified: report.generated_utc,
      name: 'AegisFlow-OmniSOC v8.1 Autonomous SOC',
      identity_class: 'system',
    },
  ];

  for (const inc of report.top_incidents) {
    const indId = `indicator--${crypto.randomUUID()}`;
    const obsId = `observed-data--${crypto.randomUUID()}`;
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: indId,
      created: inc.created_utc,
      modified: inc.last_seen_utc,
      created_by_ref: identityId,
      name: `${inc.label} (${inc.id})`,
      description: inc.llm_brief?.summary || `AegisFlow-Zenith v8.1 ${inc.zone} detection. SimHash-64: ${inc.simhash64}`,
      indicator_types: [inc.label.includes('ZERO_DAY') ? 'anomalous-activity' : 'malicious-activity'],
      pattern: `[ipv4-addr:value = '${inc.src_ip}' AND network-traffic:dst_port = ${inc.dst_port}]`,
      pattern_type: 'stix',
      valid_from: inc.created_utc,
      confidence: Math.round(inc.confidence * 100),
      labels: [inc.zone, inc.profile_id, `simhash:${inc.simhash64}`],
    });
    objects.push({
      type: 'observed-data',
      spec_version: '2.1',
      id: obsId,
      created: inc.created_utc,
      modified: inc.last_seen_utc,
      first_observed: inc.created_utc,
      last_observed: inc.last_seen_utc,
      number_observed: Math.max(1, inc.repeat_hit_count),
      objects: {
        '0': { type: 'ipv4-addr', value: inc.src_ip },
        '1': { type: 'ipv4-addr', value: inc.dst_ip },
        '2': { type: 'network-traffic', src_ref: '0', dst_ref: '1', dst_port: inc.dst_port, protocols: ['tcp'] },
      },
    });
    objects.push({
      type: 'relationship',
      spec_version: '2.1',
      id: `relationship--${crypto.randomUUID()}`,
      created: inc.created_utc,
      modified: inc.last_seen_utc,
      relationship_type: 'based-on',
      source_ref: indId,
      target_ref: obsId,
    });
  }

  return {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID()}`,
    objects,
  };
}
