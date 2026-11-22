import type { BypassStage, TriageZone } from '../types/soc';

export function zoneMeta(zone: TriageZone): {
  label: string;
  short: string;
  textClass: string;
  barColor: string;
  surfaceClass: string;
} {
  switch (zone) {
    case 'GREEN':
      return {
        label: 'Zone 1 · Certified Benign',
        short: 'Benign',
        textClass: 'text-emerald-400',
        barColor: '#10B981',
        surfaceClass: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25',
      };
    case 'YELLOW':
      return {
        label: 'Zone 2A · Boundary Ambiguity',
        short: 'Boundary',
        textClass: 'text-yellow-400',
        barColor: '#EAB308',
        surfaceClass: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/25',
      };
    case 'AMBER':
      return {
        label: 'Zone 2B · Epistemic Gray-Zone',
        short: 'Gray-Zone',
        textClass: 'text-amber-400',
        barColor: '#F59E0B',
        surfaceClass: 'bg-amber-500/10 text-amber-300 border-amber-500/25',
      };
    case 'RED':
      return {
        label: 'Zone 3 · Critical / Zero-Day',
        short: 'Critical',
        textClass: 'text-rose-400',
        barColor: '#EF4444',
        surfaceClass: 'bg-rose-500/10 text-rose-300 border-rose-500/25',
      };
  }
}

export function bypassLabel(stage: BypassStage): { text: string; tone: string } {
  switch (stage) {
    case 'TIER_0_ATTACK':
      return { text: 'Tier-0 Attack Bypass (<0.05ms)', tone: 'text-sky-400' };
    case 'TIER_0_BENIGN_SUPPRESSED':
      return { text: 'Tier-0 Benign Suppressed (<0.05ms)', tone: 'text-emerald-400' };
    case 'TIER_0_REPLAY_OVERRIDE':
      return { text: 'Tier-0B Replay Flood Override', tone: 'text-rose-400' };
    case 'TIER_1_POLYMORPHIC':
      return { text: 'Tier-1 Polymorphic Catch', tone: 'text-amber-400' };
    default:
      return { text: 'Stage 3 Neural Backbone', tone: 'text-slate-400' };
  }
}

export function ZoneTag({ zone, compact = false }: { zone: TriageZone; compact?: boolean }) {
  const m = zoneMeta(zone);
  return (
    <span className={`inline-flex items-center font-medium text-xs whitespace-nowrap ${m.textClass}`}>
      <span
        className="w-1.5 h-1.5 rounded-sm mr-1.5 shrink-0"
        style={{ backgroundColor: m.barColor }}
        aria-hidden="true"
      />
      {compact ? m.short : m.label}
    </span>
  );
}
