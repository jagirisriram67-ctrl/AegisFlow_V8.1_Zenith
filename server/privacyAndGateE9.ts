import type { GateE9Audit } from '../src/types/soc.js';

/**
 * Reversible Zero-Leakage Privacy Proxy
 * Pseudonymizes all RFC1918/internal IPs and internal hostnames before any external
 * 3rd-party LLM API call, and transparently rehydrates them locally on response.
 */
export class ReversiblePrivacyProxy {
  private realToToken = new Map<string, string>();
  private tokenToReal = new Map<string, string>();
  private counter = 0;

  private static readonly INTERNAL_IP_REGEX =
    /\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b/g;

  private static readonly INTERNAL_HOST_REGEX =
    /\b[a-zA-Z0-9-]+\.(?:corp|internal|local|lan|iot\.local)\b/gi;

  private getOrAssignToken(raw: string, prefix: string): string {
    const existing = this.realToToken.get(raw);
    if (existing) return existing;
    this.counter += 1;
    const token = `${prefix}_${String(this.counter).padStart(2, '0')}`;
    this.realToToken.set(raw, token);
    this.tokenToReal.set(token, raw);
    return token;
  }

  public sanitize(text: string): { sanitized: string; maskedCount: number; tokenMap: Record<string, string> } {
    let maskedCount = 0;
    let out = text.replace(ReversiblePrivacyProxy.INTERNAL_IP_REGEX, (ip) => {
      maskedCount += 1;
      const prefix = ip.startsWith('10.20.88.') || ip.startsWith('10.20.30.9')
        ? 'INTERNAL_IOT_HOST'
        : ip.startsWith('192.168.')
        ? 'INTERNAL_SERVER'
        : 'INTERNAL_HOST';
      return this.getOrAssignToken(ip, prefix);
    });

    out = out.replace(ReversiblePrivacyProxy.INTERNAL_HOST_REGEX, (host) => {
      maskedCount += 1;
      return this.getOrAssignToken(host, 'INTERNAL_ASSET');
    });

    const tokenMap: Record<string, string> = {};
    for (const [tok, real] of this.tokenToReal.entries()) {
      tokenMap[tok] = real;
    }
    return { sanitized: out, maskedCount, tokenMap };
  }

  public rehydrate(text: string): string {
    let out = text;
    // Sort by token length descending to avoid partial prefix replacements
    const entries = Array.from(this.tokenToReal.entries()).sort((a, b) => b[0].length - a[0].length);
    for (const [token, real] of entries) {
      out = out.split(token).join(real);
    }
    return out;
  }

  public getMappingCount(): number {
    return this.realToToken.size;
  }
}

/**
 * Gate E9 Deterministic Safety Auditor + Benign Blast-Radius Dry-Run
 * Strictly validates LLM-suggested firewall containment commands (never auto-executed).
 */
const ALLOWED_COMMAND_PATTERNS: RegExp[] = [
  /^nft add rule inet filter (input|forward|output) ip saddr (\d{1,3}(?:\.\d{1,3}){3})(?:\/(24|32))?(?: (tcp|udp) dport (\d{1,5}))? (drop|reject)$/,
  /^iptables -A (INPUT|FORWARD) -s (\d{1,3}(?:\.\d{1,3}){3})(?:\/(24|32))?(?: -p (tcp|udp) --dport (\d{1,5}))? -j (DROP|REJECT)$/,
];

const FORBIDDEN_TOKENS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\/0\b/, reason: 'Wildcard /0 CIDR subnet block is strictly prohibited.' },
  { pattern: /\b127\.0\.0\.1\b|\blocalhost\b|::1/, reason: 'Loopback interface block is strictly prohibited.' },
  { pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.1\b/, reason: 'Default gateway (.1) IP cannot be blocked automatically.' },
  { pattern: /(?:dport|--dport)\s+22\b/, reason: 'Blocking management SSH port 22 is forbidden by Gate E9.' },
  { pattern: /[;&|`$<>\\]/, reason: 'Shell chaining, subshell, or redirection metacharacters detected.' },
  { pattern: /\b(rm|curl|wget|bash|sh|nc|python|perl|chmod|chown|flush|delete table)\b/i, reason: 'Destructive or non-firewall command token detected.' },
];

function isValidIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  return parts.length === 4 && parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255);
}

export function buildSafeDefaultNftRule(srcIp: string, dstPort?: number, protocol?: number): string {
  const safeIp = isValidIpv4(srcIp) && !srcIp.endsWith('.1') && srcIp !== '127.0.0.1' ? srcIp : '198.51.100.250';
  const proto = protocol === 17 ? 'udp' : 'tcp';
  if (dstPort && dstPort > 0 && dstPort <= 65535 && dstPort !== 22) {
    return `nft add rule inet filter input ip saddr ${safeIp} ${proto} dport ${dstPort} drop`;
  }
  return `nft add rule inet filter input ip saddr ${safeIp} drop`;
}

export function auditContainmentRuleGateE9(
  rawCommand: string,
  recentBenignFlows: Array<{ src_ip: string; dst_port: number; protocol: number }>
): GateE9Audit {
  const command = rawCommand.trim().replace(/\s+/g, ' ');
  const violations: string[] = [];

  for (const check of FORBIDDEN_TOKENS) {
    if (check.pattern.test(command)) {
      violations.push(check.reason);
    }
  }

  let matchedIp: string | null = null;
  let matchedCidr: string | null = null;
  let matchedProto: string | null = null;
  let matchedPort: number | null = null;
  let matchedAllowlist = false;

  for (const regex of ALLOWED_COMMAND_PATTERNS) {
    const m = command.match(regex);
    if (m) {
      matchedAllowlist = true;
      matchedIp = m[2];
      matchedCidr = m[3] ?? '32';
      matchedProto = m[4] ?? null;
      matchedPort = m[5] ? Number(m[5]) : null;
      break;
    }
  }

  if (!matchedAllowlist) {
    violations.push('Command does not match strict Gate E9 nftables/iptables single-rule allowlist grammar.');
  } else if (matchedIp && !isValidIpv4(matchedIp)) {
    violations.push(`Invalid IPv4 address: ${matchedIp}`);
  }

  if (matchedPort !== null && (matchedPort < 1 || matchedPort > 65535 || matchedPort === 22)) {
    violations.push(`Invalid or protected destination port: ${matchedPort}`);
  }

  // Digital-Twin Blast-Radius Dry-Run against stored GREEN Certified Benign flows
  const checked = recentBenignFlows.length;
  let affected = 0;

  if (matchedAllowlist && matchedIp) {
    const targetPrefix24 = matchedIp.split('.').slice(0, 3).join('.');
    for (const flow of recentBenignFlows) {
      const ipMatch =
        matchedCidr === '24'
          ? flow.src_ip.startsWith(targetPrefix24 + '.')
          : flow.src_ip === matchedIp;
      if (!ipMatch) continue;
      if (matchedPort !== null && flow.dst_port !== matchedPort) continue;
      if (matchedProto === 'tcp' && flow.protocol !== 6) continue;
      if (matchedProto === 'udp' && flow.protocol !== 17) continue;
      affected += 1;
    }
  }

  const blastPct = checked > 0 ? Number(((affected / checked) * 100).toFixed(2)) : 0;
  if (blastPct > 1.0) {
    violations.push(`Blast-Radius Dry-Run exceeded 1.00% benign collateral threshold (${blastPct.toFixed(2)}%).`);
  }

  const passed = violations.length === 0;
  const verifiedBadge = passed
    ? `Gate E9 Passed · Blast Radius: ${blastPct.toFixed(2)}% Benign Collateral (${affected}/${checked} flows)`
    : `Gate E9 Blocked · ${violations[0]}`;

  return {
    command,
    passed,
    violations,
    blast_radius_checked_flows: checked,
    blast_radius_affected_flows: affected,
    blast_radius_pct: blastPct,
    verified_badge: verifiedBadge,
  };
}
