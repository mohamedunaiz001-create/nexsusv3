/**
 * Client-side matching for user-added rules on the pattern-based agents
 * (ioc-extraction, code-review, network-analysis, threat-intel).
 *
 * These agents run entirely in the frontend (multiAgentAnalysis.ts), unlike
 * malware-analysis which is scored server-side in python-server/app/malware_intel.
 * Rules for all five agents still live in the same `malware_rules` DB table
 * and the same /api/malware-intel/rules CRUD endpoints (see AgentDetailModal's
 * Rules panel) — this module only adds the "evaluate a 'string' rule against
 * this agent's own evidence text" step that malware-analysis already gets
 * from python-server/app/malware_intel/rules.py.
 *
 * Only `kind: 'string'` rules are meaningful here (enforced server-side too):
 * a plain, case-insensitive substring match against the text this agent is
 * already looking at. No new dependency, no change to how findings are
 * shaped — this plugs into the existing EvidenceFinding[] contract.
 */
import { EvidenceFinding, MalwareRule, RuleCapableAgentId } from '../types';
import { listMalwareRules } from './malwareIntelClient';

const RULE_CACHE = new Map<string, MalwareRule[]>();

const SEVERITY_CONFIDENCE: Record<MalwareRule['severity'], number> = {
  low: 0.4,
  medium: 0.65,
  high: 0.85,
  critical: 0.98,
};

/**
 * Fetch and cache custom rules for one or more agents. Call this once when
 * a pipeline run starts (or on app load) — NOT inside the per-tick pipeline
 * loop in App.tsx, since that loop must stay synchronous. Safe to call
 * repeatedly; each agent's rules are simply refreshed in place.
 */
export async function refreshCustomRules(agentIds: RuleCapableAgentId[]): Promise<void> {
  await Promise.all(
    agentIds.map(async (agentId) => {
      try {
        const rules = await listMalwareRules(agentId);
        RULE_CACHE.set(agentId, rules);
      } catch {
        // Leave any previously-cached rules in place on a transient failure
        // rather than wiping this agent's rule set to empty.
      }
    }),
  );
}

/** Synchronous read of whatever is currently cached for this agent (empty until refreshCustomRules has run once). */
export function getCachedCustomRules(agentId: string): MalwareRule[] {
  return RULE_CACHE.get(agentId) || [];
}

export interface CustomRuleMatchResult {
  findings: EvidenceFinding[];
  /** Highest severity confidence among matched rules, for folding into an agent's maliciousScore. 0 if nothing matched. */
  confidence: number;
  matchedCount: number;
}

/**
 * Evaluate this agent's cached 'string' rules against one blob of text
 * (whatever that agent already inspects — preview content, extracted
 * strings, IOC values, etc). Case-insensitive substring match, same
 * semantics as the server-side 'string' rule kind in malware_intel/rules.py.
 */
export function applyCustomRules(agentId: string, text: string): CustomRuleMatchResult {
  const rules = getCachedCustomRules(agentId).filter((r) => r.kind === 'string');
  if (!text || rules.length === 0) {
    return { findings: [], confidence: 0, matchedCount: 0 };
  }
  const haystack = text.toLowerCase();
  const findings: EvidenceFinding[] = [];
  let topConfidence = 0;

  for (const rule of rules) {
    const needle = rule.pattern.toLowerCase();
    if (!needle || !haystack.includes(needle)) continue;
    const confidence = SEVERITY_CONFIDENCE[rule.severity] ?? 0.5;
    topConfidence = Math.max(topConfidence, confidence);
    findings.push({
      claim: `Custom rule matched: ${rule.name}`,
      evidence: `Pattern "${rule.pattern}"${rule.family ? ` (tagged: ${rule.family})` : ''} found in scanned content.`,
      source: `custom_rule.${agentId}`,
      confidence,
    });
  }

  return { findings, confidence: topConfidence, matchedCount: findings.length };
}
