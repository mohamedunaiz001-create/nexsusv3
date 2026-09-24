import React, { useEffect, useState } from 'react';
import { Plus, Trash2, ShieldAlert, Loader2 } from 'lucide-react';
import { MalwareRule } from '../../types';
import { listMalwareRules, createMalwareRule, deleteMalwareRule } from '../../utils/malwareIntelClient';
import { refreshCustomRules } from '../../utils/customRules';

interface AgentRulesPanelProps {
  /** Rule-capable agent id, e.g. 'malware-analysis' | 'ioc-extraction' | 'code-review' | 'network-analysis' | 'threat-intel'. */
  agentId: string;
}

const SEVERITIES: MalwareRule['severity'][] = ['low', 'medium', 'high', 'critical'];

/**
 * Lets an analyst add/remove detection or matching rules scoped to one
 * agent. malware-analysis rules feed the real static-analysis pipeline
 * (python-server/app/malware_intel/rules.py) on the next scan/rescan.
 * Rules for the other four agents are evaluated client-side against that
 * agent's own evidence text (see src/utils/customRules.ts) the next time
 * that agent's step runs in the analysis pipeline.
 */
export const AgentRulesPanel: React.FC<AgentRulesPanelProps> = ({ agentId }) => {
  const [rules, setRules] = useState<MalwareRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [showForm, setShowForm] = useState(false);

  const isMalwareAnalysis = agentId === 'malware-analysis';
  const [name, setName] = useState('');
  const [kind, setKind] = useState<MalwareRule['kind']>('string');
  const [pattern, setPattern] = useState('');
  const [family, setFamily] = useState('');
  const [severity, setSeverity] = useState<MalwareRule['severity']>('medium');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await listMalwareRules(agentId);
      setRules(list);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rules.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agentId]);

  const resetForm = () => {
    setName('');
    setKind('string');
    setPattern('');
    setFamily('');
    setSeverity('medium');
  };

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !pattern.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await createMalwareRule({
        name: name.trim(),
        kind: isMalwareAnalysis ? kind : 'string',
        pattern: pattern.trim(),
        family: family.trim() || undefined,
        severity,
        agentId,
      });
      resetForm();
      setShowForm(false);
      await load();
      await refreshCustomRules([agentId as any]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add rule.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (ruleId: string) => {
    setError(null);
    try {
      await deleteMalwareRule(ruleId);
      setRules((prev) => prev.filter((r) => r.id !== ruleId));
      await refreshCustomRules([agentId as any]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete rule.');
    }
  };

  const severityColor = (s: MalwareRule['severity']) =>
    s === 'critical' ? 'text-red-400 border-red-500/30 bg-red-950/40'
      : s === 'high' ? 'text-orange-400 border-orange-500/30 bg-orange-950/40'
      : s === 'medium' ? 'text-yellow-400 border-yellow-500/30 bg-yellow-950/40'
      : 'text-slate-400 border-slate-500/30 bg-slate-950/40';

  return (
    <div className="p-3 rounded-xl bg-[#100724] border border-purple-500/20">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] font-mono uppercase text-purple-300 font-bold flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
          Custom Detection Rules
        </span>
        <button
          type="button"
          onClick={() => setShowForm((v) => !v)}
          className="flex items-center gap-1 px-2 py-1 rounded-lg bg-purple-950/60 hover:bg-purple-900/60 border border-purple-500/30 text-purple-200 text-[11px] font-mono font-semibold transition-colors"
        >
          <Plus className="w-3 h-3" />
          Add Rule
        </button>
      </div>

      {error && (
        <div className="mb-2 px-2.5 py-1.5 rounded-lg bg-red-950/40 border border-red-500/30 text-red-300 text-[11px] font-mono">
          {error}
        </div>
      )}

      {showForm && (
        <form onSubmit={handleAdd} className="mb-3 p-2.5 rounded-lg bg-[#0a0518] border border-purple-500/20 space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Rule name"
              maxLength={128}
              required
              className="px-2 py-1.5 rounded-md bg-[#12082b] border border-purple-500/30 text-xs text-slate-200 font-mono focus:outline-none focus:border-purple-400"
            />
            {isMalwareAnalysis ? (
              <select
                value={kind}
                onChange={(e) => setKind(e.target.value as MalwareRule['kind'])}
                className="px-2 py-1.5 rounded-md bg-[#12082b] border border-purple-500/30 text-xs text-slate-200 font-mono focus:outline-none focus:border-purple-400"
              >
                <option value="string">string match</option>
                <option value="hash">exact hash</option>
                <option value="import_hit">PE import</option>
              </select>
            ) : (
              <div className="px-2 py-1.5 rounded-md bg-[#0d0620] border border-purple-500/10 text-[11px] text-slate-500 font-mono flex items-center">
                string match (substring)
              </div>
            )}
          </div>
          <input
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            placeholder={kind === 'hash' && isMalwareAnalysis ? 'md5 / sha1 / sha256 hex digest' : 'text pattern to match'}
            maxLength={512}
            required
            className="w-full px-2 py-1.5 rounded-md bg-[#12082b] border border-purple-500/30 text-xs text-slate-200 font-mono focus:outline-none focus:border-purple-400"
          />
          <div className="grid grid-cols-2 gap-2">
            <input
              value={family}
              onChange={(e) => setFamily(e.target.value)}
              placeholder="Family / tag (optional)"
              maxLength={128}
              className="px-2 py-1.5 rounded-md bg-[#12082b] border border-purple-500/30 text-xs text-slate-200 font-mono focus:outline-none focus:border-purple-400"
            />
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as MalwareRule['severity'])}
              className="px-2 py-1.5 rounded-md bg-[#12082b] border border-purple-500/30 text-xs text-slate-200 font-mono focus:outline-none focus:border-purple-400"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={() => { setShowForm(false); resetForm(); }}
              className="px-3 py-1.5 rounded-md text-slate-400 hover:text-white text-[11px] font-mono"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="flex items-center gap-1 px-3 py-1.5 rounded-md bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white text-[11px] font-mono font-bold disabled:opacity-50"
            >
              {submitting && <Loader2 className="w-3 h-3 animate-spin" />}
              Save Rule
            </button>
          </div>
        </form>
      )}

      {loading ? (
        <div className="text-[11px] text-slate-500 font-mono py-2">Loading rules…</div>
      ) : rules.length === 0 ? (
        <div className="text-[11px] text-slate-500 font-mono py-2">
          No custom rules yet for this agent. Rules added here are checked every time this agent analyzes new evidence.
        </div>
      ) : (
        <div className="space-y-1.5 max-h-48 overflow-y-auto no-scrollbar">
          {rules.map((rule) => (
            <div
              key={rule.id}
              className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg bg-[#0a0518] border border-purple-500/10 text-[11px] font-mono"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-slate-200 font-semibold truncate">{rule.name}</span>
                  <span className={`px-1.5 py-0.5 rounded border text-[10px] ${severityColor(rule.severity)}`}>
                    {rule.severity}
                  </span>
                  <span className="px-1.5 py-0.5 rounded border border-purple-500/20 text-purple-300 text-[10px]">
                    {rule.kind}
                  </span>
                </div>
                <div className="text-slate-500 truncate" title={rule.pattern}>{rule.pattern}</div>
              </div>
              <button
                type="button"
                onClick={() => handleDelete(rule.id)}
                title="Delete rule"
                className="p-1 rounded text-slate-500 hover:text-red-400 hover:bg-red-950/30 transition-colors flex-shrink-0"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
