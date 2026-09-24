import { AIProvider } from '../types';

export interface ModelOption {
  /** Encoded value for a <select>: "providerName::model" */
  value: string;
  label: string;
  providerName: string;
  model: string;
}

/** Encodes a provider+model pair into a single <select> option value. */
export function encodeModelOption(providerName: string, model: string): string {
  return `${providerName}::${model}`;
}

/** Decodes a <select> option value back into { providerName, model }. */
export function decodeModelOption(value: string): { providerName: string; model: string } {
  const idx = value.indexOf('::');
  if (idx === -1) return { providerName: '', model: value };
  return { providerName: value.slice(0, idx), model: value.slice(idx + 2) };
}

/**
 * Flattens every provider's available models into one list, for pickers
 * where an operator assigns a specific engine (provider + model) to
 * something — a specialist agent, the CEO, etc. Falls back to the
 * provider's single `model` field when `availableModels` isn't populated.
 *
 * Intentionally does NOT filter out disabled providers: `enabled` just
 * reflects whether a provider is currently toggled on in Provider Hub
 * (all providers start disabled until an API key is added), not whether
 * its models are valid choices. The CEO's own "Active Model" / "Set as
 * Primary" picker in AIProvidersModal lists every provider the same way —
 * this mirrors that so an agent's model list isn't a near-empty subset.
 */
export function getFlattenedModelOptions(providers: AIProvider[]): ModelOption[] {
  const options: ModelOption[] = [];
  for (const p of providers) {
    const models = p.availableModels && p.availableModels.length > 0 ? p.availableModels : p.model ? [p.model] : [];
    for (const m of models) {
      options.push({ value: encodeModelOption(p.name, m), label: `${p.name} — ${m}`, providerName: p.name, model: m });
    }
  }
  return options;
}

function normalizeModelName(s: string): string {
  return s.toLowerCase().replace(/[\s_]+/g, '-').replace(/[^a-z0-9-.]/g, '');
}

/**
 * Finds the option matching a currently-assigned model name, tolerant of
 * the mismatch between display-style names (e.g. "Claude 3.5 Sonnet", used
 * by the seeded specialist agents) and API-style ids (e.g.
 * "claude-3-5-sonnet", used by provider catalogs) so the picker can
 * pre-select the agent's current model instead of showing it unmatched.
 */
export function findMatchingOption(options: ModelOption[], modelName: string): ModelOption | undefined {
  const exact = options.find((o) => o.model === modelName);
  if (exact) return exact;
  const normalizedTarget = normalizeModelName(modelName);
  return options.find((o) => normalizeModelName(o.model) === normalizedTarget);
}
