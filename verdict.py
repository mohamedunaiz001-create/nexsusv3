"""
Evidence fusion — combines the static heuristic/model score, rule matches,
and similarity results into one final verdict. This is the "don't let the
first model say 100% malware and immediately accept it" step from the
design notes: rules and similarity are weighted independently and a
rule hit on a known-benign-signed pattern can never be silently overridden
by a single noisy signal.
"""
from __future__ import annotations

from app.malware_intel.classifier import ModelWeights, predict_proba
from app.malware_intel.rules import evaluate_rules, rule_confidence
from app.malware_intel.similarity import find_similar, infer_family, similarity_confidence
from app.malware_intel.types import RuleMatch, SampleVerdictResult, StaticFeatures, Verdict


def _heuristic_static_confidence(features: StaticFeatures) -> float:
    """Used only when no trained classifier is available yet — a transparent,
    documented weighted score over the same feature signals the classifier
    would eventually learn weights for.

    Every term below is a *graduated* function of a real, already-computed
    signal (entropy, byte diversity, string shape, keyword hit count) —
    none of them are flat "matched / didn't match" bonuses. That matters:
    a flat bonus (e.g. "+15 if entropy >= 7.5, else +0") makes every file
    on one side of the threshold score identically, which is what made
    unrelated uploads collapse onto the same handful of percentages. A
    smooth function spreads files out across the score range in proportion
    to how much evidence they actually contain, instead of quantizing them
    into a few buckets.
    """
    score = 0.0
    score += min(30.0, len(features.suspiciousStrings) * 4.0)
    score += min(15.0, len(features.persistenceIndicatorStrings) * 5.0)
    score += min(10.0, len(features.networkIndicatorStrings) * 2.0)
    # Confirmed PE Import Table hits are stronger evidence than a printable
    # string match, so they're weighted higher per-hit.
    score += min(20.0, len(features.peSuspiciousImportedApis) * 6.0)

    # Entropy: graduated above a "this looks like ordinary text/code" floor
    # (~5.5 bits/byte) instead of an all-or-nothing threshold at 7.5, so a
    # file at 7.0 and a file at 7.9 no longer land on the exact same score.
    if features.entropyOverall > 5.5:
        score += min(18.0, (features.entropyOverall - 5.5) * 7.2)

    # Byte diversity: packed/encrypted/compressed payloads use most of the
    # byte alphabet; ordinary text uses a small fraction of it. This is
    # already computed for the classifier vector but was unused by the
    # heuristic fallback.
    if features.uniqueByteRatio > 0.6:
        score += min(10.0, (features.uniqueByteRatio - 0.6) * 25.0)

    # Very low printable-ratio content that isn't a recognised PE/ELF is
    # mildly notable — could be a stripped/obfuscated or non-text binary
    # blob riding in under an unrelated extension.
    if not features.peSections and not features.elfType and features.printableStringRatio < 0.5:
        score += min(8.0, (0.5 - features.printableStringRatio) * 16.0)

    if features.peSections:
        max_section_entropy = max((s["entropy"] for s in features.peSections), default=0.0)
        if max_section_entropy > 6.0:
            score += min(18.0, (max_section_entropy - 6.0) * 9.0)
        if features.peNumSections and features.peNumSections <= 2:
            score += 5.0
    return round(min(100.0, score), 2)


def _observed_characteristics(features: StaticFeatures, rule_matches: list[RuleMatch], sim_matches) -> list[str]:
    notes: list[str] = []
    if features.entropyOverall >= 7.5:
        notes.append(f"High overall entropy ({features.entropyOverall}/8.0) — consistent with packing/encryption.")
    if features.peSections:
        packed_sections = [s for s in features.peSections if s["entropy"] >= 7.2]
        if packed_sections:
            names = ", ".join(s["name"] for s in packed_sections[:3])
            notes.append(f"High-entropy PE section(s): {names}.")
    if features.suspiciousStrings:
        notes.append(f"{len(features.suspiciousStrings)} suspicious API/behavior string reference(s) found.")
    if features.peImportedDlls:
        notes.append(f"PE Import Table resolved: {len(features.peImportedDlls)} DLL(s), {sum(len(v) for v in features.peImportedDlls.values())} named import(s).")
    if features.peSuspiciousImportedApis:
        shown = ", ".join(features.peSuspiciousImportedApis[:4])
        notes.append(f"Confirmed suspicious import(s) via real Import Address Table: {shown}{', …' if len(features.peSuspiciousImportedApis) > 4 else ''}.")
    if features.persistenceIndicatorStrings:
        shown = ", ".join(features.persistenceIndicatorStrings[:4])
        more = f", +{len(features.persistenceIndicatorStrings) - 4} more" if len(features.persistenceIndicatorStrings) > 4 else ""
        notes.append(f"Persistence-related indicator string(s) found: {shown}{more}.")
    if features.networkIndicatorStrings:
        shown = ", ".join(features.networkIndicatorStrings[:4])
        more = f", +{len(features.networkIndicatorStrings) - 4} more" if len(features.networkIndicatorStrings) > 4 else ""
        notes.append(f"Outbound network / HTTP indicator string(s) found: {shown}{more}.")
    if rule_matches:
        notes.append(f"{len(rule_matches)} detection rule(s) matched.")
    if sim_matches and sim_matches[0].score >= 60:
        notes.append(f"Structurally similar to previously catalogued sample '{sim_matches[0].name}' ({sim_matches[0].score}%).")
    if not notes:
        notes.append("No high-signal static indicators observed.")
    return notes


def _verdict_from_confidence(confidence: float, rule_matches: list[RuleMatch]) -> Verdict:
    if any(m.severity in ("high", "critical") for m in rule_matches):
        return "malicious"
    if confidence >= 75:
        return "malicious"
    if confidence >= 40:
        return "suspicious"
    if confidence < 15 and not rule_matches:
        return "clean"
    return "unknown"


def compute_verdict(
    features: StaticFeatures,
    rules: list[dict],
    similarity_corpus: list[dict],
    model: ModelWeights | None,
    exclude_sample_id: str | None = None,
) -> SampleVerdictResult:
    rule_matches = evaluate_rules(features, rules)
    r_conf = rule_confidence(rule_matches)

    sim_matches = find_similar(features.vector, similarity_corpus, top_n=5, exclude_sample_id=exclude_sample_id)
    s_conf = similarity_confidence(sim_matches)

    model_conf = None
    if model is not None and model.numSamples > 0:
        model_conf = round(predict_proba(features.vector, model) * 100, 1)
        static_conf = model_conf
    else:
        static_conf = _heuristic_static_confidence(features)

    # Evidence fusion: rules are near-deterministic so they get the most
    # weight; the model/heuristic and similarity scores back each other up.
    weights_sum = 0.0
    fused = 0.0
    for value, weight in ((r_conf, 0.45), (static_conf, 0.35), (s_conf, 0.20)):
        if value > 0:
            fused += value * weight
            weights_sum += weight
    confidence = round(fused / weights_sum, 1) if weights_sum > 0 else round(static_conf * 0.5, 1)

    verdict = _verdict_from_confidence(confidence, rule_matches)
    family = infer_family(sim_matches) or next((m.family for m in rule_matches if m.family), None)

    return SampleVerdictResult(
        verdict=verdict,
        confidence=confidence,
        staticConfidence=round(static_conf, 1),
        ruleConfidence=round(r_conf, 1),
        similarityConfidence=round(s_conf, 1),
        modelConfidence=model_conf,
        modelVersion=getattr(model, "version", None) if (model is not None and model.numSamples) else None,
        observedCharacteristics=_observed_characteristics(features, rule_matches, sim_matches),
        ruleMatches=rule_matches,
        similarSamples=sim_matches,
        likelyFamily=family,
    )
