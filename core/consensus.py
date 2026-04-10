"""
sentinel/core/consensus.py

Multi-Model Consensus Engine.
Sends the same analysis prompt to multiple AI models independently.
Cross-references findings to produce confidence-scored output.

Models:
  - Claude Sonnet (Anthropic) — primary
  - GPT-4o (OpenAI) — cross-reference

Confidence scoring:
  - 2/2 models agree → HIGH confidence
  - 1/2 models flag  → MEDIUM confidence (still surfaces, marked for review)

This is the pattern recognition amplifier.
Different models have different training data and blind spots.
Agreement = real signal. Disagreement = worth human review.
"""

import os
import json
from typing import Optional
from anthropic import Anthropic

from .models import Finding, Severity, AgentName

# Initialize clients
_anthropic_client = None
_openai_client    = None

def _get_anthropic():
    global _anthropic_client
    if not _anthropic_client:
        _anthropic_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    return _anthropic_client

def _get_openai():
    global _openai_client
    if not _openai_client:
        try:
            from openai import OpenAI
            _openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        except ImportError:
            print("[CONSENSUS] OpenAI not installed. Run: pip install openai")
        except Exception as e:
            print(f"[CONSENSUS] OpenAI init failed: {e}")
    return _openai_client


ANALYSIS_PROMPT = """You are a senior security engineer performing code review.
Analyze the following code/content for security vulnerabilities.

For each vulnerability found, respond with a JSON array:
[
  {
    "title": "Short vulnerability name",
    "description": "What the vulnerability is and why it's dangerous",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "location": "file:line or description of where",
    "remediation": "Specific fix"
  }
]

Rules:
- Only report real vulnerabilities, not style issues
- Be specific about location
- Severity must reflect actual exploitability
- Return empty array [] if no vulnerabilities found
- Return ONLY the JSON array, no other text
"""


def consensus_analyze(content: str, context: str = "") -> list[dict]:
    """
    Run the same content through multiple models.
    Returns confidence-scored merged findings.

    Args:
        content: Code or config content to analyze
        context: Additional context (filename, language, etc.)
    """
    user_msg = f"Context: {context}\n\nContent to analyze:\n```\n{content[:8000]}\n```"

    results = {}

    # Run Claude
    claude_findings = _run_claude(user_msg)
    if claude_findings is not None:
        results["claude"] = claude_findings

    # Run GPT-4o if available
    if os.getenv("OPENAI_API_KEY"):
        gpt_findings = _run_gpt4o(user_msg)
        if gpt_findings is not None:
            results["gpt4o"] = gpt_findings

    if not results:
        return []

    # Merge with confidence scoring
    return _merge_with_confidence(results)


def _run_claude(user_msg: str) -> Optional[list]:
    """Run analysis through Claude."""
    try:
        client = _get_anthropic()
        resp = client.messages.create(
            model=os.getenv("ORCHESTRATOR_MODEL", "claude-sonnet-4-20250514"),
            max_tokens=2000,
            system=ANALYSIS_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        return _parse_model_response(resp.content[0].text, "claude")
    except Exception as e:
        print(f"[CONSENSUS/Claude] Error: {e}")
        return None


def _run_gpt4o(user_msg: str) -> Optional[list]:
    """Run analysis through GPT-4o."""
    try:
        client = _get_openai()
        if not client:
            return None
        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": ANALYSIS_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            max_tokens=2000,
        )
        return _parse_model_response(resp.choices[0].message.content, "gpt4o")
    except Exception as e:
        print(f"[CONSENSUS/GPT-4o] Error: {e}")
        return None


def _parse_model_response(raw: str, model_name: str) -> list:
    """Parse a model's JSON response into a list of findings."""
    if not raw:
        return []
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            for item in data:
                item["_source_model"] = model_name
            return data
    except json.JSONDecodeError:
        pass
    return []


def _merge_with_confidence(results: dict[str, list]) -> list[dict]:
    """
    Merge findings from multiple models with confidence scoring.
    Uses semantic similarity to group matching findings.
    """
    all_models = list(results.keys())
    num_models = len(all_models)

    # Flatten all findings with source tracking
    all_findings = []
    for model, findings in results.items():
        for f in findings:
            all_findings.append(f)

    if num_models == 1:
        # Only one model ran — all findings get MEDIUM confidence
        for f in all_findings:
            f["confidence"]    = "MEDIUM"
            f["models_agreed"] = 1
            f["total_models"]  = 1
        return all_findings

    # Group similar findings across models
    merged  = []
    matched = set()

    flat_all = list(enumerate(all_findings))

    for i, finding_a in flat_all:
        if i in matched:
            continue

        group = [finding_a]
        matched.add(i)

        for j, finding_b in flat_all:
            if j <= i or j in matched:
                continue
            if _findings_similar(finding_a, finding_b):
                group.append(finding_b)
                matched.add(j)

        models_in_group = set(f.get("_source_model") for f in group)
        agreement_count = len(models_in_group)

        # Use the highest severity from the group
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        best_sev  = min(
            (f.get("severity", "INFO") for f in group),
            key=lambda s: sev_order.index(s) if s in sev_order else 99
        )

        # Confidence based on agreement
        if agreement_count == num_models:
            confidence = "HIGH"
        elif agreement_count > 1:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"  # Only one model flagged it — still surface, lower priority

        # Use the most detailed finding description
        best = max(group, key=lambda f: len(f.get("description", "")))
        best["severity"]      = best_sev
        best["confidence"]    = confidence
        best["models_agreed"] = agreement_count
        best["total_models"]  = num_models
        best["models"]        = list(models_in_group)

        merged.append(best)

    # Sort: HIGH confidence first, then by severity
    conf_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sev_order  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    merged.sort(key=lambda f: (
        conf_order.get(f.get("confidence", "LOW"), 2),
        sev_order.get(f.get("severity", "INFO"), 4)
    ))

    return merged


def _findings_similar(a: dict, b: dict) -> bool:
    """
    Check if two findings from different models refer to the same issue.
    Uses title similarity and location overlap.
    """
    # Different models → potential match
    if a.get("_source_model") == b.get("_source_model"):
        return False

    title_a = a.get("title", "").lower()
    title_b = b.get("title", "").lower()
    loc_a   = a.get("location", "").lower()
    loc_b   = b.get("location", "").lower()

    # Check keyword overlap in titles
    words_a = set(title_a.split())
    words_b = set(title_b.split())
    stop    = {"a", "the", "in", "on", "at", "to", "for", "of", "and", "or"}
    words_a -= stop
    words_b -= stop

    if len(words_a) > 0 and len(words_b) > 0:
        overlap = len(words_a & words_b) / min(len(words_a), len(words_b))
        if overlap >= 0.5:
            return True

    # Check location similarity
    if loc_a and loc_b and loc_a == loc_b:
        return True

    # Check same severity + similar description keywords
    if a.get("severity") == b.get("severity"):
        desc_a = set(a.get("description", "").lower().split())
        desc_b = set(b.get("description", "").lower().split())
        desc_a -= stop
        desc_b -= stop
        if len(desc_a) > 5 and len(desc_b) > 5:
            overlap = len(desc_a & desc_b) / min(len(desc_a), len(desc_b))
            if overlap >= 0.4:
                return True

    return False


def consensus_findings_to_sentinel(consensus_results: list[dict],
                                    source_path: str) -> list[Finding]:
    """Convert consensus engine output to Sentinel Finding objects."""
    from .models import Severity

    sev_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH":     Severity.HIGH,
        "MEDIUM":   Severity.MEDIUM,
        "LOW":      Severity.LOW,
        "INFO":     Severity.INFO,
    }

    findings = []
    for r in consensus_results:
        confidence = r.get("confidence", "LOW")
        models     = r.get("models", [])
        models_str = f"[{'/'.join(m.upper() for m in models)}] {confidence} confidence"

        findings.append(Finding(
            agent=AgentName.SAST,
            title=f"[Consensus] {r.get('title', 'Unknown')}",
            description=f"{r.get('description', '')} — {models_str}",
            severity=sev_map.get(r.get("severity", "LOW"), Severity.LOW),
            file_path=r.get("location") or source_path,
            remediation=r.get("remediation", "Review the identified issue."),
        ))
    return findings
