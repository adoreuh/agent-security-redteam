"""
Reporting for agent security red-team runs.

Generates Markdown summary, JSON report, and JSONL findings.

SECURITY NOTE: When include_traces=True, the output may contain sensitive data
(secret file contents, emails, HTTP request bodies, OCR text, PII). Default is
include_traces=False. In production, always review outputs before sharing.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .candidate import CandidateResult
from .config import ALL_PREDICATES, OFFICIAL_PREDICATES
from .search import SearchResult


# ---------------------------------------------------------------------------
# Markdown summary
# ---------------------------------------------------------------------------

def summarize_findings(findings: Iterable[CandidateResult]) -> str:
    findings_list = list(findings)
    counts = Counter()
    for f in findings_list:
        counts.update(f.predicate_hits)

    lines = [
        "# Security Search Summary",
        "",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
        f"**Total findings:** {len(findings_list)}",
        "",
        "## Predicate counts",
        "",
        "| Predicate | Count | Official |",
        "|-----------|-------|----------|",
    ]
    for name, count in counts.most_common():
        is_official = "yes" if name in OFFICIAL_PREDICATES else "—"
        lines.append(f"| {name} | {count} | {is_official} |")
    lines.append("")

    lines.append("## Top findings")
    for i, f in enumerate(findings_list[:20], start=1):
        lines.append(
            f"{i}. **{f.candidate.candidate_id}**: "
            f"score={f.score:.4f}, "
            f"hits={', '.join(f.predicate_hits)}, "
            f"cell={'new' if f.unique_cell else 'dup'}"
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON report (traces excluded by default for data safety)
# ---------------------------------------------------------------------------

def generate_json_report(
    result: SearchResult,
    include_traces: bool = False,
) -> Dict[str, Any]:
    """Generate machine-readable JSON report.

    IMPORTANT: include_traces=True may leak secret file contents, emails,
    HTTP request bodies, and other sensitive data. Only enable for
    debugging in controlled environments.
    """
    pred_counter = Counter()
    cat_counter = Counter()
    cell_sigs: set = set()

    for f in result.findings:
        pred_counter.update(f.predicate_hits)
        cat_counter[f.candidate.metadata.get("threat_category", "unknown")] += 1
        if f.cell_signature:
            cell_sigs.add(f.cell_signature)

    unique_cells = len(cell_sigs)

    report: Dict[str, Any] = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "schema_version": "1.1.0",
            "note": "Local approximations only. Predicate/cell/score values are NOT official evaluator output.",
        },
        "summary": {
            "total_findings": len(result.findings),
            "total_traces": len(result.traces),
            "budget_used": result.budget_used,
            "budget_total": result.budget_total,
            "budget_utilization_pct": round(
                result.budget_used / max(result.budget_total, 1) * 100, 1
            ),
            "elapsed_seconds": round(result.elapsed_seconds, 2),
            "unique_cells": unique_cells,
            "exit_graceful": result.exit_graceful,
        },
        "predicates": {
            "official": {p: pred_counter.get(p, 0) for p in OFFICIAL_PREDICATES},
            "research": {
                p: pred_counter.get(p, 0)
                for p in ALL_PREDICATES if p not in OFFICIAL_PREDICATES
            },
            "total_hits": sum(pred_counter.values()),
        },
        "threat_coverage": {
            cat: {"count": count, "pct": round(count / max(len(result.findings), 1) * 100, 1)}
            for cat, count in cat_counter.most_common()
        },
        "cell_diversity": {
            "unique_cells": unique_cells,
            "duplicate_cells": len(result.findings) - unique_cells,
            "diversity_ratio": round(unique_cells / max(len(result.findings), 1), 2),
        },
        "archive_summary": result.archive_summary,
        "top_findings": [f.to_dict() for f in result.findings[:50]],
    }

    # Traces contain potentially sensitive data — only include when explicitly requested
    if include_traces:
        report["_warning"] = (
            "Traces included. May contain secret file contents, emails, "
            "HTTP request bodies, and other sensitive data. Review before sharing."
        )
        report["traces"] = [t.export_dict() for t in result.traces]

    return report


def write_report(
    result: SearchResult,
    output_dir: Path,
    include_traces: bool = False,
) -> Dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, Path] = {}

    md_path = output_dir / "summary.md"
    md_path.write_text(summarize_findings(result.findings), encoding="utf-8")
    paths["markdown"] = md_path

    json_path = output_dir / "report.json"
    json_report = generate_json_report(result, include_traces=include_traces)
    json_path.write_text(
        json.dumps(json_report, indent=2, ensure_ascii=False), encoding="utf-8",
    )
    paths["json"] = json_path

    findings_path = output_dir / "findings.jsonl"
    with open(findings_path, "w", encoding="utf-8") as f:
        for finding in result.findings:
            f.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")
    paths["findings_jsonl"] = findings_path

    return paths


# ---------------------------------------------------------------------------
# Experiment report template
# ---------------------------------------------------------------------------

EXPERIMENT_REPORT_TEMPLATE = """\
# Experiment Report: {title}

**Date:** {date}
**SDK:** aicomp-sdk 3.1.2 (compatible)
**Seed:** {seed}

## Configuration

| Parameter | Value |
|-----------|-------|
| time_budget_s | {time_budget_s} |
| max_tool_hops | {max_tool_hops} |
| max_candidates | {max_candidates} |
| mutation_depth | {mutation_depth} |

## Results

| Metric | Value |
|--------|-------|
| Total findings | {total_findings} |
| Budget used | {budget_used}/{budget_total} ({budget_utilization_pct}%) |
| Elapsed | {elapsed_seconds:.1f}s |
| Unique cells | {unique_cells} |
| Cell diversity | {diversity_ratio} |
| Exit graceful | {exit_graceful} |

### Predicate Hits

| Predicate | Count | Severity |
|-----------|-------|----------|
{predicate_table}

### Threat Category Coverage

{threat_coverage}

## Notes

- **Predicates and Cell signatures are LOCAL APPROXIMATIONS.**
  The official evaluator recomputes them during replay.
- **Paper-reported numbers** are external benchmarks cited for comparison only.
- **Local results** are actual measurements from this run.

## Reproducibility

```bash
# SDK validation
aicomp validate redteam attack.py

# Local smoke test
aicomp test redteam attack.py --budget-s 60 --agent deterministic

# Full evaluation
aicomp evaluate redteam attack.py --budget-s {budget_s} --agent deterministic --env gym
```
"""


def generate_experiment_report(
    result: SearchResult,
    title: str = "Agent Security Red-Team Run",
    seed: int = 42,
    max_candidates: int = 50,
    mutation_depth: int = 3,
    time_budget_s: float = 1800.0,
    max_tool_hops: int = 8,
) -> str:
    pred_counter = Counter()
    for f in result.findings:
        pred_counter.update(f.predicate_hits)

    cat_counter = Counter()
    for f in result.findings:
        cat_counter[f.candidate.metadata.get("threat_category", "unknown")] += 1

    cell_sigs = set(f.cell_signature for f in result.findings if f.cell_signature)
    unique_cells = len(cell_sigs)

    predicate_table = "\n".join(
        f"| {p} | {pred_counter.get(p, 0)} | {5 if p in ('EXFILTRATION','UNTRUSTED_TO_ACTION') else 4 if p == 'DESTRUCTIVE_WRITE' else 3 if p == 'CONFUSED_DEPUTY' else '—'} |"
        for p in ALL_PREDICATES
        if pred_counter.get(p, 0) > 0
    )

    threat_coverage = "\n".join(
        f"- **{cat}**: {count} findings"
        for cat, count in cat_counter.most_common()
    )

    return EXPERIMENT_REPORT_TEMPLATE.format(
        title=title,
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        seed=seed,
        time_budget_s=time_budget_s,
        max_tool_hops=max_tool_hops,
        max_candidates=max_candidates,
        mutation_depth=mutation_depth,
        total_findings=len(result.findings),
        budget_used=result.budget_used,
        budget_total=result.budget_total,
        budget_utilization_pct=round(result.budget_used / max(result.budget_total, 1) * 100, 1),
        elapsed_seconds=result.elapsed_seconds,
        unique_cells=unique_cells,
        diversity_ratio=round(unique_cells / max(len(result.findings), 1), 2),
        exit_graceful=result.exit_graceful,
        predicate_table=predicate_table,
        threat_coverage=threat_coverage,
        budget_s=int(time_budget_s),
    )
