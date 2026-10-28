"""Run the labeled triage eval and write docs/eval.md plus raw results."""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent.pipeline import triage
from config import Settings

EVALS_DIR = Path(__file__).resolve().parent
ROOT = EVALS_DIR.parent
CASES_PATH = EVALS_DIR / "cases.json"
RESULTS_DIR = EVALS_DIR / "results"
DOCS_PATH = ROOT / "docs" / "eval.md"
STATS_PATH = ROOT / "data" / "clean" / "stats.json"


def load_cases(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


async def run_case(case: dict[str, Any], *, retries: int, delay: float) -> Any:
    last_result = None
    for attempt in range(retries + 1):
        result = await triage(case["input"])
        last_result = result
        transient = result.error and ("429" in result.error or "RESOURCE_EXHAUSTED" in result.error)
        if not transient:
            return result
        if attempt < retries:
            await asyncio.sleep(delay * (attempt + 1) * 5)
    return last_result


def build_row(case: dict[str, Any], result: Any) -> dict[str, Any]:
    expected = case["expected_label"]
    predicted = result.verdict.classification
    labeled = expected in {"malicious", "benign"}
    correct = labeled and predicted == expected
    confidently_wrong = labeled and predicted != expected and result.verdict.confidence >= 0.7
    return {
        "id": case["id"],
        "group": case.get("group", expected),
        "input": case["input"],
        "expected_label": expected,
        "expected_status": case.get("expected_status"),
        "predicted_label": predicted,
        "severity": result.verdict.severity,
        "confidence": result.verdict.confidence,
        "status": result.verdict.status,
        "correct": correct,
        "confidently_wrong": confidently_wrong,
        "recommended_action": result.verdict.recommended_action,
        "reasoning": result.verdict.reasoning,
        "tools": [
            {"tool": call.tool, "status": call.status, "summary": call.summary}
            for call in result.tools_called
        ],
        "policy_escalations": result.policy_escalations,
        "latency_ms": round(result.latency_ms, 2),
        "error": result.error,
        "run_id": result.run_id,
        "notes": case.get("notes", ""),
        "raw": result.model_dump(mode="json"),
    }


def compute_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labeled = [row for row in rows if row["expected_label"] in {"malicious", "benign"}]
    correct = [row for row in labeled if row["correct"]]
    escalated = [row for row in rows if row["status"] == "needs_review"]
    unknown = [row for row in rows if row["expected_label"] == "unknown"]
    required = [row for row in rows if row.get("expected_status") == "needs_review"]
    confidently_wrong = [row for row in rows if row["confidently_wrong"]]
    false_negatives = [
        row
        for row in labeled
        if row["expected_label"] == "malicious" and row["predicted_label"] == "benign"
    ]
    false_positives = [
        row
        for row in labeled
        if row["expected_label"] == "benign" and row["predicted_label"] == "malicious"
    ]
    tool_statuses = Counter(tool["status"] for row in rows for tool in row["tools"])
    latencies = [row["latency_ms"] for row in rows]

    groups: dict[str, dict[str, float | int]] = {}
    for group in sorted({row["group"] for row in rows}):
        group_rows = [row for row in rows if row["group"] == group]
        group_labeled = [
            row for row in group_rows if row["expected_label"] in {"malicious", "benign"}
        ]
        group_correct = [row for row in group_labeled if row["correct"]]
        groups[group] = {
            "total": len(group_rows),
            "labeled": len(group_labeled),
            "correct": len(group_correct),
            "accuracy": len(group_correct) / len(group_labeled) if group_labeled else 0.0,
            "escalated": sum(1 for row in group_rows if row["status"] == "needs_review"),
        }

    return {
        "total_cases": len(rows),
        "labeled_cases": len(labeled),
        "unknown_cases": len(unknown),
        "accuracy": len(correct) / len(labeled) if labeled else 0.0,
        "correct": len(correct),
        "escalation_rate": len(escalated) / len(rows) if rows else 0.0,
        "escalated": len(escalated),
        "required_escalations_met": sum(1 for row in required if row["status"] == "needs_review"),
        "required_escalations": len(required),
        "unknown_escalated": sum(1 for row in unknown if row["status"] == "needs_review"),
        "confidently_wrong": len(confidently_wrong),
        "false_negatives": len(false_negatives),
        "false_positives": len(false_positives),
        "errors": sum(1 for row in rows if row["error"]),
        "average_latency_ms": statistics.mean(latencies) if latencies else 0.0,
        "tool_status_counts": dict(tool_statuses),
        "groups": groups,
    }


def write_report(
    rows: list[dict[str, Any]],
    metrics: dict[str, Any],
    model: str,
    command: str,
) -> None:
    stats = {}
    if STATS_PATH.exists():
        stats = json.loads(STATS_PATH.read_text(encoding="utf-8")).get("stats", {})
    wrong = [row for row in rows if row["confidently_wrong"]]
    escalated = [row for row in rows if row["status"] == "needs_review"]

    lines = [
        "# Triage Eval",
        "",
        f"- Run at: {datetime.now(UTC).isoformat()}",
        f"- Model: `{model}`",
        f"- Command: `{command}`",
        f"- Cases: {metrics['total_cases']} "
        f"({metrics['labeled_cases']} labeled, {metrics['unknown_cases']} unknown)",
        f"- Data snapshot: {stats.get('final', 'unknown')} indicators "
        f"({stats.get('malicious', 'unknown')} malicious, "
        f"{stats.get('benign', 'unknown')} benign)",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
        (
            f"| Labeled accuracy | {metrics['accuracy']:.1%} "
            f"({metrics['correct']}/{metrics['labeled_cases']}) |"
        ),
        (
            f"| Escalation rate | {metrics['escalation_rate']:.1%} "
            f"({metrics['escalated']}/{metrics['total_cases']}) |"
        ),
        (
            f"| Required escalations met | {metrics['required_escalations_met']}/"
            f"{metrics['required_escalations']} |"
        ),
        f"| Unknown cases escalated | {metrics['unknown_escalated']}/{metrics['unknown_cases']} |",
        f"| Confidently wrong | {metrics['confidently_wrong']} |",
        f"| False negatives | {metrics['false_negatives']} |",
        f"| False positives | {metrics['false_positives']} |",
        f"| Pipeline errors | {metrics['errors']} |",
        f"| Average latency | {metrics['average_latency_ms']:.0f} ms |",
        "",
        "Accuracy is computed only on the malicious/benign labeled cases. Unknown cases are "
        "synthetic escalation checks and are excluded from accuracy.",
        "",
        "### By case group",
        "",
        "| Group | Correct | Labeled | Accuracy | Escalated |",
        "|---|---:|---:|---:|---:|",
    ]
    for group, values in metrics["groups"].items():
        accuracy = f"{values['accuracy']:.1%}" if values["labeled"] else "n/a"
        lines.append(
            f"| {group} | {values['correct']} | {values['labeled']} | "
            f"{accuracy} | {values['escalated']}/{values['total']} |"
        )

    lines += [
        "",
        "## Per-case results",
        "",
        "| ID | Group | Input | Expected | Predicted | Severity | Confidence | "
        "Status | Correct | Tools |",
        "|---|---|---|---|---|---|---:|---|---|---|",
    ]
    for row in rows:
        tool_text = ", ".join(f"{tool['tool']}={tool['status']}" for tool in row["tools"])
        if row["expected_label"] == "unknown":
            correct_text = "n/a"
        else:
            correct_text = "yes" if row["correct"] else "no"
        lines.append(
            f"| {row['id']} | {row['group']} | `{row['input']}` | "
            f"{row['expected_label']} | {row['predicted_label']} | "
            f"{row['severity']} | {row['confidence']:.2f} | {row['status']} | "
            f"{correct_text} | {tool_text} |"
        )

    lines += ["", "## Confidently wrong", ""]
    if wrong:
        for row in wrong:
            lines.append(
                f"- `{row['id']}`: expected **{row['expected_label']}**, predicted "
                f"**{row['predicted_label']}** at confidence {row['confidence']:.2f}. "
                f"{row['reasoning']}"
            )
    else:
        lines.append("None in this run.")

    lines += ["", "## Escalated cases", ""]
    for row in escalated:
        lines.append(
            f"- `{row['id']}` ({row['expected_label']} -> {row['predicted_label']}, "
            f"confidence {row['confidence']:.2f}): "
            f"{'; '.join(row['policy_escalations']) or 'model requested review'}"
        )

    lines += [
        "",
        "## Limitations",
        "",
        "- The eval set has 20 cases and is intentionally small; these numbers are not a",
        "  production estimate.",
        "- Malicious labels come from OpenPhish (seen cases) and the Phishing Army active",
        "  blocklist (unseen cases); both can be noisy or stale. Benign labels come from Tranco",
        "  ranks and are not verified non-malicious.",
        "- Six malicious cases are already loaded in BigQuery and test the lookup happy path;",
        "  four malicious cases are held out and test generalization. The benign cases are",
        "  outside the loaded top 5000. The feeds are not independent ground truth.",
        "- Gemini calls are nondeterministic. This is a single run, not a repeated sample.",
        "- Transient 429 errors are retried by the eval harness; only final pipeline errors are",
        "  counted in the metrics.",
        "- RDAP gaps and shared-hosting subdomains frequently produce partial enrichment; the",
        "  policy deliberately escalates those cases.",
        "- The policy auto-closes only confident benign verdicts. Malicious, high/critical,",
        "  unknown, degraded, conflicting, or low-confidence results are escalated.",
        "- Pipeline errors are counted as fail-closed `needs_review` results with unknown",
        "  classification.",
        "",
    ]
    DOCS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOCS_PATH.write_text("\n".join(lines), encoding="utf-8")


async def main_async(args: argparse.Namespace) -> int:
    cases = load_cases(Path(args.cases))
    if args.limit:
        cases = cases[: args.limit]
    settings = Settings()
    rows: list[dict[str, Any]] = []

    for index, case in enumerate(cases, start=1):
        print(f"[{index}/{len(cases)}] {case['id']} {case['input']}", file=sys.stderr)
        result = await run_case(case, retries=args.retries, delay=args.delay)
        rows.append(build_row(case, result))
        if args.delay:
            await asyncio.sleep(args.delay)

    metrics = compute_metrics(rows)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "model": settings.gemini_model,
        "cases_path": str(Path(args.cases)),
        "metrics": metrics,
        "rows": rows,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    raw_path = RESULTS_DIR / f"eval-{timestamp}.json"
    raw_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    command = "uv run python -m evals.run_eval " + " ".join(sys.argv[1:])
    write_report(rows, metrics, settings.gemini_model, command.strip())

    print(
        json.dumps(
            {"metrics": metrics, "raw_results": str(raw_path), "report": str(DOCS_PATH)}, indent=2
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", default=str(CASES_PATH))
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--delay", type=float, default=2.0, help="Seconds between cases.")
    parser.add_argument("--retries", type=int, default=1, help="Retries for 429 errors.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
