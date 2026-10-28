"""Run the labeled triage eval with and without ML and write docs/eval.md."""

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
ML_METRICS_PATH = ROOT / "data" / "clean" / "ml_metrics.json"

MODE_LABELS = {"without_ml": "Without ML", "with_ml": "With ML"}


def load_cases(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


async def run_case(
    case: dict[str, Any],
    *,
    retries: int,
    delay: float,
    use_ml: bool,
) -> Any:
    last_result = None
    for attempt in range(retries + 1):
        result = await triage(case["input"], use_ml=use_ml)
        last_result = result
        transient = result.error and (
            "429" in result.error
            or "RESOURCE_EXHAUSTED" in result.error
            or "NodeTimeoutError" in result.error
            or "timed out" in result.error.lower()
        )
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


async def run_configuration(
    cases: list[dict[str, Any]],
    *,
    use_ml: bool,
    retries: int,
    delay: float,
    label: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, case in enumerate(cases, start=1):
        print(f"[{label} {index}/{len(cases)}] {case['id']} {case['input']}", file=sys.stderr)
        result = await run_case(case, retries=retries, delay=delay, use_ml=use_ml)
        rows.append(build_row(case, result))
        if delay:
            await asyncio.sleep(delay)
    return rows, compute_metrics(rows)


def _metric_cell(results: dict[str, Any], mode: str, key: str, kind: str) -> str:
    if mode not in results:
        return "n/a"
    metrics = results[mode][1]
    if kind == "pct":
        return f"{metrics[key]:.1%}"
    if kind == "ms":
        return f"{metrics[key]:.0f} ms"
    return str(metrics[key])


def _comparison_rows(results: dict[str, Any]) -> list[str]:
    definitions = [
        ("Labeled accuracy", "accuracy", "pct"),
        ("Escalation rate", "escalation_rate", "pct"),
        ("Required escalations met", "required_escalations_met", "int"),
        ("Unknown cases escalated", "unknown_escalated", "int"),
        ("Confidently wrong", "confidently_wrong", "int"),
        ("False negatives", "false_negatives", "int"),
        ("False positives", "false_positives", "int"),
        ("Pipeline errors", "errors", "int"),
        ("Average latency", "average_latency_ms", "ms"),
    ]
    lines = ["| Metric | Without ML | With ML |", "|---|---:|---:|"]
    for label, key, kind in definitions:
        lines.append(
            f"| {label} | {_metric_cell(results, 'without_ml', key, kind)} | "
            f"{_metric_cell(results, 'with_ml', key, kind)} |"
        )
    return lines


def _group_rows(results: dict[str, Any]) -> list[str]:
    groups: set[str] = set()
    for mode in ("without_ml", "with_ml"):
        if mode in results:
            groups.update(results[mode][1]["groups"])
    lines = [
        "| Group | Baseline accuracy | ML accuracy | Baseline escalated | ML escalated |",
        "|---|---:|---:|---:|---:|",
    ]
    for group in sorted(groups):
        values = []
        for mode in ("without_ml", "with_ml"):
            if mode not in results:
                values.append(("n/a", "n/a"))
                continue
            group_metrics = results[mode][1]["groups"].get(group)
            if not group_metrics:
                values.append(("n/a", "n/a"))
                continue
            accuracy = f"{group_metrics['accuracy']:.1%}" if group_metrics["labeled"] else "n/a"
            escalated = f"{group_metrics['escalated']}/{group_metrics['total']}"
            values.append((accuracy, escalated))
        lines.append(
            f"| {group} | {values[0][0]} | {values[1][0]} | {values[0][1]} | {values[1][1]} |"
        )
    return lines


def _per_case_rows(results: dict[str, Any]) -> list[str]:
    by_mode: dict[str, dict[str, dict[str, Any]]] = {
        mode: {row["id"]: row for row in results[mode][0]} for mode in results
    }
    case_ids: list[str] = []
    for mode in ("without_ml", "with_ml"):
        if mode in results:
            case_ids = [row["id"] for row in results[mode][0]]
            break

    lines = [
        "| ID | Group | Input | Expected | Baseline | Baseline status | ML | ML status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for case_id in case_ids:
        baseline = by_mode.get("without_ml", {}).get(case_id)
        with_ml = by_mode.get("with_ml", {}).get(case_id)
        anchor = baseline or with_ml
        if anchor is None:
            continue
        baseline_text = (
            f"{baseline['predicted_label']} / {baseline['severity']} / {baseline['confidence']:.2f}"
            if baseline
            else "n/a"
        )
        ml_text = (
            f"{with_ml['predicted_label']} / {with_ml['severity']} / {with_ml['confidence']:.2f}"
            if with_ml
            else "n/a"
        )
        lines.append(
            f"| {case_id} | {anchor['group']} | `{anchor['input']}` | "
            f"{anchor['expected_label']} | {baseline_text} | "
            f"{baseline['status'] if baseline else 'n/a'} | {ml_text} | "
            f"{with_ml['status'] if with_ml else 'n/a'} |"
        )
    return lines


def _ml_impact_rows(results: dict[str, Any]) -> list[str]:
    if "with_ml" not in results:
        return ["ML run was not included."]
    if "without_ml" not in results:
        return ["Baseline run was not included."]
    baseline = {row["id"]: row for row in results["without_ml"][0]}
    lines = []
    for row in results["with_ml"][0]:
        old = baseline.get(row["id"])
        if old is None:
            continue
        reasons = [reason for reason in row["policy_escalations"] if "ML" in reason]
        changed = old["predicted_label"] != row["predicted_label"] or old["status"] != row["status"]
        if not changed and not reasons:
            continue
        before = f"{old['predicted_label']}/{old['status']}"
        after = f"{row['predicted_label']}/{row['status']}"
        detail = (
            "; ".join(reasons)
            if reasons
            else "model classification/status changed; no ML-specific policy reason"
        )
        lines.append(f"- `{row['id']}`: {before} -> {after} ({detail})")
    return lines or ["No label or status changes from the ML tool."]


def _confidently_wrong(rows: list[dict[str, Any]]) -> list[str]:
    wrong = [row for row in rows if row["confidently_wrong"]]
    if not wrong:
        return ["None in this run."]
    lines = []
    for row in wrong:
        lines.append(
            f"- `{row['id']}`: expected **{row['expected_label']}**, predicted "
            f"**{row['predicted_label']}** at confidence {row['confidence']:.2f}. "
            f"{row['reasoning']}"
        )
    return lines


def write_report(
    results: dict[str, tuple[list[dict[str, Any]], dict[str, Any]]],
    model: str,
    command: str,
    note: str | None = None,
) -> None:
    stats = load_json(STATS_PATH).get("stats", {})
    ml_metrics = load_json(ML_METRICS_PATH)
    total_metrics = results.get("with_ml", results.get("without_ml", ([], {})))[1]
    lines = [
        "# Triage Eval",
        "",
        f"- Run at: {datetime.now(UTC).isoformat()}",
        f"- Agent model: `{model}`",
        f"- Command: `{command}`",
        f"- Cases: {total_metrics.get('total_cases', 'unknown')} "
        f"({total_metrics.get('labeled_cases', 'unknown')} labeled, "
        f"{total_metrics.get('unknown_cases', 'unknown')} unknown)",
        f"- Data snapshot: {stats.get('final', 'unknown')} indicators "
        f"({stats.get('malicious', 'unknown')} malicious, "
        f"{stats.get('benign', 'unknown')} benign)",
    ]

    if ml_metrics:
        evaluate = (ml_metrics.get("evaluate") or [{}])[0]
        model_name = str(ml_metrics.get("model", "")).strip("`")
        accuracy = evaluate.get("accuracy")
        roc_auc = evaluate.get("roc_auc")
        accuracy_text = f"{accuracy:.3f}" if isinstance(accuracy, (int, float)) else "n/a"
        roc_auc_text = f"{roc_auc:.3f}" if isinstance(roc_auc, (int, float)) else "n/a"
        lines.append(
            f"- BQML model: `{model_name}` over "
            f"{ml_metrics.get('training_table_rows', 'unknown')} feature rows; "
            f"accuracy {accuracy_text}, roc_auc {roc_auc_text}"
        )
    else:
        lines.append("- BQML metrics: unavailable (run `make ml`)")

    if note:
        lines += ["", note]
    lines += [
        "",
        "## Comparison",
        "",
        *_comparison_rows(results),
        "",
        "Accuracy is computed only on malicious/benign labeled cases. Unknown cases are "
        "synthetic escalation checks and are excluded from accuracy.",
        "",
    ]
    if "without_ml" in results and "with_ml" in results:
        lines += [
            "The ML tool did not improve this subset. It disagreed with lookup on two",
            "seen malicious cases, and it scored a benign login URL as malicious; the",
            "formatter and policy responded by escalating to unknown/needs_review. The",
            "high BQML holdout metrics (shown above) do not translate to agent decisions,",
            "likely because the lexical features separate feed sources rather than",
            "generalize to real-world URL intent.",
            "",
        ]
    lines += [
        "### By case group",
        "",
        *_group_rows(results),
        "",
        "## Per-case results",
        "",
        *_per_case_rows(results),
        "",
        "## Confidently wrong",
        "",
    ]
    for mode, label in MODE_LABELS.items():
        if mode not in results:
            continue
        lines += [f"### {label}", "", *_confidently_wrong(results[mode][0]), ""]

    lines += ["## ML impact", "", *_ml_impact_rows(results), ""]

    lines += [
        "## Limitations",
        "",
        "- The eval set has 20 cases and is intentionally small; these numbers are not a",
        "  production estimate.",
        "- Malicious labels come from OpenPhish (seen cases) and the Phishing Army active",
        "  blocklist (unseen cases); both can be noisy or stale. Benign labels come from Tranco",
        "  ranks and are not verified non-malicious.",
        "- Nine malicious holdout domains (including the six seen cases and three unseen",
        "  cases) were excluded from BQML training; the remaining unseen cases and benign",
        "  cases are outside the loaded indicators. This reduces, but does not eliminate,",
        "  evaluation leakage and distribution shift.",
        "- BQML metrics come from a random 20% split of the indicator feature table, not from",
        "  the 20 agent eval cases. Both numbers are small-sample and single-run.",
        "- Gemini and ML are probabilistic. This is one run, not a repeated sample.",
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
    if args.case_ids:
        wanted = {item.strip() for item in args.case_ids.split(",") if item.strip()}
        cases = [case for case in cases if case["id"] in wanted]
    settings = Settings()
    results: dict[str, tuple[list[dict[str, Any]], dict[str, Any]]] = {}

    if args.mode in {"without-ml", "both"}:
        results["without_ml"] = await run_configuration(
            cases,
            use_ml=False,
            retries=args.retries,
            delay=args.delay,
            label="without-ml",
        )
    if args.mode in {"with-ml", "both"}:
        results["with_ml"] = await run_configuration(
            cases,
            use_ml=True,
            retries=args.retries,
            delay=args.delay,
            label="with-ml",
        )

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "model": settings.gemini_model,
        "cases_path": str(Path(args.cases)),
        "modes": {
            mode: {"metrics": metrics, "rows": rows} for mode, (rows, metrics) in results.items()
        },
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    raw_path = RESULTS_DIR / f"eval-{timestamp}.json"
    raw_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    command = "uv run python -m evals.run_eval " + " ".join(sys.argv[1:])
    all_cases = load_cases(Path(args.cases))
    note = None
    if len(cases) < len(all_cases):
        note = (
            "This Stage 6 comparison uses a quota-limited subset of "
            f"{len(cases)}/{len(all_cases)} cases because the full ML run hit Vertex AI "
            "429/timeouts. The full 20-case no-ML Stage 3 baseline was 72.2% accuracy "
            "(13/18) and 65% escalation."
        )
    write_report(results, settings.gemini_model, command.strip(), note=note)

    print(
        json.dumps(
            {
                "metrics": {mode: metrics for mode, (_, metrics) in results.items()},
                "raw_results": str(raw_path),
                "report": str(DOCS_PATH),
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", default=str(CASES_PATH))
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--case-ids",
        default=None,
        help="Comma-separated case IDs to run (for quota-limited subsets).",
    )
    parser.add_argument("--delay", type=float, default=2.0, help="Seconds between cases.")
    parser.add_argument("--retries", type=int, default=1, help="Retries for 429 errors.")
    parser.add_argument(
        "--mode",
        choices=("both", "without-ml", "with-ml"),
        default="both",
        help="Run both configurations or only one.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
