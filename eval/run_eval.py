"""Rules-only eval over the 5 expert-curated benchmarks.

Each benchmark is a (system.yaml, system.expected.json) pair. The
expected file lists ``(component_name, STRIDE_letter)`` pairs an
expert reviewer would expect to see flagged. The eval:

  1. Runs the rules-only modeller on the system description.
  2. Projects the produced ThreatModel into the same
     ``(component, stride_letter)`` set.
  3. Computes precision / recall / F1 against the expected set.

Universe per benchmark = (every component) × (six STRIDE categories).
The eval is offline-only and deterministic; re-runs produce identical
numbers."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from generator.modeller import model_system  # noqa: E402
from generator.parser import load_system  # noqa: E402
from generator.validator import StrideCategory  # noqa: E402


_LETTER = {
    StrideCategory.SPOOFING:               "S",
    StrideCategory.TAMPERING:              "T",
    StrideCategory.REPUDIATION:            "R",
    StrideCategory.INFORMATION_DISCLOSURE: "I",
    StrideCategory.DENIAL_OF_SERVICE:      "D",
    StrideCategory.ELEVATION_OF_PRIVILEGE: "E",
}
_STRIDE_LETTERS = list(_LETTER.values())


def _short(p: Path) -> str:
    try:
        return str(p.relative_to(_REPO))
    except ValueError:
        return str(p)


def _expected_pairs(json_path: Path) -> set[tuple[str, str]]:
    raw = json.loads(json_path.read_text())
    return {(c, s) for c, s in raw.get("expected_pairs", [])}


def _observed_pairs(model) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for t in model.threats:
        cat = t.stride_category
        if not isinstance(cat, StrideCategory):
            cat = StrideCategory(cat)
        out.add((t.component, _LETTER[cat]))
    return out


def _universe(system) -> set[tuple[str, str]]:
    return {(c.name, ltr) for c in system.components
             for ltr in _STRIDE_LETTERS}


def _benchmark(yaml_path: Path) -> dict:
    expected_path = yaml_path.with_suffix("").with_suffix(".expected.json")
    system = load_system(yaml_path)
    model = model_system(system)
    universe = _universe(system)
    expected = _expected_pairs(expected_path) & universe
    observed = _observed_pairs(model) & universe

    tp = expected & observed
    fp = observed - expected
    fn = expected - observed
    tn = universe - (expected | observed)

    precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) else 1.0
    recall = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) else 1.0
    f1 = (2 * precision * recall / (precision + recall)
           if (precision + recall) else 0.0)
    accuracy = ((len(tp) + len(tn)) / len(universe)) if universe else 0.0

    return {
        "benchmark": yaml_path.stem,
        "n_components": len(system.components),
        "universe": len(universe),
        "tp": len(tp),
        "fp": len(fp),
        "fn": len(fn),
        "tn": len(tn),
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "accuracy":  round(accuracy, 4),
        "total_threats": model.threat_count,
        "fp_pairs": sorted(fp),
        "fn_pairs": sorted(fn),
    }


def _aggregate(rows: list[dict]) -> dict:
    """Micro-averaged precision/recall/F1 across benchmarks."""
    tp = sum(r["tp"] for r in rows)
    fp = sum(r["fp"] for r in rows)
    fn = sum(r["fn"] for r in rows)
    tn = sum(r["tn"] for r in rows)
    universe = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)
           if (precision + recall) else 0.0)
    accuracy = (tp + tn) / universe if universe else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "universe": universe,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "accuracy":  round(accuracy, 4),
    }


def main() -> None:
    bench_dir = _REPO / "eval" / "benchmarks"
    out_dir = _REPO / "results"
    out_dir.mkdir(parents=True, exist_ok=True)

    yaml_files = sorted(bench_dir.glob("*.yaml"))
    if not yaml_files:
        sys.exit(f"no benchmarks found in {_short(bench_dir)}")

    print(f"[eval] running {len(yaml_files)} benchmark(s)")
    rows = []
    for path in yaml_files:
        row = _benchmark(path)
        rows.append(row)
        print(f"  {row['benchmark']:<14}  "
              f"prec={row['precision']:.4f} "
              f"rec={row['recall']:.4f} "
              f"F1={row['f1']:.4f} "
              f"(tp={row['tp']} fp={row['fp']} "
              f"fn={row['fn']} tn={row['tn']})")

    aggregate = _aggregate(rows)

    summary = {
        "n_benchmarks": len(rows),
        "aggregate": aggregate,
        "per_benchmark": [{k: v for k, v in r.items()
                            if k not in ("fp_pairs", "fn_pairs")}
                           for r in rows],
        "fp_fn_detail": [
            {"benchmark": r["benchmark"],
             "fp_pairs": r["fp_pairs"],
             "fn_pairs": r["fn_pairs"]}
            for r in rows
        ],
    }
    (out_dir / "eval_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True))

    raw_csv = out_dir / "eval_raw.csv"
    fields = ["benchmark", "n_components", "universe", "tp", "fp", "fn", "tn",
               "precision", "recall", "f1", "accuracy", "total_threats"]
    with raw_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fields})

    print(f"[eval] wrote {_short(out_dir / 'eval_summary.json')}")
    print(f"[eval] wrote {_short(raw_csv)}")
    a = aggregate
    print(f"[eval] aggregate: accuracy={a['accuracy']:.4f} "
           f"precision={a['precision']:.4f} "
           f"recall={a['recall']:.4f} f1={a['f1']:.4f}")
    print(f"[eval] tp={a['tp']} fp={a['fp']} fn={a['fn']} tn={a['tn']}")


if __name__ == "__main__":
    main()
