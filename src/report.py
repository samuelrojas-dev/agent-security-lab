"""Summaries and report writers: JSON (raw), Markdown (humans), SARIF (GitHub code scanning)."""
import json
import math
from collections import Counter
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a rate of k successes in n trials."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - margin), min(1.0, centre + margin)


def summarize(results: list[dict], modes: list[str], total_secrets: int) -> dict:
    summary = {}
    for mode in modes:
        trials = [t for r in results for t in r["runs"][mode] if t["leaked"] is not None]
        k = sum(t["leaked"] for t in trials)
        low, high = wilson(k, len(trials))
        exposed = {leak["secret"] for t in trials for leak in t["leaks"]}
        summary[mode] = {
            "attacks": len(results),
            "attacks_leaked": sum(any(t["leaked"] for t in r["runs"][mode]) for r in results),
            "trials": len(trials),
            "trials_leaked": k,
            "empty_trials": sum(t["leaked"] is None for r in results for t in r["runs"][mode]),
            "asr": k / len(trials) if trials else 0.0,
            "asr_ci95": [low, high],
            "secrets_exposed": len(exposed),
            "secrets_total": total_secrets,
            "channels": dict(Counter(c for t in trials for c in _channels(t))),
            "actions_blocked": sum(len(t["blocked"]) for t in trials),
            "judge_only": sum(bool(t["leaked"]) and not t["leaks"] for t in trials),
            "judge_errors": sum(t.get("judge_errors", 0) for t in trials),
        }
    return summary


def _verified(trial: dict) -> list[dict]:
    return [i for i in trial.get("inferences", []) if i["verified"]]


def _channels(trial: dict) -> set[str]:
    return {leak["channel"] for leak in trial["leaks"] + _verified(trial)}


def _cell(runs: list[dict]) -> str:
    done = [t for t in runs if t["leaked"] is not None]
    if not done:
        return "EMPTY"
    k = sum(t["leaked"] for t in done)
    if len(runs) == 1:
        return "LEAK" if k else "safe"
    return f"LEAK {k}/{len(done)}" if k else f"safe 0/{len(done)}"


def write_reports(out: Path, meta: dict, results: list[dict], summary: dict, attacks_file: str) -> None:
    out.mkdir(parents=True, exist_ok=True)
    modes = list(summary)
    (out / "report.json").write_text(
        json.dumps({"meta": meta, "summary": summary, "results": results}, ensure_ascii=False, indent=1),
        encoding="utf-8")

    judged = bool(meta.get("judge"))
    lines = [f"# Run: model `{meta['model']}` · data `{meta['data']}` · {meta['attacks']} attacks "
             f"· {meta['trials']} trial(s) each" + (f" · judge `{meta['judge']}`" if judged else "")
             + (f" · {meta['tool_protocol']} tool calling" if meta.get("tool_protocol") else ""), "",
             "| Design | Attacks leaked | Attack success rate (95% CI) | Secrets exposed | Leak channels | Actions blocked |"
             + (" Found only by judge |" if judged else ""),
             "|---|---|---|---|---|---|" + ("---|" if judged else "")]
    for mode, s in summary.items():
        channels = ", ".join(f"{c} {n}" for c, n in sorted(s["channels"].items())) or "-"
        empty = f" ({s['empty_trials']} empty)" if s["empty_trials"] else ""
        lines.append(f"| `{mode}` | {s['attacks_leaked']}/{s['attacks']}{empty} | {s['asr']:.0%} "
                     f"[{s['asr_ci95'][0]:.0%}, {s['asr_ci95'][1]:.0%}] | "
                     f"{s['secrets_exposed']}/{s['secrets_total']} | {channels} | {s['actions_blocked']} |"
                     + (f" {s['judge_only']} |" if judged else ""))
    lines += ["", "| Attack | Category | " + " | ".join(modes) + " |", "|---|---|" + "---|" * len(modes)]
    for r in results:
        lines.append(f"| {r['id']} | {r['category']} | " + " | ".join(_cell(r["runs"][m]) for m in modes) + " |")
    (out / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    sarif_results = []
    for r in results:
        for mode in modes:
            leaks = [leak for t in r["runs"][mode] for leak in t["leaks"]]
            inferred = [i for t in r["runs"][mode] for i in _verified(t)]
            if not leaks and not inferred:
                continue
            how = sorted({f"{leak['channel']}→{leak['destination']} ({leak['technique']})" for leak in leaks}
                         | {f"{i['channel']}→{i['destination']} (judge: {i['kind']} {i['field']})" for i in inferred})
            sarif_results.append({
                "ruleId": r["category"].replace(" ", "-"),
                "level": "error",
                "message": {"text": f"[{mode}] attack '{r['id']}' exfiltrated {len({l['secret'] for l in leaks})} "
                                    f"internal value(s) and {len(inferred)} inference(s) via {', '.join(how)}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": attacks_file}}}],
                "partialFingerprints": {"attackMode": f"{r['id']}|{mode}"},
            })
    rules = sorted({res["ruleId"] for res in sarif_results})
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "agent-security-lab", "informationUri":
                                      "https://github.com/samuelrojas-dev/agent-security-lab",
                                      "rules": [{"id": rule} for rule in rules]}},
                  "results": sarif_results}],
    }
    (out / "report.sarif").write_text(json.dumps(sarif, ensure_ascii=False, indent=1), encoding="utf-8")
