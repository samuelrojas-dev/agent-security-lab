# CLAUDE.md

A test harness that measures whether a B2B sales agent leaks internal data (cost, margin, supplier
ID, supplier notes) to a customer or an outside email address, across six agent designs. The
README holds the results and findings; this file is about how the code fits together.

## Commands

```bash
pip install -r requirements.txt
pytest -m "not live"                      # offline suite, no keys needed (runs in CI)
python -m src.evaluate                    # compromised model, local data, all designs -> results/compromised/
python -m src.evaluate --mutate --gate hardened agent_least_privilege   # the CI gate
python -m src.evaluate --model claude|gemini [--trials N] [--judge claude|gemini] [--tool-protocol text]
python -m src.judge --model claude        # judge precision/recall on attacks/judge_calibration.json
pytest -m live -s                         # real model; LAB_MODEL, LAB_DATA, LAB_JUDGE pick what runs
```

Everything offline uses `CompromisedLLM` and `data/catalog.json`: no API keys, no Supabase,
deterministic output. Real-model runs cache progress in `results/<model>/cache.json` and resume.

## Architecture

```
attacks/attacks.json ─► evaluate.run_suite ─► agent.make_agent(mode, source, llm, protocol)
                                                 │  SalesAgent (chat designs) | ToolAgent (tool designs)
                                                 ▼
                                             Transcript: replies, tool_calls, egress events
                                                 ▼
                         evaluate.score ─► detect.find_leaks  (+ judge.Judge when --judge)
                                                 ▼
                         report.summarize ─► report.md / report.json / report.sarif
```

| Module | Role |
|---|---|
| `src/data.py` | `LocalSource` / `SupabaseSource`; `PUBLIC_FIELDS`, `INTERNAL_FIELDS`, `public_view` |
| `src/agent.py` | The six designs (`MODES`, `AGENT_MODES`), `AGENT_SCOPES`, the tool loop, `Egress`/`Transcript` |
| `src/tools.py` | Tools with a sensitivity `Label`; `quote` decides discounts in code and returns only the outcome |
| `src/flow.py` | `FlowGuard`: context label vs. sink clearance for email; DLP on replies |
| `src/detect.py` | String leak detector: normalization, number formats, encodings, canaries |
| `src/judge.py` | LLM judge for inference leaks, nonce-fenced, evidence-verified, calibrated |
| `src/llm.py` | Adapters: `chat()` for text, `step()` for native tool calling; `CompromisedLLM` |
| `src/mutate.py` | Deterministic evasion operators and the `shift1` cipher + `DECODERS` |
| `src/evaluate.py` | CLI, `build_agent`, `score`, `run_suite`, the `--gate` exit code |
| `src/report.py` | Wilson intervals, blast radius, report writers |
| `src/guards.py` | The v1 keyword output filter used by the `hardened` chat design |

### Tool loop (`ToolAgent`)

- `protocol="native"` calls `llm.step()` with the tool objects; `"text"` asks the model for
  `CALL {...}` lines via `llm.chat()`; `"auto"` picks native when `llm.native_tools` is true.
- Both loops send every call through `ToolAgent._execute`, which is the only place policy is
  enforced (scope check, `FlowGuard.authorize_email`, `FlowGuard.observe`) and the only place an
  `Egress` for email is recorded. The reply to the customer is recorded in `run()`, after
  `FlowGuard.check_reply`.
- Native messages use a provider-neutral shape (`user` / `assistant` with `calls` and `raw` /
  `tool` with `results`). Adapters replay `raw` unchanged: Claude thinking blocks and Gemini
  thought signatures break if they are rebuilt.

### Scoring

A trial leaks when an internal value reaches a **delivered** egress whose clearance is below
`INTERNAL` (the customer, or an external email). Blocked egress never counts. `score` tries the
attack's `decoder` and the raw text. The judge runs only on egress the string detector found
clean, and only findings whose evidence quote occurs in the text count (`verified`).

## Invariants: keep these true

- **The loop enforces policy, never the SDK.** Do not switch to an SDK tool runner or enable
  Gemini's automatic function calling: tools must not run without passing `_execute`.
- **`agent_least_privilege` must not be granted a tool labeled `INTERNAL`.** The CI gate and
  `test_structural_designs_leak_nothing_under_a_compromised_model` prove this design leaks nothing
  even from a compromised model. A red gate is a real regression, never a flaky test.
- **Native and text protocols must stay equivalent.** `test_native_and_text_loops_enforce_the_same_policy`
  checks it attack by attack.
- **Tool implementations run with privileged rows.** Exposure is decided by the tool's label and
  the design's scope, not by what the tool function can read.
- **Every judge finding needs verifiable evidence.** Keep the evidence check in code; do not trust
  the judge's `leak` field on its own.
- **The calibration set must stay invisible to the string detector**
  (`test_calibration_set_is_well_formed_and_invisible_to_the_string_detector`); otherwise it
  measures the wrong thing.

## Conventions

- Python 3.11+, standard library plus the provider SDKs; SDK imports are lazy so offline tests need
  none of them. `python-dotenv` is optional.
- Match the existing style: module docstrings that explain *why*, short functions, dataclasses for
  records, no framework.
- Reports under `results/compromised/` are generated: regenerate them with
  `python -m src.evaluate --out results/compromised`, never edit them by hand. `report.json` and
  caches are git-ignored.
- `results/results.md` and `results/results.json` are the v1 Gemini run and are kept as-is.
- Keep `data/catalog.json` and `supabase/*.sql` in sync when products change.
- README numbers (attack counts, CIs, blocked emails) come from the generated report; update them
  together.
- Attack entries need a unique `id`, a `category`, and exactly one of `prompt` or `turns`;
  `decoder` must be a key of `mutate.DECODERS`. `tests/test_offline.py` enforces the schema.

## Tests

- `tests/test_offline.py`: v1 behavior (filter, detector, chat designs, attack schema).
- `tests/test_agents.py`: detector encodings, flow guard, scopes, worst-case guarantees, reports, gate.
- `tests/test_judge.py`: judge fencing, evidence check, calibration, scoring integration.
- `tests/test_native_tools.py`: shared loop, and Claude/Gemini request shapes with fake clients.
- `tests/test_live.py`: `@pytest.mark.live`, real models; never runs in CI.

New behavior gets an offline test with a scripted LLM or a fake client; nothing in the offline
suite may need network access or keys.
