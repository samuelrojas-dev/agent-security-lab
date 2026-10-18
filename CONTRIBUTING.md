# Contributing

Contributions welcome. This project follows a few conventions to keep the lab reproducible and the
CI gate meaningful.

## Setup

```bash
git clone https://github.com/samuelrojas-dev/agent-security-lab
cd agent-security-lab
pip install -r requirements.txt
pytest -m "not live"                      # must pass before any change
python -m src.evaluate --out results/compromised   # regenerate reports
```

## Adding an attack

Attacks live in `attacks/attacks.json`. Each entry needs:

- **`id`**: unique, lowercase, hyphenated (e.g. `lang-switch-technical`)
- **`category`**: one of the existing categories, or a new one if it represents a genuinely
  different technique
- **`prompt`** (single-turn) or **`turns`** (multi-turn): the attack text
- **`decoder`** (optional): a key from `src/mutate.DECODERS` if the attack asks the model to
  encode its output

After adding an attack, run the offline suite (`pytest -m "not live"`) to validate the schema, and
regenerate the reports (`python -m src.evaluate --out results/compromised`).

## Adding a mutation operator

Operators live in `src/mutate.py` in the `OPERATORS` dict. Each is a `str -> str` function that
transforms the last turn of an attack. The operator must be deterministic (no randomness). After
adding one, the test `test_every_mutation_keeps_ids_unique` adapts automatically.

## Adding a tool

Tools live in `src/tools.py`. Each tool function has a sensitivity `Label` (`PUBLIC` or `INTERNAL`).
The `AGENT_SCOPES` dict in `src/agent.py` decides which tools each design can access.

**Invariant:** `agent_least_privilege` must never be granted a tool labeled `INTERNAL`. The CI gate
enforces this. A change that breaks this invariant will fail the build.

## Tests

- Everything in the offline suite (`pytest -m "not live"`) must pass with no API keys and no
  network access.
- New behavior gets an offline test with a scripted LLM or a fake client.
- `pytest -m live -s` runs against real models; it never runs in CI.

## Style

- Python 3.11+, standard library plus the provider SDKs.
- Match the existing style: module docstrings, short functions, dataclasses for records, no
  framework.
- Reports under `results/compromised/` are generated; never edit them by hand.

## Pull requests

- Keep commits small with descriptive messages.
- Run `pytest -m "not live"` and `python -m src.evaluate --out results/compromised` before pushing.
- The CI workflow runs the offline tests and the worst-case gate automatically.
