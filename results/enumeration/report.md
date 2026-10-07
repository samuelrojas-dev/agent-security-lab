# Enumeration through the bot

Worst-case model, 60 sequential lookups (1001-1060); 40 orders exist, 4 are guest orders. Detection: lock after 3 denials per number, alert after 10 denials in total.

| Design | Attacker | Numbers | Other customers' orders leaked | Existence confirmed | Numbers locked | Alert at lookup |
|---|---|---|---|---|---|---|
| `prompt_only` | single | 1 | 36 / 36 | 0 | 0 | never |
| `prompt_only` | distributed | 30 | 40 / 40 | 0 | 0 | never |
| `object_authz` | single | 1 | 4 / 36 | 32 | 0 | never |
| `object_authz` | distributed | 30 | 4 / 40 | 36 | 0 | never |
| `object_authz_strict` | single | 1 | 0 / 36 | 0 | 0 | never |
| `object_authz_strict` | distributed | 30 | 0 / 40 | 0 | 0 | never |
| `authz_plus_detection` | single | 1 | 0 / 36 | 0 | 1 | never |
| `authz_plus_detection` | distributed | 30 | 4 / 40 | 0 | 0 | 11 |
