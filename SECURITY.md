# Security policy

## Scope

This is an **educational security lab** that attacks its own test agent with its own test data.
It does not handle user data, secrets or real credentials. The "attacks" in `attacks/attacks.json`
are prompt-injection and data-exfiltration techniques evaluated in a controlled environment.

## Reporting a vulnerability in the lab itself

If you find a bug in the lab's own code that would cause it to produce **misleading security
results** (a leak that goes unreported, a false positive that inflates a defense's score, or a CI
gate that can be bypassed), please open a GitHub issue. These bugs are equivalent to test failures
and are handled in the open.

If you find a vulnerability in a **dependency** this lab uses (an SDK, a Python package), report it
to the upstream project.

## Responsible disclosure for findings made with this lab

If you use this lab's techniques to test a production system and find a vulnerability, report it
through that system's own responsible disclosure channel (typically a bug bounty program or a
`security.txt` contact). Do not open an issue here for vulnerabilities in other people's systems.
