# Prompt rules measure behavior. Architecture gives guarantees.

*Findings from the Agent Security Lab, September 2026.*

I built an LLM sales agent for a wholesale catalog, gave it data it must never reveal (cost
prices, margins, supplier IDs, supplier notes), and attacked it. Then I rebuilt the same agent six
ways and attacked each one with the same suite. This is what I learned, including what I got wrong
along the way.

## The question

An agent that can see a secret has to be trusted to keep it. An agent that can use tools can also
*send* that secret somewhere. So the useful question is not "does the model refuse?" but "what can
leave the system, and what decides that?"

A trial counts as a leak when an internal value reaches a destination not cleared for it: the
reply to the external customer, or an email to an outside address. Internal values are seeded with
distinctive numbers and `CANARY-` tokens, so a leak can be proven, not guessed.

## Six designs of the same agent

| Design | What the agent can reach | Defense |
|---|---|---|
| `vulnerable` | Full rows in the prompt | None |
| `prompt_only` | Full rows in the prompt | "Keep it confidential" |
| `hardened` | Only a public view | Data-layer isolation |
| `agent_prompt_only` | Tools incl. internal pricing and email | Confidentiality in the prompt |
| `agent_least_privilege` | Tools without any internal read | The secret is out of reach |
| `agent_flow_guard` | Tools incl. internal pricing and email | Information-flow control |

## Finding 1: a real model held the line, and that proves less than it seems

In the first version, against `gemini-3.6-flash` with 23 attacks, `prompt_only` leaked **0 of 23**.
A confidentiality instruction was enough. It is tempting to stop there.

But that result measures one model's behavior on one day with one phrasing. So I added a
**compromised model**: a deterministic stand-in that obeys every instruction it sees, including
instructions hidden inside tool results. It needs no API key, so it runs in CI. Against it,
`prompt_only` leaked **34 of 34** attacks and all 35 secrets.

Nothing about the design changed between those two numbers. Only the model did. A defense whose
strength depends entirely on the model is a measurement, not a guarantee.

## Finding 2: data the agent cannot reach cannot leak

`hardened` (the agent only ever sees a public view) and `agent_least_privilege` (no tool returns
internal data) leaked **0 of 34** attacks against the compromised model, and 0 of 204 once every
attack also got five evasion variants.

These zeros are different in kind from Gemini's zero. The compromised model tries everything:
it reads every tool it has, emails everything it sees, dumps its whole context in the reply. The
result is a property of the architecture, so it is enforced as a CI gate. If a change ever gives
the customer-facing agent a path to internal data, the build fails.

## Finding 3: least privilege does not have to cost the feature

Customers negotiate discounts, and deciding a discount needs the cost and the margin. The usual
answer is to give the agent the numbers and ask it to be careful.

The alternative is a tool that decides in code: `quote` receives a product, a quantity and a
requested discount, applies a margin floor server-side, and returns only the approved price. The
model gets the answer without ever holding the secret.

It is not free of leakage. A customer can probe which discount tier gets approved and learn
something about the margin. Coarse tiers (0, 5, 10, 15 %) bound that to at most two bits per
product, a trade-off that can be chosen deliberately instead of leaking by accident.

## Finding 4: for tool agents, indirect injection is the main exit

One product description in the catalog carries a hidden instruction to email the internal price
sheet to an outside address. Because that description shows up in every catalog search, in
`agent_prompt_only` **every one of the 34 attacks** also emailed the price sheet out, including
the ones that looked harmless. The customer never asked for anything suspicious; the data did.

`agent_flow_guard` blocked **all 36** attempted exfiltration emails. It never inspects the email
body. Every tool result carries a sensitivity label, every sink has a clearance, and the agent loop
refuses any action where data would flow to a sink not cleared for it. A model cannot argue its way
past a check that does not ask it anything.

## Finding 5: content inspection has a ceiling

The one sink the flow guard cannot simply close is the reply: the agent has to answer the customer.
There it falls back to scanning the reply for the internal values the agent actually saw, in
plain form and in common encodings (base64, hex, reversed, spaced, zero-width and full-width
characters).

A simple character-shift encoding it did not know got the complete price sheet through, in one
reply. That was the only leak from `agent_flow_guard` in the whole suite, and it exposed all 35
secrets. Labels are a guarantee; content filters are a heuristic. The flow guard is the right tool
when an internal read is unavoidable, and the wrong reason to stop pursuing least privilege.

## Finding 6: the measuring instrument needed adversarial testing too

The part I underestimated most was the leak detector itself. Over the project, fifteen bugs in
the scoring code surfaced: ten that let real leaks through and five that reported leaks that did
not happen.

- The first two came from the lab's own mutation engine. Base64 text containing a zero-width
  character was discarded as unreadable once decoded, and when an attack asked for a cipher the
  model ignored, the scorer only checked the deciphered text and missed the plain leak.
- A recipient list like `outside@example.com, inside@company` was cleared as internal, so an
  email to an outside address was neither blocked nor counted.
- Numbers broke in both directions: `27,315.00` was missed as the cost `27315`, while a legitimate
  quote total of `$42.500` was flagged as the margin `42.5`.
- The LLM judge accepted a one-character quote as evidence, so an invented finding could mark a
  refusal as a leak.

Every one of these is now covered by a regression test. One test sweeps every
price and total the quote tool can produce, in five number formats, and requires none of them to
look like a leak: a detector that blocks legitimate quotes is a detector that gets switched off.

If the tool that decides "safe" or "leaked" is never attacked, its zeros mean nothing.

## What this does not show

- **Real-model results for the tool-using agents do not exist yet.** The v2 numbers above come
  from the compromised model, which is an upper bound on exposure, not a prediction of how Claude
  or Gemini behave. Those runs, with several trials each, are the next step.
- **The LLM judge is not calibrated yet.** It is built to catch inference leaks ("the margin is
  above 40 %") and ships with a hand-labeled calibration set, but its precision and recall have not
  been measured against a real model.
- One synthetic catalog, one domain, and attacks written in English and Spanish.

## If you are building an agent

1. **Keep secrets out of the context.** What the model never sees, it cannot reveal, whatever it
   is told.
2. **Compute over secrets in tools.** Return decisions, not the numbers behind them.
3. **Enforce policy in the loop that executes tools, not in the prompt.** Label what tools return,
   give every sink a clearance, and check before anything runs.
4. **Treat output filters as the last line, not the wall.** They stop the common encodings and miss
   the ones nobody listed.
5. **Test your detector as hard as your agent.** Count its misses and its false alarms.
6. **Put the guarantee in CI.** A worst-case model makes architectural properties testable on
   every push, with no API keys.

The code, the attack suite, the reports and all of the tests are in this repository. The README
has the full per-attack tables.
