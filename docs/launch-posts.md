# Posts de lanzamiento: Agent Security Lab

Enlace a usar en todos: https://github.com/samuelrojas-dev/agent-security-lab
Texto largo: https://github.com/samuelrojas-dev/agent-security-lab/blob/main/docs/findings.md

**Antes de publicar:**
- Lo ideal es lanzar **después** de tener resultados con Gemini o Claude reales. Todavía no existen, así que las líneas que los citaban se quitaron de los posts y están guardadas en [Líneas pendientes de resultados reales](#líneas-pendientes-de-resultados-reales), al final de este archivo, con el lugar donde reinsertarlas.
- Hacker News: publica de martes a jueves, entre 8 y 10 a. m. hora de Nueva York, y responde los comentarios durante las primeras 2 o 3 horas. Nunca pidas votos: HN lo penaliza.
- No publiques en todos lados el mismo día. Empieza por HN o Reddit, y al día siguiente LinkedIn y X.

---

## 1. Hacker News (Show HN)

**Título** (máximo 80 caracteres):

> Show HN: Testing which LLM agent defenses survive a fully jailbroken model

**URL:** el enlace al repo.

**Primer comentario** (publícalo tú mismo apenas salga el post):

> I built the same B2B sales agent six ways and attacked each one with 34 prompt-injection and data-exfiltration attacks. The agent can read a catalog, quote prices and send email; the data also holds cost prices and supplier notes that must never reach a customer.
>
> The interesting part is the model I tested against. A real model (Gemini) respected a "keep this confidential" rule on all 23 attacks I tried in v1, which proves less than it looks. So I added a deterministic "compromised model" that obeys every instruction it sees, including ones hidden inside tool results. Against it:
>
> - prompt-only confidentiality: 34/34 attacks leaked
> - the agent never sees internal data, or no tool returns it: 0/34
> - information-flow control in the agent loop (labels on tool results, clearances on sinks): 1/34, and it blocked all 36 exfiltration emails without reading them
>
> The structural results run in CI with no API keys, so they are a gate, not a measurement. `python -m src.evaluate` runs everything in about 2 seconds with no dependencies.
>
> What I underestimated most: the leak detector itself. It had 15 bugs over the project, 10 that missed real leaks and 5 false alarms (e.g. a quote total of $42.500 flagged as a 42.5% margin). The write-up covers what worked, what didn't, and what isn't measured yet. Feedback very welcome, especially on the flow-control design.

---

## 2. Reddit: r/MachineLearning (o r/LocalLLaMA)

**Título:**

> [P] A worst-case model shows prompt rules give no guarantees for LLM agents; structural defenses held at 0-1/34

**Texto:**

> I compared six designs of the same tool-using sales agent (catalog search, internal pricing, quotes, email) under 34 injection and exfiltration attacks, plus 5 evasion variants of each.
>
> Instead of relying only on a real model, the main run uses a deterministic model that follows every instruction it sees, including instructions planted in tool results. That turns "does this defense hold?" into something you can test in CI.
>
> **Results (worst case, 34 attacks):**
>
> | Design | Leaked |
> |---|---|
> | Confidentiality rule in the prompt | 34/34 |
> | Same, with tools and email | 34/34 |
> | Information-flow control in the loop | 1/34 (36 exfil emails blocked) |
> | Agent only sees a public view | 0/34 |
> | Least privilege (no tool returns internal data) | 0/34 |
>
> Things I found interesting:
> - Indirect injection was the main way out: one poisoned product description made every one of the 34 attacks also email the price sheet.
> - Content filters have a ceiling: an encoding the reply filter didn't know got all 35 secrets out in one reply. The label-based check never read content and never let an email through.
> - The leak detector needed as much adversarial testing as the agent (15 scoring bugs fixed, each with a regression test).
>
> Code (MIT, runs offline in ~2 s): https://github.com/samuelrojas-dev/agent-security-lab
> Write-up: https://github.com/samuelrojas-dev/agent-security-lab/blob/main/docs/findings.md
>
> Limitations are in the write-up: one synthetic domain, and the LLM judge for inference leaks isn't calibrated yet.

---

## 3. LinkedIn (español)

> ¿Basta con decirle a un agente de IA "no reveles esta información"?
>
> Construí el mismo agente de ventas de seis formas distintas y lo ataqué con 34 técnicas de prompt injection y fuga de datos. El agente puede consultar un catálogo, cotizar y enviar correos, y tiene acceso a costos y datos de proveedores que nunca deben llegar al cliente.
>
> Lo probé contra un "modelo comprometido": uno que obedece cualquier instrucción que vea, incluso las escondidas en los datos. Estos fueron los resultados:
>
> 🔴 Regla de confidencialidad en el prompt: 34 de 34 ataques filtraron datos.
> 🟡 Control de flujo de información en el loop del agente: 1 de 34, y bloqueó los 36 correos de exfiltración sin leer su contenido.
> 🟢 Mínimo privilegio (el agente nunca ve los datos internos): 0 de 34.
>
> La conclusión: una regla en el prompt mide el comportamiento del modelo; la arquitectura da garantías. Y esas garantías se pueden verificar en CI en cada push, sin API keys.
>
> Lo que más me sorprendió fue que el propio detector de fugas tenía 15 bugs: 10 dejaban pasar fugas reales y 5 inventaban fugas que no existían. Hay que atacar el instrumento de medición con la misma seriedad que el sistema.
>
> El código es open source (MIT) y corre en 2 segundos sin instalar nada:
> https://github.com/samuelrojas-dev/agent-security-lab
>
> #SeguridadIA #LLM #AgentesIA #PromptInjection #CiberSeguridad

## 4. LinkedIn (English)

> Is "never reveal this" enough to keep an AI agent from leaking data?
>
> I built the same sales agent six ways and attacked it with 34 prompt-injection and data-exfiltration techniques. It can search a catalog, quote prices and send email, and it has access to costs and supplier data that must never reach a customer.
>
> I tested it against a "compromised model", one that obeys every instruction it sees, including ones hidden in the data. The results:
>
> 🔴 Confidentiality rule in the prompt: 34/34 attacks leaked.
> 🟡 Information-flow control in the agent loop: 1/34, and all 36 exfiltration emails blocked without reading them.
> 🟢 Least privilege (the agent never sees internal data): 0/34.
>
> The takeaway: prompt rules measure behavior; architecture gives guarantees. And those guarantees can be checked in CI on every push, with no API keys.
>
> What surprised me most: the leak detector itself had 15 bugs, 10 that missed real leaks and 5 that reported leaks that never happened. Test your measuring instrument as hard as your system.
>
> Open source (MIT), runs in 2 seconds with nothing to install:
> https://github.com/samuelrojas-dev/agent-security-lab
>
> #AISecurity #LLM #AIAgents #PromptInjection #Cybersecurity

---

## 5. Hilo para X (inglés)

**1/**
> I built the same LLM agent 6 ways and attacked each with 34 prompt-injection & exfiltration attacks.
>
> Prompt rule "keep it confidential": 34/34 leaked.
> Least privilege: 0/34.
>
> Here's why prompt rules can't be your security boundary 🧵

**2/**
> The agent searches a catalog, quotes prices and sends email. The data also holds costs and supplier notes.
>
> I tested against a "compromised model" that obeys every instruction it sees, even ones hidden in tool results. It's deterministic, so the results run in CI.

**3/**
> Indirect injection was the main exit.
>
> One poisoned product description showed up in every search, so every one of the 34 attacks also emailed the price sheet out, including the harmless-looking ones.

**4/**
> Information-flow control fixed that: tool results carry labels, sinks carry clearances, and the agent loop blocks the flow.
>
> 36/36 exfiltration emails blocked, without reading them.
>
> But content filters have a ceiling: an unknown encoding got 35 secrets out in one reply.

**5/**
> The part I underestimated: the leak detector had 15 bugs (10 misses, 5 false alarms).
>
> Open source, MIT, runs in 2 s with no keys:
> github.com/samuelrojas-dev/agent-security-lab

---

## 6. Listas "awesome"

Una línea para proponer por PR en listas de seguridad de LLMs (por ejemplo, las de LLM security o prompt injection en GitHub):

> - [Agent Security Lab](https://github.com/samuelrojas-dev/agent-security-lab) - Six designs of the same tool-using agent under 34 injection and exfiltration attacks, with a worst-case model that verifies structural defenses in CI.

---

## Líneas pendientes de resultados reales

Estas líneas se quitaron de los posts porque todavía no existen resultados con Gemini o Claude reales para los diseños de agente. `X` e `Y` son marcadores: no hay cifras. Cuando existan, reemplaza `X` e `Y` por los resultados medidos, quita el marcador `[CON RESULTADOS REALES]` y reinserta cada línea en su lugar, como un párrafo propio dentro de la cita.

**Hacker News**, primer comentario, después del párrafo que termina en "with no dependencies.":

> `[CON RESULTADOS REALES]` With real models: Gemini leaked X/34 and Claude Y/34 on the prompt-only agent.

**Reddit**, después de la tabla de resultados:

> `[CON RESULTADOS REALES]` Real models on the prompt-only agent: Gemini X/34, Claude Y/34 (3 trials each, 95% CIs in the repo).

**LinkedIn (español)**, después de la línea "🟢 Mínimo privilegio…":

> `[CON RESULTADOS REALES]` Con modelos reales, Gemini filtró X de 34 y Claude Y de 34 con la regla en el prompt.

**LinkedIn (English)**, después de la línea "🟢 Least privilege…":

> `[CON RESULTADOS REALES]` With real models, Gemini leaked X/34 and Claude Y/34 under the prompt rule.
