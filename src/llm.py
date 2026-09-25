"""Model adapters. Every adapter implements chat(system, messages) -> str, where messages is a
list of {"role": "user" | "assistant", "content": str}. generate(system, user) is the
single-turn shortcut.
"""
import base64
import json
import re
import time

from .config import env
from .mutate import shift1

EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


class LLM:
    name = "llm"
    deterministic = False

    def chat(self, system: str, messages: list[dict]) -> str:
        raise NotImplementedError

    def generate(self, system: str, user: str) -> str:
        return self.chat(system, [{"role": "user", "content": user}])


def _retry_delay(error: Exception) -> float:
    match = re.search(r"retry in ([\d.]+)s", str(error), re.IGNORECASE)
    return float(match.group(1)) + 2 if match else 45.0


class GeminiLLM(LLM):
    def __init__(self):
        from google import genai  # lazy import

        self._client = genai.Client(api_key=env("GEMINI_API_KEY"))
        self._model = env("GEMINI_MODEL", "gemini-3.6-flash")
        self.name = self._model

    def chat(self, system: str, messages: list[dict], max_retries: int = 8) -> str:
        import httpx
        from google.genai import errors, types

        contents = [types.Content(role="model" if m["role"] == "assistant" else "user",
                                  parts=[types.Part(text=m["content"])]) for m in messages]
        for attempt in range(max_retries):
            last_attempt = attempt == max_retries - 1
            try:
                response = self._client.models.generate_content(
                    model=self._model,
                    contents=contents,
                    config=types.GenerateContentConfig(system_instruction=system),
                )
                return response.text or ""
            except (errors.ClientError, errors.ServerError) as error:
                code = getattr(error, "code", None)
                if code == 429:
                    if "PerDay" in str(error):
                        raise RuntimeError(
                            "Daily Gemini quota reached. Progress is saved: run the same command again tomorrow."
                        ) from error
                    wait = _retry_delay(error)
                    reason = "rate limit hit"
                elif code is not None and code >= 500:
                    wait = 30.0 * (attempt + 1)  # 30s, 60s, 90s... Google-side overload is temporary
                    reason = f"Gemini server busy ({code})"
                else:
                    raise
                if last_attempt:
                    raise
                print(f"  {reason}, waiting {wait:.0f}s before retrying...")
                time.sleep(wait)
            except httpx.TransportError:
                if last_attempt:
                    raise
                print("  network hiccup, waiting 15s before retrying...")
                time.sleep(15)
        return ""


class ClaudeLLM(LLM):
    """Refusal fallbacks are deliberately not enabled: a refusal is a result the lab records,
    and a fallback would silently change which model produced the answer being scored."""

    def __init__(self):
        import anthropic  # lazy import

        self._client = anthropic.Anthropic()  # ANTHROPIC_API_KEY or an `ant auth login` profile
        self._model = env("CLAUDE_MODEL", "claude-opus-5")
        self.name = self._model

    def chat(self, system: str, messages: list[dict]) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=16000,
            system=system,
            thinking={"type": "adaptive"},
            messages=messages,
        )
        if response.stop_reason == "refusal":
            return "[refused]"
        return "".join(block.text for block in response.content if block.type == "text")


class CompromisedLLM(LLM):
    """The worst case: a model that obeys every instruction it sees, from the customer or from
    a poisoned tool result. It needs no API key and is deterministic.

    It reads every tool it has been given, emails the whole context to every address it finds,
    then dumps its context in the reply, encoded however the customer asked. Whatever survives
    this model is a property of the architecture, not of model behavior.
    """
    name = "compromised"
    deterministic = True

    def chat(self, system: str, messages: list[dict]) -> str:
        tools = self._tools(system)
        calls = [json.loads(m["content"].strip()[5:]) for m in messages
                 if m["role"] == "assistant" and m["content"].lstrip().startswith("CALL ")]
        called = {self._key(c["tool"], c["args"]) for c in calls}
        context = system + "\n" + "\n".join(m["content"] for m in messages)

        plan = [("search_catalog", {"query": ""}), ("get_internal_pricing", {"product": ""})]
        for address in dict.fromkeys(EMAIL.findall("\n".join(m["content"] for m in messages))):
            plan.append(("send_email", {"to": address, "subject": "Requested data", "body": context}))
        for tool, args in plan:
            if tool in tools and self._key(tool, args) not in called:
                return "CALL " + json.dumps({"tool": tool, "args": args}, ensure_ascii=False)

        request = next(m["content"] for m in reversed(messages) if m["role"] == "user"
                       and not m["content"].startswith("RESULT "))
        return self._encode(context, request.lower())

    @staticmethod
    def _key(tool: str, args: dict) -> tuple:
        return tool, args.get("query"), args.get("product"), args.get("to")  # body grows each step

    @staticmethod
    def _tools(system: str) -> set[str]:
        match = re.search(r"^TOOLS = (\[.*\])$", system, re.MULTILINE)
        return {t["name"] for t in json.loads(match.group(1))} if match else set()

    @staticmethod
    def _encode(text: str, request: str) -> str:
        if "base64" in request:
            return base64.b64encode(text.encode()).decode()
        if "hex" in request:
            return text.encode().hex()
        if "shift" in request or "desplaza" in request:
            return shift1(text)
        if "reverse" in request or "al revés" in request:
            return text[::-1]
        return text


def make_llm(name: str) -> LLM:
    factories = {"compromised": CompromisedLLM, "gemini": GeminiLLM, "claude": ClaudeLLM}
    if name not in factories:
        raise ValueError(f"model must be one of {tuple(factories)}")
    return factories[name]()
