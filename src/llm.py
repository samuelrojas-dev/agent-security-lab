import re
import time

from .config import env


def _retry_delay(error: Exception) -> float:
    match = re.search(r"retry in ([\d.]+)s", str(error), re.IGNORECASE)
    return float(match.group(1)) + 2 if match else 45.0


class GeminiLLM:
    def __init__(self):
        from google import genai  # lazy import

        self._client = genai.Client(api_key=env("GEMINI_API_KEY"))
        self._model = env("GEMINI_MODEL", "gemini-3.6-flash")

    def generate(self, system: str, user: str, max_retries: int = 8) -> str:
        import httpx
        from google.genai import errors, types

        for attempt in range(max_retries):
            last_attempt = attempt == max_retries - 1
            try:
                response = self._client.models.generate_content(
                    model=self._model,
                    contents=user,
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
