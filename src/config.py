import os

try:
    from dotenv import load_dotenv
except ImportError:  # offline runs (compromised model + local data) need no .env
    pass
else:
    load_dotenv()


def env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value
