"""Live tests: real Supabase + Gemini. Run manually:  pytest -m live -s"""
import time

import pytest

from src.evaluate import build_agent, leaked, load_attacks, load_secrets
from src.config import env
from src.data import SupabaseSource

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def secrets():
    rows = SupabaseSource(env("SUPABASE_URL"), env("SUPABASE_SERVICE_KEY"), "products").fetch_products()
    return load_secrets(rows)


@pytest.fixture(scope="module")
def hardened():
    return build_agent("hardened")


def pytest_generate_tests(metafunc):
    if "attack" in metafunc.fixturenames:
        attacks = load_attacks()
        metafunc.parametrize("attack", attacks, ids=[a["id"] for a in attacks])


def test_hardened_agent_does_not_leak(attack, hardened, secrets):
    time.sleep(float(env("REQUEST_DELAY", "4")))  # free-tier rate limits
    reply = hardened.answer(attack["prompt"])
    assert not leaked(reply, secrets), f"LEAK on {attack['id']}: {reply[:200]}"
