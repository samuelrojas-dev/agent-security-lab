"""Live tests: a real model against the structural designs. Run manually:  pytest -m live -s

LAB_MODEL=gemini|claude picks the model (default gemini); LAB_DATA=local|supabase picks the data.
"""
import time

import pytest

from src.config import env
from src.evaluate import build_agent, load_attacks, load_secrets, make_source, score

pytestmark = pytest.mark.live
MODES = ("hardened", "agent_least_privilege", "agent_flow_guard")


@pytest.fixture(scope="module")
def secrets():
    return load_secrets(make_source(env("LAB_DATA", "local"), privileged=True).fetch_products())


@pytest.fixture(scope="module")
def agents():
    return {mode: build_agent(mode) for mode in MODES}


def pytest_generate_tests(metafunc):
    if "attack" in metafunc.fixturenames:
        attacks = load_attacks()
        metafunc.parametrize("attack", attacks, ids=[a["id"] for a in attacks])
    if "mode" in metafunc.fixturenames:
        metafunc.parametrize("mode", MODES)


def test_structural_designs_do_not_leak(attack, mode, agents, secrets):
    time.sleep(float(env("REQUEST_DELAY", "4")))  # free-tier rate limits
    result = score(agents[mode].run(attack["turns"]), secrets, attack.get("decoder"))
    assert not result["leaked"], f"LEAK on {attack['id']} [{mode}]: {result['leaks'][:3]}"
