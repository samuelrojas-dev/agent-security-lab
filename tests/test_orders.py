"""Enumeration experiment (src/orders.py): offline, deterministic, no keys."""
import json

import pytest

from src.orders import (ATTACKER, DESIGNS, PROFILES, LOCKED, UNIFORM, Monitor, OrderTool,
                        attack, load_orders, render, run_all)


@pytest.fixture(scope="module")
def orders():
    return load_orders()


def test_dataset_is_fictitious_and_shaped_for_the_scenario(orders):
    assert len(orders) == 40
    assert sum(o["customer_phone"] is None for o in orders.values()) == 4
    assert any(o["customer_phone"] == ATTACKER for o in orders.values())
    assert all(o["card_message"].startswith(f"CANARY-ORD-{oid}") for oid, o in orders.items())


@pytest.mark.parametrize("profile", PROFILES)
def test_prompt_rules_do_not_stop_enumeration(profile, orders):
    r = attack("prompt_only", profile, orders)
    assert r["leaked"] == r["foreign_orders_in_range"]


@pytest.mark.parametrize("profile", PROFILES)
def test_strict_object_authorization_leaks_nothing_and_confirms_nothing(profile, orders):
    r = attack("object_authz_strict", profile, orders)
    assert r["leaked"] == 0 and r["existence_confirmed"] == 0


def test_authz_gaps_leak_guest_orders_and_act_as_an_existence_oracle(orders):
    r = attack("object_authz", "single", orders)
    guests = sorted(oid for oid, o in orders.items() if o["customer_phone"] is None)
    assert r["leaked_ids"] == guests
    assert r["existence_confirmed"] == r["foreign_orders_in_range"] - len(guests)


def test_detection_stops_a_single_number_before_it_reaches_the_gap(orders):
    r = attack("authz_plus_detection", "single", orders)
    assert r["leaked"] == 0 and r["sessions_locked"] == 1 and r["existence_confirmed"] == 0


def test_rotating_numbers_evades_per_number_limits_but_not_the_global_alert(orders):
    r = attack("authz_plus_detection", "distributed", orders)
    assert r["sessions_locked"] == 0
    assert r["leaked"] > 0                      # detection alone does not close an authz gap
    assert r["alert_at_lookup"] is not None and r["alert_at_lookup"] < 20


def test_session_identity_comes_from_the_channel_not_the_arguments(orders):
    tool = OrderTool("object_authz_strict", orders, Monitor())
    victim = next(oid for oid, o in orders.items() if o["customer_phone"] not in (ATTACKER, None))
    assert tool.lookup(ATTACKER, f"{victim}") == UNIFORM
    assert tool.lookup(ATTACKER, "not-a-number") == UNIFORM


def test_locked_numbers_get_nothing_even_for_their_own_orders(orders):
    tool = OrderTool("authz_plus_detection", orders, Monitor())
    for oid in (1041, 1042, 1043):
        tool.lookup(ATTACKER, oid)
    own = next(oid for oid, o in orders.items() if o["customer_phone"] == ATTACKER)
    assert tool.lookup(ATTACKER, own) == LOCKED


def test_report_covers_every_design_and_profile():
    rows = run_all()
    assert {(r["design"], r["profile"]) for r in rows} == {(d, p) for d in DESIGNS for p in PROFILES}
    json.dumps(rows)
    assert render(rows).count("\n| `") == len(rows)
