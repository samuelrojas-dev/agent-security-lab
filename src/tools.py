"""Tools a sales agent can be given. They run server-side with full access to the rows;
what the *agent* can reach is decided by which tools it is granted (its scope).

`quote` is the pattern that makes least privilege practical: the discount decision needs the
cost and the margin, so the tool computes it in code and returns only the outcome. The model
gets the answer without ever holding the secret.
"""
from dataclasses import dataclass
from typing import Callable

from .data import INTERNAL_FIELDS, PUBLIC_FIELDS
from .flow import Label

DISCOUNT_TIERS = (0, 5, 10, 15)  # coarse tiers: a yes/no per tier bounds what probing can learn
MIN_MARGIN_PCT = 25.0


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    params: dict
    label: Label       # sensitivity of what the tool returns
    sink: bool         # sends data outside the conversation
    run: Callable[[dict], object]

    def spec(self) -> dict:
        return {"name": self.name, "description": self.description, "params": self.params}


def _matches(rows: list[dict], query: str) -> list[dict]:
    query = (query or "").strip().lower()
    return [r for r in rows if query in r["name"].lower() or query in (r.get("description") or "").lower()]


def _unit_price(row: dict, tier: float) -> int:
    return round(row["price"] * (1 - tier / 100))


def _profitable(row: dict, tier: float) -> bool:
    unit = _unit_price(row, tier)
    return (unit - row["cost_price"]) / unit * 100 >= MIN_MARGIN_PCT


def build_tools(rows: list[dict]) -> dict[str, Tool]:
    def search_catalog(args):
        return [{k: r[k] for k in PUBLIC_FIELDS} for r in _matches(rows, args.get("query", ""))]

    def get_internal_pricing(args):
        return [{"name": r["name"], **{k: r[k] for k in INTERNAL_FIELDS}}
                for r in _matches(rows, args.get("product", ""))]

    def quote(args):
        found = _matches(rows, args.get("product", ""))
        if len(found) != 1:
            return {"error": "specify exactly one product"}
        row, quantity = found[0], max(1, int(args.get("quantity", 1)))
        requested = float(args.get("discount_pct", 0))
        tier = max((t for t in DISCOUNT_TIERS if t <= requested and _profitable(row, t)), default=0)
        unit = _unit_price(row, tier)
        return {"product": row["name"], "quantity": quantity, "requested_discount_pct": requested,
                "discount_pct": tier, "unit_price": unit, "total": unit * quantity}

    def send_email(args):  # delivery is recorded by the agent loop, which sees every sink call
        return {"status": "sent", "to": args.get("to", "")}

    tools = [
        Tool("search_catalog", "Search products by name. Empty query lists all. Returns public fields.",
             {"query": "string"}, Label.PUBLIC, False, search_catalog),
        Tool("get_internal_pricing", "Internal cost, margin and supplier data for matching products.",
             {"product": "string"}, Label.INTERNAL, False, get_internal_pricing),
        Tool("quote", f"Price a bulk order. Discounts are granted in tiers {DISCOUNT_TIERS} while "
                      "the order stays profitable; returns the best allowed tier.",
             {"product": "string", "quantity": "integer", "discount_pct": "number"}, Label.PUBLIC, False, quote),
        Tool("send_email", "Send an email.", {"to": "string", "subject": "string", "body": "string"},
             Label.PUBLIC, True, send_email),
    ]
    return {t.name: t for t in tools}
