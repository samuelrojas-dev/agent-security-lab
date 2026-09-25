"""Data sources. The security boundary lives here: which table/view the agent can read."""
import json
from pathlib import Path

PUBLIC_FIELDS = ("id", "name", "description", "price", "stock")
INTERNAL_FIELDS = ("cost_price", "margin_pct", "supplier_id", "supplier_notes")
CATALOG_FILE = Path(__file__).resolve().parent.parent / "data" / "catalog.json"


def public_view(rows: list[dict]) -> list[dict]:
    """The same projection as the products_public view in supabase/schema.sql."""
    return [{k: v for k, v in row.items() if k in PUBLIC_FIELDS} for row in rows]


class SupabaseSource:
    def __init__(self, url: str, key: str, relation: str):
        from supabase import create_client  # lazy import so offline tests need no deps

        self._client = create_client(url, key)
        self._relation = relation

    def fetch_products(self) -> list[dict]:
        return self._client.table(self._relation).select("*").execute().data


class LocalSource:
    """data/catalog.json, the same rows as the Supabase seed. `public_only` mirrors products_public."""

    def __init__(self, public_only: bool, path: Path = CATALOG_FILE):
        self._rows = json.loads(path.read_text(encoding="utf-8"))
        self._public_only = public_only

    def fetch_products(self) -> list[dict]:
        return public_view(self._rows) if self._public_only else [dict(r) for r in self._rows]
