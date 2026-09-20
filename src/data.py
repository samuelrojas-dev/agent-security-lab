"""Data sources. The security boundary lives here: which table/view the agent can read."""

PUBLIC_FIELDS = ("id", "name", "description", "price", "stock")
INTERNAL_FIELDS = ("cost_price", "margin_pct", "supplier_id", "supplier_notes")


class SupabaseSource:
    def __init__(self, url: str, key: str, relation: str):
        from supabase import create_client  # lazy import so offline tests need no deps

        self._client = create_client(url, key)
        self._relation = relation

    def fetch_products(self) -> list[dict]:
        return self._client.table(self._relation).select("*").execute().data
