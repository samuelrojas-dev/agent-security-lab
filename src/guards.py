"""Layer 3: output filter. Defense in depth, NOT the primary control."""

INTERNAL_MARKERS = (
    "cost_price",
    "margin_pct",
    "supplier_id",
    "supplier_notes",
    "canary-",
)

REFUSAL = "Sorry, I can't share that information. I can help with product names, prices and availability."


def output_blocked(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in INTERNAL_MARKERS)


def sanitize_output(text: str) -> str:
    return REFUSAL if output_blocked(text) else text
