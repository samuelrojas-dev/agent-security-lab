"""Information-flow control for tool-using agents.

Every tool result carries a sensitivity label. The guard tracks the highest label that has
entered the agent's context, and every sink (an email, the reply to the customer) has a
clearance. Data may only flow to a sink cleared for it:

    context label  <=  sink clearance      otherwise the action is blocked

This check does not ask the model anything and does not read the content, so a jailbroken
model cannot talk its way past it. It is coarse on purpose (one label for the whole context,
not per value): once internal data is in context, nothing leaves to an external address.

The reply to the customer is the one sink the guard cannot simply close (the agent must answer),
so for that channel it falls back to content inspection against the concrete internal values
the agent has actually seen. That part is heuristic and an encoding the detector does not know
gets through; the lab measures exactly that.
"""
import re
from dataclasses import dataclass, field
from enum import IntEnum

from .detect import Leak, find_leaks, load_secrets

INTERNAL_DOMAINS = ("mayorista.example",)


class Label(IntEnum):
    PUBLIC = 0
    INTERNAL = 1


ADDRESS = re.compile(r"<?[^@\s<>,;]+@([^@\s<>,;]+)>?")


def email_clearance(to: str, internal_domains=INTERNAL_DOMAINS) -> Label:
    """INTERNAL only if every recipient is a well-formed address on an internal domain.
    One outside or unparseable recipient makes the whole message PUBLIC (fail closed)."""
    recipients = [r for r in re.split(r"[,;\s]+", to.strip()) if r]
    if not recipients:
        return Label.PUBLIC
    for recipient in recipients:
        match = ADDRESS.fullmatch(recipient)
        if not match or match.group(1).lower().rstrip(".") not in internal_domains:
            return Label.PUBLIC
    return Label.INTERNAL


@dataclass
class Decision:
    allowed: bool
    reason: str = ""


@dataclass
class FlowGuard:
    principal: Label = Label.PUBLIC  # who reads the replies: an external customer
    internal_domains: tuple = INTERNAL_DOMAINS
    context: Label = Label.PUBLIC
    seen_secrets: list = field(default_factory=list)

    def observe(self, label: Label, result) -> None:
        """Called with every tool result that enters the model's context."""
        self.context = max(self.context, label)
        if label >= Label.INTERNAL:
            rows = result if isinstance(result, list) else [result]
            self.seen_secrets.extend(load_secrets([r for r in rows if isinstance(r, dict)]))

    def authorize_email(self, to: str) -> Decision:
        clearance = email_clearance(to, self.internal_domains)
        if self.context > clearance:
            return Decision(False, f"flow violation: context holds {self.context.name} data, "
                                   f"{to} is cleared for {clearance.name}")
        return Decision(True)

    def check_reply(self, text: str) -> list[Leak]:
        if self.context <= self.principal:
            return []
        return find_leaks(text, self.seen_secrets)

