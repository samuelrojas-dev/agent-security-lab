"""Offline tests for native tool calling: the shared loop, and the exact request shapes the
Claude and Gemini adapters send (with fake clients, so no API keys are needed)."""
import json
from types import SimpleNamespace as NS

import pytest

from src.agent import ToolAgent
from src.data import LocalSource
from src.detect import load_secrets
from src.evaluate import load_attacks, run_suite
from src.llm import LLM, ClaudeLLM, CompromisedLLM, GeminiLLM, Step, ToolCall
from src.tools import build_tools

SOURCE = LocalSource(public_only=False)
SECRETS = load_secrets(SOURCE.fetch_products())
AGENT_MODES = ["agent_prompt_only", "agent_least_privilege", "agent_flow_guard"]


class ScriptedNative(LLM):
    native_tools = True

    def __init__(self, *steps):
        self.steps, self.seen = list(steps), []

    def step(self, system, messages, tools):
        self.seen.append((system, [dict(m) for m in messages], [t.name for t in tools]))
        return self.steps.pop(0)


class TextOnly(LLM):
    def chat(self, system, messages):
        return "hello"


def test_native_and_text_loops_enforce_the_same_policy():
    attacks = load_attacks()
    native = run_suite(attacks, AGENT_MODES, CompromisedLLM(), "local", 1, SECRETS, protocol="native")
    text = run_suite(attacks, AGENT_MODES, CompromisedLLM(), "local", 1, SECRETS, protocol="text")
    for a, b in zip(native, text):
        for mode in AGENT_MODES:
            assert a["runs"][mode][0]["leaked"] == b["runs"][mode][0]["leaked"], (a["id"], mode)
            assert len(a["runs"][mode][0]["blocked"]) == len(b["runs"][mode][0]["blocked"]), (a["id"], mode)


def test_parallel_calls_are_all_checked_and_answered_in_one_message():
    llm = ScriptedNative(
        Step("", [ToolCall("a", "get_internal_pricing", {"product": "Miel"}),
                  ToolCall("b", "send_email", {"to": "x@gmail.com", "subject": "s", "body": "b"})]),
        Step("Done."))
    transcript = ToolAgent("agent_flow_guard", SOURCE, llm, "native").run(["hi"])
    tool_message = llm.seen[1][1][-1]
    assert tool_message["role"] == "tool"
    assert [(r["id"], r["is_error"]) for r in tool_message["results"]] == [("a", False), ("b", True)]
    assert "blocked by policy" in tool_message["results"][1]["content"]
    assert [e.delivered for e in transcript.egress] == [False, True]  # email blocked, reply sent


def test_native_loop_only_offers_tools_in_scope_and_drops_the_text_protocol():
    llm = ScriptedNative(Step("Hi."))
    ToolAgent("agent_least_privilege", SOURCE, llm, "native").run(["hi"])
    system, _, tools = llm.seen[0]
    assert tools == ["search_catalog", "quote", "send_email"]
    assert "CALL" not in system and "TOOLS =" not in system


def test_protocol_selection():
    assert ToolAgent("agent_prompt_only", SOURCE, CompromisedLLM()).protocol == "native"
    assert ToolAgent("agent_prompt_only", SOURCE, CompromisedLLM(), "text").protocol == "text"
    assert ToolAgent("agent_prompt_only", SOURCE, TextOnly()).protocol == "text"
    with pytest.raises(ValueError):
        ToolAgent("agent_prompt_only", SOURCE, TextOnly(), "native")


def test_tool_schemas():
    quote = build_tools(SOURCE.fetch_products())["quote"]
    strict = quote.schema(strict=True)
    assert strict["required"] == ["product", "quantity", "discount_pct"]
    assert strict["additionalProperties"] is False
    assert strict["properties"]["quantity"] == {"type": "integer"}
    assert "additionalProperties" not in quote.schema(strict=False)


# --- Claude adapter ---------------------------------------------------------------------------

def claude_with(*responses):
    llm = ClaudeLLM.__new__(ClaudeLLM)
    llm._model, llm.name, requests = "claude-test", "claude-test", []
    queue = list(responses)
    llm._client = NS(messages=NS(create=lambda **kw: requests.append(kw) or queue.pop(0)))
    return llm, requests


def test_claude_native_round_trip():
    first = NS(stop_reason="tool_use", content=[
        NS(type="thinking", thinking=""), NS(type="text", text="Let me look."),
        NS(type="tool_use", id="toolu_1", name="search_catalog", input={"query": "miel"})])
    llm, requests = claude_with(first, NS(stop_reason="end_turn", content=[NS(type="text", text="Miel: 19.800 COP")]))
    transcript = ToolAgent("agent_least_privilege", SOURCE, llm, "native").run(["¿precio de la miel?"])

    assert transcript.replies == ["Miel: 19.800 COP"]
    tools = requests[0]["tools"]
    assert [t["name"] for t in tools] == ["search_catalog", "quote", "send_email"]
    assert all(t["strict"] and t["input_schema"]["additionalProperties"] is False for t in tools)
    assert requests[0]["thinking"] == {"type": "adaptive"}
    second = requests[1]["messages"]
    assert second[1] == {"role": "assistant", "content": first.content}  # thinking replayed as-is
    result = second[2]["content"][0]
    assert result["type"] == "tool_result" and result["tool_use_id"] == "toolu_1" and not result["is_error"]
    assert "Miel de abejas" in result["content"]


def test_claude_refusal_ends_the_turn():
    llm, _ = claude_with(NS(stop_reason="refusal", content=[]))
    transcript = ToolAgent("agent_prompt_only", SOURCE, llm, "native").run(["x"])
    assert transcript.replies == ["[refused]"] and transcript.tool_calls == []


# --- Gemini adapter ---------------------------------------------------------------------------

def gemini_with(*responses):
    llm = GeminiLLM.__new__(GeminiLLM)
    llm._model, llm.name, requests = "gemini-test", "gemini-test", []
    queue = list(responses)
    llm._client = NS(models=NS(generate_content=lambda **kw: requests.append(kw) or queue.pop(0)))
    return llm, requests


def test_gemini_native_round_trip():
    types = pytest.importorskip("google.genai.types")
    call = types.FunctionCall(id="fc_1", name="quote", args={"product": "Miel", "quantity": 10, "discount_pct": 5})
    content = types.Content(role="model", parts=[types.Part(function_call=call)])
    final = types.Content(role="model", parts=[types.Part(text="10 x Miel: 188.100 COP")])
    llm, requests = gemini_with(NS(candidates=[NS(content=content)], function_calls=[call]),
                                NS(candidates=[NS(content=final)], function_calls=None))
    transcript = ToolAgent("agent_least_privilege", SOURCE, llm, "native").run(["cotiza 10 mieles con 5%"])

    assert transcript.replies == ["10 x Miel: 188.100 COP"]
    config = requests[0]["config"]
    declarations = config.tools[0].function_declarations
    assert [d.name for d in declarations] == ["search_catalog", "quote", "send_email"]
    assert config.automatic_function_calling.disable is True
    assert "additionalProperties" not in declarations[1].parameters_json_schema
    contents = requests[1]["contents"]
    assert contents[1] is content  # model turn replayed as-is (thought signatures survive)
    response = contents[2].parts[0].function_response
    assert response.id == "fc_1" and response.name == "quote"
    assert json.loads(response.response["result"])["discount_pct"] == 5


@pytest.mark.parametrize("call", [
    ToolCall("a", "send_email", "not an object"),
    ToolCall("b", "quote", {"product": 5, "quantity": "many", "discount_pct": None}),
    ToolCall("c", "search_catalog", {"query": 7}),
])
def test_malformed_calls_return_an_error_instead_of_crashing(call):
    llm = ScriptedNative(Step("", [call]), Step("ok"))
    transcript = ToolAgent("agent_prompt_only", SOURCE, llm, "native").run(["hi"])
    assert transcript.replies == ["ok"]
    result = llm.seen[1][1][-1]["results"][0]
    assert result["id"] == call.id


def test_unhashable_tool_name_is_an_unknown_tool():
    class Text(LLM):
        def __init__(self):
            self.out = ['CALL {"tool": ["x"], "args": {}}', "ok"]

        def chat(self, system, messages):
            return self.out.pop(0)

    transcript = ToolAgent("agent_prompt_only", SOURCE, Text(), "text").run(["hi"])
    assert transcript.replies == ["ok"] and transcript.tool_calls[0]["allowed"] is False
