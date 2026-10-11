"""cism/agent/guardrails/privacy.py: §5.1 (BACKLOG.md) — real<->placeholder
mapping, and the action-chain stage that restores real values before a
tool call executes."""

from __future__ import annotations

from cism.agent.guardrails.privacy import PrivacyGateway, PrivacySwapOutStage


def test_anonymize_replaces_an_ip_with_a_stable_placeholder() -> None:
    gw = PrivacyGateway()

    first = gw.anonymize("scan found 10.0.0.5 open on port 80")
    second = gw.anonymize("also seen: 10.0.0.5")

    assert "10.0.0.5" not in first
    assert "<ip-1>" in first
    assert "<ip-1>" in second  # same real value -> same placeholder


def test_anonymize_assigns_distinct_placeholders_to_distinct_ips() -> None:
    gw = PrivacyGateway()

    text = gw.anonymize("hosts: 10.0.0.5 and 10.0.0.6")

    assert "<ip-1>" in text and "<ip-2>" in text


def test_anonymize_leaves_non_ip_numbers_alone() -> None:
    gw = PrivacyGateway()

    text = gw.anonymize("found 999.999.999.999 and version 1.2.3.4.5")

    assert "<ip-" not in text


def test_anonymize_replaces_a_known_scope_domain() -> None:
    gw = PrivacyGateway(domains=frozenset({"example.internal"}))

    text = gw.anonymize("target is example.internal")

    assert "example.internal" not in text
    assert "<host-1>" in text


def test_deanonymize_round_trips() -> None:
    gw = PrivacyGateway()
    anonymized = gw.anonymize("10.0.0.5")

    restored = gw.deanonymize(anonymized)

    assert restored == "10.0.0.5"


def test_deanonymize_leaves_an_unknown_placeholder_unchanged() -> None:
    gw = PrivacyGateway()

    assert gw.deanonymize("<ip-99>") == "<ip-99>"


def test_swap_out_stage_restores_the_real_value_in_tool_call_args() -> None:
    gw = PrivacyGateway()
    gw.anonymize("10.0.0.5")  # mint <ip-1> -> 10.0.0.5
    stage = PrivacySwapOutStage(gw)
    call = {"id": "c1", "name": "nmap", "args": {"target": "<ip-1>"}, "type": "tool_call"}

    result = stage.check(call)

    assert result.allowed is True
    assert result.value["args"]["target"] == "10.0.0.5"


def test_swap_out_stage_is_a_no_op_when_nothing_to_restore() -> None:
    gw = PrivacyGateway()
    stage = PrivacySwapOutStage(gw)
    call = {"id": "c1", "name": "nmap", "args": {"target": "10.0.0.5"}, "type": "tool_call"}

    result = stage.check(call)

    assert result.value == call
