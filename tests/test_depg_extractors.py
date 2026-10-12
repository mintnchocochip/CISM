"""cism/depg/extractors.py: real parsing for nmap open ports and hydra
credential attempts."""

from __future__ import annotations

from langchain_core.messages import ToolMessage

from cism.depg.extractors import (
    GobusterExtractor,
    HydraExtractor,
    NiktoExtractor,
    NmapExtractor,
    SqlmapExtractor,
    Wafw00fExtractor,
)
from cism.depg.graph import Graph

_SQLMAP_VULNERABLE = """
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
"""

_SQLMAP_CLEAN = "all tested parameters do not appear to be injectable"

_GOBUSTER_OUTPUT = """
===============================================================
/admin                (Status: 301) [Size: 315] [--> /admin/]
/login.php            (Status: 200) [Size: 1234]
/doesnotexist          (Status: 404) [Size: 12]
===============================================================
"""

_NMAP_OUTPUT = """
Starting Nmap 7.94
Nmap scan report for 10.0.0.5
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  closed https
Nmap done: 1 IP address (1 host up) scanned in 1.2 seconds
"""

_HYDRA_SUCCESS = "[22][ssh] host: 10.0.0.5   login: admin   password: hunter2"
_HYDRA_FAILURE = "1 of 1 target completed, 0 valid passwords found"


def test_nmap_extractor_produces_one_node_per_open_port() -> None:
    message = ToolMessage(content=_NMAP_OUTPUT, tool_call_id="c1", name="nmap")
    call = {"id": "c1", "name": "nmap", "args": {"target": "10.0.0.5"}}

    extraction = NmapExtractor().extract(call, message, Graph(), "10.0.0.5")

    signals = {n.signal for n in extraction.nodes}
    assert signals == {"22/tcp", "80/tcp"}
    assert all(n.cause_class == "open-port" for n in extraction.nodes)
    assert all(n.evidence[0].tier == "T2" for n in extraction.nodes)
    assert all(n.evidence[0].verdict == "alive" for n in extraction.nodes)


def test_nmap_extractor_ignores_closed_ports() -> None:
    message = ToolMessage(content=_NMAP_OUTPUT, tool_call_id="c1", name="nmap")
    call = {"id": "c1", "name": "nmap", "args": {"target": "10.0.0.5"}}

    extraction = NmapExtractor().extract(call, message, Graph(), "10.0.0.5")

    assert "443/tcp" not in {n.signal for n in extraction.nodes}


def test_hydra_extractor_success_is_a_t1_credential_node() -> None:
    message = ToolMessage(content=_HYDRA_SUCCESS, tool_call_id="c1", name="hydra")
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ssh"}}

    extraction = HydraExtractor().extract(call, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "credential-found"
    assert node.signal == "admin:hunter2"
    assert node.evidence[0].tier == "T1"
    assert node.evidence[0].verdict == "alive"


def test_hydra_extractor_failure_is_a_t3_tombstone() -> None:
    message = ToolMessage(content=_HYDRA_FAILURE, tool_call_id="c1", name="hydra")
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ssh"}}

    extraction = HydraExtractor().extract(call, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "credential-attempt"
    assert node.evidence[0].tier == "T3"
    assert node.evidence[0].verdict == "dead"


def test_hydra_extractor_treats_an_error_status_as_a_failed_attempt() -> None:
    message = ToolMessage(
        content="ToolTimeoutError: hydra: timed out after 120s",
        tool_call_id="c1", name="hydra", status="error",
    )
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ssh"}}

    extraction = HydraExtractor().extract(call, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "credential-attempt"
    assert node.evidence[0].verdict == "dead"


def test_sqlmap_extractor_confirmed_injection_is_a_t1_node() -> None:
    message = ToolMessage(content=_SQLMAP_VULNERABLE, tool_call_id="c1", name="sqlmap")
    call = {"id": "c1", "name": "sqlmap", "args": {"target": "http://10.0.0.5/"}}

    extraction = SqlmapExtractor().extract(call, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "sql-injection"
    assert node.signal == "id (GET)"
    assert node.evidence[0].tier == "T1"
    assert node.evidence[0].verdict == "alive"


def test_sqlmap_extractor_no_injection_is_a_t3_tombstone() -> None:
    message = ToolMessage(content=_SQLMAP_CLEAN, tool_call_id="c1", name="sqlmap")
    call = {"id": "c1", "name": "sqlmap", "args": {"target": "http://10.0.0.5/"}}

    extraction = SqlmapExtractor().extract(call, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "sql-injection-attempt"
    assert node.evidence[0].verdict == "dead"


def test_gobuster_extractor_one_node_per_hit_excluding_404() -> None:
    message = ToolMessage(content=_GOBUSTER_OUTPUT, tool_call_id="c1", name="gobuster")
    call = {"id": "c1", "name": "gobuster", "args": {"target": "http://10.0.0.5/"}}

    extraction = GobusterExtractor().extract(call, message, Graph(), "10.0.0.5")

    signals = {n.signal for n in extraction.nodes}
    assert signals == {"/admin (301)", "/login.php (200)"}
    assert all(n.cause_class == "exposed-path" for n in extraction.nodes)


_NIKTO_OUTPUT = """- Nikto v2.6.1
---------------------------------------------------------------------------
+ Target IP:          10.0.0.5
+ Target Hostname:    10.0.0.5
+ Target Port:        80
+ Start Time:         2026-10-12 06:00:00 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.25 (Debian)
+ ERROR: Failed to check for updates:
+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.
+ [600050] Apache/2.4.25 appears to be outdated (current is at least 2.4.68).
+ [013587] /: Suggested security header missing: permissions-policy.
+ [013587] /: Suggested security header missing: referrer-policy.
+ [750500] /config/: Directory indexing found. See: CWE-548
+ 8003 requests: 0 errors and 14 items reported on the remote host
+ End Time:           2026-10-12 06:00:14 (GMT0) (14 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
"""

_WAFW00F_DETECTED = (
    '[{"detected": true, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc.", '
    '"trigger_url": null, "url": "http://10.0.0.5/"}]'
)
_WAFW00F_ABSENT = (
    '[{"detected": false, "firewall": "None", "manufacturer": "None", '
    '"trigger_url": null, "url": "http://10.0.0.5/"}]'
)


def test_nikto_extractor_splits_server_banner_from_findings() -> None:
    message = ToolMessage(content=_NIKTO_OUTPUT, tool_call_id="c1", name="nikto")

    extraction = NiktoExtractor().extract(None, message, Graph(), "10.0.0.5")

    by_class = {n.cause_class for n in extraction.nodes}
    assert by_class == {"server-banner", "nikto-finding"}
    banner = next(n for n in extraction.nodes if n.cause_class == "server-banner")
    assert banner.signal == "Apache/2.4.25 (Debian)"


def test_nikto_extractor_ignores_housekeeping_lines() -> None:
    """Target IP/Hostname/Port, Start/End Time, 'No CGI Directories found',
    and the summary/host-count lines are not findings."""
    message = ToolMessage(content=_NIKTO_OUTPUT, tool_call_id="c1", name="nikto")

    extraction = NiktoExtractor().extract(None, message, Graph(), "10.0.0.5")

    joined = " ".join(n.signal for n in extraction.nodes)
    assert "Target IP" not in joined
    assert "requests:" not in joined
    assert "host(s) tested" not in joined


def test_nikto_extractor_keeps_duplicate_ids_as_distinct_findings() -> None:
    """[013587] repeats for two different missing headers — the id alone
    can't be the distinguishing key, the full text is."""
    message = ToolMessage(content=_NIKTO_OUTPUT, tool_call_id="c1", name="nikto")

    extraction = NiktoExtractor().extract(None, message, Graph(), "10.0.0.5")

    findings = [n for n in extraction.nodes if n.cause_class == "nikto-finding"]
    ids = [n.id for n in findings]
    assert len(ids) == len(set(ids))
    assert sum(1 for n in findings if "013587" in n.signal) == 2


def test_wafw00f_extractor_reports_detected_waf() -> None:
    message = ToolMessage(content=_WAFW00F_DETECTED, tool_call_id="c1", name="wafw00f")

    extraction = Wafw00fExtractor().extract(None, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "waf-detected"
    assert node.signal == "Cloudflare"
    assert node.evidence[0].verdict == "alive"


def test_wafw00f_extractor_reports_absence_as_a_finding_too() -> None:
    message = ToolMessage(content=_WAFW00F_ABSENT, tool_call_id="c1", name="wafw00f")

    extraction = Wafw00fExtractor().extract(None, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "waf-absent"


def test_wafw00f_extractor_malformed_json_is_zero_nodes_not_a_crash() -> None:
    message = ToolMessage(content="not json", tool_call_id="c1", name="wafw00f")

    extraction = Wafw00fExtractor().extract(None, message, Graph(), "10.0.0.5")

    assert extraction.nodes == []


def test_extractors_dict_keys_are_known_tool_names() -> None:
    """One cheap test catches a typo in EXTRACTORS at CI time instead of it
    silently falling through to the default extractor at runtime — hydra
    is included explicitly since it has no CATALOG row (design doc §5)."""
    from cism.agent.tools.catalog import CATALOG
    from cism.depg.extractors import EXTRACTORS

    assert set(EXTRACTORS) <= set(CATALOG) | {"hydra"}


def test_extractors_maps_nmap_and_hydra_to_their_real_extractors() -> None:
    from cism.depg.extractors import EXTRACTORS

    assert isinstance(EXTRACTORS["nmap"], NmapExtractor)
    assert isinstance(EXTRACTORS["hydra"], HydraExtractor)
