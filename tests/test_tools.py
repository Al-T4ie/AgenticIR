"""Tool layer: IOC extraction, n8n bridge, config parsing."""

from __future__ import annotations

import pytest

from app.config import Settings
from app.tools.builtin import alert_to_text, extract_indicators


# ── IOC extraction ───────────────────────────────────────────────────────────
def test_extracts_a_mixed_bag_of_indicators():
    text = (
        "Host 10.4.2.19 connected to 45.33.32.156 and cdn-update-service.top. "
        "Dropped file 9f2b8c1e4a7d3f6b0c5e8a1d4f7b2c9e6a3d0f5b8c1e4a7d2f9b6c3e0a5d8f1b "
        "and d41d8cd98f00b204e9800998ecf8427e. Phish sent to j.okafor@corp.example.com "
        "exploiting CVE-2024-21412."
    )
    found = extract_indicators(text)

    assert found["public_ips"] == ["45.33.32.156"]
    assert found["non_public_ips"] == ["10.4.2.19"]
    assert "cdn-update-service.top" in found["domains"]
    assert found["sha256"] == ["9f2b8c1e4a7d3f6b0c5e8a1d4f7b2c9e6a3d0f5b8c1e4a7d2f9b6c3e0a5d8f1b"]
    assert found["md5"] == ["d41d8cd98f00b204e9800998ecf8427e"]
    assert found["emails"] == ["j.okafor@corp.example.com"]
    assert found["cves"] == ["CVE-2024-21412"]


def test_routable_and_non_routable_addresses_are_separated():
    """Chasing an RFC1918 address as external infrastructure wastes a round."""
    found = extract_indicators("192.168.1.1 127.0.0.1 8.8.8.8 172.16.0.5 169.254.1.1")
    assert set(found["non_public_ips"]) == {
        "192.168.1.1",
        "127.0.0.1",
        "172.16.0.5",
        "169.254.1.1",
    }
    assert found["public_ips"] == ["8.8.8.8"]


def test_documentation_ranges_are_not_treated_as_public():
    """TEST-NET addresses appear constantly in runbooks and sample alerts;
    enriching them against threat intel is pure noise."""
    found = extract_indicators("192.0.2.5 198.51.100.77 203.0.113.9")
    assert found["public_ips"] == []
    assert len(found["non_public_ips"]) == 3


def test_sha256_is_not_double_counted_as_md5():
    sha = "a" * 64
    found = extract_indicators(f"hash {sha}")
    assert found["sha256"] == [sha]
    assert found["md5"] == []


def test_invalid_octets_are_not_treated_as_ips():
    found = extract_indicators("version 999.888.777.666 and 256.1.1.1")
    assert found["public_ips"] == []
    assert found["non_public_ips"] == []


def test_empty_input_yields_no_indicators():
    assert all(v == [] for v in extract_indicators("").values())


# ── Alert flattening ─────────────────────────────────────────────────────────
def test_alert_to_text_flattens_nested_structures():
    text = alert_to_text(
        {
            "title": "Beacon",
            "host": {"hostname": "WS-1", "ip": "10.0.0.4"},
            "tags": ["c2", "persistence"],
        }
    )
    assert "title: Beacon" in text
    assert "host.hostname: WS-1" in text
    assert "tags.0: c2" in text


def test_alert_to_text_survives_an_empty_alert():
    assert alert_to_text({}) == ""


def test_alert_to_text_caps_runaway_payloads():
    """A SIEM dumping 10k raw events must not blow the prompt budget."""
    huge = {f"field_{i}": f"value_{i}" for i in range(5000)}
    assert len(alert_to_text(huge).splitlines()) <= 400


# ── n8n tool configuration ───────────────────────────────────────────────────
def test_parses_n8n_tool_triples():
    settings = Settings(
        n8n_tools="enrich_ioc:agentic-ir/enrich:Look up an indicator,"
        "create_ticket:agentic-ir/ticket:Open a ticket"
    )
    tools = settings.parsed_n8n_tools()
    assert [t["name"] for t in tools] == ["enrich_ioc", "create_ticket"]
    assert tools[0]["path"] == "agentic-ir/enrich"
    assert tools[0]["description"] == "Look up an indicator"


def test_tool_description_defaults_to_its_name():
    tools = Settings(n8n_tools="just_a_name:some/path").parsed_n8n_tools()
    assert tools[0]["description"] == "just_a_name"


@pytest.mark.parametrize("value", ["", "   ", ",,,", "malformed"])
def test_malformed_tool_specs_are_ignored(value: str):
    assert Settings(n8n_tools=value).parsed_n8n_tools() == []


def test_no_tools_registered_when_n8n_disabled():
    from app.tools.n8n import n8n_tools

    assert n8n_tools() == []


# ── Connection strings ───────────────────────────────────────────────────────
def test_database_urls_are_built_for_both_drivers():
    settings = Settings(
        postgres_host="db.internal",
        postgres_port=5433,
        postgres_db="ir",
        postgres_user="svc",
        postgres_password="pw",
    )
    assert settings.database_url == "postgresql://svc:pw@db.internal:5433/ir"
    assert settings.async_database_url == "postgresql+asyncpg://svc:pw@db.internal:5433/ir"


def test_blank_numeric_env_falls_back_to_the_default():
    """Compose interpolation can hand us an empty string for an unset number."""
    assert Settings(postgres_port="").postgres_port == 5432


def test_cors_origins_parsed_into_a_list():
    assert Settings(cors_origins="https://a.test, https://b.test").cors_origin_list == [
        "https://a.test",
        "https://b.test",
    ]
