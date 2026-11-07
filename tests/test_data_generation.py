import ipaddress

from big_guard.config import REQUIRED_COLUMNS
from big_guard.data import ATTACK_SCENARIOS, SCENARIOS, generate_events

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def test_reproducible_for_same_seed_and_different_otherwise():
    a, b, c = generate_events(7), generate_events(7), generate_events(8)
    assert a.equals(b)
    assert not a.equals(c)


def test_schema_and_volume():
    df = generate_events(42)
    assert set(REQUIRED_COLUMNS) <= set(df.columns)
    assert len(df) > 10_000
    assert df["event_id"].is_unique
    assert df["timestamp"].is_monotonic_increasing
    assert df["timestamp"].notna().all()


def test_records_are_labelled_synthetic_and_use_documentation_ips():
    df = generate_events(42)
    assert df["is_synthetic"].all()
    for ip in df["source_ip"].unique():
        assert any(ipaddress.ip_address(ip) in net for net in DOC_NETS), ip


def test_all_scenarios_present_with_both_classes():
    df = generate_events(42)
    assert set(df["scenario"]) <= set(SCENARIOS)
    for s in ATTACK_SCENARIOS:
        assert (df["scenario"] == s).any(), s
    assert set(df["label"].unique()) == {0, 1}
    assert 0 < df["label"].mean() < 0.05            # rare positives
    assert set(df.loc[df["label"] == 1, "scenario"]) <= set(ATTACK_SCENARIOS)


def test_dormant_identities_are_actually_dormant_then_active():
    df = generate_events(42)
    d = df[df["scenario"] == "dormant_misuse"]
    for ident in d["identity"].unique():
        t = df[df["identity"] == ident]["timestamp"].sort_values()
        assert t.diff().max().days > 30


def test_no_personal_data_like_emails():
    df = generate_events(42)
    assert not df["identity"].str.contains("@").any()
