from big_guard.data import generate_events
from big_guard.detection import score_events
from big_guard.features import compute_event_features
from big_guard.graph import (NODE_TYPES, RELATIONS, build_graph, identity_behavior_summary, neighborhood,
                             session_sequence, temporal_edge_table)


def _scored():
    return score_events(compute_event_features(generate_events(42)))


def test_node_and_relationship_types():
    s = _scored()
    G = build_graph(s)
    assert {d["node_type"] for _, d in G.nodes(data=True)} == set(NODE_TYPES)
    assert {e["relation"] for *_, e in G.edges(data=True)} == set(RELATIONS)
    for u, v, e in G.edges(data=True):
        assert (G.nodes[u]["node_type"], G.nodes[v]["node_type"]) == RELATIONS[e["relation"]]


def test_edges_carry_temporal_attributes():
    G = build_graph(_scored())
    for *_, e in list(G.edges(data=True))[:500]:
        assert e["first_seen"] <= e["last_seen"] and e["count"] >= 1


def test_suspicious_relationships_are_highlighted():
    s = _scored()
    G = build_graph(s)
    flagged_ident = s.loc[s["flagged"], "identity"].iloc[0]
    sub = neighborhood(G, flagged_ident)
    assert any(e["suspicious"] for *_, e in sub.edges(data=True))
    quiet = s.groupby("identity")["flagged"].sum()
    quiet_ident = quiet[quiet == 0].index[0]
    assert not any(e["suspicious"] for *_, e in neighborhood(G, quiet_ident).edges(data=True))


def test_neighborhood_options_and_unknown_identity():
    s = _scored()
    G = build_graph(s)
    ident = s["identity"].iloc[0]
    base = neighborhood(G, ident)
    with_sess = neighborhood(G, ident, include_sessions=True)
    assert with_sess.number_of_nodes() > base.number_of_nodes()
    assert neighborhood(G, "does-not-exist").number_of_nodes() == 0


def test_temporal_edge_table_schema_and_order():
    te = temporal_edge_table(_scored())
    assert {"src", "dst", "relation", "timestamp", "event_id"} <= set(te.columns)
    assert te["timestamp"].is_monotonic_increasing and set(te["relation"]) == set(RELATIONS)


def test_identity_summary_and_session_sequence():
    s = _scored()
    ident = s["identity"].iloc[0]
    summ = identity_behavior_summary(s, ident)
    assert summ["events"] == (s["identity"] == ident).sum()
    seq = session_sequence(s, s["session_id"].iloc[0])
    assert seq["timestamp"].is_monotonic_increasing
