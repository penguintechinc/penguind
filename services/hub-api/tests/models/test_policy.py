"""Effective-config merge rules and ConfigRevision digest stability."""

import uuid
from typing import Any

import pytest

from app.models import (
    ConfigRevision,
    GroupPolicy,
    Policy,
    PolicyError,
    TenantDB,
    effective_config,
    merge_groups,
    resolve,
)
from tests.models.factories import agent, group


def gp(name: str, doc: dict[str, Any]) -> GroupPolicy:
    """Build a GroupPolicy with a random public_id."""
    return GroupPolicy(name, uuid.uuid4(), Policy.parse(doc))


def test_tools_intersect_and_null_is_unrestricted() -> None:
    """allowed_tools is the intersection; null groups do not restrict."""
    merged = merge_groups(
        [
            gp("a", {"allowed_tools": ["x", "y", "z"]}),
            gp("b", {"allowed_tools": None}),
            gp("c", {"allowed_tools": ["y", "z", "w"]}),
        ]
    )
    assert merged.allowed_tools == frozenset({"y", "z"})
    assert merge_groups([gp("a", {"allowed_tools": None})]).has_tools is False


def test_disjoint_tools_yield_empty_set() -> None:
    """Disjoint allowed_tools intersect to nothing allowed, not unrestricted."""
    merged = merge_groups([gp("a", {"allowed_tools": ["x"]}), gp("b", {"allowed_tools": ["y"]})])
    assert merged.allowed_tools == frozenset()
    assert merged.to_doc()["allowed_tools"] == []


def test_limits_take_minimum_per_key() -> None:
    """Numeric limits fold with min; keys absent in a group don't lower others."""
    merged = merge_groups(
        [
            gp("a", {"limits": {"max_fuel": 100, "max_memory_mb": 64}}),
            gp("b", {"limits": {"max_fuel": 50, "poll_interval_s": 600}}),
            gp("c", {"limits": {"max_memory_mb": 128}}),
        ]
    )
    assert merged.limits == {"max_fuel": 50, "max_memory_mb": 64, "poll_interval_s": 600}


def test_group_order_deterministic_by_name() -> None:
    """Settings conflicts resolve last-by-name regardless of input order."""
    a = gp("alpha", {"settings": {"m": {"v": 1}}})
    z = gp("zulu", {"settings": {"m": {"v": 2}}})
    assert merge_groups([z, a]).settings == merge_groups([a, z]).settings == {"m": {"v": 2}}


def test_precedence_override_groups_default() -> None:
    """Per field: override > groups > tenant default."""
    default = Policy.parse(
        {"allowed_tools": ["d"], "limits": {"max_fuel": 1000, "max_stale_s": 900}}
    )
    groups = [gp("g", {"allowed_tools": ["g1", "g2"], "limits": {"max_fuel": 200}})]
    override = Policy.parse({"limits": {"max_fuel": 300}})
    eff = resolve(default, groups, override)
    assert eff.allowed_tools == frozenset({"g1", "g2"})
    assert eff.limits == {"max_fuel": 300, "max_stale_s": 900}
    assert resolve(default, [], None).allowed_tools == frozenset({"d"})
    unrestricted = resolve(default, groups, Policy.parse({"allowed_tools": None}))
    assert unrestricted.has_tools and unrestricted.allowed_tools is None
    assert unrestricted.to_doc()["allowed_tools"] is None


@pytest.mark.parametrize(
    "doc",
    [
        [],
        {"bogus": 1},
        {"allowed_tools": "x"},
        {"allowed_tools": [1]},
        {"limits": []},
        {"limits": {"nope": 1}},
        {"limits": {"max_fuel": 0}},
        {"limits": {"max_fuel": True}},
        {"settings": {"m": 1}},
        {"settings": []},
    ],
)
def test_parse_rejects_malformed(doc: Any) -> None:
    """Malformed policy documents fail loudly."""
    with pytest.raises(PolicyError):
        Policy.parse(doc)


def test_parse_none_is_empty() -> None:
    """None parses to the empty policy."""
    assert Policy.parse(None) == Policy()


def test_revision_digest_stable() -> None:
    """Digest ignores key order and changes on any content change."""
    a = {"policy": {"limits": {"max_fuel": 1}, "settings": {}}, "flags": {"x": True, "y": False}}
    b = {"flags": {"y": False, "x": True}, "policy": {"settings": {}, "limits": {"max_fuel": 1}}}
    ra, rb = ConfigRevision.of(a), ConfigRevision.of(b)
    assert ra == rb and len(ra.digest) == 64
    assert ra.digest == ConfigRevision.of(a).digest
    assert ConfigRevision.of({**a, "flags": {"x": False, "y": False}}) != ra
    assert ra.etag == f'"{ra.digest}"'


def test_revision_pinned_vector() -> None:
    """Canonical form is frozen: a known payload has a known digest."""
    rev = ConfigRevision.of({"b": [1, "é"], "a": None})
    assert rev.digest == ConfigRevision.of({"a": None, "b": [1, "é"]}).digest
    import hashlib

    expected = hashlib.sha256('{"a":null,"b":[1,"é"]}'.encode()).hexdigest()
    assert rev.digest == expected


def test_revision_matches_if_none_match() -> None:
    """If-None-Match handles lists, weak prefixes, wildcard and absence."""
    rev = ConfigRevision.of({"x": 1})
    assert rev.matches(rev.etag)
    assert rev.matches(f'"other", W/{rev.etag}')
    assert rev.matches("*")
    assert not rev.matches('"other"')
    assert not rev.matches(None)
    assert not rev.matches("")


def test_policy_doc_round_trip_identical_digest() -> None:
    """Equivalent policies (tool order differs) produce identical digests."""
    p1 = Policy.parse({"allowed_tools": ["b", "a"], "limits": {"max_fuel": 2, "max_memory_mb": 1}})
    p2 = Policy.parse({"limits": {"max_memory_mb": 1, "max_fuel": 2}, "allowed_tools": ["a", "b"]})
    assert ConfigRevision.of(p1.to_doc()) == ConfigRevision.of(p2.to_doc())


def test_effective_config_from_db(tdb: TenantDB, other: TenantDB) -> None:
    """DB-backed resolution uses tenant default, member groups (min/∩) and override."""
    tdb.insert("tenant_configs", policy={"limits": {"max_stale_s": 3600, "max_fuel": 9999}})
    g1 = group(tdb, "b-group", {"allowed_tools": ["t1", "t2"], "limits": {"max_fuel": 500}})
    g2 = group(tdb, "a-group", {"allowed_tools": ["t2", "t3"], "limits": {"max_fuel": 100}})
    group(tdb, "unrelated", {"limits": {"max_fuel": 1}})
    a = agent(tdb, override={"limits": {"max_stale_s": 600}})
    for g in (g1, g2):
        tdb.insert("group_members", group_id=g.id, agent_id=a.id)
    eff = effective_config(tdb, a.public_id)
    assert eff is not None
    assert eff.allowed_tools == frozenset({"t2"})
    assert eff.limits == {"max_fuel": 100, "max_stale_s": 600}
    assert effective_config(other, a.public_id) is None


def test_effective_config_no_default_no_groups(tdb: TenantDB) -> None:
    """An agent with nothing configured resolves to the empty policy."""
    a = agent(tdb)
    assert effective_config(tdb, a.public_id) == Policy()
