"""Regression tests for record-group preparation reuse.

A single batch request must call ``prepare_records`` at most once for any
given baseline / new-version / candidate record group: all queries against
the group reuse one prepared snapshot, and searches that rebuild a group
already seen (the full edit subset, the full subsequence, an all-old /
all-new rollout mix, a content-identical candidate) reuse its snapshot or
its memoized preparation failure.
"""

import app.engine as engine


def caa(owner, tag, value="", flag=0):
    return {"type": "CAA", "owner": owner, "flag": flag, "tag": tag, "value": value}


def cname(owner, target):
    return {"type": "CNAME", "owner": owner, "target": target}


def query(qid, domain, ca="ca.net", wildcard=False):
    return {"id": qid, "domain": domain, "wildcard": wildcard, "ca": ca}


class PrepareSpy:
    """Count prepare_records calls keyed by raw record-group content."""

    def __init__(self, monkeypatch):
        self.calls = []
        self._orig = engine.prepare_records

        def spy(records):
            self.calls.append(
                tuple(tuple(sorted(rec.items())) for rec in records)
            )
            return self._orig(records)

        monkeypatch.setattr(engine, "prepare_records", spy)

    def count(self):
        return len(self.calls)

    def distinct(self):
        return len(set(self.calls))

    def count_for(self, records):
        key = tuple(tuple(sorted(rec.items())) for rec in records)
        return self.calls.count(key)


# ---------- /v1/authorize/change-impact ----------

def test_change_impact_full_subset_prepared_once_across_queries(monkeypatch):
    # The minimal subset reproducing the new verdict is the full pair, so
    # each flipping query's search reaches the complete edit subset. That
    # group is identical to the new version and must be prepared once and
    # then reused, not re-normalized per query.
    spy = PrepareSpy(monkeypatch)
    records = [
        cname("www.test", "deny.net"),
        caa("deny.net", "issue", ""),
        caa("test", "issue", ""),
    ]
    edits = [
        {"remove": 0},
        {"add": cname("www.test", "allow.net")},
        {"add": caa("allow.net", "issue", "letsencrypt.org")},
    ]
    queries = [
        query("q1", "www.test", "letsencrypt.org"),
        query("q2", "www.test", "letsencrypt.org"),
    ]
    result = engine.change_impact(records, edits, queries)

    new_records = engine.apply_edits(records, edits)
    assert [f["id"] for f in result["flips"]] == ["q1", "q2"]
    assert all(f["minimal_edits"] == [0, 1] for f in result["flips"])
    # Full subset built once for the "after" pass and shared thereafter.
    assert spy.count_for(new_records) == 1
    assert spy.count() == spy.distinct()


def test_change_impact_invalid_candidate_failure_memoized(monkeypatch):
    # Subset [1] mixes CAA and CNAME at a.test and is skipped for *each*
    # flipping query; its preparation failure must surface only once.
    spy = PrepareSpy(monkeypatch)
    records = [cname("a.test", "b.test"), caa("test", "issue", "")]
    edits = [
        {"remove": 0},
        {"add": caa("a.test", "issue", "letsencrypt.org")},
    ]
    queries = [
        query("q1", "a.test", "letsencrypt.org"),
        query("q2", "a.test", "letsencrypt.org"),
    ]
    result = engine.change_impact(records, edits, queries)

    assert [f["id"] for f in result["flips"]] == ["q1", "q2"]
    assert all(f["minimal_edits"] == [0, 1] for f in result["flips"])
    # baseline, full subset, [0], invalid [1]: four distinct groups, and
    # the invalid one is not re-validated for the second query.
    assert spy.count() == 4 == spy.distinct()


def test_change_impact_identical_subset_groups_share_snapshot(monkeypatch):
    # Two individually sufficient, identical adds produce content-equal
    # full-result groups for the two flips; every group prepares once.
    spy = PrepareSpy(monkeypatch)
    records = [caa("example.com", "issue", "pki.goog")]
    add = caa("www.example.com", "issue", "letsencrypt.org")
    edits = [{"add": add}, {"add": dict(add)}]
    queries = [
        query("q1", "www.example.com", "letsencrypt.org"),
        query("q2", "www.example.com", "letsencrypt.org"),
    ]
    result = engine.change_impact(records, edits, queries)
    assert [f["minimal_edits"] for f in result["flips"]] == [[0], [0]]
    assert spy.count() == spy.distinct()


# ---------- /v1/records/minimize ----------

def test_minimize_full_subsequence_reuses_baseline_snapshot(monkeypatch):
    # Every record is essential for its own query, so the enumeration ends
    # on the full subsequence — content-identical to the baseline group.
    spy = PrepareSpy(monkeypatch)
    records = [
        caa("h0.test", "issue", "ca.net"),
        caa("h1.test", "issue", "ca.net"),
    ]
    queries = [
        query("q0", "h0.test", "other.net"),
        query("q1", "h1.test", "other.net"),
    ]
    result = engine.minimize_records(records, queries)

    assert result["kept"] == [0, 1]
    # The full set is prepared once: baseline pass and full-subsequence
    # candidate share the same snapshot.
    assert spy.count_for(records) == 1
    assert spy.count() == spy.distinct()


def test_minimize_content_identical_subsequences_share_snapshot(monkeypatch):
    # The first two records are identical and both unrelated. Size-2
    # subsequences [0,2] and [1,2] (likewise [0,3] and [1,3]) have equal
    # content; both are enumerated on the way to winner [2,3] and each
    # distinct content must be prepared only once.
    spy = PrepareSpy(monkeypatch)
    unrelated = caa("other.net", "issue", "ca.net")
    records = [
        dict(unrelated),
        dict(unrelated),
        caa("a.test", "issue", "ca.net"),
        caa("b.test", "issue", "ca.net"),
    ]
    queries = [
        query("a", "a.test", "x.net"),
        query("b", "b.test", "x.net"),
    ]
    result = engine.minimize_records(records, queries)

    assert result["kept"] == [2, 3]
    assert spy.count() == spy.distinct()
    # Baseline + empty + three size-1 contents + four distinct size-2
    # contents ([u,u], [u,a], [u,b], [a,b]).
    assert spy.count() == 9
    # [0,2] and [1,2] collapse to one prepare for their shared content.
    assert spy.calls.count(engine._group_key([unrelated, records[2]])) == 1


# ---------- /v1/authorize/rollout-window ----------

def test_rollout_all_old_and_all_new_mixes_reuse_endpoint_snapshots(monkeypatch):
    spy = PrepareSpy(monkeypatch)
    before = [caa("a.test", "issue", ""), caa("b.test", "issue", "")]
    after = [
        caa("a.test", "issue", "ca.net"),
        caa("b.test", "issue", "ca.net"),
    ]
    result = engine.rollout_window(
        before,
        after,
        [query("qa", "a.test"), query("qb", "b.test")],
        {"a.test": 10, "b.test": 60},
    )

    assert result["changed_owners"] == ["a.test", "b.test"]
    assert result["safe_from"] == 60
    assert result["first_unsafe"] == {
        "old_owners": ["a.test"],
        "query_id": "qa",
        "error": None,
    }
    # Endpoint groups each prepare once even though the mask enumeration
    # rebuilds the all-new (mask 0) and all-old (mask 3) combinations.
    assert spy.count_for(before) == 1
    assert spy.count_for(after) == 1
    assert spy.count() == spy.distinct()


def test_rollout_duplicate_interior_mix_prepared_once(monkeypatch):
    # Only one changed owner: masks are all-new and all-old, both endpoint
    # groups, so no third preparation happens at all.
    spy = PrepareSpy(monkeypatch)
    before = [caa("example.com", "issue", "pki.goog")]
    after = [caa("example.com", "issue", "letsencrypt.org")]
    result = engine.rollout_window(
        before,
        after,
        [
            query("q-le", "www.example.com", "letsencrypt.org"),
            query("q-goog", "www.example.com", "pki.goog"),
        ],
        {"example.com": 30},
    )
    assert result["safe_from"] == 30
    assert spy.count() == 2
    assert spy.count_for(before) == 1
    assert spy.count_for(after) == 1
