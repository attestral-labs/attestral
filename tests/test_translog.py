"""Transparency log for conformance attestations (issue #79).

RFC 6962 hashing, per-append checkpoints, portable inclusion proofs, and the
fail-closed properties: tampering breaks every later checkpoint, an
inconsistent log refuses appends, and a truncation - honestly - verifies from
the file alone (the docstring's external-witness caveat, pinned as a test so
the limitation stays documented, not accidental).
"""
import hashlib
import json
from pathlib import Path

import pytest

from attestral.translog import (
    append_bundle,
    bundle_digest,
    find_entry,
    inclusion_proof,
    read_log,
    verify_inclusion,
    verify_log,
)


def _bundle(i: int) -> dict:
    return {"statement": {"predicate": {"signer": f"ci-{i}",
                                        "runtime": {"verdict": "CONFORM"}}},
            "envelope": None, "n": i}


def _grow(path: Path, n: int) -> list[dict]:
    return [append_bundle(path, _bundle(i), f"2026-07-23T00:0{i}:00+00:00")
            for i in range(n)]


def test_append_grow_and_full_history_verifies(tmp_path):
    log = tmp_path / "conformance.log"
    entries = _grow(log, 7)
    assert [e["index"] for e in entries] == list(range(7))
    ok, failures = verify_log(read_log(log))
    assert ok, failures


def test_two_leaf_root_matches_rfc6962_by_hand(tmp_path):
    log = tmp_path / "log"
    _grow(log, 2)
    e = read_log(log)
    leaf = lambda d: hashlib.sha256(b"\x00" + d).digest()  # noqa: E731
    want = hashlib.sha256(
        b"\x01" + leaf(e[0]["bundle_sha256"].encode())
        + leaf(e[1]["bundle_sha256"].encode())).hexdigest()
    assert e[1]["root"] == want


def test_inclusion_proof_verifies_for_every_entry(tmp_path):
    log = tmp_path / "log"
    _grow(log, 7)
    entries = read_log(log)
    for e in entries:
        proof = inclusion_proof(entries, e["index"])
        assert verify_inclusion(e["bundle_sha256"], proof), e["index"]


def test_inclusion_proof_rejects_wrong_leaf_and_malformed_proof(tmp_path):
    log = tmp_path / "log"
    _grow(log, 5)
    entries = read_log(log)
    proof = inclusion_proof(entries, 2)
    assert not verify_inclusion(entries[3]["bundle_sha256"], proof)
    assert not verify_inclusion("deadbeef", proof)
    assert not verify_inclusion(entries[2]["bundle_sha256"],
                                {**proof, "root": "00" * 32})
    assert not verify_inclusion(entries[2]["bundle_sha256"],
                                {**proof, "proof": proof["proof"][:-1]})
    assert not verify_inclusion(entries[2]["bundle_sha256"], {})


def test_tampered_entry_breaks_every_later_checkpoint(tmp_path):
    log = tmp_path / "log"
    _grow(log, 5)
    entries = read_log(log)
    entries[1]["bundle_sha256"] = "f" * 64
    log.write_text("".join(json.dumps(e) + "\n" for e in entries))
    ok, failures = verify_log(read_log(log))
    assert not ok
    # The edited entry and every subsequent checkpoint stop recomputing.
    assert any("entry 1" in f for f in failures)
    assert any("entry 4" in f for f in failures)


def test_append_refuses_a_tampered_log(tmp_path):
    log = tmp_path / "log"
    _grow(log, 3)
    entries = read_log(log)
    entries[0]["bundle_sha256"] = "f" * 64
    log.write_text("".join(json.dumps(e) + "\n" for e in entries))
    with pytest.raises(ValueError, match="refusing to append"):
        append_bundle(log, _bundle(9), "2026-07-23T01:00:00+00:00")


def test_truncation_verifies_from_the_file_alone_by_design(tmp_path):
    """A rollback to a past checkpoint is a valid earlier log - the file alone
    cannot prove it; the head root must be witnessed externally. Pinned so the
    limitation stays an explicit design statement."""
    log = tmp_path / "log"
    _grow(log, 5)
    entries = read_log(log)
    log.write_text("".join(json.dumps(e) + "\n" for e in entries[:3]))
    ok, failures = verify_log(read_log(log))
    assert ok, failures


def test_find_entry_and_digest_stability(tmp_path):
    log = tmp_path / "log"
    _grow(log, 3)
    entries = read_log(log)
    d = bundle_digest(_bundle(1))
    assert bundle_digest(json.loads(json.dumps(_bundle(1)))) == d
    assert find_entry(entries, d)["index"] == 1
    assert find_entry(entries, "0" * 64) is None


def test_unparseable_log_raises_not_verifies(tmp_path):
    log = tmp_path / "log"
    log.write_text('{"index": 0}\nnot json\n')
    with pytest.raises(ValueError, match="line 2"):
        read_log(log)


def test_empty_and_missing_log(tmp_path):
    assert read_log(tmp_path / "absent") == []
    ok, failures = verify_log([])
    assert ok and failures == []


# --- CLI: attest --log / attest --verify --log ------------------------------

def _design(tmp_path: Path) -> Path:
    d = tmp_path / "design"
    d.mkdir()
    (d / ".mcp.json").write_text(
        '{"mcpServers": {"docs": {"command": "npx",'
        ' "args": ["@acme/docs-mcp@1.0.0"]}}}')
    return d


def test_cli_attest_logs_and_verify_checks_inclusion(tmp_path):
    from click.testing import CliRunner

    from attestral.cli import main
    runner = CliRunner()
    design, out = _design(tmp_path), tmp_path / "att.json"
    log = tmp_path / "conformance.log"
    r = runner.invoke(main, ["attest", str(design), "-o", str(out),
                             "--log", str(log)])
    assert r.exit_code == 0, r.output
    assert "logged: entry #0" in r.output
    r = runner.invoke(main, ["attest", str(design), "-o", str(out),
                             "--verify", "--log", str(log)])
    assert r.exit_code == 0, r.output
    assert "history CONSISTENT" in r.output and "inclusion VERIFIED" in r.output


def test_cli_verify_fails_on_tampered_log_and_missing_entry(tmp_path):
    from click.testing import CliRunner

    from attestral.cli import main
    runner = CliRunner()
    design, out = _design(tmp_path), tmp_path / "att.json"
    log = tmp_path / "conformance.log"
    assert runner.invoke(main, ["attest", str(design), "-o", str(out),
                                "--log", str(log)]).exit_code == 0
    entries = read_log(log)
    entries[0]["bundle_sha256"] = "f" * 64
    log.write_text(json.dumps(entries[0]) + "\n")
    r = runner.invoke(main, ["attest", str(design), "-o", str(out),
                             "--verify", "--log", str(log)])
    assert r.exit_code == 1
    assert "transparency log FAILED" in r.output
    # A consistent log that simply never saw this bundle also fails closed.
    other = tmp_path / "other.log"
    append_bundle(other, _bundle(0), "2026-07-23T00:00:00+00:00")
    r = runner.invoke(main, ["attest", str(design), "-o", str(out),
                             "--verify", "--log", str(other)])
    assert r.exit_code == 1
    assert "not in" in r.output
