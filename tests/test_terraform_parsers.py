import attestral.ingest.terraform as tf
from attestral.model import SystemModel
from attestral.rules import RuleEngine


def _findings_ids(monkeypatch=None, force_fallback=False):
    model = SystemModel()
    if force_fallback:
        # simulate python-hcl2 not installed
        original = tf._ingest_with_hcl2
        tf._ingest_with_hcl2 = lambda f, m: False
        try:
            tf.ingest_terraform("examples/demo-project", model)
        finally:
            tf._ingest_with_hcl2 = original
    else:
        tf.ingest_terraform("examples/demo-project", model)
    return {f.rule_id for f in RuleEngine().evaluate(model)}, len(model.components)


def test_hcl2_parser_used_when_available():
    import hcl2  # noqa: F401  (test env has the extra installed)
    ids, count = _findings_ids()
    assert count == 4
    assert {"ATL-001", "ATL-002", "ATL-003", "ATL-004", "ATL-005"} <= ids


def test_fallback_scanner_parity():
    ids_full, n_full = _findings_ids()
    ids_fb, n_fb = _findings_ids(force_fallback=True)
    assert n_full == n_fb == 4
    assert ids_full == ids_fb
