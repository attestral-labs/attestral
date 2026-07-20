"""Security-group CIDR direction semantics.

ATL-002 ("open to the world") is an *ingress* rule, but Terraform's
near-universal default-outbound idiom (`egress { cidr_blocks = ["0.0.0.0/0"] }`,
or an `aws_security_group_rule` with `type = "egress"`) also carries a world
CIDR. The ingester therefore attributes every collected CIDR to a direction -
from the enclosing `ingress`/`egress` block, or from a rule resource's `type`
attribute - and ATL-002 matches only `_ingress_cidr_blocks`. A CIDR whose
direction is not statically decidable stays union-only and never becomes an
ingress finding (fail closed). ATL-032 (default SG must have *no* rules at all)
deliberately keeps matching the direction-blind `_cidr_blocks` union.

Every case runs through both parse tiers: python-hcl2 and the fallback scanner.
"""
import pytest

import attestral.ingest.terraform as tf
from attestral.model import SystemModel
from _helpers import rule_ids


def _model(path, force_fallback):
    model = SystemModel()
    if force_fallback:
        original = tf._parse_with_hcl2
        tf._parse_with_hcl2 = lambda f, dm: False
        try:
            tf.ingest_terraform(path, model)
        finally:
            tf._parse_with_hcl2 = original
    else:
        tf.ingest_terraform(path, model)
    return model




TIERS = [False, True]


@pytest.mark.parametrize("fallback", TIERS)
def test_open_egress_block_is_not_an_ingress_finding(tmp_path, fallback):
    # The standard Terraform default-outbound idiom: scoped ingress, open egress.
    (tmp_path / "main.tf").write_text(
        'resource "aws_security_group" "app" {\n'
        "  ingress {\n"
        "    from_port   = 443\n"
        "    to_port     = 443\n"
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["10.0.0.0/8"]\n'
        "  }\n"
        "  egress {\n"
        "    from_port   = 0\n"
        "    to_port     = 0\n"
        '    protocol    = "-1"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
    )
    model = _model(tmp_path, fallback)
    (sg,) = model.by_type("aws_security_group")
    assert sg.attr("_ingress_cidr_blocks") == ["10.0.0.0/8"]
    assert sg.attr("_egress_cidr_blocks") == ["0.0.0.0/0"]
    assert sorted(sg.attr("_cidr_blocks")) == ["0.0.0.0/0", "10.0.0.0/8"]
    assert "ATL-002" not in rule_ids(model)


@pytest.mark.parametrize("fallback", TIERS)
def test_open_ingress_block_still_fires(tmp_path, fallback):
    (tmp_path / "main.tf").write_text(
        'resource "aws_security_group" "web" {\n'
        "  ingress {\n"
        "    from_port   = 22\n"
        "    to_port     = 22\n"
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
    )
    model = _model(tmp_path, fallback)
    (sg,) = model.by_type("aws_security_group")
    assert sg.attr("_ingress_cidr_blocks") == ["0.0.0.0/0"]
    assert "ATL-002" in rule_ids(model)


@pytest.mark.parametrize("fallback", TIERS)
def test_egress_rule_resource_is_not_an_ingress_finding(tmp_path, fallback):
    # The exact terragoat false-positive shape: type = "egress" on a rule resource.
    (tmp_path / "main.tf").write_text(
        'resource "aws_security_group_rule" "egress" {\n'
        '  type              = "egress"\n'
        "  from_port         = 0\n"
        "  to_port           = 0\n"
        '  protocol          = "-1"\n'
        '  cidr_blocks       = ["0.0.0.0/0"]\n'
        '  security_group_id = "sg-123"\n'
        "}\n"
    )
    model = _model(tmp_path, fallback)
    (r,) = model.by_type("aws_security_group_rule")
    assert r.attr("_egress_cidr_blocks") == ["0.0.0.0/0"]
    assert r.attr("_ingress_cidr_blocks") is None
    assert r.attr("_cidr_blocks") == ["0.0.0.0/0"]  # union keeps the fact on record
    assert "ATL-002" not in rule_ids(model)


@pytest.mark.parametrize("fallback", TIERS)
def test_ingress_rule_resource_fires(tmp_path, fallback):
    (tmp_path / "main.tf").write_text(
        'resource "aws_security_group_rule" "ssh" {\n'
        '  type              = "ingress"\n'
        "  from_port         = 22\n"
        "  to_port           = 22\n"
        '  protocol          = "tcp"\n'
        '  cidr_blocks       = ["0.0.0.0/0"]\n'
        '  security_group_id = "sg-123"\n'
        "}\n"
    )
    model = _model(tmp_path, fallback)
    (r,) = model.by_type("aws_security_group_rule")
    assert r.attr("_ingress_cidr_blocks") == ["0.0.0.0/0"]
    assert "ATL-002" in rule_ids(model)


@pytest.mark.parametrize("fallback", TIERS)
def test_undecidable_direction_fails_closed(tmp_path, fallback):
    # Direction behind an unresolvable reference: never becomes an ingress claim.
    (tmp_path / "main.tf").write_text(
        'resource "aws_security_group_rule" "dynamic" {\n'
        "  type              = var.direction\n"
        '  cidr_blocks       = ["0.0.0.0/0"]\n'
        '  security_group_id = "sg-123"\n'
        "}\n"
    )
    model = _model(tmp_path, fallback)
    (r,) = model.by_type("aws_security_group_rule")
    assert r.attr("_cidr_blocks") == ["0.0.0.0/0"]
    assert r.attr("_ingress_cidr_blocks") is None
    assert r.attr("_egress_cidr_blocks") is None
    assert "ATL-002" not in rule_ids(model)


@pytest.mark.parametrize("fallback", TIERS)
def test_default_sg_stays_direction_blind_for_atl_032(tmp_path, fallback):
    # CIS: the default SG must hold no rules at all, so egress-only still fires.
    (tmp_path / "main.tf").write_text(
        'resource "aws_default_security_group" "default" {\n'
        '  vpc_id = "vpc-1"\n'
        "  egress {\n"
        "    from_port   = 0\n"
        "    to_port     = 0\n"
        '    protocol    = "-1"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
    )
    model = _model(tmp_path, fallback)
    ids = rule_ids(model)
    assert "ATL-032" in ids
    assert "ATL-002" not in ids
