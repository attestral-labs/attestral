"""Static HCL resolution: variables, tfvars, locals, and local module calls.

The fixture (examples/hcl-resolution) has no risky literal anywhere - every
finding requires resolution, so these tests fail if resolution regresses to
literal-only ingestion. Negative tests pin the fail-open contract: what is
not statically decidable stays exactly as written and never becomes a finding.
"""
import attestral.ingest.terraform as tf
from attestral.model import SystemModel
from _helpers import rule_ids

FIXTURE = "examples/hcl-resolution"


def _model(path=FIXTURE, force_fallback=False):
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




def test_tfvars_overrides_variable_default():
    model = _model()
    bucket = model.get("aws_s3_bucket.logs")
    assert bucket.attr("acl") == "public-read"   # default is "private"
    assert "ATL-001" in rule_ids(model)


def test_local_reference_resolves():
    model = _model()
    cluster = model.get("aws_rds_cluster.events")
    assert cluster.attr("storage_encrypted") is False
    assert "ATL-006" in rule_ids(model)


def test_variable_default_resolves():
    model = _model()
    cluster = model.get("aws_rds_cluster.events")
    assert cluster.attr("backup_retention_period") in (0, "0")
    assert "ATL-007" in rule_ids(model)


def test_module_instantiated_with_call_inputs():
    model = _model()
    sg = model.get("module.edge.aws_security_group.gateway")
    assert sg is not None, "module resources carry their Terraform address"
    assert sg.attr("_cidr_blocks") == ["0.0.0.0/0"]  # call input beat the default
    assert "ATL-002" in rule_ids(model)
    # the module directory is instantiated via its call, not double-scanned
    assert len(model.by_type("aws_security_group")) == 1


def test_fallback_scanner_parity_on_resolution():
    full, fallback = _model(), _model(force_fallback=True)
    assert len(full.components) == len(fallback.components) == 3
    assert rule_ids(full) == rule_ids(fallback)


def test_unresolvable_reference_stays_inert(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n'
        '  acl = var.undeclared\n'
        '  bucket = coalesce(var.name, "x")\n'
        "}\n"
    )
    model = _model(tmp_path)
    (bucket,) = model.by_type("aws_s3_bucket")
    assert bucket.attr("acl") in ("var.undeclared", "${var.undeclared}")
    assert "ATL-001" not in rule_ids(model)  # an unknown value is never a finding


def test_registry_module_is_skipped(tmp_path):
    (tmp_path / "main.tf").write_text(
        'module "vpc" {\n'
        '  source  = "terraform-aws-modules/vpc/aws"\n'
        '  version = "5.0.0"\n'
        "}\n"
    )
    model = _model(tmp_path)
    assert model.components == []  # code not in scan: nothing invented


def test_module_self_reference_terminates(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" { acl = "public-read" }\n'
        'module "loop" { source = "./" }\n'
    )
    model = _model(tmp_path)
    assert len(model.components) == 1  # emitted once, cycle cut


def test_locals_may_reference_variables_and_locals(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "world" { default = "0.0.0.0/0" }\n'
        "locals {\n"
        "  open  = var.world\n"
        "  cidrs = local.open\n"
        "}\n"
        'resource "aws_security_group" "sg" {\n'
        "  ingress {\n"
        "    cidr_blocks = [local.cidrs]\n"
        "  }\n"
        "}\n"
    )
    model = _model(tmp_path)
    (sg,) = model.by_type("aws_security_group")
    assert sg.attr("_cidr_blocks") == ["0.0.0.0/0"]
    assert "ATL-002" in rule_ids(model)
