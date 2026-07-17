"""Service-coverage expansion for the AWS pack (ATL-055..ATL-068): Lambda URL,
RDS IAM auth, Redshift VPC routing, ElastiCache encryption, DocumentDB, SageMaker,
ALB, Kinesis, API Gateway, CloudFront WAF, CloudTrail logging, GuardDuty."""
from attestral.ingest import build_model
from attestral.rules import RuleEngine

FIXTURE = "examples/aws-pack-ext"
NEW_IDS = {f"ATL-{n:03d}" for n in range(55, 69)}   # 055..068 inclusive


def _fired():
    model = build_model(FIXTURE)
    return {f.rule_id for f in RuleEngine().evaluate(model)}


def test_all_new_aws_rules_fire():
    missing = sorted(NEW_IDS - _fired())
    assert not missing, f"new AWS rules that did not fire on the fixture: {missing}"


def test_new_ids_registered_and_unique():
    engine = RuleEngine()
    ids = [r["id"] for r in engine.rules]
    assert NEW_IDS <= set(ids)
    assert len(ids) == len(set(ids)), "duplicate rule id in the pack"


def test_no_stray_new_band_ids():
    # Only 055..068 from the 0xx band's new range should fire here; a stray
    # 069+ would mean a fixture resource drifted into an unintended new rule.
    fired_new = {i for i in _fired() if i.startswith("ATL-0") and i >= "ATL-055"}
    assert fired_new == NEW_IDS
