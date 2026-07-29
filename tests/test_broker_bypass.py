"""ATL-221: a credential broker is declared but bypassed by a standing credential
(CB4A TM-11, the Model C in disguise). This is the model-level pairing of the
agentgateway ingester with the credential rules: it fires ONLY when a broker is
present AND a component still holds a raw key, so it never nags a design that
made no brokering claim."""
import json
from pathlib import Path

from attestral.ingest.agentgateway import ingest_agentgateway
from attestral.ingest.mcp import ingest_mcp
from attestral.model import SystemModel
from attestral.rules import RuleEngine
from _helpers import ids_for

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"

_BROKER = """
binds:
  - port: 3000
    listeners:
      - routes:
          - name: brokered
            policies: { jwtAuth: { mode: strict } }
            backends:
              - mcp: { name: gh }
                backendAuth:
                  oauthTokenExchange:
                    clientAuth: { clientId: gw, secretRef: { name: s } }
"""


def _ids(tmp_path, *, broker: bool, raw_cred: bool) -> set[str]:
    if broker:
        (tmp_path / "agentgateway.yaml").write_text(_BROKER)
    server = {"command": "npx", "args": ["-y", "srv@1.0.0"]}
    if raw_cred:
        server["env"] = {"API_KEY": "${API_KEY}"}
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {"srv": server}}))
    model = SystemModel()
    ingest_agentgateway(str(tmp_path), model)
    ingest_mcp(str(tmp_path), model)
    return {f.rule_id for f in RuleEngine().evaluate(model)}


def test_broker_plus_raw_credential_fires_atl_221():
    assert "ATL-221" in ids_for(str(EXAMPLES / "broker-bypassed"))


def test_a_broker_with_no_raw_credential_is_silent(tmp_path):
    # The broker is the only credential path; nothing is bypassing it.
    assert "ATL-221" not in _ids(tmp_path, broker=True, raw_cred=False)


def test_a_raw_credential_with_no_broker_does_not_fire(tmp_path):
    # No brokering was claimed, so this is plain credential sprawl (ATL-104's
    # job), not a bypassed broker. ATL-221 must stay silent, or it collapses
    # into ATL-104 and becomes noise on every credentialed server.
    ids = _ids(tmp_path, broker=False, raw_cred=True)
    assert "ATL-221" not in ids
    assert "ATL-104" in ids   # the sprawl is still caught, just not as a bypass


def test_both_signals_needed(tmp_path):
    assert "ATL-221" in _ids(tmp_path, broker=True, raw_cred=True)
