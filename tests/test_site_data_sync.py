"""The website's baked data must match what it was rendered from.

Three pages embed generated payloads: docs.html (rule index + evidence-chain
demo), index.html (browser-checker rules + count strings), and
architecture.html (the code-graph map). Each has a render script with a
--check mode; this test runs them so a rule wave or fixture change cannot
silently strand the site. Same spirit as test_docs_sync.py: sync is enforced,
not promised.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# (script, prerequisite path or None). render_codegraph needs the local
# .codegraph index, which exists on dev machines but not in a fresh checkout.
SCRIPTS = [
    ("render_docs_data.py", None),
    ("render_index_data.py", None),
    ("render_codegraph.py", REPO / ".codegraph" / "codegraph.db"),
]


@pytest.mark.parametrize(("script", "needs"), SCRIPTS, ids=[s for s, _ in SCRIPTS])
def test_site_data_in_sync(script: str, needs: Path | None) -> None:
    if needs is not None and not needs.exists():
        pytest.skip(f"{needs.name} not present (dev-only index)")
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / script), "--check"],
        capture_output=True, text=True, cwd=REPO,
    )
    assert proc.returncode == 0, (
        f"{script} --check failed; the site has drifted from its sources.\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
