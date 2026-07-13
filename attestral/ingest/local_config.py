"""Discover MCP server configs already installed on this machine.

This powers ``attestral scan --local``: instead of pointing attestral at a
repo, a user runs one command and it scans the MCP servers their agent tools
(Claude Desktop, Cursor, VS Code, Windsurf, ...) are *already* wired to. No
repo, no setup - an instant read on the attack surface sitting on their disk.

The discovery table below is the single extension point. To teach attestral
about a new MCP client, add one ``_Candidate`` to ``_candidates()``; the
config is parsed by the same :func:`attestral.ingest.mcp.ingest_mcp` used for
repo scans, so any client that stores ``mcpServers`` / ``servers`` JSON works
without further changes.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from attestral.ingest.mcp import component_from_server, ingest_mcp
from attestral.model import SystemModel, TrustBoundary


@dataclass
class ConfigSource:
    """A known place an MCP client keeps its server config."""

    tool: str            # human-readable client name, e.g. "Claude Desktop"
    path: Path           # resolved candidate path on this machine
    scope: str = "user"  # "user" (per-account) | "project" (per-repo)
    found: bool = False  # set by discovery: does the file actually exist?
    servers: int = 0     # set by ingestion: servers this source contributed,
                         # so "found but empty" is distinguishable from broken


@dataclass
class _Candidate:
    """A discovery rule: a client name plus a factory that yields its path(s)."""

    tool: str
    scope: str
    # platforms this candidate applies to; empty tuple == all platforms.
    platforms: tuple[str, ...]
    factory: "callable"  # (home: Path, cwd: Path) -> Iterable[Path]


def _platform_key(platform: str | None) -> str:
    """Normalize sys.platform into 'darwin' | 'windows' | 'linux'."""
    plat = (platform or sys.platform).lower()
    if plat.startswith("win"):
        return "windows"
    if plat.startswith("darwin"):
        return "darwin"
    return "linux"


def _claude_desktop_path(home: Path, plat: str) -> Path:
    """Platform-specific Claude Desktop config location."""
    if plat == "darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if plat == "windows":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else home / "AppData" / "Roaming"
        return base / "Claude" / "claude_desktop_config.json"
    # linux / other posix
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else home / ".config"
    return base / "Claude" / "claude_desktop_config.json"


# ---------------------------------------------------------------------------
# Discovery table - THE extension point. Add a client by appending one entry.
# Each factory returns an iterable of candidate paths (dedup'd downstream).
# ---------------------------------------------------------------------------
def _candidates(plat: str) -> list[_Candidate]:
    return [
        # Claude Desktop - path differs per OS, resolved in the factory.
        _Candidate(
            "Claude Desktop", "user", (),
            lambda home, cwd, _p=plat: [_claude_desktop_path(home, _p)],
        ),
        # Claude Code - user scope is the top-level mcpServers of
        # ~/.claude.json (the same file also nests per-project servers under
        # "projects"; build_local_model pulls out the current project's).
        # Project scope is a checked-in .mcp.json at the repo root.
        _Candidate(
            "Claude Code (user)", "user", (),
            lambda home, cwd: [home / ".claude.json"],
        ),
        _Candidate(
            "Claude Code (project)", "project", (),
            lambda home, cwd: [cwd / ".mcp.json"],
        ),
        # Cursor - global (per-account) and project-local overrides.
        _Candidate(
            "Cursor (global)", "user", (),
            lambda home, cwd: [home / ".cursor" / "mcp.json"],
        ),
        _Candidate(
            "Cursor (project)", "project", (),
            lambda home, cwd: [cwd / ".cursor" / "mcp.json"],
        ),
        # VS Code (Copilot MCP) - workspace config uses the `servers` key,
        # which ingest_mcp already understands.
        _Candidate(
            "VS Code (project)", "project", (),
            lambda home, cwd: [cwd / ".vscode" / "mcp.json"],
        ),
        # Windsurf (Codeium) - global config.
        _Candidate(
            "Windsurf (global)", "user", (),
            lambda home, cwd: [home / ".codeium" / "windsurf" / "mcp_config.json"],
        ),
        # --- EXTENSION POINT --------------------------------------------------
        # Add new MCP clients here, e.g.:
        #   _Candidate("Zed (project)", "project", (),
        #       lambda home, cwd: [cwd / ".zed" / "settings.json"]),
        # If a client's format is unusual, teach ingest_mcp about it instead of
        # special-casing here.
        # ---------------------------------------------------------------------
    ]


def discover_config_sources(
    home: str | Path | None = None,
    cwd: str | Path | None = None,
    platform: str | None = None,
) -> list[ConfigSource]:
    """Return every known MCP config location with ``found`` marked.

    Args are injectable so tests never touch the runner's real machine:
      home     -- overrides ``Path.home()`` (user-scoped configs)
      cwd      -- overrides the current dir (project-scoped configs)
      platform -- overrides ``sys.platform`` ('darwin'|'win32'|'linux')
    """
    home_p = Path(home) if home is not None else Path.home()
    cwd_p = Path(cwd) if cwd is not None else Path.cwd()
    plat = _platform_key(platform)

    sources: list[ConfigSource] = []
    seen: set[Path] = set()
    for cand in _candidates(plat):
        if cand.platforms and plat not in cand.platforms:
            continue
        for path in cand.factory(home_p, cwd_p):
            if path in seen:
                continue
            seen.add(path)
            sources.append(
                ConfigSource(
                    tool=cand.tool,
                    path=path,
                    scope=cand.scope,
                    found=path.is_file(),
                )
            )
    return sources


def _claude_code_project_servers(config_path: Path, project_dir: Path) -> dict:
    """Per-project ("local scope") servers nested inside ~/.claude.json.

    Only the entry for project_dir is returned. Other projects' servers never
    co-load with this one in a real session, so merging them into one model
    would fabricate fleet-level findings (ATL-202/203/206) no session can
    actually produce. To audit another project, run --local from its root.
    """
    try:
        data = json.loads(config_path.read_text(errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return {}
    projects = data.get("projects")
    if not isinstance(projects, dict):
        return {}
    try:
        want = Path(project_dir).expanduser().resolve()
    except OSError:
        return {}
    for path, cfg in projects.items():
        try:
            if Path(str(path)).expanduser().resolve() != want:
                continue
        except OSError:
            continue
        servers = cfg.get("mcpServers") if isinstance(cfg, dict) else None
        return servers if isinstance(servers, dict) else {}
    return {}


def _empty_model() -> SystemModel:
    """A model seeded with the same trust boundaries as a full repo scan."""
    return SystemModel(
        boundaries=[
            TrustBoundary("cloud", "Cloud infrastructure"),
            TrustBoundary("cluster", "Kubernetes cluster"),
            TrustBoundary("agent_runtime", "Agent / MCP runtime"),
        ]
    )


def build_local_model(
    sources: list[ConfigSource] | None = None,
    home: str | Path | None = None,
    cwd: str | Path | None = None,
    platform: str | None = None,
) -> tuple[SystemModel, list[ConfigSource]]:
    """Discover installed MCP configs and ingest the found ones into a model.

    Returns ``(model, sources)`` where ``sources`` carries the full
    found/absent report so the caller can tell the user what was scanned.
    Pass ``sources`` explicitly (e.g. in tests) to skip auto-discovery.
    """
    if sources is None:
        sources = discover_config_sources(home=home, cwd=cwd, platform=platform)
    model = _empty_model()
    cwd_p = Path(cwd) if cwd is not None else Path.cwd()
    for src in sources:
        if not src.found:
            continue
        before = len(model.by_type("mcp_server"))
        ingest_mcp(src.path, model)
        # ingest_mcp reads a file's top-level servers; Claude Code's user
        # config additionally nests the current project's local scope.
        if src.tool == "Claude Code (user)":
            for name, cfg in _claude_code_project_servers(src.path, cwd_p).items():
                model.add(component_from_server(
                    name, cfg, f"{src.path} [project: {cwd_p}]"
                ))
        src.servers = len(model.by_type("mcp_server")) - before
    return model, sources
