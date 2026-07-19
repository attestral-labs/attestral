"""Terraform (HCL) ingestion with static reference resolution.

Two parse tiers per file - python-hcl2 (``attestral[terraform]``) with a
dependency-free scanner fallback - feed one resolution pass that binds what is
statically decidable and nothing more:

* ``var.x``   from ``variable`` defaults, overridden by ``terraform.tfvars``
              and ``*.auto.tfvars`` (root modules only, per Terraform's own
              semantics - called modules see only their call inputs).
* ``local.x`` from ``locals`` blocks, resolved iteratively so locals may
              reference variables and other locals.
* ``"${..}"`` string interpolations, substituted only when *every* reference
              in the string resolves.
* local ``module`` calls (``source = "./.."``): the module directory's
  resources are instantiated once per call under the Terraform address
  (``module.<name>.<type>.<rname>``), with call inputs overriding the
  module's own defaults. Directories consumed as module targets are not
  also scanned standalone. Registry/git modules are skipped - their code
  is not in the scan.

Anything not statically decidable (functions, conditionals, resource
references, count/for_each) is left exactly as written. An unresolved value
can never match a literal-valued rule, so resolution only ever *adds*
findings provably implied by the code - it never guesses one.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from attestral.model import Component, SystemModel

_RESOURCE_RE = re.compile(r'resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{', re.MULTILINE)
_VARIABLE_RE = re.compile(r'variable\s+"([\w-]+)"\s*\{', re.MULTILINE)
_MODULE_RE = re.compile(r'module\s+"([\w-]+)"\s*\{', re.MULTILINE)
_LOCALS_RE = re.compile(r'\blocals\s*\{', re.MULTILINE)
_ATTR_RE = re.compile(r'^\s*([\w]+)\s*=\s*(.+?)\s*$', re.MULTILINE)

# "no value": distinct from None, which is a legitimate `default = null`.
_UNSET = object()

_MAX_MODULE_DEPTH = 4
_MODULE_META_KEYS = {"source", "version", "providers", "count", "for_each", "depends_on"}

# ${var.x} / ${local.x} occurrences inside a string.
_INTERP_RE = re.compile(r'\$\{\s*(var|local)\.([\w-]+)\s*\}')


# --- parse phase: raw, unresolved structures per directory -------------------

@dataclass
class _RawResource:
    rtype: str
    rname: str
    attrs: dict
    cidr_vals: list  # (direction, raw cidr_blocks value); direction is "ingress"/"egress"/None
    file: str


@dataclass
class _DirModule:
    """One directory of .tf files = one Terraform module scope."""
    dir: Path
    resources: list[_RawResource] = field(default_factory=list)
    variables: dict = field(default_factory=dict)   # name -> default | _UNSET
    locals: dict = field(default_factory=dict)
    calls: list = field(default_factory=list)       # (name, source, inputs, file)


def _unq(v):
    """Normalize python-hcl2 output: strip HCL string quoting, recurse containers."""
    if isinstance(v, str):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        return v.replace('\\"', '"')
    if isinstance(v, list):
        return [_unq(x) for x in v]
    if isinstance(v, dict):
        return {_unq(k): _unq(x) for k, x in v.items() if k != "__is_block__"}
    return v


_DIRECTION_BLOCKS = ("ingress", "egress")


def _flatten(attrs: dict, out: dict, cidr_vals: list, direction: str | None = None) -> None:
    for k, v in attrs.items():
        sub = k if k in _DIRECTION_BLOCKS else direction
        if isinstance(v, dict):
            _flatten(v, out, cidr_vals, sub)
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            for block in v:
                _flatten(block, out, cidr_vals, sub)
        else:
            out[k] = v
            if k == "cidr_blocks":
                cidr_vals.append((direction, v))


def _parse_with_hcl2(f: Path, dm: _DirModule) -> bool:
    try:
        import hcl2
    except ImportError:
        return False
    try:
        with f.open() as fh:
            data = hcl2.load(fh)
    except Exception:
        return False  # malformed file: let the lenient scanner have a try
    data = _unq(data)
    for block in data.get("resource", []) or []:
        for rtype, instances in block.items():
            for rname, raw in instances.items():
                attrs: dict = {}
                cidr_vals: list = []
                _flatten(raw if isinstance(raw, dict) else {}, attrs, cidr_vals)
                dm.resources.append(_RawResource(rtype, rname, attrs, cidr_vals, str(f)))
    for block in data.get("variable", []) or []:
        for vname, spec in block.items():
            dm.variables[vname] = (
                spec.get("default", _UNSET) if isinstance(spec, dict) else _UNSET
            )
    for block in data.get("locals", []) or []:
        if isinstance(block, dict):
            dm.locals.update(block)
    for block in data.get("module", []) or []:
        for mname, spec in block.items():
            if isinstance(spec, dict):
                inputs = {k: v for k, v in spec.items() if k not in _MODULE_META_KEYS}
                dm.calls.append((mname, str(spec.get("source", "")), inputs, str(f)))
    return True


# --- dependency-free fallback scanner ----------------------------------------

def _block_body(text: str, start: int) -> str:
    """Return the text of the brace-balanced block starting at `start` ('{')."""
    depth, i = 0, start
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
        i += 1
    return text[start + 1 :]


def _strip_comment(value: str) -> str:
    """Drop a trailing `#` / `//` comment, respecting double-quoted strings."""
    in_str = False
    for i, c in enumerate(value):
        if c == '"' and (i == 0 or value[i - 1] != "\\"):
            in_str = not in_str
        elif not in_str and (c == "#" or value[i : i + 2] == "//"):
            return value[:i]
    return value


def _clean(value: str):
    v = _strip_comment(value).strip().rstrip(",")
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1].replace('\\"', '"')
    if v in ("true", "false"):
        return v == "true"
    return v


def _scan_value(value: str):
    """A scanner-tier value for resolution contexts (defaults, locals, module
    inputs): scalars via _clean, one-line lists as real lists. A value the
    line-based scanner cannot capture (multi-line list/object) is _UNSET -
    an unknowable value must stay unbound, not become junk."""
    v = _strip_comment(value).strip().rstrip(",")
    if v in ("[", "{"):
        return _UNSET
    if v.startswith("[") and v.endswith("]"):
        return [_clean(x) for x in v[1:-1].split(",") if x.strip()]
    return _clean(v)


_CIDR_ATTR_RE = re.compile(r'cidr_blocks\s*=\s*(\[[^\]]*\]|\S+)')
_DIRECTION_BLOCK_RE = re.compile(r'\b(ingress|egress)\s*\{')


def _scan_cidrs(text: str) -> list:
    vals = []
    for raw in _CIDR_ATTR_RE.findall(text):
        sv = _scan_value(raw)
        if sv is not _UNSET:
            vals.append(sv)
    return vals


def _parse_with_scanner(f: Path, dm: _DirModule) -> None:
    text = f.read_text(errors="ignore")
    for m in _RESOURCE_RE.finditer(text):
        rtype, rname = m.group(1), m.group(2)
        body = _block_body(text, text.index("{", m.end() - 1))
        attrs = {k: _clean(v) for k, v in _ATTR_RE.findall(body)}
        cidr_vals = []
        rest = body
        for bm in _DIRECTION_BLOCK_RE.finditer(body):
            start = bm.end() - 1
            inner = _block_body(body, start)
            for sv in _scan_cidrs(inner):
                cidr_vals.append((bm.group(1), sv))
            end = min(start + len(inner) + 2, len(body))
            rest = rest[: bm.start()] + " " * (end - bm.start()) + rest[end:]
        for sv in _scan_cidrs(rest):
            cidr_vals.append((None, sv))
        dm.resources.append(_RawResource(rtype, rname, attrs, cidr_vals, str(f)))
    for m in _VARIABLE_RE.finditer(text):
        default = _UNSET
        body = _block_body(text, text.index("{", m.end() - 1))
        for k, v in _ATTR_RE.findall(body):
            if k == "default":
                default = _scan_value(v)
        dm.variables[m.group(1)] = default
    for m in _LOCALS_RE.finditer(text):
        body = _block_body(text, text.index("{", m.end() - 1))
        for k, v in _ATTR_RE.findall(body):
            sv = _scan_value(v)
            if sv is not _UNSET:
                dm.locals[k] = sv
    for m in _MODULE_RE.finditer(text):
        body = _block_body(text, text.index("{", m.end() - 1))
        raw = {}
        for k, v in _ATTR_RE.findall(body):
            sv = _scan_value(v)
            if sv is not _UNSET:
                raw[k] = sv
        inputs = {k: v for k, v in raw.items() if k not in _MODULE_META_KEYS}
        dm.calls.append((m.group(1), str(raw.get("source", "")), inputs, str(f)))


# --- resolution phase ---------------------------------------------------------

def _ref_parts(s: str) -> tuple[str, str] | None:
    """('var'|'local', name) when the whole string is one reference."""
    t = s.strip()
    if t.startswith("${") and t.endswith("}") and t.count("${") == 1:
        t = t[2:-1].strip()
    m = re.fullmatch(r'(var|local)\.([\w-]+)', t)
    return (m.group(1), m.group(2)) if m else None


def _resolve(value, var_env: dict, local_env: dict):
    if isinstance(value, list):
        return [_resolve(v, var_env, local_env) for v in value]
    if isinstance(value, dict):
        return {k: _resolve(v, var_env, local_env) for k, v in value.items()}
    if not isinstance(value, str):
        return value
    envs = {"var": var_env, "local": local_env}
    ref = _ref_parts(value)
    if ref:
        scope, name = ref
        return envs[scope][name] if name in envs[scope] else value
    refs = _INTERP_RE.findall(value)
    if refs and all(name in envs[scope] for scope, name in refs):
        return _INTERP_RE.sub(lambda m: str(envs[m.group(1)][m.group(2)]), value)
    return value  # not statically decidable: leave exactly as written


def _is_resolved(v) -> bool:
    if isinstance(v, str):
        return _ref_parts(v) is None and not _INTERP_RE.search(v)
    if isinstance(v, list):
        return all(_is_resolved(x) for x in v)
    if isinstance(v, dict):
        return all(_is_resolved(x) for x in v.values())
    return True


def _resolve_locals(raw_locals: dict, var_env: dict) -> dict:
    """Fixed-point pass: locals may reference vars and already-resolved
    locals. Whatever never fully resolves is simply left out of the env."""
    resolved: dict = {}
    pending = dict(raw_locals)
    for _ in range(len(raw_locals) + 1):
        progressed = False
        for k in list(pending):
            rv = _resolve(pending[k], var_env, resolved)
            if _is_resolved(rv):
                resolved[k] = rv
                del pending[k]
                progressed = True
        if not pending or not progressed:
            break
    return resolved


def _load_tfvars(directory: Path) -> dict:
    """terraform.tfvars then *.auto.tfvars (alphabetical), later files win."""
    out: dict = {}
    candidates = []
    tv = directory / "terraform.tfvars"
    if tv.is_file():
        candidates.append(tv)
    candidates.extend(sorted(directory.glob("*.auto.tfvars")))
    for f in candidates:
        out.update(_parse_tfvars(f))
    return out


def _parse_tfvars(f: Path) -> dict:
    try:
        import hcl2
    except ImportError:
        hcl2 = None
    if hcl2 is not None:
        try:
            with f.open() as fh:
                data = _unq(hcl2.load(fh))
            return data if isinstance(data, dict) else {}
        except Exception:
            pass  # malformed under the full parser: scanner gets a try
    out = {}
    for k, v in _ATTR_RE.findall(f.read_text(errors="ignore")):
        sv = _scan_value(v)
        if sv is not _UNSET:
            out[k] = sv
    return out


# --- IAM admin cross-resource resolution -------------------------------------
#
# An agent runtime's blast radius is decided by the IAM role it can assume, and
# that grant is spread across separate resources (the role, an inline
# aws_iam_role_policy, an aws_iam_role_policy_attachment, a standalone
# aws_iam_policy). None of them is the finding alone, so this is a model-level
# post-pass that joins them: it stamps `_admin_wildcard` on the role once any
# path grants administrator/wildcard access, so a cross-boundary rule can later
# tie that role to the Kubernetes ServiceAccount an agent actually assumes.
# Everything here is typed string handling - no eval - and fails closed: an
# unresolved reference or an unparseable policy contributes nothing.

_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
# A terraform resource address: `aws_iam_role.agent.name`, tolerating a `${..}`
# interpolation wrapper. Requires at least type.name.attr (two dots).
_TF_ADDR_RE = re.compile(r'([a-z][\w]*)\.([\w-]+)(?:\.[\w-]+)+')


def _addr_ref(value) -> tuple[str, str] | None:
    """('aws_iam_role', 'agent') for a terraform resource address, else None."""
    if not isinstance(value, str):
        return None
    t = value.strip()
    if t.startswith("${") and t.endswith("}"):
        t = t[2:-1].strip()
    m = _TF_ADDR_RE.fullmatch(t)
    return (m.group(1), m.group(2)) if m else None


def _has_action_star(v) -> bool:
    if v == "*":
        return True
    if isinstance(v, list):
        return any(x == "*" for x in v)
    return False


def _policy_is_admin_wildcard(policy_value) -> bool:
    """True when an IAM policy document (escaped-JSON string form) has an
    Effect=Allow statement granting Action "*" on Resource "*". Only the
    reliably-available literal JSON string is parsed; a jsonencode()/heredoc
    body or anything unparseable yields False - never guess an admin grant."""
    if not isinstance(policy_value, str):
        return False
    try:
        doc = json.loads(policy_value)
    except (ValueError, TypeError):
        return False
    if not isinstance(doc, dict):
        return False
    stmts = doc.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return False
    for st in stmts:
        if not isinstance(st, dict):
            continue
        if str(st.get("Effect", "")).lower() != "allow":
            continue
        if _has_action_star(st.get("Action")) and _has_action_star(st.get("Resource")):
            return True
    return False


def _role_ref_matches(value, role_names: set[str]) -> bool:
    """Does a `role = ...` reference (literal name or `aws_iam_role.<n>.<a>`
    address) name a role in `role_names`? Unresolved => no match (fail closed)."""
    if not isinstance(value, str):
        return False
    ref = _addr_ref(value)
    if ref is not None:
        return ref[0] == "aws_iam_role" and ref[1] in role_names
    return value.strip() in role_names


def _arn_is_admin(value, admin_policy_names: set[str]) -> bool:
    """A policy_arn that grants admin: the AWS-managed AdministratorAccess ARN,
    or an `aws_iam_policy.<name>.arn` address whose policy doc is wildcard."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if v == _ADMIN_POLICY_ARN:
        return True
    ref = _addr_ref(v)
    if ref is not None and ref[0] == "aws_iam_policy":
        return ref[1] in admin_policy_names
    return False


def _resolve_iam_admin(model: SystemModel) -> None:
    """Join IAM resources into an `_admin_wildcard` signal on each role.

    `type ==` (not by_type's prefix) is used deliberately: aws_iam_role,
    aws_iam_role_policy, and aws_iam_role_policy_attachment all share the
    `aws_iam_role` prefix and must be told apart."""
    policies = [c for c in model.components if c.type == "aws_iam_policy"]
    role_policies = [c for c in model.components if c.type == "aws_iam_role_policy"]
    attachments = [
        c for c in model.components if c.type == "aws_iam_role_policy_attachment"
    ]
    roles = [c for c in model.components if c.type == "aws_iam_role"]

    # Stamp the wildcard signal on every policy-document-bearing component, for
    # the role join below and for audit transparency on the policy itself.
    for c in policies + role_policies:
        c.attributes["_admin_wildcard"] = _policy_is_admin_wildcard(c.attr("policy"))
    admin_policy_names = {
        c.name for c in policies if c.attributes.get("_admin_wildcard")
    }

    for role in roles:
        names = {role.name}
        nm = role.attr("name")
        if isinstance(nm, str) and nm:
            names.add(nm)
        admin = False
        for rp in role_policies:
            if rp.attributes.get("_admin_wildcard") and _role_ref_matches(
                rp.attr("role"), names
            ):
                admin = True
        for att in attachments:
            if _role_ref_matches(att.attr("role"), names) and _arn_is_admin(
                att.attr("policy_arn"), admin_policy_names
            ):
                admin = True
        role.attributes["_admin_wildcard"] = admin
        role.attributes["_role_name"] = nm if isinstance(nm, str) and nm else role.name
        arn = role.attr("arn")
        if isinstance(arn, str) and arn.startswith("arn:"):
            role.attributes["_role_arn"] = arn


# --- emission ------------------------------------------------------------------

def ingest_terraform(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    files = [p] if p.is_file() else sorted(p.rglob("*.tf"))
    dirs: dict[Path, _DirModule] = {}
    for f in files:
        key = f.parent.resolve()
        dm = dirs.setdefault(key, _DirModule(dir=key))
        if not _parse_with_hcl2(f, dm):
            _parse_with_scanner(f, dm)

    # Directories consumed as local module targets are instantiated by their
    # caller(s), with call inputs - not scanned standalone with defaults.
    # (Self-references are excluded: Terraform forbids module cycles anyway,
    # and a root must never suppress itself.)
    targets: set[Path] = set()
    for dm in dirs.values():
        for _name, src, _inputs, _file in dm.calls:
            if src.startswith(("./", "../")):
                t = (dm.dir / src).resolve()
                if t in dirs and t != dm.dir:
                    targets.add(t)

    for d in sorted(dirs):
        if d in targets:
            continue
        dm = dirs[d]
        var_env = {n: v for n, v in dm.variables.items() if v is not _UNSET}
        if not p.is_file():
            var_env.update(_load_tfvars(d))
        _emit(dm, model, dirs, prefix="", var_env=var_env, stack=(d,))
    # Cross-resource IAM join, run once every component in this ingest exists.
    _resolve_iam_admin(model)
    return model


def _emit(
    dm: _DirModule,
    model: SystemModel,
    dirs: dict[Path, _DirModule],
    prefix: str,
    var_env: dict,
    stack: tuple[Path, ...],
) -> None:
    local_env = _resolve_locals(dm.locals, var_env)
    for r in dm.resources:
        attrs = {k: _resolve(v, var_env, local_env) for k, v in r.attrs.items()}
        cidrs: list[str] = []
        directed: dict[str, list[str]] = {"ingress": [], "egress": []}
        # aws_security_group_rule declares direction as a `type` attribute, not
        # a named block; an unresolved/unknown direction stays union-only.
        own = attrs.get("type") if r.rtype.endswith("_security_group_rule") else None
        for direction, cand in r.cidr_vals:
            rv = _resolve(cand, var_env, local_env)
            values = rv if isinstance(rv, list) else [rv]
            # only resolved strings: an inert "var.x" is not a CIDR
            resolved = [str(x) for x in values if _is_resolved(x) and x is not None]
            cidrs.extend(resolved)
            d = direction or own
            if d in directed:
                directed[d].extend(resolved)
        if cidrs:
            attrs["_cidr_blocks"] = cidrs
        for d, vals in directed.items():
            if vals:
                attrs[f"_{d}_cidr_blocks"] = vals
        model.add(
            Component(
                id=f"{prefix}{r.rtype}.{r.rname}",
                type=r.rtype,
                name=r.rname,
                source=r.file,
                attributes=attrs,
                trust_boundary="cloud",
            )
        )
    if len(stack) > _MAX_MODULE_DEPTH:
        return
    for mname, src, inputs, _file in dm.calls:
        if not src.startswith(("./", "../")):
            continue  # registry/git module: its code is not in the scan
        target = (dm.dir / src).resolve()
        child = dirs.get(target)
        if child is None or target in stack:
            continue  # outside the scan, or a call cycle
        child_env = {n: v for n, v in child.variables.items() if v is not _UNSET}
        child_env.update(
            {k: _resolve(v, var_env, local_env) for k, v in inputs.items()}
        )
        _emit(child, model, dirs, f"{prefix}module.{mname}.", child_env, stack + (target,))
