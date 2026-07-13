# HCL-resolution fixture

Real Terraform almost never writes risky values as literals - they arrive
through `variable` defaults, `terraform.tfvars`, `locals`, and module inputs.
A scanner that only reads literals returns a clean scan on exactly the repos
that matter. **Nothing in this fixture carries a risky literal**: every
finding below exists only because Attestral statically resolves references
before the rules run.

```bash
attestral scan examples/hcl-resolution
```

## What fires, and which resolution step proves it

| Rule | Severity | Resource | What had to be resolved |
|---|---|---|---|
| ATL-001 | critical | `aws_s3_bucket.logs` | `acl = var.log_acl`, whose *default* is safe (`private`) - `terraform.tfvars` overrides it to `public-read`. Fires only if the default → tfvars precedence chain is applied. |
| ATL-002 | high | `module.edge.aws_security_group.gateway` | The module's own default CIDR is safe (`10.0.0.0/8`); the **call input** passes `0.0.0.0/0`. Fires only if the local module is instantiated with its caller's inputs - and the component carries the real Terraform address. |
| ATL-006 | high | `aws_rds_cluster.events` | `storage_encrypted = local.encrypt_db` - a `locals` reference. |
| ATL-007 | medium | `aws_rds_cluster.events` | `backup_retention_period = var.db_backups` - a plain variable default. |

## The resolution contract (fail-open, never guess)

- Only statically decidable values are bound: variable defaults, tfvars
  (root modules only, matching Terraform's semantics), locals, whole-string
  interpolations, and local `module` calls (`source = "./…"`), instantiated
  once per call with inputs overriding defaults.
- Anything else - functions, conditionals, resource references, undeclared
  variables, registry/git modules - is left **exactly as written**. An
  unresolved value can never match a literal-valued rule, so resolution only
  adds findings that are provably implied by the code; it never invents one.
- Module cycles are cut (Terraform forbids them anyway) and expansion depth
  is bounded.

Both parse tiers behave identically here: the full parser
(`attestral[terraform]`, python-hcl2) and the dependency-free fallback
scanner produce the same components and the same findings - covered by
`tests/test_hcl_resolution.py`.
