# C76 — aiven-client 4.18.0: `user-creds-download` writes `service.key` world-readable

## Program / asset
- **Program:** Aiven Managed Bug Bounty (Bugcrowd `aiven-mbb-og`) — public, paid
- **Asset:** `github.com/Aiven` → `aiven/aiven-client` (also PyPI `aiven-client`)
- **Vulnerable version:** tag / PyPI **4.18.0** (`268cc1df13eed28ba37c2527f2a1e18a9d384cf1`, uploaded 2026-09-01)
- **Unreleased fix:** `34e9822` (2026-09-22) — `os.chmod(fp.name, 0o600)` before writing key/cert; merged via PR #480 (`234f1c6`); **not** in any tag after 4.18.0

## Title
`avn service user-creds-download` creates TLS client private key with mode 0644 under common umask 022.

## Root cause
`service__user_creds_download` opens `service.key` / `service.cert` with `open(path, "w")` and writes PEM material without setting restrictive permissions. File mode is therefore `0666 & ~umask`. With the common umask `022`, the private key is **world-readable (0644)**.

The same codebase already hardens the CLI config file via `os.chmod(..., 0o600)` in `argx.py Config.save()`, but that pattern was not applied to downloaded key material until the unreleased commit.

Fingerprint: `aiven-client | cli.service__user_creds_download | avn service user-creds-download | open(service.key,"w") without chmod | umask-dependent 0644 private key | CWE-732 | local key disclosure | multi-user host + umask 022`

## Trust-boundary failure
Operator downloads mutual-TLS credentials for Kafka/etc. expecting a private key; any local user on the same host can read `service.key` and impersonate the service user.

## Affected code (4.18.0)
`aiven/client/cli.py` — `service__user_creds_download`:
```python
with open(os.path.join(self.args.target_directory, "service.cert"), "w", encoding="utf-8") as fp:
    fp.write(cert)
with open(os.path.join(self.args.target_directory, "service.key"), "w", encoding="utf-8") as fp:
    fp.write(key)
```

## Reproduction (synthetic, no API)
```bash
cd poc/r21-aiven-client-key-perms
python3 poc_key_perms.py
```
Mirrors the vulnerable `open`+`write` vs fixed `chmod 0o600` under `umask 022`.

### Actual (vulnerable pattern)
`service.key` mode `0o644`, `world-readable=True`.

### Expected
Private key mode `0o600`, not world-readable (as in unreleased fix / config-file pattern).

### Negative controls
- Fixed write path with `os.chmod(0o600)` → `0o600`, `world-readable=False`.
- `Config.save()` already uses 0600 — demonstrates intended project standard.

## Impact
- **Confidentiality:** TLS client private key readable by other local UIDs → service impersonation (e.g. Kafka mTLS user).
- **Prerequisites:** Shared multi-user host (CI runner, bastion, laptop with other accounts); default umask 022; attacker local read access to the target directory.
- **Limitations:** Local attack; single-user workstations with umask 077 are unaffected; directory ACLs may already restrict access.

## CWE / CVSS (conservative)
- **CWE-732** Incorrect Permission Assignment for Critical Resource
- **CVSS 3.1:** `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` ≈ **5.5 Medium**

## Duplicate search
- No CVE/GHSA for aiven-client `user-creds-download` permissions.
- Unrelated: GHSA-99j8-wv67-4c72 / CVE-2026-39961 (aiven-operator ClickhouseUser) — different product.

## Distinctness
New asset (`aiven-client`), new sink (filesystem mode on key material). Not overlapping C69/C75.

## Remediation
Release a tag containing `34e9822` (chmod 0600 on key and cert before write). Prefer `os.open(..., O_CREAT|O_WRONLY|O_TRUNC, 0o600)` to avoid the brief umask window. Document that operators should `chmod 600 service.key` on existing downloads.

## Realistic payout
Aiven Bugcrowd Medium / P3 — roughly **$150–$750**.

## Evidence
- `EVIDENCE_C76.tar.gz`
- `poc_key_perms.py`, slices under `evidence/`
