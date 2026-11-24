# GitHub repository settings (owner actions)

CI only gates merges if the repository settings make it a gate. These settings cannot be changed
from the build environment, so the owner applies them with `scripts/configure_github.sh`, signed
in to `gh` as the owner. `scripts/verify_github_settings.sh` then **reads them back from the API**,
and that output is the evidence.

| Setting | Value | Why |
|---|---|---|
| Default branch | `main` | Workflows, rulesets and the report role's `ref:refs/heads/main` subject |
| Secret scanning + push protection, Dependabot alerts and security updates | enabled | Free for public repositories |
| Default `GITHUB_TOKEN` | read-only. Actions cannot approve PRs | Least privilege (zizmor/Checkov also enforce per-workflow permissions) |
| Ruleset `main` (`.github/rulesets/main.json`) | PR required, review threads resolved, **`ci-ok` required** (strict), no force push, no deletion, no bypass | `ci-ok` succeeds only if every CI job succeeded |
| Environment `dev-plan` | deployments from `main` only | Read-only plan role trust (`environment:dev-plan`) |
| Environments `dev`, `dev-cleanup` | `main` only + **owner approval** | Apply and cleanup role trust. Approval = the human gate (ADR 0008) |
| OIDC subject format | `use_immutable_subject: true` → `repo:oteyami2001@157901928/Automated-Cloud-Security-Compliance-Governance@1465572625:…` | The AWS trust policies match exactly this prefix. A recreated repository with the same name is rejected |

**Single maintainer:** required approvals are 0 and self-review is allowed, because GitHub never
lets an author approve their own PR and the owner is the only reviewer. The protection comes from
`ci-ok` plus the environment approval for every AWS-changing run. When a second maintainer joins,
raise the approval count to 1.

**Codespaces:** `gh` uses the Codespace token, which cannot read or change these settings. Run
`unset GITHUB_TOKEN && gh auth login` first.

```bash
bash scripts/configure_github.sh
```

```bash
bash scripts/verify_github_settings.sh
```
