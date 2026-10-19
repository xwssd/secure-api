# Screenshots for the report

The assignment requires screenshots of the SAST/SCA reports from the CI/CD section of the
repository. Save them here with these names so the README and the report can reference them:

| File | What it must show |
|------|-------------------|
| `ci-green.png` | The GitHub **Actions** (or GitLab **Pipelines**) run page: all jobs green, commit hash visible. |
| `ci-bandit.png` | Expanded `SAST - bandit` step: `No issues identified.` |
| `ci-pip-audit.png` | Expanded `SCA - pip-audit` step: `No known vulnerabilities found`. |
| `ci-artifacts.png` | The `security-reports` artifact with `bandit-report.txt` and `pip-audit-report.json`. |
| `local-pytest.png` | Local `pytest -q` run: `16 passed`. |
| `curl-401.png` | `curl /api/data` without a token → `401`. |
| `curl-200.png` | `curl /api/data` with a token → JSON list of posts. |

Terminal evidence can be produced with the commands in the README; a screenshot of the
terminal window is enough.
