# Releasing QuoxProof

Releases publish to PyPI automatically on a version tag, using **PyPI Trusted
Publishing** (OIDC). No API token is stored in GitHub or anywhere else: GitHub
mints a short-lived OIDC token that PyPI trusts for this exact repo and workflow.
This is what closes the token-exposure risk of the manual `twine upload` path.

## One-time setup (owner, on PyPI, ~2 minutes)

1. Sign in at pypi.org → the `quoxproof` project → **Manage** → **Publishing**.
2. Add a **Trusted Publisher** → GitHub Actions, with:
   - Owner: `quoxai`
   - Repository: `quoxproof`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. Save. (Optionally create a GitHub Environment called `pypi` in repo Settings →
   Environments for an extra approval gate.)

That's it. No secret to paste, ever.

## Cutting a release

1. Bump the version in `pyproject.toml`, `src/quoxproof/__init__.py`
   (`__version__`), and `src/quoxproof/receipt.py` (`SDK_VERSION`).
2. Commit, then tag and push:

   ```
   git tag v0.2.0
   git push origin v0.2.0
   ```

3. The `release.yml` workflow runs the test suite, builds sdist + wheel, and
   publishes to PyPI via OIDC. Watch it under the repo's Actions tab.

## Manual fallback (only if Trusted Publishing is not yet configured)

```
python -m build
TWINE_USERNAME=__token__ TWINE_PASSWORD=<project-scoped-token> twine upload dist/*
```

Use a **project-scoped** token, never an account-scoped one, and never paste it
into a chat or a shared shell that logs to a transcript.
