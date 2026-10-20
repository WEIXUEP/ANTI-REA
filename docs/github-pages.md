# Publish Documentation on GitHub Pages

English | [简体中文](github-pages.zh-CN.md)

The repository includes a MkDocs Material site and a GitHub Actions workflow.
No C++ compiler, libsodium or xollvm installation is required to build the site.

Repository: <https://github.com/WEIXUEP/ANTI-REA>.
Documentation URL: <https://weixuep.github.io/ANTI-REA/>.

## Preview Locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-docs.txt
python -m mkdocs serve --dev-addr 127.0.0.1:8000
```

Open `http://127.0.0.1:8000/`. MkDocs reloads the site when documentation changes.
Run a production-style check with:

```bash
python -m unittest discover -s tests -p test_docs.py -v
python -m mkdocs build --strict
```

Output is generated under `build/site`, which is ignored by Git. Link and
navigation warnings fail the strict build. Keep generated HTML out of the source
branch; deployment uses an Actions artifact rather than a committed `gh-pages`
branch.

## Enable Pages Once

1. Push the repository, including the documentation workflow, to GitHub.
2. Open **Settings > Pages > Build and deployment**.
3. Select **GitHub Actions** as the source. If the option is unavailable, check
   repository visibility, account plan and organization policy with an administrator.
4. Push a documentation change to `main`, or run the **Documentation** workflow
   manually from **Actions** on `main`.
5. Open the deployment URL shown in the workflow's `github-pages` environment
   or the repository's Pages settings.

For an ordinary project repository, the address has this shape:

```text
https://<owner>.github.io/<repository>/
```

The workflow derives the owner and repository name from GitHub metadata; the
local configuration defaults to the repository linked above. Publishing requires a real
remote repository and the Pages setting above. Local tests do not prove that a
remote deployment has completed.

Repository administrators can also enable the Actions publishing source with the
GitHub CLI, using their existing authenticated account:

```bash
# One-time setup for a repository without a Pages site.
gh api --method POST repos/OWNER/REPOSITORY/pages -f build_type=workflow

# Check that the publishing source is GitHub Actions.
gh api repos/OWNER/REPOSITORY/pages --jq '.build_type'
```

For an existing Pages site, use `--method PUT` instead of `--method POST` to
change its publishing source. The expected `build_type` is `workflow`.

The workflow's ordinary `GITHUB_TOKEN` can deploy an enabled site, but cannot
perform this initial enablement. Adding `enablement: true` to `configure-pages`
alone does not fix a missing site: that option requires a separate token with
administrative permissions. Enable Pages once through the settings or API above;
no additional token or repository secret is needed for routine deployment.

## Deployment Behavior

Pull requests build and validate the documentation without deployment permissions.
On matching pushes to `main`, the build uploads `build/site`; the separate deploy
job requests only Pages and OIDC permissions and publishes the artifact. Manual
runs deploy only when executed on `main`. Existing deployment jobs are not
cancelled mid-release.

The documentation workflow uses Node.js 24 actions, including the Pages artifact
uploader's nested upload action. It runs on GitHub-hosted Ubuntu runners; upgrading
only checkout or Python setup would leave the older Pages actions' Node.js 20
deprecation warnings unresolved.

The workflow is filtered to documentation, skill, site-hook, configuration and
documentation-test changes. A source-only C++ change does not rebuild the site
unless its documentation changes too.

For a custom domain or a nonstandard Pages URL, set the Actions repository
variable `ANTI_REA_SITE_URL` to the full public base URL, including a trailing
slash. Configure the domain and DNS in GitHub Pages separately. Use the same
environment variable for a local production build when checking canonical URLs.

## Publication Boundaries

The site includes `docs/`, reviewed measurement summaries and two generated skill
downloads (read-only detection and protection guidance). The site hook explicitly allowlists each package's public files and
includes their project license. It
does not walk private or build directories. Canonical skill Markdown is rendered
at build time, so rule changes do not require updating a second documentation copy.

Do not place raw audit findings, private diagnostic maps, keys, IR, PDBs or native
release packages under `docs/`. Every file placed there can become public even
if it is absent from the navigation. Review measurement JSON before publication.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `configure-pages` returns `HttpError: Not Found` | Enable Pages once and select GitHub Actions as its source; check administrator access and organization policy |
| Pages returns 404 | Wait for successful deployment, verify the exact environment URL and include the repository path |
| Broken navigation after a move | Run `mkdocs build --strict` and update the Markdown link target |
| An unexpected address appears in canonical links | Check `ANTI_REA_SITE_URL`, especially when publishing a fork |
| Skill changes are missing locally | Rebuild or restart `mkdocs serve`; the skill lives outside `docs/` |
| A deploy job waits for approval | Review the repository's `github-pages` environment protection rules |
