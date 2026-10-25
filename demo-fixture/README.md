# Strazh demo fixture

This folder is **not a real project** — it contains only dependency manifests,
deliberately pinned to **old, vulnerable versions** that have real advisories
in the [OSV](https://osv.dev) database. It exists so the Strazh "Apply fix"
button can be demonstrated end to end:

1. In Strazh, **Choose repository** → select this `demo-fixture/` folder.
2. **Run scan** — OSV returns advisories for the pinned packages below.
3. Select a Critical/High finding → **Generate suggestion** → **Apply fix**.
   Strazh rewrites the pinned version in the manifest on disk (e.g.
   `agno 1.7.2 → 2.3.24`) and shows a confirmation with an **Undo**.

Pinned packages (chosen because they have real OSV advisories with fixed
versions):

| Manifest | Package | Pinned version |
|---|---|---|
| `pyproject.toml` | `agno` | `1.7.2` |
| `pyproject.toml` | `pillow` | `9.0.0` |
| `package.json` | `lodash` | `4.17.11` |
| `package.json` | `minimist` | `1.2.0` |

Applying a fix edits these files **locally only**. To re-run the demo from a
clean state, revert the files (Strazh's Undo does this immediately after an
apply, or restore them from version control).
