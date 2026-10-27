# Reddit post — r/devops / r/netsec

Suggested subreddits: r/devops, r/netsec, r/rust (Tauri angle), r/opensource.
Read each sub's self-promotion rules before posting. Post as a text (self) post.
Reply to comments; don't drive-by drop a link.

---

**Title options (pick one):**

- I built a local desktop app that scans your repo's dependencies against OSV and suggests + applies the fix
- Strazh: find supply-chain CVEs in your deps and apply the version bump locally (no cloud, no account)

---

**Body:**

Like a lot of you, I don't always have a security team to wait on, and `npm audit` /
scattered CVE emails don't tell me *which manifest* declared the vulnerable thing or
*what to bump it to*. So I built a small desktop tool to close that loop.

**Strazh** is a local Tauri (Rust + React) app. The flow is:

1. **Scan** — it reads the dependencies declared in your manifests (`package.json`,
   `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `go.mod`) and queries the live
   **OSV** database for known advisories.
2. **Attack path** — for each finding it shows the manifest → package → advisory
   relationship, so you see exactly which file pulled in the vulnerable version.
3. **Suggestion** — it asks an NVIDIA **Nemotron** model (via Nebius Token Factory) for
   remediation guidance grounded in the advisory. It only sends advisory metadata —
   **your source code never leaves your machine.**
4. **Apply** — when the advisory has a fixed version, it rewrites that one dependency's
   version in the declaring manifest, locally, with one-click **Undo**.

**What I'm deliberately NOT claiming:**

- Findings are **declaration-based**. A match means the vulnerable version is declared,
  not that the code path is reachable or exploitable at runtime. No reachability analysis.
- The AI output is **advisory-grounded guidance, not a tested patch**. Review and test
  before shipping it.
- **Apply fix is conservative on purpose.** It handles clean single-version pins and
  simple ranges. If a package appears multiple times or uses a workspace/complex form,
  it refuses and tells you to edit by hand rather than guess.
- **No accounts, no telemetry, no cloud sync, no auto-PRs.** Everything is local. Scanning
  and generating suggestions never write to your project — only the explicit Apply does.

**Pricing:** scanning + findings + attack paths + AI suggestions are **free**. Applying
fixes is a $29/mo (or $249/yr) Pro feature. The license check is fully offline.

Windows installer is up now; macOS/Linux are planned (it's Tauri, so not a big lift).

- Demo (3 min): https://www.youtube.com/watch?v=CFnPRriDur4
- Site + download: https://strazh.dev
- Source: https://github.com/rustoman-AI/strazh-code

Happy to answer anything about the OSV matching, the version-comparison logic (it's
ecosystem-aware, not lexical), or why I kept Apply so conservative. Feedback welcome —
especially on what would make the "apply" step trustworthy enough for you to actually use.
