<img src="./public/strazh-logo.png" alt="Strazh" width="200" />

# Strazh — Repository Security Scanner

**License: [MIT](./LICENSE)**

Strazh is a desktop app (Tauri + React + Rust) that inspects a **local
repository's declared dependencies** for known vulnerabilities and helps you
understand and remediate them. It:

- scans a local repository and reads the dependencies **declared in its
  manifests** (e.g. `Cargo.toml`, `package.json`, `requirements.txt`,
  `pyproject.toml`);
- matches each declared package + version against the **[OSV](https://osv.dev)**
  advisory database;
- shows, for a selected finding, the **manifest → package → advisory**
  relationship and, when the advisory provides one, an **advisory-reported
  fixed version**;
- generates **advisory-based remediation guidance** with an **NVIDIA Nemotron**
  model served through **[Nebius Token Factory](https://nebius.com)**.

> **Scope of the analysis.** A finding means a declared dependency matches an
> OSV advisory for the scanned version. This is a **declaration-based
> relationship** — it shows that the vulnerable package is declared/available,
> **not** that the vulnerable code is reached at runtime or is exploitable in
> your application. Strazh does not perform reachability or exploitability
> analysis.

Strazh does **not** modify your repository, does **not** apply patches, and the
AI guidance is **not** a verified or tested fix. "Advisory-reported fix"
versions come from OSV, not from Strazh verifying your project.

## Screenshots

Captured from the running release build. The personal repository path shown in
the sidebar has been redacted to `demo-cookbook`; findings and generated output
are unaltered.

**Welcome / repository selection**

![Strazh welcome screen: empty state prompting the user to choose a local repository to scan](./docs/screenshots/welcome.png)

**Completed scan with severity summary and a selected finding**

![Strazh scan results for the demo-cookbook repository: 913 OSV advisories with a severity summary (15 Critical, 178 High, 226 Medium, 69 Low, 425 Unknown), the agno@1.7.2 GHSA-77rh-m34w-rv36 Critical finding selected, its advisory-reported fix 2.3.24, and the manifest-to-package-to-advisory relationship](./docs/screenshots/scan-findings.png)

**Generated AI remediation guidance**

![Strazh AI remediation for the agno Eval Injection advisory: an Advisory section restating the issue and a Recommended remediation section advising an upgrade to version 2.3.24 with a note to test compatibility](./docs/screenshots/ai-remediation.png)

## Quick start (Windows)

### Install and launch

1. Build the installer locally (see [Development](#development)) or use an
   existing artifact from `src-tauri/target/release/bundle/` (see
   [Release](#release)).
2. Run the NSIS setup (`Strazh_<version>_x64-setup.exe`) or the MSI
   (`Strazh_<version>_x64_en-US.msi`) and follow the prompts, or run the
   portable executable `cyclonedx-tauri-ui.exe` directly.
3. Launch **Strazh — Repository Security Scanner** from the Start menu (or the
   executable).

**WebView2 runtime.** The UI renders in Microsoft Edge WebView2, which is
preinstalled on current Windows 10/11. The bundle does not pin a custom
WebView2 install mode, so Tauri's default behavior applies: if the runtime is
missing, the NSIS installer offers to download and install it. No bundled
offline WebView2 installer is included.

### What needs network or a key

- **Repository scanning works without a Nebius key.** However, matching
  dependencies against OSV requires **network access** to `https://api.osv.dev`.
- **AI remediation guidance requires a Nebius credential and network access**
  to Nebius Token Factory.

### Configuring the Nebius credential

Strazh reads the key `NEBIUS_API_KEY` at **startup**, in this exact order (from
`src-tauri/src/lib.rs`, `load_local_env`):

1. **Process environment** — if `NEBIUS_API_KEY` is already set in the
   environment, that value is used and nothing below overrides it.
2. **Development only** — in development builds (`cargo`/`npm run tauri dev`,
   i.e. `debug_assertions` on), a `.env` in the current working directory is
   loaded. This does **not** apply to the packaged app.
3. **Per-user config file (all builds)** — exactly one file:

   ```
   %APPDATA%\com.strazh.app\.env
   ```

   containing:

   ```
   NEBIUS_API_KEY=your_key_here
   ```

This file **stores the credential locally on disk** in your user profile. It is
**outside the installer** and is never bundled into the app. There is **no**
directory-walking or repository `.env` discovery — only the locations above are
consulted. After creating or changing this file, **restart the app**; a running
instance does not pick up configuration changes.

> Development configuration note: the repository ships
> `src-tauri/.env.example`. For local development you may copy it to
> `src-tauri/.env` and run from `src-tauri/` (step 2 above). The packaged app
> does **not** read `src-tauri/.env` — use the `%APPDATA%\com.strazh.app\.env`
> location instead.

Optional overrides (environment variable or the same `.env`):

- `NEBIUS_MODEL` — Nemotron model id (default `nvidia/Nemotron-3_5-Lightning`).
- `NEBIUS_BASE_URL` — Token Factory base URL (default
  `https://api.tokenfactory.nebius.com/v1`).

## Usage

1. **Choose repository** — pick a local folder.
2. **Run scan** — Strazh reads declared dependencies and queries OSV. Files,
   lines, and dependency counts populate as the scan progresses; the advisory
   count appears when the OSV lookup completes.
3. **Filter findings** — search by package or advisory id, and filter by
   severity. A severity summary (Critical / High / Medium / Low / Unknown) is
   shown above the list.
4. **Select an advisory** — the detail pane shows the package, advisory id,
   severity, and the advisory summary when provided.
5. **Inspect the declaring manifest** — the relationship graph shows
   **manifest → package → advisory**. The manifest is the file that declares
   the dependency (evidence from the scan). This indicates declaration, not
   runtime reachability.
6. **Generate guidance** — request AI remediation for the selected finding.

Notes on interpreting results:

- **Severity "Unknown"** means OSV did not provide a severity Strazh could
  classify (for example, only a CVSS vector string with no numeric score). It
  does not mean "safe."
- **Advisory-reported fix version** is taken from the OSV advisory for the
  scanned version. It indicates an available upgrade target, **not** proof that
  your project is secure. When applicability cannot be determined, the UI shows
  **"Fix version not determined."** Always review version compatibility and
  test upgrades before relying on them.
- **Advisory counts** reflect advisory records, not proven exploitable paths.
  The same advisory can appear more than once when a package is declared at
  different versions or in different manifests; Strazh de-duplicates only the
  identical `(name, version, ecosystem)` tuple before querying OSV.

## Development

Prerequisites:

- Node.js 18+ and npm
- Rust (stable) and the
  [Tauri v2 prerequisites](https://tauri.app/start/prerequisites/) (on Windows:
  the MSVC toolchain and WebView2)

Commands (verified against `package.json` and `src-tauri/Cargo.toml`):

```bash
# Install frontend dependencies
npm install

# Run the app in development (frontend + Rust backend, hot reload)
npm run tauri dev

# Frontend production build + TypeScript typecheck
npm run build        # runs: tsc && vite build

# Frontend behavior tests (Vitest + Testing Library + jsdom)
npm run test         # runs: vitest run

# Backend compile check
cargo check --lib --manifest-path src-tauri/Cargo.toml

# Build the Windows release + installers (MSI and NSIS)
npm run tauri build
```

### Architecture

- **Frontend (`src/`)** — a single-screen React 19 UI. `src/StrazhApp.tsx`
  drives the flow; `src/Markdown.tsx` is a small, dependency-free Markdown
  renderer used for AI output (no raw HTML / no `dangerouslySetInnerHTML`, with
  a copy-to-clipboard control for code blocks).
- **Shell (`src-tauri/`)** — Tauri v2 wraps the web UI in a native window and
  exposes Rust commands over the Tauri bridge.
- **Scanning (Rust)** — `src-tauri/src/supply_chain.rs` walks the repository and
  parses declared dependencies from manifests; `src-tauri/src/commands.rs`
  (`scan_code_graph`, `scan_with_osv`) runs the scan.
- **OSV (Rust)** — `src-tauri/src/osv_client.rs` queries the OSV API and
  extracts advisory severity and the applicable fixed version (ecosystem-aware
  version comparison; never lexical).
- **AI (Rust)** — `src-tauri/src/nebius_client.rs` calls an NVIDIA Nemotron
  model (default `nvidia/Nemotron-3_5-Lightning`) on the Nebius Token Factory
  OpenAI-compatible endpoint; `generate_nemotron_fix` in `commands.rs` builds
  the request from advisory evidence.

### Tests and a known limitation

- **Frontend:** `npm run test` runs Vitest suites in `src/*.test.tsx` covering
  AI-response isolation across finding selection and rescans, duplicate-submit
  prevention, exact clipboard copy, and the fixed-version / "not determined"
  display.
- **Backend:** the Rust regression suite for OSV fixed-version matching and the
  credential-loader scoping is run via a standalone binary:

  ```bash
  cargo run --bin osv_tests --manifest-path src-tauri/Cargo.toml
  ```

  This harness exists because `cargo test --lib` does not start on this
  Tauri/Windows library crate (the test executable fails to load with
  `STATUS_ENTRYPOINT_NOT_FOUND`). The same assertions also exist as
  `#[cfg(test)]` modules for environments where the standard harness works.

- **Connectivity check:** `cargo run --bin nebius_test --manifest-path src-tauri/Cargo.toml`
  sends one request to confirm the Nebius credential and model are reachable
  (requires `NEBIUS_API_KEY`). It never prints the key.

## Data handling and limitations

Based on the current code:

- **Stays local:** the repository contents, the parsed manifest/dependency
  list, scan metrics, and your selection. Strazh does not upload repository
  source code.
- **Sent to OSV (`https://api.osv.dev/v1/query`):** for each declared
  dependency with a concrete version, the **package name, ecosystem, and
  version** are sent to look up advisories.
- **Sent to Nebius (only when you click Generate):** the **advisory id and
  summary, the declared component (`name@version`), the ecosystem, the
  declaring manifest path, and the advisory-reported fixed version** (when
  present). Dependency **source code is not fetched or sent** — the remediation
  prompt explicitly states source is unavailable, so guidance is advisory-based
  rather than a source-level patch.
- **Repository files are not modified.** Generating guidance never writes to
  your project; there is no auto-patching.

Analysis limitations:

- Findings are **declaration-based**; Strazh does not prove runtime reachability
  or exploitability.
- Dependencies without a concrete, resolvable version are **not queried**
  (Strazh does not guess a version).
- Severity may be **Unknown** when OSV does not provide a classifiable severity.
- The AI remediation is **AI-generated guidance, not a tested repository
  patch**; review and test before applying anything.

This section describes current behavior and is not a privacy guarantee.

## Release

Strazh is built locally; there is no hosted release in this repository. Build
the Windows artifacts with `npm run tauri build`. They are written to:

```
src-tauri/target/release/bundle/msi/Strazh_0.1.0_x64_en-US.msi
src-tauri/target/release/bundle/nsis/Strazh_0.1.0_x64-setup.exe
src-tauri/target/release/cyclonedx-tauri-ui.exe
```

SHA-256 of the installers from the most recent local build on this machine
(recompute after your own build — hashes change per build):

| Artifact | SHA-256 |
|---|---|
| `Strazh_0.1.0_x64_en-US.msi` | `29BFEBE9B84A1CF87B61A09B85F9D53155727F626BFBC02F5479E96616C5FC09` |
| `Strazh_0.1.0_x64-setup.exe` | `4873AB7B8F3A297C390A3BE92A873B13152D96A9A8E6305614EE0139B2213798` |

Recompute with:

```powershell
Get-FileHash .\src-tauri\target\release\bundle\msi\Strazh_0.1.0_x64_en-US.msi -Algorithm SHA256
```

The installers and executable contain no API keys or `.env` contents; the
credential lives only in your per-user config file described above.

## License

[MIT](./LICENSE)
