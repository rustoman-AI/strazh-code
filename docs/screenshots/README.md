# Screenshots

These images are referenced by the top-level `README.md`.

## Provenance

Live captures of the **actual running Strazh release build**
(`Strazh — Repository Security Scanner`, from
`src-tauri/target/release/cyclonedx-tauri-ui.exe`), taken on Windows via a
`System.Drawing` `CopyFromScreen` capture of the application window. They are
real application output, not mockups, reconstructions, or edited interfaces.

The repository scanned is the public `nebius/token-factory-cookbook` checkout
used for the demo. The AI remediation was produced by a single live call to
NVIDIA Nemotron on Nebius Token Factory using the locally configured
credential.

| File | State |
|---|---|
| `welcome.png` | Welcome / repository-selection screen (maximized window). |
| `scan-findings.png` | Completed scan of the cookbook checkout: 547 declared dependencies, 913 OSV advisories (15 Critical, 178 High, 226 Medium, 69 Low, 425 Unknown), with the Critical `agno@1.7.2` GHSA-77rh-m34w-rv36 (Eval Injection) finding selected and its advisory-reported fix 2.3.24. |
| `ai-remediation.png` | Live Nemotron remediation guidance for that same advisory (Advisory + Recommended remediation sections). Captured before the local **Apply fix / Undo** controls were added; see the top-level README's "Apply fix" section for current behavior. |

## Relationship to the demo video

`scan-findings.png` and `ai-remediation.png` were captured earlier than the
[demo video](https://www.youtube.com/watch?v=CFnPRriDur4), so their advisory
totals are lower (913 advisories / 15 Critical, `agno` resolving to 1.7.2) than
the demo's later run (1,078 findings / 31 Critical, `agno@1.5.1`). This is
expected: **OSV is a live database that keeps adding advisory records over
time**, so re-scanning the same repository later surfaces more advisories. The
declared-dependency count (547), the vulnerability (GHSA-77rh-m34w-rv36, Eval
Injection), and the advisory-reported fix (2.3.24) are identical across both.

## Redaction

Only the personal absolute filesystem path shown in the sidebar's repository
field was redacted (replaced with `demo-cookbook`) in `scan-findings.png` and
`ai-remediation.png`. No findings, counts, severities, fixed-version values, or
generated text were altered. No API keys or `.env` contents appear in any
capture. `welcome.png` required no redaction (it shows "No repository
selected").
