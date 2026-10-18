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
| `welcome.png` | Welcome / repository-selection screen. |
| `scan-findings.png` | Completed scan: severity summary + selected `agno@1.7.2` finding. |
| `ai-remediation.png` | Live AI remediation guidance for the selected advisory. |

## Redaction

Only the personal absolute filesystem path shown in the sidebar's repository
field was redacted (replaced with `demo-cookbook`) in `scan-findings.png` and
`ai-remediation.png`. No findings, counts, severities, fixed-version values, or
generated text were altered. No API keys or `.env` contents appear in any
capture. `welcome.png` required no redaction (it shows "No repository
selected").
