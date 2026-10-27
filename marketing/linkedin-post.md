# LinkedIn post

Short, scannable version. Put the links in the first comment if you want to avoid
LinkedIn's link-reach penalty, or keep them inline — your call.

---

Most dependency scanners tell you that you have a CVE. They rarely tell you which
manifest declared it or what to bump it to — and then you wait on a security review.

I built **Strazh** to close that loop, locally.

It's a desktop app (Tauri + Rust + React) that:

🔍 Scans your repo's declared dependencies against the live OSV advisory database
🧭 Shows the manifest → package → advisory path for every finding
🤖 Suggests a grounded fix with an NVIDIA Nemotron model on Nebius Token Factory
🔧 Applies the version bump to your manifest locally — with one-click Undo

Built for developers and small teams who want to find and fix supply-chain issues
without waiting on a security review.

A few things I'm keeping honest:
• It runs 100% locally — no accounts, no cloud, no telemetry. Your source never leaves
  your machine; only advisory metadata is sent out.
• Findings are declaration-based, not runtime-reachability proof.
• The AI suggestion is guidance, not a tested patch — review before you ship.
• Apply fix is intentionally conservative: clean, single-version cases only.

Free to scan and get suggestions. Applying fixes is a $29/mo Pro feature.

▶️ Demo: https://www.youtube.com/watch?v=CFnPRriDur4
🌐 Download: https://strazh.dev
💻 Source: https://github.com/rustoman-AI/strazh-code

Would love feedback from folks doing supply-chain / dependency security.

#DevSecOps #SupplyChainSecurity #OpenSource #AppSec
