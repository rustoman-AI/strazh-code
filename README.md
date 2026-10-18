# Strazh

**License: [MIT](./LICENSE)**

Strazh is a desktop app that scans a code repository, builds a supply-chain
attack graph, and asks **NVIDIA Nemotron** (served on **Nebius Token Factory**)
to write a fix for a concrete attack path it found. Built with Tauri + React +
Rust.

It runs as a single screen with one flow:

1. **Point at a repository** — pick any local folder.
2. **Scan it** — Strazh walks the source tree (AST + build files), produces a
   CycloneDX SBOM, and derives attack paths from the graph with a Datalog
   engine (`crepe`).
3. **See one attack path** — entry point → intermediate hops → vulnerable
   target component.
4. **Get a Nemotron-written fix** — the selected attack path is sent to NVIDIA
   Nemotron on Nebius Token Factory, which returns a root-cause summary and a
   concrete code fix.

> Attack paths and SBOM data come from a real scan of the folder you select.
> The fix is generated live by Nemotron — nothing is pre-scripted.

## Where Nebius and Nemotron are used

- **Client:** [`src-tauri/src/nebius_client.rs`](./src-tauri/src/nebius_client.rs)
  talks to the Nebius Token Factory OpenAI-compatible endpoint
  `https://api.tokenfactory.nebius.com/v1` and calls an **NVIDIA Nemotron**
  model (default `nvidia/Nemotron-3_5-Lightning`).
- **Fix generation (the judge flow):** the `generate_nemotron_fix` command in
  [`src-tauri/src/commands.rs`](./src-tauri/src/commands.rs) calls
  `NebiusClient::generate_fix(...)` with the selected attack path.
- **Live proof binary:** [`src-tauri/src/bin/nebius_test.rs`](./src-tauri/src/bin/nebius_test.rs)
  makes one real Nemotron call so you can confirm connectivity.

The API key is read **only** from the `NEBIUS_API_KEY` environment variable. It
is never hardcoded, printed, logged, or committed. The `Authorization` header
is marked sensitive so it is never surfaced in logs.

## Prerequisites

- Node.js 18+ and npm
- Rust (stable) and the [Tauri prerequisites](https://tauri.app/start/prerequisites/)
- A Nebius Token Factory API key

## Setup

```bash
# 1. Install frontend dependencies
npm install

# 2. Provide your Nebius key (never committed)
cp src-tauri/.env.example src-tauri/.env
# then edit src-tauri/.env and set NEBIUS_API_KEY=...
```

Alternatively, export the key in your shell instead of using `.env`:

```bash
# macOS / Linux
export NEBIUS_API_KEY=your-key-here
```

```powershell
# Windows PowerShell
$env:NEBIUS_API_KEY = "your-key-here"
```

Optional overrides:

- `NEBIUS_MODEL` — pick a different Nemotron model id (e.g.
  `nvidia/Nemotron-3-Ultra-550b-a55b`, `nvidia/Nemotron-3.5-Super-VL`).
- `NEBIUS_BASE_URL` — override the Token Factory base URL.

## Prove the live Nemotron call

Run the small proof binary. It makes one real request and prints the model's
reply (it never prints your key):

```bash
cd src-tauri
cargo run --bin nebius_test
```

Expected output ends with `✅ SUCCESS: Nemotron responded via Nebius Token
Factory.` If the default model id is not available on your account, the binary
lists the Nemotron model ids it can see so you can set `NEBIUS_MODEL`.

## Run the app

```bash
npm run tauri dev
```

The React frontend lives in `src/` (single screen: `src/StrazhApp.tsx`). The
Rust backend lives in `src-tauri/`.

## Build

```bash
npm run tauri build
```

## Security notes

- `NEBIUS_API_KEY` is required at runtime and read from the environment only.
- `src-tauri/.env` is gitignored; commit `src-tauri/.env.example` instead.
- No telemetry. The only outbound network call is to Nebius Token Factory for
  inference.

## License

[MIT](./LICENSE)
