import { useState, useCallback, useMemo, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { open } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Markdown } from "./Markdown";
import "./App.css";

// Public product links, surfaced in the About dialog and first-run welcome.
const LINKS = {
  site: "https://strazh.dev",
  repo: "https://github.com/rustoman-AI/strazh-code",
  releases: "https://github.com/rustoman-AI/strazh-code/releases",
  latestRelease: "https://github.com/rustoman-AI/strazh-code/releases/latest",
  license: "https://github.com/rustoman-AI/strazh-code/blob/main/LICENSE",
};

// localStorage key that records the first-run welcome has been dismissed.
const FIRST_RUN_KEY = "strazh.welcome.seen.v1";

// Open an external URL in the user's default browser. Falls back to a plain
// window.open if the Tauri opener is unavailable (e.g. in the browser test env).
async function openExternal(url: string): Promise<void> {
  try {
    await openUrl(url);
  } catch {
    try { window.open(url, "_blank", "noopener"); } catch { /* ignore */ }
  }
}

// ──────────────────────────────────────────────────────────
//  Types mirrored from the Rust backend (unchanged scan logic)
// ──────────────────────────────────────────────────────────

interface AstStats {
  total_files: number;
  total_lines: number;
  total_imports: number;
  languages: Record<string, number>;
  build_systems: string[];
  declared_deps: number;
  internal_imports: number;
  external_imports: number;
}

interface CodeGraphResult {
  source_nodes: { path: string; language: string; lines: number; is_entry: boolean }[];
  import_edges: unknown[];
  build_files: { path: string; build_system: string; declared_deps: unknown[] }[];
  stats: AstStats;
}

// One OSV advisory affecting a declared dependency. NOTE: this is an advisory
// record tied to a dependency/import relationship — not a proven, runtime
// exploitable attack path.
interface OsvPath {
  entry_point: string; // manifest that declares the dependency (evidence)
  target_component: string; // "name@version"
  vulnerability_id: string; // OSV / CVE / GHSA id
  severity: string;
  ecosystem: string;
  summary: string | null;
  fixed_version: string | null; // verified fixed version from the advisory, if any
  proof_chain: string[];
}

interface OsvScanResult {
  exploitation_paths: OsvPath[];
  stats: {
    dependencies_declared: number;
    dependencies_queried: number;
    vulnerable_dependencies: number;
    entry_points: number;
    advisories_found: number;
  };
}

interface NemotronFix {
  model: string;
  fix_markdown: string;
}

type ScanPhase = "idle" | "ready" | "scanning" | "failed" | "done";
type Severity = "critical" | "high" | "medium" | "low" | "unknown";

const MODEL = "nvidia/Nemotron-3_5-Lightning";

// Documented per-user config location for the API key, matching the backend
// loader (per-user app config dir for identifier "com.strazh.app"). Shown to
// the user as the canonical place to store the key for the packaged app.
const CONFIG_ENV_HINT =
  typeof navigator !== "undefined" && /Win/i.test(navigator.platform)
    ? "%APPDATA%\\com.strazh.app\\.env"
    : "<app config dir>/com.strazh.app/.env";

const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", unknown: "Unknown",
};

function basename(p: string): string {
  if (!p) return "";
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] || p;
}

function nf(n: number): string {
  return n.toLocaleString("en-US");
}

function sevKey(s: string): Severity {
  const t = (s || "").toUpperCase();
  if (t === "CRITICAL") return "critical";
  if (t === "HIGH") return "high";
  if (t === "MODERATE" || t === "MEDIUM") return "medium";
  if (t === "LOW") return "low";
  return "unknown";
}

// Recognise the "no API key" backend error so we can show friendly setup help
// instead of a raw environment error with an ineffective Retry.
function isProviderNotConfigured(err: string): boolean {
  const e = (err || "").toUpperCase();
  return e.includes("NEBIUS_API_KEY") || e.includes("NOT SET IN THE ENVIRONMENT");
}

// Split "name@version" safely (version may be absent or contain @ rarely).
function splitComponent(tc: string): { name: string; version: string } {
  const at = tc.lastIndexOf("@");
  if (at > 0) return { name: tc.slice(0, at), version: tc.slice(at + 1) };
  return { name: tc, version: "" };
}

// Ecosystems for which the local Apply-fix command can safely rewrite a
// manifest version. Mirrors apply_manifest_fix in the Rust backend.
const APPLY_SUPPORTED = new Set(["npm", "crates.io", "PyPI", "Go"]);

// A plausible concrete release version (e.g. 1.8.0, 2.3.24, v1.2.3).
const VERSION_RE = /\bv?\d+\.\d+(?:\.\d+)?(?:[.\-+][0-9A-Za-z.\-]+)?\b/;

// Decide the version to upgrade to for a finding + optional Nemotron fix text.
// Prefer the advisory's verified fixed version; otherwise parse a concrete
// version from the model's "Recommended remediation" section, but only accept
// it when it is greater than the currently declared version (a real upgrade).
function resolveUpgradeTarget(
  path: OsvPath,
  fixText: string | null,
): { target: string | null; source: "advisory" | "model" | null } {
  if (path.fixed_version && path.fixed_version.trim()) {
    return { target: path.fixed_version.trim(), source: "advisory" };
  }
  if (fixText) {
    const current = splitComponent(path.target_component).version;
    // Scan candidate versions in the text; take the first that is clearly a
    // higher release than the declared one.
    const re = new RegExp(VERSION_RE, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(fixText)) !== null) {
      const cand = m[0].replace(/^v/, "");
      if (compareVersions(cand, current) > 0) {
        return { target: cand, source: "model" };
      }
    }
  }
  return { target: null, source: null };
}

// Numeric, non-lexical version compare (frontend mirror of the backend rule,
// used only to decide whether a parsed target is a real upgrade).
function compareVersions(a: string, b: string): number {
  const seg = (v: string) =>
    v.replace(/^v/, "").split(/[.\-+]/).map((s) => parseInt(s, 10)).filter((n) => !Number.isNaN(n));
  const as = seg(a), bs = seg(b);
  const n = Math.max(as.length, bs.length);
  for (let i = 0; i < n; i++) {
    const x = as[i] ?? 0, y = bs[i] ?? 0;
    if (x !== y) return x - y;
  }
  return 0;
}

interface ApplyFixResult {
  applied: boolean;
  manifest: string;
  package: string;
  from_version: string;
  to_version: string;
  message: string;
  original_content: string;
}

// Mirrors crate::license::LicenseStatus (Rust). Apply fix is Pro-only.
interface LicenseStatus {
  pro: boolean;
  plan: string; // "none" | "pro" | "invalid" | "expired"
  name: string;
  exp: number; // unix seconds, 0 = perpetual
  message: string;
}

const PRICING_URL = `${LINKS.site}/#pricing`;

export default function StrazhApp() {
  const [repoPath, setRepoPath] = useState<string>("");
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [scanError, setScanError] = useState<string>("");

  const [code, setCode] = useState<CodeGraphResult | null>(null);
  const [osv, setOsv] = useState<OsvScanResult | null>(null);

  const [selectedId, setSelectedId] = useState<number | null>(null);

  // Findings filters
  const [query, setQuery] = useState<string>("");
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");

  // AI remediation — isolated per selected finding
  const [fix, setFix] = useState<NemotronFix | null>(null);
  const [fixState, setFixState] = useState<"idle" | "loading" | "error" | "done">("idle");
  const [fixError, setFixError] = useState<string>("");
  // monotonically increasing token; a response is only accepted if it matches
  // the request issued for the still-selected finding.
  const fixReq = useRef(0);

  // Local "Apply fix" state, isolated per selected finding.
  const [applyState, setApplyState] = useState<"idle" | "applying" | "done" | "error" | "reverted">("idle");
  const [applyMsg, setApplyMsg] = useState<string>("");
  // Original manifest text + path captured before an apply, for Undo.
  const [applyUndo, setApplyUndo] = useState<{ manifest: string; original: string } | null>(null);

  // App version (from tauri.conf.json via the Tauri app API) and the two
  // dialogs for public polish: a one-time first-run welcome and an About box.
  const [appVersion, setAppVersion] = useState<string>("");
  const [showAbout, setShowAbout] = useState<boolean>(false);
  const [showWelcome, setShowWelcome] = useState<boolean>(false);

  // Pro license status (validated locally in Rust). Apply fix is Pro-only.
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const isPro = license?.pro === true;
  // Shown when a Free user tries to Apply.
  const [showUpgrade, setShowUpgrade] = useState<boolean>(false);

  const refreshLicense = useCallback(async () => {
    try {
      const s = await invoke<LicenseStatus>("license_status");
      setLicense(s);
      return s;
    } catch {
      // If the command is unavailable (e.g. not a Tauri runtime), treat as Free.
      const free: LicenseStatus = { pro: false, plan: "none", name: "", exp: 0, message: "Free plan." };
      setLicense(free);
      return free;
    }
  }, []);

  useEffect(() => {
    // Resolve the version for the header chip + About dialog.
    getVersion().then(setAppVersion).catch(() => setAppVersion(""));
    // Resolve the Pro license status.
    refreshLicense();
    // Show the welcome once per machine (until localStorage is cleared).
    try {
      if (!localStorage.getItem(FIRST_RUN_KEY)) setShowWelcome(true);
    } catch {
      /* localStorage unavailable — skip the welcome rather than block the app */
    }
  }, [refreshLicense]);

  const dismissWelcome = useCallback(() => {
    setShowWelcome(false);
    try { localStorage.setItem(FIRST_RUN_KEY, "1"); } catch { /* ignore */ }
  }, []);

  const paths = osv?.exploitation_paths ?? [];
  const selected = selectedId !== null ? paths[selectedId] ?? null : null;

  // Reset AI output + apply state whenever the selected finding changes.
  useEffect(() => {
    fixReq.current += 1; // invalidate any in-flight request
    setFix(null);
    setFixState("idle");
    setFixError("");
    setApplyState("idle");
    setApplyMsg("");
    setApplyUndo(null);
  }, [selectedId]);

  const pickRepo = useCallback(async () => {
    setScanError("");
    const dir = await open({ directory: true, multiple: false, title: "Select a repository to scan" });
    if (typeof dir === "string") {
      setRepoPath(dir);
      setCode(null);
      setOsv(null);
      setSelectedId(null);
      setPhase("ready");
    }
  }, []);

  const scan = useCallback(async () => {
    if (!repoPath || phase === "scanning") return;
    setPhase("scanning");
    setScanError("");
    setSelectedId(null);
    setOsv(null);
    try {
      const codeRes = await invoke<CodeGraphResult>("scan_code_graph", { rootDir: repoPath });
      setCode(codeRes);
      // Real OSV-backed scan — grounded in the repo's own manifests.
      const res = await invoke<OsvScanResult>("scan_with_osv", { rootDir: repoPath });
      setOsv(res);
      setSelectedId(res.exploitation_paths.length > 0 ? 0 : null);
      setPhase("done");
    } catch (e) {
      setScanError(String(e));
      setPhase("failed");
    }
  }, [repoPath, phase]);

  const generateFix = useCallback(async () => {
    if (!selected || fixState === "loading") return;
    const req = ++fixReq.current;
    const forId = selectedId;
    setFixState("loading");
    setFix(null);
    setFixError("");
    try {
      const res = await invoke<NemotronFix>("generate_nemotron_fix", {
        vulnId: selected.vulnerability_id,
        advisorySummary: selected.summary,
        targetComponent: selected.target_component,
        ecosystem: selected.ecosystem,
        manifest: selected.entry_point,
        fixedVersion: selected.fixed_version,
        // Dependency source is not fetched by the scanner, so none is supplied.
        // The backend prompt therefore produces advisory-based guidance only.
        sourceExcerpt: null,
      });
      // Ignore if the selection moved on or a newer request superseded this one.
      if (req !== fixReq.current || forId !== selectedId) return;
      setFix(res);
      setFixState("done");
    } catch (e) {
      if (req !== fixReq.current || forId !== selectedId) return;
      setFixError(String(e));
      setFixState("error");
    }
  }, [selected, selectedId, fixState]);

  // Apply the resolved upgrade to the declaring manifest, locally.
  const applyFix = useCallback(async () => {
    if (!selected || !repoPath || applyState === "applying") return;
    const { version: current } = splitComponent(selected.target_component);
    const { target } = resolveUpgradeTarget(selected, fix?.fix_markdown ?? null);
    if (!target) return;
    // Apply fix is a Pro feature. Free users get the upgrade prompt instead of
    // a write. (The backend enforces this too, as defense in depth.)
    if (!isPro) {
      setShowUpgrade(true);
      return;
    }
    const pkg = splitComponent(selected.target_component).name;
    setApplyState("applying");
    setApplyMsg("");
    try {
      const res = await invoke<ApplyFixResult>("apply_manifest_fix", {
        repoRoot: repoPath,
        manifestRelPath: selected.entry_point,
        ecosystem: selected.ecosystem,
        package: pkg,
        fromVersion: current,
        toVersion: target,
      });
      setApplyMsg(res.message);
      setApplyState(res.applied ? "done" : "error");
      if (res.applied) {
        setApplyUndo({ manifest: selected.entry_point, original: res.original_content });
      }
    } catch (e) {
      setApplyMsg(String(e));
      setApplyState("error");
    }
  }, [selected, repoPath, fix, applyState, isPro]);

  // Undo the last apply by restoring the original manifest text.
  const undoFix = useCallback(async () => {
    if (!repoPath || !applyUndo) return;
    try {
      const msg = await invoke<string>("revert_manifest", {
        repoRoot: repoPath,
        manifestRelPath: applyUndo.manifest,
        originalContent: applyUndo.original,
      });
      setApplyMsg(msg);
      setApplyState("reverted");
      setApplyUndo(null);
    } catch (e) {
      setApplyMsg(String(e));
      setApplyState("error");
    }
  }, [repoPath, applyUndo]);

  const languages = useMemo(() => {
    if (!code) return [] as [string, number][];
    return Object.entries(code.stats.languages).sort((a, b) => b[1] - a[1]);
  }, [code]);

  // Severity totals derived from the real data.
  const sevTotals = useMemo(() => {
    const t: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    for (const p of paths) t[sevKey(p.severity)] += 1;
    return t;
  }, [paths]);

  // Count findings per package name (simple blast-radius proxy).
  const pkgCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const p of paths) {
      const name = splitComponent(p.target_component).name;
      m.set(name, (m.get(name) ?? 0) + 1);
    }
    return m;
  }, [paths]);

  // Top recommended actions: rank by severity, then by shared-package count.
  // Keeps the original index so clicking selects the same path as the list.
  const recommended = useMemo(() => {
    return paths
      .map((p, i) => {
        const name = splitComponent(p.target_component).name;
        return { p, i, name, shared: (pkgCounts.get(name) ?? 1) - 1 };
      })
      .sort((a, b) => {
        const s = SEV_ORDER[sevKey(a.p.severity)] - SEV_ORDER[sevKey(b.p.severity)];
        if (s !== 0) return s;
        return b.shared - a.shared;
      })
      .slice(0, 5);
  }, [paths, pkgCounts]);

  // Filtered + severity-sorted findings (keep index into original array).
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const rows = paths
      .map((p, i) => ({ p, i }))
      .filter(({ p }) => {
        if (sevFilter !== "all" && sevKey(p.severity) !== sevFilter) return false;
        if (!q) return true;
        return (
          p.target_component.toLowerCase().includes(q) ||
          p.vulnerability_id.toLowerCase().includes(q) ||
          (p.summary ?? "").toLowerCase().includes(q)
        );
      });
    rows.sort((a, b) => SEV_ORDER[sevKey(a.p.severity)] - SEV_ORDER[sevKey(b.p.severity)]);
    return rows;
  }, [paths, query, sevFilter]);

  const VISIBLE_CAP = 200;
  const visible = filtered.slice(0, VISIBLE_CAP);

  const repoName = basename(repoPath);
  const statusLabel =
    phase === "idle" ? "No repository" :
    phase === "ready" ? "Ready to scan" :
    phase === "scanning" ? "Scanning…" :
    phase === "failed" ? "Scan failed" :
    osv && paths.length > 0 ? `${nf(paths.length)} advisories` :
    "No advisories";

  // Code metrics (files/lines/deps) are available as soon as the AST scan
  // returns — even while the OSV step is still running. Advisories only once
  // the OSV scan completes.
  const codeMetricsAvailable = !!code;
  const advisoriesAvailable = phase === "done" && !!osv;

  // Keyboard selection within the findings list.
  const onListKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (visible.length === 0) return;
    const curPos = visible.findIndex((r) => r.i === selectedId);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = curPos < 0 ? 0 : Math.min(curPos + 1, visible.length - 1);
      setSelectedId(visible[next].i);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const prev = curPos < 0 ? 0 : Math.max(curPos - 1, 0);
      setSelectedId(visible[prev].i);
    }
  }, [visible, selectedId]);

  return (
    <div className="sz-root">
      {/* ── Header ── */}
      <header className="sz-header">
        <div className="sz-brand">
          <img className="sz-emblem" src="/strazh-logo.png" alt="Strazh" />
          <span className="sz-wordmark">STRAZH</span>
        </div>
        <div className="sz-head-right">
          <div className="sz-repo-status">
            {repoName && (
              <span className="sz-repo-name" title={repoPath || undefined}>
                {repoName}
              </span>
            )}
            <span className={`sz-status sz-status-${phase}`}>
              <span className="sz-status-dot" aria-hidden="true" />
              {statusLabel}
            </span>
          </div>
          <span className="sz-model-badge" title={`Model: ${MODEL}`}>
            Nemotron
          </span>
          {license && (
            <button
              className={`sz-plan-badge sz-plan-btn ${isPro ? "pro" : "free"}`}
              onClick={() => setShowAbout(true)}
              title={isPro ? "Strazh Pro — manage license" : "Free plan — click to upgrade or enter a key"}
            >
              {isPro ? "PRO" : "FREE"}
            </button>
          )}
          {appVersion && (
            <span className="sz-ver-chip" title={`Strazh version ${appVersion}`}>v{appVersion}</span>
          )}
          <button
            className="sz-iconbtn"
            onClick={() => setShowAbout(true)}
            title="About Strazh"
            aria-label="About Strazh"
          >
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="16" x2="12" y2="12" />
              <line x1="12" y1="8" x2="12.01" y2="8" />
            </svg>
          </button>
        </div>
      </header>

      <div className="sz-body">
        {/* ── Sidebar ── */}
        <aside className="sz-sidebar">
          <div className="sz-side-section">
            <h2 className="sz-side-title">Repository</h2>
            <button className="sz-btn sz-btn-block" onClick={pickRepo}>Choose repository</button>
            <div className="sz-repo-path" tabIndex={0} title={repoPath || "No repository selected"}>
              {repoPath || "No repository selected"}
            </div>
          </div>

          <button
            className="sz-btn sz-btn-primary sz-btn-block sz-btn-run"
            onClick={scan}
            disabled={!repoPath || phase === "scanning"}
            title={!repoPath ? "Choose a repository first" : undefined}
          >
            {phase === "scanning" ? "Scanning…" : "Run scan"}
          </button>
          {!repoPath && <p className="sz-hint">Choose a repository to enable scanning.</p>}

          <div className="sz-metrics" role="group" aria-label="Scan metrics">
            <Metric label="Files" value={codeMetricsAvailable ? nf(code!.stats.total_files) : null} />
            <Metric label="Lines" value={codeMetricsAvailable ? nf(code!.stats.total_lines) : null} />
            <Metric label="Dependencies" value={codeMetricsAvailable ? nf(code!.stats.declared_deps) : null} />
            <Metric
              label="Advisories"
              value={advisoriesAvailable ? nf(paths.length) : null}
              accent={advisoriesAvailable && paths.length > 0}
            />
          </div>

          {languages.length > 0 && (
            <div className="sz-side-section">
              <h2 className="sz-side-title">Languages</h2>
              <div className="sz-langs">
                {languages.map(([lang, n]) => (
                  <span key={lang} className="sz-lang">{lang}<b>{nf(n)}</b></span>
                ))}
              </div>
            </div>
          )}
        </aside>

        {/* ── Main ── */}
        <main className="sz-main">
          {/* State 1: no repo — onboarding */}
          {phase === "idle" && (
            <div className="sz-onboard">
              <div className="sz-onboard-card">
                <img className="sz-onboard-logo" src="/strazh-logo.png" alt="Strazh" />
                <h1 className="sz-onboard-title">Scan a repository for dependency risks</h1>
                <p className="sz-onboard-sub">
                  Choose a local repository to inspect its declared dependencies and explore
                  advisories reported by the OSV database.
                </p>
                <button className="sz-btn sz-btn-primary" onClick={pickRepo}>Choose repository</button>
              </div>
            </div>
          )}

          {/* State 2: ready */}
          {phase === "ready" && (
            <div className="sz-onboard">
              <div className="sz-onboard-card">
                <h1 className="sz-onboard-title">Ready to scan</h1>
                <p className="sz-onboard-sub">
                  <span className="sz-mono">{repoName}</span> is selected. Run a scan to query OSV for
                  advisories affecting the dependencies declared in its manifests.
                </p>
                <button className="sz-btn sz-btn-primary" onClick={scan}>Run scan</button>
              </div>
            </div>
          )}

          {/* State 3: scanning */}
          {phase === "scanning" && (
            <div className="sz-onboard">
              <div className="sz-onboard-card">
                <h1 className="sz-onboard-title">Scanning {repoName}</h1>
                <p className="sz-onboard-sub">
                  Querying OSV for{code ? ` ${nf(code.stats.declared_deps)} declared ` : " "}dependencies…
                </p>
                <div className="sz-bar" role="progressbar" aria-label="Scanning"><div className="sz-bar-fill" /></div>
              </div>
            </div>
          )}

          {/* State 4: scan failed */}
          {phase === "failed" && (
            <div className="sz-onboard">
              <div className="sz-onboard-card">
                <h1 className="sz-onboard-title">Scan couldn't finish</h1>
                <p className="sz-onboard-sub">
                  Strazh couldn't complete the scan of <span className="sz-mono">{repoName}</span>.
                  Matching dependencies against OSV needs network access to{" "}
                  <span className="sz-mono">api.osv.dev</span> — check your connection, confirm the
                  folder is a readable repository, and try again.
                </p>
                <details className="sz-err-details">
                  <summary>Technical details</summary>
                  <p className="sz-error-text">{scanError}</p>
                </details>
                <button className="sz-btn sz-btn-primary" onClick={scan}>Retry scan</button>
              </div>
            </div>
          )}

          {/* State 5: done, no findings */}
          {phase === "done" && paths.length === 0 && (
            <div className="sz-onboard">
              <div className="sz-onboard-card">
                <h1 className="sz-onboard-title">No advisories found</h1>
                <p className="sz-onboard-sub">
                  Scanned <span className="sz-mono">{repoName}</span> —
                  {osv ? ` ${nf(osv.stats.dependencies_queried)} of ${nf(osv.stats.dependencies_declared)} ` : " "}
                  declared dependencies had a concrete version to query against OSV, and none returned a
                  current advisory.
                </p>
              </div>
            </div>
          )}

          {/* State 6+: done with findings — two-column workspace */}
          {phase === "done" && paths.length > 0 && (
            <div className="sz-workspace">
              {/* Left: findings */}
              <section className="sz-findings" aria-label="Findings">
                <div className="sz-findings-head">
                  <h2 className="sz-h2">
                    Findings <span className="sz-count">{nf(filtered.length)}</span>
                  </h2>
                  <p className="sz-findings-note">
                    OSV advisories affecting declared dependencies
                  </p>
                </div>

                {recommended.length > 0 && (
                  <div className="sz-reco" aria-label="Recommended actions">
                    <div className="sz-reco-head">Recommended actions</div>
                    <ul className="sz-reco-list">
                      {recommended.map(({ p, i, shared }) => {
                        const rk = sevKey(p.severity);
                        const reason =
                          `${SEV_LABEL[rk]}` +
                          (shared > 0 ? ` · affects ${shared} other finding${shared === 1 ? "" : "s"} of this package` : "") +
                          (p.fixed_version ? ` · fix ${p.fixed_version}` : "");
                        return (
                          <li key={`reco-${i}`}>
                            <button
                              className={`sz-reco-row ${selectedId === i ? "sz-reco-sel" : ""}`}
                              onClick={() => setSelectedId(i)}
                              title={`Select ${p.target_component} (${p.vulnerability_id})`}
                            >
                              <span className={`sz-badge sev-${rk}`}>{SEV_LABEL[rk]}</span>
                              <span className="sz-reco-pkg sz-mono">{p.target_component}</span>
                              <span className="sz-reco-reason">{reason}</span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                )}

                <div className="sz-sevsum" role="group" aria-label="Severity summary">
                  {(["critical", "high", "medium", "low", "unknown"] as Severity[]).map((s) => (
                    <button
                      key={s}
                      className={`sz-sevsum-item sev-${s} ${sevFilter === s ? "active" : ""}`}
                      onClick={() => setSevFilter(sevFilter === s ? "all" : s)}
                      aria-pressed={sevFilter === s}
                      title={`${SEV_LABEL[s]}: ${sevTotals[s]} — click to ${sevFilter === s ? "clear" : "filter"}`}
                    >
                      <span className="sz-sevsum-n">{nf(sevTotals[s])}</span>
                      <span className="sz-sevsum-l">{SEV_LABEL[s]}</span>
                    </button>
                  ))}
                </div>

                <div className="sz-filters">
                  <input
                    className="sz-input"
                    type="search"
                    placeholder="Search package or advisory…"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    aria-label="Search findings"
                  />
                  <select
                    className="sz-select"
                    value={sevFilter}
                    onChange={(e) => setSevFilter(e.target.value as Severity | "all")}
                    aria-label="Filter by severity"
                  >
                    <option value="all">All severities</option>
                    <option value="critical">Critical ({sevTotals.critical})</option>
                    <option value="high">High ({sevTotals.high})</option>
                    <option value="medium">Medium ({sevTotals.medium})</option>
                    <option value="low">Low ({sevTotals.low})</option>
                    <option value="unknown">Unknown ({sevTotals.unknown})</option>
                  </select>
                </div>

                {filtered.length === 0 ? (
                  <div className="sz-empty-rows">
                    <p>No findings match your filters.</p>
                    <button
                      className="sz-btn sz-btn-sm"
                      onClick={() => { setQuery(""); setSevFilter("all"); }}
                    >
                      Clear filters
                    </button>
                  </div>
                ) : (
                  <ul
                    className="sz-rows"
                    role="listbox"
                    aria-label="Findings"
                    tabIndex={0}
                    onKeyDown={onListKeyDown}
                  >
                    {visible.map(({ p, i }) => {
                      const k = sevKey(p.severity);
                      const { name, version } = splitComponent(p.target_component);
                      const isSel = selectedId === i;
                      return (
                        <li key={i} role="option" aria-selected={isSel}>
                          <button
                            className={`sz-row ${isSel ? "sz-row-sel" : ""}`}
                            onClick={() => setSelectedId(i)}
                          >
                            <span className={`sz-sev-bar sev-${k}`} aria-hidden="true" />
                            <span className="sz-row-main">
                              <span className="sz-row-pkg">
                                {name}
                                {version && <span className="sz-row-ver">@{version}</span>}
                              </span>
                              <span className="sz-row-id">{p.vulnerability_id}</span>
                            </span>
                            <span className={`sz-badge sev-${k}`}>{SEV_LABEL[k]}</span>
                          </button>
                        </li>
                      );
                    })}
                    {filtered.length > VISIBLE_CAP && (
                      <li className="sz-rows-more">
                        Showing {nf(VISIBLE_CAP)} of {nf(filtered.length)} — refine the search to narrow results.
                      </li>
                    )}
                  </ul>
                )}
              </section>

              {/* Right: selected finding detail + AI remediation */}
              <section className="sz-detail" aria-label="Finding details">
                {!selected ? (
                  <div className="sz-detail-empty">Select a finding to see its details.</div>
                ) : (
                  <SelectedFinding
                    path={selected}
                    fix={fix}
                    fixState={fixState}
                    fixError={fixError}
                    onGenerate={generateFix}
                    onApply={applyFix}
                    onUndo={undoFix}
                    applyState={applyState}
                    applyMsg={applyMsg}
                    canUndo={!!applyUndo}
                    isPro={isPro}
                    onUpgrade={() => setShowUpgrade(true)}
                  />
                )}
              </section>
            </div>
          )}
        </main>
      </div>

      {showWelcome && <WelcomeDialog onDismiss={dismissWelcome} configHint={CONFIG_ENV_HINT} />}
      {showAbout && (
        <AboutDialog
          version={appVersion}
          license={license}
          onLicenseChange={setLicense}
          onClose={() => setShowAbout(false)}
        />
      )}
      {showUpgrade && (
        <UpgradeDialog
          onClose={() => setShowUpgrade(false)}
          onEnterKey={() => { setShowUpgrade(false); setShowAbout(true); }}
        />
      )}

      <style>{STYLES}</style>
    </div>
  );
}

// ──────────────────────────────────────────────────────────
//  First-run welcome — one-time, explains the flow + local-only.
// ──────────────────────────────────────────────────────────
function WelcomeDialog({ onDismiss, configHint }: { onDismiss: () => void; configHint: string }) {
  return (
    <div className="sz-modal-overlay" role="dialog" aria-modal="true" aria-label="Welcome to Strazh">
      <div className="sz-modal sz-modal-welcome">
        <div className="sz-modal-brand">
          <img className="sz-modal-logo" src="/strazh-logo.png" alt="Strazh" />
          <h1 className="sz-modal-title">Welcome to Strazh</h1>
          <p className="sz-modal-sub">
            Strazh scans a local repository's declared dependencies for known
            vulnerabilities, then helps you understand and fix them — all on your machine.
          </p>
        </div>

        <ol className="sz-flow">
          <li>
            <span className="sz-flow-num">1</span>
            <div>
              <b>Scan</b>
              <span>Reads your manifests and checks each dependency against the live OSV advisory database.</span>
            </div>
          </li>
          <li>
            <span className="sz-flow-num">2</span>
            <div>
              <b>Attack path</b>
              <span>Shows the manifest → package → advisory relationship for each finding.</span>
            </div>
          </li>
          <li>
            <span className="sz-flow-num">3</span>
            <div>
              <b>Nemotron suggestion</b>
              <span>Generates advisory-grounded remediation guidance with NVIDIA Nemotron on Nebius Token Factory.</span>
            </div>
          </li>
          <li>
            <span className="sz-flow-num">4</span>
            <div>
              <b>Apply &amp; Undo</b>
              <span>Applies a single, conservative version bump to the declaring manifest — reversible with one click.</span>
            </div>
          </li>
        </ol>

        <div className="sz-welcome-note">
          <p>
            <b>Local-only.</b> No accounts, no cloud sync. Your source code never leaves your
            machine — only advisory metadata is sent to OSV and Nemotron.
          </p>
          <p className="sz-welcome-note-dim">
            Scanning works without a key. To enable AI remediation, add
            <code className="sz-inline"> NEBIUS_API_KEY</code> to
            <code className="sz-inline"> {configHint}</code> and relaunch.
          </p>
        </div>

        <div className="sz-modal-actions">
          <button className="sz-btn sz-btn-primary" onClick={onDismiss}>Get started</button>
        </div>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────
//  About dialog — version, description, links, check for updates.
// ──────────────────────────────────────────────────────────
function AboutDialog({
  version, license, onLicenseChange, onClose,
}: {
  version: string;
  license: LicenseStatus | null;
  onLicenseChange: (s: LicenseStatus) => void;
  onClose: () => void;
}) {
  // Local state for the license-key entry field.
  const [keyInput, setKeyInput] = useState<string>("");
  const [licBusy, setLicBusy] = useState<boolean>(false);
  const [licError, setLicError] = useState<string>("");
  const isPro = license?.pro === true;

  // Close on Escape for a native-feeling dialog.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const activate = useCallback(async () => {
    const key = keyInput.trim();
    if (!key || licBusy) return;
    setLicBusy(true);
    setLicError("");
    try {
      const s = await invoke<LicenseStatus>("save_license", { key });
      onLicenseChange(s);
      setKeyInput("");
    } catch (e) {
      setLicError(String(e));
    } finally {
      setLicBusy(false);
    }
  }, [keyInput, licBusy, onLicenseChange]);

  const deactivate = useCallback(async () => {
    if (licBusy) return;
    setLicBusy(true);
    setLicError("");
    try {
      const s = await invoke<LicenseStatus>("clear_license");
      onLicenseChange(s);
    } catch (e) {
      setLicError(String(e));
    } finally {
      setLicBusy(false);
    }
  }, [licBusy, onLicenseChange]);

  const expLabel = (() => {
    if (!isPro || !license || license.exp === 0) return "";
    try {
      const d = new Date(license.exp * 1000);
      return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
    } catch { return ""; }
  })();

  return (
    <div className="sz-modal-overlay" role="dialog" aria-modal="true" aria-label="About Strazh" onClick={onClose}>
      <div className="sz-modal sz-modal-about" onClick={(e) => e.stopPropagation()}>
        <button className="sz-modal-close" onClick={onClose} aria-label="Close">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>

        <div className="sz-modal-brand">
          <img className="sz-modal-logo" src="/strazh-logo.png" alt="Strazh" />
          <h1 className="sz-modal-title">Strazh</h1>
          <span className="sz-about-ver">{version ? `Version ${version}` : "Desktop app"}</span>
          <p className="sz-modal-sub">
            Autonomous supply-chain security scanner. Finds OSV advisories in your
            dependencies, suggests grounded fixes with NVIDIA Nemotron on Nebius Token
            Factory, and applies conservative local updates.
          </p>
        </div>

        {/* License section */}
        <div className="sz-lic">
          <div className="sz-lic-head">
            <span className="sz-lic-title">License</span>
            <span className={`sz-plan-badge ${isPro ? "pro" : "free"}`}>{isPro ? "PRO" : "FREE"}</span>
          </div>

          {isPro ? (
            <div className="sz-lic-active">
              <p className="sz-lic-msg">
                {license?.message || "Strazh Pro — active."}
                {license?.name ? ` Issued to ${license.name}.` : ""}
                {expLabel ? ` Renews/expires ${expLabel}.` : " Perpetual."}
              </p>
              <button className="sz-btn sz-btn-sm" onClick={deactivate} disabled={licBusy}>
                {licBusy ? "Removing…" : "Remove key"}
              </button>
            </div>
          ) : (
            <div className="sz-lic-entry">
              <p className="sz-lic-msg">
                Free includes scanning, findings, attack paths, and AI suggestions.
                <b> Apply fix</b> requires Pro. Paste your key below, or{" "}
                <button className="sz-link-inline" onClick={() => openExternal(PRICING_URL)}>get Pro</button>.
              </p>
              <div className="sz-lic-row">
                <input
                  className="sz-input sz-lic-input"
                  type="text"
                  spellCheck={false}
                  placeholder="SZ1-…"
                  value={keyInput}
                  onChange={(e) => setKeyInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") activate(); }}
                  aria-label="License key"
                />
                <button
                  className="sz-btn sz-btn-primary sz-btn-sm"
                  onClick={activate}
                  disabled={!keyInput.trim() || licBusy}
                >
                  {licBusy ? "Checking…" : "Activate"}
                </button>
              </div>
              {licError && <p className="sz-lic-err">{licError}</p>}
            </div>
          )}
        </div>

        <div className="sz-about-links">
          <button className="sz-linkrow" onClick={() => openExternal(LINKS.site)}>
            <span className="sz-linkrow-label">Website</span>
            <span className="sz-linkrow-url">strazh.dev</span>
          </button>
          <button className="sz-linkrow" onClick={() => openExternal(LINKS.repo)}>
            <span className="sz-linkrow-label">Source code</span>
            <span className="sz-linkrow-url">GitHub</span>
          </button>
          <button className="sz-linkrow" onClick={() => openExternal(LINKS.license)}>
            <span className="sz-linkrow-label">License</span>
            <span className="sz-linkrow-url">MIT</span>
          </button>
        </div>

        <div className="sz-about-update">
          <span className="sz-about-update-txt">
            Updates are published on GitHub Releases.
          </span>
          <button className="sz-btn sz-btn-sm" onClick={() => openExternal(LINKS.latestRelease)}>
            Check for updates
          </button>
        </div>

        <p className="sz-about-foot">Runs locally — no accounts, no cloud sync.</p>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────
//  Upgrade prompt — shown when a Free user tries to Apply.
// ──────────────────────────────────────────────────────────
function UpgradeDialog({ onClose, onEnterKey }: { onClose: () => void; onEnterKey: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="sz-modal-overlay" role="dialog" aria-modal="true" aria-label="Upgrade to Strazh Pro" onClick={onClose}>
      <div className="sz-modal sz-modal-upgrade" onClick={(e) => e.stopPropagation()}>
        <button className="sz-modal-close" onClick={onClose} aria-label="Close">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>

        <div className="sz-modal-brand">
          <span className="sz-plan-badge pro sz-upgrade-badge">PRO</span>
          <h1 className="sz-modal-title">Apply fix is a Pro feature</h1>
          <p className="sz-modal-sub">
            Scanning, findings, attack paths, and AI suggestions are free. Upgrade to
            <b> Strazh Pro</b> to apply the recommended version bump to your manifest —
            still fully local, with one-click Undo.
          </p>
        </div>

        <ul className="sz-upgrade-list">
          <li><span className="sz-upgrade-tick">✓</span> Everything in Free</li>
          <li><span className="sz-upgrade-tick">✓</span> Apply fix (with Undo)</li>
          <li><span className="sz-upgrade-tick">✓</span> Priority support</li>
        </ul>
        <p className="sz-upgrade-price"><b>$29</b>/month <span>·</span> or <b>$249</b>/year</p>

        <div className="sz-modal-actions sz-upgrade-actions">
          <button className="sz-btn sz-btn-primary" onClick={() => openExternal(PRICING_URL)}>Get Pro</button>
          <button className="sz-btn" onClick={onEnterKey}>I have a key</button>
        </div>
        <p className="sz-about-foot">After paying you'll get a key by email — paste it in About → License.</p>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────
//  Selected finding detail + AI remediation
// ──────────────────────────────────────────────────────────
function SelectedFinding({
  path, fix, fixState, fixError, onGenerate, onApply, onUndo, applyState, applyMsg, canUndo,
  isPro, onUpgrade,
}: {
  path: OsvPath;
  fix: NemotronFix | null;
  fixState: "idle" | "loading" | "error" | "done";
  fixError: string;
  onGenerate: () => void;
  onApply: () => void;
  onUndo: () => void;
  applyState: "idle" | "applying" | "done" | "error" | "reverted";
  applyMsg: string;
  canUndo: boolean;
  isPro: boolean;
  onUpgrade: () => void;
}) {
  const k = sevKey(path.severity);
  const { name, version } = splitComponent(path.target_component);
  const entry = basename(path.entry_point) || path.entry_point;

  // Decide whether a local apply is possible for this finding + fix text.
  const upgrade = resolveUpgradeTarget(path, fix?.fix_markdown ?? null);
  const ecoSupported = APPLY_SUPPORTED.has(path.ecosystem);
  const hasDeclaredVersion = !!splitComponent(path.target_component).version;
  const canApply = !!upgrade.target && ecoSupported && hasDeclaredVersion;
  const applyDisabledReason = !upgrade.target
    ? "No concrete version upgrade was found in the advisory or the suggestion."
    : !ecoSupported
      ? `Automatic apply isn't supported for the ${path.ecosystem} ecosystem.`
      : !hasDeclaredVersion
        ? "The scanned dependency has no pinned version to update."
        : "";

  return (
    <div className="sz-sf">
      {/* Header: package / advisory / severity */}
      <div className="sz-sf-head">
        <div className="sz-sf-title">
          <h2 className="sz-h2 sz-mono">
            {name}{version && <span className="sz-row-ver">@{version}</span>}
          </h2>
          <span className={`sz-badge sev-${k}`}>{SEV_LABEL[k]}</span>
        </div>
        <div className="sz-sf-meta">
          <span className="sz-mono sz-sf-advid">{path.vulnerability_id}</span>
          <span className="sz-sf-eco">{path.ecosystem}</span>
          {path.fixed_version ? (
            <span
              className="sz-fixed sz-fixed-yes"
              title="Advisory-reported fixed version for the scanned version. This indicates an available upgrade, not proof the repository is secure."
            >
              Advisory-reported fix: {path.fixed_version}
            </span>
          ) : (
            <span
              className="sz-fixed sz-fixed-no"
              title="The advisory does not provide a fixed version applicable to the scanned version, or applicability could not be determined reliably."
            >
              Fix version not determined
            </span>
          )}
        </div>
      </div>

      {path.summary && (
        <p className="sz-sf-summary">
          <span className="sz-evidence-tag">Advisory</span> {path.summary}
        </p>
      )}

      {/* Relationship graph: manifest → package → advisory.
          The source node is the manifest that declares the dependency — real
          evidence from the scan — not an assumed runtime entry file. */}
      <div className="sz-sf-block">
        <h3 className="sz-h3">Dependency relationship</h3>
        <p className="sz-sf-caption">
          This dependency is declared in the manifest below. The link reflects declaration, not
          confirmed runtime reachability or exploitability.
        </p>
        <div className="sz-graph">
          <GraphNode role="Manifest" label={entry} title={path.entry_point} kind="entry" />
          <span className="sz-graph-edge" aria-hidden="true" />
          <GraphNode role="Package" label={path.target_component} kind="pkg" />
          <span className="sz-graph-edge" aria-hidden="true" />
          <GraphNode role="Advisory" label={path.vulnerability_id} kind="adv" sev={k} />
        </div>
      </div>

      {/* AI remediation */}
      <div className="sz-sf-block">
        <div className="sz-ai-head">
          <div>
            <h3 className="sz-h3">AI remediation</h3>
            <span className="sz-ai-sub">Powered by Nemotron</span>
          </div>
          <button
            className="sz-btn sz-btn-primary sz-btn-sm"
            onClick={onGenerate}
            disabled={fixState === "loading"}
          >
            {fixState === "loading" ? "Generating…" : fix ? "Regenerate" : "Generate suggestion"}
          </button>
        </div>

        {fixState === "idle" && (
          <p className="sz-ai-empty">
            Generate an AI remediation suggestion for <span className="sz-mono">{path.vulnerability_id}</span>.
          </p>
        )}
        {fixState === "loading" && (
          <div className="sz-ai-loading">
            <div className="sz-bar"><div className="sz-bar-fill" /></div>
            <span>Asking Nemotron for a suggestion…</span>
          </div>
        )}
        {fixState === "error" && isProviderNotConfigured(fixError) && (
          <div className="sz-ai-notice" role="status">
            <h4 className="sz-ai-notice-title">AI provider not configured</h4>
            <p className="sz-ai-notice-body">
              Repository scanning works without AI. To enable AI remediation guidance, provide a
              Nebius Token Factory key by either setting the <code className="sz-inline">NEBIUS_API_KEY</code>{" "}
              environment variable, or saving it in a config file that Strazh reads at startup:
            </p>
            <ol className="sz-ai-notice-steps">
              <li>
                Create <code className="sz-inline">{CONFIG_ENV_HINT}</code> (the per-user app config folder).
              </li>
              <li>Add the line <code className="sz-inline">NEBIUS_API_KEY=your-key</code> and save.</li>
              <li>Relaunch Strazh (a running app does not pick up new configuration).</li>
            </ol>
            <p className="sz-ai-notice-foot">
              The key is read from your environment or this config file at startup and stored only in
              that file on your machine. It is not embedded in the Strazh app or its installer.
            </p>
          </div>
        )}
        {fixState === "error" && !isProviderNotConfigured(fixError) && (
          <div className="sz-ai-error">
            <p className="sz-error-text">{fixError}</p>
            <button className="sz-btn sz-btn-sm" onClick={onGenerate}>Retry</button>
          </div>
        )}
        {fixState === "done" && fix && (
          <div className="sz-ai-result">
            <div className="sz-ai-banner">
              <span className="sz-ai-tag">AI suggestion</span>
              <span className="sz-ai-model">{fix.model}</span>
            </div>
            <p className="sz-ai-disclaimer">
              Advisory-based guidance generated by AI. Not a verified repository patch and not
              tested against this codebase — review and test before applying.
            </p>
            <Markdown source={fix.fix_markdown} />

            {/* Local apply — edits the declaring manifest on disk only.
                Apply fix is a Pro feature: Free users see a locked button that
                opens the upgrade prompt; the fix is otherwise applicable. */}
            <div className="sz-apply">
              <div className="sz-apply-row">
                <button
                  className="sz-btn sz-btn-primary sz-btn-sm"
                  onClick={canApply && !isPro ? onUpgrade : onApply}
                  disabled={!canApply || applyState === "applying" || applyState === "done"}
                  title={
                    !canApply
                      ? applyDisabledReason
                      : isPro
                        ? `Update ${name} to ${upgrade.target} in ${entry}`
                        : "Apply fix is a Strazh Pro feature — click to upgrade"
                  }
                >
                  {applyState === "applying"
                    ? "Applying…"
                    : applyState === "done"
                      ? "Applied ✓"
                      : !canApply
                        ? "Apply fix"
                        : isPro
                          ? `Apply fix → ${upgrade.target}`
                          : `🔒 Apply fix → ${upgrade.target} (Pro)`}
                </button>
                {canApply && isPro && (applyState === "idle" || applyState === "reverted") && (
                  <span className="sz-apply-hint">
                    Updates <span className="sz-mono">{entry}</span> locally
                    {upgrade.source === "advisory" ? " (advisory-reported version)" : " (version from suggestion)"}.
                  </span>
                )}
                {canApply && !isPro && (applyState === "idle" || applyState === "reverted") && (
                  <span className="sz-apply-hint">
                    Applying fixes is a <b>Pro</b> feature.{" "}
                    <button className="sz-link-inline" onClick={onUpgrade}>Upgrade to apply</button>.
                  </span>
                )}
                {!canApply && (
                  <span className="sz-apply-hint sz-apply-hint-muted">{applyDisabledReason}</span>
                )}
              </div>
              {applyState === "done" && (
                <div className="sz-apply-ok" role="status">
                  <span>{applyMsg}</span>
                  {canUndo && (
                    <button className="sz-btn sz-btn-sm sz-apply-undo" onClick={onUndo}>Undo</button>
                  )}
                </div>
              )}
              {applyState === "reverted" && (
                <div className="sz-apply-hint" role="status">{applyMsg}</div>
              )}
              {applyState === "error" && (
                <div className="sz-apply-err" role="status">{applyMsg}</div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function GraphNode({
  role, label, title, kind, sev,
}: {
  role: string; label: string; title?: string; kind: "entry" | "pkg" | "adv"; sev?: Severity;
}) {
  const color = kind === "adv" && sev ? `var(--sev-${sev})` : kind === "entry" ? "var(--teal)" : "var(--border-strong)";
  return (
    <div className="sz-gnode">
      <span className="sz-gcircle" style={{ borderColor: color, color }}>
        {kind === "adv" ? "!" : "●"}
      </span>
      <span className="sz-grole">{role}</span>
      <span className="sz-glabel" title={title} style={kind === "adv" && sev ? { color } : undefined}>
        {label}
      </span>
    </div>
  );
}

function Metric({ label, value, accent }: { label: string; value: string | null; accent?: boolean }) {
  return (
    <div className="sz-metric">
      <span className={`sz-metric-val ${accent ? "sz-accent" : ""} ${value === null ? "sz-metric-na" : ""}`}>
        {value ?? "—"}
      </span>
      <span className="sz-metric-lbl">{label}</span>
    </div>
  );
}

// ──────────────────────────────────────────────────────────
//  Styles (design tokens + layout)
// ──────────────────────────────────────────────────────────
const STYLES = `
  :root{
    --bg:#0B1017; --sidebar:#101720; --panel:#151E29; --elev:#1C2836;
    --border:#2B3A4C; --border-strong:#3a4d63;
    --text:#E6EDF3; --text-2:#A6B4C5;
    --teal:#20C7BB; --teal-dim:#17998f;
    --sev-critical:#F87171; --sev-high:#FB923C; --sev-medium:#FBBF24; --sev-low:#60A5FA; --sev-unknown:#8aa0b8;
    --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,Roboto,"Helvetica Neue",Arial,sans-serif;
  }
  .sz-root *{box-sizing:border-box}
  /* Force a consistent sans-serif across the whole app, including headings and
     native form controls (button/input/select do NOT inherit font-family by
     default and would otherwise fall back to a UA serif). Monospace is applied
     explicitly only to code and paths via .sz-mono / the Markdown renderer. */
  .sz-root,.sz-root *{font-family:var(--sans)}
  .sz-root h1,.sz-root h2,.sz-root h3,.sz-root h4,
  .sz-root button,.sz-root input,.sz-root select,.sz-root textarea{font-family:var(--sans)}
  .sz-root{height:100vh;width:100vw;display:flex;flex-direction:column;overflow:hidden;
    background:var(--bg);color:var(--text);font-size:14px;line-height:1.5}
  .sz-mono,.sz-root .sz-mono{font-family:var(--mono)}

  /* Header */
  .sz-header{height:72px;flex-shrink:0;display:flex;align-items:center;justify-content:space-between;
    gap:16px;padding:0 24px;background:var(--sidebar);border-bottom:1px solid var(--border)}
  .sz-brand{display:flex;align-items:center;gap:12px}
  /* Original approved Strazh logo (public/strazh-logo.png). Shown at the
     improved display size with aspect ratio preserved. Opaque background is
     left intact per direction. */
  .sz-emblem{height:48px;width:auto;display:block;border-radius:6px}
  .sz-wordmark{font-size:22px;font-weight:600;letter-spacing:2px;color:var(--text)}
  .sz-head-right{display:flex;align-items:center;gap:16px}
  .sz-repo-status{display:flex;flex-direction:column;align-items:flex-end;gap:2px;min-width:0}
  .sz-repo-name{font-size:14px;color:var(--text);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .sz-status{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--text-2)}
  .sz-status-dot{width:7px;height:7px;border-radius:50%;background:var(--text-2)}
  .sz-status-scanning .sz-status-dot{background:var(--teal);animation:pulse 1.1s ease-in-out infinite}
  .sz-status-done .sz-status-dot{background:var(--teal)}
  .sz-status-failed{color:var(--sev-critical)} .sz-status-failed .sz-status-dot{background:var(--sev-critical)}
  .sz-model-badge{font-size:12px;color:var(--teal);background:rgba(32,199,187,.1);
    border:1px solid rgba(32,199,187,.35);border-radius:8px;padding:5px 10px;white-space:nowrap}

  .sz-body{flex:1;display:flex;min-height:0}

  /* Sidebar */
  .sz-sidebar{width:260px;flex-shrink:0;background:var(--sidebar);border-right:1px solid var(--border);
    padding:24px 20px;display:flex;flex-direction:column;gap:24px;overflow-y:auto}
  .sz-side-section{display:flex;flex-direction:column;gap:12px}
  .sz-side-title{margin:0;font-size:12px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--text-2)}
  .sz-repo-path{font-family:var(--mono);font-size:12px;color:var(--text-2);background:var(--bg);
    border:1px solid var(--border);border-radius:8px;padding:8px 10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .sz-repo-path:focus-visible{outline:2px solid var(--teal);outline-offset:1px;white-space:normal;word-break:break-all}
  .sz-hint{margin:-4px 0 0;font-size:12px;color:var(--text-2)}

  .sz-btn{height:40px;padding:0 16px;font-size:14px;color:var(--text);background:var(--elev);
    border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:background .14s,border-color .14s;
    display:inline-flex;align-items:center;justify-content:center;gap:8px}
  .sz-btn:hover:not(:disabled){background:#243244;border-color:var(--border-strong)}
  .sz-btn:focus-visible{outline:2px solid var(--teal);outline-offset:2px}
  .sz-btn:disabled{opacity:.45;cursor:not-allowed}
  .sz-btn-block{width:100%}
  .sz-btn-primary{background:var(--teal);border-color:var(--teal);color:#06201e;font-weight:600}
  .sz-btn-primary:hover:not(:disabled){background:#2ad6c9;border-color:#2ad6c9}
  .sz-btn-sm{height:32px;padding:0 12px;font-size:13px}
  .sz-btn-run{margin-top:-8px}

  /* Metric grid 2x2 */
  .sz-metrics{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .sz-metric{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px;
    display:flex;flex-direction:column;gap:6px}
  .sz-metric-val{font-size:26px;font-weight:700;letter-spacing:-.5px;color:var(--text);font-variant-numeric:tabular-nums}
  .sz-metric-val.sz-accent{color:var(--teal)}
  .sz-metric-val.sz-metric-na{color:var(--text-2);font-weight:500}
  .sz-metric-lbl{font-size:12px;color:var(--text-2)}

  .sz-langs{display:flex;flex-wrap:wrap;gap:8px}
  .sz-lang{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--text);
    background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:4px 10px}
  .sz-lang b{color:var(--teal);font-weight:600}

  /* Main */
  .sz-main{flex:1;min-width:0;padding:24px;overflow:hidden;display:flex;flex-direction:column}

  /* Onboarding / single-state cards */
  .sz-onboard{flex:1;display:flex;align-items:center;justify-content:center}
  .sz-onboard-card{width:min(560px,calc(100% - 48px));text-align:center;background:var(--panel);
    border:1px solid var(--border);border-radius:12px;padding:32px;display:flex;flex-direction:column;
    align-items:center;gap:16px}
  /* Original approved Strazh logo at ~140px wide, aspect ratio preserved.
     Opaque background left intact per direction. */
  .sz-onboard-logo{width:140px;height:auto;display:block;border-radius:8px;margin-bottom:4px}
  .sz-onboard-title{margin:0;font-size:22px;font-weight:600;color:var(--text)}
  .sz-onboard-sub{margin:0;font-size:15px;color:var(--text-2);line-height:1.6}
  .sz-onboard-card .sz-btn{height:44px;padding:0 20px}
  .sz-error-text{color:var(--sev-critical);font-family:var(--mono);font-size:13px;word-break:break-word}
  .sz-err-details{width:100%;max-width:440px;text-align:left;background:var(--bg);border:1px solid var(--border);
    border-radius:8px;padding:8px 12px;margin:-4px 0 4px}
  .sz-err-details summary{cursor:pointer;font-size:13px;color:var(--text-2);user-select:none}
  .sz-err-details summary:hover{color:var(--text)}
  .sz-err-details p{margin:8px 0 2px}

  /* Progress bar */
  .sz-bar{width:100%;max-width:360px;height:4px;background:var(--border);border-radius:2px;overflow:hidden}
  .sz-bar-fill{height:100%;width:35%;background:var(--teal);border-radius:2px;animation:slide 1.1s ease-in-out infinite}
  @keyframes slide{0%{transform:translateX(-120%)}100%{transform:translateX(360%)}}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

  /* Workspace two-column */
  .sz-workspace{flex:1;min-height:0;display:grid;grid-template-columns:minmax(360px,40%) 1fr;gap:20px}
  @media (max-width:1280px){ .sz-workspace{grid-template-columns:1fr;overflow-y:auto} }

  /* Findings */
  .sz-findings{min-width:0;display:flex;flex-direction:column;background:var(--panel);
    border:1px solid var(--border);border-radius:12px;padding:20px;min-height:0}
  .sz-findings-head{margin-bottom:14px}
  .sz-h2{margin:0;font-size:18px;font-weight:700;color:var(--text)}
  .sz-count{font-size:14px;font-weight:600;color:var(--text-2);margin-left:6px}
  .sz-findings-note{margin:4px 0 0;font-size:12px;color:var(--text-2)}
  .sz-sevsum{display:flex;gap:8px;margin:14px 0}
  .sz-sevsum-item{flex:1;min-width:0;display:flex;flex-direction:column;align-items:center;gap:2px;
    padding:8px 4px;background:var(--bg);border:1px solid var(--border);border-top-width:2px;border-radius:8px;cursor:pointer}
  .sz-sevsum-item:hover{background:var(--elev)}
  .sz-sevsum-item:focus-visible{outline:2px solid var(--teal);outline-offset:1px}
  .sz-sevsum-item.active{border-color:var(--teal);background:rgba(32,199,187,.08)}
  .sz-sevsum-item.sev-critical{border-top-color:var(--sev-critical)}
  .sz-sevsum-item.sev-high{border-top-color:var(--sev-high)}
  .sz-sevsum-item.sev-medium{border-top-color:var(--sev-medium)}
  .sz-sevsum-item.sev-low{border-top-color:var(--sev-low)}
  .sz-sevsum-item.sev-unknown{border-top-color:var(--sev-unknown)}
  .sz-sevsum-n{font-size:18px;font-weight:700;color:var(--text);font-variant-numeric:tabular-nums}
  .sz-sevsum-l{font-size:11px;color:var(--text-2)}
  .sz-filters{display:flex;gap:10px;margin-bottom:14px}
  .sz-input,.sz-select{height:40px;background:var(--bg);border:1px solid var(--border);border-radius:8px;
    color:var(--text);font-size:14px;padding:0 12px}
  .sz-input{flex:1;min-width:0}
  .sz-input::placeholder{color:var(--text-2)}
  .sz-input:focus-visible,.sz-select:focus-visible{outline:2px solid var(--teal);outline-offset:1px;border-color:var(--teal)}
  .sz-select{cursor:pointer}

  .sz-rows{list-style:none;margin:0;padding:0;flex:1;min-height:0;overflow-y:auto;display:flex;flex-direction:column;gap:8px}
  .sz-rows:focus-visible{outline:2px solid var(--teal);outline-offset:2px;border-radius:8px}
  .sz-row{width:100%;min-height:68px;display:flex;align-items:center;gap:12px;text-align:left;
    background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:12px 14px;cursor:pointer;
    transition:background .12s,border-color .12s}
  .sz-row:hover{background:var(--elev);border-color:var(--border-strong)}
  .sz-row:focus-visible{outline:2px solid var(--teal);outline-offset:2px}
  .sz-row-sel{background:rgba(32,199,187,.08);border-color:var(--teal)}
  .sz-sev-bar{width:4px;align-self:stretch;border-radius:2px;flex-shrink:0}
  .sz-sev-bar.sev-critical{background:var(--sev-critical)} .sz-sev-bar.sev-high{background:var(--sev-high)}
  .sz-sev-bar.sev-medium{background:var(--sev-medium)} .sz-sev-bar.sev-low{background:var(--sev-low)}
  .sz-sev-bar.sev-unknown{background:var(--sev-unknown)}
  .sz-row-main{flex:1;min-width:0;display:flex;flex-direction:column;gap:3px}
  .sz-row-pkg{font-family:var(--mono);font-size:15px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .sz-row-ver{color:var(--text-2)}
  .sz-row-id{font-family:var(--mono);font-size:13px;color:var(--text-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .sz-rows-more{font-size:12px;color:var(--text-2);padding:8px 4px}

  .sz-badge{flex-shrink:0;font-size:12px;font-weight:600;border-radius:8px;padding:4px 10px;border:1px solid transparent}
  .sz-badge.sev-critical{color:var(--sev-critical);background:rgba(248,113,113,.12);border-color:rgba(248,113,113,.4)}
  .sz-badge.sev-high{color:var(--sev-high);background:rgba(251,146,60,.12);border-color:rgba(251,146,60,.4)}
  .sz-badge.sev-medium{color:var(--sev-medium);background:rgba(251,191,36,.12);border-color:rgba(251,191,36,.4)}
  .sz-badge.sev-low{color:var(--sev-low);background:rgba(96,165,250,.12);border-color:rgba(96,165,250,.4)}
  .sz-badge.sev-unknown{color:var(--sev-unknown);background:rgba(138,160,184,.12);border-color:rgba(138,160,184,.35)}

  .sz-empty-rows{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;color:var(--text-2)}

  /* Detail pane */
  .sz-detail{min-width:0;display:flex;flex-direction:column;background:var(--panel);
    border:1px solid var(--border);border-radius:12px;padding:20px;overflow-y:auto}
  .sz-detail-empty{margin:auto;color:var(--text-2)}
  .sz-sf{display:flex;flex-direction:column;gap:20px}
  .sz-sf-head{display:flex;flex-direction:column;gap:8px}
  .sz-sf-title{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  .sz-sf-meta{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .sz-sf-advid{font-size:13px;color:var(--text)}
  .sz-sf-eco{font-size:12px;color:var(--text-2);background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:2px 9px}
  .sz-fixed{font-size:12px;border-radius:12px;padding:2px 9px;border:1px solid}
  .sz-fixed-yes{color:var(--teal);background:rgba(32,199,187,.1);border-color:rgba(32,199,187,.4)}
  .sz-fixed-no{color:var(--text-2);background:var(--bg);border-color:var(--border)}
  .sz-sf-summary{margin:0;font-size:14px;color:var(--text);line-height:1.6}
  .sz-evidence-tag{font-size:10px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:var(--text-2);
    background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:2px 7px;margin-right:6px;vertical-align:middle}
  .sz-ai-disclaimer{margin:0;font-size:12px;color:var(--text-2);line-height:1.5;
    background:var(--bg);border:1px solid var(--border);border-left:3px solid var(--sev-medium);border-radius:6px;padding:8px 10px}
  .sz-sf-block{display:flex;flex-direction:column;gap:10px}
  .sz-h3{margin:0;font-size:16px;font-weight:600;color:var(--text)}
  .sz-sf-caption{margin:0;font-size:12px;color:var(--text-2);line-height:1.5}

  /* Relationship graph */
  .sz-graph{display:flex;align-items:flex-start;gap:0;flex-wrap:wrap;background:var(--bg);
    border:1px solid var(--border);border-radius:10px;padding:18px 14px}
  .sz-gnode{display:flex;flex-direction:column;align-items:center;gap:6px;flex:1;min-width:120px;max-width:220px}
  .sz-gcircle{width:36px;height:36px;border-radius:50%;border:2px solid var(--border-strong);
    display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;background:var(--bg)}
  .sz-grole{font-size:11px;color:var(--text-2);text-transform:uppercase;letter-spacing:.5px}
  .sz-glabel{font-family:var(--mono);font-size:13px;color:var(--text);text-align:center;word-break:break-word;line-height:1.4}
  .sz-graph-edge{flex:0 0 32px;height:2px;background:var(--border-strong);margin-top:17px}

  /* AI remediation */
  .sz-ai-head{display:flex;align-items:center;justify-content:space-between;gap:12px}
  .sz-ai-sub{font-size:12px;color:var(--text-2)}
  .sz-ai-empty{margin:0;font-size:14px;color:var(--text-2)}
  .sz-ai-loading{display:flex;flex-direction:column;gap:10px;font-size:13px;color:var(--text-2)}
  .sz-ai-error{display:flex;flex-direction:column;gap:10px;align-items:flex-start}
  .sz-ai-notice{background:var(--bg);border:1px solid var(--border);border-left:3px solid var(--teal);
    border-radius:8px;padding:14px 16px;display:flex;flex-direction:column;gap:8px}
  .sz-ai-notice-title{margin:0;font-size:14px;font-weight:600;color:var(--text)}
  .sz-ai-notice-body{margin:0;font-size:13px;color:var(--text-2);line-height:1.6}
  .sz-ai-notice-steps{margin:0;padding-left:20px;display:flex;flex-direction:column;gap:5px;font-size:13px;color:var(--text)}
  .sz-ai-notice-foot{margin:0;font-size:12px;color:var(--text-2)}
  .sz-inline{font-family:var(--mono);font-size:12px;background:var(--panel);border:1px solid var(--border);
    border-radius:4px;padding:1px 5px;color:var(--teal)}
  .sz-ai-result{display:flex;flex-direction:column;gap:10px}
  .sz-ai-banner{display:flex;align-items:center;gap:10px}
  .sz-ai-tag{font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:var(--teal);
    background:rgba(32,199,187,.1);border:1px solid rgba(32,199,187,.35);border-radius:6px;padding:2px 8px}
  .sz-ai-model{font-family:var(--mono);font-size:12px;color:var(--text-2)}

  /* Local apply-fix */
  .sz-apply{margin-top:14px;padding-top:14px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:8px}
  .sz-apply-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  .sz-apply-hint{font-size:12px;color:var(--text-2)}
  .sz-apply-hint-muted{color:var(--text-2);opacity:.85}
  .sz-apply-ok{font-size:13px;color:var(--teal);background:rgba(32,199,187,.08);
    border:1px solid rgba(32,199,187,.35);border-radius:8px;padding:8px 10px;
    display:flex;align-items:center;justify-content:space-between;gap:12px}
  .sz-apply-undo{flex-shrink:0}
  .sz-apply-err{font-size:13px;color:var(--sev-high);background:rgba(251,146,60,.08);
    border:1px solid rgba(251,146,60,.35);border-radius:8px;padding:8px 10px}

  /* Recommended actions */
  .sz-reco{margin-bottom:14px;background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:12px}
  .sz-reco-head{font-size:12px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--teal);margin-bottom:8px}
  .sz-reco-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px}
  .sz-reco-row{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:var(--panel);
    border:1px solid var(--border);border-radius:8px;padding:8px 10px;cursor:pointer;transition:background .12s,border-color .12s}
  .sz-reco-row:hover{background:var(--elev);border-color:var(--border-strong)}
  .sz-reco-row:focus-visible{outline:2px solid var(--teal);outline-offset:2px}
  .sz-reco-sel{border-color:var(--teal);background:rgba(32,199,187,.08)}
  .sz-reco-pkg{font-size:13px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:220px}
  .sz-reco-reason{font-size:12px;color:var(--text-2);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

  /* Header: version chip + About icon button */
  .sz-ver-chip{font-family:var(--mono);font-size:12px;color:var(--text-2);background:var(--bg);
    border:1px solid var(--border);border-radius:8px;padding:4px 9px;white-space:nowrap}
  .sz-iconbtn{width:34px;height:34px;display:inline-flex;align-items:center;justify-content:center;
    color:var(--text-2);background:var(--elev);border:1px solid var(--border);border-radius:8px;cursor:pointer;
    transition:background .14s,border-color .14s,color .14s}
  .sz-iconbtn:hover{background:#243244;border-color:var(--border-strong);color:var(--text)}
  .sz-iconbtn:focus-visible{outline:2px solid var(--teal);outline-offset:2px}

  /* Modal overlay + shell (first-run welcome and About) */
  .sz-modal-overlay{position:fixed;inset:0;z-index:100;display:flex;align-items:center;justify-content:center;
    padding:24px;background:rgba(6,10,15,.72);backdrop-filter:blur(4px);animation:sz-fade .16s ease-out}
  @keyframes sz-fade{from{opacity:0}to{opacity:1}}
  .sz-modal{position:relative;width:min(520px,100%);max-height:calc(100vh - 48px);overflow-y:auto;
    background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:28px;
    box-shadow:0 30px 80px -30px rgba(0,0,0,.7);animation:sz-pop .18s ease-out}
  @keyframes sz-pop{from{transform:translateY(8px) scale(.98);opacity:0}to{transform:none;opacity:1}}
  .sz-modal-close{position:absolute;top:14px;right:14px;width:32px;height:32px;display:inline-flex;
    align-items:center;justify-content:center;color:var(--text-2);background:transparent;border:1px solid transparent;
    border-radius:8px;cursor:pointer}
  .sz-modal-close:hover{color:var(--text);background:var(--elev);border-color:var(--border)}
  .sz-modal-close:focus-visible{outline:2px solid var(--teal);outline-offset:2px}
  .sz-modal-brand{display:flex;flex-direction:column;align-items:center;text-align:center;gap:8px;margin-bottom:20px}
  .sz-modal-logo{width:84px;height:auto;border-radius:10px;margin-bottom:2px}
  .sz-modal-title{margin:0;font-size:24px;font-weight:700;letter-spacing:.5px}
  .sz-modal-sub{margin:4px 0 0;font-size:14px;color:var(--text-2);line-height:1.6;max-width:420px}
  .sz-modal-actions{display:flex;justify-content:center;margin-top:22px}
  .sz-modal-actions .sz-btn{height:44px;padding:0 24px}

  /* Welcome flow list */
  .sz-flow{list-style:none;margin:0 0 18px;padding:0;display:flex;flex-direction:column;gap:10px}
  .sz-flow li{display:flex;gap:12px;align-items:flex-start;background:var(--bg);border:1px solid var(--border);
    border-radius:10px;padding:12px 14px}
  .sz-flow-num{flex-shrink:0;width:26px;height:26px;display:flex;align-items:center;justify-content:center;
    border-radius:7px;background:rgba(32,199,187,.1);border:1px solid rgba(32,199,187,.35);color:var(--teal);
    font-size:13px;font-weight:700}
  .sz-flow li>div{display:flex;flex-direction:column;gap:2px;min-width:0}
  .sz-flow b{font-size:14px;color:var(--text)}
  .sz-flow span:not(.sz-flow-num){font-size:13px;color:var(--text-2);line-height:1.5}
  .sz-welcome-note{background:var(--bg);border:1px solid var(--border);border-left:3px solid var(--teal);
    border-radius:8px;padding:12px 14px;display:flex;flex-direction:column;gap:8px}
  .sz-welcome-note p{margin:0;font-size:13px;color:var(--text);line-height:1.6}
  .sz-welcome-note-dim{color:var(--text-2) !important}

  /* About links + update row */
  .sz-about-ver{font-family:var(--mono);font-size:12px;color:var(--teal);background:rgba(32,199,187,.1);
    border:1px solid rgba(32,199,187,.35);border-radius:8px;padding:3px 10px}
  .sz-about-links{display:flex;flex-direction:column;gap:8px;margin-bottom:16px}
  .sz-linkrow{display:flex;align-items:center;justify-content:space-between;gap:12px;width:100%;text-align:left;
    background:var(--bg);border:1px solid var(--border);border-radius:9px;padding:11px 14px;cursor:pointer;
    transition:background .12s,border-color .12s}
  .sz-linkrow:hover{background:var(--elev);border-color:var(--border-strong)}
  .sz-linkrow:focus-visible{outline:2px solid var(--teal);outline-offset:2px}
  .sz-linkrow-label{font-size:14px;color:var(--text)}
  .sz-linkrow-url{font-size:13px;color:var(--teal)}
  .sz-about-update{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
    background:var(--bg);border:1px solid var(--border);border-radius:9px;padding:12px 14px}
  .sz-about-update-txt{font-size:13px;color:var(--text-2)}
  .sz-about-foot{margin:16px 0 0;text-align:center;font-size:12px;color:var(--text-2)}

  /* Plan badge (header + dialogs) */
  .sz-plan-badge{font-size:11px;font-weight:700;letter-spacing:.6px;border-radius:7px;padding:3px 8px;
    border:1px solid transparent;line-height:1.4}
  .sz-plan-badge.pro{color:#06201e;background:var(--teal);border-color:var(--teal)}
  .sz-plan-badge.free{color:var(--text-2);background:var(--bg);border-color:var(--border)}
  .sz-plan-btn{cursor:pointer}
  .sz-plan-btn:hover{filter:brightness(1.08)}
  .sz-plan-btn:focus-visible{outline:2px solid var(--teal);outline-offset:2px}

  /* Inline text link (buttons styled as links inside hints/paragraphs) */
  .sz-link-inline{background:none;border:none;padding:0;margin:0;font:inherit;color:var(--teal);
    cursor:pointer;text-decoration:underline;text-underline-offset:2px}
  .sz-link-inline:hover{color:#2ad6c9}
  .sz-link-inline:focus-visible{outline:2px solid var(--teal);outline-offset:2px;border-radius:3px}

  /* License section in About */
  .sz-lic{margin-bottom:16px;background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:14px}
  .sz-lic-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
  .sz-lic-title{font-size:12px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--text-2)}
  .sz-lic-msg{margin:0 0 10px;font-size:13px;color:var(--text-2);line-height:1.6}
  .sz-lic-msg b{color:var(--text)}
  .sz-lic-row{display:flex;gap:8px}
  .sz-lic-input{flex:1;min-width:0;font-family:var(--mono);font-size:12px}
  .sz-lic-active{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
  .sz-lic-err{margin:8px 0 0;font-size:12px;color:var(--sev-high);word-break:break-word}

  /* Upgrade dialog */
  .sz-modal-upgrade{width:min(440px,100%)}
  .sz-upgrade-badge{margin-bottom:10px;font-size:12px;padding:4px 12px}
  .sz-upgrade-list{list-style:none;margin:0 0 14px;padding:0;display:flex;flex-direction:column;gap:8px}
  .sz-upgrade-list li{display:flex;align-items:center;gap:10px;font-size:14px;color:var(--text);
    background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
  .sz-upgrade-tick{color:var(--teal);font-weight:700}
  .sz-upgrade-price{margin:0 0 4px;text-align:center;font-size:15px;color:var(--text-2)}
  .sz-upgrade-price b{color:var(--text);font-size:18px}
  .sz-upgrade-price span{opacity:.5;margin:0 4px}
  .sz-upgrade-actions{gap:10px;flex-wrap:wrap}
`;
