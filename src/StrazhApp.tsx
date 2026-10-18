import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import "./App.css";

// ── Types mirrored from the Rust backend ──

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

interface OsvPath {
  entry_point: string;
  target_component: string;
  vulnerability_id: string;
  severity: string;
  ecosystem: string;
  summary: string | null;
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

type Phase = "idle" | "scanning" | "scanned" | "fixing";

const MODEL = "nvidia/Nemotron-3_5-Lightning";

function basename(p: string): string {
  if (!p) return "";
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] || p;
}

// Normalize an OSV severity label to a severity key used for colours.
function sevKey(s: string): "critical" | "high" | "medium" | "low" | "unknown" {
  const t = (s || "").toUpperCase();
  if (t === "CRITICAL") return "critical";
  if (t === "HIGH") return "high";
  if (t === "MODERATE" || t === "MEDIUM") return "medium";
  if (t === "LOW") return "low";
  return "unknown";
}

const SEV_COLOR: Record<string, string> = {
  critical: "#ff4d6d",
  high: "#ff8c42",
  medium: "#e0b54a",
  low: "#6b7a99",
  unknown: "#55607a",
};

export default function StrazhApp() {
  const [repoPath, setRepoPath] = useState<string>("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState<string>("");

  const [code, setCode] = useState<CodeGraphResult | null>(null);
  const [osv, setOsv] = useState<OsvScanResult | null>(null);

  const [selected, setSelected] = useState<number | null>(null);
  const [fix, setFix] = useState<NemotronFix | null>(null);
  const [fixError, setFixError] = useState<string>("");

  const pickRepo = useCallback(async () => {
    setError("");
    const dir = await open({ directory: true, multiple: false, title: "Select a repository to scan" });
    if (typeof dir === "string") {
      setRepoPath(dir);
      setCode(null);
      setOsv(null);
      setSelected(null);
      setFix(null);
      setPhase("idle");
    }
  }, []);

  const scan = useCallback(async () => {
    if (!repoPath) return;
    setPhase("scanning");
    setError("");
    setFix(null);
    setSelected(null);
    setOsv(null);
    try {
      const codeRes = await invoke<CodeGraphResult>("scan_code_graph", { rootDir: repoPath });
      setCode(codeRes);

      // Attack paths are grounded entirely in the scanned repo: real entry
      // files from the AST scan + dependencies declared in this repo's own
      // manifests, scored against the live OSV advisory database. A path only
      // appears when OSV returns a real advisory for a declared package+version.
      // No sample SBOM, no hardcoded CVE.
      const res = await invoke<OsvScanResult>("scan_with_osv", { rootDir: repoPath });
      setOsv(res);
      setSelected(res.exploitation_paths.length > 0 ? 0 : null);
      setPhase("scanned");
    } catch (e) {
      setError(String(e));
      setPhase("idle");
    }
  }, [repoPath]);

  const generateFix = useCallback(async () => {
    if (!osv || selected === null) return;
    const path = osv.exploitation_paths[selected];
    setPhase("fixing");
    setFix(null);
    setFixError("");
    try {
      const res = await invoke<NemotronFix>("generate_nemotron_fix", {
        vulnId: path.vulnerability_id,
        advisorySummary: path.summary,
        entryPoint: path.entry_point,
        targetComponent: path.target_component,
        proofChain: path.proof_chain,
        sourceExcerpt: null,
      });
      setFix(res);
    } catch (e) {
      setFixError(String(e));
    } finally {
      setPhase("scanned");
    }
  }, [osv, selected]);

  const paths = osv?.exploitation_paths ?? [];
  const activePath = selected !== null ? paths[selected] : null;

  const languages = useMemo(() => {
    if (!code) return [] as [string, number][];
    return Object.entries(code.stats.languages).sort((a, b) => b[1] - a[1]);
  }, [code]);

  const repoName = basename(repoPath);
  const filesScanned = code ? code.stats.total_files : null;
  const pathsFound = osv ? paths.length : null;

  return (
    <div className="sz-root">
      {/* Top bar */}
      <header className="sz-topbar">
        <div className="sz-brand">
          <span className="sz-logo">◆</span>
          <span className="sz-name">Strazh</span>
        </div>
        <div className="sz-status">
          <TopStat label="repo" value={repoName || "—"} mono />
          <TopStat label="files" value={filesScanned ?? "—"} />
          <TopStat label="paths" value={pathsFound ?? "—"} />
          <TopStat label="model" value={MODEL} mono accent />
        </div>
      </header>

      <div className="sz-body">
        {/* Left rail */}
        <aside className="sz-rail">
          <button className="sz-btn" onClick={pickRepo}>Choose folder…</button>
          <code className="sz-path" title={repoPath}>{repoPath || "No repository selected"}</code>
          <button
            className="sz-btn sz-btn-accent"
            onClick={scan}
            disabled={!repoPath || phase === "scanning"}
          >
            {phase === "scanning" ? "Scanning…" : "Run scan"}
          </button>
          {error && <div className="sz-alert">{error}</div>}

          <div className="sz-tiles">
            <Tile label="Files" value={code ? code.stats.total_files : "—"} />
            <Tile label="Lines" value={code ? code.stats.total_lines : "—"} />
            <Tile label="Dependencies" value={code ? code.stats.declared_deps : "—"} />
            <Tile label="Attack paths" value={osv ? paths.length : "—"} accent={!!osv && paths.length > 0} />
          </div>

          {languages.length > 0 && (
            <div className="sz-langs">
              <div className="sz-rail-label">Languages</div>
              <div className="sz-chips">
                {languages.map(([lang, n]) => (
                  <span key={lang} className="sz-lang">{lang}<b>{n}</b></span>
                ))}
              </div>
            </div>
          )}
        </aside>

        {/* Main dashboard: two rows */}
        <main className="sz-main">
          {/* Row 1: attack-path graph + list */}
          <section className="sz-panel sz-graph-panel">
            <div className="sz-panel-head">
              <h2 className="sz-panel-title">Attack path</h2>
              {osv && paths.length > 0 && (
                <span className="sz-count">{paths.length} advisor{paths.length === 1 ? "y" : "ies"}</span>
              )}
            </div>

            {/* Graph area */}
            <div className="sz-graph">
              {phase === "scanning" && (
                <div className="sz-progress">
                  <div className="sz-progress-text">
                    Querying OSV{code ? ` · ${code.stats.declared_deps} dependencies` : ""}
                  </div>
                  <div className="sz-bar"><div className="sz-bar-fill" /></div>
                </div>
              )}

              {phase !== "scanning" && !osv && (
                <div className="sz-graph-empty">Pick a repository and run a scan to map attack paths from its own dependencies.</div>
              )}

              {phase !== "scanning" && osv && paths.length === 0 && (
                <div className="sz-graph-empty">
                  No exploitable path — {osv.stats.dependencies_queried} of {osv.stats.dependencies_declared} dependencies queried against OSV, none with a current advisory.
                </div>
              )}

              {phase !== "scanning" && activePath && (
                <PathGraph path={activePath} />
              )}
            </div>

            {/* Scrollable severity-sorted list */}
            {paths.length > 0 && (
              <div className="sz-list">
                {paths.slice(0, 12).map((p, i) => {
                  const idx = i;
                  const k = sevKey(p.severity);
                  return (
                    <button
                      key={i}
                      className={`sz-row ${selected === idx ? "active" : ""}`}
                      onClick={() => { setSelected(idx); setFix(null); }}
                    >
                      <span className="sz-dot" style={{ background: SEV_COLOR[k] }} />
                      <span className="sz-row-id">{p.vulnerability_id}</span>
                      <span className="sz-row-pkg">{p.target_component}</span>
                      <span className={`sz-sev sev-${k}`}>{p.severity}</span>
                    </button>
                  );
                })}
                {paths.length > 12 && (
                  <div className="sz-list-more">+{paths.length - 12} more, sorted by severity</div>
                )}
              </div>
            )}
          </section>

          {/* Row 2: Nemotron fix */}
          <section className="sz-panel sz-fix-panel">
            <div className="sz-panel-head">
              <h2 className="sz-panel-title">Nemotron fix</h2>
              {/* Chip reflects the SELECTED PATH's real OSV severity, not the fix text. */}
              {activePath && (
                <span className={`sz-sev sev-${sevKey(activePath.severity)}`}>{activePath.severity}</span>
              )}
              <div className="sz-panel-head-spacer" />
              <button
                className="sz-btn sz-btn-accent sz-btn-sm"
                onClick={generateFix}
                disabled={!activePath || phase === "fixing"}
              >
                {phase === "fixing" ? "Asking Nemotron…" : "Generate fix"}
              </button>
            </div>

            {fixError && <div className="sz-alert">{fixError}</div>}
            {!fix && !fixError && (
              <div className="sz-fix-empty">Select a path and generate a fix written live by {MODEL}.</div>
            )}
            {fix && (
              <div className="sz-fix">
                <div className="sz-fix-model">model: {fix.model}</div>
                <pre className="sz-fix-md">{fix.fix_markdown}</pre>
              </div>
            )}
          </section>
        </main>
      </div>

      <style>{`
        *{box-sizing:border-box}
        .sz-root{height:100vh;width:100vw;display:flex;flex-direction:column;background:#0b0d12;color:#e7e9f0;
          font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;overflow:hidden}

        /* Top bar */
        .sz-topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;
          padding:0 20px;height:52px;border-bottom:1px solid #1b1f2b;background:#0e1118;flex-shrink:0}
        .sz-brand{display:flex;align-items:center;gap:9px}
        .sz-logo{color:#7c5cff;font-size:16px}
        .sz-name{font-size:15px;font-weight:700;letter-spacing:.4px}
        .sz-status{display:flex;align-items:center;gap:26px}
        .sz-ts{display:flex;flex-direction:column;line-height:1.2}
        .sz-ts-lbl{font-size:9px;color:#5b6479;text-transform:uppercase;letter-spacing:.6px}
        .sz-ts-val{font-size:13px;color:#e7e9f0;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .sz-ts-val.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
        .sz-ts-val.accent{color:#9f8bff}

        .sz-body{flex:1;display:flex;min-height:0}

        /* Left rail */
        .sz-rail{width:280px;min-width:260px;flex-shrink:0;border-right:1px solid #1b1f2b;background:#0d1016;
          padding:16px;display:flex;flex-direction:column;gap:12px;overflow-y:auto}
        .sz-btn{background:#171b26;color:#e7e9f0;border:1px solid #262c3b;border-radius:8px;padding:9px 14px;
          font-size:13px;cursor:pointer;transition:all .14s;width:100%}
        .sz-btn:hover:not(:disabled){background:#1e2431;border-color:#343c50}
        .sz-btn:disabled{opacity:.4;cursor:not-allowed}
        .sz-btn-accent{background:#7c5cff;border-color:#7c5cff;color:#fff;font-weight:600}
        .sz-btn-accent:hover:not(:disabled){background:#8c6fff;border-color:#8c6fff}
        .sz-btn-sm{width:auto;padding:6px 12px;font-size:12px}
        .sz-path{display:block;font-size:11px;color:#8690a5;background:#0b0d12;padding:8px 10px;border-radius:6px;
          border:1px solid #1b1f2b;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
          font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
        .sz-alert{padding:9px 11px;border-radius:7px;background:#2a1118;border:1px solid #5c2130;color:#ffb3bd;
          font-size:12px;white-space:pre-wrap;word-break:break-word}

        /* Stat tiles — the visual anchor */
        .sz-tiles{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:2px}
        .sz-tile{background:#141824;border:1px solid #1b1f2b;border-radius:10px;padding:14px 14px 12px;display:flex;flex-direction:column;gap:6px}
        .sz-tile-val{font-size:26px;font-weight:700;letter-spacing:-.5px;color:#f2f3f8;font-variant-numeric:tabular-nums}
        .sz-tile-val.accent{color:#9f8bff}
        .sz-tile-lbl{font-size:10px;color:#5b6479;text-transform:uppercase;letter-spacing:.6px}

        .sz-rail-label{font-size:10px;color:#5b6479;text-transform:uppercase;letter-spacing:.6px;margin-bottom:7px}
        .sz-chips{display:flex;flex-wrap:wrap;gap:6px}
        .sz-lang{display:inline-flex;align-items:center;gap:5px;font-size:11px;color:#c3c9d6;background:#141824;
          border:1px solid #1b1f2b;border-radius:12px;padding:3px 9px}
        .sz-lang b{color:#9f8bff;font-weight:600}

        /* Main dashboard */
        .sz-main{flex:1;min-width:0;display:flex;flex-direction:column;gap:14px;padding:16px 18px;overflow:hidden}
        .sz-panel{background:#141824;border:1px solid #1b1f2b;border-radius:12px;padding:16px 18px;display:flex;flex-direction:column;min-height:0}
        .sz-graph-panel{flex:1;min-height:0}
        .sz-fix-panel{flex:1;min-height:0}
        .sz-panel-head{display:flex;align-items:center;gap:12px;margin-bottom:12px}
        .sz-panel-title{margin:0;font-size:12px;color:#aab2c5;text-transform:uppercase;letter-spacing:.7px;font-weight:600}
        .sz-panel-head-spacer{flex:1}
        .sz-count{font-size:11px;color:#8690a5;font-variant-numeric:tabular-nums}

        /* Graph area */
        .sz-graph{min-height:150px;display:flex;align-items:center;justify-content:center;
          border:1px solid #1b1f2b;border-radius:10px;background:#0f131c;padding:14px;margin-bottom:12px}
        .sz-graph-empty{color:#6b7488;font-size:13px;text-align:center;padding:0 12px}

        /* Progress state */
        .sz-progress{width:100%;max-width:480px;display:flex;flex-direction:column;gap:10px;align-items:center}
        .sz-progress-text{font-size:13px;color:#aab2c5;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
        .sz-bar{width:100%;height:4px;background:#1b1f2b;border-radius:2px;overflow:hidden}
        .sz-bar-fill{height:100%;width:35%;background:#7c5cff;border-radius:2px;animation:slide 1.1s ease-in-out infinite}
        @keyframes slide{0%{transform:translateX(-120%)}100%{transform:translateX(360%)}}

        /* Path list */
        .sz-list{flex:1;min-height:0;overflow-y:auto;display:flex;flex-direction:column;gap:4px}
        .sz-row{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:#0f131c;
          border:1px solid #1b1f2b;border-radius:8px;padding:8px 11px;cursor:pointer;transition:all .12s}
        .sz-row:hover{border-color:#2c3448;background:#121726}
        .sz-row.active{border-color:#7c5cff;background:#171433}
        .sz-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
        .sz-row-id{font-size:12.5px;color:#e7e9f0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
        .sz-row-pkg{flex:1;font-size:12px;color:#8690a5;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
          overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .sz-list-more{font-size:11px;color:#6b7488;padding:6px 2px}

        /* Severity chips */
        .sz-sev{font-size:10.5px;font-weight:700;letter-spacing:.4px;border-radius:11px;padding:3px 9px;flex-shrink:0}
        .sev-critical{background:#3b0d1a;color:#ff4d6d;border:1px solid #6b1830}
        .sev-high{background:#3a1e0c;color:#ff8c42;border:1px solid #6b3a16}
        .sev-medium{background:#342b0c;color:#e0b54a;border:1px solid #5f4f17}
        .sev-low{background:#1a2030;color:#9fb0cc;border:1px solid #2c3850}
        .sev-unknown{background:#191d28;color:#9aa3b8;border:1px solid #2a3142}

        /* Fix panel */
        .sz-fix-empty{color:#6b7488;font-size:13px;padding:8px 2px}
        .sz-fix{flex:1;min-height:0;display:flex;flex-direction:column;background:#0f131c;border:1px solid #1b1f2b;
          border-radius:10px;overflow:hidden}
        .sz-fix-model{font-size:11px;color:#8690a5;padding:8px 12px;border-bottom:1px solid #1b1f2b;background:#0d1016;
          font-family:ui-monospace,SFMono-Regular,Menlo,monospace;flex-shrink:0}
        .sz-fix-md{margin:0;padding:14px;font-size:12.5px;line-height:1.6;color:#d7dbe6;white-space:pre-wrap;
          word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow:auto;flex:1;min-height:0}

        /* scrollbars */
        .sz-rail::-webkit-scrollbar,.sz-list::-webkit-scrollbar,.sz-fix-md::-webkit-scrollbar{width:7px;height:7px}
        .sz-rail::-webkit-scrollbar-thumb,.sz-list::-webkit-scrollbar-thumb,.sz-fix-md::-webkit-scrollbar-thumb{background:#262c3b;border-radius:4px}
      `}</style>
    </div>
  );
}

// ── Attack-path graph: entry file → package@version → advisory ──
function PathGraph({ path }: { path: OsvPath }) {
  const k = sevKey(path.severity);
  const advColor = SEV_COLOR[k];
  const entryLabel = basename(path.entry_point) || path.entry_point;

  return (
    <div className="pg">
      <div className="pg-node">
        <span className="pg-circle" style={{ borderColor: "#7c5cff", color: "#9f8bff" }}>●</span>
        <span className="pg-role">entry</span>
        <span className="pg-label" title={path.entry_point}>{entryLabel}</span>
      </div>
      <div className="pg-edge" />
      <div className="pg-node">
        <span className="pg-circle" style={{ borderColor: "#343c50" }} />
        <span className="pg-role">package</span>
        <span className="pg-label">{path.target_component}</span>
      </div>
      <div className="pg-edge" />
      <div className="pg-node">
        <span className="pg-circle pg-adv" style={{ borderColor: advColor, color: advColor, background: advColor + "22" }}>!</span>
        <span className="pg-role">advisory</span>
        <span className="pg-label" style={{ color: advColor }}>{path.vulnerability_id}</span>
      </div>

      <style>{`
        .pg{display:flex;align-items:center;justify-content:center;gap:0;width:100%;flex-wrap:wrap}
        .pg-node{display:flex;flex-direction:column;align-items:center;gap:6px;min-width:120px;max-width:260px}
        .pg-circle{width:34px;height:34px;border-radius:50%;border:2px solid #343c50;display:flex;align-items:center;
          justify-content:center;font-size:13px;background:#0b0d12;color:#8690a5}
        .pg-adv{font-weight:800}
        .pg-role{font-size:9px;color:#5b6479;text-transform:uppercase;letter-spacing:.6px}
        .pg-label{font-size:12.5px;color:#e7e9f0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
          text-align:center;word-break:break-word;line-height:1.35}
        .pg-edge{flex:0 0 48px;height:2px;background:linear-gradient(90deg,#343c50,#2c3448);margin:0 2px;margin-bottom:34px}
      `}</style>
    </div>
  );
}

function TopStat({ label, value, mono, accent }: { label: string; value: string | number; mono?: boolean; accent?: boolean }) {
  return (
    <div className="sz-ts">
      <span className="sz-ts-lbl">{label}</span>
      <span className={`sz-ts-val ${mono ? "mono" : ""} ${accent ? "accent" : ""}`} title={String(value)}>{value}</span>
    </div>
  );
}

function Tile({ label, value, accent }: { label: string; value: string | number; accent?: boolean }) {
  return (
    <div className="sz-tile">
      <span className={`sz-tile-val ${accent ? "accent" : ""}`}>{value}</span>
      <span className="sz-tile-lbl">{label}</span>
    </div>
  );
}
