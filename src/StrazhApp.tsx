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

function riskFrom(text: string): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null {
  const t = text.toUpperCase();
  if (t.includes("CRITICAL")) return "CRITICAL";
  if (t.includes("HIGH")) return "HIGH";
  if (t.includes("MEDIUM")) return "MEDIUM";
  if (t.includes("LOW")) return "LOW";
  return null;
}

// Normalize an OSV severity label to a chip css class.
function sevClass(s: string): string {
  const t = s.toUpperCase();
  if (t === "CRITICAL") return "critical";
  if (t === "HIGH") return "high";
  if (t === "MODERATE" || t === "MEDIUM") return "medium";
  if (t === "LOW") return "low";
  return "unknown";
}

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

  const fixRisk = fix ? riskFrom(fix.fix_markdown) : null;

  // Status bar values
  const repoName = basename(repoPath);
  const filesScanned = code ? code.stats.total_files : null;
  const pathsFound = osv ? paths.length : null;

  return (
    <div className="strazh-root">
      {/* Top status bar */}
      <header className="strazh-topbar">
        <div className="tb-brand">
          <span className="tb-logo">🛡️</span>
          <span className="tb-name">Strazh</span>
        </div>
        <div className="tb-status">
          <StatusItem label="repo" value={repoName || "—"} />
          <StatusItem label="files" value={filesScanned ?? "—"} />
          <StatusItem label="paths" value={pathsFound ?? "—"} />
          <StatusItem label="model" value={MODEL} mono />
        </div>
      </header>

      {/* Main two-column body */}
      <div className="strazh-body">
        {/* Left: controls + counts */}
        <aside className="strazh-left">
          <h2 className="panel-title">Scan</h2>
          <button className="btn block" onClick={pickRepo}>Choose folder…</button>
          <code className="repo-path" title={repoPath}>{repoPath || "No repository selected"}</code>
          <button
            className="btn btn-primary block"
            onClick={scan}
            disabled={!repoPath || phase === "scanning"}
          >
            {phase === "scanning" ? "Scanning…" : "Run scan"}
          </button>
          {error && <div className="alert">{error}</div>}

          {code && (
            <div className="counts">
              <Count label="Files" value={code.stats.total_files} />
              <Count label="Lines" value={code.stats.total_lines} />
              <Count label="Dependencies" value={code.stats.declared_deps} />
              <Count label="Attack paths" value={osv ? paths.length : 0} />
            </div>
          )}

          {code && languages.length > 0 && (
            <div className="langs">
              <div className="langs-title">Languages</div>
              <div className="lang-chips">
                {languages.map(([lang, n]) => (
                  <span key={lang} className="lang-chip">{lang} <b>{n}</b></span>
                ))}
              </div>
            </div>
          )}
        </aside>

        {/* Right: attack path + fix */}
        <main className="strazh-right">
          <section className="panel">
            <h2 className="panel-title">Attack path</h2>

            {!osv && (
              <p className="muted">Pick a repository and run a scan. Strazh queries OSV for the dependencies declared in the repo's own manifests.</p>
            )}
            {osv && paths.length === 0 && (
              <p className="muted">
                No exploitable path: {repoName || "this repo"} was scanned — {osv.stats.dependencies_queried} of {osv.stats.dependencies_declared} declared dependencies had a concrete version to query against OSV, and none returned a current advisory.
              </p>
            )}

            {paths.length > 1 && (
              <>
                <div className="path-tabs">
                  {paths.slice(0, 25).map((p, i) => (
                    <button
                      key={i}
                      className={`path-tab sev-${sevClass(p.severity)} ${selected === i ? "active" : ""}`}
                      onClick={() => { setSelected(i); setFix(null); }}
                      title={`${p.target_component} — ${p.severity}`}
                    >
                      {p.vulnerability_id}
                    </button>
                  ))}
                </div>
                {paths.length > 25 && (
                  <p className="muted" style={{ marginBottom: 12 }}>
                    Showing 25 of {paths.length} advisories (sorted by severity).
                  </p>
                )}
              </>
            )}

            {activePath && (
              <div className="chain-wrap">
                <div className="chain-vuln">
                  <span className="vuln-badge">{activePath.vulnerability_id}</span>
                  {activePath.severity && (
                    <span className={`risk-chip risk-${sevClass(activePath.severity)}`}>{activePath.severity}</span>
                  )}
                  <span className="eco-tag">{activePath.ecosystem}</span>
                </div>
                {activePath.summary && <p className="vuln-summary">{activePath.summary}</p>}
                <ol className="vchain">
                  {activePath.proof_chain.map((step, i) => {
                    const isEntry = i === 0;
                    const isSink = i === activePath.proof_chain.length - 1;
                    const role = isEntry ? "entry" : isSink ? "advisory" : `hop ${i}`;
                    const cls = isEntry ? "entry" : isSink ? "sink" : "hop";
                    return (
                      <li key={i} className={`vnode ${cls}`}>
                        <span className="vrole">{role}</span>
                        <span className="vlabel">{step}</span>
                      </li>
                    );
                  })}
                </ol>
              </div>
            )}
          </section>

          <section className="panel">
            <div className="fix-header">
              <h2 className="panel-title">Nemotron fix</h2>
              {fixRisk && <span className={`risk-chip risk-${fixRisk.toLowerCase()}`}>{fixRisk}</span>}
            </div>
            <button
              className="btn btn-primary"
              onClick={generateFix}
              disabled={!activePath || phase === "fixing"}
            >
              {phase === "fixing" ? "Asking Nemotron…" : "Generate fix with Nemotron"}
            </button>
            {fixError && <div className="alert">{fixError}</div>}
            {!fix && !fixError && (
              <p className="muted">Select an attack path and generate a fix written live by {MODEL}.</p>
            )}
            {fix && (
              <div className="fix-card">
                <div className="fix-model">model: {fix.model}</div>
                <pre className="fix-md">{fix.fix_markdown}</pre>
              </div>
            )}
          </section>
        </main>
      </div>

      <style>{`
        *{box-sizing:border-box}
        .strazh-root{min-height:100vh;width:100vw;background:#0a0a16;color:#e6e6f0;font-family:system-ui,-apple-system,sans-serif;display:flex;flex-direction:column}

        /* Top status bar */
        .strazh-topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:10px 20px;border-bottom:1px solid #1c1c33;background:#0e0e1a;flex-wrap:wrap}
        .tb-brand{display:flex;align-items:center;gap:8px}
        .tb-logo{font-size:20px}
        .tb-name{font-size:16px;font-weight:700;letter-spacing:.5px}
        .tb-status{display:flex;align-items:center;gap:22px;flex-wrap:wrap}
        .si{display:flex;align-items:baseline;gap:6px}
        .si-lbl{font-size:10px;color:#6f6f92;text-transform:uppercase;letter-spacing:.5px}
        .si-val{font-size:13px;color:#e6e6f0;max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .si-val.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#9fd0ff}

        /* Two-column body, full width */
        .strazh-body{flex:1;display:flex;min-height:0;width:100%}
        .strazh-left{width:300px;min-width:260px;border-right:1px solid #1c1c33;background:#0d0d1c;padding:18px;display:flex;flex-direction:column;gap:12px;overflow-y:auto}
        .strazh-right{flex:1;min-width:0;padding:18px 24px;display:flex;flex-direction:column;gap:16px;overflow-y:auto}

        .panel{background:#101024;border:1px solid #1c1c33;border-radius:12px;padding:18px 20px}
        .panel-title{margin:0 0 12px;font-size:13px;color:#c9c9e8;text-transform:uppercase;letter-spacing:.6px}

        .btn{background:#1a1a3a;color:#e6e6f0;border:1px solid #2a2a55;border-radius:8px;padding:9px 16px;font-size:13px;cursor:pointer;transition:all .15s}
        .btn:hover:not(:disabled){background:#24244d;border-color:#3a3a70}
        .btn:disabled{opacity:.45;cursor:not-allowed}
        .btn.block{width:100%}
        .btn-primary{background:#4f46e5;border-color:#6366f1}
        .btn-primary:hover:not(:disabled){background:#5b52f0}

        .repo-path{display:block;font-size:11.5px;color:#8c8ca8;background:#0a0a16;padding:8px 10px;border-radius:6px;border:1px solid #1c1c33;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .alert{padding:10px 12px;border-radius:8px;background:#2a1216;border:1px solid #5c1f28;color:#ffb3bd;font-size:12px;white-space:pre-wrap;word-break:break-word}

        .counts{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:4px}
        .count{background:#0a0a16;border:1px solid #1c1c33;border-radius:8px;padding:10px 12px;display:flex;flex-direction:column}
        .count-val{font-size:20px;font-weight:700;color:#e6e6f0}
        .count-lbl{font-size:10px;color:#8c8ca8;text-transform:uppercase;letter-spacing:.5px}

        .langs{margin-top:4px}
        .langs-title{font-size:10px;color:#6f6f92;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
        .lang-chips{display:flex;flex-wrap:wrap;gap:6px}
        .lang-chip{font-size:11px;color:#c9c9e8;background:#15152e;border:1px solid #24244d;border-radius:12px;padding:3px 9px}
        .lang-chip b{color:#9fd0ff}

        .muted{color:#8c8ca8;font-size:13px;margin:0;line-height:1.5}

        .path-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
        .path-tab{background:#0a0a16;border:1px solid #1c1c33;color:#9f9fe0;border-radius:6px;padding:4px 10px;font-size:12px;cursor:pointer}
        .path-tab.active{background:#4f46e5;border-color:#6366f1;color:#fff}
        .path-tab.sev-critical{border-left:3px solid #ff5277}
        .path-tab.sev-high{border-left:3px solid #ff8c4a}
        .path-tab.sev-medium{border-left:3px solid #e0b54a}
        .path-tab.sev-low{border-left:3px solid #4ac87a}
        .path-tab.sev-unknown{border-left:3px solid #555}

        .chain-vuln{margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
        .vuln-badge{background:#5c1f28;color:#ffb3bd;border-radius:6px;padding:4px 10px;font-size:12px;font-weight:700;letter-spacing:.3px}
        .eco-tag{font-size:11px;color:#9fd0ff;background:#15152e;border:1px solid #24244d;border-radius:12px;padding:2px 9px}
        .vuln-summary{margin:0 0 12px;font-size:12.5px;color:#c9c9e8;line-height:1.5}

        /* Vertical attack chain */
        .vchain{list-style:none;margin:0;padding:0;position:relative}
        .vnode{position:relative;display:flex;flex-direction:column;gap:2px;background:#0a0a16;border:1px solid #24244d;border-radius:8px;padding:10px 14px;margin:0 0 0 18px}
        .vnode:not(:last-child){margin-bottom:22px}
        .vnode:not(:last-child)::after{content:"";position:absolute;left:-10px;top:100%;height:22px;width:2px;background:#2a2a55}
        .vnode::before{content:"";position:absolute;left:-14px;top:50%;transform:translateY(-50%);width:10px;height:10px;border-radius:50%;background:#2a2a55;border:2px solid #0a0a16}
        .vnode.entry{border-color:#3a6ea5}
        .vnode.entry::before{background:#3a6ea5}
        .vnode.sink{border-color:#5c1f28}
        .vnode.sink::before{background:#d64558}
        .vrole{font-size:10px;color:#6f6f92;text-transform:uppercase;letter-spacing:.5px}
        .vlabel{font-size:13px;color:#e6e6f0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-word}
        .vnode.entry .vlabel{color:#9fd0ff}
        .vnode.sink .vlabel{color:#ffb3bd}

        .fix-header{display:flex;align-items:center;gap:12px;margin-bottom:12px}
        .fix-header .panel-title{margin:0}
        .risk-chip{font-size:11px;font-weight:700;letter-spacing:.5px;border-radius:12px;padding:3px 10px}
        .risk-critical{background:#4a1020;color:#ff8fae}
        .risk-high{background:#5c1f28;color:#ffb3bd}
        .risk-medium{background:#5c4a1f;color:#ffe0a3}
        .risk-low{background:#1f5c3a;color:#a3ffc8}
        .risk-unknown{background:#2a2a4a;color:#b8b8d8}

        .fix-card{margin-top:14px;background:#0a0a16;border:1px solid #1c1c33;border-radius:10px;overflow:hidden}
        .fix-model{font-size:11px;color:#8c8ca8;padding:8px 12px;border-bottom:1px solid #1c1c33;background:#0e0e1a;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
        .fix-md{margin:0;padding:16px;font-size:12.5px;line-height:1.6;color:#d8d8ec;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;max-height:520px;overflow:auto}
      `}</style>
    </div>
  );
}

function StatusItem({ label, value, mono }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="si">
      <span className="si-lbl">{label}</span>
      <span className={`si-val ${mono ? "mono" : ""}`} title={String(value)}>{value}</span>
    </div>
  );
}

function Count({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="count">
      <span className="count-val">{value}</span>
      <span className="count-lbl">{label}</span>
    </div>
  );
}
