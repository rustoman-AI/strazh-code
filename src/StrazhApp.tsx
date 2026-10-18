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

interface ExploitationPath {
  entry_point: string;
  target_component: string;
  vulnerability_id: string;
  proof_chain: string[];
}

interface DatalogResult {
  exploitation_paths: ExploitationPath[];
  blast_radius: { vulnerability_id: string; vulnerable_component: string; total_affected: number }[];
  stats: {
    total_facts: number;
    total_derived: number;
    components_analyzed: number;
    vulnerabilities_analyzed: number;
    entry_points_analyzed: number;
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

function riskFrom(text: string): "HIGH" | "MEDIUM" | "LOW" | null {
  const t = text.toUpperCase();
  if (t.includes("HIGH")) return "HIGH";
  if (t.includes("MEDIUM")) return "MEDIUM";
  if (t.includes("LOW")) return "LOW";
  return null;
}

export default function StrazhApp() {
  const [repoPath, setRepoPath] = useState<string>("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState<string>("");

  const [code, setCode] = useState<CodeGraphResult | null>(null);
  const [datalog, setDatalog] = useState<DatalogResult | null>(null);

  const [selected, setSelected] = useState<number | null>(null);
  const [fix, setFix] = useState<NemotronFix | null>(null);
  const [fixError, setFixError] = useState<string>("");

  const pickRepo = useCallback(async () => {
    setError("");
    const dir = await open({ directory: true, multiple: false, title: "Select a repository to scan" });
    if (typeof dir === "string") {
      setRepoPath(dir);
      setCode(null);
      setDatalog(null);
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

      // Attack paths are derived ONLY from the scanned repo: its real entry
      // files and the dependencies declared in its own manifests. We do not
      // inject any sample SBOM, so a path appears only if it is grounded in
      // this repository. No bundled/sample CVE is used.
      const paths = await invoke<DatalogResult>("compute_attack_paths", {
        sbomJson: null,
        astRoot: repoPath,
      });
      setDatalog(paths);
      setSelected(paths.exploitation_paths.length > 0 ? 0 : null);
      setPhase("scanned");
    } catch (e) {
      setError(String(e));
      setPhase("idle");
    }
  }, [repoPath]);

  const generateFix = useCallback(async () => {
    if (!datalog || selected === null) return;
    const path = datalog.exploitation_paths[selected];
    setPhase("fixing");
    setFix(null);
    setFixError("");
    try {
      const res = await invoke<NemotronFix>("generate_nemotron_fix", {
        vulnId: path.vulnerability_id,
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
  }, [datalog, selected]);

  const paths = datalog?.exploitation_paths ?? [];
  const activePath = selected !== null ? paths[selected] : null;

  const languages = useMemo(() => {
    if (!code) return [] as [string, number][];
    return Object.entries(code.stats.languages).sort((a, b) => b[1] - a[1]);
  }, [code]);

  const fixRisk = fix ? riskFrom(fix.fix_markdown) : null;

  // Status bar values
  const repoName = basename(repoPath);
  const filesScanned = code ? code.stats.total_files : null;
  const pathsFound = datalog ? paths.length : null;

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
              <Count label="Attack paths" value={datalog ? paths.length : 0} />
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

            {!datalog && (
              <p className="muted">Pick a repository and run a scan to compute attack paths from the graph.</p>
            )}
            {datalog && paths.length === 0 && (
              <p className="muted">
                No exploitable path: {repoName || "this repo"} was scanned ({datalog.stats.entry_points_analyzed} entry points) and no attack path grounded in its own dependencies was found.
              </p>
            )}

            {paths.length > 1 && (
              <div className="path-tabs">
                {paths.map((p, i) => (
                  <button
                    key={i}
                    className={`path-tab ${selected === i ? "active" : ""}`}
                    onClick={() => { setSelected(i); setFix(null); }}
                  >
                    {p.vulnerability_id}
                  </button>
                ))}
              </div>
            )}

            {activePath && (
              <div className="chain-wrap">
                <div className="chain-vuln">
                  <span className="vuln-badge">{activePath.vulnerability_id}</span>
                </div>
                <ol className="vchain">
                  <li className="vnode entry">
                    <span className="vrole">entry</span>
                    <span className="vlabel">{activePath.entry_point}</span>
                  </li>
                  {activePath.proof_chain.map((hop, i) => (
                    <li key={i} className="vnode hop">
                      <span className="vrole">hop {i + 1}</span>
                      <span className="vlabel">{hop}</span>
                    </li>
                  ))}
                  <li className="vnode sink">
                    <span className="vrole">sink</span>
                    <span className="vlabel">{activePath.target_component}</span>
                  </li>
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

        .chain-vuln{margin-bottom:12px}
        .vuln-badge{background:#5c1f28;color:#ffb3bd;border-radius:6px;padding:4px 10px;font-size:12px;font-weight:700;letter-spacing:.3px}

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
        .risk-high{background:#5c1f28;color:#ffb3bd}
        .risk-medium{background:#5c4a1f;color:#ffe0a3}
        .risk-low{background:#1f5c3a;color:#a3ffc8}

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
