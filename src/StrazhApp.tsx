import { useState, useCallback } from "react";
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
      // 1. Real AST / supply-chain scan of the repo
      const codeRes = await invoke<CodeGraphResult>("scan_code_graph", { rootDir: repoPath });
      setCode(codeRes);

      // 2. SBOM (CycloneDX)
      const sbomRes = await invoke<string>("generate_sbom");

      // 3. Attack paths from the graph (Datalog over SBOM + AST)
      const paths = await invoke<DatalogResult>("compute_attack_paths", {
        sbomJson: sbomRes,
        astRoot: repoPath,
      });
      setDatalog(paths);
      // Preselect the first attack path if any
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

  return (
    <div className="strazh-root">
      <header className="strazh-header">
        <div className="strazh-brand">
          <span className="strazh-logo">🛡️</span>
          <div>
            <h1>Strazh</h1>
            <p>Supply-chain attack paths, fixed by NVIDIA Nemotron on Nebius Token Factory</p>
          </div>
        </div>
      </header>

      <div className="strazh-flow">
        {/* Step 1: point at a repo */}
        <section className="strazh-step">
          <div className="step-num">1</div>
          <div className="step-body">
            <h2>Point at a repository</h2>
            <div className="repo-row">
              <button className="btn" onClick={pickRepo}>Choose folder…</button>
              <code className="repo-path">{repoPath || "No repository selected"}</code>
            </div>
          </div>
        </section>

        {/* Step 2: scan */}
        <section className="strazh-step">
          <div className="step-num">2</div>
          <div className="step-body">
            <h2>Scan (SBOM + attack paths)</h2>
            <button className="btn btn-primary" onClick={scan} disabled={!repoPath || phase === "scanning"}>
              {phase === "scanning" ? "Scanning…" : "Run scan"}
            </button>
            {error && <div className="alert">{error}</div>}
            {code && (
              <div className="scan-summary">
                <Stat label="Files" value={code.stats.total_files} />
                <Stat label="Lines" value={code.stats.total_lines} />
                <Stat label="Imports" value={code.stats.total_imports} />
                <Stat label="Declared deps" value={code.stats.declared_deps} />
                <Stat label="Build systems" value={code.stats.build_systems.join(", ") || "—"} />
                {datalog && <Stat label="Attack paths" value={paths.length} />}
              </div>
            )}
          </div>
        </section>

        {/* Step 3: one attack path */}
        <section className="strazh-step">
          <div className="step-num">3</div>
          <div className="step-body">
            <h2>Attack path</h2>
            {!datalog && <p className="muted">Run a scan to compute attack paths from the graph.</p>}
            {datalog && paths.length === 0 && (
              <p className="muted">
                No exploitation paths were derived from this repo's current SBOM. The scan found{" "}
                {datalog.stats.components_analyzed} components and{" "}
                {datalog.stats.entry_points_analyzed} entry points. Try a repo whose SBOM carries
                known vulnerabilities, or load a richer SBOM.
              </p>
            )}
            {paths.length > 0 && (
              <>
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
                  <div className="path-card">
                    <div className="path-head">
                      <span className="vuln-badge">{activePath.vulnerability_id}</span>
                      <span className="path-target">→ {activePath.target_component}</span>
                    </div>
                    <div className="path-chain">
                      <span className="chain-node entry">{activePath.entry_point}</span>
                      {activePath.proof_chain.map((hop, i) => (
                        <span key={i} className="chain-node">
                          <span className="chain-arrow">→</span>
                          {hop}
                        </span>
                      ))}
                      <span className="chain-node target">
                        <span className="chain-arrow">→</span>
                        {activePath.target_component}
                      </span>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </section>

        {/* Step 4: Nemotron fix */}
        <section className="strazh-step">
          <div className="step-num">4</div>
          <div className="step-body">
            <h2>Nemotron-written fix</h2>
            <button
              className="btn btn-primary"
              onClick={generateFix}
              disabled={!activePath || phase === "fixing"}
            >
              {phase === "fixing" ? "Asking Nemotron…" : "Generate fix with Nemotron"}
            </button>
            {fixError && <div className="alert">{fixError}</div>}
            {fix && (
              <div className="fix-card">
                <div className="fix-model">model: {fix.model}</div>
                <pre className="fix-md">{fix.fix_markdown}</pre>
              </div>
            )}
          </div>
        </section>
      </div>

      <footer className="strazh-footer">
        Live analysis runs on <strong>NVIDIA Nemotron</strong> via{" "}
        <strong>Nebius Token Factory</strong>. Set <code>NEBIUS_API_KEY</code> in your environment.
      </footer>

      <style>{`
        .strazh-root{min-height:100vh;background:#0a0a16;color:#e6e6f0;font-family:system-ui,-apple-system,sans-serif;display:flex;flex-direction:column}
        .strazh-header{padding:20px 28px;border-bottom:1px solid #1c1c33;background:#0e0e1a}
        .strazh-brand{display:flex;align-items:center;gap:14px}
        .strazh-logo{font-size:34px}
        .strazh-brand h1{margin:0;font-size:22px;letter-spacing:.5px}
        .strazh-brand p{margin:2px 0 0;font-size:12px;color:#8c8ca8}
        .strazh-flow{flex:1;max-width:860px;width:100%;margin:0 auto;padding:24px 20px;display:flex;flex-direction:column;gap:14px}
        .strazh-step{display:flex;gap:16px;background:#101024;border:1px solid #1c1c33;border-radius:12px;padding:18px 20px}
        .step-num{flex:0 0 32px;height:32px;border-radius:50%;background:#1a1a3a;color:#9f9fe0;display:flex;align-items:center;justify-content:center;font-weight:700}
        .step-body{flex:1;min-width:0}
        .step-body h2{margin:2px 0 12px;font-size:15px;color:#c9c9e8}
        .repo-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
        .repo-path{font-size:12px;color:#8c8ca8;background:#0a0a16;padding:6px 10px;border-radius:6px;border:1px solid #1c1c33;overflow:hidden;text-overflow:ellipsis;max-width:560px}
        .btn{background:#1a1a3a;color:#e6e6f0;border:1px solid #2a2a55;border-radius:8px;padding:8px 16px;font-size:13px;cursor:pointer;transition:all .15s}
        .btn:hover:not(:disabled){background:#24244d;border-color:#3a3a70}
        .btn:disabled{opacity:.45;cursor:not-allowed}
        .btn-primary{background:#4f46e5;border-color:#6366f1}
        .btn-primary:hover:not(:disabled){background:#5b52f0}
        .alert{margin-top:12px;padding:10px 12px;border-radius:8px;background:#2a1216;border:1px solid #5c1f28;color:#ffb3bd;font-size:12px;white-space:pre-wrap}
        .scan-summary{display:flex;flex-wrap:wrap;gap:18px;margin-top:14px}
        .stat{display:flex;flex-direction:column}
        .stat-val{font-size:18px;font-weight:700;color:#e6e6f0}
        .stat-lbl{font-size:11px;color:#8c8ca8;text-transform:uppercase;letter-spacing:.5px}
        .muted{color:#8c8ca8;font-size:13px;margin:0}
        .path-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
        .path-tab{background:#0a0a16;border:1px solid #1c1c33;color:#9f9fe0;border-radius:6px;padding:4px 10px;font-size:12px;cursor:pointer}
        .path-tab.active{background:#4f46e5;border-color:#6366f1;color:#fff}
        .path-card{background:#0a0a16;border:1px solid #1c1c33;border-radius:10px;padding:14px}
        .path-head{display:flex;align-items:center;gap:10px;margin-bottom:12px}
        .vuln-badge{background:#5c1f28;color:#ffb3bd;border-radius:6px;padding:3px 9px;font-size:12px;font-weight:700}
        .path-target{font-size:13px;color:#c9c9e8}
        .path-chain{display:flex;flex-wrap:wrap;align-items:center;gap:6px}
        .chain-node{display:inline-flex;align-items:center;gap:6px;background:#15152e;border:1px solid #24244d;border-radius:6px;padding:4px 9px;font-size:12px;color:#c9c9e8}
        .chain-node.entry{border-color:#3a6ea5;color:#9fd0ff}
        .chain-node.target{border-color:#5c1f28;color:#ffb3bd}
        .chain-arrow{color:#55557a}
        .fix-card{margin-top:14px;background:#0a0a16;border:1px solid #1c1c33;border-radius:10px;overflow:hidden}
        .fix-model{font-size:11px;color:#8c8ca8;padding:8px 12px;border-bottom:1px solid #1c1c33;background:#0e0e1a}
        .fix-md{margin:0;padding:14px;font-size:12.5px;line-height:1.55;color:#d8d8ec;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
        .strazh-footer{padding:14px 28px;border-top:1px solid #1c1c33;background:#0e0e1a;font-size:12px;color:#8c8ca8;text-align:center}
      `}</style>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="stat">
      <span className="stat-val">{value}</span>
      <span className="stat-lbl">{label}</span>
    </div>
  );
}
