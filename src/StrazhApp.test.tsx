import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import StrazhApp from "./StrazhApp";
import { open } from "@tauri-apps/plugin-dialog";
import { invoke } from "@tauri-apps/api/core";

// ── Mock the Tauri bridge ──
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const CODE = {
  source_nodes: [],
  import_edges: [],
  build_files: [],
  stats: {
    total_files: 235, total_lines: 35049, total_imports: 1137,
    languages: { python: 204 }, build_systems: ["python"],
    declared_deps: 547, internal_imports: 0, external_imports: 0,
  },
};

// Two deterministic findings. mkOsv builds a scan result; ids may repeat across
// scans to exercise the repeated-id case.
function mkOsv(a: string, b: string) {
  return {
    exploitation_paths: [
      { entry_point: "reqA/requirements.txt", target_component: "agno@1.7.2", vulnerability_id: a,
        severity: "CRITICAL", ecosystem: "PyPI", summary: "A summary", fixed_version: "2.3.24", proof_chain: [] },
      { entry_point: "reqB/requirements.txt", target_component: "litellm@1.74.1", vulnerability_id: b,
        severity: "HIGH", ecosystem: "PyPI", summary: "B summary", fixed_version: null, proof_chain: [] },
    ],
    stats: { dependencies_declared: 547, dependencies_queried: 473, vulnerable_dependencies: 2, entry_points: 14, advisories_found: 2 },
  };
}

type Deferred<T> = { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void };
function defer<T>(): Deferred<T> {
  let resolve!: (v: T) => void, reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const mockInvoke = invoke as unknown as ReturnType<typeof vi.fn>;
const mockOpen = open as unknown as ReturnType<typeof vi.fn>;

const PRO_STATUS = { pro: true, plan: "pro", name: "test", exp: 0, message: "Strazh Pro — active." };
const FREE_STATUS = { pro: false, plan: "none", name: "", exp: 0, message: "Free plan." };

async function runScan(osv = mkOsv("GHSA-AAAA", "GHSA-BBBB"), pro = false) {
  mockInvoke.mockImplementation(async (cmd: string) => {
    if (cmd === "license_status") return pro ? PRO_STATUS : FREE_STATUS;
    if (cmd === "scan_code_graph") return CODE;
    if (cmd === "scan_with_osv") return osv;
    throw new Error("unexpected " + cmd);
  });
  mockOpen.mockResolvedValueOnce("C:/repo/demo");
  fireEvent.click(screen.getAllByText("Choose repository")[0]);
  // The sidebar "Run scan" button is always present; click the first match.
  await waitFor(() => expect(screen.getAllByRole("button", { name: "Run scan" }).length).toBeGreaterThan(0));
  fireEvent.click(screen.getAllByRole("button", { name: "Run scan" })[0]);
  await screen.findByText("Findings");
}

// After a scan the sidebar "Run scan" button is the rescan trigger.
function clickRunScan() {
  fireEvent.click(screen.getAllByRole("button", { name: "Run scan" })[0]);
}

beforeEach(() => {
  mockInvoke.mockReset();
  mockOpen.mockReset();
});

describe("Strazh AI remediation isolation", () => {
  it("a response for finding A does not appear under finding B", async () => {
    render(<StrazhApp />);
    await runScan();

    // Row A is auto-selected (first). Set up a deferred generate for A.
    const genA = defer<{ model: string; fix_markdown: string }>();
    mockInvoke.mockImplementation(async (cmd: string, args: any) => {
      if (cmd === "generate_nemotron_fix") {
        if (args.vulnId === "GHSA-AAAA") return genA.promise;
        return { model: "m", fix_markdown: "## Advisory\nB fix" };
      }
      throw new Error("unexpected " + cmd);
    });

    fireEvent.click(screen.getByText("Generate suggestion"));
    // Switch to B while A is still pending.
    fireEvent.click(screen.getByText("GHSA-BBBB"));

    // Now resolve A's (stale) response.
    await act(async () => {
      genA.resolve({ model: "m", fix_markdown: "## Advisory\nA fix SHOULD NOT SHOW" });
      await Promise.resolve();
    });

    // B is selected; A's late response must not be rendered.
    expect(screen.queryByText(/A fix SHOULD NOT SHOW/)).toBeNull();
    // B shows its own empty/idle state: the generate button is back to its
    // initial label (not "Regenerate"), i.e. no suggestion exists for B.
    expect(screen.getByRole("button", { name: "Generate suggestion" })).toBeTruthy();
  });

  it("stale error cannot overwrite the newly selected finding", async () => {
    render(<StrazhApp />);
    await runScan();

    const genA = defer<never>();
    mockInvoke.mockImplementation(async (cmd: string, args: any) => {
      if (cmd === "generate_nemotron_fix") {
        if (args.vulnId === "GHSA-AAAA") return genA.promise;
        return { model: "m", fix_markdown: "ok" };
      }
      throw new Error("unexpected");
    });
    fireEvent.click(screen.getByText("Generate suggestion"));
    fireEvent.click(screen.getByText("GHSA-BBBB"));
    await act(async () => {
      genA.reject(new Error("A failed late"));
      await Promise.resolve();
    });
    // B must not show A's error.
    expect(screen.queryByText(/A failed late/)).toBeNull();
  });

  it("selection reset survives a rescan with repeated finding ids", async () => {
    render(<StrazhApp />);
    await runScan(mkOsv("GHSA-AAAA", "GHSA-BBBB"));

    // Generate for A, leave pending.
    const genA = defer<{ model: string; fix_markdown: string }>();
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "generate_nemotron_fix") return genA.promise;
      if (cmd === "scan_code_graph") return CODE;
      if (cmd === "scan_with_osv") return mkOsv("GHSA-AAAA", "GHSA-CCCC"); // id repeats (AAAA)
      throw new Error("unexpected");
    });
    fireEvent.click(screen.getByText("Generate suggestion"));

    // Rescan (same repo already selected) — new scan, repeated id AAAA.
    clickRunScan();
    await screen.findByText("GHSA-CCCC");

    // Late A response resolves; it must not appear under the new AAAA selection.
    await act(async () => {
      genA.resolve({ model: "m", fix_markdown: "STALE A AFTER RESCAN" });
      await Promise.resolve();
    });
    expect(screen.queryByText(/STALE A AFTER RESCAN/)).toBeNull();
  });

  it("blocks duplicate submissions while a generation is in flight", async () => {
    render(<StrazhApp />);
    await runScan();

    const gen = defer<{ model: string; fix_markdown: string }>();
    let calls = 0;
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "generate_nemotron_fix") { calls++; return gen.promise; }
      throw new Error("unexpected");
    });

    const btn = screen.getByText("Generate suggestion");
    fireEvent.click(btn);
    // Button now reads "Generating…" and is disabled.
    const busy = await screen.findByText("Generating…");
    fireEvent.click(busy);
    fireEvent.click(busy);
    expect(calls).toBe(1);

    await act(async () => { gen.resolve({ model: "m", fix_markdown: "## Advisory\ndone" }); await Promise.resolve(); });
  });

  it("shows the advisory-reported fix for A and 'Fix version not determined' for B", async () => {
    render(<StrazhApp />);
    await runScan();
    // A selected by default -> has fixed_version 2.3.24
    expect(screen.getByText(/Advisory-reported fix: 2\.3\.24/)).toBeTruthy();
    fireEvent.click(screen.getByText("GHSA-BBBB"));
    expect(screen.getByText(/Fix version not determined/)).toBeTruthy();
  });
});

describe("Pro license gating of Apply fix", () => {
  // Generate a suggestion for the selected (applicable) finding so the Apply
  // control renders. Finding A (agno@1.7.2, PyPI, fixed 2.3.24) is applicable.
  async function generateForA() {
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "license_status") return FREE_STATUS; // overridden by closures below when needed
      if (cmd === "generate_nemotron_fix") return { model: "m", fix_markdown: "## Recommended remediation\nUpgrade to 2.3.24" };
      throw new Error("unexpected " + cmd);
    });
    fireEvent.click(screen.getByText("Generate suggestion"));
    await screen.findByText(/AI suggestion/);
  }

  it("Free user sees a locked Apply button and gets the upgrade prompt instead of a write", async () => {
    render(<StrazhApp />);
    await runScan(mkOsv("GHSA-AAAA", "GHSA-BBBB"), /* pro */ false);
    await generateForA();

    // The Apply control is labeled as a Pro-locked action.
    const applyBtn = await screen.findByRole("button", { name: /Apply fix .* \(Pro\)/ });

    // Track whether apply_manifest_fix is ever called — it must not be.
    let applyCalls = 0;
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "license_status") return FREE_STATUS;
      if (cmd === "apply_manifest_fix") { applyCalls++; return { applied: true, manifest: "", package: "", from_version: "", to_version: "", message: "", original_content: "" }; }
      throw new Error("unexpected " + cmd);
    });

    fireEvent.click(applyBtn);

    // Upgrade dialog appears; backend apply was never invoked.
    expect(await screen.findByText(/Apply fix is a Pro feature/)).toBeTruthy();
    expect(applyCalls).toBe(0);
  });

  it("Pro user can apply — the backend command is invoked", async () => {
    let applyCalls = 0;
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "license_status") return PRO_STATUS;
      if (cmd === "scan_code_graph") return CODE;
      if (cmd === "scan_with_osv") return mkOsv("GHSA-AAAA", "GHSA-BBBB");
      if (cmd === "generate_nemotron_fix") return { model: "m", fix_markdown: "## Recommended remediation\nUpgrade to 2.3.24" };
      if (cmd === "apply_manifest_fix") {
        applyCalls++;
        return { applied: true, manifest: "reqA/requirements.txt", package: "agno", from_version: "1.7.2", to_version: "2.3.24", message: "Updated requirements.txt: agno 1.7.2 → 2.3.24", original_content: "agno==1.7.2\n" };
      }
      throw new Error("unexpected " + cmd);
    });
    mockOpen.mockResolvedValueOnce("C:/repo/demo");

    render(<StrazhApp />);
    // Wait for the Pro license to load (header badge reflects it).
    await waitFor(() => expect(screen.getByText("PRO")).toBeTruthy());

    fireEvent.click(screen.getAllByText("Choose repository")[0]);
    await waitFor(() => expect(screen.getAllByRole("button", { name: "Run scan" }).length).toBeGreaterThan(0));
    fireEvent.click(screen.getAllByRole("button", { name: "Run scan" })[0]);
    await screen.findByText("Findings");

    fireEvent.click(screen.getByText("Generate suggestion"));
    await screen.findByText(/AI suggestion/);

    // Pro label (no lock), and clicking applies via the backend.
    const applyBtn = await screen.findByRole("button", {
      name: (n) => n.includes("Apply fix") && n.includes("2.3.24") && !n.includes("Pro"),
    });
    await act(async () => { fireEvent.click(applyBtn); await Promise.resolve(); });

    expect(applyCalls).toBe(1);
    expect(await screen.findByText(/Updated requirements\.txt: agno 1\.7\.2 → 2\.3\.24/)).toBeTruthy();
  });
});
