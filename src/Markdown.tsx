import { useState, useCallback, type ReactNode } from "react";

// A small, safe Markdown renderer for AI remediation output.
//
// Supports: ATX headings (#..######), paragraphs, unordered (-,*) and ordered
// lists, fenced code blocks (``` with optional language) each with a Copy
// button, and inline `code` + **bold** + *italic* within text.
//
// Safety: content is rendered exclusively through React text nodes and
// elements. There is NO dangerouslySetInnerHTML and no HTML passthrough, so
// embedded HTML in the model output is shown as inert text, never executed.

type Block =
  | { type: "heading"; level: number; text: string }
  | { type: "paragraph"; text: string }
  | { type: "list"; ordered: boolean; items: string[] }
  | { type: "code"; lang: string; code: string };

function parseBlocks(src: string): Block[] {
  const lines = src.replace(/\r\n/g, "\n").split("\n");
  const blocks: Block[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    const fence = line.match(/^```(.*)$/);
    if (fence) {
      const lang = fence[1].trim();
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) {
        body.push(lines[i]);
        i++;
      }
      i++; // consume closing fence (if present)
      blocks.push({ type: "code", lang, code: body.join("\n") });
      continue;
    }

    // Blank line
    if (line.trim() === "") { i++; continue; }

    // Heading
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      blocks.push({ type: "heading", level: h[1].length, text: h[2].trim() });
      i++;
      continue;
    }

    // List (consecutive list lines)
    const isUl = (s: string) => /^\s*[-*]\s+/.test(s);
    const isOl = (s: string) => /^\s*\d+[.)]\s+/.test(s);
    if (isUl(line) || isOl(line)) {
      const ordered = isOl(line);
      const items: string[] = [];
      while (i < lines.length && (ordered ? isOl(lines[i]) : isUl(lines[i]))) {
        items.push(lines[i].replace(/^\s*(?:[-*]|\d+[.)])\s+/, ""));
        i++;
      }
      blocks.push({ type: "list", ordered, items });
      continue;
    }

    // Paragraph (gather until blank / block start)
    const para: string[] = [line];
    i++;
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !/^```/.test(lines[i]) &&
      !/^#{1,6}\s/.test(lines[i]) &&
      !/^\s*[-*]\s+/.test(lines[i]) &&
      !/^\s*\d+[.)]\s+/.test(lines[i])
    ) {
      para.push(lines[i]);
      i++;
    }
    blocks.push({ type: "paragraph", text: para.join(" ") });
  }

  return blocks;
}

// Render inline spans: `code`, **bold**, *italic*. Everything else is text.
function renderInline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  // Tokenize on the three inline constructs.
  const re = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let key = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("`")) {
      out.push(<code key={key++} className="md-inline-code">{tok.slice(1, -1)}</code>);
    } else if (tok.startsWith("**")) {
      out.push(<strong key={key++}>{tok.slice(2, -2)}</strong>);
    } else {
      out.push(<em key={key++}>{tok.slice(1, -1)}</em>);
    }
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function CodeBlock({ lang, code }: { lang: string; code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable — ignore */
    }
  }, [code]);

  return (
    <div className="md-code">
      <div className="md-code-head">
        <span className="md-code-lang">{lang || "code"}</span>
        <button className="md-copy" onClick={copy} aria-label="Copy code">
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="md-pre"><code>{code}</code></pre>
    </div>
  );
}

export function Markdown({ source }: { source: string }) {
  const blocks = parseBlocks(source || "");
  return (
    <div className="md">
      {blocks.map((b, i) => {
        if (b.type === "heading") {
          const H = `h${Math.min(b.level + 2, 6)}` as "h3" | "h4" | "h5" | "h6";
          return <H key={i} className="md-h">{renderInline(b.text)}</H>;
        }
        if (b.type === "code") return <CodeBlock key={i} lang={b.lang} code={b.code} />;
        if (b.type === "list") {
          return b.ordered ? (
            <ol key={i} className="md-list">{b.items.map((it, j) => <li key={j}>{renderInline(it)}</li>)}</ol>
          ) : (
            <ul key={i} className="md-list">{b.items.map((it, j) => <li key={j}>{renderInline(it)}</li>)}</ul>
          );
        }
        return <p key={i} className="md-p">{renderInline(b.text)}</p>;
      })}

      <style>{`
        .md{display:flex;flex-direction:column;gap:12px;max-width:72ch}
        .md-h{margin:6px 0 0;font-weight:600;color:var(--text);line-height:1.3}
        h3.md-h{font-size:16px} h4.md-h{font-size:14px} h5.md-h,h6.md-h{font-size:13px;color:var(--text-2)}
        .md-p{margin:0;font-size:14px;line-height:1.65;color:var(--text)}
        .md-list{margin:0;padding-left:22px;display:flex;flex-direction:column;gap:6px}
        .md-list li{font-size:14px;line-height:1.6;color:var(--text)}
        .md code,.md-inline-code{font-family:var(--mono);font-size:13px;background:var(--bg);
          border:1px solid var(--border);border-radius:4px;padding:1px 5px;color:var(--teal)}
        .md-code{border:1px solid var(--border);border-radius:8px;overflow:hidden;background:#0a0f16}
        .md-code-head{display:flex;align-items:center;justify-content:space-between;
          padding:6px 10px;background:var(--bg);border-bottom:1px solid var(--border)}
        .md-code-lang{font-family:var(--mono);font-size:11px;color:var(--text-2);text-transform:lowercase}
        .md-copy{font-size:12px;color:var(--text-2);background:transparent;border:1px solid var(--border);
          border-radius:6px;padding:3px 10px;cursor:pointer;transition:all .12s}
        .md-copy:hover{color:var(--teal);border-color:var(--teal)}
        .md-copy:focus-visible{outline:2px solid var(--teal);outline-offset:1px}
        .md .md-pre,.md-pre{margin:0;padding:12px 14px;overflow-x:auto;font-family:var(--mono);font-size:13px;
          line-height:1.6;color:var(--text);white-space:pre}
        .md-pre code{font-family:var(--mono)}
        .md-code-lang{font-family:var(--mono)}
      `}</style>
    </div>
  );
}
