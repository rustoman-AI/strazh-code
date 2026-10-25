import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Markdown } from "./Markdown";

describe("Markdown copy-code", () => {
  it("copies the exact fenced code block text to the clipboard", async () => {
    const writeText = vi.fn(async () => {});
    // jsdom has no clipboard; install a mock.
    Object.assign(navigator, { clipboard: { writeText } });

    const code = 'import ast\nresult = ast.literal_eval(x)\n# trailing';
    const md = ["## Recommended remediation", "Upgrade the package.", "", "```python", code, "```"].join("\n");

    render(<Markdown source={md} />);

    const copyBtn = screen.getByRole("button", { name: /copy code/i });
    fireEvent.click(copyBtn);

    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    // Exact text, verbatim, no markdown fences, no HTML transforms.
    expect(writeText).toHaveBeenCalledWith(code);
    // Copy feedback appears.
    await screen.findByText("Copied");
  });

  it("renders headings/lists without emitting literal markdown syntax", () => {
    const md = ["## Advisory", "- item one", "- item two", "Use `safe()` here."].join("\n");
    render(<Markdown source={md} />);
    // Heading text present without the '##'
    expect(screen.getByText("Advisory").textContent).toBe("Advisory");
    expect(screen.getByText("item one")).toBeTruthy();
    // inline code rendered as <code>, not backticks
    expect(screen.getByText("safe()").tagName.toLowerCase()).toBe("code");
  });
});
