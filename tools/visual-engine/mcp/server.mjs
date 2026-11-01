#!/usr/bin/env node
/**
 * CredMgr visual-engine MCP facade (spec §7.3 Candidate C — SELECTED).
 *
 * A constrained agent-control adapter over the direct renderer. It is NOT the
 * source of chart truth and the project must work with it down — CI, batch and
 * fallback all use adapters/echarts/ directly (mcp/fallback-plan.md).
 *
 * Deliberate constraints (SECURITY_POLICY.md):
 *  - stdio transport only, local process, no network listener
 *  - tool surface limited to the approved eight visual.* tools
 *  - jobs pass the same fail-closed validation gates as the direct path
 *  - restricted-classification jobs are ALWAYS refused here (no override)
 *  - file output only inside <engine>/renders/ — no caller-chosen paths
 *  - no shell, no arbitrary JS, no external URLs, no cloud storage
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  renderSVG, renderPNG, renderInteractiveHTML, listPresets, listCapabilities,
  themes, explainSelection, validateVisualJob, writeEvidence, ENGINE_ROOT,
  ECHARTS_VERSION, ENGINE_VERSION,
} from "../adapters/echarts/render.mjs";

const RENDER_DIR = join(ENGINE_ROOT, "renders", "current");

const JobSchema = z.object({}).passthrough(); // full validation happens in validateVisualJob (fail-closed)

const server = new McpServer(
  { name: "credmgr-visuals", version: ENGINE_VERSION },
  { instructions: `CredMgr visualization engine (echarts@${ECHARTS_VERSION}, project-themed). ` +
    "Agents ORCHESTRATE: consult knowledge/CHART_USE_CASE_CATALOG.json, build a compact visual job packet " +
    "(schemas/visual-job.schema.json), then call visual_render. Documents/diagrams belong to tools/docgen — " +
    "call visual_explain_selection when unsure. NO_CHART is a valid outcome. Restricted-classification data is never rendered here." },
);

function jsonContent(obj) {
  return { content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] };
}

function refuseRestricted(job) {
  if (job?.classification === "restricted") {
    return { content: [{ type: "text", text: JSON.stringify({ refused: true, gate: "G-CONF", reason: "restricted-classification jobs are never rendered through MCP. Use the direct adapter with human sign-off (SECURITY_POLICY.md)." }) }], isError: true };
  }
  return null;
}

server.tool("visual_list_capabilities", "List supported visual families, themes, presets, formats and routing policy.", {}, async () => jsonContent(listCapabilities()));

server.tool("visual_list_presets", "List project presets (id, visual family, summary, required fields).", {}, async () =>
  jsonContent(Object.values(listPresets()).map(({ id, visual, family, summary, canonical_reader_question, required_fields, notes }) =>
    ({ id, visual, family, summary, canonical_reader_question, required_fields, notes }))));

server.tool("visual_get_theme", "Return an approved project theme (palette, semantic colors, fonts).",
  { theme: z.enum(["project-theme", "project-theme-dark", "project-theme-light", "print-theme"]).default("project-theme") },
  async ({ theme }) => jsonContent(themes()[theme]));

server.tool("visual_validate_job", "Validate a visual job packet against all gates without rendering. Returns ok/warnings or the failing gate.",
  { job: JobSchema }, async ({ job }) => {
    const refused = refuseRestricted(job); if (refused) return refused;
    try {
      const r = validateVisualJob(job);
      return jsonContent({ ok: true, no_chart: r.no_chart ?? false, warnings: r.warnings });
    } catch (e) {
      return { ...jsonContent({ ok: false, gate: e.gate ?? null, error: e.message }), isError: true };
    }
  });

server.tool("visual_render",
  "Render a validated visual job. formats: svg|png|html (any combination). Writes files under renders/current/ and returns paths + hashes + inline SVG.",
  { job: JobSchema, formats: z.array(z.enum(["svg", "png", "html"])).default(["svg"]) },
  async ({ job, formats }) => {
    const refused = refuseRestricted(job); if (refused) return refused;
    try {
      mkdirSync(RENDER_DIR, { recursive: true });
      const id = String(job.visual_id ?? "visual").replace(/[^A-Za-z0-9._-]/g, "_");
      const paths = {};
      let meta, svg;
      if (formats.includes("png")) {
        const r = await renderPNG(job);
        if (r.no_chart) return jsonContent(r);
        writeFileSync(join(RENDER_DIR, `${id}.png`), r.png);
        paths.png = join(RENDER_DIR, `${id}.png`);
        meta = r.meta; svg = r.svg;
      } else {
        const r = renderSVG(job);
        if (r.no_chart) return jsonContent(r);
        meta = r.meta; svg = r.svg;
      }
      if (formats.includes("svg")) {
        writeFileSync(join(RENDER_DIR, `${id}.svg`), svg);
        paths.svg = join(RENDER_DIR, `${id}.svg`);
      }
      if (formats.includes("html")) {
        const r = renderInteractiveHTML(job);
        writeFileSync(join(RENDER_DIR, `${id}.html`), r.html);
        paths.html = join(RENDER_DIR, `${id}.html`);
        meta = { ...meta, html_sha256: r.meta.html_sha256 };
      }
      meta.evidence_path = writeEvidence(meta);
      return jsonContent({ meta, paths, svg: formats.includes("svg") ? svg : undefined });
    } catch (e) {
      return { ...jsonContent({ ok: false, gate: e.gate ?? null, error: e.message }), isError: true };
    }
  });

server.tool("visual_render_batch", "Render up to 20 jobs (svg only). Per-job errors are reported, not thrown.",
  { jobs: z.array(JobSchema).max(20) },
  async ({ jobs }) => {
    const out = [];
    mkdirSync(RENDER_DIR, { recursive: true });
    for (const job of jobs) {
      const refused = refuseRestricted(job);
      if (refused) { out.push({ visual_id: job?.visual_id, refused: true, gate: "G-CONF" }); continue; }
      try {
        const r = renderSVG(job);
        if (r.no_chart) { out.push({ visual_id: job.visual_id, no_chart: true }); continue; }
        const id = String(job.visual_id ?? "visual").replace(/[^A-Za-z0-9._-]/g, "_");
        writeFileSync(join(RENDER_DIR, `${id}.svg`), r.svg);
        out.push({ visual_id: job.visual_id, path: join(RENDER_DIR, `${id}.svg`), svg_sha256: r.meta.svg_sha256 });
      } catch (e) {
        out.push({ visual_id: job?.visual_id, error: e.message, gate: e.gate ?? null });
      }
    }
    return jsonContent(out);
  });

server.tool("visual_explain_selection", "Explain which engine owns a visual family and why (docgen vs echarts vs NO_CHART).",
  { job: JobSchema }, async ({ job }) => jsonContent(explainSelection(job)));

const transport = new StdioServerTransport();
await server.connect(transport);
