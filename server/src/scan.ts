import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Request, Response } from "express";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "../..");
const GITHUB_URL_RE = /^https:\/\/github\.com\/[^/\s]+\/[^/\s#?]+?(\.git)?\/?$/;

type Verdict = "SAFE" | "UNSAFE" | "NEEDS_INVESTIGATION" | "ERROR";

function verdictFor(code: number | null): Verdict {
  if (code === 0) return "SAFE";
  if (code === 2) return "UNSAFE";
  if (code === 1) return "NEEDS_INVESTIGATION";
  return "ERROR";
}

export function scanHandler(req: Request, res: Response) {
  const url = typeof req.body?.url === "string" ? req.body.url.trim() : "";
  if (!GITHUB_URL_RE.test(url)) {
    res.status(400).json({ error: "Invalid GitHub HTTPS URL" });
    return;
  }

  res.status(200);
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const send = (event: string, data: unknown) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  const child = spawn("python3", ["osm_scan.py", url, "--no-report"], {
    cwd: REPO_ROOT,
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
  });

  const lineEmitter = (stream: NodeJS.ReadableStream, kind: "log" | "stderr") => {
    let buf = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk: string) => {
      buf += chunk;
      let idx: number;
      while ((idx = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        send(kind, line);
      }
    });
    stream.on("end", () => {
      if (buf.length > 0) {
        send(kind, buf);
        buf = "";
      }
    });
  };

  lineEmitter(child.stdout, "log");
  lineEmitter(child.stderr, "stderr");

  child.on("error", (err) => {
    send("error", { message: `Failed to start scanner: ${err.message}` });
    res.end();
  });

  child.on("close", (code) => {
    send("verdict", { exitCode: code, verdict: verdictFor(code) });
    res.end();
  });

  res.on("close", () => {
    if (!child.killed && child.exitCode === null) {
      child.kill("SIGTERM");
    }
  });
}
