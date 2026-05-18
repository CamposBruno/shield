export type Verdict = "SAFE" | "UNSAFE" | "NEEDS_INVESTIGATION" | "ERROR";

export interface VerdictPayload {
  exitCode: number | null;
  verdict: Verdict;
}

export interface ScanCallbacks {
  onLog?: (line: string, stream: "log" | "stderr") => void;
  onVerdict?: (v: VerdictPayload) => void;
  onError?: (message: string) => void;
}

export function startScan(url: string, cb: ScanCallbacks): AbortController {
  const ctrl = new AbortController();

  (async () => {
    let res: Response;
    try {
      res = await fetch("/v1/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
        body: JSON.stringify({ url }),
        signal: ctrl.signal,
      });
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        cb.onError?.(`Network error: ${(err as Error).message}`);
      }
      return;
    }

    if (!res.ok || !res.body) {
      let msg = `HTTP ${res.status}`;
      try {
        const data = await res.json();
        if (data?.error) msg = data.error;
      } catch {}
      cb.onError?.(msg);
      return;
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });

        let sep: number;
        while ((sep = buf.indexOf("\n\n")) !== -1) {
          const frame = buf.slice(0, sep);
          buf = buf.slice(sep + 2);
          handleFrame(frame, cb);
        }
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        cb.onError?.(`Stream error: ${(err as Error).message}`);
      }
    }
  })();

  return ctrl;
}

function handleFrame(frame: string, cb: ScanCallbacks) {
  let event = "message";
  const dataLines: string[] = [];
  for (const raw of frame.split("\n")) {
    if (raw.startsWith("event:")) event = raw.slice(6).trim();
    else if (raw.startsWith("data:")) dataLines.push(raw.slice(5).trimStart());
  }
  if (dataLines.length === 0) return;
  const data = dataLines.join("\n");

  let parsed: unknown;
  try {
    parsed = JSON.parse(data);
  } catch {
    return;
  }

  if (event === "log" && typeof parsed === "string") cb.onLog?.(parsed, "log");
  else if (event === "stderr" && typeof parsed === "string") cb.onLog?.(parsed, "stderr");
  else if (event === "verdict") cb.onVerdict?.(parsed as VerdictPayload);
  else if (event === "error") {
    const msg = (parsed as { message?: string })?.message ?? "Unknown error";
    cb.onError?.(msg);
  }
}
