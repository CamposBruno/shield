import { useEffect, useReducer, useRef, useState } from "react";
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { startScan, type VerdictPayload } from "@/lib/scan";

const GITHUB_URL_RE = /^https:\/\/github\.com\/[^/\s]+\/[^/\s#?]+?(\.git)?\/?$/;

type LogEntry = { kind: "log" | "stderr"; line: string };

type State = {
  status: "idle" | "scanning" | "done" | "error";
  logs: LogEntry[];
  verdict?: VerdictPayload;
  error?: string;
};

type Action =
  | { type: "start" }
  | { type: "log"; entry: LogEntry }
  | { type: "verdict"; payload: VerdictPayload }
  | { type: "error"; message: string }
  | { type: "reset" };

const initial: State = { status: "idle", logs: [] };

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "start":
      return { status: "scanning", logs: [], verdict: undefined, error: undefined };
    case "log":
      return { ...state, logs: [...state.logs, action.entry] };
    case "verdict":
      return { ...state, status: "done", verdict: action.payload };
    case "error":
      return { ...state, status: "error", error: action.message };
    case "reset":
      return initial;
  }
}

export default function App() {
  const [state, dispatch] = useReducer(reducer, initial);
  const [url, setUrl] = useState("");
  const logRef = useRef<HTMLPreElement>(null);
  const ctrlRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [state.logs]);

  useEffect(() => () => ctrlRef.current?.abort(), []);

  const valid = GITHUB_URL_RE.test(url.trim());
  const scanning = state.status === "scanning";

  const handleScan = () => {
    if (!valid || scanning) return;
    dispatch({ type: "start" });
    ctrlRef.current?.abort();
    ctrlRef.current = startScan(url.trim(), {
      onLog: (line, stream) => dispatch({ type: "log", entry: { kind: stream, line } }),
      onVerdict: (payload) => dispatch({ type: "verdict", payload }),
      onError: (message) => dispatch({ type: "error", message }),
    });
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container max-w-3xl py-10">
        <header className="mb-8 flex items-center gap-3">
          <Shield className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Shield</h1>
            <p className="text-sm text-muted-foreground">
              Scan a GitHub repository for malicious dependencies.
            </p>
          </div>
        </header>

        <Card>
          <CardHeader>
            <CardTitle>New scan</CardTitle>
            <CardDescription>
              Paste a public GitHub HTTPS URL (e.g. <code>https://github.com/owner/repo</code>).
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                handleScan();
              }}
            >
              <Input
                type="url"
                placeholder="https://github.com/owner/repo"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={scanning}
                spellCheck={false}
                autoFocus
              />
              <Button type="submit" disabled={!valid || scanning}>
                {scanning ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Scanning
                  </>
                ) : (
                  "Scan"
                )}
              </Button>
            </form>
            {!valid && url.length > 0 && (
              <p className="mt-2 text-xs text-muted-foreground">
                URL must look like <code>https://github.com/owner/repo</code>.
              </p>
            )}
          </CardContent>
        </Card>

        {state.error && (
          <Alert variant="destructive" className="mt-6">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Scan failed</AlertTitle>
            <AlertDescription>{state.error}</AlertDescription>
          </Alert>
        )}

        {(state.logs.length > 0 || scanning || state.verdict) && (
          <Card className="mt-6">
            <CardHeader className="flex flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle>Report</CardTitle>
                <CardDescription>Live output from scan script</CardDescription>
              </div>
              {state.verdict && <VerdictBadge v={state.verdict} />}
            </CardHeader>
            <CardContent>
              <pre
                ref={logRef}
                className="h-[28rem] overflow-auto rounded-md border bg-black/40 p-4 font-mono text-xs leading-relaxed text-foreground/90"
              >
                {state.logs.map((entry, i) => (
                  <div
                    key={i}
                    className={entry.kind === "stderr" ? "text-amber-400" : undefined}
                  >
                    {entry.line || " "}
                  </div>
                ))}
                {scanning && <div className="text-muted-foreground">…</div>}
              </pre>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

function VerdictBadge({ v }: { v: VerdictPayload }) {
  if (v.verdict === "SAFE") {
    return (
      <Badge variant="success" className="gap-1 text-sm">
        <ShieldCheck className="h-3.5 w-3.5" />
        SAFE
      </Badge>
    );
  }
  if (v.verdict === "UNSAFE") {
    return (
      <Badge variant="danger" className="gap-1 text-sm">
        <ShieldAlert className="h-3.5 w-3.5" />
        UNSAFE
      </Badge>
    );
  }
  if (v.verdict === "NEEDS_INVESTIGATION") {
    return (
      <Badge variant="warning" className="gap-1 text-sm">
        <AlertTriangle className="h-3.5 w-3.5" />
        NEEDS INVESTIGATION
      </Badge>
    );
  }
  return (
    <Badge variant="secondary" className="gap-1 text-sm">
      ERROR (exit {v.exitCode ?? "?"})
    </Badge>
  );
}

