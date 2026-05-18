# Shield

Scan a GitHub repository (and its declared dependencies) against the [OpenSourceMalware](https://opensourcemalware.com) API and stream the verdict back to a small web UI.

## How it works

- **`osm_scan.py`** — Python scanner. Resolves the repo + its package manifests, queries the OSM `check-malicious` endpoint for each artifact, and exits with a verdict-bearing status code (`0` SAFE, `1` NEEDS_INVESTIGATION, `2` UNSAFE).
- **`server/`** — Express + TypeScript. Exposes `POST /v1/scan`, spawns the Python scanner, and streams `log` / `stderr` / `verdict` events to the client over SSE. Also serves the built client.
- **`client/`** — React + Vite + Tailwind. Takes a GitHub URL, opens the SSE stream, and renders live logs + the final verdict.

## Setup

Requires Node 20+ and Python 3.

```bash
npm install
export OSM_TOKEN=your_opensourcemalware_token
```

## Development

```bash
npm run dev
```

Runs the server (`:8080`) and the Vite dev server concurrently.

## Production build

```bash
npm run build
npm start
```

Serves the built client from the Express server on `PORT` (default `8080`).

## CLI usage

The scanner can also be run directly:

```bash
OSM_TOKEN=... python3 osm_scan.py https://github.com/owner/repo
```

Add `--no-report` to skip submitting a threat report on UNSAFE findings.
