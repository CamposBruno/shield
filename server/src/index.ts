import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanHandler } from "./scan.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 8080);

const app = express();
app.use(express.json());

app.post("/v1/scan", scanHandler);

const clientDist = path.resolve(__dirname, "../../client/dist");
app.use(express.static(clientDist));
app.get("*", (_req, res) => {
  res.sendFile(path.join(clientDist, "index.html"));
});

app.listen(PORT, () => {
  console.log(`shield server listening on http://localhost:${PORT}`);
});
