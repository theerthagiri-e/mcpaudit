import express from "express";
import { authMiddleware } from "./auth.js";
import { buildDefaultAllowedHosts } from "./allowed-hosts.js";

const host = process.env.HOST || "localhost";
const app = express();
const allowed = buildDefaultAllowedHosts(host, 3000);
app.post("/mcp", authMiddleware, async (req, res) => { res.end(); });
app.listen(3000, host);
