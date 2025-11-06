import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(helmet());
app.use(rateLimit({ windowMs: 60 * 1000, max: 20 }));

app.use("/", express.static(path.join(__dirname, "../frontend")));

app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/api/scan", async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: "Missing URL" });
  res.json({ url, trusted: Math.random() > 0.5, payment_safe: Math.random() > 0.5 });
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log("AI TrustAdvisor server running on port", port));
