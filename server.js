import express from "express";
import mongoose from "mongoose";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import mongoSanitize from "express-mongo-sanitize";
import path from "node:path";
import { fileURLToPath } from "node:url";
import "dotenv/config";

import signaturesRouter from "./routes/signatures.js";

/* ---------- Auth básica para zona privada ---------- */
function adminAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const [scheme, token] = auth.split(" ");
  if (scheme !== "Basic" || !token) {
    res.set("WWW-Authenticate", 'Basic realm="private"');
    return res.status(401).send("Auth required");
  }
  const [user, pass] = Buffer.from(token, "base64").toString().split(":");
  if (user === process.env.ADMIN_USER && pass === process.env.ADMIN_PASS) return next();
  return res.status(401).send("Unauthorized");
}

/* ------------------------ App ----------------------- */
const app = express();
app.disable("x-powered-by");

// seguridad
app.use(helmet());
app.use(mongoSanitize());
app.use(cors({ origin: true }));

// parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// rate limit (anti-spam global)
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// estáticos (landing en /public)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, "public")));

// rutas “bonitas” para archivos estáticos
app.get("/privacidad", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "privacidad.html"));
});
app.get("/gracias", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "gracias.html"));
});

// panel privado
app.get("/admin", adminAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// healthcheck
app.get("/health", (_req, res) => res.json({ ok: true }));

// API firmas
app.use("/api/sign", signaturesRouter);

/* ---------------------- Mongo & boot ---------------------- */
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error("❌ Falta MONGO_URI en .env");
  process.exit(1);
}

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("✅ Conectado a MongoDB");
    app.listen(PORT, () =>
      console.log(`🚀 Servidor en http://localhost:${PORT}`)
    );
  })
  .catch((err) => {
    console.error("❌ Error conectando a Mongo:", err.message);
    process.exit(1);
  });
