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
// ✅ necesario en Render/hosting con proxy para que rate-limit use la IP real
app.set("trust proxy", 1);

// seguridad
app.use(helmet());
app.use(mongoSanitize());

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

/* ------------ CORS SOLO para la API (/api/**) ------------ */
// Orígenes permitidos: tu dominio de Render (auto), APP_ORIGIN (opcional) y local
const renderOrigin =
  process.env.RENDER_EXTERNAL_URL ||
  (process.env.RENDER_EXTERNAL_HOSTNAME
    ? `https://${process.env.RENDER_EXTERNAL_HOSTNAME}`
    : null);

const allowedOrigins = new Set(
  [
    process.env.APP_ORIGIN,     // p.ej. https://parking-comillas.onrender.com (opcional)
    renderOrigin,               // el que expone Render automáticamente
    "http://localhost:3000",
    "http://127.0.0.1:3000",
  ].filter(Boolean)
);

const corsOptions = {
  origin(origin, cb) {
    // Permite peticiones sin Origin (navegación directa/same-origin/curl)
    if (!origin) return cb(null, true);
    if (allowedOrigins.has(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
  },
};

// 👉 aplica CORS solo a la API (no a estáticos ni páginas)
app.use("/api", cors(corsOptions));
// preflight
app.options("/api/*", cors(corsOptions));

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
