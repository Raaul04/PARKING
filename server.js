import express from "express";
import mongoose from "mongoose";
import helmet from "helmet";
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
// necesario en Render para que rate-limit identifique la IP real
app.set("trust proxy", 1);

// seguridad
app.use(helmet());
if (process.env.NODE_ENV === "production") {
  // fuerza HTTPS en navegadores
  app.use(helmet.hsts({ maxAge: 15552000 })); // ~180 días
}
app.use(mongoSanitize());

// parsers (con límite para evitar floods)
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: true, limit: "20kb" }));

// rate limit (anti-spam global)
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// límites específicos
const signLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 5,              // 5 firmas/min/IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: "Demasiadas firmas seguidas. Inténtalo en 1 minuto." },
});
app.use("/api/sign", signLimiter);

const adminLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 min
  max: 30,                 // 30 req / 5 min / IP
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests",
});
app.use("/admin", adminLimiter);

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

// API firmas (mismo origen; no necesitamos CORS)
app.use("/api/sign", signaturesRouter);

// 404 sencillo
app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) return res.status(404).json({ ok: false, error: "No encontrado" });
  return res.status(404).send("No encontrado");
});

// manejador de errores (evita 500 feos)
app.use((err, req, res, next) => {
  console.error("❌ Unhandled error:", err);
  if (req.path.startsWith("/api/")) {
    return res.status(500).json({ ok: false, error: "Error de servidor" });
  }
  return res.status(500).send("Error de servidor");
});

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
