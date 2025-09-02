import { Router } from "express";
import { body, validationResult } from "express-validator";
import Signature from "../models/Signature.js";

const router = Router();

/* --- Basic Auth para endpoints privados --- */
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

// ping
router.get("/ping", (_req, res) => res.json({ ok: true, pong: true }));

// total (PRIVADO)
router.get("/total", adminAuth, async (_req, res) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  const total = await Signature.countDocuments({ verified: true });
  res.json({ total });
});

// export CSV (PRIVADO)
router.get("/export.csv", adminAuth, async (_req, res) => {
  const docs = await Signature.find({ verified: true })
    .select("name email district comment createdAt -_id")
    .sort({ createdAt: -1 })
    .lean();

  const esc = (v = "") => `"${String(v).replaceAll('"','""')}"`;
  const header = ["name","email","district","comment","createdAt"].map(esc).join(",");
  const rows = docs.map(d => [d.name, d.email, d.district, d.comment, d.createdAt.toISOString()].map(esc).join(","));
  const csv = [header, ...rows].join("\r\n");

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="firmas.csv"');
  res.send(csv);
});

// guardar firma (PÚBLICO)
router.post(
  "/",
  [
    body("name").trim().notEmpty().isLength({ max: 140 }),
    body("email").isEmail().normalizeEmail(),
    body("district").trim().notEmpty().isLength({ max: 120 }),
    body("comment").optional().trim().isLength({ max: 280 }),
    body("consent").equals("on"),
  ],
  async (req, res) => {
    // honeypot
    const honey = (req.body.website || "").toString();
    if (honey) return res.json({ ok: false });

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ ok: false, errors: errors.array() });
    }

    const { name, email, district, comment } = req.body;

    try {
      await Signature.create({ name, email, district, comment });
      const accept = (req.headers.accept || "");
      if (accept.includes("text/html")) return res.redirect(303, "/gracias.html");
      return res.json({ ok: true });
    } catch (err) {
      if (err?.code === 11000) {
        return res.status(409).json({ ok: false, error: "Este email ya ha firmado" });
      }
      console.error(err);
      return res.status(500).json({ ok: false, error: "Error de servidor" });
    }
  }
);

export default router;
