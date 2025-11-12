import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import mongoose from "mongoose";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import fs from "fs";
import axios from "axios";

dotenv.config();

const app = express();
app.use(helmet());
app.use(express.json());
app.use(
  cors({
    origin: process.env.CORS_ORIGINS?.split(",") || ["http://localhost:3000"],
    credentials: true,
  })
);
app.use(morgan("dev"));

const PORT = process.env.PORT || 8005;
const NAME = process.env.SERVICE_NAME || "audit-service";
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://localhost:27017/des_audit";
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY_PATH
  ? fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH, "utf8")
  : process.env.JWT_PUBLIC_KEY || "";

const auditSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now, index: true },
  actorId: { type: String, index: true },
  actorRole: String,
  action: { type: String, index: true },
  entityType: { type: String, index: true },
  entityId: String,
  metadata: Object,
  ip: String,
  userAgent: String,
  severity: {
    type: String,
    enum: ["INFO", "WARNING", "ERROR", "CRITICAL"],
    default: "INFO",
  },
  status: { type: String, enum: ["SUCCESS", "FAILURE"], default: "SUCCESS" },
});

// Add compound indexes for common queries
auditSchema.index({ timestamp: -1, actorId: 1 });
auditSchema.index({ action: 1, timestamp: -1 });
auditSchema.index({ severity: 1, timestamp: -1 });

const Audit = mongoose.model("Audit", auditSchema);

// Security-sensitive actions for audit classification
const SECURITY_ACTIONS = new Set([
  "LOGIN_SUCCESS",
  "LOGIN_FAILURE",
  "ACCOUNT_LOCKED",
  "VALIDATION_FAILURE",
  "ACCESS_CONTROL_FAILURE",
  "SESSION_REVOKE",
  "SESSIONS_REVOKE_ALL",
  "PASSWORD_CHANGE_SUCCESS",
  "PASSWORD_CHANGE_FAILURE",
  "PASSWORD_RESET_ADMIN",
  "PASSWORD_RESET_USER",
  "SECURITY_ANSWER_FAILURE",
  "JWT_VERIFICATION_FAILURE",
]);

// Entity types classified as security-related
const SECURITY_ENTITY_TYPES = new Set([
  "Authentication",
  "ValidationError",
  "Authz",
  "Session",
  "AccountSecurity",
]);

function requireAdmin(req, res, next) {
  const header = req.headers["authorization"] || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const claims = jwt.verify(token, JWT_PUBLIC_KEY, { algorithms: ["RS256"] });
    if (claims.role !== "ADMIN")
      return res.status(403).json({ error: "Forbidden" });
    req.user = claims;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function normalizeActor(actorId, actorRole) {
  return {
    actorId: actorId && String(actorId).trim() ? String(actorId) : "ANONYMOUS",
    actorRole:
      actorRole && String(actorRole).trim() ? String(actorRole) : "UNKNOWN",
  };
}

function setCacheHeaders(res) {
  res.set("Cache-Control", "no-store");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
}

app.get("/health", (req, res) => res.json({ status: "ok", service: NAME }));

// Write audit (no auth enforced here for simplicity; could use shared secret or mTLS in prod)
app.post("/audit", async (req, res) => {
  try {
    const {
      timestamp,
      actorId,
      actorRole,
      action,
      entityType,
      entityId,
      metadata,
      severity,
      status,
    } = req.body || {};

    if (!action || typeof action !== "string") {
      return res.status(400).json({ error: "action is required (string)" });
    }
    if (!entityType || typeof entityType !== "string") {
      return res.status(400).json({ error: "entityType is required (string)" });
    }

    // Skip refresh events entirely (not important)
    const normalizedAction = String(action).toUpperCase();
    if (
      normalizedAction === "REFRESH_SUCCESS" ||
      normalizedAction === "REFRESH_FAILURE"
    ) {
      return res.status(204).end();
    }

    const { actorId: normActorId, actorRole: normActorRole } = normalizeActor(
      actorId,
      actorRole
    );

    const ip = req.ip;
    const userAgent =
      req.headers["user-agent"] ||
      (metadata && metadata.userAgent) ||
      undefined;

    const docToCreate = {
      timestamp: timestamp ? new Date(timestamp) : undefined,
      actorId: normActorId,
      actorRole: normActorRole,
      action: String(action).toUpperCase(),
      entityType,
      entityId,
      metadata,
      ip,
      userAgent,
      severity,
      status,
    };

    // Remove undefined to avoid overwriting defaults
    Object.keys(docToCreate).forEach(
      (k) => docToCreate[k] === undefined && delete docToCreate[k]
    );

    // Guard against hanging writes
    const write = Audit.create(docToCreate);
    const timeoutMs = parseInt(process.env.WRITE_TIMEOUT_MS || "8000", 10);
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Write timeout")), timeoutMs)
    );

    const created = await Promise.race([write, timeout]);
    return res.status(201).json({ id: created._id });
  } catch (err) {
    const isValidation =
      err?.name === "ValidationError" || /validation/i.test(err?.message || "");
    if (isValidation) {
      return res
        .status(400)
        .json({ error: "ValidationError", details: err.message });
    }
    console.error("[AUDIT] Write error:", err?.message || err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

// Admin-only read/filter
app.get("/audit", requireAdmin, async (req, res) => {
  const { actorId, action, entityType, from, to } = req.query;
  const q = {};
  if (actorId) q.actorId = actorId;
  if (action) q.action = action;
  if (entityType) q.entityType = entityType;
  if (from || to) q.timestamp = {};
  if (from) q.timestamp.$gte = new Date(from);
  if (to) q.timestamp.$lte = new Date(to);

  const items = await Audit.find(q).sort({ timestamp: -1 }).limit(500);
  setCacheHeaders(res);
  res.json(items);
});

// Security Audit: security-sensitive events and failures
// Admin-only. Supports filters: actorId, from, to. Optionally action/entityType override.
app.get("/audit/security", requireAdmin, async (req, res) => {
  const { actorId, action, entityType, from, to } = req.query;

  const q = {};
  if (actorId) q.actorId = actorId;

  // Base security classification: by action set OR severity >= WARNING OR entityType security-related
  q.$or = [
    { action: { $in: Array.from(SECURITY_ACTIONS) } },
    { severity: { $in: ["WARNING", "ERROR", "CRITICAL"] } },
    { entityType: { $in: Array.from(SECURITY_ENTITY_TYPES) } },
  ];

  // Optional explicit overrides
  if (action) q.action = action;
  if (entityType) q.entityType = entityType;
  if (from || to) q.timestamp = {};
  if (from) q.timestamp.$gte = new Date(from);
  if (to) q.timestamp.$lte = new Date(to);

  const items = await Audit.find(q).sort({ timestamp: -1 }).limit(500);
  setCacheHeaders(res);
  res.json(items);
});

// Action Audit: general business actions (show all non-security, any severity)
// Admin-only. Supports filters: actorId, action, entityType, from, to
app.get("/audit/actions", requireAdmin, async (req, res) => {
  const { actorId, action, entityType, from, to } = req.query;

  const q = {};
  if (actorId) q.actorId = actorId;

  // Exclude events deemed security-related by action or entityType
  const actionExclusion = { action: { $nin: Array.from(SECURITY_ACTIONS) } };
  const entityTypeExclusion = {
    entityType: { $nin: Array.from(SECURITY_ENTITY_TYPES) },
  };

  // If explicit filters are provided, respect them; otherwise exclude security-classified ones
  if (action) {
    q.action = action;
  } else {
    Object.assign(q, actionExclusion);
  }
  if (entityType) {
    q.entityType = entityType;
  } else {
    Object.assign(q, entityTypeExclusion);
  }

  if (from || to) q.timestamp = {};
  if (from) q.timestamp.$gte = new Date(from);
  if (to) q.timestamp.$lte = new Date(to);

  const items = await Audit.find(q).sort({ timestamp: -1 }).limit(500);
  setCacheHeaders(res);
  res.json(items);
});

export async function start() {
  await mongoose.connect(MONGO_URI);
  app.listen(PORT, () => console.log(`${NAME} listening on :${PORT}`));
}

if (process.env.NODE_ENV !== "test") {
  start().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

export default app;
