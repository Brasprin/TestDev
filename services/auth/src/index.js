import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import fs from "fs";
import axios from "axios";

dotenv.config();

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: (origin, callback) => {
      const allowed = process.env.CORS_ORIGINS?.split(",").map((o) =>
        o.trim()
      ) || ["http://localhost:3000"];
      if (!origin || allowed.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("CORS not allowed"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(morgan("dev"));

// Centralized request validation helper
function badRequest(res, message = "invalid request") {
  return res.status(400).json({ error: message });
}

// Note: 404 and error handlers must be registered after all routes

const PORT = process.env.PORT || 8001;
const NAME = process.env.SERVICE_NAME || "auth-service";
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/des_auth";
const JWT_PRIVATE_KEY = process.env.JWT_PRIVATE_KEY_PATH
  ? fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH, "utf8")
  : process.env.JWT_PRIVATE_KEY || "";
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY_PATH
  ? fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH, "utf8")
  : process.env.JWT_PUBLIC_KEY || "";
const AUDIT_URL = process.env.AUDIT_URL || "http://localhost:8005";

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  firstName: String,
  lastName: String,
  passwordHash: String,
  role: {
    type: String,
    enum: ["ADMIN", "TEACHER", "STUDENT"],
    default: "STUDENT",
  },
  createdAt: { type: Date, default: Date.now },
  // Security additions
  failedLoginCount: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
  passwordChangedAt: { type: Date, default: null },
  passwordHistory: { type: [String], default: [] },
  lastLoginAt: { type: Date, default: null },
  lastFailedLoginAt: { type: Date, default: null },
  // Security questions (now supports multiple)
  securityQuestions: [
    {
      question: String,
      answerHash: String,
    },
  ],
});

const sessionSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  refreshTokenHash: String,
  issuedAt: Date,
  expiresAt: Date,
  revokedAt: Date,
  ip: String,
  userAgent: String,
});

const User = mongoose.model("User", userSchema);
const Session = mongoose.model("Session", sessionSchema);

function signAccessToken(payload, ttl = process.env.ACCESS_TOKEN_TTL || "15m") {
  return jwt.sign(payload, JWT_PRIVATE_KEY, {
    algorithm: "RS256",
    expiresIn: ttl,
  });
}

function signRefreshToken(
  payload,
  ttl = process.env.REFRESH_TOKEN_TTL || "7d"
) {
  return jwt.sign(payload, JWT_PRIVATE_KEY, {
    algorithm: "RS256",
    expiresIn: ttl,
  });
}

function verifyRefreshToken(token) {
  try {
    return jwt.verify(token, JWT_PUBLIC_KEY, { algorithms: ["RS256"] });
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const claims = jwt.verify(token, JWT_PUBLIC_KEY, { algorithms: ["RS256"] });
    req.user = claims;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (!roles.includes(req.user.role))
      return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

function isValidObjectId(val) {
  return typeof val === "string" && /^[a-fA-F0-9]{24}$/.test(val);
}

// Audit logging helper functions
async function auditAuth(action, actorId, actorRole, entityId, metadata, req) {
  try {
    await axios.post(`${AUDIT_URL}/audit`, {
      timestamp: new Date().toISOString(),
      actorId: actorId || "ANONYMOUS",
      actorRole: actorRole || "UNKNOWN",
      action,
      entityType: "Authentication",
      entityId: entityId || "N/A",
      metadata: {
        ...metadata,
        ip: req?.ip,
        userAgent: req?.headers?.["user-agent"],
      },
      severity:
        action.includes("FAILURE") || action.includes("LOCKED")
          ? "WARNING"
          : "INFO",
      status: action.includes("FAILURE") ? "FAILURE" : "SUCCESS",
    });
  } catch (e) {
    console.error("[AUDIT] Failed to log auth event:", e.message);
  }
}

async function auditValidationFailure(field, reason, metadata, req) {
  try {
    await axios.post(`${AUDIT_URL}/audit`, {
      timestamp: new Date().toISOString(),
      actorId: req.user?.sub ? String(req.user.sub) : "ANONYMOUS",
      actorRole: req.user?.role || "UNKNOWN",
      action: "VALIDATION_FAILURE",
      entityType: "ValidationError",
      entityId: field,
      metadata: {
        field,
        reason,
        endpoint: req.path,
        method: req.method,
        ip: req.ip,
        ...metadata,
      },
      severity: "INFO",
      status: "FAILURE",
    });
  } catch (e) {
    console.error("[AUDIT] Failed to log validation failure:", e.message);
  }
}

app.get("/health", (req, res) => res.json({ status: "ok", service: NAME }));

app.post("/auth/register", async (req, res) => {
  const { email, password, firstName, lastName, securityQuestionsAnswers } =
    req.body || {};
  const minLen = 8;
  const complexity = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/;
  const normalizedEmail =
    typeof email === "string" ? email.toLowerCase().trim() : "";
  if (
    typeof email !== "string" ||
    !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalizedEmail) ||
    typeof password !== "string" ||
    password.length < minLen ||
    !complexity.test(password)
  ) {
    return res.status(400).json({ error: "Invalid password policy" });
  }
  if (typeof firstName !== "string" || firstName.length < 1) {
    return res.status(400).json({ error: "First name required" });
  }
  if (typeof lastName !== "string" || lastName.length < 1) {
    return res.status(400).json({ error: "Last name required" });
  }
  if (
    !Array.isArray(securityQuestionsAnswers) ||
    securityQuestionsAnswers.length !== 3
  ) {
    return res
      .status(400)
      .json({ error: "Exactly 3 security questions required" });
  }
  for (const qa of securityQuestionsAnswers) {
    if (typeof qa.question !== "string" || qa.question.trim().length < 1) {
      return res.status(400).json({ error: "All security questions required" });
    }
    if (typeof qa.answer !== "string" || qa.answer.trim().length < 1) {
      return res.status(400).json({ error: "All security answers required" });
    }
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const securityQuestions = [];
  for (const qa of securityQuestionsAnswers) {
    const answerHash = await bcrypt.hash(qa.answer.trim().toLowerCase(), 10);
    securityQuestions.push({
      question: qa.question.trim(),
      answerHash,
    });
  }
  try {
    const user = await User.create({
      email: normalizedEmail,
      firstName,
      lastName,
      passwordHash,
      securityQuestions,
      role: "STUDENT",
    });
    res.status(201).json({
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
    });
  } catch (e) {
    if (e.code === 11000)
      return res.status(409).json({ error: "email already exists" });
    res.status(500).json({ error: "registration failed" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== "string" || typeof password !== "string")
    return res.status(400).json({ error: "Invalid input" });
  const normalizedEmail = email.toLowerCase().trim();
  const user = await User.findOne({ email: normalizedEmail });
  // Generic invalid response regardless of specifics
  const invalid = () => res.status(401).json({ error: "invalid credentials" });
  if (!user) return invalid();
  // Check lockout
  const nowLoginCheck = new Date();
  if (user.lockUntil && user.lockUntil > nowLoginCheck) {
    const secondsRemaining = Math.ceil(
      (user.lockUntil.getTime() - Date.now()) / 1000
    );
    return res.status(401).json({
      error: "invalid credentials",
      attemptsRemaining: 0,
      lockout: { until: user.lockUntil.toISOString(), secondsRemaining },
    });
  }
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    user.failedLoginCount = (user.failedLoginCount || 0) + 1;
    user.lastFailedLoginAt = new Date();
    let locked = false;
    if (user.failedLoginCount >= 5) {
      user.lockUntil = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
      user.failedLoginCount = 0; // reset counter after lock
      locked = true;
    }
    await user.save();

    // Log failed login attempt
    await auditAuth(
      "LOGIN_FAILURE",
      String(user._id),
      user.role,
      String(user._id),
      {
        email: user.email,
        attemptNumber: user.failedLoginCount,
        locked: locked,
      },
      req
    );

    // Log account lockout if triggered
    if (locked) {
      await auditAuth(
        "ACCOUNT_LOCKED",
        String(user._id),
        user.role,
        String(user._id),
        {
          email: user.email,
          reason: "Too many failed login attempts (5)",
          lockoutDuration: "10 minutes",
        },
        req
      );
    }

    const attemptsRemaining = locked
      ? 0
      : Math.max(0, 5 - user.failedLoginCount);
    let body = { error: "invalid credentials", attemptsRemaining };
    const nowTs = Date.now();
    if (user.lockUntil && user.lockUntil.getTime() > nowTs) {
      const secondsRemaining = Math.ceil(
        (user.lockUntil.getTime() - nowTs) / 1000
      );
      body.lockout = { until: user.lockUntil.toISOString(), secondsRemaining };
    }
    return res.status(401).json(body);
  }
  // Success: capture previous last usage
  const prevLastLoginAt = user.lastLoginAt;
  const prevLastFailedLoginAt = user.lastFailedLoginAt;
  user.failedLoginCount = 0;
  user.lockUntil = null;
  user.lastLoginAt = new Date();
  await user.save();

  // Log successful login
  await auditAuth(
    "LOGIN_SUCCESS",
    String(user._id),
    user.role,
    String(user._id),
    {
      email: user.email,
      previousLoginAt: prevLastLoginAt,
    },
    req
  );
  const accessToken = signAccessToken({
    sub: String(user._id),
    role: user.role,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
  });
  const refreshToken = signRefreshToken({ sub: String(user._id) });
  const refreshTokenHash = await bcrypt.hash(refreshToken, 10);
  const now = new Date();
  const exp = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  await Session.create({
    userId: user._id,
    refreshTokenHash,
    issuedAt: now,
    expiresAt: exp,
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });
  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  res.json({
    accessToken,
    user: {
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
    },
    lastLoginAt: prevLastLoginAt,
    lastFailedLoginAt: prevLastFailedLoginAt,
  });
});

app.post("/auth/refresh", async (req, res) => {
  const token = req.cookies["refresh_token"];
  if (!token) {
    console.log("[REFRESH] No refresh token in cookies");
    await auditAuth(
      "REFRESH_FAILURE",
      null,
      null,
      null,
      { reason: "no refresh token" },
      req
    ).catch(() => {});
    return res.status(401).json({ error: "no refresh token" });
  }
  const claims = verifyRefreshToken(token);
  if (!claims) {
    console.log("[REFRESH] Invalid refresh token signature");
    await auditAuth(
      "JWT_VERIFICATION_FAILURE",
      null,
      null,
      null,
      { where: "refresh" },
      req
    ).catch(() => {});
    await auditAuth(
      "REFRESH_FAILURE",
      null,
      null,
      null,
      { reason: "invalid refresh token" },
      req
    ).catch(() => {});
    return res.status(401).json({ error: "invalid refresh token" });
  }
  const sessions = await Session.find({ userId: claims.sub, revokedAt: null });
  if (!sessions || sessions.length === 0) {
    console.log("[REFRESH] No active sessions found for user", claims.sub);
    await auditAuth(
      "REFRESH_FAILURE",
      String(claims.sub),
      null,
      String(claims.sub),
      { reason: "no active sessions" },
      req
    ).catch(() => {});
    return res.status(401).json({ error: "session not found" });
  }
  let match = false;
  for (const s of sessions) {
    if (await bcrypt.compare(token, s.refreshTokenHash)) {
      match = true;
      break;
    }
  }
  if (!match) {
    console.log("[REFRESH] Token does not match any session hash");
    await auditAuth(
      "REFRESH_FAILURE",
      String(claims.sub),
      null,
      String(claims.sub),
      { reason: "token mismatch" },
      req
    ).catch(() => {});
    return res.status(401).json({ error: "session not found" });
  }
  const user = await User.findById(claims.sub);
  if (!user) {
    console.log("[REFRESH] User not found", claims.sub);
    await auditAuth(
      "REFRESH_FAILURE",
      String(claims.sub),
      null,
      String(claims.sub),
      { reason: "user not found" },
      req
    ).catch(() => {});
    return res.status(401).json({ error: "user not found" });
  }
  const accessToken = signAccessToken({
    sub: String(user._id),
    role: user.role,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
  });
  console.log("[REFRESH] Successfully refreshed token for user", user.email);
  await auditAuth(
    "REFRESH_SUCCESS",
    String(user._id),
    user.role,
    String(user._id),
    { email: user.email },
    req
  ).catch(() => {});
  res.json({ accessToken });
});

app.post("/auth/logout", async (req, res) => {
  const token = req.cookies["refresh_token"];
  if (token) {
    const claims = verifyRefreshToken(token);
    if (claims) {
      const sessions = await Session.find({
        userId: claims.sub,
        revokedAt: null,
      });
      for (const s of sessions) {
        if (await bcrypt.compare(token, s.refreshTokenHash)) {
          s.revokedAt = new Date();
          await s.save();
          await auditAuth(
            "SESSION_REVOKE",
            String(claims.sub),
            null,
            String(s._id),
            { reason: "logout" },
            req
          ).catch(() => {});
        }
      }
    }
  }
  res.clearCookie("refresh_token");
  res.json({ ok: true });
});

// ADMIN: list active sessions for a user (or all if none provided, limited)
app.get(
  "/auth/sessions",
  requireAuth,
  requireRole("ADMIN"),
  async (req, res) => {
    const { userId } = req.query;
    const filter = { revokedAt: null };
    if (userId) filter.userId = userId;
    const sessions = await Session.find(filter)
      .sort({ issuedAt: -1 })
      .limit(200)
      .select("_id userId issuedAt expiresAt ip userAgent revokedAt");
    res.json(sessions);
  }
);

// ADMIN: revoke a specific session by id
app.post(
  "/auth/sessions/:id/revoke",
  requireAuth,
  requireRole("ADMIN"),
  async (req, res) => {
    const s = await Session.findById(req.params.id);
    if (!s) return res.status(404).json({ error: "session not found" });
    if (s.revokedAt) return res.status(409).json({ error: "already revoked" });
    s.revokedAt = new Date();
    await s.save();
    await auditAuth(
      "SESSION_REVOKE",
      String(req.user.sub),
      req.user.role,
      String(s._id),
      { targetUserId: String(s.userId), reason: "admin" },
      req
    ).catch(() => {});
    res.json({ ok: true });
  }
);

// ADMIN-ONLY: List all users (for sync purposes)
app.get(
  "/auth/users/list",
  requireAuth,
  requireRole("ADMIN"),
  async (req, res) => {
    const users = await User.find().select(
      "_id email firstName lastName role createdAt"
    );
    res.json(users);
  }
);

// ADMIN-ONLY: Create a new user (ADMIN, TEACHER, or STUDENT)
app.post("/auth/users", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const {
    email,
    password,
    role,
    firstName,
    lastName,
    securityQuestion,
    securityAnswer,
    securityQuestionsAnswers,
  } = req.body || {};

  const minLen = 8;
  const complexity = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/;

  if (typeof email !== "string" || email.length < 3) {
    return res.status(400).json({ error: "invalid email" });
  }
  if (
    typeof password !== "string" ||
    password.length < minLen ||
    !complexity.test(password)
  ) {
    return res.status(400).json({ error: "password does not meet policy" });
  }
  if (typeof firstName !== "string" || firstName.length < 1) {
    return res.status(400).json({ error: "First name required" });
  }
  if (typeof lastName !== "string" || lastName.length < 1) {
    return res.status(400).json({ error: "Last name required" });
  }

  const allowed = ["ADMIN", "TEACHER", "STUDENT"];
  if (!allowed.includes(role)) {
    return res.status(400).json({ error: "invalid role" });
  }

  // Accept either legacy single securityQuestion/securityAnswer OR new securityQuestionsAnswers (3 items)
  let securityQuestionsPayload = [];
  if (
    Array.isArray(securityQuestionsAnswers) &&
    securityQuestionsAnswers.length === 3
  ) {
    for (const qa of securityQuestionsAnswers) {
      if (typeof qa?.question !== "string" || qa.question.trim().length < 1) {
        return res.status(400).json({ error: "All security questions required" });
      }
      if (typeof qa?.answer !== "string" || qa.answer.trim().length < 1) {
        return res.status(400).json({ error: "All security answers required" });
      }
      securityQuestionsPayload.push({
        question: qa.question.trim(),
        answer: qa.answer.trim(),
      });
    }
  } else {
    // Legacy path
    if (
      typeof securityQuestion !== "string" ||
      securityQuestion.trim().length < 1
    ) {
      return res.status(400).json({ error: "Security question required" });
    }
    if (typeof securityAnswer !== "string" || securityAnswer.trim().length < 1) {
      return res.status(400).json({ error: "Security answer required" });
    }
    securityQuestionsPayload.push({
      question: securityQuestion.trim(),
      answer: securityAnswer.trim(),
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    // Normalize into new schema: securityQuestions [{question, answerHash}]
    const securityQuestions = [];
    for (const qa of securityQuestionsPayload) {
      const answerHash = await bcrypt.hash(qa.answer.toLowerCase(), 10);
      securityQuestions.push({ question: qa.question, answerHash });
    }

    const user = await User.create({
      email,
      firstName,
      lastName,
      passwordHash,
      securityQuestions,
      role,
    });
    console.log("[AUTH] Admin created user:", email, "with role:", role);
    res.status(201).json({
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
    });
  } catch (e) {
    if (e.code === 11000)
      return res.status(409).json({ error: "email already exists" });
    console.error("[AUTH] Failed to create user:", e.message);
    res.status(500).json({ error: "create failed" });
  }
});

// ADMIN-ONLY: Update a user's role in Auth DB
app.patch(
  "/auth/users/:id/role",
  requireAuth,
  requireRole("ADMIN"),
  async (req, res) => {
    const { role } = req.body || {};
    const allowed = ["ADMIN", "TEACHER", "STUDENT"];
    if (!allowed.includes(role))
      return res.status(400).json({ error: "invalid role" });
    const ident = req.params.id;
    let user;
    if (isValidObjectId(ident)) {
      user = await User.findByIdAndUpdate(ident, { role }, { new: true });
    } else {
      user = await User.findOneAndUpdate(
        { email: ident },
        { role },
        { new: true }
      );
    }
    if (!user) return res.status(404).json({ error: "user not found" });
    res.json({ id: user._id, email: user.email, role: user.role });
  }
);

// USER: change own password
app.post("/auth/change-password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword, forceLogoutAllSessions } =
    req.body || {};
  const minLen = 8;
  const complexity = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/;
  if (typeof currentPassword !== "string" || typeof newPassword !== "string") {
    await auditAuth(
      "PASSWORD_CHANGE_FAILURE",
      String(req.user.sub),
      req.user.role,
      String(req.user.sub),
      { reason: "invalid input" },
      req
    ).catch(() => {});
    return res.status(400).json({ error: "invalid input" });
  }
  if (newPassword.length < minLen || !complexity.test(newPassword)) {
    await auditAuth(
      "PASSWORD_CHANGE_FAILURE",
      String(req.user.sub),
      req.user.role,
      String(req.user.sub),
      { reason: "policy" },
      req
    ).catch(() => {});
    return res.status(400).json({ error: "password does not meet policy" });
  }
  const user = await User.findById(req.user.sub);
  if (!user) {
    await auditAuth(
      "PASSWORD_CHANGE_FAILURE",
      String(req.user.sub),
      req.user.role,
      String(req.user.sub),
      { reason: "user not found" },
      req
    ).catch(() => {});
    return res.status(404).json({ error: "user not found" });
  }
  // Re-authenticate with current password
  const ok = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!ok) {
    await auditAuth(
      "PASSWORD_CHANGE_FAILURE",
      String(user._id),
      user.role,
      String(user._id),
      { reason: "invalid credentials" },
      req
    ).catch(() => {});
    return res.status(401).json({ error: "invalid credentials" });
  }
  // Enforce min password age (24h)
  if (
    user.passwordChangedAt &&
    Date.now() - user.passwordChangedAt.getTime() < 24 * 60 * 60 * 1000
  ) {
    const nextChangeTime = new Date(
      user.passwordChangedAt.getTime() + 24 * 60 * 60 * 1000
    );
    const secondsRemaining = Math.ceil(
      (nextChangeTime.getTime() - Date.now()) / 1000
    );
    await auditAuth(
      "PASSWORD_CHANGE_FAILURE",
      String(user._id),
      user.role,
      String(user._id),
      { reason: "min-age", secondsRemaining },
      req
    ).catch(() => {});
    return res.status(409).json({
      error: "password recently changed",
      nextChangeTime: nextChangeTime.toISOString(),
      secondsRemaining,
    });
  }
  // Prevent reuse: compare against current and history
  const allHashes = [user.passwordHash, ...(user.passwordHistory || [])];
  for (const h of allHashes) {
    if (await bcrypt.compare(newPassword, h)) {
      await auditAuth(
        "PASSWORD_CHANGE_FAILURE",
        String(user._id),
        user.role,
        String(user._id),
        { reason: "reuse" },
        req
      ).catch(() => {});
      return res.status(409).json({
        error: "New password cannot be the same as a previous password.",
      });
    }
  }
  // Rotate history (cap 5)
  const newHistory = [user.passwordHash, ...(user.passwordHistory || [])].slice(
    0,
    5
  );
  user.passwordHistory = newHistory;
  user.passwordHash = await bcrypt.hash(newPassword, 10);
  user.passwordChangedAt = new Date();
  await user.save();
  if (forceLogoutAllSessions) {
    const sessions = await Session.find({ userId: user._id, revokedAt: null });
    const nowTs = new Date();
    for (const s of sessions) {
      s.revokedAt = nowTs;
      await s.save();
    }
  }
  await auditAuth(
    "PASSWORD_CHANGE_SUCCESS",
    String(user._id),
    user.role,
    String(user._id),
    { sessionsRevoked: !!forceLogoutAllSessions },
    req
  ).catch(() => {});
  res.json({ ok: true, sessionsRevoked: !!forceLogoutAllSessions });
});

// ADMIN: reset a user's password (no current password required)
app.post(
  "/auth/admin/reset-password/:id",
  requireAuth,
  requireRole("ADMIN"),
  async (req, res) => {
    const { newPassword, forceLogoutAllSessions } = req.body || {};
    const minLen = 8;
    const complexity = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/;
    if (
      typeof newPassword !== "string" ||
      newPassword.length < minLen ||
      !complexity.test(newPassword)
    ) {
      await auditAuth(
        "PASSWORD_RESET_ADMIN",
        String(req.user.sub),
        req.user.role,
        String(req.params.id),
        { outcome: "FAILURE", reason: "policy" },
        req
      ).catch(() => {});
      return res.status(400).json({ error: "password does not meet policy" });
    }
    const ident = req.params.id;
    const user = isValidObjectId(ident)
      ? await User.findById(ident)
      : await User.findOne({ email: ident });
    if (!user) {
      await auditAuth(
        "PASSWORD_RESET_ADMIN",
        String(req.user.sub),
        req.user.role,
        String(req.params.id),
        { outcome: "FAILURE", reason: "user not found" },
        req
      ).catch(() => {});
      return res.status(404).json({ error: "user not found" });
    }
    if (user.role === "ADMIN") {
      await auditAuth(
        "PASSWORD_RESET_ADMIN",
        String(req.user.sub),
        req.user.role,
        String(user._id),
        { outcome: "FAILURE", reason: "target is admin" },
        req
      ).catch(() => {});
      return res
        .status(403)
        .json({ error: "forbidden: cannot reset password for ADMIN users" });
    }
    // Prevent reuse: compare against current and history
    const allHashes = [user.passwordHash, ...(user.passwordHistory || [])];
    for (const h of allHashes) {
      if (await bcrypt.compare(newPassword, h)) {
        await auditAuth(
          "PASSWORD_RESET_ADMIN",
          String(req.user.sub),
          req.user.role,
          String(user._id),
          { outcome: "FAILURE", reason: "reuse" },
          req
        ).catch(() => {});
        return res.status(409).json({
          error: "New password cannot be the same as a previous password.",
        });
      }
    }
    // Rotate history (cap 5)
    const newHistory = [
      user.passwordHash,
      ...(user.passwordHistory || []),
    ].slice(0, 5);
    user.passwordHistory = newHistory;
    user.passwordHash = await bcrypt.hash(newPassword, 10);
    user.passwordChangedAt = new Date();
    await user.save();
    if (forceLogoutAllSessions) {
      const sessions = await Session.find({
        userId: user._id,
        revokedAt: null,
      });
      const nowTs = new Date();
      for (const s of sessions) {
        s.revokedAt = nowTs;
        await s.save();
      }
    }
    await auditAuth(
      "PASSWORD_RESET_ADMIN",
      String(req.user.sub),
      req.user.role,
      String(user._id),
      { outcome: "SUCCESS", sessionsRevoked: !!forceLogoutAllSessions },
      req
    ).catch(() => {});
    res.json({ ok: true, sessionsRevoked: !!forceLogoutAllSessions });
  }
);

// Forgot password via security question - start
app.post("/auth/forgot-password/start", async (req, res) => {
  const { email } = req.body || {};
  if (typeof email !== "string") return res.status(200).json({ ok: true });
  const normalizedEmail = email.toLowerCase().trim();
  const user = await User.findOne({ email: normalizedEmail });
  if (!user) {
    return res.status(200).json({ ok: true, questions: null });
  }

  // Handle both old schema (single question) and new schema (multiple questions)
  let questions = [];
  if (
    user.securityQuestions &&
    Array.isArray(user.securityQuestions) &&
    user.securityQuestions.length > 0
  ) {
    questions = user.securityQuestions.map((q) => q.question);
  } else if (user.securityQuestion) {
    // Fallback for old schema
    questions = [user.securityQuestion];
  }

  if (questions.length === 0) {
    return res.status(200).json({ ok: true, questions: null });
  }

  return res.status(200).json({ ok: true, questions });
});

// Forgot password via security question - finish
app.post("/auth/forgot-password/finish", async (req, res) => {
  const { email, answers, newPassword } = req.body || {};
  const minLen = 8;
  const complexity = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/;

  // Validate input format
  if (
    typeof email !== "string" ||
    !Array.isArray(answers) ||
    typeof newPassword !== "string"
  ) {
    return res.status(400).json({ ok: false, error: "Invalid input format" });
  }

  const normalizedEmail = email.toLowerCase().trim();
  const user = await User.findOne({ email: normalizedEmail });
  if (!user) {
    await auditAuth(
      "SECURITY_ANSWER_FAILURE",
      null,
      null,
      normalizedEmail,
      { reason: "user not found" },
      req
    ).catch(() => {});
    return res.status(400).json({ ok: false, error: "User not found" });
  }

  // Handle both old and new schema
  let isValid = false;

  // New schema: multiple security questions
  if (
    user.securityQuestions &&
    Array.isArray(user.securityQuestions) &&
    user.securityQuestions.length > 0
  ) {
    if (answers.length !== user.securityQuestions.length) {
      return res
        .status(400)
        .json({ ok: false, error: "Invalid number of answers" });
    }

    for (let i = 0; i < user.securityQuestions.length; i++) {
      const answerHash = user.securityQuestions[i].answerHash;
      const providedAnswer = answers[i];
      if (!answerHash || typeof providedAnswer !== "string") {
        return res
          .status(400)
          .json({ ok: false, error: "Invalid answer format" });
      }
      const ansOk = await bcrypt.compare(
        providedAnswer.toLowerCase(),
        answerHash
      );
      if (!ansOk) {
        await auditAuth(
          "SECURITY_ANSWER_FAILURE",
          String(user._id),
          user.role,
          String(user._id),
          { questionIndex: i },
          req
        ).catch(() => {});
        return res.status(400).json({
          ok: false,
          error: "One or more security answers are incorrect",
        });
      }
    }
    isValid = true;
  }
  // Old schema: single security question (fallback)
  else if (user.securityQuestion && user.securityAnswerHash) {
    if (!Array.isArray(answers) || answers.length === 0) {
      return res
        .status(400)
        .json({ ok: false, error: "Security answer required" });
    }
    const ansOk = await bcrypt.compare(answers[0], user.securityAnswerHash);
    if (!ansOk) {
      await auditAuth(
        "SECURITY_ANSWER_FAILURE",
        String(user._id),
        user.role,
        String(user._id),
        {},
        req
      ).catch(() => {});
      return res
        .status(400)
        .json({ ok: false, error: "Security answer is incorrect" });
    }
    isValid = true;
  }

  if (!isValid) {
    return res
      .status(400)
      .json({ ok: false, error: "No security questions found" });
  }

  // Enforce min password age (24h) - even for forgot password
  if (
    user.passwordChangedAt &&
    Date.now() - user.passwordChangedAt.getTime() < 24 * 60 * 60 * 1000
  ) {
    const nextChangeTime = new Date(
      user.passwordChangedAt.getTime() + 24 * 60 * 60 * 1000
    );
    const secondsRemaining = Math.ceil(
      (nextChangeTime.getTime() - Date.now()) / 1000
    );
    return res.status(409).json({
      ok: false,
      error: "password recently changed",
      nextChangeTime: nextChangeTime.toISOString(),
      secondsRemaining,
    });
  }

  // Validate new password
  if (newPassword.length < minLen || !complexity.test(newPassword)) {
    return res
      .status(400)
      .json({ ok: false, error: "Password does not meet policy" });
  }

  // Prevent reuse
  const allHashes = [user.passwordHash, ...(user.passwordHistory || [])];
  for (const h of allHashes) {
    if (await bcrypt.compare(newPassword, h)) {
      return res.status(400).json({
        ok: false,
        error: "New password cannot be the same as a previous password",
      });
    }
  }

  // Rotate history
  user.passwordHistory = [
    user.passwordHash,
    ...(user.passwordHistory || []),
  ].slice(0, 5);
  user.passwordHash = await bcrypt.hash(newPassword, 10);
  user.passwordChangedAt = new Date();
  await user.save();

  // Revoke all sessions
  const sessions = await Session.find({ userId: user._id, revokedAt: null });
  const nowTs = new Date();
  for (const s of sessions) {
    s.revokedAt = nowTs;
    await s.save();
  }

  await auditAuth(
    "PASSWORD_RESET_USER",
    String(user._id),
    user.role,
    String(user._id),
    {},
    req
  ).catch(() => {});
  return res
    .status(200)
    .json({ ok: true, message: "Password reset successfully" });
});

// Re-authenticate to perform critical operations
app.post("/auth/reauthenticate", requireAuth, async (req, res) => {
  const { password } = req.body || {};
  if (typeof password !== "string")
    return res.status(400).json({ error: "invalid input" });
  const user = await User.findById(req.user.sub);
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });
  const accessToken = signAccessToken({
    sub: String(user._id),
    role: user.role,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    reauthAt: Date.now(),
  });
  res.json({ accessToken });
});

function requireRecentAuth(windowMs = 10 * 60 * 1000) {
  return (req, res, next) => {
    const ts = req.user?.reauthAt;
    if (!ts || Date.now() - ts > windowMs) {
      return res.status(401).json({ error: "reauth_required" });
    }
    next();
  };
}

// Example critical operation: revoke all own sessions
app.post(
  "/auth/sessions/revoke-all",
  requireAuth,
  requireRecentAuth(),
  async (req, res) => {
    const sessions = await Session.find({
      userId: req.user.sub,
      revokedAt: null,
    });
    const nowTs = new Date();
    for (const s of sessions) {
      s.revokedAt = nowTs;
      await s.save();
    }
    await auditAuth(
      "SESSIONS_REVOKE_ALL",
      String(req.user.sub),
      req.user.role,
      String(req.user.sub),
      { count: sessions.length },
      req
    ).catch(() => {});
    res.json({ ok: true });
  }
);

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
