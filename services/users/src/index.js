import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import mongoose from "mongoose";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import fs from "fs";

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

const PORT = process.env.PORT || 8002;
const NAME = process.env.SERVICE_NAME || "users-service";
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://localhost:27017/des_users";
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY_PATH
  ? fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH, "utf8")
  : process.env.JWT_PUBLIC_KEY || "";

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  firstName: String,
  lastName: String,
  role: {
    type: String,
    enum: ["ADMIN", "TEACHER", "STUDENT"],
    default: "STUDENT",
  },
  passwordHash: String,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);

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

app.get("/health", (req, res) => res.json({ status: "ok", service: NAME }));

// Admin bootstrap: create initial admin if none exists
app.post("/admin/bootstrap", async (req, res) => {
  const { email, passwordHash } = req.body;
  const existingAdmin = await User.findOne({ role: "ADMIN" });
  if (existingAdmin) return res.status(409).json({ error: "admin exists" });
  const user = await User.create({ email, passwordHash, role: "ADMIN" });
  res.json({ id: user._id, email: user.email, role: user.role });
});

// Admin create Admin or Role A
app.post("/users", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const { email, role, passwordHash } = req.body;
  if (!["ADMIN", "TEACHER"].includes(role))
    return res.status(400).json({ error: "invalid role" });
  try {
    const user = await User.create({ email, role, passwordHash });
    res.status(201).json({ id: user._id, email: user.email, role: user.role });
  } catch (e) {
    if (e.code === 11000)
      return res.status(409).json({ error: "email exists" });
    res.status(500).json({ error: "create failed" });
  }
});

// Admin assign roles
app.patch(
  "/users/:id/role",
  requireAuth,
  requireRole("ADMIN"),
  async (req, res) => {
    const { role } = req.body;
    if (!["ADMIN", "TEACHER", "STUDENT"].includes(role))
      return res.status(400).json({ error: "invalid role" });
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: "user not found" });
    res.json({ id: user._id, email: user.email, role: user.role });
  }
);

// Self get profile (return from JWT claims - JWT is source of truth)
app.get("/users/me", requireAuth, async (req, res) => {
  // Return user info from JWT token claims
  // The JWT is the authoritative source for user identity and role
  res.json({
    id: req.user.sub,
    email: req.user.email,
    role: req.user.role,
  });
});

// Helper: Sync users from Auth service
async function syncUsersFromAuth(authToken) {
  try {
    const authServiceUrl = process.env.AUTH_URL || "http://localhost:8001";
    const authRes = await fetch(`${authServiceUrl}/auth/users/list`, {
      headers: { Authorization: authToken },
    });

    if (!authRes.ok) {
      console.error("[USERS] Failed to fetch from auth:", authRes.status);
      return;
    }

    const authUsers = await authRes.json();
    for (const authUser of authUsers) {
      try {
        await User.updateOne(
          { _id: authUser._id },
          {
            $set: {
              email: authUser.email,
              role: authUser.role,
              createdAt: authUser.createdAt,
            },
          },
          { upsert: true }
        );
      } catch (e) {
        if (e.code !== 11000) {
          console.error("[USERS] Sync error:", e.message);
        }
      }
    }
    console.log("[USERS] Auto-synced users from Auth");
  } catch (e) {
    console.error("[USERS] Auto-sync failed:", e.message);
  }
}

// Admin list/search users by email (auto-syncs from Auth first)
app.get("/users", requireAuth, requireRole("ADMIN"), async (req, res) => {
  // Auto-sync users from Auth before searching
  await syncUsersFromAuth(req.headers["authorization"]);

  const qRaw = typeof req.query.q === "string" ? req.query.q : "";
  const q = qRaw.trim();
  const limitRaw = parseInt(String(req.query.limit || ""), 10);
  const limit = Number.isFinite(limitRaw)
    ? Math.min(Math.max(limitRaw, 1), 100)
    : 50;

  if (q.length > 100) return res.status(400).json({ error: "query too long" });

  const filter = q ? { email: { $regex: q, $options: "i" } } : {};
  const users = await User.find(filter).select("_id email role").limit(limit);
  res.json(users.map((u) => ({ id: u._id, email: u.email, role: u.role })));
});

// Admin sync users from Auth service to Users service
app.post("/users/sync", requireAuth, requireRole("ADMIN"), async (req, res) => {
  try {
    const authServiceUrl = process.env.AUTH_URL || "http://localhost:8001";
    const authToken = req.headers["authorization"];

    // Fetch all users from Auth service
    const authRes = await fetch(`${authServiceUrl}/auth/users/list`, {
      headers: { Authorization: authToken },
    });

    if (!authRes.ok) {
      return res
        .status(500)
        .json({ error: "failed to fetch users from auth service" });
    }

    const authUsers = await authRes.json();
    let synced = 0;
    let skipped = 0;

    // Upsert each user into Users DB
    for (const authUser of authUsers) {
      try {
        await User.updateOne(
          { _id: authUser._id },
          {
            $set: {
              email: authUser.email,
              firstName: authUser.firstName,
              lastName: authUser.lastName,
              role: authUser.role,
              createdAt: authUser.createdAt,
            },
          },
          { upsert: true }
        );
        synced++;
      } catch (e) {
        if (e.code === 11000) {
          skipped++;
        } else {
          console.error("[USERS] Sync error:", e.message);
        }
      }
    }

    console.log(`[USERS] Synced ${synced} users, skipped ${skipped}`);
    res.json({ synced, skipped, total: authUsers.length });
  } catch (e) {
    console.error("[USERS] Sync failed:", e.message);
    res.status(500).json({ error: "sync failed" });
  }
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
