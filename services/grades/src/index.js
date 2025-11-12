import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import mongoose from "mongoose";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import axios from "axios";
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

const PORT = process.env.PORT || 8004;
const NAME = process.env.SERVICE_NAME || "grades-service";
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://localhost:27017/des_grades";
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY_PATH
  ? fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH, "utf8")
  : process.env.JWT_PUBLIC_KEY || "";
const AUDIT_URL = process.env.AUDIT_URL || "http://localhost:8005";

const gradeSchema = new mongoose.Schema({
  studentId: mongoose.Schema.Types.ObjectId,
  courseId: mongoose.Schema.Types.ObjectId,
  courseCode: String,
  value: {
    type: String,
    enum: ["4.0", "3.5", "3.0", "2.5", "2.0", "1.5", "1.0", "0.0", "W"],
    required: true,
  },
  gradedBy: mongoose.Schema.Types.ObjectId,
  version: { type: Number, default: 1 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Unique index: one grade per student per course
gradeSchema.index({ studentId: 1, courseId: 1 }, { unique: true });

const Grade = mongoose.model("Grade", gradeSchema);

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

async function audit(actor, action, entityType, entityId, metadata) {
  try {
    await axios.post(`${AUDIT_URL}/audit`, { timestamp: new Date().toISOString(), actorId: actor.sub, actorRole: actor.role, action, entityType, entityId, metadata });
  } catch {}
}

app.get("/health", (req, res) => res.json({ status: "ok", service: NAME }));

// ROLE_A: upload/update grade for a student in a course
app.post("/grades", requireAuth, requireRole("TEACHER"), async (req, res) => {
  const { studentId, courseId, courseCode, value } = req.body || {};
  if (!studentId || !courseId || typeof value !== "string") {
    return res.status(400).json({ error: "invalid input" });
  }
  const allowedGrades = [
    "4.0",
    "3.5",
    "3.0",
    "2.5",
    "2.0",
    "1.5",
    "1.0",
    "0.0",
    "W",
  ];
  if (!allowedGrades.includes(value)) {
    return res.status(400).json({ error: "invalid grade value" });
  }
  try {
    // Upsert: create or update
    let grade = await Grade.findOne({ studentId, courseId });
    if (grade) {
      grade.value = value;
      grade.courseCode = courseCode || grade.courseCode;
      grade.version += 1;
      grade.updatedAt = new Date();
      await grade.save();
      await audit(req.user, "GRADE_UPDATE", "Grade", grade._id, {
        studentId,
        courseId,
        value,
      });
    } else {
      grade = await Grade.create({
        studentId,
        courseId,
        courseCode,
        value,
        gradedBy: req.user.sub,
      });
      await audit(req.user, "GRADE_CREATE", "Grade", grade._id, {
        studentId,
        courseId,
        value,
      });
    }
    res.status(201).json(grade);
  } catch (e) {
    if (e.code === 11000) {
      return res.status(409).json({ error: "grade already exists" });
    }
    res.status(500).json({ error: "create failed" });
  }
});

// ROLE_A: modify grade by ID
app.patch(
  "/grades/:id",
  requireAuth,
  requireRole("TEACHER"),
  async (req, res) => {
    const { value } = req.body || {};
    if (typeof value !== "string" || !value)
      return res.status(400).json({ error: "invalid input" });
    const allowedGrades = [
      "4.0",
      "3.5",
      "3.0",
      "2.5",
      "2.0",
      "1.5",
      "1.0",
      "0.0",
      "W",
    ];
    if (!allowedGrades.includes(value)) {
      return res.status(400).json({ error: "invalid grade value" });
    }
    const grade = await Grade.findById(req.params.id);
    if (!grade) return res.status(404).json({ error: "not found" });
    grade.value = value;
    grade.version += 1;
    grade.updatedAt = new Date();
    await grade.save();
    await audit(req.user, "GRADE_UPDATE", "Grade", grade._id, { value });
    res.json(grade);
  }
);

// ROLE_B: view own grades
app.get("/me/grades", requireAuth, requireRole("STUDENT"), async (req, res) => {
  const grades = await Grade.find({ studentId: req.user.sub });
  res.json(grades);
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
