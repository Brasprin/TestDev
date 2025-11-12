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


const PORT = process.env.PORT || 8003;
const NAME = process.env.SERVICE_NAME || "courses-service";
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://localhost:27017/des_courses";
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY_PATH
  ? fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH, "utf8")
  : process.env.JWT_PUBLIC_KEY || "";
const AUDIT_URL = process.env.AUDIT_URL || "http://localhost:8005";

const courseSchema = new mongoose.Schema({
  code: { type: String, unique: true },
  section: String,
  title: String,
  description: String,
  capacity: Number,
  professorEmail: String,
  professorName: String,
  status: { type: String, enum: ["OPEN", "CLOSED"], default: "OPEN" },
  droppingAllowed: { type: Boolean, default: true },
  createdBy: mongoose.Schema.Types.ObjectId,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const enrollmentSchema = new mongoose.Schema({
  studentId: mongoose.Schema.Types.ObjectId,
  courseId: mongoose.Schema.Types.ObjectId,
  status: {
    type: String,
    enum: ["ENROLLED", "DROPPED", "WAITLISTED"],
    default: "ENROLLED",
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Prevent duplicate active enrollments (only for ENROLLED status)
enrollmentSchema.index(
  { studentId: 1, courseId: 1 },
  { unique: true, partialFilterExpression: { status: "ENROLLED" } }
);

const Course = mongoose.model("Course", courseSchema);
const Enrollment = mongoose.model("Enrollment", enrollmentSchema);

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
    await axios.post(`${AUDIT_URL}/audit`, {
      timestamp: new Date().toISOString(),
      actorId: actor.sub,
      actorRole: actor.role,
      action,
      entityType,
      entityId,
      metadata,
    });
  } catch {}
}

app.get("/health", (req, res) => res.json({ status: "ok", service: NAME }));

// Auth required: list courses
// Teachers see only their own courses; others (Admin/Student) see all
app.get("/courses", requireAuth, async (req, res) => {
  const query = req.user?.role === "TEACHER" ? { createdBy: req.user.sub } : {};
  const courses = await Course.find(query);
  // Attach enrolledCount for transparency
  const withCounts = await Promise.all(
    courses.map(async (c) => {
      const count = await Enrollment.countDocuments({
        courseId: c._id,
        status: "ENROLLED",
      });
      return { ...c.toObject(), enrolledCount: count };
    })
  );
  res.json(withCounts);
});

// ROLE_A: create course
app.post("/courses", requireAuth, requireRole("TEACHER"), async (req, res) => {
  const {
    code,
    section,
    title,
    description,
    capacity,
    status,
    professorEmail,
    professorName,
  } = req.body;
  if (
    !code ||
    typeof code !== "string" ||
    !title ||
    typeof title !== "string"
  ) {
    return res.status(400).json({ error: "invalid input" });
  }
  const capNum = Number(capacity);
  if (!Number.isFinite(capNum) || capNum <= 0) {
    return res.status(400).json({ error: "capacity must be positive" });
  }
  try {
    const course = await Course.create({
      code,
      section,
      title,
      description,
      capacity: capNum,
      professorEmail,
      professorName,
      status: status === "CLOSED" ? "CLOSED" : "OPEN",
      createdBy: req.user.sub,
    });
    await audit(req.user, "COURSE_CREATE", "Course", course._id, { code });
    res.status(201).json(course);
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: "code exists" });
    res.status(500).json({ error: "create failed" });
  }
});

// ROLE_A: update course (teacher can only modify their own)
app.patch(
  "/courses/:id",
  requireAuth,
  requireRole("TEACHER"),
  async (req, res) => {
    // Ensure teacher owns the course
    const existing = await Course.findById(req.params.id);
    if (!existing) return res.status(404).json({ error: "not found" });
    if (String(existing.createdBy) !== String(req.user.sub))
      return res.status(403).json({ error: "forbidden" });

    const updates = { ...req.body, updatedAt: new Date() };
    // Prevent changing ownership
    delete updates.createdBy;

    // Only allow certain fields to be updated via general patch
    const allowed = [
      "title",
      "description",
      "capacity",
      "status",
      "section",
      "professorEmail",
      "professorName",
    ];
    Object.keys(updates).forEach((k) => {
      if (!allowed.includes(k)) delete updates[k];
    });
    const course = await Course.findByIdAndUpdate(req.params.id, updates, {
      new: true,
    });
    await audit(req.user, "COURSE_UPDATE", "Course", course._id, {});
    res.json(course);
  }
);

// ROLE_A: delete course (teacher can only delete their own)
app.delete(
  "/courses/:id",
  requireAuth,
  requireRole("TEACHER"),
  async (req, res) => {
    const existing = await Course.findById(req.params.id);
    if (!existing) return res.status(404).json({ error: "not found" });
    if (String(existing.createdBy) !== String(req.user.sub))
      return res.status(403).json({ error: "forbidden" });

    const course = await Course.findByIdAndDelete(req.params.id);
    await audit(req.user, "COURSE_DELETE", "Course", course._id, {});
    res.json({ ok: true });
  }
);

// ROLE_B: enroll self (students only). Teachers cannot enroll into others' courses as students here.
app.post(
  "/courses/:id/enroll",
  requireAuth,
  requireRole("STUDENT"),
  async (req, res) => {
    const courseId = req.params.id;
    const course = await Course.findById(courseId);
    if (!course) return res.status(404).json({ error: "course not found" });
    if (course.status !== "OPEN")
      return res.status(409).json({ error: "course not open" });

    const exists = await Enrollment.findOne({
      courseId,
      studentId: req.user.sub,
      status: "ENROLLED",
    });
    if (exists) return res.status(409).json({ error: "already enrolled" });

    const enrolledCount = await Enrollment.countDocuments({
      courseId,
      status: "ENROLLED",
    });
    if (
      typeof course.capacity === "number" &&
      enrolledCount >= course.capacity
    ) {
      return res.status(409).json({ error: "course full" });
    }

    try {
      const enrollment = await Enrollment.create({
        courseId,
        studentId: req.user.sub,
        status: "ENROLLED",
      });
      // After enrolling, auto-close if full
      const newCount = await Enrollment.countDocuments({
        courseId,
        status: "ENROLLED",
      });
      if (typeof course.capacity === "number" && newCount >= course.capacity) {
        const updated = await Course.findByIdAndUpdate(
          courseId,
          { status: "CLOSED", updatedAt: new Date() },
          { new: true }
        );
        console.log(
          `Course ${courseId} auto-closed. Enrolled: ${newCount}, Capacity: ${course.capacity}`
        );
      }
      await audit(req.user, "ENROLL", "Enrollment", enrollment._id, {
        courseId,
      });
      // Return fresh enrollment with all fields
      const fresh = await Enrollment.findById(enrollment._id);
      res.status(201).json(fresh);
    } catch (e) {
      if (e.code === 11000)
        return res.status(409).json({ error: "already enrolled" });
      res.status(500).json({ error: "enroll failed" });
    }
  }
);

// ROLE_B: drop self
app.delete(
  "/courses/:id/enroll",
  requireAuth,
  requireRole("STUDENT"),
  async (req, res) => {
    const courseId = req.params.id;
    const enrollment = await Enrollment.findOneAndUpdate(
      { courseId, studentId: req.user.sub, status: "ENROLLED" },
      { status: "DROPPED", updatedAt: new Date() },
      { new: true }
    );
    if (!enrollment) return res.status(404).json({ error: "not enrolled" });
    // After drop, auto-open if spots available
    const course = await Course.findById(courseId);
    const newCount = await Enrollment.countDocuments({
      courseId,
      status: "ENROLLED",
    });
    if (
      course &&
      typeof course.capacity === "number" &&
      newCount < course.capacity &&
      course.status !== "OPEN"
    ) {
      await Course.findByIdAndUpdate(courseId, {
        status: "OPEN",
        updatedAt: new Date(),
      });
    }
    await audit(req.user, "DROP", "Enrollment", enrollment._id, { courseId });
    res.json(enrollment);
  }
);

// ROLE_B: my enrollments
app.get(
  "/me/enrollments",
  requireAuth,
  requireRole("STUDENT"),
  async (req, res) => {
    const enrollments = await Enrollment.find({ studentId: req.user.sub });
    res.json(enrollments);
  }
);

// TEACHER: manage course participants (own courses only)
app.get(
  "/courses/:id/enrollments",
  requireAuth,
  requireRole("TEACHER"),
  async (req, res) => {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ error: "not found" });
    if (String(course.createdBy) !== String(req.user.sub))
      return res.status(403).json({ error: "forbidden" });
    const enrollments = await Enrollment.find({
      courseId: req.params.id,
      status: "ENROLLED",
    }).lean();
    // Note: grades are now managed by the grades service
    res.json(enrollments);
  }
);

// TEACHER: remove a student from their course
app.delete(
  "/courses/:id/students/:studentId",
  requireAuth,
  requireRole("TEACHER"),
  async (req, res) => {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ error: "not found" });
    if (String(course.createdBy) !== String(req.user.sub))
      return res.status(403).json({ error: "forbidden" });

    const enrollment = await Enrollment.findOneAndUpdate(
      {
        courseId: req.params.id,
        studentId: req.params.studentId,
        status: "ENROLLED",
      },
      { status: "DROPPED", updatedAt: new Date() },
      { new: true }
    );
    if (!enrollment) return res.status(404).json({ error: "not enrolled" });
    // After removal, auto-open if spots available
    const newCount = await Enrollment.countDocuments({
      courseId: req.params.id,
      status: "ENROLLED",
    });
    if (
      typeof course.capacity === "number" &&
      newCount < course.capacity &&
      course.status !== "OPEN"
    ) {
      await Course.findByIdAndUpdate(req.params.id, {
        status: "OPEN",
        updatedAt: new Date(),
      });
    }
    await audit(
      req.user,
      "TEACHER_REMOVE_STUDENT",
      "Enrollment",
      enrollment._id,
      { courseId: req.params.id, studentId: req.params.studentId }
    );
    res.json(enrollment);
  }
);

// TEACHER: toggle dropping allowed (own course only)
app.patch(
  "/courses/:id/dropping",
  requireAuth,
  requireRole("TEACHER"),
  async (req, res) => {
    const { droppingAllowed } = req.body;
    if (typeof droppingAllowed !== "boolean") {
      return res.status(400).json({ error: "droppingAllowed must be boolean" });
    }
    const existing = await Course.findById(req.params.id);
    if (!existing) return res.status(404).json({ error: "not found" });
    if (String(existing.createdBy) !== String(req.user.sub))
      return res.status(403).json({ error: "forbidden" });

    const course = await Course.findByIdAndUpdate(
      req.params.id,
      { droppingAllowed, updatedAt: new Date() },
      { new: true }
    );
    await audit(req.user, "COURSE_DROPPING_TOGGLE", "Course", course._id, {
      droppingAllowed,
    });
    res.json(course);
  }
);

// TEACHER: change course capacity (own course only)
app.patch(
  "/courses/:id/capacity",
  requireAuth,
  requireRole("TEACHER"),
  async (req, res) => {
    const capNum = Number(req.body.capacity);
    if (!Number.isFinite(capNum) || capNum <= 0) {
      return res.status(400).json({ error: "capacity must be positive" });
    }
    const existing = await Course.findById(req.params.id);
    if (!existing) return res.status(404).json({ error: "not found" });
    if (String(existing.createdBy) !== String(req.user.sub))
      return res.status(403).json({ error: "forbidden" });

    // Update capacity
    let course = await Course.findByIdAndUpdate(
      req.params.id,
      { capacity: capNum, updatedAt: new Date() },
      { new: true }
    );
    // Adjust status based on new capacity
    const enrolledCount = await Enrollment.countDocuments({
      courseId: req.params.id,
      status: "ENROLLED",
    });
    const desiredStatus =
      typeof capNum === "number" && enrolledCount >= capNum ? "CLOSED" : "OPEN";
    if (course.status !== desiredStatus) {
      course = await Course.findByIdAndUpdate(
        req.params.id,
        { status: desiredStatus, updatedAt: new Date() },
        { new: true }
      );
    }
    await audit(req.user, "COURSE_CAPACITY_CHANGE", "Course", course._id, {
      capacity: capNum,
    });
    res.json(course);
  }
);

// Note: Grade management has been moved to the grades service
// Teachers should use POST /grades on the grades service to assign grades

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
