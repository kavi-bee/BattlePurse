require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");

const app = express();
process.setMaxListeners(20);

/* ======================
   DEBUG ENV
====================== */
console.log("RESEND KEY LOADED:", !!process.env.RESEND_API_KEY);

console.log("EMAIL USER LOADED:", !!process.env.EMAIL_USER);
console.log("EMAIL PASS LOADED:", !!process.env.EMAIL_PASS);

/* ======================
   MIDDLEWARE
====================== */
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

/* ======================
   STATIC FILES
====================== */
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

/* ======================
   MONGODB CONNECTION
====================== */
mongoose
  .connect(process.env.MONGO_URI, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000
  })
  .then(() => console.log("✅ MongoDB Atlas connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });

/* ======================
   ROUTES
====================== */
app.use("/api/wallet", require("./routes/wallet"));

/* ======================
   FRONTEND ENTRY
====================== */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* ======================
   404 HANDLER
====================== */
app.use((req, res) => {
  res.status(404).json({ msg: "Route not found" });
});

/* ======================
   START SERVER
====================== */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
