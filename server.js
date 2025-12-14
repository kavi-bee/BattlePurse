const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const path = require("path");

// 🔥 Initialize Firebase (OTP)
require("./config/firebase");

// Load environment variables
dotenv.config();

const app = express();

// ✅ Middleware
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// ✅ Serve static frontend files
app.use(express.static(path.join(__dirname, "public")));

// ✅ Serve uploaded files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ✅ MongoDB connection
mongoose.set("bufferCommands", false);

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// ✅ API routes
app.use("/api/auth", require("./routes/auth"));   // 🔥 OTP auth
app.use("/api/wallet", require("./routes/wallet"));

// ✅ Root route
app.get("/", (req, res) => {
  res.send("🎮 GameZone API is running successfully!");
});

// ✅ 404 fallback
app.use((req, res) => {
  res.status(404).json({ msg: "Route not found" });
});

// ✅ Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
