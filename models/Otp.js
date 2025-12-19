const mongoose = require("mongoose"); // ✅ REQUIRED

const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true
  },
  otp: {
    type: String,
    required: true
  },
  purpose: {
    type: String,
    enum: ["register", "forgot"],
    required: true
  },

  // 🔐 temp registration data
  name: String,
  phone: String,
  password: String,

  expiresAt: {
    type: Date,
    required: true
  },

  isAdmin: {
  type: Boolean,
  default: false
}

}, { timestamps: true });

module.exports = mongoose.model("Otp", otpSchema);
