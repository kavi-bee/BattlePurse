// models/Promo.js
const mongoose = require("mongoose");

const promoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  images: [String],
  code: { type: String, unique: true, default: () => Date.now().toString(36) } // 👈 auto-generate
}, { timestamps: true });


module.exports = mongoose.model("Promo", promoSchema);
