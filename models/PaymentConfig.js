const mongoose = require("mongoose");

const PaymentConfigSchema = new mongoose.Schema({
  qrImage: { type: String },  // filename of uploaded QR image
  upiId: { type: String },
}, { timestamps: true });

module.exports = mongoose.model("PaymentConfig", PaymentConfigSchema);
