// models/Transaction.js
const mongoose = require("mongoose");

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  amount: Number,
  type: String, // deposit/withdrawal
  method: String, // bank / upi
  status: String, // pending, approved, rejected
  bankName: String,
  cardNumber: String,
  ifsc: String,
  utr: String,
  accountHolder: String,
  upiId: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Transaction", transactionSchema);
