const mongoose = require("mongoose");

const historySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  matchId: { type: mongoose.Schema.Types.ObjectId, ref: "QuickMatch", required: true },
  game: { type: String, required: true },
  entryFee: { type: Number, default: 0 },
  winAmount: { type: Number, default: 0 },
  kills: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("History", historySchema);
