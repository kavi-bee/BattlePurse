const mongoose = require("mongoose");

const leaderboardSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, unique: true },
  totalWinnings: { type: Number, default: 0 },
  totalSpent: { type: Number, default: 0 },
  matchesPlayed: { type: Number, default: 0 },
  netWin: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now }
});

// Automatically update `updatedAt` on every save
leaderboardSchema.pre("save", function(next) {
  this.updatedAt = new Date();
  next();
});

module.exports = mongoose.model("Leaderboard", leaderboardSchema);
