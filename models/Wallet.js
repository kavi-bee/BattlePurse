const mongoose = require('mongoose');

const walletSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true  // One wallet per user
  },
  balance: {
    type: Number,
    required: true,
    default: 0
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  uids: {
  freeFire: String,
  bgmi: String,
  candy: String,
  carrom: String,
  ludo: String,
  eightBall: String
},


});

// Auto-update `updatedAt` on save
walletSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Wallet', walletSchema);
