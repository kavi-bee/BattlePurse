const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  // ✅ User profile info
  name: {
    type: String,
    required: true,
    trim: true
  },
  phone: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  wallet: {
    type: Number,
    default: 0
  },
  avatarUrl: {
    type: String,
    default: ""
  },

  // ✅ Store user IDs for different games
  uids: {
    freeFire: String,
    bgmi: String,
    cricket: String,
    carrom: String,
    ludo: String,
    eightBall: String
  },

  // ✅ Admin access
  isAdmin: {
    type: Boolean,
    default: false
  },

  // ✅ K-CODE feature for device unlock
  kCodes: [{
    deviceId: String,
    codeHash: String,   // store hashed K-CODE
    createdAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true }); // adds createdAt & updatedAt automatically

module.exports = mongoose.model('User', UserSchema);
