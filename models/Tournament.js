// models/Tournament.js
const mongoose = require("mongoose");

const TournamentSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    game: { type: String, required: true },
    date: { type: Date, required: true },
    time: { type: String, required: true },
    entryFee: { type: Number, required: true },
    prizePool: { type: Number, required: true },
    maxPlayers: { type: Number, required: true },

    poster: { type: String },

    roomId: { type: String },
    roomPassword: { type: String },

    joinedUsers: [
      {
        userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        name: { type: String },
        phone: { type: String },
        gameUIDs: [String],
        paid: { type: Boolean, default: false },
        joinedAt: { type: Date, default: Date.now },
      },
    ],

    results: [
      {
        userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        screenshot: String,
        uploadedAt: { type: Date, default: Date.now },
      },
    ],

    mode: {
      type: String,
      enum: ["solo", "duo", "squad"],
      default: "solo",
    },

    
    
    players: {
  type: [
    {
      userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      name: String,
      phone: String,
      gameUIDs: [String],
      paid: { type: Boolean, default: false },
      joinedAt: { type: Date, default: Date.now },
    },
  ],
  default: [], // prevents .some() errors
},


    // ✅ Multi-winner support with name + tournament info
    winners: [
      {
        userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        name: { type: String },                // 👈 Winner's name
        tournamentName: { type: String },      // 👈 Tournament name
        position: { type: Number, enum: [1, 2, 3] },
        prize: { type: Number },
        declaredAt: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);



module.exports = mongoose.model("Tournament", TournamentSchema);
