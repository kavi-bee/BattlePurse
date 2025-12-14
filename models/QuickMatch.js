


const mongoose = require("mongoose");

//
// SLOT SCHEMA
//
const SlotSchema = new mongoose.Schema({
  uid: { type: String, default: null },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  phone: { type: String, default: null },
  whatsappNumber: { type: String, default: null },
  joinedAt: { type: Date, default: Date.now },

  result: { type: String, enum: ["win", "loss", "pending"], default: "pending" },
  winningPrice: { type: Number, default: 0 }
});

//
// FREE FIRE SUB-SCHEMAS
//
const FFRoomSettingsSchema = new mongoose.Schema({
  roomType: String,
  gameMode: String,
  map: String,
  teamMode: String
}, { _id: false });

const FFGameSettingsSchema = new mongoose.Schema({
  headshot: { type: Boolean, default: null },
  characterSkill: { type: Boolean, default: null },
  gunAttributes: { type: Boolean, default: null },
  throwableLimit: { type: Number, default: null }
}, { _id: false });

const FFGunsSchema = new mongoose.Schema({
  AR: [String],
  SMG: [String],
  SNIPER: [String],
  SHOTGUN: [String],
  PISTOLS: [String],
  LAUNCHERS: [String],
  SPECIAL: [String]
}, { _id: false });

const FFThrowablesSchema = new mongoose.Schema({
  grenades: String,
  smoke: String,
  flashFreeze: String,
  decoy: String
}, { _id: false });

const FFStoreItemsSchema = new mongoose.Schema({
  items: { type: Object, default: {} }
}, { _id: false });

//
// PLAYER SCHEMA
//
const PlayerSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  name: String,
  uid: String,
  phone: String,
  whatsappNumber: { type: String, default: null },
  team: { type: String, enum: ["LION", "TIGER"], default: null },
  joinedAt: { type: Date, default: Date.now },

  // ⭐ Full Free Fire Support
  freeFireSettings: {
    roomSettings: FFRoomSettingsSchema,
    gameSettings: FFGameSettingsSchema,
    guns: FFGunsSchema,
    throwables: FFThrowablesSchema,
    storeItems: FFStoreItemsSchema
  }
});

//
// MAIN MATCH SCHEMA
//
const QuickMatchSchema = new mongoose.Schema(
  {
    matchNumber: { type: String, unique: true, default: null },

    prizeSystem: {
      type: String,
      enum: ["kill_based", "team_equal", null],
      default: null
    },

    // Match Type
    type: {
      type: String,
      enum: [
        "1v1", "1v2", "1v3", "2v2", "3v3", "4v4", "5v5", "6v6", "TDM",
        "Gun Game", "classic", "freestyle", "Custom Room", "quick", "popular",
        // FREE FIRE
        "Clash Squad", "Lone Wolf",
        // Cricket
        "1 over"
      ],
      required: true
    },

    // Game
    game: {
      type: String,
      enum: [
        "BGMI",
        "PUBG",
        "Free Fire",
        "Ludo",
        "Carrom",
        "8 Ball Pool",
        "Cricket",
        "Chess"
      ],
      required: true
    },

    // Mode (Combined for All Games)
    mode: {
      type: String,
      enum: [
        "TDM",
        "Gun Game",
        "classic",
        "freestyle",
        "Custom Room",
        "quick",
        "popular",
        // FREE FIRE
        "Clash Squad",
        "Lone Wolf",
        // Cricket
        "1 over"
      ],
      required: true
    },

    entryFee: { type: Number, required: true },

    slots: { type: [SlotSchema], default: [] },
    players: { type: [PlayerSchema], default: [] },

    roomDetails: {
      roomId: { type: String, default: null },
      roomPassword: { type: String, default: null },
      startTime: { type: Date, default: null },
      message: { type: String, default: null },
      publishedAt: { type: Date, default: null }
    },

    userResults: [
      {
        userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        gameUid: String,
        screenshotUrl: String,
        kills: { type: Number, default: 0 },
        uploadedAt: { type: Date, default: Date.now },
        team: { type: String, enum: ["LION", "TIGER"], default: null }
      }
    ],

players: [
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    uid: String,
    phone: String,
    whatsappNumber: String,
    team: String,
    joinedAt: Date,
    freeFireSettings: {
      map: String,
      roomType: String,
      gameSettings: {
        headshot: Boolean,
        characterSkill: Boolean,
        gunAttributes: Boolean,
        throwableLimit: Number
      },
      selectedGuns: {
        AR: [String],
        SMG: [String],
        SNIPER: [String],
        SHOTGUN: [String],
        PISTOLS: [String],
        LAUNCHERS: [String],
        SPECIAL: [String]
      }
    }
  }
]

,


    status: {
      type: String,
      enum: [
        "waiting",
        "ready",
        "paired",
        "filled",
        "completed",
        "room_published",
        "full"
      ],
      default: "waiting"
    },

    createdAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);





//
// AUTO MATCH NUMBER + SLOT CREATION (run before validation so unique checks pass)
//
QuickMatchSchema.pre("validate", async function (next) {
  try {
    // generate matchNumber early so unique index validation won't see null
    if (!this.matchNumber) {
      const randomPart = Math.random().toString(36).substring(2, 6).toUpperCase();
      this.matchNumber = `QM-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${randomPart}`;
    }

    // ensure slots exist (based on type), only if slots are empty
    const typeToPlayers = {
      "1v1": 2,
      "1v2": 3,
      "1v3": 4,
      "2v2": 4,
      "3v3": 6,
      "4v4": 8,
      "5v5": 10,
      "6v6": 12
    };

    if (!Array.isArray(this.slots) || this.slots.length === 0) {
      const totalSlots = typeToPlayers[this.type] || 2;
      this.slots = [];
      for (let i = 0; i < totalSlots; i++) {
        this.slots.push({});
      }
    }
    next();
  } catch (err) {
    next(err);
  }
});

// Virtual that counts *filled* slots (only truthy uid or userId)
QuickMatchSchema.virtual("joinedCount").get(function () {
  if (!Array.isArray(this.slots)) return 0;
  return this.slots.filter(s => {
    // count if uid string present OR userId object present
    if (!s) return false;
    if (s.userId) return true;
    if (typeof s.uid === "string" && s.uid.trim().length > 0) return true;
    return false;
  }).length;
});

// Optional: expose joinedCount when converting to JSON
QuickMatchSchema.set("toJSON", { virtuals: true });
QuickMatchSchema.set("toObject", { virtuals: true });

module.exports = mongoose.model("QuickMatch", QuickMatchSchema);
