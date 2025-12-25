const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const Wallet = require('../models/Wallet');
const Transaction = require('../models/Transaction');
const User = require('../models/User');
const PaymentConfig = require("../models/PaymentConfig");
const auth = require('../middleware/authmiddleware');
const adminAuth = require("../middleware/adminAuth"); // Adjust path as needed
const authAdmin = require("../middleware/adminAuth");  // adjust the path if needed

const axios = require("axios");

require("dotenv").config();


const JWT_SECRET = process.env.JWT_SECRET;




// Register a new user
 


// POST /api/wallet/register


// ====================== REGISTER ======================


const sendOTP = require("../utils/sendOTP");



const Otp = require("../models/Otp");
const mailer = require("../utils/sendEmail");
const sendEmail = require("../utils/sendEmail");


/* 🔢 OTP generator */
const genOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

/* ================================
   REGISTER → SEND EMAIL OTP
================================ */
/* ================================
   REGISTER → SEND EMAIL OTP
================================ */


/* ================================
   REGISTER → SEND OTP
================================ */
router.post("/register-email", async (req, res) => {
  try {
    const { name, phone, email, password } = req.body;

    if (!name || !phone || !email || !password) {
      return res.status(400).json({ msg: "All fields required" });
    }

    const exists = await User.findOne({
      $or: [{ phone }, { email }]
    }).lean();

    if (exists) {
      return res.status(400).json({ msg: "User already exists" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await Otp.deleteMany({ email, purpose: "register" });

    await Otp.create({
      email,
      phone,
      name,
      password,
      otp,
      purpose: "register",
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    // ✅ SEND EMAIL
    sendEmail({
      to: email,
      subject: "BattlePurse Registration OTP",
      html: `<h2>Your OTP is <b>${otp}</b></h2>`
    }).catch(err => {
      console.error("OTP email failed:", err.message);
    });

    res.json({ success: true, msg: "OTP sent to email" });

  } catch (err) {
    console.error("Register-email error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

/* ================================
   VERIFY OTP → CREATE USER
================================ */
router.post("/verify-email-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ msg: "Email and OTP required" });
    }

    const record = await Otp.findOne({
      email,
      otp,
      purpose: "register",
      expiresAt: { $gt: new Date() }
    });

    if (!record) {
      return res.status(400).json({ msg: "Invalid or expired OTP" });
    }

    const exists = await User.findOne({
      $or: [{ phone: record.phone }, { email: record.email }]
    }).lean();

    if (exists) {
      await Otp.deleteMany({ email });
      return res.status(400).json({ msg: "User already registered" });
    }

    const hashedPassword = await bcrypt.hash(record.password, 10);

    await User.create({
      name: record.name,
      phone: record.phone,
      email: record.email,
      password: hashedPassword
    });

    await Otp.deleteMany({ email });

    res.json({ success: true, msg: "Registration successful" });

  } catch (err) {
    console.error("Verify-email-otp error:", err.message);
    res.status(500).json({ msg: "Server error" });
  }
});

/* ================================
   LOGIN
================================ */
router.post("/login", async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.status(400).json({ msg: "Phone and password required" });
    }

    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(400).json({ msg: "User not found" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ msg: "Wrong password" });
    }

    const token = jwt.sign(
      {
        id: user._id,
        isAdmin: user.isAdmin === true
      },
      process.env.JWT_SECRET,
      { expiresIn: "365d" }
    );

    res.json({
      success: true,
      token,
      isAdmin: user.isAdmin === true
    });

  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ msg: "Server error" });
  }
});

/* ================================
   FORGOT → SEND OTP
================================ */
router.post("/forgot/send-otp", async (req, res) => {
  try {
    const { phone, email } = req.body;

    const user = await User.findOne({ phone, email }).lean();
    if (!user) return res.status(400).json({ msg: "User not found" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await Otp.deleteMany({ email, purpose: "forgot" });

    await Otp.create({
      email,
      phone,
      otp,
      purpose: "forgot",
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    sendEmail({
      to: email,
      subject: "Password Reset OTP",
      html: `<h2>Your OTP is <b>${otp}</b></h2>`
    }).catch(err => {
      console.error("Forgot OTP email failed:", err.message);
    });

    res.json({ msg: "OTP sent" });

  } catch (err) {
    console.error("Forgot-send-otp error:", err.message);
    res.status(500).json({ msg: "Server error" });
  }
});

/* ================================
   RESEND OTP
================================ */
router.post("/resend-otp", async (req, res) => {
  try {
    const { email, purpose } = req.body;

    if (!email || !purpose) {
      return res.status(400).json({ msg: "Missing data" });
    }

    const prev = await Otp.findOne({ email, purpose });
    if (!prev) return res.status(400).json({ msg: "No OTP request found" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await Otp.deleteMany({ email, purpose });

    await Otp.create({
      email,
      phone: prev.phone,
      name: prev.name,
      password: prev.password,
      otp,
      purpose,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    sendEmail({
      to: email,
      subject: "Your OTP (Resent)",
      html: `<h2>Your new OTP is <b>${otp}</b></h2>`
    }).catch(err => {
      console.error("Resend OTP email failed:", err.message);
    });

    res.json({ msg: "OTP resent successfully" });

  } catch (err) {
    console.error("Resend-otp error:", err.message);
    res.status(500).json({ msg: "Server error" });
  }
});



router.post("/register-email", async (req, res) => {
  try {
    const { name, phone, email, password } = req.body;

    // ✅ Validate
    if (!name || !phone || !email || !password) {
      return res.status(400).json({ msg: "All fields required" });
    }

    // ✅ Check existing user
    const exists = await User.findOne({
      $or: [{ phone }, { email }]
    });

    if (exists) {
      return res.status(400).json({ msg: "User already exists" });
    }

    // ✅ Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // ✅ Remove old OTPs
    await Otp.deleteMany({ email, purpose: "register" });

    // ✅ Save OTP + temp registration data
    await Otp.create({
      email,
      phone,
      name,
      password,          // stored temporarily
      otp,
      purpose: "register",
      expiresAt: new Date(Date.now() + 5 * 60 * 1000) // 5 min
    });

    // ✅ Send email
    await mailer.sendMail({
      to: email,
      subject: "Registration OTP",
      html: `<h2>Your OTP is <b>${otp}</b></h2>`
    });

    res.json({ success: true, msg: "OTP sent to email" });

  } catch (err) {
    console.error("Register-email error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});


/* ================================
   VERIFY EMAIL OTP & CREATE USER
================================ */
/* ================================
   VERIFY EMAIL OTP & CREATE USER
================================ */
router.post("/verify-email-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ msg: "Email and OTP required" });
    }

    // ✅ Find OTP record
    const record = await Otp.findOne({
      email,
      otp,
      purpose: "register"
    });

    if (!record || record.expiresAt < Date.now()) {
      return res.status(400).json({ msg: "Invalid or expired OTP" });
    }

    // ✅ Safety check
    if (!record.password || !record.phone || !record.name) {
      return res.status(400).json({
        msg: "Registration data missing. Please resend OTP."
      });
    }

    // ✅ Check again if user already exists
    const exists = await User.findOne({
      $or: [{ phone: record.phone }, { email: record.email }]
    });

    if (exists) {
      await Otp.deleteMany({ email });
      return res.status(400).json({ msg: "User already registered" });
    }

    // ✅ Hash password
    const hashedPassword = await bcrypt.hash(record.password, 10);

    // ✅ Create user
    await User.create({
      name: record.name,
      phone: record.phone,
      email: record.email,
      password: hashedPassword
    });

    // ✅ Remove OTP
    await Otp.deleteMany({ email });

    res.json({ success: true, msg: "Registration successful" });

  } catch (err) {
    console.error("Verify-email-otp error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});




/* ================================
   LOGIN
================================ */
/* ================================
   LOGIN
================================ */
router.post("/login", async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.status(400).json({ msg: "Phone and password required" });
    }

    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(400).json({ msg: "User not found" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ msg: "Wrong password" });
    }

   const token = jwt.sign(
  {
    id: user._id,
    isAdmin: user.isAdmin === true
  },
  process.env.JWT_SECRET,
  {
    expiresIn: 12614400000   // ✅ 400 years
  }
);

res.json({
  success: true,
  token,
  isAdmin: user.isAdmin === true
});


  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

/* ================================
   FORGOT → SEND OTP
================================ */
router.post("/forgot/send-otp", async (req, res) => {
  try {
    const { phone, email } = req.body;

    const user = await User.findOne({ phone, email });
    if (!user) return res.status(400).json({ msg: "User not found" });

    const otp = genOtp();

    await Otp.deleteMany({ email, purpose: "forgot" });

    await Otp.create({
      email,
      phone,
      otp,
      purpose: "forgot",
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    await mailer.sendMail({
      to: email,
      subject: "Password Reset OTP",
      html: `<h2>Your OTP is <b>${otp}</b></h2>`
    });

    res.json({ msg: "OTP sent" });

  } catch {
    res.status(500).json({ msg: "Server error" });
  }
});

/* ================================
   FORGOT → RESET PASSWORD
================================ */
router.post("/forgot/reset", async (req, res) => {
  try {
    const { phone, email, otp, newPassword } = req.body;

    const record = await Otp.findOne({ email, phone, otp, purpose: "forgot" });
    if (!record || record.expiresAt < Date.now())
      return res.status(400).json({ msg: "Invalid or expired OTP" });

    const hashed = await bcrypt.hash(newPassword, 10);

    await User.updateOne({ phone, email }, { password: hashed });
    await Otp.deleteMany({ email });

    res.json({ msg: "Password updated" });

  } catch {
    res.status(500).json({ msg: "Server error" });
  }
});

/* ================================
   RESEND OTP (REGISTER / FORGOT)
================================ */
router.post("/resend-otp", async (req, res) => {
  try {
    const { email, purpose } = req.body; 
    // purpose = "register" or "forgot"

    if (!email || !purpose)
      return res.status(400).json({ msg: "Missing data" });

    const otp = genOtp();

    // Delete old OTP
    await Otp.deleteMany({ email, purpose });

    // Save new OTP
    await Otp.create({
      email,
      otp,
      purpose,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    await mailer.sendMail({
      to: email,
      subject: "Your OTP (Resent)",
      html: `<h2>Your new OTP is <b>${otp}</b></h2>`
    });

    res.json({ msg: "OTP resent successfully" });

  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});


function getColor(status) {
  if (!status) return "gray";
  if (status === "win") return "green";
  if (status === "lose") return "red";
  if (status === "pending") return "orange";
  return "blue";
}

// 🔹 GET USER BALANCE + ALL TRANSACTIONS
router.get('/balance', auth, async (req, res) => {
  try {
    const userId = req.user.id;

    let wallet = await Wallet.findOne({ userId });
    if (!wallet) {
      wallet = new Wallet({ userId, balance: 0 });
      await wallet.save();
    }

    const transactions = await Transaction.find({ userId })
      .sort({ createdAt: -1 })
      .limit(00);

    // Add color field
    const updatedTransactions = transactions.map(t => ({
      ...t._doc,
      color: getColor(t.type, t.amount)
    }));

    res.json({
      success: true,
      balance: wallet.balance,
      transactions: updatedTransactions
    });

  } catch (err) {
    console.error("Error in /balance:", err);
    res.status(500).json({ msg: 'Server error' });
  }
});







// Deposit to wallet
router.post("/deposit", auth, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || amount < 300) {
      return res.status(400).json({ msg: "Minimum deposit is ₹300" });
    }

    const txn = new Transaction({
      userId: req.user.id,
      amount,
      type: "deposit",
      status: "pending",
      date: new Date()
    });

    await txn.save();
    res.json({ msg: "Deposit request submitted", txn });
  } catch (err) {
    console.error("Deposit error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});


// Withdraw from wallet
router.post('/withdraw', auth, async (req, res) => {
  const { amount } = req.body;
  try {
    const wallet = await Wallet.findOne({ userId: req.user.id });
    if (!wallet || wallet.balance < amount)
      return res.status(400).json({ msg: 'Insufficient balance' });

    wallet.balance -= amount;
    await wallet.save();

    await new Transaction({ userId: req.user.id, type: 'debit', amount }).save();

    res.json({ msg: 'Withdrawal successful', balance: wallet.balance });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Admin adds balance to user wallet
router.post('/admin/approve-deposit', auth, async (req, res) => {
  try {
    const { txnId } = req.body;

    const txn = await Transaction.findById(txnId).populate('userId');
    if (!txn || txn.status !== 'pending') {
      return res.status(400).json({ msg: 'Invalid or already processed transaction' });
    }

    // Update transaction status
    txn.status = 'approved';
    await txn.save();

    // Find or create wallet
    let wallet = await Wallet.findOne({ userId: txn.userId._id });
    if (!wallet) {
      wallet = new Wallet({ userId: txn.userId._id, balance: 0 });
    }

    // Add deposit amount to wallet balance
    wallet.balance += txn.amount;
    await wallet.save();

    res.json({ success: true, msg: '✅ Deposit approved and balance updated successfully.' });
  } catch (err) {
    console.error("Approve Deposit Error:", err);
    res.status(500).json({ msg: '❌ Server error' });
  }
});

// 🔹 FILTERED TRANSACTIONS
router.get('/transactions', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { type, startDate, endDate } = req.query;

    const filter = { userId };

    if (type) filter.type = type;

    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate)   filter.createdAt.$lte = new Date(endDate);
    }

    const transactions = await Transaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(100);

    let wallet = await Wallet.findOne({ userId });
    if (!wallet) {
      wallet = new Wallet({ userId, balance: 0 });
      await wallet.save();
    }

    const updatedTransactions = transactions.map(t => ({
      ...t._doc,
      color: getColor(t.type, t.amount)
    }));

    res.json({
      success: true,
      balance: wallet.balance,
      transactions: updatedTransactions
    });

  } catch (err) {
    console.error("Error in /transactions:", err);
    res.status(500).json({ msg: 'Server error fetching transactions' });
  }
});




// Get user profile
// ✅ Get user profile (with name, phone, wallet balance, etc.)
router.get('/profile', auth, async (req, res) => {
  try {
    // 🔍 Find user & exclude password
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }

    // 💰 Get wallet balance
    const wallet = await Wallet.findOne({ userId: req.user.id });
    const balance = wallet ? wallet.balance : 0;

    // 📦 Send profile data
    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name || "Player",
        phone: user.phone,
        email: user.email,          // ✅ ADDED
        avatarUrl: user.avatarUrl,
        uids: user.uids,
        isAdmin: user.isAdmin
      },
      balance
    });

  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ msg: 'Server error' });
  }
});



// Logout (client should just delete token)
// ====================== LOGOUT ======================
router.post("/logout", auth, (req, res) => {
  return res.json({
    success: true,
    msg: "Logout successful. Please remove token from client."
  });
});

router.post('/logout', auth, (req, res) => {
  // JWT can't be invalidated unless you're using a token blacklist
  // Just instruct client to delete token
  res.json({ msg: 'Logout successful (please delete token on client)' });
});

// Profile route
router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ msg: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Save UIDs Route (Protected)



router.post("/save-uids", async (req, res) => {
  try {
    // ----------------------
    // 1️⃣ Verify token
    // ----------------------
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ msg: "No token provided" });
    }

    const token = authHeader.split(" ")[1];
    let decoded;

    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ msg: "Invalid or expired token" });
    }

    const userId = decoded.id;

    // ----------------------
    // 2️⃣ Get UIDs from request
    // ----------------------
    const { freeFire, bgmi, carrom, ludo, eightBall, cricket } = req.body;

    if (!freeFire && !bgmi && !carrom && !ludo && !eightBall && !cricket) {
      return res.status(400).json({ msg: "At least one UID is required" });
    }

    // ----------------------
    // 3️⃣ Update only UIDs using updateOne
    // ----------------------
    const updateResult = await User.updateOne(
      { _id: userId },
      {
        $set: {
          "uids.freeFire": freeFire || "",
          "uids.bgmi": bgmi || "",
          "uids.carrom": carrom || "",
          "uids.ludo": ludo || "",
          "uids.eightBall": eightBall || "",
          "uids.cricket": cricket || ""
        }
      }
    );

    if (updateResult.matchedCount === 0) {
      return res.status(404).json({ msg: "User not found" });
    }

    res.json({ success: true, msg: "Game UIDs saved successfully" });

  } catch (err) {
    console.error("Save UIDs Error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});


// Add this to routes/wallet.js
const bcrypt = require('bcrypt'); // Add at top if not already present

router.post("/change-password", auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ msg: "Old and new passwords are required." });
  }

  try {
    const user = await User.findById(req.user.id);

    if (!user || !user.password) {
      return res.status(404).json({ msg: "User or password not found." });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);


    if (!isMatch) {
      return res.status(400).json({ msg: "Old password is incorrect." });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    res.json({ msg: "Password changed successfully." });
  } catch (err) {
    console.error("Change Password Error:", err.message);
    res.status(500).send("Server error");
  }
});

const multer = require("multer");
const path = require("path");
const fs = require("fs");

// Setup multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + ext);
  },
});

const upload = multer({ storage });

// Upload avatar route
router.post("/upload-avatar", auth, upload.single("avatar"), async (req, res) => {
  if (!req.file) return res.status(400).json({ msg: "No file uploaded" });

  const fileUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;

  try {
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { avatarUrl: fileUrl },
      { new: true }
    );
    res.json({ msg: "Avatar uploaded successfully", url: fileUrl });
  } catch (err) {
    console.error("Avatar Upload Error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});


router.post("/update-profile", auth, async (req, res) => {
  const { name, freeFire, bgmi, candy, carrom, ludo, eightBall } = req.body;
  try {
    const update = {
      ...(name && { name }),
      uids: { freeFire, bgmi, candy, carrom, ludo, eightBall }
    };

    const user = await User.findByIdAndUpdate(req.user.id, update, { new: true });
    res.json({ msg: "Profile updated successfully", user });
  } catch (err) {
    console.error("Profile Update Error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

// Get all pending deposits
router.get('/admin/pending-deposits', adminAuth, async (req, res) => {
  const deposits = await Transaction.find({ type: 'deposit', status: 'pending' })
    .populate('userId', 'phone')
    .select('amount utr createdAt userId status'); // Include these fields
  res.json({ success: true, data: deposits });
});


// Approve a deposit
router.post("/admin/approve-deposit", adminAuth, async (req, res) => {
  const { txnId } = req.body;
  try {
    const txn = await Transaction.findById(txnId);
    if (!txn || txn.status !== "pending") return res.status(404).json({ msg: "Invalid transaction" });

    await User.findByIdAndUpdate(txn.userId, { $inc: { wallet: txn.amount } });
    txn.status = "completed";
    await txn.save();

    res.json({ msg: "Deposit approved & wallet updated" });
  } catch (err) {
    console.error("Approve error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

// Reject a deposit
router.post("/admin/reject-deposit", adminAuth, async (req, res) => {
  const { txnId } = req.body;
  try {
    await Transaction.findByIdAndDelete(txnId);
    res.json({ msg: "Deposit rejected and removed" });
  } catch (err) {
    console.error("Reject error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});


// Create a deposit request
router.post("/deposit-request", auth, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || amount < 300) {
      return res.status(400).json({ msg: "Minimum deposit is ₹300" });
    }

    const txn = new Transaction({
      userId: req.user.id,
      amount,
      type: "deposit",
      status: "pending",
      date: new Date()
    });

    await txn.save();
    res.json({ success: true, msg: "Proceed to payment", txnId: txn._id });

  } catch (err) {
    console.error("Deposit Request Error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// Submit UTR after payment
router.post("/submit-utr", auth, async (req, res) => {
  try {
    const { amount, utr } = req.body;

    if (!utr || !amount) {
      return res.status(400).json({ msg: "Amount and UTR are required" });
    }

    const txn = await Transaction.findOne({
      userId: req.user.id,
      amount,
      type: "deposit",
      status: "pending"
    }).sort({ date: -1 })
    .limit(100);

    if (!txn) {
      return res.status(404).json({ msg: "No matching pending transaction found" });
    }

    txn.utr = utr;
    await txn.save();

    res.json({ success: true, msg: "UTR submitted. Await admin approval." });

  } catch (err) {
    console.error("Submit UTR Error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

router.post("/make-admin", async (req, res) => {
  try {
    const { phone, email } = req.body;

    // ✅ Validation
    if (!phone || !email) {
      return res.status(400).json({
        msg: "Phone and email are required"
      });
    }

    // ✅ Find user using BOTH phone & email
    const user = await User.findOne({ phone, email });

    if (!user) {
      return res.status(404).json({
        msg: "User not found with given phone and email"
      });
    }

    // ✅ Already admin check
    if (user.isAdmin) {
      return res.status(400).json({
        msg: "User is already an admin"
      });
    }

    // ✅ Make admin
    user.isAdmin = true;
    await user.save();

    res.json({
      success: true,
      msg: `${phone} (${email}) is now an admin`
    });

  } catch (err) {
    console.error("Make admin error:", err);
    res.status(500).json({
      msg: "Server error"
    });
  }
});




router.post('/withdraw', auth, async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount < 1) return res.status(400).json({ msg: 'Invalid amount' });

  const wallet = await Wallet.findOne({ userId: req.user.id });
  if (!wallet || wallet.balance < amount)
    return res.status(400).json({ msg: 'Insufficient balance' });

  wallet.balance -= amount;
  await wallet.save();

  await new Transaction({
    userId: req.user.id,
    amount,
    type: 'withdrawal',
    status: 'pending'
  }).save();

  res.json({ success: true, msg: 'Withdrawal request submitted' });
});


// Get pending withdrawals
router.get('/admin/pending-withdrawals', adminAuth, async (req, res) => {
  const txns = await Transaction.find({ type: 'withdrawal', status: 'pending' }).populate('userId', 'phone');
  res.json(txns);
});

// Approve
router.post('/admin/approve-withdrawal', adminAuth, async (req, res) => {
  const { txnId } = req.body;
  const txn = await Transaction.findById(txnId);
  if (!txn) return res.status(404).json({ msg: 'Transaction not found' });

  txn.status = 'approved';
  await txn.save();

  res.json({ success: true, msg: 'Withdrawal approved' });
});

// Reject
router.post('/admin/reject-withdrawal', adminAuth, async (req, res) => {
  const { txnId } = req.body;
  const txn = await Transaction.findById(txnId);
  if (!txn) return res.status(404).json({ msg: 'Transaction not found' });

  const wallet = await Wallet.findOne({ userId: txn.userId });
  wallet.balance += txn.amount; // Refund
  await wallet.save();

  txn.status = 'rejected';
  await txn.save();

  res.json({ success: true, msg: 'Withdrawal rejected and refunded' });
});

// POST /api/wallet/request-withdrawal
// routes/wallet.js
router.post('/request-withdrawal', auth, async (req, res) => {
  try {
    const {
      amount,
      method,         // 'bank' or 'upi'
      bankName,
      cardNumber,
      ifsc,
      accountHolder,
      upiId
    } = req.body;

    if (!amount || amount < 500) {
      return res.status(400).json({ msg: "Minimum withdrawal is ₹500" });
    }

    if (!method || (method !== 'bank' && method !== 'upi')) {
      return res.status(400).json({ msg: "Invalid withdrawal method" });
    }

    const wallet = await Wallet.findOne({ userId: req.user.id });
    if (!wallet || wallet.balance < amount) {
      return res.status(400).json({ msg: "Insufficient wallet balance" });
    }

    // Deduct balance
    wallet.balance -= amount;
    await wallet.save();

    // Create withdrawal transaction
    const txn = new Transaction({
      userId: req.user.id,
      amount,
      type: 'withdrawal',
      status: 'pending',
      method,
      bankName: method === 'bank' ? bankName : undefined,
      cardNumber: method === 'bank' ? cardNumber : undefined,
      ifsc: method === 'bank' ? ifsc : undefined,
      accountHolder: method === 'bank' ? accountHolder : undefined,
      upiId: method === 'upi' ? upiId : undefined,
    });

    await txn.save();

    res.json({ success: true, msg: "Withdrawal request submitted" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
});


// routes/support.js



const TELEGRAM_BOT_TOKEN = '7675260954:AAHnGwI25fC_blB1XXudaHLnxQ-tqJQWm7s'; // replace this
const TELEGRAM_CHAT_ID = '6786921237';         // replace this

router.post('/support/contact', async (req, res) => {
  const { name,Username, mobile, message } = req.body;

  if (!name | !Username|| !mobile || !message) {
    return res.status(400).json({ msg: 'All fields are required' });
  }

  const text = `
📨 *New Support Message*
👤 *Name:* ${name}
 📨 *Username:* ${Username}
📱 *Mobile:* ${mobile}
📝 *Message:* ${message}
`;

  try {
    await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text,
      parse_mode: 'Markdown'
    });

    res.json({ msg: 'Message sent to BattlePurse.' });
  } catch (err) {
    console.error('Telegram Error:', err.message);
    res.status(500).json({ msg: 'Failed to send message.' });
  }
});



// Replace with your actual bot token and Telegram chat ID


router.post('/supports/contact', async (req, res) => {
  const { name, email, message } = req.body;

  // Validate fields
  if (!name || !email || !message) {
    return res.status(400).json({ msg: 'All fields are required' });
  }

  // Construct the message for Telegram
  const text = `
📨 *New Support Message*
👤 *Name:* ${name}
📧 *Email:* ${email}
📝 *Message:* ${message}
`;

  try {
    // Send message to Telegram
    await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text,
      parse_mode: 'Markdown'
    });

    res.json({ msg: 'Message sent to support.' });
  } catch (err) {
    console.error('Telegram Error:', err.message);
    res.status(500).json({ msg: 'Failed to send message.' });
  }
});

// GET /api/wallet/admin/users

// ✅ 1. Get All Registered Users
router.get('/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, 'phone isAdmin banned');
    res.json({ users });
  } catch (err) {
    res.status(500).json({ msg: 'Failed to fetch users' });
  }
});

// ✅ 2. Ban a User
router.put('/admin/ban/:id', adminAuth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.id, { banned: true });
    res.json({ msg: 'User banned successfully' });
  } catch (err) {
    res.status(500).json({ msg: 'Failed to ban user' });
  }
});

// ✅ 3. Unban a User
router.put('/admin/unban/:id', adminAuth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.id, { banned: false });
    res.json({ msg: 'User unbanned successfully' });
  } catch (err) {
    res.status(500).json({ msg: 'Failed to unban user' });
  }
});

// ✅ 4. Reset Password
router.put('/admin/reset-password/:id', adminAuth, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ msg: 'New password must be at least 4 characters' });
  }

  try {
    const hashed = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(req.params.id, { password: hashed });
    res.json({ msg: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ msg: 'Failed to reset password' });
  }
});

// ✅ Admin - Get any user's profile
router.get('/admin/user/:id', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ msg: 'User not found' });

    const wallet = await Wallet.findOne({ userId: req.params.id });
    const balance = wallet ? wallet.balance : 0;

    res.json({ user, balance });
  } catch (err) {
    res.status(500).json({ msg: 'Failed to load profile' });
  }
});

// ==================== 🎮 GAME ROUTES ====================

const Game = require('../models/Game');

// Get all games
router.get('/games', async (req, res) => {
  try {
    const games = await Game.find();
    res.json(games);
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

const Tournament = require('../models/Tournament');

// Create tournament (with poster)
// ✅ GET all tournaments
router.get("/tournaments", async (req, res) => {
  try {
    const tournaments = await Tournament.find().sort({ createdAt: -1 })
    .limit(100);
    res.json(tournaments);
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});

// ✅ ADMIN uploads room details
router.post("/tournaments/:tournamentId/room", auth, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { roomId, roomPassword } = req.body;

    if (req.user.role !== "admin")
      return res.status(403).json({ msg: "Access denied. Admins only." });

    const tournament = await Tournament.findById(tournamentId);
    if (!tournament)
      return res.status(404).json({ msg: "Tournament not found" });

    tournament.roomInfo = {
      roomId: roomId || "",
      roomPassword: roomPassword || "",
      uploadedAt: new Date(),
    };

    tournament.roomUploaded = true;
    await tournament.save();

    return res.json({
      msg: "Room details uploaded successfully",
      roomUploaded: true,
      roomInfo: tournament.roomInfo,
    });
  } catch (err) {
    console.error("Room upload error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

// ✅ USER leaves tournament (with lock checks)
router.delete("/leave/:tournamentId", auth, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const userId = req.user.id;

    const tournament = await Tournament.findById(tournamentId);
    if (!tournament)
      return res.status(404).json({ msg: "Tournament not found" });

    // 🚫 block leaving if admin uploaded room details
    if (tournament.roomUploaded || (tournament.roomInfo && tournament.roomInfo.roomId)) {
      return res.status(400).json({
        msg: "You cannot leave now. Admin has uploaded room details.",
      });
    }

    // 🚫 block if results uploaded
    if (tournament.resultsUploaded === true) {
      return res.status(400).json({
        msg: "You cannot leave now. Tournament results already uploaded.",
      });
    }

    // remove user from joined list
    const index = tournament.joinedUsers.findIndex(
      (u) => u.userId.toString() === userId.toString()
    );
    if (index === -1)
      return res.status(400).json({ msg: "You are not joined in this tournament." });

    tournament.joinedUsers.splice(index, 1);
    await tournament.save();

    // refund entry fee
    let wallet = await Wallet.findOne({ userId });
    if (!wallet) wallet = new Wallet({ userId, balance: 0 });
    wallet.balance += tournament.entryFee;
    await wallet.save();

    // create transaction record
    await Transaction.create({
      userId,
      type: "refund",
      amount: tournament.entryFee,
      description: `Refund for leaving tournament: ${tournament.name}`,
    });

    return res.json({
      msg: "Left tournament successfully",
      balance: wallet.balance,
    });

  } catch (err) {
    console.error("Leave error:", err);
    res.status(500).json({ msg: "Server error", error: err.message });
  }
});

// List all tournaments
router.get("/tournaments", auth, async (req, res) => {
  try {
    const tournaments = await Tournament.find()
      .select("name entryFee prizePool maxPlayers date time poster roomInfo results resultsUploaded userResults joinedUsers");
    res.json(tournaments);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
});


router.get('/tournaments', async (req, res) => {
  try {
    const tournaments = await Tournament.find();
    res.json(tournaments);
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Get specific tournament
// Get tournament details by ID
router.get("/tournaments/:id", auth, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    const tournament = await Tournament.findById(id);
    if (!tournament) return res.status(404).json({ msg: "Tournament not found" });

    const joinedUser = tournament.joinedUsers.find(
      u => u.userId.toString() === userId
    );

    const result = {
      name: tournament.name,
      game: tournament.game,                 // still plain string (or ObjectId if populated)
      date: tournament.date,
      time: tournament.time,                 // ✅ now included
      mode: tournament.mode,                 // ✅ now included
      entryFee: tournament.entryFee,
      prizePool: tournament.prizePool,
      maxPlayers: tournament.maxPlayers,
      poster: tournament.poster 
        ? `https://battlepurse-17.onrender.com/uploads/${tournament.poster}` // ✅ return full image URL
        : null,
      roomId: joinedUser ? tournament.roomId : null,
      roomPassword: joinedUser ? tournament.roomPassword : null,
      joined: !!joinedUser
    };

    res.json(result);
  } catch (err) {
    console.error("Error fetching tournament:", err);
    res.status(500).json({ msg: "Server error" });
  }
});



// ✅ GET Tournament Details + Joined Status
// ✅ GET Tournament Details (User/Admin unified)
router.get("/tournament/:id", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const isAdmin = req.user.role === "admin"; // make sure your User model has a 'role' field
    const tournamentId = req.params.id;

    // Find tournament and populate joinedUsers.userId if admin
    const tournamentQuery = Tournament.findById(tournamentId);
    if (isAdmin) {
      tournamentQuery.populate("joinedUsers.userId", "name phone wallet avatarUrl");
    } else {
      tournamentQuery.populate("joinedUsers.userId", "name phone");
    }

    const tournament = await tournamentQuery.lean();

    if (!tournament) {
      return res.status(404).json({ msg: "Tournament not found" });
    }

    // Prepare base response
    const response = {
      tournamentId: tournament._id,
      name: tournament.name,
      game: tournament.game,
      date: tournament.date,
      entryFee: tournament.entryFee,
      prizePool: tournament.prizePool,
      maxPlayers: tournament.maxPlayers,
      mode: tournament.mode,
      joinedCount: tournament.joinedUsers.length,
    };

    if (isAdmin) {
      // Admin gets all joined users details
      response.players = tournament.joinedUsers.map(u => ({
        userId: u.userId?._id || null,
        name: u.userId?.name || "Unknown",
        phone: u.userId?.phone || "N/A",
        avatarUrl: u.userId?.avatarUrl || "",
        wallet: u.userId?.wallet || 0,
        gameUIDs: u.gameUIDs || [],
        paid: u.paid || false,
        joinedAt: u.createdAt || tournament.createdAt,
      }));
      response.totalPlayers = response.players.length;
    } else {
      // Regular user: show if they joined + their own UIDs
      const joinedUser = tournament.joinedUsers.find(
        u => u.userId._id.toString() === userId
      );
      response.joined = !!joinedUser;

      if (joinedUser) {
        response.joinedUsers = tournament.joinedUsers.map(u => ({
          userId: u.userId._id,
          name: u.userId.name,
          phone: u.userId.phone,
          gameUIDs: u.gameUIDs,
          paid: u.paid,
        }));

        response.roomInfo = {
          roomId: tournament.roomId || null,
          roomPassword: tournament.roomPassword || null,
        };
      }
    }

    res.json(response);
  } catch (err) {
    console.error("Error fetching tournament:", err);
    res.status(500).json({ msg: "Server error" });
  }
});




// Update tournament
router.put('/tournaments/:id', adminAuth, async (req, res) => {
  try {
    const updated = await Tournament.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json({ msg: 'Tournament updated', updated });
  } catch (err) {
    res.status(500).json({ msg: 'Update failed' });
  }
});

// Delete tournament
router.delete('/tournaments/:id', adminAuth, async (req, res) => {
  try {
    await Tournament.findByIdAndDelete(req.params.id);
    res.json({ msg: 'Tournament deleted' });
  } catch (err) {
    res.status(500).json({ msg: 'Delete failed' });
  }
});

const TournamentJoin = require('../models/TournamentJoin');

// Join tournament
// routes/wallet.js

// Leave tournament
router.delete('/leave/:tournamentId', auth, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const userId = req.user.id;

    // find tournament
    const tournament = await Tournament.findById(tournamentId);
    if (!tournament)
      return res.status(404).json({ msg: "Tournament not found" });

    // ❌ block if admin uploaded room details
    if (tournament.roomInfo && tournament.roomInfo.roomId) {
      return res.status(400).json({
        msg: "You cannot leave now. Admin already uploaded room details."
      });
    }

    // ❌ block if results already uploaded
    if (tournament.resultsUploaded === true || (tournament.results && tournament.results.length > 0)) {
      return res.status(400).json({
        msg: "You cannot leave now. Tournament results already uploaded."
      });
    }

    // find user in joinedUsers
    const index = tournament.joinedUsers.findIndex(
      u => u.userId.toString() === userId.toString()
    );

    if (index === -1) {
      return res.status(400).json({ msg: "You have not joined this tournament." });
    }

    // remove user
    const entryFee = tournament.entryFee;
    tournament.joinedUsers.splice(index, 1);
    await tournament.save();

    // refund wallet
    let wallet = await Wallet.findOne({ userId });
    if (!wallet) wallet = new Wallet({ userId, balance: 0 });
    wallet.balance += Number(entryFee);
    await wallet.save();

    // transaction log
    await Transaction.create({
      userId,
      type: "refund",
      amount: entryFee,
      description: `Refund for leaving tournament: ${tournament.name}`,
    });

    return res.json({
      msg: "Successfully left and refunded.",
      balance: wallet.balance,
    });

  } catch (err) {
    console.error("Leave error:", err);
    return res.status(500).json({ msg: "Server error" });
  }
});






// Upload tournament poster
router.post('/uploads/tournament-banner', adminAuth, upload.single('banner'), async (req, res) => {
  try {
    const imageUrl = `/uploads/${req.file.filename}`;
    res.json({ msg: 'Tournament banner uploaded', imageUrl });
  } catch (err) {
    res.status(500).json({ msg: 'Upload failed' });
  }
});

// Upload match result


// Upload screenshot


router.post(
  "/uploadResult/:tournamentId",
  auth,
  upload.single("screenshot"), // must match frontend field name
  async (req, res) => {
    try {
      const { tournamentId } = req.params;

      // Find the tournament
      const tournament = await Tournament.findById(tournamentId);
      if (!tournament) {
        return res.status(404).json({ msg: "Tournament not found" });
      }

      // Check if file is uploaded
      if (!req.file) {
        return res.status(400).json({ msg: "No screenshot uploaded" });
      }

      // Ensure results array exists
      if (!Array.isArray(tournament.results)) {
        tournament.results = [];
      }

      // Add result to tournament
      const resultData = {
        userId: req.user.id,
        screenshot: req.file.filename, // multer saves filename
        uploadedAt: new Date(),
      };

      tournament.results.push(resultData);
      await tournament.save();

      res.json({
        msg: "Screenshot uploaded successfully!",
        result: resultData,
      });
    } catch (err) {
      console.error("Upload error:", err);
      res.status(500).json({ msg: "Server error while uploading result" });
    }
  }
);



const Match = require('../models/Match');

// Create match
router.post('/tournaments/:id/matches', adminAuth, async (req, res) => {
  const players = await TournamentJoin.find({ tournamentId: req.params.id }).select('userId -_id');
  const match = new Match({
    tournamentId: req.params.id,
    players: players.map(p => p.userId),
  });
  await match.save();
  res.json({ msg: 'Match created', match });
});

// List matches
router.get('/tournaments/:id/matches', async (req, res) => {
  const matches = await Match.find({ tournamentId: req.params.id })
    .populate('players', 'phone')
    .populate('tournamentId', 'name');
  res.json(matches);
});

// Update match result
router.put('/matches/:matchId', adminAuth, async (req, res) => {
  const updated = await Match.findByIdAndUpdate(req.params.matchId, { result: req.body.result }, { new: true });
  res.json({ msg: 'Result updated', updated });
});

// Get joined players


// Get all players who joined a specific tournament (Admin view)
// GET /tournaments/:id/players
// Admin route to fetch all joined users (no room info)
// ✅ Admin route to fetch all tournament info + joined users
// routes/wallet.js (or wherever your routes live)



// Admin (or authorized) endpoint to get players for a tournament
// ✅ Admin (or authorized) endpoint to get all tournament players with UID support
router.get("/tournaments/:id/players", /* authAdmin, */ async (req, res) => {
  try {
    const tournamentId = req.params.id;

    const tournament = await Tournament.findById(tournamentId)
      .populate("joinedUsers.userId", "name phone avatarUrl uid gameUIDs")
      .lean();

    if (!tournament)
      return res.status(404).json({ msg: "Tournament not found" });

    // pick whichever array has actual players
    const participants = Array.isArray(tournament.joinedUsers) && tournament.joinedUsers.length > 0
      ? tournament.joinedUsers
      : Array.isArray(tournament.players)
        ? tournament.players
        : [];

    // get all userIds
    const userIds = participants
      .map((p) => p.userId?._id)
      .filter(Boolean);

    // fetch wallets for all players
    const wallets = await Wallet.find({ userId: { $in: userIds } }).lean();
    const walletMap = wallets.reduce((map, w) => {
      map[w.userId.toString()] =
        typeof w.balance === "number" ? w.balance : 0;
      return map;
    }, {});

    // build player list
    const players = participants.map((p) => {
      const uid = p.userId?._id?.toString();

      // ✅ Correct gameUID logic for solo/duo/squad
      const uidList = Array.isArray(p.gameUIDs)
        ? p.gameUIDs
        : p.userId?.gameUIDs
          ? Array.isArray(p.userId.gameUIDs)
            ? p.userId.gameUIDs
            : [p.userId.gameUIDs]
          : p.userId?.uid
            ? [p.userId.uid]
            : [];

      // ✅ Use each player's real join time
      const joinedAt =
        p.joinedAt || p.createdAt || tournament.createdAt || null;

      return {
        userId: uid,
        name: p.name || p.userId?.name || "Unknown",
        phone: p.phone || p.userId?.phone || "N/A",
        avatarUrl: p.userId?.avatarUrl || "",
        wallet: walletMap[uid] ?? 0,
        gameUIDs: uidList,
        paid: !!p.paid,
        joinedAt,
      };
    });

    res.json({
      success: true,
      tournamentId: tournament._id,
      tournamentName: tournament.name,
      game: tournament.game,
      mode: tournament.mode,
      date: tournament.date || null,
      time: tournament.time || null,
      entryFee: tournament.entryFee,
      prizePool: tournament.prizePool,
      maxPlayers: tournament.maxPlayers,
      totalPlayers: players.length,
      players,
    });
  } catch (err) {
    console.error("Error fetching tournament players:", err);
    res.status(500).json({ msg: "Server error" });
  }
});



// Route 2: Authenticated users creating tournaments (if allowed)


router.post('/tournaments', adminAuth, upload.single('poster'), async (req, res) => {
  try {
    const {
      name,
      game,
      gameId,
      mode,
      date,
      time,
      entryFee,
      prizePool,
      maxPlayers,
      description
    } = req.body;

    const tournament = new Tournament({
      name,
      game,
      gameId,
      mode,
      date,
      time,
      entryFee,
      prizePool,
      maxPlayers,
      description,
      poster: req.file ? req.file.filename : null,
      posterUrl: req.file ? `/uploads/${req.file.filename}` : null,
      players: []
    });

    await tournament.save();
    res.json({ msg: 'Tournament created successfully', tournament });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Error creating tournament' });
  }
});

// routes/wallet.js

const Promo = require("../models/promo");



// ================= ROUTES ================= //

// Promo routes



// ===== Routes =====

// Get all promos
// routes/promoRoutes.js


// POST add promo
// GET all active promos

// POST add promo
router.post("/promos", upload.array("images", 10), async (req, res) => {
  try {
    if (!req.body.title || !req.files.length) {
      return res.status(400).json({ error: "Title and images are required" });
    }

    const promo = new Promo({
      title: req.body.title,
      images: req.files.map(f => f.filename)
    });

    await promo.save();
    res.json({ msg: "Promo added successfully", promo });
  } catch (err) {
    console.error("Error adding promo", err);
    res.status(500).json({ error: "Failed to add promo" });
  }
});

// GET all promos
router.get("/promos", async (req, res) => {
  try {
    const promos = await Promo.find().sort({ createdAt: -1 })
    .limit(100);
    res.json(promos);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch promos" });
  }
});

// DELETE promo
router.delete("/promos/:id", async (req, res) => {
  try {
    await Promo.findByIdAndDelete(req.params.id);
    res.json({ msg: "Promo deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete promo" });
  }
});



// ✅ Admin uploads or updates room ID & password
router.put("/tournaments/:id/room", authAdmin, async (req, res) => {
  try {
    const { roomId, roomPassword } = req.body;

    if (!roomId || !roomPassword) {
      return res.status(400).json({ msg: "Room ID and Room Password are required" });
    }

    // Update tournament + lock leave option
    const tournament = await Tournament.findByIdAndUpdate(
      req.params.id,
      { 
        roomId, 
        roomPassword,
        roomUploaded: true // 🔒 lock leaving
      },
      { new: true }
    );

    if (!tournament) {
      return res.status(404).json({ msg: "Tournament not found" });
    }

    res.json({
      success: true,
      msg: "Room details uploaded successfully",
      roomUploaded: true,
      tournament
    });

  } catch (err) {
    console.error("Room Upload Error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});



router.post("/tournaments/:tournamentId/room", auth, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { roomId, roomPassword } = req.body;

    // check admin
    if (req.user.role !== "admin") {
      return res.status(403).json({ msg: "Access denied. Admins only." });
    }

    const tournament = await Tournament.findById(tournamentId);
    if (!tournament) {
      return res.status(404).json({ msg: "Tournament not found" });
    }

    // ✅ save room details
    tournament.roomInfo = {
      roomId: roomId || "",
      roomPassword: roomPassword || "",
      uploadedAt: new Date(),
    };

    // ✅ lock leave
    tournament.roomUploaded = true;

    await tournament.save();

    return res.json({
      msg: "Room details uploaded successfully",
      roomUploaded: true,
      roomInfo: tournament.roomInfo,
      joinedCount: tournament.joinedUsers?.length || 0,
    });
  } catch (err) {
    console.error("Room upload error:", err);
    res.status(500).json({ msg: "Server error", error: err.message });
  }
});




// Backend: GET room details for members
router.get("/tournaments/:id/room", auth, async (req, res) => {
  try {
    const tournament = await Tournament.findById(req.params.id);

    if (!tournament) {
      return res.status(404).json({ msg: "Tournament not found" });
    }

    res.json({
      roomId: tournament.roomId || null,
      roomPassword: tournament.roomPassword || null
    });
  } catch (err) {
    console.error("Fetch Room Error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});




// Admin route to get all results for a specific tournament
const mongoose = require("mongoose");

// GET /results/admin/:tournamentId
router.get("/results/:tournamentId", authAdmin, async (req, res) => {
  try {
    const { tournamentId } = req.params;

    const tournament = await Tournament.findById(tournamentId).populate(
      "results.userId",
      "name phone email" // only limited user details
    );

    if (!tournament) {
      return res.status(404).json({ msg: "Tournament not found" });
    }

    res.json({
      tournamentName: tournament.name,
      results: (tournament.results || []).map(r => ({
        id: r._id,
        screenshot: r.screenshot
          ? `https://battlepurse-17.onrender.com/uploads/${r.screenshot}` // ✅ Correct: serve actual file
          : null,
        uploadedAt: r.uploadedAt,
        user: r.userId
          ? {
              id: r.userId._id,
              name: r.userId.name || "Unknown",
              phone: r.userId.phone || "N/A",
              email: r.userId.email || "N/A",
            }
          : { id: null, name: "Unknown", phone: "N/A", email: "N/A" },
      })),
    });
  } catch (err) {
    console.error("Admin fetch error:", err);
    res.status(500).json({
      msg: "Server error while fetching results",
      error: err.message,
    });
  }
});

// POST /declareWinner/:tournamentId
// ✅ Declare winners and distribute prize money
router.post('/join/:tournamentId', auth, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { uids } = req.body;
    const userId = req.user.id;

    // 🔹 Find tournament
    const tournament = await Tournament.findById(tournamentId);
    if (!tournament) 
      return res.status(404).json({ msg: "Tournament not found" });

    // 🔹 Find user
    const user = await User.findById(userId);
    if (!user) 
      return res.status(404).json({ msg: "User not found" });

    // 🔹 Find or create wallet
    let wallet = await Wallet.findOne({ userId });
    if (!wallet) {
      wallet = new Wallet({ userId, balance: 0 });
      await wallet.save();
    }

    // 🔹 Check if already joined
    const existingJoin = tournament.joinedUsers.find(
      u => u.userId.toString() === userId
    );
    if (existingJoin) {
      return res.json({
        msg: "Already joined this tournament.",
        redirect: `/joined.html?id=${tournamentId}`,
      });
    }

    // 🔹 Check if tournament is full
    if (tournament.joinedUsers.length >= tournament.maxPlayers) {
      return res.status(400).json({ msg: "Tournament is full" });
    }

    // 🔹 Wallet balance check
    if (wallet.balance < tournament.entryFee) {
      return res.status(400).json({ msg: "Insufficient balance" });
    }

    // 🔹 Deduct entry fee
    wallet.balance -= tournament.entryFee;
    await wallet.save();

    // 🔹 Add player details
    tournament.joinedUsers.push({
      userId: user._id,
      name: user.name,
      phone: user.phone,
      gameUIDs: Array.isArray(uids) ? uids : [],
      paid: true,
    });
    await tournament.save();

    // 🔹 Log transaction
    const transaction = new Transaction({
      userId,
      type: "debit",
      amount: tournament.entryFee,
      description: `Joined tournament: ${tournament.name}`,
    });
    await transaction.save();

    // 🔹 Success response
    res.json({
      msg: "Successfully joined tournament!",
      redirect: `/joined.html?id=${tournament._id}`,
    });

  } catch (err) {
    console.error("Join error:", err);
    res.status(500).json({ msg: "Server error" });
  }
}); 


// ✅ JOIN TOURNAMENT ROUTE
router.post('/join/:tournamentId', auth, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { uids } = req.body;
    const userId = req.user.id;

    // 🔹 Find tournament
    const tournament = await Tournament.findById(tournamentId);
    if (!tournament)
      return res.status(404).json({ msg: "Tournament not found" });

    // 🔹 Find user
    const user = await User.findById(userId);
    if (!user)
      return res.status(404).json({ msg: "User not found" });

    // 🔹 Find or create wallet
    let wallet = await Wallet.findOne({ userId });
    if (!wallet) {
      wallet = new Wallet({ userId, balance: 0 });
      await wallet.save();
    }

    // 🔹 Check if already joined
    const alreadyJoined = tournament.joinedUsers.some(
      u => u.userId.toString() === userId
    );
    if (alreadyJoined) {
      return res.json({
        msg: "You already joined this tournament.",
        redirect: `/joined.html?id=${tournamentId}`,
      });
    }

    // 🔹 Check if tournament is full
    if (tournament.joinedUsers.length >= tournament.maxPlayers) {
      return res.status(400).json({ msg: "Tournament is full" });
    }

    // 🔹 Wallet balance check
    if (wallet.balance < tournament.entryFee) {
      return res.status(400).json({ msg: "Insufficient balance" });
    }

    // ✅ Handle required UID count based on mode
    const requiredUIDs =
      tournament.mode === "duo" ? 2 :
      tournament.mode === "squad" ? 4 : 1;

    if (!uids || !Array.isArray(uids) || uids.length !== requiredUIDs) {
      return res.status(400).json({
        msg: `Invalid UID input. This ${tournament.mode} tournament requires ${requiredUIDs} UID(s).`,
      });
    }

    // 🔹 Deduct entry fee
    wallet.balance -= tournament.entryFee;
    await wallet.save();

    // 🔹 Add player details
    tournament.joinedUsers.push({
      userId: user._id,
      name: user.name,
      phone: user.phone,
      gameUIDs: uids,
      paid: true,
      joinedAt: new Date(), // ✅ record exact join time
    });
    await tournament.save();

    // 🔹 Log transaction
    const transaction = new Transaction({
      userId,
      type: "debit",
      amount: tournament.entryFee,
      description: `Joined ${tournament.name} (${tournament.mode})`,
      createdAt: new Date(),
    });
    await transaction.save();

    // ✅ Success response
    res.json({
      success: true,
      msg: "Successfully joined tournament!",
      tournamentId: tournament._id,
      mode: tournament.mode,
      joinedAt: new Date(),
      redirect: `/joined.html?id=${tournament._id}`,
    });

  } catch (err) {
    console.error("Join error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});




// ✅ GET /api/wallet/leaderboard/:tournamentId
// 🏆 Live Leaderboard - Admin Declared Winners
// Get tournament details for a user

router.get("/tournament/:tournamentId", auth, async (req, res) => {
  try {
    const { tournamentId } = req.params;

    const tournament = await Tournament.findById(tournamentId)
      .populate("joinedUsers.userId", "name phone wallet avatarUrl") // populate user info
      .lean();

    if (!tournament) {
      return res.status(404).json({ msg: "Tournament not found" });
    }

    const players = Array.isArray(tournament.joinedUsers) ? tournament.joinedUsers : [];
    const joinedCount = players.length;

    const startTime = tournament.startTime || tournament.date || tournament.createdAt || null;

    // check if logged-in user has joined
    const hasJoined = req.user
      ? players.some(p => p.userId?._id?.toString() === req.user.id)
      : false;

    // check if leaving is allowed
    const canLeave = !tournament.roomUploaded && !tournament.resultsUploaded;

    const formattedPlayers = players.map(p => {
      const uid = p.userId?._id?.toString();
      return {
        userId: uid,
        name: p.userId?.name || p.name || "Unknown",
        phone: p.userId?.phone || p.phone || "N/A",
        wallet: p.userId?.wallet ?? 0,
        avatarUrl: p.userId?.avatarUrl || null,
        gameUIDs: Array.isArray(p.gameUIDs) ? p.gameUIDs : (p.gameUIDs ? [p.gameUIDs] : []),
        paid: !!p.paid,
        joinedAt: p.joinedAt || p.createdAt || tournament.createdAt || null
      };
    });

    res.json({
      id: tournament._id,
      name: tournament.title || tournament.name || "Tournament",
      game: tournament.game,
      mode: tournament.mode,
      entryFee: tournament.entryFee,
      prizePool: tournament.prizePool,
      maxPlayers: tournament.maxPlayers,
      joinedCount,
      hasJoined,
      startTime,
      canLeave,
      roomInfo: tournament.roomInfo ? {
        ...tournament.roomInfo,
        uploadedAt: tournament.roomUploaded ? tournament.roomInfo.uploadedAt || tournament.updatedAt : null
      } : null,
      players: formattedPlayers
    });
  } catch (err) {
    console.error("GET tournament error:", err);
    return res.status(500).json({ msg: "Server error" });
  }
});



// ✅ Member sees their declared result
// ✅ GET /api/wallet/myResult/:tournamentId
// GET /api/wallet/memberResults/:tournamentId
router.get("/memberResults/:tournamentId", auth, async (req, res) => {
  try {
    const { tournamentId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(tournamentId)) {
      return res.status(400).json({ msg: "Invalid tournament ID" });
    }

    const tournament = await Tournament.findById(tournamentId)
      .populate("winners.userId", "name avatarUrl wallet");

    if (!tournament) {
      return res.status(404).json({ msg: "Tournament not found" });
    }

    // Send winners only
    const winners = (tournament.winners || []).map(w => ({
      userId: w.userId?._id || null,
      name: w.userId?.name || w.name || "Unknown",
      avatarUrl: w.userId?.avatarUrl || "",
      position: w.position,
      prize: w.prize || 0,
      declaredAt: w.declaredAt,
    }));

    res.json({
      tournamentId: tournament._id,
      tournamentName: tournament.name,
      winners
    });
  } catch (err) {
    console.error("Member leaderboard fetch error:", err);
    res.status(500).json({ msg: "Server error", error: err.message });
  }
});



router.post("/declareWinner/:tournamentId", authAdmin, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { winners } = req.body;

    if (!Array.isArray(winners) || winners.length === 0 || winners.length > 3)
      return res.status(400).json({ msg: "Winners array must include 1–3 players" });

    const positions = winners.map(w => w.position);
    if (new Set(positions).size !== positions.length)
      return res.status(400).json({ msg: "Duplicate positions are not allowed" });

    if (!positions.every(p => [1, 2, 3].includes(p)))
      return res.status(400).json({ msg: "Positions must be 1, 2, 3" });

    const tournament = await Tournament.findById(tournamentId);
    if (!tournament)
      return res.status(404).json({ msg: "Tournament not found" });

    // 💰 Prize logic
    const totalPrize = tournament.prizePool;
    const adminCut = totalPrize * 0.05;
    const remaining = totalPrize - adminCut;
    const distribution = { 1: remaining * 0.5, 2: remaining * 0.3, 3: remaining * 0.2 };

    const declaredWinners = [];

    for (const w of winners) {
      if (!w.userId) continue;

      const user = await User.findById(w.userId);
      if (!user) continue;

      const prizeAmount = distribution[w.position] || 0;

      // 💼 Wallet update
      let wallet = await Wallet.findOne({ userId: user._id });
      if (!wallet) wallet = new Wallet({ userId: user._id, balance: 0 });

      wallet.balance += prizeAmount;
      await wallet.save();

      // 💳 Tournament award transaction
      await new Transaction({
        userId: user._id,
        amount: prizeAmount,
        type: "tournament_award",   // ⭐ UPDATED
        description: `🏆 Tournament Award - ₹${prizeAmount} in ${tournament.name}`, // ⭐ UPDATED
        sign: "+",
        uiColor: "green"
      }).save();

      const rankEmoji = w.position === 1 ? "🥇" : w.position === 2 ? "🥈" : "🥉";

      declaredWinners.push({
        name: user.name,
        userId: user._id,
        gameUid: w.gameUid || user.gameUid || "N/A",
        prize: prizeAmount,
        avatarUrl: user.avatarUrl || "https://cdn-icons-png.flaticon.com/512/147/147144.png",
        rankEmoji,
        position: w.position,
        declaredAt: new Date(),
        sign: "+",
        uiColor: "green"
      });
    }

    // 💼 Admin commission
    const admin = await User.findOne({ role: "admin" });
    if (admin) {
      let adminWallet = await Wallet.findOne({ userId: admin._id });
      if (!adminWallet) adminWallet = new Wallet({ userId: admin._id, balance: 0 });

      adminWallet.balance += adminCut;
      await adminWallet.save();

      await new Transaction({
        userId: admin._id,
        amount: adminCut,
        type: "credit",
        description: `🏦 Admin commission from ${tournament.name}`,
        sign: "+",
        uiColor: "green"
      }).save();
    }

    // Save winners
    const updatedWinners = [...(tournament.winners || [])];
    declaredWinners.forEach(winner => {
      const idx = updatedWinners.findIndex(x => x.position === winner.position);
      if (idx !== -1) updatedWinners[idx] = winner;
      else updatedWinners.push(winner);
    });

    tournament.winners = updatedWinners;
    await tournament.save();

    res.json({
      success: true,
      msg: "🏁 Winners declared!",
      tournamentName: tournament.name,
      winners: updatedWinners,
      adminCut
    });

  } catch (err) {
    console.error("Declare winners error:", err);
    res.status(500).json({ msg: "Server error", error: err.message });
  }
});

// POST /declareWinner/:tournamentId
router.post("/declareWinner/:tournamentId", authAdmin, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { winners } = req.body;

    if (!Array.isArray(winners) || winners.length === 0 || winners.length > 3)
      return res.status(400).json({ msg: "Winners array must include 1–3 players" });

    const positions = winners.map(w => w.position);
    if (new Set(positions).size !== positions.length)
      return res.status(400).json({ msg: "Duplicate positions are not allowed" });

    if (!positions.every(p => [1, 2, 3].includes(p)))
      return res.status(400).json({ msg: "Positions must be 1, 2, or 3" });

    const tournament = await Tournament.findById(tournamentId);
    if (!tournament)
      return res.status(404).json({ msg: "Tournament not found" });

    // 💰 Prize logic
    const totalPrize = tournament.prizePool;
    const adminCut = totalPrize * 0.05;
    const remaining = totalPrize - adminCut;
    const distribution = { 1: remaining * 0.5, 2: remaining * 0.3, 3: remaining * 0.2 };

    const declaredWinners = [];

    for (const w of winners) {
      if (!w.userId) continue;

      const user = await User.findById(w.userId);
      if (!user) continue;

      const prizeAmount = distribution[w.position] || 0;

      // 💼 Wallet update
      let wallet = await Wallet.findOne({ userId: user._id });
      if (!wallet) wallet = new Wallet({ userId: user._id, balance: 0 });

      wallet.balance += prizeAmount;
      await wallet.save();

      // 💳 Transaction for winning
      await new Transaction({
        userId: user._id,
        amount: prizeAmount,
        type: "winning",
        description: `🏆 Won ₹${prizeAmount} in ${tournament.name}`,
        sign: "+",
        uiColor: "green"
      }).save();

      const rankEmoji = w.position === 1 ? "🥇" : w.position === 2 ? "🥈" : "🥉";

      declaredWinners.push({
        name: user.name,
        userId: user._id,
        gameUid: w.gameUid || user.gameUid || "N/A",
        prize: prizeAmount,
        avatarUrl: user.avatarUrl || "https://cdn-icons-png.flaticon.com/512/147/147144.png",
        rankEmoji,
        position: w.position,
        declaredAt: new Date(),
        sign: "+",
        uiColor: "green"
      });
    }

    // 💼 Admin commission
    const admin = await User.findOne({ role: "admin" });
    if (admin) {
      let adminWallet = await Wallet.findOne({ userId: admin._id });
      if (!adminWallet) adminWallet = new Wallet({ userId: admin._id, balance: 0 });

      adminWallet.balance += adminCut;
      await adminWallet.save();

      await new Transaction({
        userId: admin._id,
        amount: adminCut,
        type: "credit",
        description: `🏦 Admin commission from ${tournament.name}`,
        sign: "+",
        uiColor: "green"
      }).save();
    }

    // Save winners
    const updatedWinners = [...(tournament.winners || [])];
    declaredWinners.forEach(winner => {
      const idx = updatedWinners.findIndex(x => x.position === winner.position);
      if (idx !== -1) updatedWinners[idx] = winner;
      else updatedWinners.push(winner);
    });

    tournament.winners = updatedWinners;
    await tournament.save();

    res.json({
      success: true,
      msg: "🏁 Winners declared!",
      tournamentName: tournament.name,
      winners: updatedWinners,
      adminCut
    });

  } catch (err) {
    console.error("Declare winners error:", err);
    res.status(500).json({ msg: "Server error", error: err.message });
  }
});

router.post("/declareWinner/:tournamentId", authAdmin, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { winners } = req.body;

    if (!Array.isArray(winners) || winners.length === 0 || winners.length > 3)
      return res.status(400).json({ msg: "Winners array must include 1–3 players" });

    const positions = winners.map(w => w.position);
    if (new Set(positions).size !== positions.length)
      return res.status(400).json({ msg: "Duplicate positions are not allowed" });

    if (!positions.every(p => [1, 2, 3].includes(p)))
      return res.status(400).json({ msg: "Positions must be 1, 2, or 3" });

    const tournament = await Tournament.findById(tournamentId);
    if (!tournament)
      return res.status(404).json({ msg: "Tournament not found" });

    // 💰 Prize logic
    const totalPrize = tournament.prizePool;
    const adminCut = totalPrize * 0.05;
    const remaining = totalPrize - adminCut;
    const distribution = { 1: remaining * 0.5, 2: remaining * 0.3, 3: remaining * 0.2 };

    const declaredWinners = [];

    for (const w of winners) {
      if (!w.userId) continue;

      const user = await User.findById(w.userId);
      if (!user) continue;

      const prizeAmount = distribution[w.position] || 0;

      // 💼 Wallet update
      let wallet = await Wallet.findOne({ userId: user._id });
      if (!wallet) wallet = new Wallet({ userId: user._id, balance: 0 });

      wallet.balance += prizeAmount;
      await wallet.save();

      // 💳 Transaction + UI fields
      await new Transaction({
        userId: user._id,
        amount: prizeAmount,
        type: "credit",
        description: `🏆 ${tournament.name} - ${w.position} place reward`,
        sign: "+",          // ⭐ NEW
        uiColor: "green"    // ⭐ NEW
      }).save();

      const rankEmoji = w.position === 1 ? "🥇" : w.position === 2 ? "🥈" : "🥉";

      declaredWinners.push({
        name: user.name,
        userId: user._id,
        gameUid: w.gameUid || user.gameUid || "N/A",
        prize: prizeAmount,
        avatarUrl: user.avatarUrl || "https://cdn-icons-png.flaticon.com/512/147/147144.png",
        rankEmoji,
        position: w.position,
        declaredAt: new Date(),
        sign: "+",          // ⭐ for frontend
        uiColor: "green"    // ⭐ for frontend
      });
    }

    // 💼 Admin commission
    const admin = await User.findOne({ role: "admin" });
    if (admin) {
      let adminWallet = await Wallet.findOne({ userId: admin._id });
      if (!adminWallet) adminWallet = new Wallet({ userId: admin._id, balance: 0 });

      adminWallet.balance += adminCut;
      await adminWallet.save();

      await new Transaction({
        userId: admin._id,
        amount: adminCut,
        type: "credit",
        description: `🏦 Admin commission from ${tournament.name}`,
        sign: "+",
        uiColor: "green"
      }).save();
    }

    // Save winners
    const updatedWinners = [...(tournament.winners || [])];
    declaredWinners.forEach(winner => {
      const idx = updatedWinners.findIndex(x => x.position === winner.position);
      if (idx !== -1) updatedWinners[idx] = winner;
      else updatedWinners.push(winner);
    });

    tournament.winners = updatedWinners;
    await tournament.save();

    res.json({
      success: true,
      msg: "🏁 Winners declared!",
      tournamentName: tournament.name,
      winners: updatedWinners,
      adminCut
    });

  } catch (err) {
    console.error("Declare winners error:", err);
    res.status(500).json({ msg: "Server error", error: err.message });
  }
});

router.post("/declareWinner/:tournamentId", authAdmin, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { winners } = req.body;

    if (!Array.isArray(winners) || winners.length === 0 || winners.length > 3)
      return res.status(400).json({ msg: "Winners array must include 1–3 players" });

    const positions = winners.map(w => w.position);
    if (new Set(positions).size !== positions.length)
      return res.status(400).json({ msg: "Duplicate positions are not allowed" });

    if (!positions.every(p => [1, 2, 3].includes(p)))
      return res.status(400).json({ msg: "Positions must be 1, 2, or 3" });

    const tournament = await Tournament.findById(tournamentId);
    if (!tournament)
      return res.status(404).json({ msg: "Tournament not found" });

    // Prize distribution
    const totalPrize = tournament.prizePool;
    const adminCut = totalPrize * 0.05;
    const remaining = totalPrize - adminCut;
    const distribution = { 1: remaining * 0.5, 2: remaining * 0.3, 3: remaining * 0.2 };

    const declaredWinners = [];

    for (const w of winners) {
      if (!w.userId) continue;
      const user = await User.findById(w.userId);
      if (!user) continue;

      const prizeAmount = distribution[w.position] || 0;

      // Update wallet
      let wallet = await Wallet.findOne({ userId: user._id });
      if (!wallet) wallet = new Wallet({ userId: user._id, balance: 0 });
      wallet.balance += prizeAmount;
      await wallet.save();

      // Create Transaction with green + for frontend
      await new Transaction({
        userId: user._id,
        amount: prizeAmount,
        type: "credit",
        sign: "+",             // <- show plus sign
        color: "green",        // <- show green in frontend
        description: `🏆 ${tournament.name} - ${w.position} place reward`,
      }).save();

      const rankEmoji = w.position === 1 ? "🥇" : w.position === 2 ? "🥈" : "🥉";

      declaredWinners.push({
        name: user.name,
        userId: user._id,
        gameUid: w.gameUid || user.gameUid || "N/A",
        prize: prizeAmount,
        avatarUrl: user.avatarUrl || "https://cdn-icons-png.flaticon.com/512/147/147144.png",
        rankEmoji,
        position: w.position,
        declaredAt: new Date(),
      });
    }

    // Admin commission
    const admin = await User.findOne({ role: "admin" });
    if (admin) {
      let adminWallet = await Wallet.findOne({ userId: admin._id });
      if (!adminWallet) adminWallet = new Wallet({ userId: admin._id, balance: 0 });
      adminWallet.balance += adminCut;
      await adminWallet.save();

      await new Transaction({
        userId: admin._id,
        amount: adminCut,
        type: "credit",
        sign: "+",
        color: "green",
        description: `🏦 Admin commission from ${tournament.name}`,
      }).save();
    }

    // Merge winners
    const updatedWinners = [...(tournament.winners || [])];
    declaredWinners.forEach(winner => {
      const idx = updatedWinners.findIndex(x => x.position === winner.position);
      if (idx !== -1) updatedWinners[idx] = winner;
      else updatedWinners.push(winner);
    });

    tournament.winners = updatedWinners;
    await tournament.save();

    res.json({
      success: true,
      msg: "🏁 Winners declared successfully for all top 3 players!",
      tournamentName: tournament.name,
      winners: updatedWinners,
      adminCut,
    });

  } catch (err) {
    console.error("Declare winners error:", err);
    res.status(500).json({ msg: "Server error", error: err.message });
  }
});

// POST /declareWinner/:tournamentId
router.post("/declareWinner/:tournamentId", authAdmin, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { winners } = req.body;

    if (!Array.isArray(winners) || winners.length === 0 || winners.length > 3)
      return res.status(400).json({ msg: "Winners array must include 1–3 players" });

    const positions = winners.map(w => w.position);
    if (new Set(positions).size !== positions.length)
      return res.status(400).json({ msg: "Duplicate positions are not allowed" });

    if (!positions.every(p => [1, 2, 3].includes(p)))
      return res.status(400).json({ msg: "Positions must be 1, 2, or 3" });

    const tournament = await Tournament.findById(tournamentId);
    if (!tournament)
      return res.status(404).json({ msg: "Tournament not found" });

    // 💰 Prize logic
    const totalPrize = tournament.prizePool;
    const adminCut = totalPrize * 0.05;
    const remaining = totalPrize - adminCut;
    const distribution = { 1: remaining * 0.5, 2: remaining * 0.3, 3: remaining * 0.2 };

    const declaredWinners = [];

    for (const w of winners) {
      // ✅ Defensive: make sure winner has a userId
      if (!w.userId) {
        console.warn("Skipping winner entry without userId:", w);
        continue;
      }

      const user = await User.findById(w.userId);
      if (!user) {
        console.warn("User not found for ID:", w.userId);
        continue;
      }

      const prizeAmount = distribution[w.position] || 0;

      // 💼 Update wallet
      let wallet = await Wallet.findOne({ userId: user._id });
      if (!wallet) wallet = new Wallet({ userId: user._id, balance: 0 });
      wallet.balance += prizeAmount;
      await wallet.save();

      // 💳 Log transaction
      await new Transaction({
        userId: user._id,
        amount: prizeAmount,
        type: "credit",
        description: `🏆 ${tournament.name} - ${w.position} place reward`,
      }).save();

      // 🥇 Assign rank emoji
      const rankEmoji = w.position === 1 ? "🥇" : w.position === 2 ? "🥈" : "🥉";

      // ✅ Add winner entry
      declaredWinners.push({
        name: user.name,
        userId: user._id,
        gameUid: w.gameUid || user.gameUid || "N/A",
        prize: prizeAmount,
        avatarUrl: user.avatarUrl || "https://cdn-icons-png.flaticon.com/512/147/147144.png",
        rankEmoji,
        position: w.position,
        declaredAt: new Date(),
      });
    }

    // 💼 Admin commission
    const admin = await User.findOne({ role: "admin" });
    if (admin) {
      let adminWallet = await Wallet.findOne({ userId: admin._id });
      if (!adminWallet) adminWallet = new Wallet({ userId: admin._id, balance: 0 });
      adminWallet.balance += adminCut;
      await adminWallet.save();

      await new Transaction({
        userId: admin._id,
        amount: adminCut,
        type: "credit",
        description: `🏦 Admin commission from ${tournament.name}`,
      }).save();
    }

    // 🧩 Merge winners (update or insert)
    const updatedWinners = [...(tournament.winners || [])];
    declaredWinners.forEach(winner => {
      const idx = updatedWinners.findIndex(x => x.position === winner.position);
      if (idx !== -1) updatedWinners[idx] = winner;
      else updatedWinners.push(winner);
    });

    tournament.winners = updatedWinners;
    await tournament.save();

    res.json({
      success: true,
      msg: "🏁 Winners declared successfully for all top 3 players!",
      tournamentName: tournament.name,
      winners: updatedWinners,
      adminCut,
    });

  } catch (err) {
    console.error("Declare winners error:", err);
    res.status(500).json({ msg: "Server error", error: err.message });
  }
});

// GET /leaderboard/:tournamentId
router.get("/leaderboard/:tournamentId", async (req, res) => {
  try {
    const { tournamentId } = req.params;

    const tournament = await Tournament.findById(tournamentId)
      .populate("winners.userId", "name avatarUrl gameUid")
      .lean();

    if (!tournament) return res.status(404).json({ msg: "Tournament not found" });

    const winners = (tournament.winners || []).sort((a, b) => a.position - b.position);

    const leaderboard = [1,2,3].map(pos => {
      const w = winners.find(x => x.position === pos);
      return w ? {
        position: pos,
        rankEmoji: pos===1?"🥇":pos===2?"🥈":"🥉",
        name: w.userId?.name || "Unknown Player",
        prize: w.prize || 0,
        avatarUrl: w.userId?.avatarUrl || "https://cdn-icons-png.flaticon.com/512/147/147144.png",
        gameUid: w.userId?.gameUid || "-",
        declaredAt: w.declaredAt ? new Date(w.declaredAt).toLocaleString() : "Not Declared"
      } : {
        position: pos,
        rankEmoji: pos===1?"🥇":pos===2?"🥈":"🥉",
        name: "Waiting...",
        prize: 0,
        avatarUrl: "https://cdn-icons-png.flaticon.com/512/147/147144.png",
        gameUid: "-",
        declaredAt: "Not Declared"
      };
    });

    res.json({
      success: true,
      tournamentId: tournament._id,
      tournamentName: tournament.name,
      game: tournament.game,
      mode: tournament.mode,
      prizePool: tournament.prizePool,
      totalWinners: winners.length,
      leaderboard
    });

  } catch (err) {
    console.error("Leaderboard fetch error:", err);
    res.status(500).json({ success:false, msg:"Server error while fetching leaderboard", error: err.message });
  }
});





const QuickMatch = require('../models/QuickMatch');

// 🧠 Utility to generate next match number
async function generateMatchNumber() {
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, "");

  const last = await QuickMatch
    .findOne({ matchNumber: new RegExp(`^QM-${today}-`) })
    .sort({ matchNumber: -1 })   // 🔥 SAFE SORT
    .select("matchNumber")
    .lean();

  let nextSeq = 1;

  if (last?.matchNumber) {
    const parts = last.matchNumber.split("-");
    const lastSeq = parseInt(parts[2], 10);
    if (!isNaN(lastSeq)) nextSeq = lastSeq + 1;
  }

  return `QM-${today}-${String(nextSeq).padStart(4, "0")}`;
}



/* -------------------------------------------------------------------------- */
/*                              ✅ WALLET DEDUCT                               */
/* -------------------------------------------------------------------------- */
// ---------------------------
// GET ALL JOINED PLAYERS
// ---------------------------
router.get("/joined", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find({})
      .sort({ createdAt: -1 })
      .limit(300)
      .populate("players.userId", "name phone wallet avatarUrl")
      .lean();

    let allJoined = [];

    for (const match of matches) {
      if (!Array.isArray(match.players)) continue;

      const typeMap = { "1v1": 1, "2v2": 2, "3v3": 3, "4v4": 4 };
      const half = typeMap[match.type] || 1;

      match.players.forEach((p, index) => {
        const ff = p.freeFireSettings || {};

        allJoined.push({
          matchId: match._id,
          matchNumber: match.matchNumber || "N/A",

          userId: p.userId?._id || null,
          uid: p.uid || "",
          name: p.userId?.name || p.name || "Unknown",
          phone: p.userId?.phone || "",
          wallet: p.userId?.wallet || 0,
          avatarUrl: p.userId?.avatarUrl || "",
          whatsappNumber: p.whatsappNumber || "",

          game: match.game,
          mode: match.mode,
          type: match.type,
          prizeSystem: match.prizeSystem,
          entryFee: match.entryFee,
          joinedAt: p.joinedAt || match.createdAt,
          status: match.status,

          team: p.team || (index < half ? "LION" : "TIGER"),

          map: ff.map || "Not Selected",
          roomType: ff.roomType || "regular",

          gameSettings: {
            headshot: !!ff.gameSettings?.headshot,
            characterSkill: !!ff.gameSettings?.characterSkill,
            gunAttributes: !!ff.gameSettings?.gunAttributes,
            throwableLimit: ff.gameSettings?.throwableLimit || 0
          },

          selectedGuns: {
            AR: ff.selectedGuns?.AR || [],
            SMG: ff.selectedGuns?.SMG || [],
            SNIPER: ff.selectedGuns?.SNIPER || [],
            SHOTGUN: ff.selectedGuns?.SHOTGUN || [],
            PISTOLS: ff.selectedGuns?.PISTOLS || [],
            LAUNCHERS: ff.selectedGuns?.LAUNCHERS || [],
            SPECIAL: ff.selectedGuns?.SPECIAL || []
          }
        });
      });
    }

    res.json({ success: true, count: allJoined.length, data: allJoined });
  } catch (err) {
    console.error("Joined fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

router.get("/joined/unpaired", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find({ status: "waiting" })
      .sort({ createdAt: -1 })
      .limit(300)
      .populate("players.userId", "name phone wallet avatarUrl")
      .lean();

    let result = [];

    for (const match of matches) {
      if (!Array.isArray(match.players)) continue;

      const typeMap = { "1v1": 1, "2v2": 2, "3v3": 3, "4v4": 4 };
      const half = typeMap[match.type] || 1;

      match.players.forEach((p, idx) => {
        const ff = p.freeFireSettings || {};

        result.push({
          matchId: match._id,
          matchNumber: match.matchNumber || "",

          userId: p.userId?._id || null,
          uid: p.uid || "",
          name: p.userId?.name || p.name || "Unknown",
          phone: p.userId?.phone || "",
          whatsappNumber: p.whatsappNumber || "",
          wallet: p.userId?.wallet || 0,
          avatarUrl: p.userId?.avatarUrl || "",

          game: match.game,
          mode: match.mode,
          type: match.type,
          prizeSystem: match.prizeSystem,
          entryFee: match.entryFee,
          status: match.status,
          joinedAt: p.joinedAt,

          team: p.team || (idx < half ? "LION" : "TIGER"),

          map: ff.map || "Not Selected",
          roomType: ff.roomType || "regular",

          gameSettings: {
            headshot: !!ff.gameSettings?.headshot,
            characterSkill: !!ff.gameSettings?.characterSkill,
            gunAttributes: !!ff.gameSettings?.gunAttributes,
            throwableLimit: ff.gameSettings?.throwableLimit || 0
          },

          selectedGuns: ff.selectedGuns || {}
        });
      });
    }

    res.json({ success: true, count: result.length, data: result });
  } catch (err) {
    console.error("Unpaired fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

router.get("/joined/paired", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find({
      status: { $in: ["paired", "filled", "ongoing", "completed"] }
    })
      .sort({ createdAt: -1 })
      .limit(300)
      .populate("players.userId", "name phone wallet avatarUrl")
      .lean();

    let result = [];

    for (const match of matches) {
      if (!Array.isArray(match.players)) continue;

      const typeMap = { "1v1": 1, "2v2": 2, "3v3": 3, "4v4": 4 };
      const half = typeMap[match.type] || 1;

      match.players.forEach((p, idx) => {
        const ff = p.freeFireSettings || {};

        result.push({
          matchId: match._id,
          matchNumber: match.matchNumber,

          userId: p.userId?._id || null,
          uid: p.uid || "",
          name: p.userId?.name || p.name || "Unknown",
          phone: p.userId?.phone || "",
          whatsappNumber: p.whatsappNumber || "",
          wallet: p.userId?.wallet || 0,
          avatarUrl: p.userId?.avatarUrl || "",

          game: match.game,
          mode: match.mode,
          type: match.type,
          prizeSystem: match.prizeSystem,
          entryFee: match.entryFee,
          status: match.status,
          joinedAt: p.joinedAt,

          team: p.team || (idx < half ? "LION" : "TIGER"),

          map: ff.map || "Not Selected",
          roomType: ff.roomType || "regular",

          gameSettings: ff.gameSettings || {},
          selectedGuns: ff.selectedGuns || {}
        });
      });
    }

    res.json({ success: true, count: result.length, data: result });
  } catch (err) {
    console.error("Paired fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});



router.get("/pairss/:matchId", authAdmin, async (req, res) => {
  try {
    const { matchId } = req.params;

    const match = await QuickMatch.findById(matchId)
      .populate("players.userId", "name phone wallet avatarUrl");

    if (!match)
      return res.status(404).json({ success: false, msg: "Match Not Found" });

    // ⭐ team size map
    const typeMap = { "1v1": 1, "2v2": 2, "3v3": 3, "4v4": 4 };
    const half = typeMap[match.type] || 1;

    // ⭐ team_equal logic
    const isTeamEqual = match.prizeSystem === "team_equal";

    const players = match.players.map((p, idx) => {
      const ff = p.freeFireSettings || {};

      return {
        userId: p.userId?._id || null,
        uid: p.uid,
        name: p.userId?.name || p.name || "Unknown",
        phone: p.userId?.phone || p.phone || "",
        wallet: p.userId?.wallet || 0,
        avatarUrl: p.userId?.avatarUrl || null,
        whatsappNumber: p.whatsappNumber || "",

        // ⭐ team logic merged (team_equal vs normal)
        team: isTeamEqual
          ? (p.team || (idx < half ? "LION" : "TIGER"))
          : (p.team || (idx < half ? "LION" : "TIGER")),

        // ⭐ FULL FF SETTINGS MERGED
        map: ff.map || "Not Selected",
        roomType: ff.roomType || "regular",

        gameSettings: {
          headshot: ff.gameSettings?.headshot || false,
          characterSkill: ff.gameSettings?.characterSkill || false,
          gunAttributes: ff.gameSettings?.gunAttributes || false,
          throwableLimit: ff.gameSettings?.throwableLimit || 0
        },

        selectedGuns: {
          AR: ff.selectedGuns?.AR || [],
          SMG: ff.selectedGuns?.SMG || [],
          SNIPER: ff.selectedGuns?.SNIPER || [],
          SHOTGUN: ff.selectedGuns?.SHOTGUN || [],
          PISTOLS: ff.selectedGuns?.PISTOLS || [],
          LAUNCHERS: ff.selectedGuns?.LAUNCHERS || [],
          SPECIAL: ff.selectedGuns?.SPECIAL || []
        }
      };
    });

    return res.json({
      success: true,
      matchId: match._id,
      matchNumber: match.matchNumber,
      game: match.game,
      mode: match.mode,
      type: match.type,
      entryFee: match.entryFee,
      prizeSystem: match.prizeSystem, // ⭐ exact
      status: match.status,
      players
    });

  } catch (err) {
    console.error("pair fetch error", err);
    return res.status(500).json({ success: false, msg: "Server Err" });
  }
});



router.post("/pair", authAdmin, async (req, res) => {
  try {
    const { selectedMembers, game, mode, type, entryFee, map, roomType, gameSettings } = req.body;

    if (!Array.isArray(selectedMembers) || selectedMembers.length === 0)
      return res.status(400).json({ success: false, msg: "No members selected" });

    const n = parseInt(type.split("v")[0], 10);
    const teamSize = n * 2;

    if (selectedMembers.length % teamSize !== 0)
      return res.status(400).json({
        success: false,
        msg: `You must select ${teamSize} players per match (${type})`
      });

    // GROUP PLAYERS
    const groups = [];
    for (let i = 0; i < selectedMembers.length; i += teamSize)
      groups.push(selectedMembers.slice(i, i + teamSize));

    const createdMatches = [];

    // LOOP EVERY GROUP
    for (const group of groups) {
      const half = group.length / 2;

      // Prize system rule
      let prizeSystem = type === "1v1" 
        ? "kill_based" 
        : (group[0].prizeSystem || "kill_based");

      // ⭐ NO SNIPER VALIDATION ANYMORE
      // ALL PAIRINGS ARE ALLOWED

      // CREATE PLAYERS FOR MATCH
      const playersArr = group.map((p, idx) => {
        return {
          userId: p.userId ? new mongoose.Types.ObjectId(p.userId) : null,
          uid: p.uid,
          name: p.name || "Unknown",
          phone: p.phone || "Unknown",
          prizeSystem: p.prizeSystem,
          team: idx < half ? "LION" : "TIGER",

          // EXTRA SETTINGS TO SAVE
          game,
          mode,
          map,
          roomType,
          entryFee,

          gameSettings: {
            headshot: p.gameSettings?.headshot || false,
            characterSkill: p.gameSettings?.characterSkill || false,
            gunAttributes: p.gameSettings?.gunAttributes || false,
            throwableLimit: p.gameSettings?.throwableLimit || 0
          },

          // GUN LISTS
          AR: p.AR || [],
          SMG: p.SMG || [],
          SNIPER: p.SNIPER || [],
          SHOTGUN: p.SHOTGUN || [],
          PISTOLS: p.PISTOLS || [],
          LAUNCHERS: p.LAUNCHERS || [],
          SPECIAL: p.SPECIAL || []
        };
      });

      // SAVE MATCH
      const newMatch = new QuickMatch({
        type,
        game,
        mode,
        entryFee,
        prizeSystem,
        map,
        roomType,
        gameSettings,
        players: playersArr,
        status: "paired"
      });

      await newMatch.save();
      createdMatches.push(newMatch);
    }

    res.json({
      success: true,
      msg: "Players paired successfully",
      data: createdMatches
    });

  } catch (err) {
    console.error("Pair Error:", err);
    return res.status(500).json({ success: false, msg: "Server error" });
  }
});










router.get("/joined", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find()
      .populate("players.userId", "name phone wallet avatarUrl")
      .sort({ createdAt: -1 })
      .limit(300);

    let allJoined = [];

    matches.forEach(match => {
      const half = match.type === "1v1" ? 1 :
                   match.type === "2v2" ? 2 :
                   match.type === "3v3" ? 3 :
                   match.type === "4v4" ? 4 : 1;

      match.players.forEach((player, index) => {
        allJoined.push({
          matchId: match._id,
          matchNumber: match.matchNumber,
          userId: player.userId?._id || null,
          uid: player.uid,
          name: player.userId?.name || player.name || "Unknown",
          phone: player.userId?.phone || "N/A",
          wallet: player.userId?.wallet || 0,
          avatarUrl: player.userId?.avatarUrl || null,

          // match data
          game: match.game,
          mode: match.mode,
          type: match.type,
          prizeSystem: match.prizeSystem,
          entryFee: match.entryFee,
          joinedAt: match.createdAt,
          status: match.status,

          // auto calculate team
          team: player.team || (index < half ? "LION" : "TIGER")
        });
      });
    });

    res.json({
      success: true,
      count: allJoined.length,
      data: allJoined
    });

  } catch (err) {
    console.error("Joined fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});


router.get("/joined/unpaired", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find({ status: "waiting" })
      .populate("players.userId", "name phone wallet avatarUrl")
      .sort({ createdAt: -1 })
      .limit(300);

    let result = [];

    matches.forEach(match => {

      // Half team size detection
      const half =
        match.type === "1v1" ? 1 :
        match.type === "2v2" ? 2 :
        match.type === "3v3" ? 3 :
        match.type === "4v4" ? 4 : 1;

      const prizeSystem = match.prizeSystem || "kill_based";

      match.players.forEach((player, index) => {

        // 🦁🐯 TEAM LOGIC (fixed for both systems)
        let teamValue = player.team;

        if (!teamValue) {
          // Auto-assign fallback team
          teamValue = index < half ? "LION" : "TIGER";
        }

        result.push({
          matchId: match._id,
          matchNumber: match.matchNumber,

          userId: player.userId?._id || null,
          uid: player.uid,
          name: player.userId?.name || player.name || "Unknown",
          phone: player.userId?.phone || "N/A",
          wallet: player.userId?.wallet || 0,
          avatarUrl: player.userId?.avatarUrl || null,

          game: match.game,
          mode: match.mode,
          type: match.type,
          entryFee: match.entryFee,
          prizeSystem: prizeSystem,
          joinedAt: match.createdAt,
          status: match.status,

          // ✔ FIXED: team shown for both team_equal & kill_based
          team: teamValue 
        });
      });
    });

    res.json({ success: true, count: result.length, data: result });

  } catch (err) {
    console.error("Unpaired fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});



router.get("/joined/paired", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find({
      status: { $in: ["filled", "ongoing", "completed"] }
    })
      .populate("players.userId", "name phone wallet avatarUrl")
      .sort({ createdAt: -1 })
      .limit(300);

    let result = [];

    matches.forEach(match => {
      const half = match.type === "1v1" ? 1 :
                   match.type === "2v2" ? 2 :
                   match.type === "3v3" ? 3 :
                   match.type === "4v4" ? 4 : 1;

      match.players.forEach((player, index) => {
        result.push({
          matchId: match._id,
          matchNumber: match.matchNumber,
          userId: player.userId?._id || null,
          uid: player.uid,
          name: player.userId?.name || player.name || "Unknown",
          phone: player.userId?.phone || "N/A",
          wallet: player.userId?.wallet || 0,
          avatarUrl: player.userId?.avatarUrl || null,

          game: match.game,
          mode: match.mode,
          type: match.type,
          prizeSystem: match.prizeSystem,
          entryFee: match.entryFee,
          joinedAt: match.createdAt,
          status: match.status,

          team: player.team || (index < half ? "LION" : "TIGER")
        });
      });
    });

    res.json({ success: true, count: result.length, data: result });

  } catch (err) {
    console.error("Paired fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});




router.post("/pair", authAdmin, async (req, res) => {
  try {
    const { selectedMembers, game, mode, type, entryFee } = req.body;

    if (!Array.isArray(selectedMembers) || selectedMembers.length === 0)
      return res.status(400).json({ success: false, msg: "No members selected" });

    const n = parseInt(type.split("v")[0], 10); 
    const teamSize = n * 2;

    if (selectedMembers.length % teamSize !== 0)
      return res.status(400).json({
        success: false,
        msg: `You must select ${teamSize} players per match (${type})`
      });

    // Group players
    const groups = [];
    for (let i = 0; i < selectedMembers.length; i += teamSize)
      groups.push(selectedMembers.slice(i, i + teamSize));

    const createdMatches = [];

    for (const group of groups) {
      const half = group.length / 2;

      // ⭐ FIXED PRIZE SYSTEM LOGIC
      let prizeSystem;

      if (type === "1v1") {
        prizeSystem = "kill_based"; // forced for 1v1
      } else {
        // pick system from first player exactly
        prizeSystem = group[0].prizeSystem;

        if (!prizeSystem) {
          return res.status(400).json({
            success: false,
            msg: "❌ Missing prizeSystem for selected players"
          });
        }
      }

      // 🎯 PLAYER ARRAY
      const playersArr = group.map((p, idx) => {
        let team = null;

        if (type !== "1v1") {
          team = idx < half ? "LION" : "TIGER";
        }

        return {
          userId: p.userId ? new mongoose.Types.ObjectId(p.userId) : null,
          uid: p.uid,
          name: p.name || "Unknown",
          phone: p.phone || "Unknown",
          prizeSystem: p.prizeSystem, // ⭐ KEEP ORIGINAL SYSTEM
          team
        };
      });

      // 🎯 SAVE MATCH
      const newMatch = new QuickMatch({
        type,
        game,
        mode,
        entryFee,
        prizeSystem, // ⭐ NEVER CHANGES NOW
        players: playersArr,
        status: "paired"
      });

      await newMatch.save();
      createdMatches.push(newMatch);
    }

    res.json({
      success: true,
      msg: "Players paired successfully",
      data: createdMatches
    });

  } catch (err) {
    console.error("Pair Error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});



router.get("/pairs/:matchId", async (req, res) => {
  try {
    const { matchId } = req.params;

    const match = await QuickMatch.findById(matchId)
      .populate("players.userId", "name phone wallet avatarUrl");

    if (!match) {
      return res.json({ success: false, msg: "Match Not Found" });
    }

    // check if prizeSystem = team_equal
    const isTeamEqual = match.prizeSystem === "team_equal";

    return res.json({
      success: true,
      matchId: match._id,
      game: match.game,
      mode: match.mode,
      type: match.type,
      entryFee: match.entryFee,
      prizeSystem: match.prizeSystem, // ⭐ exact system, no fallback
      status: match.status,

      players: match.players.map((p, idx) => ({
        userId: p.userId?._id || null,
        uid: p.uid,
        name: p.userId?.name || p.name || "Unknown",
        phone: p.userId?.phone || p.phone || "Unknown",
        wallet: p.userId?.wallet || 0,
        avatarUrl: p.userId?.avatarUrl || null,

        // ⭐ team only shown for team_equal matches
        team: isTeamEqual ? (p.team || (idx < match.players.length / 2 ? "LION" : "TIGER")) : null
      }))
    });

  } catch (err) {
    console.log("pair fetch error", err);
    return res.status(500).json({ success: false, msg: "Server Err" });
  }
});




// Deduct entry fee from user's wallet
router.post("/deduct", auth, async (req, res) => {
  try {
    const { fee } = req.body;
    const userId = req.user.id;

    if (!fee || fee <= 0)
      return res.status(400).json({ success: false, msg: "Invalid fee amount" });

    // ✅ Find user's wallet or create a new one
    let wallet = await Wallet.findOne({ userId });
    if (!wallet) {
      wallet = new Wallet({ userId, balance: 0 });
      await wallet.save();
    }

    // ✅ Check balance
    if (wallet.balance < fee)
      return res
        .status(400)
        .json({ success: false, msg: "Insufficient wallet balance" });

    // ✅ Deduct amount
    wallet.balance -= fee;
    await wallet.save();

    // ✅ Log a transaction (optional but recommended)
    const transaction = new Transaction({
      userId,
      type: "debit",
      amount: fee,
      description: "Quick match entry fee deduction",
      balanceAfter: wallet.balance,
    });
    await transaction.save();

    res.json({
      success: true,
      msg: `₹${fee} deducted successfully`,
      walletBalance: wallet.balance,
    });
  } catch (err) {
    console.error("Error in /wallet/deduct:", err);
    res.status(500).json({ success: false, msg: "Internal server error" });
  }
});


/* -------------------------------------------------------------------------- */
/*                         ✅ JOIN OR CREATE QUICK MATCH                      */
/* -------------------------------------------------------------------------- */
// ✅ Join or create a quick match




// ✅ Get all quick matches (for admin or display)
router.get("/quickmatch/all", async (req, res) => {
  try {
    const matches = await QuickMatch.find()
      .populate("players.userId", "name phone wallet")
      .sort({ createdAt: -1 })
      .limit(100);

    res.json(matches);
  } catch (err) {
    console.error("Error fetching matches:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Get user’s joined matches
router.get("/quickmatch/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    const matches = await QuickMatch.find({
      "players.userId": userId,
    }).sort({ createdAt: -1 })
    .limit(00);

    res.json(matches);
  } catch (err) {
    console.error("Error fetching user matches:", err);
    res.status(500).json({ message: "Server error" });
  }
});





/* -------------------------------------------------------------------------- */
/*                      ✅ ADMIN PAIR EXISTING PLAYERS                        */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* 🧠 Helper: Generate Unique Match Number                                    */
/* -------------------------------------------------------------------------- */
async function generateMatchNumber() {
  const randomPart = Math.random().toString(36).substring(2, 6).toUpperCase();
  return `QM-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${randomPart}`;
}

/* -------------------------------------------------------------------------- */
/* ✅ CREATE / PAIR EXISTING UNPAIRED MEMBERS                                 */
/* -------------------------------------------------------------------------- */



/* -------------------------------------------------------------------------- */
/* ✅ DECLARE WINNER (ADMIN ONLY)                                            */
/* -------------------------------------------------------------------------- */
router.post("/:matchId/result", async (req, res) => {
  const { winnerUid } = req.body;
  try {
    const match = await QuickMatch.findById(req.params.matchId);
    if (!match)
      return res.status(404).json({ success: false, msg: "Match not found" });

    match.winnerUid = winnerUid;
    match.status = "completed";
    await match.save();

    res.json({ success: true, msg: "Result updated", match });
  } catch (err) {
    console.error("Error in /result route:", err);
    res.status(500).json({ success: false, msg: "Internal server error" });
  }
});

/* -------------------------------------------------------------------------- */
/* ✅ GET ALL MATCHES (ADMIN)                                                */
/* -------------------------------------------------------------------------- */
router.get("/all", async (req, res) => {
  try {
    const matches = await QuickMatch.find()
      .populate("players.userId", "name phone wallet avatarUrl")
      .sort({ createdAt: -1 })
      .limit(100);
    res.json({ success: true, data: matches });
  } catch (err) {
    console.error("Error fetching matches:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

/* -------------------------------------------------------------------------- */
/* ✅ GET MATCH STATUS (PLAYER)                                              */
/* -------------------------------------------------------------------------- */
router.get("/:matchId/status", async (req, res) => {
  try {
    const match = await QuickMatch.findById(req.params.matchId)
      .populate("players.userId", "name phone wallet avatarUrl");
    if (!match)
      return res.status(404).json({ success: false, msg: "Match not found" });

    res.json({ success: true, data: match });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});


// ✅ Join Quick Match



/* -------------------------------------------------------------------------- */
/* ✅ GET ALL JOINED MEMBERS (ALL MATCHES)                                     */
/* -------------------------------------------------------------------------- */

router.get("/joined", async (req, res) => {
  try {
    const matches = await QuickMatch.find().sort({ createdAt: -1 })
    .limit(100);
    const members = [];

    matches.forEach((m) => {
      m.players.forEach((p) => {
        if (p.uid) {
          members.push({
            uid: p.uid,
            name: p.name || "Unknown",
            phone: p.phone || "Unknown",   // ✅ FIXED
            userId: p.userId,
            game: m.game,
            mode: m.mode,
            type: m.type,
            entryFee: m.entryFee,
            joinedAt: m.createdAt,
            matchNumber: m.matchNumber,
            prizeSystem: match.prizeSystem,
            status: m.status,
            team: p.team || null,
          });
        }
      });
    });

    res.json({ success: true, data: members });
  } catch (err) {
    console.error("❌ Error fetching joined members:", err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});



/* -------------------------------------------------------------------------- */
/* ✅ GET UNPAIRED MEMBERS                                                    */
/* -------------------------------------------------------------------------- */
// GET all unpaired matches with players & team split
/* -------------------------------------------------------------------------- */
/* ✅ GET UNPAIRED MEMBERS (WAITING OR FILLED MATCHES)                        */
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* ✅ GET UNPAIRED MEMBERS (WAITING OR FILLED MATCHES)                        */
/* -------------------------------------------------------------------------- */
// GET all unpaired matches with players & team split
// GET ALL UNPAIRED MEMBERS GROUPED FIGHT APPROACH

router.get("/joined/unpaired", async (req, res) => {
  try {
    // fetch only waiting or filled matches
    const waitingMatches = await QuickMatch.find({
      status: { $in: ["waiting", "filled"] }
    })
      .populate("players.userId", "name phone wallet avatarUrl")
      .sort({ createdAt: -1 })
      .limit(100);

    const unpairedMembers = [];

    waitingMatches.forEach((match) => {
      // determine total players from type (1v1=2, 2v2=4, etc.)
      const totalPlayersMap = { "1v1": 2, "2v2": 4, "3v3": 6, "4v4": 8 };
      const totalSlots = totalPlayersMap[match.type] || 2;
      const half = totalSlots / 2;

      match.players.forEach((player, index) => {
        if (player.uid) {
          // assign team dynamically if not stored
          const team =
            player.team ||
            (index < half ? "LION" : "TIGER");

          unpairedMembers.push({
            matchId: match._id,
            matchNumber: match.matchNumber,
            userId: player.userId?._id || null,
            uid: player.uid,
            name: player.userId?.name || player.name || "Unknown",
            phone: player.userId?.phone || "N/A",
            wallet: player.userId?.wallet || 0,
            avatarUrl: player.userId?.avatarUrl || null,
            game: match.game,
            mode: match.mode,
            type: match.type,
            entryFee: match.entryFee,
            prizeSystem: match.prizeSystem,
            joinedAt: match.createdAt,
            status: match.status,
            team,
          });
        }
      });
    });

    // optional dev console log
    if (process.env.NODE_ENV === "development") {
      console.log(`🟢 Found ${unpairedMembers.length} unpaired members`);
    }

    res.json({
      success: true,
      count: unpairedMembers.length,
      data: unpairedMembers,
    });
  } catch (err) {
    console.error("❌ Error fetching unpaired members:", err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});





/* -------------------------------------------------------------------------- */
/* ✅ GET ONLY PAIRED MEMBERS                                                */
/* -------------------------------------------------------------------------- */



router.get("/joined/paired", async (req, res) => {
  try {
    // Fetch matches with paired or filled status
    const pairedMatches = await QuickMatch.find({
      $or: [{ status: "paired" }, { status: "filled" }],
    })
      .populate("players.userId", "name phone wallet avatarUrl")
      .sort({ createdAt: -1 })
      .limit(100);

    const pairedMembers = pairedMatches.map((match) => {
      const playersData = match.players.map((p) => ({
        userId: p.userId?._id || null,             // keep null if not registered
        name: p.userId?.name || p.name || "Unknown",
        phone: p.userId?.phone || "N/A",
        wallet: p.userId?.wallet || 0,
        uid: p.uid || null,
        game: match.game,
        mode: match.mode,
        entryFee: match.entryFee,
        matchNumber: match.matchNumber,
      }));

      return {
        matchId: match._id,
        pairedMatchNo: match.matchNumber,
        players: playersData,
      };
    });

    if (process.env.NODE_ENV === "development") {
      console.log(`🟢 Found ${pairedMembers.length} paired matches`);
    }

    res.json({ success: true, data: pairedMembers });
  } catch (err) {
    console.error("❌ Error fetching paired members:", err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});



/* -------------------------------------------------------------------------- */
/* ✅ ADMIN: PAIR SELECTED MEMBERS                                           */
/* -------------------------------------------------------------------------- */




// Helper: generate match number
async function generateMatchNumber() {
  const last = await QuickMatch.findOne().sort({ createdAt: -1 })
  .limit(100).lean();
  if (!last || !last.matchNumber) return `QM-${new Date().toISOString().slice(0,10).replace(/-/g,'')}-0001`;
  const parts = (last.matchNumber || '').split('-');
  const lastSeq = parts[2] ? parseInt(parts[2]) : NaN;
  const nextSeq = isNaN(lastSeq) ? 1 : lastSeq + 1;
  return `QM-${new Date().toISOString().slice(0,10).replace(/-/g,'')}-${String(nextSeq).padStart(4,'0')}`;
}

/**
 * POST /api/wallet/pair
 * Body: {
 *   selectedMembers: [{ userId, uid, name, contact }],
 *   game, mode, type, entryFee
 * }
 */
router.post("/pair", async (req, res) => {
  try {
    const { selectedMembers, game, mode, type, entryFee } = req.body;

    if (!Array.isArray(selectedMembers) || selectedMembers.length === 0)
      return res.status(400).json({ success: false, msg: 'No members selected' });

    if (!game || !mode || !type || !entryFee)
      return res.status(400).json({ success: false, msg: 'Missing pairing metadata (game/mode/type/entryFee)' });

    const baseN = parseInt(String(type).split('v')[0], 10);
    if (isNaN(baseN) || baseN <= 0)
      return res.status(400).json({ success: false, msg: 'Invalid match type' });

    const teamSize = baseN * 2;

    if (selectedMembers.length % teamSize !== 0)
      return res.status(400).json({ success: false, msg: `You must select ${teamSize} players per match (${type})` });

    const sameProps = selectedMembers.every(m =>
      m.game === game && m.mode === mode && Number(m.entryFee) === Number(entryFee) && m.type === type
    );
    if (!sameProps)
      return res.status(400).json({ success: false, msg: 'Selected members must have same game/mode/type/entryFee' });

    const groups = [];
    for (let i = 0; i < selectedMembers.length; i += teamSize) {
      groups.push(selectedMembers.slice(i, i + teamSize));
    }

    const createdMatches = [];
    for (const g of groups) {

      const half = g.length / 2;

      const playersArr = g.map((p, idx) => ({
        userId: p.userId ? new mongoose.Types.ObjectId(p.userId) : null,
        name: p.name || null,
        uid: p.uid || null,
        team: idx < half ? "LION" : "TIGER"       // ✅ team assign here
      }));

      const newMatch = new QuickMatch({
        type,
        game,
        mode,
        entryFee,
        players: playersArr,
        status: "paired"
      });

      await newMatch.save();
      createdMatches.push(newMatch);
    }

    return res.json({
      success: true,
      msg: `Paired ${selectedMembers.length} players into ${createdMatches.length} match(es).`,
      data: createdMatches
    });

  } catch (err) {
    console.error('Pair Error:', err);
    return res.status(500).json({ success: false, msg: 'Server Error' });
  }
});




router.get("/pairs/:matchId", async (req,res)=>{
  try{
    const { matchId } = req.params;
    
    const match = await QuickMatch.findById(matchId)
      .populate("players.userId", "phone name");

    if(!match) return res.json({success:false, msg:"Match Not Found"});

    res.json({
      success:true,
      game:match.game,
      mode:match.mode,
      type:match.type,
      players: match.players.map(p=>({
        uid: p.uid,
        name: p.name || p.userId?.name || "Unknown",
        phone: p.userId?.phone || "Unknown",
        team: p.team || null      // ✅ show team here
      }))
    });

  }catch(err){
    console.log("pair fetch error", err);
    res.status(500).json({success:false, msg:"Server Err"});
  }
});



/* -------------------------------------------------------------------------- */
/* ✅ PUBLISH ROOM DETAILS (ADMIN-MATCH-DETAILS.HTML)                         */
/* -------------------------------------------------------------------------- */
router.post("/admin/quickmatch/add-room", authAdmin, async (req, res) => {
  try {
    const { matchId, roomId, roomPassword, startTime, message } = req.body;

    if (!matchId || !roomId || !roomPassword || !startTime) {
      return res.status(400).json({ success: false, msg: "Missing required fields" });
    }

    const match = await QuickMatch.findById(matchId);
    if (!match) {
      return res.status(404).json({ success: false, msg: "Match not found" });
    }

    // store exact same string user sent (no timezone conversion)
    match.roomDetails = {
      roomId,
      roomPassword,
      startTime,   // ← keep string as it is
      message: message || "",
      publishedAt: new Date(),
    };

    match.status = "room_published";
    await match.save();

    return res.json({
      success: true,
      msg: "Room details saved successfully"
    });

  } catch (err) {
    console.error("Error in /admin/quickmatch/add-room:", err);
    return res.status(500).json({ success: false, msg: "Internal server error" });
  }
});




// GET room details for users by matchId
router.get("/quickmatch/room/:matchId", async (req, res) => {
  try {
    const { matchId } = req.params;

    const match = await QuickMatch.findById(matchId);

    if (!match) {
      return res.status(404).json({ success: false, msg: "Match not found" });
    }

    if (!match.roomDetails || !match.roomDetails.roomId) {
      return res.json({ success: false, msg: "Room Details not uploaded yet" });
    }

    // return the exact same string (no timezone conversion)
    return res.json({
      success: true,
      room: {
        roomId: match.roomDetails.roomId,
        roomPassword: match.roomDetails.roomPassword,
        startTime: match.roomDetails.startTime, // already string
        message: match.roomDetails.message || "",
         
        status: match.status,
      }
    });

  } catch (err) {
    console.error("Error at GET /quickmatch/room/:matchId:", err);
    return res.status(500).json({ success: false, msg: "Internal server error" });
  }
});




// ✅ UNIVERSAL SINGLE ACTIVE MATCH ROUTE WITH PRIZE SYSTEM LOGIC
router.get("/active-matches", auth, async (req, res) => {
  try {
    const userId = req.user.id;

    // 1️⃣ Query to find user's active match
    const query = {
      status: { $nin: ["ongoing"] },
      $or: [
        { "players.userId": userId },
        { "slots.userId": userId }
      ]
    };

    // 2️⃣ Load latest active match
    const match = await QuickMatch.findOne(query)
      .populate("players.userId", "name phone avatarUrl wallet")
      .populate("slots.userId", "name phone avatarUrl wallet")
      .select("type game mode entryFee status players slots createdAt matchNumber prizeSystem")
      .sort({ createdAt: -1 })
      .lean();

    if (!match) return res.json({ success: true, data: null });

    // 3️⃣ Find logged user's participation
    const inPlayers = match.players?.find(p => String(p.userId?._id) === String(userId));
    const inSlots = match.slots?.find(s => String(s.userId?._id) === String(userId));
    const userData = inPlayers || inSlots;

    // 4️⃣ Hide prize system for specific games
    const NON_PRIZE_GAMES = ["Ludo", "Carrom", "8 Ball Pool", "Cricket"];
    const prizeSystemToSend = NON_PRIZE_GAMES.includes(match.game) ? null : match.prizeSystem;

    // 5️⃣ Merge all joined players (players + slots) and filter out blanks
    const allPlayers = [
      ...(match.players || []),
      ...(match.slots || [])
    ]
      .filter(p => (p.userId || p.name)) // remove empty entries
      .map(p => ({
        uid: p.uid,
        name: p.userId?.name || p.name || "No Name",
        team: p.team || null,
        avatarUrl: p.userId?.avatarUrl || null,
        phone: p.userId?.phone || null,
        whatsappNumber: p.whatsappNumber || null
      }));

    // 6️⃣ Optional: group players by team if teams exist
    const teams = {};
    allPlayers.forEach(p => {
      const team = p.team || "NO_TEAM";
      if (!teams[team]) teams[team] = [];
      teams[team].push(p);
    });

    // 7️⃣ Final formatted match object
    const formatted = {
      _id: match._id,
      matchNumber: match.matchNumber,
      type: match.type,
      game: match.game,
      mode: match.mode,
      entryFee: match.entryFee,
      status: match.status,
      createdAt: match.createdAt,
      prizeSystem: prizeSystemToSend,
      team: userData?.team || null,
      joinedAt: userData?.joinedAt || match.createdAt,
      players: allPlayers,
      teams // grouped by team
    };

    return res.json({ success: true, data: formatted });
  } catch (err) {
    console.error("Active match error:", err);
    return res.status(500).json({ success: false, msg: "Internal server error" });
  }
});  


router.get("/my-active", auth, async (req, res) => {
  try {
    const userId = req.user.id;

    const activeMatches = await QuickMatch.find({
      "players.userId": userId,
      status: { $nin: ["completed"] }
    })
      .select("type game mode entryFee status players createdAt matchNumber prizeSystem")
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    const filtered = activeMatches.map(m => {
      const playerData = m.players.find(p => String(p.userId) === String(userId));

      return {
        _id: m._id,
        matchNumber: m.matchNumber || null,
        type: m.type,
        game: m.game,
        mode: m.mode,
        entryFee: m.entryFee,
        prizeSystem: m.prizeSystem, // ⭐ exact system
        status: m.status,
        team: playerData?.team || null,

        createdAt: m.createdAt,

        players: m.players.map(p => ({
          uid: p.uid,
          name: p.name,
          team: p.team || null  // ⭐ correct team for team_equal only
        }))
      };
    });

    res.json({
      success: true,
      data: filtered
    });

  } catch (err) {
    console.error("Error in /my-active:", err);
    res.status(500).json({ success: false, msg: "Internal server error" });
  }
});

router.post("/upload-result", auth, async (req, res) => {
  try {
    const { screenshotUrl, kills } = req.body;

    if (!screenshotUrl)
      return res.json({ success: false, msg: "Screenshot is required" });

    const match = await QuickMatch.findOne({
      "players.userId": req.user.id,
      status: "room_published",
      "userResults.userId": { $ne: req.user.id }
    }).populate("players.userId", "name phone uid");

    if (!match)
      return res.json({ success: false, msg: "No published match found" });

    if (!match.userResults) match.userResults = [];

    // Get real player
    const player = match.players.find(
      p => String(p.userId._id) === String(req.user.id)
    );

    if (!player)
      return res.json({ success: false, msg: "Player not found in match" });

    const teamName = player.team || null;

    const savedName = player.userId?.name || "Unknown";
    const savedUid = player.userId?.uid || player.uid || "-";
    const savedPhone = player.userId?.phone || "-";

    // Games where kills should NOT be saved
    const NON_KILL_GAMES = ["Ludo", "Carrom", "8 Ball Pool", "Cricket"];

    // ⭐ Decide Final Kills
    let finalKills = null; // default null

    if (!NON_KILL_GAMES.includes(match.game)) {
      // Other games → Save kills normally
      finalKills = Number(kills) || 0;
    }

    match.userResults.push({
      userId: req.user.id,
      uid: savedUid,
      name: savedName,
      phone: savedPhone,
      team: teamName,
      game: match.game,
      mode: match.mode,
      type: match.type,
      matchId: match._id,
      matchNumber: match.matchNumber,
      entryFee: match.entryFee,
      prizeSystem: match.prizeSystem,
      screenshotUrl,
      kills: finalKills,  // ⭐ Correct kills value
      uploadedAt: new Date()
    });

    await match.save();

    res.json({ success: true, msg: "Result Uploaded Successfully" });

  } catch (err) {
    console.error("upload result error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});





router.get("/admin/match/results/:matchId", authAdmin, async (req, res) => {
  try {
    const { matchId } = req.params;

    const match = await QuickMatch.findById(matchId)
      .populate("players.userId", "name phone uid avatarUrl");

    if (!match) {
      return res.json({ success: false, msg: "Match Not Found" });
    }

    const isTeamEqual = match.prizeSystem === "team_equal";
    const players = match.players;

    // ⭐ FUNCTION: get REAL team exactly like /pairs route
    const getRealTeam = (userId) => {
      const index = players.findIndex(p => String(p.userId?._id) === String(userId));
      if (index === -1) return null;

      const p = players[index];

      // if prize system is NOT team_equal => no team
      if (!isTeamEqual) return null;

      // if DB already stored team, use that
      if (p.team) return p.team;

      // fallback same as /pairs logic
      return index < players.length / 2 ? "LION" : "TIGER";
    };

    // ⭐ FINAL results with REAL TEAMS
    const formattedResults = match.userResults
      .map((r) => {
        const realTeam = getRealTeam(r.userId);

        return {
          userId: r.userId,
          name: r.name,
          uid: r.uid,
          phone: r.phone,
          team: realTeam,                 // ⭐ EXACT TEAM like /pairs
          kills: r.kills || 0,
          screenshotUrl: r.screenshotUrl,
          uploadedAt: r.uploadedAt
        };
      })
      .sort((a, b) => b.kills - a.kills);

    res.json({
      success: true,
      matchId: match._id,
      matchNumber: match.matchNumber,
      game: match.game,
      mode: match.mode,
      type: match.type,
      entryFee: match.entryFee,
      prizeSystem: match.prizeSystem,
      totalPlayers: players.length,
      results: formattedResults
    });

  } catch (err) {
    console.log("admin match results fetch error:", err);
    return res.status(500).json({ success: false, msg: "Server Error" });
  }
});

// GET /admin/match/results
// completeMatch.js
const History = require("../models/History");
const Leaderboard = require("../models/Leaderboard");
// completeMatch.js
// Utility: safe extraction of userId string from populated or raw userId

router.post("/admin/match/complete", authAdmin, async (req, res) => {
  try {
    const { matchId, winnerTeam, kills = [], prizeSystem } = req.body;

    if (!matchId) return res.json({ success: false, msg: "Missing matchId" });

    const match = await QuickMatch.findById(matchId).populate("players.userId", "name phone");
    if (!match) return res.json({ success: false, msg: "Match not found" });

    // entry fee, players count
    const entryFee = Number(match.entryFee || 0);
    const numPlayers = Array.isArray(match.players) ? match.players.length : 1;
    const totalCollected = entryFee * numPlayers;
    const adminCut = Math.round((totalCollected * 8) / 100);
    let prizePool = Math.max(0, Math.round(totalCollected - adminCut));

    // helper ensureWallet
    const ensureWallet = async (userId) => {
      let w = await Wallet.findOne({ userId });
      if (!w) w = await Wallet.create({ userId, balance: 0 });
      return w;
    };

    // Normalize admin-provided kills (only winners expected)
    // Format: [{ userId: "...", kills: 5 }, ...]
    const adminKillsMap = {};
    for (const k of kills) {
      if (!k || !k.userId) continue;
      adminKillsMap[String(k.userId)] = Number(k.kills || 0);
    }

    // Build/merge userResults array:
    // - For winners (those in adminKillsMap) use admin kills
    // - For other players, keep existing match.userResults if present, else default kills=0
    const existingResults = Array.isArray(match.userResults) ? [...match.userResults] : [];

    // Map existing by userId string
    const existingMap = {};
    for (const r of existingResults) {
      if (!r.userId) continue;
      existingMap[String(r.userId)] = r;
    }

    // Build unified userResults for all players (so history/leaderboard can compute)
    const finalUserResults = match.players.map(p => {
      const uid = String(p.userId?._id ?? p.userId);
      const team = p.team || null;
      // admin overrides only for winners (admin sent kills only for winners)
      if (adminKillsMap.hasOwnProperty(uid)) {
        return {
          userId: uid,
          gameUid: existingMap[uid]?.gameUid || "",
          screenshotUrl: existingMap[uid]?.screenshotUrl || "",
          kills: adminKillsMap[uid],
          uploadedAt: existingMap[uid]?.uploadedAt || new Date(),
          team
        };
      } else if (existingMap[uid]) {
        // keep uploaded result for losers (or if user had uploaded)
        return {
          userId: uid,
          gameUid: existingMap[uid].gameUid || "",
          screenshotUrl: existingMap[uid].screenshotUrl || "",
          kills: Number(existingMap[uid].kills || 0),
          uploadedAt: existingMap[uid].uploadedAt || existingMap[uid].createdAt || null,
          team
        };
      } else {
        // default
        return {
          userId: uid,
          gameUid: "",
          screenshotUrl: "",
          kills: 0,
          uploadedAt: null,
          team
        };
      }
    });

    // Save final userResults back to match so history/leaderboard use same source
    match.userResults = finalUserResults;

    // ----------------------------
    // Determine winners (admin selected winnerTeam required for team matches)
    // ----------------------------
    if (match.type === "1v1" || (String(match.type || "").toLowerCase() === "solo")) {
      // For 1v1, admin should provide kills for winners (expected one or two entries)
      // Determine top by finalUserResults kills (but adminKillsMap for winners has priority)
      const sorted = [...finalUserResults].sort((a, b) => (b.kills || 0) - (a.kills || 0));
      const top = sorted[0];
      if (!top) return res.json({ success: false, msg: "No players found for 1v1" });

      const winnerId = String(top.userId);

      // pay full prizePool to the winner
      await ensureWallet(winnerId);
      await Wallet.updateOne({ userId: winnerId }, { $inc: { balance: prizePool } });

      await Transaction.create({
        userId: winnerId,
        matchId,
        type: "MATCH_REWARD",
        amount: prizePool,
        description: "1v1 Admin Result"
      });

      // create history & leaderboard update for winner
      await History.create({
        userId: winnerId,
        matchId,
        game: match.game,
        entryFee,
        winAmount: prizePool,
        kills: top.kills || 0,
        createdAt: new Date()
      });

      await Leaderboard.updateOne(
        { userId: winnerId },
        {
          $inc: {
            totalWinnings: prizePool,
            totalSpent: entryFee,
            matchesPlayed: 1,
            netWin: prizePool - entryFee
          },
          $setOnInsert: { userId: winnerId }
        },
        { upsert: true }
      );

      match.status = "completed";
      match.winnerTeam = "SOLO";
      match.winnerIds = [winnerId];
      match.prizeGiven = prizePool;
      await match.save();

      return res.json({ success: true, msg: "1v1 match completed (admin priority)", prizePool, payouts: [{ userId: winnerId, amount: prizePool }] });
    }

    // Team match: admin must provide winnerTeam (Option A)
    if (!winnerTeam) return res.json({ success: false, msg: "winnerTeam required for team matches" });

    const winningPlayers = match.players.filter(p => p.team === winnerTeam);
    if (!winningPlayers.length) return res.json({ success: false, msg: "Winner team has no players" });

    // Map winners with kills (from finalUserResults)
    const winnerResults = finalUserResults.filter(r => winningPlayers.some(p => String(p.userId?._id ?? p.userId) === String(r.userId)));

    // Compute payouts according to prizeSystem
    const payouts = [];
    if (String(prizeSystem) === "team_equal") {
      const share = Math.round(prizePool / winnerResults.length);
      for (const wr of winnerResults) {
        const uid = String(wr.userId);
        await ensureWallet(uid);
        await Wallet.updateOne({ userId: uid }, { $inc: { balance: share } });

        await Transaction.create({
          userId: uid,
          matchId,
          type: "MATCH_REWARD",
          amount: share,
          description: "Team Equal (Admin Result)"
        });

        await History.create({
          userId: uid,
          matchId,
          game: match.game,
          entryFee,
          winAmount: share,
          kills: wr.kills || 0,
          createdAt: new Date()
        });

        await Leaderboard.updateOne(
          { userId: uid },
          {
            $inc: {
              totalWinnings: share,
              totalSpent: entryFee,
              matchesPlayed: 1,
              netWin: share - entryFee
            },
            $setOnInsert: { userId: uid }
          },
          { upsert: true }
        );

        payouts.push({ userId: uid, amount: share, kills: wr.kills || 0 });
      }
    } else { // kill_based or default
      const totalKills = winnerResults.reduce((s, x) => s + (Number(x.kills) || 0), 0);
      if (totalKills > 0) {
        let distributed = 0;
        for (let i = 0; i < winnerResults.length; i++) {
          const wr = winnerResults[i];
          let share = Math.round(((wr.kills || 0) / totalKills) * prizePool);
          if (i === winnerResults.length - 1) share = prizePool - distributed; // adjust last
          distributed += share;

          const uid = String(wr.userId);
          await ensureWallet(uid);
          await Wallet.updateOne({ userId: uid }, { $inc: { balance: share } });

          await Transaction.create({
            userId: uid,
            matchId,
            type: "MATCH_REWARD",
            amount: share,
            description: "Kill Based (Admin Result)"
          });

          await History.create({
            userId: uid,
            matchId,
            game: match.game,
            entryFee,
            winAmount: share,
            kills: wr.kills || 0,
            createdAt: new Date()
          });

          await Leaderboard.updateOne(
            { userId: uid },
            {
              $inc: {
                totalWinnings: share,
                totalSpent: entryFee,
                matchesPlayed: 1,
                netWin: share - entryFee
              },
              $setOnInsert: { userId: uid }
            },
            { upsert: true }
          );

          payouts.push({ userId: uid, amount: share, kills: wr.kills || 0 });
        }
      } else {
        // no kills among winners, equal split
        const equal = Math.round(prizePool / winnerResults.length);
        for (const wr of winnerResults) {
          const uid = String(wr.userId);
          await ensureWallet(uid);
          await Wallet.updateOne({ userId: uid }, { $inc: { balance: equal } });

          await Transaction.create({
            userId: uid,
            matchId,
            type: "MATCH_REWARD",
            amount: equal,
            description: "Kill Based (no-kills) Admin Result"
          });

          await History.create({
            userId: uid,
            matchId,
            game: match.game,
            entryFee,
            winAmount: equal,
            kills: wr.kills || 0,
            createdAt: new Date()
          });

          await Leaderboard.updateOne(
            { userId: uid },
            {
              $inc: {
                totalWinnings: equal,
                totalSpent: entryFee,
                matchesPlayed: 1,
                netWin: equal - entryFee
              },
              $setOnInsert: { userId: uid }
            },
            { upsert: true }
          );

          payouts.push({ userId: uid, amount: equal, kills: wr.kills || 0 });
        }
      }
    }

    // Finalize match document
    match.status = "completed";
    match.winnerTeam = winnerTeam;
    match.winnerIds = winnerResults.map(r => String(r.userId));
    match.prizeGiven = prizePool;
    // Persist final userResults (admin-overridden winners + existing losers)
    match.userResults = finalUserResults;
    await match.save();

    return res.json({ success: true, msg: "Match completed (admin priority)", prizePool, payouts });

  } catch (err) {
    console.error("complete match error:", err);
    res.status(500).json({ success: false, msg: "Server Error", error: err.message });
  }
});


router.get("/history", auth, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.user._id);

    /* ================= MATCH HISTORY ================= */
    const matches = await QuickMatch.find({
      status: "completed",
      $or: [
        { "players.userId": userId },
        { "slots.userId": userId }
      ]
    })
      .select(
        "matchNumber game mode entryFee createdAt prizeSystem prizeGiven type players userResults winnerIds"
      )
      .sort({ createdAt: -1 })
      .limit(100) // 🔥 reduced for speed
      .lean();

    const history = [];

    for (const m of matches) {
      const entryFee = Number(m.entryFee || 0);
      const joinedPlayers = m.players?.length || 1;

      const totalCollected = entryFee * joinedPlayers;
      const prizePool = Math.max(
        0,
        totalCollected - Math.round(totalCollected * 0.08)
      );

      const myResult = (m.userResults || []).find(
        r => String(r.userId) === String(userId)
      );

      let isWinner = false;
      let prizeWon = 0;

      const winnerIds = (m.winnerIds || []).map(String);

      // ✅ ADMIN DECIDED
      if (winnerIds.length && winnerIds.includes(String(userId))) {
        isWinner = true;

        if (m.prizeSystem === "kill_based") {
          const winners = m.userResults.filter(r =>
            winnerIds.includes(String(r.userId))
          );
          const totalKills = winners.reduce((s, x) => s + (x.kills || 0), 0);

          if (totalKills > 0) {
            prizeWon = Math.round(
              ((myResult?.kills || 0) / totalKills) *
              (m.prizeGiven || prizePool)
            );
          }
        } else {
          const winnersCount =
            m.userResults.filter(r =>
              winnerIds.includes(String(r.userId))
            ).length || 1;

          prizeWon = Math.round(
            (m.prizeGiven || prizePool) / winnersCount
          );
        }
      }

      history.push({
        type: "match",
        matchId: m._id,
        matchNumber: m.matchNumber,
        game: m.game,
        mode: m.mode,
        entryFee,
        createdAt: m.createdAt,
        kills: myResult?.kills ?? null,
        result: isWinner ? "win" : "loss",
        prize: prizeWon
      });
    }

    /* ================= TOURNAMENT HISTORY ================= */
    const tournaments = await Tournament.find({
      $or: [
        { "winners.userId": userId },
        { "players.userId": userId }
      ]
    })
      .select("name game entryFee winners players createdAt")
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    for (const t of tournaments) {
      const win = t.winners?.find(w => String(w.userId) === String(userId));

      history.push({
        type: "tournament",
        tournamentId: t._id,
        tournamentName: t.name,
        game: t.game,
        entryFee: t.entryFee,
        result: win ? "win" : "loss",
        prize: win?.prize || 0,
        createdAt: win?.declaredAt || t.createdAt
      });
    }

    history.sort((a, b) => b.createdAt - a.createdAt);

    res.json({ success: true, count: history.length, history });

  } catch (err) {
    console.error("History Error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});


router.get("/history", auth, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.user.id);

    /* =========================
       MATCH HISTORY
    ========================= */
    const matches = await QuickMatch.find({
      status: "completed",
      $or: [
        { "slots.userId": userId },
        { "players.userId": userId }
      ]
    })
      .sort({ createdAt: -1 })
      .limit(500)
      .lean();

    const history = [];

    for (const m of matches) {
      const entryFee = Number(m.entryFee || 0);

      const playersCount =
        (m.players?.length || 0) +
        (m.slots?.length || 0) || 1;

      const totalCollected = entryFee * playersCount;
      const prizePool = Math.max(
        0,
        totalCollected - Math.round(totalCollected * 0.08)
      );

      const winnerIds = (m.winnerIds || []).map(id => String(id));
      const userResults = Array.isArray(m.userResults) ? m.userResults : [];

      const myResult = userResults.find(
        r => String(r.userId) === String(userId)
      );

      let isWinner = false;
      let prizeWon = 0;

      /* ===== ADMIN SELECTED WINNERS ===== */
      if (winnerIds.length > 0) {
        if (winnerIds.includes(String(userId))) {
          isWinner = true;

          if (m.prizeSystem === "team_equal") {
            const winners = userResults.filter(r =>
              winnerIds.includes(String(r.userId))
            );
            prizeWon = Math.round(
              (m.prizeGiven || prizePool) / (winners.length || 1)
            );
          } 
          else if (m.prizeSystem === "kill_based") {
            const winners = userResults.filter(r =>
              winnerIds.includes(String(r.userId))
            );
            const totalKills = winners.reduce(
              (s, x) => s + Number(x.kills || 0), 0
            );

            if (totalKills > 0) {
              const ur = winners.find(r => String(r.userId) === String(userId));
              prizeWon = Math.round(
                ((ur?.kills || 0) / totalKills) * (m.prizeGiven || prizePool)
              );
            } else {
              prizeWon = Math.round(
                (m.prizeGiven || prizePool) / (winners.length || 1)
              );
            }
          } 
          else {
            prizeWon = m.prizeGiven || prizePool;
          }
        }
      }

      /* ===== AUTO RESULT (NO ADMIN) ===== */
      else {
        if (m.type === "1v1") {
          const top = [...userResults].sort(
            (a, b) => (b.kills || 0) - (a.kills || 0)
          )[0];

          if (top && String(top.userId) === String(userId)) {
            isWinner = true;
            prizeWon = top.prize || m.prizeGiven || prizePool;
          }
        } 
        else {
          const teamKills = {};
          userResults.forEach(r => {
            teamKills[r.team] = (teamKills[r.team] || 0) + Number(r.kills || 0);
          });

          const winnerTeam = Object.keys(teamKills).sort(
            (a, b) => teamKills[b] - teamKills[a]
          )[0];

          const ur = userResults.find(
            r => String(r.userId) === String(userId)
          );

          if (ur && ur.team === winnerTeam) {
            isWinner = true;

            if (m.prizeSystem === "kill_based") {
              prizeWon = Math.round(
                ((ur.kills || 0) / teamKills[winnerTeam]) *
                (m.prizeGiven || prizePool)
              );
            } else {
              const winners = userResults.filter(r => r.team === winnerTeam);
              prizeWon = Math.round(
                (m.prizeGiven || prizePool) / (winners.length || 1)
              );
            }
          }
        }
      }

      history.push({
        type: "match",
        matchId: m._id,
        matchNumber: m.matchNumber,
        game: m.game,
        mode: m.mode,
        entryFee,
        createdAt: m.createdAt,
        kills: myResult?.kills || 0,
        result: isWinner ? "win" : "loss",
        prize: prizeWon
      });
    }

    /* =========================
       TOURNAMENT HISTORY
    ========================= */
    const tournaments = await Tournament.find({
      $or: [
        { "winners.userId": userId },
        { "joinedUsers.userId": userId },
        { "players.userId": userId }
      ]
    })
      .sort({ createdAt: -1 })
      .limit(500)
      .lean();

    for (const t of tournaments) {
      const win = t.winners?.find(w => String(w.userId) === String(userId));
      const join =
        t.joinedUsers?.find(j => String(j.userId) === String(userId)) ||
        t.players?.find(p => String(p.userId) === String(userId));

      history.push({
        type: "tournament",
        tournamentId: t._id,
        tournamentName: t.name,
        game: t.game,
        entryFee: t.entryFee,
        result: win ? "win" : "loss",
        prize: win?.prize || 0,
        position: win?.position || null,
        createdAt: win?.declaredAt || join?.joinedAt || t.createdAt
      });
    }

    history.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({ success: true, count: history.length, history });

  } catch (err) {
    console.error("History Error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

router.get("/leaderboard", auth, async (req, res) => {
  try {
    const { date, game } = req.query;

    let start = date ? new Date(date) : new Date("2000-01-01");
    let end = date ? new Date(date) : new Date();
    if (date) { start.setHours(0,0,0,0); end.setHours(23,59,59,999); }

    const userMap = new Map();

    const matches = await QuickMatch.find({
      status: "completed",
      createdAt: { $gte: start, $lte: end },
      ...(game ? { game } : {})
    }).lean();

    for (const m of matches) {
      const entryFee = Number(m.entryFee || 0);
      const totalPlayers = (m.players || []).length || 1;
      const totalCollected = entryFee * totalPlayers;
      const prizePool = Math.max(0, totalCollected - Math.round(totalCollected * 0.08));

      const winnerIds = (m.winnerIds || []).map(id => String(id));
      const userResults = Array.isArray(m.userResults) ? m.userResults : [];

      // Add spend for all players
      const allPlayers = (m.players || []).map(p => {
        if (!p || !p.userId) return null;
        return typeof p.userId === "object" ? String(p.userId._id || p.userId) : String(p.userId);
      }).filter(Boolean);

      for (const uid of allPlayers) {
        if (!userMap.has(uid)) userMap.set(uid, { userId: uid, name: "Unknown", totalWinnings: 0, totalSpent: 0 });
        userMap.get(uid).totalSpent += entryFee;
      }

      // If admin selected winners, use those winnerIds + m.prizeGiven
      if (winnerIds.length > 0) {
        // winnerPlayers details from userResults (which were saved by admin)
        const winnerPlayers = userResults.filter(r => winnerIds.includes(String(r.userId)));

        // if team_equal
        if (m.prizeSystem === "team_equal") {
          const share = Math.round((m.prizeGiven || prizePool) / (winnerPlayers.length || 1));
          for (const p of winnerPlayers) {
            const uid = String(p.userId);
            if (!userMap.has(uid)) userMap.set(uid, { userId: uid, name: "Unknown", totalWinnings: 0, totalSpent: 0 });
            userMap.get(uid).totalWinnings += share;
          }
        } else { // kill_based
          const totalTeamKills = winnerPlayers.reduce((s, x) => s + (Number(x.kills || 0)), 0);
          if (totalTeamKills > 0) {
            for (const p of winnerPlayers) {
              const uid = String(p.userId);
              const share = Math.round(((Number(p.kills || 0)) / totalTeamKills) * (m.prizeGiven || prizePool));
              if (!userMap.has(uid)) userMap.set(uid, { userId: uid, name: "Unknown", totalWinnings: 0, totalSpent: 0 });
              userMap.get(uid).totalWinnings += share;
            }
          } else {
            // equal split fallback
            const share = Math.round((m.prizeGiven || prizePool) / (winnerPlayers.length || 1));
            for (const p of winnerPlayers) {
              const uid = String(p.userId);
              if (!userMap.has(uid)) userMap.set(uid, { userId: uid, name: "Unknown", totalWinnings: 0, totalSpent: 0 });
              userMap.get(uid).totalWinnings += share;
            }
          }
        }
        continue; // next match
      }

      // If no admin winners, fallback to old (auto) logic
      if (m.type === "1v1") {
        const sorted = [...userResults].sort((a, b) => (b.kills || 0) - (a.kills || 0));
        const top = sorted[0];
        if (top) {
          const uid = String(top.userId);
          const prize = top.prize || m.prizeGiven || prizePool;
          if (!userMap.has(uid)) userMap.set(uid, { userId: uid, name: "Unknown", totalWinnings: 0, totalSpent: 0 });
          userMap.get(uid).totalWinnings += prize;
        }
      } else {
        // team auto-detect
        const teamKills = {};
        userResults.forEach(r => {
          teamKills[r.team] = (teamKills[r.team] || 0) + (Number(r.kills || 0));
        });

        const winnerTeam = Object.keys(teamKills).sort((a, b) => (teamKills[b] || 0) - (teamKills[a] || 0))[0];
        const winnerPlayers = userResults.filter(r => r.team === winnerTeam);

        if (winnerPlayers.length) {
          if (m.prizeSystem === "team_equal") {
            const share = Math.round((m.prizeGiven || prizePool) / (winnerPlayers.length || 1));
            winnerPlayers.forEach(p => {
              const uid = String(p.userId);
              if (!userMap.has(uid)) userMap.set(uid, { userId: uid, name: "Unknown", totalWinnings: 0, totalSpent: 0 });
              userMap.get(uid).totalWinnings += share;
            });
          } else { // kill_based
            const totalTeamKills = winnerPlayers.reduce((s, x) => s + (Number(x.kills || 0)), 0);
            if (totalTeamKills > 0) {
              winnerPlayers.forEach(p => {
                const uid = String(p.userId);
                const share = Math.round(((p.kills || 0) / totalTeamKills) * (m.prizeGiven || prizePool));
                if (!userMap.has(uid)) userMap.set(uid, { userId: uid, name: "Unknown", totalWinnings: 0, totalSpent: 0 });
                userMap.get(uid).totalWinnings += share;
              });
            } else {
              const share = Math.round((m.prizeGiven || prizePool) / (winnerPlayers.length || 1));
              winnerPlayers.forEach(p => {
                const uid = String(p.userId);
                if (!userMap.has(uid)) userMap.set(uid, { userId: uid, name: "Unknown", totalWinnings: 0, totalSpent: 0 });
                userMap.get(uid).totalWinnings += share;
              });
            }
          }
        }
      }
    }

    // Attach names for user IDs
    const allUserIds = Array.from(userMap.keys());
    const users = await User.find({ _id: { $in: allUserIds } }, { name: 1 }).lean();
    const nameMap = new Map(users.map(u => [String(u._id), u.name || "Unknown"]));
    for (const uid of allUserIds) {
      const entry = userMap.get(uid);
      if (!entry) continue;
      entry.name = nameMap.get(uid) || "Unknown";
    }

    const leaderboard = Array.from(userMap.values())
      .map(u => ({ ...u, netWin: (u.totalWinnings || 0) - (u.totalSpent || 0) }))
      .sort((a, b) => b.netWin - a.netWin)
      .map((u, i) => ({ ...u, rank: i + 1 }));

    res.json({ success: true, leaderboard });

  } catch (err) {
    console.error("Leaderboard Error:", err);
    res.status(500).json({ success: false, msg: "Server Error", error: err.message });
  }
});







// GET /admin/match/results
// GET /admin/match/results
router.get("/admin/match/results", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find({
      "userResults.0": { $exists: true }
    })
      .sort({ createdAt: -1 })
      .limit(300)
      .populate("players.userId", "name phone") // ✅ removed uid
      .lean();

    if (!matches.length) {
      return res.json({ success: false, msg: "No match results found" });
    }

    const NON_KILL_GAMES = ["ludo", "carrom", "8 ball pool", "8ball", "cricket"];
    const KILL_GAMES = ["bgmi", "pubg", "free fire", "freefire"];

    const formatted = matches.map(match => {
      const matchGame = String(match.game || "").toLowerCase();
      const isNonKill = NON_KILL_GAMES.some(g => matchGame.includes(g));
      const isKill = KILL_GAMES.some(g => matchGame.includes(g));

      const playersArr = Array.isArray(match.players) ? match.players : [];
      const slotsArr = Array.isArray(match.slots) ? match.slots : [];

      const getId = (obj) => {
        if (!obj) return "";
        if (obj.userId) {
          if (typeof obj.userId === "object") return String(obj.userId._id);
          return String(obj.userId);
        }
        if (obj._id) return String(obj._id);
        return "";
      };

      const originalById = {};
      playersArr.forEach(p => {
        const id = getId(p);
        if (id) originalById[id] = p;
      });

      const rawResults = Array.isArray(match.userResults)
        ? match.userResults
        : [];

      const results = rawResults.map(r => {
        const userId = getId(r);
        const original = originalById[userId] || {};

        const name =
          original?.userId?.name ||
          original?.name ||
          original?.phone ||
          "Unknown";

        const uid = original?.uid || "-";
        const phone = original?.userId?.phone || original?.phone || "-";

        let killsValue = Number(r.kills);
        if (!Number.isFinite(killsValue)) killsValue = 0;
        if (isNonKill) killsValue = null;

        return {
          userId,
          name,
          uid,
          phone,
          team: r.team || original.team || "",
          kills: killsValue,
          prize: Number(r.prize || 0),
          result: r.result || "",
          screenshotUrl: r.screenshotUrl || "",
          uploadedAt: r.uploadedAt || null,
          prizeSystem: match.prizeSystem || "team_equal"
        };
      });

      const sortedResults = isKill
        ? results.sort((a, b) => {
            if (b.kills !== a.kills) return b.kills - a.kills;
            return new Date(a.uploadedAt || 0) - new Date(b.uploadedAt || 0);
          })
        : results.sort(
            (a, b) =>
              new Date(a.uploadedAt || 0) - new Date(b.uploadedAt || 0)
          );

      return {
        _id: match._id,
        matchNumber: match.matchNumber,
        type: match.type,
        game: match.game,
        mode: match.mode,
        entryFee: match.entryFee,
        prizeSystem: match.prizeSystem || "team_equal",
        totalPlayers: slotsArr.filter(s => s.userId).length, // ✅ correct
        results: sortedResults
      };
    });

    res.json({ success: true, list: formatted });

  } catch (err) {
    console.error("❌ admin result error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});




// ----------------------------------------------------------------------


// -------------------------
// 1️⃣ Admin Complete Match
// -------------------------

// -------------------------
// 2️⃣ User Match History
// -------------------------
// ---------------
// 1️⃣ Admin Complete Match
// (same as before, ensure userResults is saved correctly)
// ---------------

// ---------------
// 2️⃣ History
// ---------------






// DELETE a completed match (admin only)
router.delete("/admin/match/:matchId", authAdmin, async (req, res) => {
  try {
    const { matchId } = req.params;
    if (!matchId) return res.status(400).json({ success: false, msg: "Missing matchId" });

    const match = await QuickMatch.findById(matchId);
    if (!match) return res.status(404).json({ success: false, msg: "Match not found" });

    // Only allow deletion if match is completed
    if (match.status !== "completed") {
      return res.status(400).json({ success: false, msg: "Cannot delete incomplete match" });
    }

    // Optionally: delete related transactions
    await Transaction.deleteMany({ matchId });

    // Delete match
    await QuickMatch.findByIdAndDelete(matchId);

    res.json({ success: true, msg: "Match deleted successfully" });
  } catch (err) {
    console.error("Delete match error:", err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});


router.get("/admin/match/winners", authAdmin, async (req, res) => {
  try {
    const matches = await Match.find({ status: "completed" })
      .sort({ updatedAt: -1 })
      .limit(300)
      .limit(10)
      .populate("results.userId", "name avatar");

    const winners = [];

    matches.forEach(m => {
      if(m.type === "1v1"){
        const winner = m.results.sort((a,b)=>b.kills-a.kills)[0];
        winners.push({
          name: winner.userId.name,
          avatar: winner.userId.avatar,
          matchId: m._id,
          amount: m.prizeGiven,
          game: m.game,
          mode: m.mode
        });
      } else {
        const winningTeam = m.winnerTeam;
        const winnerPlayers = m.results.filter(r => r.team === winningTeam);
        winnerPlayers.forEach(p=>{
          winners.push({
            name: p.userId.name,
            avatar: p.userId.avatar,
            matchId: m._id,
            amount: p.share,
            game: m.game,
            mode: m.mode,
            teamColor: p.team.toLowerCase() // red, blue, green, etc.
          });
        });
      }
    });

    res.json({ success: true, list: winners });
  } catch(err) {
    console.error(err);
    res.status(500).json({ success:false, msg:"Server error" });
  }
});


// ✅ User completed matches history
router.get("/my-completed", auth, async (req, res) => {
  try {
    const userId = req.user.id;

    const completedMatches = await QuickMatch.find({
      "players.userId": userId,
      status: "completed"
    })
      .select("-__v")
      .sort({ updatedAt: -1 })
      .limit(100);

    res.json({
      success: true,
      data: completedMatches
    });

  } catch (err) {
    console.error("Error in /my-completed:", err);
    res.status(500).json({ success: false, msg: "Internal server error" });
  }
});

// ✅ only matches where user is winner
router.get("/my-wins", auth, async (req, res) => {
  try {
    const userId = req.user.id;

    const myWins = await QuickMatch.find({
      status: "completed",
      winnerId: userId
    })
      .select("-__v")
      .sort({ updatedAt: -1 })
      .limit(100);

    res.json({
      success: true,
      data: myWins
    });

  } catch (err) {
    console.error("Error in /my-wins:", err);
    res.status(500).json({ success: false, msg: "Internal server error" });
  }
});


router.post("/admin/assign-teams", authAdmin, async(req,res)=>{
  try{
    const { matchId, teams } = req.body;

    if(!matchId || !teams || !Array.isArray(teams)){
      return res.json({success:false,msg:"Missing matchId or teams"});
    }

    const match = await QuickMatch.findById(matchId);
    if(!match) return res.json({success:false,msg:"match not found"});

    // update each player's team
    teams.forEach(t=>{
      const idx = match.players.findIndex(p=>String(p.userId)==String(t.userId));
      if(idx>=0){
        match.players[idx].team = t.team; // store LION / TIGER
      }
    });

    await match.save();

    res.json({success:true,msg:"Teams Assigned"});
  }
  catch(err){
    console.log("team assign err",err);
    res.status(500).json({success:false,msg:"server err"});
  }
});

// set team for each player
router.post("/api/wallet/admin/match/set-teams", authAdmin, async(req,res)=>{
  try{
    const { matchId, teams } = req.body;
    /**
      teams = [
        { userId:"66xxxx", team:"LION" },
        { userId:"66yyyy", team:"TIGER" },
        ...
      ]
    */

    if(!matchId) return res.json({success:false,msg:"Missing matchId"});
    if(!teams || !Array.isArray(teams)) 
        return res.json({success:false,msg:"Teams array required"});

    const match = await QuickMatch.findById(matchId);
    if(!match) return res.json({success:false,msg:"Match not found"});

    // apply team to each player
    teams.forEach(t=>{
      const p = match.players.find(x=>String(x.userId)==String(t.userId));
      if(p) p.team = t.team;
    });

    await match.save();

    res.json({success:true,msg:"Teams updated successfully",match});
  }
  catch(err){
    console.log("set team error:",err);
    res.status(500).json({success:false,msg:"Server Error"});
  }
});


// Delete single unpaired player

// ---------------------------------------------------------
// DELETE all unpaired members
// ---------------------------------------------------------
// delete all unpaired players from ALL unpaired matches
router.delete("/joined/unpaired", async (req, res) => {
  try {
    const result = await QuickMatch.updateMany(
      { status: { $in:["waiting","filled"] } },  // include filled also
      { $set: { players: [] } }                  // clear players
    );

    res.json({
      success: true,
      msg: `Deleted all unpaired members from ${result.modifiedCount} match(es)`
    });

  } catch (err) {
    console.error("❌ Error deleting unpaired members:", err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});

router.delete("/joined/unpaired", async (req, res) => {
  try {
    const result = await QuickMatch.updateMany(
      { status: "waiting" },      // only unpaired/waiting matches
      { $set: { players: [] } }   // clear players array
    );
    res.json({ success: true, msg: `Deleted all unpaired members from ${result.modifiedCount} match(es)` });
  } catch (err) {
    console.error("❌ Error deleting unpaired members:", err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});

// ---------------------------------------------------------
// DELETE all paired matches
// ---------------------------------------------------------
router.delete("/joined/paired", async (req, res) => {
  try {
    const result = await QuickMatch.deleteMany(
      { status: { $in: ["paired", "filled"] } } // remove paired/filled matches completely
    );
    res.json({ success: true, msg: `Deleted ${result.deletedCount} paired match(es)` });
  } catch (err) {
    console.error("❌ Error deleting paired matches:", err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});

// ---------------------------------------------------------
// DELETE all joined members (waiting/unpaired only)
// ---------------------------------------------------------
// DELETE ALL JOINED MEMBERS
router.delete("/joined/all", async (req, res) => {
  try {
    // This deletes all players who joined (both paired/unpaired)
    const result = await QuickMatch.deleteMany({});
    return res.json({ success: true, msg: `Deleted ${result.deletedCount} joined member(s)` });
  } catch (err) {
    console.error("❌ Error deleting all joined members:", err);
    return res.status(500).json({ success: false, msg: "Server Error" });
  }
});


router.delete("/joined/all", async (req, res) => {
  try {
    const result = await QuickMatch.updateMany(
      { status: "waiting" },     // only waiting/unpaired matches
      { $set: { players: [] } }  // clear players array
    );
    res.json({ success: true, msg: `Deleted all joined members from ${result.modifiedCount} match(es)` });
  } catch (err) {
    console.error("❌ Error deleting all joined members:", err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});


// Delete a single unpaired player from a match
// Pass query params: matchId & userId
// delete single unpaired player from a match
router.delete("/joined/unpaired/:matchId/:userId", async (req, res) => {
  try {
    const { matchId, userId } = req.params;

    if (!matchId || !userId)
      return res.status(400).json({ success: false, msg: "Missing matchId or userId" });

    // match should be unpaired (waiting OR filled)
    const match = await QuickMatch.findOne({
      _id: matchId,
      status: { $in: ["waiting","filled"] }
    });

    if (!match) return res.status(404).json({ success: false, msg: "Match not found / Not unpaired" });

    const originalCount = match.players.length;
    match.players = match.players.filter(p => String(p.userId) !== userId);
    await match.save();

    res.json({
      success: true,
      msg: `Deleted player. Removed ${originalCount - match.players.length} player(s).`,
    });

  } catch (err) {
    console.error("❌ Error deleting single unpaired player:", err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});


router.delete("/joined/unpaired/:matchId/:userId", async (req, res) => {
  try {
    const { matchId, userId } = req.params;

    if (!matchId || !userId) return res.status(400).json({ success: false, msg: "Missing matchId or userId" });

    const match = await QuickMatch.findById(matchId);
    if (!match) return res.status(404).json({ success: false, msg: "Match not found" });

    const originalCount = match.players.length;
    match.players = match.players.filter(p => String(p.userId) !== userId);
    await match.save();

    res.json({
      success: true,
      msg: `Deleted player from match. Removed ${originalCount - match.players.length} player(s).`,
    });

  } catch (err) {
    console.error("❌ Error deleting single unpaired player:", err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});

// Delete a single paired match
// Pass param: matchId
router.delete("/joined/paired/:matchId", async (req, res) => {
  try {
    const { matchId } = req.params;
    if (!matchId) return res.status(400).json({ success: false, msg: "Missing matchId" });

    const result = await QuickMatch.deleteOne({ _id: matchId });
    if (result.deletedCount === 0) return res.status(404).json({ success: false, msg: "Match not found" });

    res.json({ success: true, msg: "Deleted paired match successfully" });

  } catch (err) {
    console.error("❌ Error deleting single paired match:", err);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
});






router.post("/joins", auth, async (req, res) => {
  try {
    const userId = req.user.id;

    let {
      type,
      game,
      mode,
      fee,
      uid,
      prizeSystem,
      countryCode,
      whatsappNumber,
      map,
      roomType,
      headshot,
      characterSkill,
      gunAttributes,
      throwableLimit,
      selectedGuns
    } = req.body;

    // ----------------------------
    // 1️⃣ BASIC VALIDATION
    // ----------------------------
    if (!type || !game || !uid || !prizeSystem || !fee)
      return res.status(400).json({ success: false, msg: "Missing match data" });

    if (!["kill_based", "team_equal"].includes(prizeSystem))
      return res.status(400).json({ success: false, msg: "Invalid prize system" });

    const user = await User.findById(userId);
    if (!user)
      return res.status(400).json({ success: false, msg: "User not found" });

    // ----------------------------
    // 2️⃣ WHATSAPP VALIDATION
    // ----------------------------
    if (!countryCode || !countryCode.startsWith("+"))
      return res.status(400).json({ success: false, msg: "Invalid country code" });

    if (!whatsappNumber)
      return res.status(400).json({ success: false, msg: "WhatsApp number required" });

    const cleanNumber = whatsappNumber.replace(/[\s-]/g, "");
    if (!/^\d{10,15}$/.test(cleanNumber))
      return res.status(400).json({ success: false, msg: "Invalid WhatsApp number" });

    const finalWhatsApp = countryCode + cleanNumber;

    // ----------------------------
    // 3️⃣ PREVENT MULTI-JOIN
    // ----------------------------
    const pendingMatch = await QuickMatch.findOne({
      "players.userId": userId,
      status: { $in: ["waiting", "filled", "ongoing"] }
    });

    if (pendingMatch)
      return res.status(400).json({ success: false, msg: "⚠️ Complete your previous match first." });

    // ----------------------------
    // 4️⃣ PLAYER COUNT
    // ----------------------------
    const totalPlayersMap = { "1v1": 2, "2v2": 4, "3v3": 6, "4v4": 8 };
    const totalSlots = totalPlayersMap[type];
    if (!totalSlots)
      return res.status(400).json({ success: false, msg: "Invalid match type" });

    // ----------------------------
    // 5️⃣ FREE FIRE MAP + MODE HANDLING
    // ----------------------------
    if (game === "Free Fire") {
      const FF_MODES = ["Clash Squad", "Lone Wolf"];
      if (!FF_MODES.includes(mode))
        return res.status(400).json({ success: false, msg: "Invalid Free Fire mode" });

      const CS_MAPS = ["Bermuda", "Alpine", "Kalahari", "Purgatory", "Nexterra"];

      if (mode === "Clash Squad") {
        if (!map) map = CS_MAPS[0];
        if (!CS_MAPS.includes(map))
          return res.status(400).json({ success: false, msg: "Invalid map" });
      }

      if (mode === "Lone Wolf") {
        map = "Iron Cage"; // forced
      }
    }

    // ----------------------------
    // 6️⃣ FIND OR CREATE MATCH
    // ----------------------------
    let match = await QuickMatch.findOne({
      game,
      mode,
      type,
      prizeSystem,
      status: "waiting"
    });

    if (!match) {
      match = new QuickMatch({
        type,
        game,
        mode,
        entryFee: fee,
        prizeSystem,
        status: "waiting",
        players: []
      });
    }

    if (match.players.length >= totalSlots)
      return res.status(400).json({ success: false, msg: "Match full" });

    // ----------------------------
    // 7️⃣ AUTO TEAM ASSIGN
    // ----------------------------
    const teamSize = totalSlots / 2;
    const lionCount = match.players.filter(p => p.team === "LION").length;
    const tigerCount = match.players.filter(p => p.team === "TIGER").length;

    let assignedTeam =
      lionCount < teamSize ? "LION" :
        tigerCount < teamSize ? "TIGER" : null;

    if (!assignedTeam)
      return res.status(400).json({ success: false, msg: "Teams full" });

    // ----------------------------
    // 8️⃣ CATEGORIZE GUNS
    // ----------------------------
    const gunCategories = {
      AR: ["AK", "M4A1", "SCAR", "GROZA", "FAMAS", "AN94", "XM8", "M14", "PARAFAL", "KINGFISHER", "AUG", "AC80"],
      SMG: ["MP40", "MP5", "UMP", "VSS", "THOMPSON", "VECTOR", "BIZON", "UZI", "MAC10"],
      SNIPER: ["AWM", "KAR98K", "M82B", "M24", "SVD", "SKS", "WOODPECKER"],
      SHOTGUN: ["M1014", "M1887", "MAG7", "SPAS12", "Trogon"],
      PISTOLS: ["USP", "G18", "M500", "Desert Eagle", "Treatment Pistol", "Hand Cannon"],
      LAUNCHERS: ["M79", "RGS50", "MGL140"],
      SPECIAL: ["Plasma Gun", "Laser Gun (CS)", "CG15", "Crossbow", "Flame Bow"]
    };

    const categorizedGuns = {
      AR: [], SMG: [], SNIPER: [], SHOTGUN: [], PISTOLS: [], LAUNCHERS: [], SPECIAL: []
    };

    (selectedGuns || []).forEach(gun => {
      for (const cat in gunCategories) {
        if (gunCategories[cat].includes(gun)) {
          categorizedGuns[cat].push(gun);
        }
      }
    });

    // ----------------------------
    // 9️⃣ PREPARE PLAYER DATA
    // ----------------------------
    const playerData = {
      userId,
      uid,
      name: user.name,
      phone: user.phone,
      whatsappNumber: finalWhatsApp,
      team: assignedTeam,
      joinedAt: new Date(),

      // ⭐ SAME FORMAT AS SECOND ROUTE ⭐
      freeFireSettings: {
        map: map || "Not Selected",
        roomType: roomType || (selectedGuns?.length ? "advance" : "regular"),
        gameSettings: {
          headshot: headshot ?? false,
          characterSkill: characterSkill ?? false,
          gunAttributes: gunAttributes ?? false,
          throwableLimit: throwableLimit ?? 0
        },
        selectedGuns: categorizedGuns
      }
    };

    // ----------------------------
    // 🔟 SAVE MATCH
    // ----------------------------
    match.players.push(playerData);
    await match.save();

    res.json({
      success: true,
      msg: `Joined match — Team ${assignedTeam}`,
      assignedTeam,
      match
    });

  } catch (err) {
    console.error("Join Error:", err);
    res.status(500).json({ success: false, msg: "Internal server error" });
  }
});








router.get("/admin/match/:matchId", async (req, res) => {
  try {
    const { matchId } = req.params;

    const match = await QuickMatch.findById(matchId).lean();

    if (!match)
      return res.status(404).json({ success: false, msg: "Match not found" });

    return res.json({
      success: true,
      data: {
        matchId: match._id,
        game: match.game,
        mode: match.mode,
        type: match.type,
        entryFee: match.entryFee,
        prizeSystem: match.prizeSystem, // 🔥 match-level
        status: match.status,
        players: match.players.map(p => ({
          userId: p.userId,
          name: p.name,
          uid: p.uid,
          team: p.team,
          prizeSystem: p.prizeSystem, // 🔥 player-level
        }))
      }
    });
  } catch (err) {
    console.error("Admin Match Detail Error:", err);
    return res.status(500).json({ success: false, msg: "Server Error" });
  }
});

router.get("/admin/matches", async (req, res) => {
  try {
    const matches = await QuickMatch.find()
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    return res.json({
      success: true,
      data: matches.map(m => ({
        matchId: m._id,
        game: m.game,
        mode: m.mode,
        type: m.type,
        entryFee: m.entryFee,
        prizeSystem: m.prizeSystem, // 🔥 match winning system
        status: m.status,
        players: m.players.map(p => ({
          userId: p.userId,
          name: p.name,
          uid: p.uid,
          team: p.team,
          prizeSystem: p.prizeSystem, // 🔥 player-wise system (Kill-Based / Team-Equal)
        }))
      }))
    });
  } catch (err) {
    console.error("Admin Get Matches Error:", err);
    return res.status(500).json({ success: false, msg: "Server Error" });
  }
});

router.get("/matches/winners", async (req, res) => {
  try {
const matches = await QuickMatch.find({ status: "completed" })
      .sort({ createdAt: -1 })
      .limit(100)
      .limit(3)  // ⭐ only last 3 matches
      .populate("players.userId", "name phone uid wallet avatarUrl");

    if (!matches.length) {
      return res.json({ success: false, msg: "No completed matches found" });
    }

    const formatted = matches.map(match => {
      const prizeSystem = match.prizeSystem || null;
      const entryFee = Number(match.entryFee) || 0;
      const totalPlayers = match.players.length;
      const totalCollected = entryFee * totalPlayers;
      const adminCut = Math.round(totalCollected * 0.08);
      const prizePool = Math.max(0, totalCollected - adminCut);

      const results = match.userResults || [];

      let winners = [];

      // ----------------------------------
      // 🟢 1v1 MATCHES
      // ----------------------------------
      if (match.type === "1v1") {
        const winner = results.sort((a, b) => b.kills - a.kills)[0];
        if (winner) {
          const playerObj = match.players.find(p => String(p.userId?._id) === String(winner.userId));
          winners.push({
            ...winner,
            avatarUrl: playerObj?.userId?.avatarUrl || null,
            uid: winner.uid || playerObj?.uid || "-",
            name: winner.name || playerObj?.userId?.name || "Unknown",
            phone: winner.phone || playerObj?.userId?.phone || "-",
            wallet: playerObj?.userId?.wallet || 0,
            winningPrice: prizePool
          });
        }
      }

      // ----------------------------------
      // 🟢 TEAM MATCHES (2v2, 3v3, 4v4)
      // ----------------------------------
      else {
        // Group kills by team
        const teamKills = {};

        results.forEach(r => {
          if (!teamKills[r.team]) teamKills[r.team] = 0;
          teamKills[r.team] += Number(r.kills || 0);
        });

        // Find highest kill team
        const winnerTeam = Object.keys(teamKills).sort((a, b) => teamKills[b] - teamKills[a])[0];

        // Filter winners
        const winnerPlayers = results.filter(r => r.team === winnerTeam);

        // Calculate prize share
        winnerPlayers.forEach(p => {
          const playerObj = match.players.find(pl => String(pl.userId?._id) === String(p.userId));

          let share = 0;

          if (prizeSystem === "team_equal") {
            share = Math.round(prizePool / winnerPlayers.length);
          } else if (prizeSystem === "kill_based") {
            const totalKills = teamKills[winnerTeam] || 0;
            share = totalKills > 0
              ? Math.round((p.kills / totalKills) * prizePool)
              : Math.round(prizePool / winnerPlayers.length);
          }

          winners.push({
            ...p,
            avatarUrl: playerObj?.userId?.avatarUrl || null,
            uid: p.uid || playerObj?.uid || "-",
            name: p.name || playerObj?.userId?.name || "Unknown",
            phone: p.phone || playerObj?.userId?.phone || "-",
            wallet: playerObj?.userId?.wallet || 0,
            winningPrice: share
          });
        });
      }

      return {
        matchId: match._id,
        matchNumber: match.matchNumber,
        game: match.game,
        mode: match.mode,
        type: match.type,
        entryFee,
        prizeSystem,
        prizeGiven: prizePool,
        completedAt: match.updatedAt || match.createdAt,
        winners
      };
    });

    return res.json({ success: true, list: formatted });

  } catch (err) {
    console.error("fetch winners error:", err);
    return res.status(500).json({ success: false, msg: "Server error" });
  }
});

router.post("/admin/refresh-token", async (req, res) => {
  try {
    const oldToken = req.header("auth-token-admin");

    if (!oldToken) {
      return res.status(401).json({
        success: false,
        msg: "Admin token missing"
      });
    }

    // 🔓 Decode even if expired
    const payload = jwt.verify(oldToken, process.env.JWT_SECRET_ADMIN, {
      ignoreExpiration: true
    });

    // ✅ EXTRA SAFETY: check role
    if (payload.role !== "admin") {
      return res.status(403).json({
        success: false,
        msg: "Not an admin"
      });
    }

    // ✅ OPTIONAL BUT RECOMMENDED: verify admin still exists
    const admin = await User.findById(payload.id);
    if (!admin || admin.isAdmin !== true) {
      return res.status(401).json({
        success: false,
        msg: "Admin no longer valid"
      });
    }

    // 🔁 Issue new token
    const newToken = jwt.sign(
      {
        id: admin._id,
        role: "admin"
      },
      process.env.JWT_SECRET_ADMIN,
      {
        expiresIn: "24h" // admin stays short-lived (secure)
      }
    );

    res.json({
      success: true,
      token: newToken
    });

  } catch (err) {
    console.error("Admin refresh error:", err);
    res.status(401).json({
      success: false,
      msg: "refresh_failed"
    });
  }
});


router.get("/admin/refresh-token", (req, res) => {
  const oldToken = req.header("auth-token-admin");

  try {
    const payload = jwt.verify(oldToken, process.env.JWT_SECRET_ADMIN, {
      ignoreExpiration: true,
    });

    const newToken = jwt.sign(
      { id: payload.id, role: "admin" },
      process.env.JWT_SECRET_ADMIN,
      { expiresIn: "24h" }
    );

    res.json({ success: true, token: newToken });
  } catch (err) {
    res.status(401).json({ success: false, msg: "refresh_failed" });
  }
});

router.post("/join", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { game, type, mode, entryFee, uid, whatsappNumber } = req.body;

    // ---------------------------- VALIDATION ----------------------------
    if (!game || !type || !mode || !uid || !entryFee || !whatsappNumber) {
      return res.status(400).json({ success: false, msg: "Missing match data" });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(400).json({ success: false, msg: "User not found" });

    // ---------------------------- GAME RULES ----------------------------
    const GAME_RULES = {
      Ludo: { types: ["1v1", "1v2", "1v3", "2v2"], modes: ["classic", "popular", "quick"], slots: { "1v1": 2, "1v2": 3, "1v3": 4, "2v2": 4 } },
      Carrom: { types: ["1v1", "2v2"], modes: ["classic", "freestyle"], slots: { "1v1": 2, "2v2": 4 } },
      "8 Ball Pool": { types: ["1v1"], modes: ["classic"], slots: { "1v1": 2 } },
      Cricket: { types: ["1v1"], modes: ["1 over"], slots: { "1v1": 2 } },
    };

    const rules = GAME_RULES[game];
    if (!rules) return res.status(400).json({ success: false, msg: "Invalid game" });
    if (!rules.types.includes(type)) return res.status(400).json({ success: false, msg: "Invalid match type" });
    if (!rules.modes.includes(mode)) return res.status(400).json({ success: false, msg: "Invalid mode" });

    const totalSlots = rules.slots[type];

    // ---------------------------- CHECK USER ACTIVE MATCH ----------------------------
    const activeMatch = await QuickMatch.findOne({
      "players.userId": userId,
      status: { $in: ["waiting", "filled", "ongoing"] },
    });

    if (activeMatch) {
      return res.status(400).json({
        success: false,
        msg: "⚠️ You already have an active match. Complete it first.",
      });
    }

    // ---------------------------- WALLET CHECK ----------------------------
    let wallet = await Wallet.findOne({ userId });
    if (!wallet) wallet = new Wallet({ userId, balance: 0 });
    if (wallet.balance < entryFee) return res.status(400).json({ success: false, msg: "❌ Not enough balance" });

    wallet.balance -= entryFee;
    await wallet.save();

    await Transaction.create({
      userId,
      amount: entryFee,
      type: "debit",
      purpose: "Quick Match Join",
      balanceAfter: wallet.balance,
      createdAt: new Date(),
    });

    // ---------------------------- FIND OR CREATE MATCH ----------------------------
    let match = await QuickMatch.findOne({
      game,
      type,
      mode,
      entryFee,
      status: "waiting",
      "players.0": { $exists: true } // has players
    });

    // If no waiting match or waiting match is full, create new
    if (!match || match.players.length >= totalSlots) {
      match = new QuickMatch({
        game,
        type,
        mode,
        entryFee,
        status: "waiting",
        players: [],
        slots: [],
      });
    }

    // ---------------------------- ADD USER TO MATCH ----------------------------
    match.slots.push({
      uid,
      userId,
      phone: user.phone,
      whatsappNumber,
      joinedAt: new Date(),
      team: null,
    });

    match.players.push({
      userId,
      uid,
      name: user.name,
      phone: user.phone,
      team: null,
      joinedAt: new Date(),
    });

    // Keep as waiting until admin pairs
    if (match.players.length === totalSlots) match.status = "waiting";

    await match.save();

    // ---------------------------- SUCCESS RESPONSE ----------------------------
    res.json({
      success: true,
      msg: "Joined match successfully",
      walletBalance: wallet.balance,
      matchId: match._id,
      redirectUrl: `user-room.html?matchId=${match._id}`,
    });

  } catch (err) {
    console.error("Join error:", err);
    res.status(500).json({ success: false, msg: "Internal server error" });
  }
});





// Get active matches for ANY game (Ludo, Carrom, Chess, Pool, Cricket)
router.get("/active-matches", auth, async (req, res) => {
  try {
    const userId = req.user.id;

    // 1️⃣ Query user's active matches
    const query = {
      status: { $nin: ["completed"] },
      $or: [
        { "players.userId": userId },
        { "slots.userId": userId }
      ]
    };

    // 2️⃣ fetch + populate
    const match = await QuickMatch.findOne(query)
      .populate("players.userId", "name phone avatarUrl wallet")
      .populate("slots.userId", "name phone avatarUrl wallet")
      .select("type game mode entryFee status players slots createdAt matchNumber prizeSystem")
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    if (!match) {
      return res.json({
        success: true,
        data: null
      });
    }

    // 3️⃣ find user inside match
    const inPlayers = match.players?.find(p => String(p.userId?._id) === String(userId));
    const inSlots = match.slots?.find(s => String(s.userId?._id) === String(userId));
    const userData = inPlayers || inSlots;

    // 4️⃣ hide prize system for non-prize games
    const NON_PRIZE_GAMES = ["Ludo", "Carrom", "8 Ball Pool", "Cricket"];
    let prizeSystemToSend = NON_PRIZE_GAMES.includes(match.game)
      ? null
      : match.prizeSystem;

    // 5️⃣ formatted list - NOW ALWAYS SHOW PLAYER NAMES
    const formattedPlayers =
      match.players?.map(p => ({
        userId: p.userId?._id || null,
        uid: p.uid || null,
        name: p.userId?.name || p.name || "Unknown",
        phone: p.userId?.phone || null,
        avatarUrl: p.userId?.avatarUrl || null,
        team: p.team || null
      })) || [];

    const formattedSlots =
      match.slots?.map(s => ({
        userId: s.userId?._id || null,
        uid: s.uid || null,
        name: s.userId?.name || "Unknown",
        phone: s.userId?.phone || null,
        avatarUrl: s.userId?.avatarUrl || null,
        whatsappNumber: s.whatsappNumber || null,
        team: s.team || null
      })) || [];

    // 6️⃣ final response
    const formatted = {
      _id: match._id,
      matchNumber: match.matchNumber,
      type: match.type,
      game: match.game,
      mode: match.mode,
      entryFee: match.entryFee,
      status: match.status,
      createdAt: match.createdAt,
      prizeSystem: prizeSystemToSend,

      team: userData?.team || null,
      joinedAt: userData?.joinedAt || match.createdAt,

      players: formattedPlayers,
      slots: formattedSlots
    };

    return res.json({
      success: true,
      data: formatted
    });

  } catch (err) {
    console.error("Active match error:", err);
    return res.status(500).json({ success: false, msg: "Internal server error" });
  }
});



// Get active matches for ANY game (Ludo, Carrom, Chess, Pool, Cricket)

router.get("/my-actives", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const game = req.query.game; // optional game filter

    // Build query
    const query = {
      status: { $nin: ["completed"] }, // not completed
      $or: [
        { "players.userId": userId },
        { "slots.userId": userId } // in case your slots array is used
      ]
    };
    if (game) query.game = game;

    const activeMatches = await QuickMatch.find(query)
      .select("type game mode entryFee status players slots createdAt matchNumber prizeSystem")
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    const formatted = activeMatches.map(m => {
      // Find the user in either players or slots
      const player = m.players.find(p => String(p.userId) === String(userId)) ||
                     m.slots.find(s => String(s.userId) === String(userId));

      return {
        _id: m._id,
        matchNumber: m.matchNumber || null,
        game: m.game,
        type: m.type,
        mode: m.mode,
        entryFee: m.entryFee,
        prizeSystem: m.prizeSystem || null,
        status: m.status,
        team: player?.team || null,
        joinedAt: player?.joinedAt || m.createdAt,
        players: m.players.map(p => ({
          uid: p.uid,
          name: p.name,
          team: p.team || null
        })),
        slots: m.slots.map(s => ({
          uid: s.uid,
          whatsappNumber: s.whatsappNumber,
          team: s.team || null
        }))
      };
    });

    return res.json({ success: true, data: formatted });

  } catch (err) {
    console.error("Error in /my-active:", err);
    return res.status(500).json({ success: false, msg: "Internal server error" });
  }
});



// Get active matches for ANY game (Ludo, Carrom, Chess, Pool, Cricket)
router.get("/my-active", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const game = req.query.game; // dynamic game input

    if (!game) {
      return res.status(400).json({ success: false, msg: "Game is required" });
    }

    // Find matches for the given game that are not completed
    const activeMatches = await QuickMatch.find({
      game,
      "players.userId": userId,
      status: { $nin: ["completed"] }
    })
      .select("type game mode entryFee status players createdAt matchNumber prizeSystem")
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    const formatted = activeMatches.map(m => {
      const player = m.players.find(p => String(p.userId) === String(userId));

      return {
        _id: m._id,
        matchNumber: m.matchNumber || null,
        game: m.game,
        type: m.type,
        mode: m.mode,
        entryFee: m.entryFee,
        prizeSystem: m.prizeSystem || null,
        status: m.status,
        team: player?.team || null,
        createdAt: m.createdAt,
        players: m.players.map(p => ({
          uid: p.uid,
          name: p.name,
          team: p.team || null
        }))
      };
    });

    return res.json({ success: true, data: formatted });

  } catch (err) {
    console.error("Error in /my-active:", err);
    return res.status(500).json({ success: false, msg: "Internal server error" });
  }
});

router.get("/match/all", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find().sort({ createdAt: -1 });

    // Collect all unique userIds from all matches
    const userIds = matches.flatMap(match =>
      match.slots.map(slot => slot.userId).filter(Boolean)
    );

    // Fetch all user details once
    const users = await User.find({ _id: { $in: userIds } }).lean();
    const userMap = {};
    users.forEach(u => {
      userMap[u._id.toString()] = u;
    });

    const allJoined = matches.flatMap(match => {
      const totalSlots = match.slots.length;

      return match.slots.map((slot, idx) => {
        const user = slot.userId ? userMap[slot.userId.toString()] : null;

        return {
          // ------------------------
          // MATCH DETAILS
          // ------------------------
          matchId: match._id,
          matchNumber: match.matchNumber || null,
          game: match.game,
          mode: match.mode,
          type: match.type,
          entryFee: match.entryFee,
          status: match.status,
          joinedAt: slot.joinedAt || match.createdAt,

          // ------------------------
          // PLAYER DETAILS
          // ------------------------
          userId: slot.userId || null,
          uid: slot.uid || "N/A",
          name: slot.name || (user ? user.name : "Unknown"),
          phone: slot.phone || (user ? user.phone : "N/A"),
          whatsapp: slot.whatsappNumber || (user ? user.whatsappNumber : "N/A"),

          // User wallet & avatar
          wallet: user?.wallet || 0,
          avatarUrl: user?.avatarUrl || null,

          // ------------------------
          // TEAM LOGIC
          // ------------------------
          team: slot.team || (idx < totalSlots / 2 ? "LION" : "TIGER")
        };
      });
    });

    res.json({
      success: true,
      count: allJoined.length,
      data: allJoined
    });

  } catch (err) {
    console.error("Match fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// GET UNPAIRED / WAITING MATCHES
// ----------------------------


router.get("/match/unpaired", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find({ status: "waiting" })
      .populate("slots.userId", "name phone wallet avatarUrl")
      .sort({ createdAt: -1 })
      .limit(300);

    const result = matches.flatMap(match => {
      const totalSlots = match.slots.length;
      return match.slots.map((slot, idx) => ({
        matchId: match._id,
        matchNumber: match.matchNumber,
        userId: slot.userId?._id || null,
        uid: slot.uid || "N/A",
        name: slot.userId?.name || "Unknown",
        phone: slot.phone || slot.userId?.phone || "N/A",
        whatsapp: slot.whatsappNumber || "N/A",
        wallet: slot.userId?.wallet || 0,
        avatarUrl: slot.userId?.avatarUrl || null,
        game: match.game,
        mode: match.mode,
        type: match.type,
        entryFee: match.entryFee,
        joinedAt: slot.joinedAt || match.createdAt,
        status: match.status,
        team: slot.team || (idx < totalSlots / 2 ? "LION" : "TIGER")
      }));
    });

    res.json({ success: true, count: result.length, data: result });
  } catch (err) {
    console.error("Unpaired match fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ----------------------------
// GET PAIRED / ONGOING / COMPLETED MATCHES
// ----------------------------
router.get("/match/paired", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find().sort({ createdAt: -1 })
      .limit(300);

    const userIds = matches.flatMap(match =>
      match.slots.map(s => s.userId).filter(Boolean)
    );

    const users = await User.find({ _id: { $in: userIds } }).lean();
    const userMap = {};
    users.forEach(u => userMap[u._id.toString()] = u);

    const paired = matches.flatMap(match => {
      return match.slots
        .filter(s => s.team) // only paired members
        .map((slot, idx) => {
          const user = userMap[slot.userId?.toString()] || null;

          return {
            matchId: match._id,
            game: match.game,
            type: match.type,
            mode: match.mode,
            entryFee: match.entryFee,
            status: match.status,

            userId: slot.userId,
            uid: slot.uid,
            name: slot.name || user?.name || "Unknown",
            phone: slot.phone || user?.phone || "N/A",
            whatsapp: slot.whatsappNumber || user?.whatsappNumber || "N/A",
            wallet: user?.wallet || 0,
            avatarUrl: user?.avatarUrl || null,

            team: slot.team
          };
        });
    });

    res.json({ success: true, count: paired.length, data: paired });

  } catch (err) {
    console.error("Paired fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});


router.get("/match/paired", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find({ status: "filled" }).sort({ createdAt: -1 })
      .limit(300);

    const userIds = matches.flatMap(m =>
      m.players.map(p => p.userId).filter(Boolean)
    );

    const users = await User.find({ _id: { $in: userIds } }).lean();
    const userMap = {};
    users.forEach(u => userMap[u._id.toString()] = u);

    const pairedList = matches.flatMap(match =>
      match.players.map(player => {
        const u = userMap[player.userId?.toString()] || null;

        return {
          matchId: match._id,
          matchNumber: match.matchNumber || null,
          game: match.game,
          mode: match.mode,
          type: match.type,
          entryFee: match.entryFee,
          status: match.status,

          userId: player.userId || null,
          uid: player.uid || "N/A",
          name: player.name || u?.name || "Unknown",
          phone: player.phone || u?.phone || "N/A",
          whatsapp: player.whatsappNumber || u?.whatsappNumber || "N/A",
          wallet: u?.wallet || 0,
          avatarUrl: u?.avatarUrl || null,
          team: player.team || "N/A",
          pairedAt: player.joinedAt
        };
      })
    );

    res.json({ success: true, count: pairedList.length, data: pairedList });

  } catch (err) {
    console.error("Paired fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});


router.get("/match/paired", authAdmin, async (req, res) => {
  try {
    const matches = await QuickMatch.find({ status: { $in: ["filled", "ongoing", "completed"] } })
      .populate("slots.userId", "name phone wallet avatarUrl")
      .sort({ createdAt: -1 })
      .limit(300);

    const result = matches.flatMap(match => {
      const totalSlots = match.slots.length;
      return match.slots.map((slot, idx) => ({
        matchId: match._id,
        matchNumber: match.matchNumber || "N/A",
        userId: slot.userId?._id || null,
        uid: slot.uid || "N/A",
        name: slot.userId?.name || "Unknown",
        phone: slot.phone || slot.userId?.phone || "N/A",
        whatsapp: slot.whatsappNumber || "N/A",
        wallet: slot.userId?.wallet || 0,
        avatarUrl: slot.userId?.avatarUrl || null,
        game: match.game,
        mode: match.mode,
        type: match.type,
        entryFee: match.entryFee,
        joinedAt: slot.joinedAt || match.createdAt,
        status: match.status,
        team: slot.team || (idx < totalSlots / 2 ? "LION" : "TIGER")
      }));
    });

    res.json({ success: true, count: result.length, data: result });
  } catch (err) {
    console.error("Paired match fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ----------------------------
// PAIR SELECTED MEMBERS INTO MATCH
// ----------------------------
router.post("/match/pair", authAdmin, async (req, res) => {
  try {
    const { selectedMembers, game, type, mode, entryFee } = req.body;

    if (!Array.isArray(selectedMembers) || selectedMembers.length === 0) {
      return res.status(400).json({ success: false, msg: "No members selected" });
    }

    // NO auto pairing — selectedMembers directly used!
    const slotsArr = selectedMembers.map(p => ({
      userId: p.userId ? new mongoose.Types.ObjectId(p.userId) : null,
      uid: p.uid,
      phone: p.phone || "Unknown",
      whatsappNumber: p.whatsapp || "N/A",
      team: p.team || null,    // ⭐ Admin decides team manually
      joinedAt: new Date()
    }));

    // Create only ONE match — no auto grouping
    const newMatch = new QuickMatch({
      type,
      game,
      mode,
      entryFee,
      slots: slotsArr,
      status: "paired"
    });

    await newMatch.save();

    return res.json({
      success: true,
      msg: "Match created successfully",
      data: newMatch
    });

  } catch (err) {
    console.error("Pair match error:", err);
    return res.status(500).json({ success: false, msg: "Server error" });
  }
});

// ================================
// DELETE — CLEAR ALL UNPAIRED PLAYERS (WAITING MATCHES)
router.delete("/match/all", authAdmin, async (req, res) => {
  try {
    const result = await QuickMatch.deleteMany({});
    res.json({
      success: true,
      msg: `Deleted ${result.deletedCount} matches`
    });
  } catch (err) {
    console.error("Delete ALL matches error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});
router.delete("/match/unpaired", authAdmin, async (req, res) => {
  try {
    const result = await QuickMatch.deleteMany({ status: "waiting" });

    res.json({
      success: true,
      msg: `Deleted ${result.deletedCount} unpaired match(es)`
    });
  } catch (err) {
    console.error("Delete unpaired error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});
router.delete("/match/paired", authAdmin, async (req, res) => {
  try {
    const result = await QuickMatch.deleteMany({
      status: { $in: ["filled", "ongoing", "completed"] }
    });

    res.json({
      success: true,
      msg: `Deleted ${result.deletedCount} paired match(es)`
    });
  } catch (err) {
    console.error("Delete paired error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});
router.delete("/match/unpaired/players", authAdmin, async (req, res) => {
  try {
    const result = await QuickMatch.updateMany(
      { status: "waiting" },
      { $set: { slots: [] } }
    );

    res.json({
      success: true,
      msg: `Cleared slots from ${result.modifiedCount} unpaired match(es)`
    });
  } catch (err) {
    console.error("Delete unpaired players error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});
router.delete("/match/paired/players", authAdmin, async (req, res) => {
  try {
    const result = await QuickMatch.updateMany(
      { status: { $in: ["filled", "ongoing", "completed"] } },
      { $set: { slots: [] } }
    );

    res.json({
      success: true,
      msg: `Cleared slots from ${result.modifiedCount} paired match(es)`
    });
  } catch (err) {
    console.error("Delete paired players error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});
router.delete("/match/:matchId", authAdmin, async (req, res) => {
  try {
    const result = await QuickMatch.deleteOne({ _id: req.params.matchId });

    if (!result.deletedCount)
      return res.status(404).json({ success: false, msg: "Match not found" });

    res.json({ success: true, msg: "Match deleted successfully" });
  } catch (err) {
    console.error("Delete single match error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});
router.delete("/match/player/:matchId/:userId", authAdmin, async (req, res) => {
  try {
    const { matchId, userId } = req.params;

    const match = await QuickMatch.findById(matchId);
    if (!match)
      return res.status(404).json({ success: false, msg: "Match not found" });

    const before = match.slots.length;

    match.slots = match.slots.filter(s => s.userId?.toString() !== userId);
    await match.save();

    res.json({
      success: true,
      msg: `Removed ${before - match.slots.length} player(s)`
    });
  } catch (err) {
    console.error("Delete slot player error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// GET SINGLE MATCH
// ----------------------------
// GET /history  — returns authenticated user's history (matches + tournaments)
// USER HISTORY ROUTE


// POST - make public
router.get("/payment-config", async (req, res) => {
  try {
    const config = await PaymentConfig.findOne();
    res.json({
      success: true,
      config: config || { upiId: "yourupi@upi", qrImage: "default.png" },
    });
  } catch (err) {
    console.error("Payment config fetch error:", err);
    res.status(500).json({ success: false, msg: "Server error", error: err.message });
  }
});

// ----------------------
// POST Payment Config
// ----------------------
router.post("/payment-config", authAdmin, upload.single("qrImage"), async (req, res) => {
  try {
    const { upiId } = req.body;
    const qrImage = req.file ? req.file.filename : null;

    let config = await PaymentConfig.findOne();
    if (!config) config = new PaymentConfig({});

    if (upiId) config.upiId = upiId;
    if (qrImage) config.qrImage = qrImage;

    await config.save();

    res.json({
      success: true,
      msg: "Payment config updated successfully",
      config,
    });
  } catch (err) {
    console.error("Payment config update error:", err);
    res.status(500).json({ success: false, msg: "Server error", error: err.message });
  }
});



module.exports = router;



