'use strict';
/**
 * db/db.js
 * MongoDB Atlas data layer via Mongoose.
 * Exposes synchronous-style interfaces (Users, OTPs) that match
 * the rest of the auth routes — but internally uses Mongoose models.
 *
 * SETUP:
 *  1. npm install mongoose
 *  2. Set MONGODB_URI in your environment / Render env vars, e.g.:
 *     mongodb+srv://<user>:<pass>@cluster0.xxxxx.mongodb.net/pepetahigh?retryWrites=true&w=majority
 */

const mongoose = require('mongoose');

// ── Connection ────────────────────────────────────────────────────────
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('[db] MONGODB_URI environment variable is not set!');
  process.exit(1);
}

mongoose.connect(MONGODB_URI)
  .then(() => console.log('[db] Connected to MongoDB Atlas'))
  .catch(err => { console.error('[db] Connection error:', err); process.exit(1); });

// ── Schemas & Models ──────────────────────────────────────────────────

// User
const userSchema = new mongoose.Schema({
  id           : { type: String, required: true, unique: true },
  // Stored in lowercase for fast, index-friendly lookups.
  // Use displayUsername if you want to preserve original casing for display.
  username     : { type: String, required: true, unique: true },
  phone        : { type: String, required: true, unique: true },  // used at registration / OTP only
  passwordHash : { type: String, required: true },
  verified     : { type: Boolean, default: false },
  verifiedAt   : { type: Number, default: null },
  wallet       : { type: Number, default: 0 },
  demoBalance  : { type: Number, default: 10000 },
  createdAt    : { type: Number, default: () => Date.now() },
  lastLoginAt  : { type: Number, default: null },
  referredBy   : { type: String, default: null }
}, { versionKey: false });

const UserModel = mongoose.model('User', userSchema);

// OTP
const otpSchema = new mongoose.Schema({
  phone    : { type: String, required: true },
  purpose  : { type: String, required: true, enum: ['register', 'login'] },
  code     : { type: String, required: true },
  expiresAt: { type: Number, required: true },
  attempts : { type: Number, default: 0 }
}, { versionKey: false });

// Compound unique index: one OTP per phone+purpose at a time
otpSchema.index({ phone: 1, purpose: 1 }, { unique: true });

// TTL index — MongoDB will auto-delete expired docs (best-effort, ~60s lag)
otpSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 }
);

const OTPModel = mongoose.model('OTP', otpSchema);

// ── Helper: convert Mongoose doc → plain object ───────────────────────
function toPlain(doc) {
  if (!doc) return null;
  const obj = doc.toObject ? doc.toObject() : { ...doc };
  delete obj._id;
  return obj;
}

// ─────────────────────────────────────────────────────────────────────
// Users API
// All methods are async — auth routes already use await.
// ─────────────────────────────────────────────────────────────────────
const Users = {
  /**
   * Find user by username.
   * Lowercases the input so the query hits the index directly —
   * no regex scan, sub-50ms lookup regardless of collection size.
   */
  async findByUsername(username) {
    const doc = await UserModel.findOne({
      username: username.toLowerCase()   // exact match → uses index ✅
    }).lean();
    return doc ? (({ _id, ...rest }) => rest)(doc) : null;
  },

  /**
   * Find user by normalized phone number.
   * Used during registration / OTP flows only — NOT during login.
   */
  async findByPhone(phone) {
    const doc = await UserModel.findOne({ phone }).lean();
    return doc ? (({ _id, ...rest }) => rest)(doc) : null;
  },

  /**
   * Find user by their UUID id field.
   */
  async findById(id) {
    const doc = await UserModel.findOne({ id }).lean();
    return doc ? (({ _id, ...rest }) => rest)(doc) : null;
  },

  /**
   * Create a new user document.
   * Username is normalized to lowercase before saving so that
   * findByUsername() can always do a fast exact-match index lookup.
   *
   * @param {object} data  — must include id, username, phone, passwordHash
   * Returns the created plain object.
   */
  async create(data) {
    const doc = await UserModel.create({
      ...data,
      username: data.username.toLowerCase()  // normalize on save ✅
    });
    return toPlain(doc);
  },

  /**
   * Update fields on a user by their UUID id.
   * @param {string} id
   * @param {object} fields  — partial update fields
   */
  async update(id, fields) {
    // If username is being updated, keep it lowercase.
    if (fields.username) {
      fields.username = fields.username.toLowerCase();
    }
    await UserModel.updateOne({ id }, { $set: fields });
  }
};

// ─────────────────────────────────────────────────────────────────────
// OTPs API
// ─────────────────────────────────────────────────────────────────────
const OTPs = {
  /**
   * Find an OTP record by phone + purpose.
   */
  async find(phone, purpose) {
    const doc = await OTPModel.findOne({ phone, purpose }).lean();
    return doc ? (({ _id, ...rest }) => rest)(doc) : null;
  },

  /**
   * Insert or replace an OTP record (upsert).
   */
  async upsert(phone, code, expiresAt, purpose) {
    await OTPModel.findOneAndUpdate(
      { phone, purpose },
      { phone, code, expiresAt, purpose, attempts: 0 },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
  },

  /**
   * Delete an OTP record.
   */
  async delete(phone, purpose) {
    await OTPModel.deleteOne({ phone, purpose });
  },

  /**
   * Increment the failed-attempt counter.
   */
  async incrementAttempts(phone, purpose) {
    await OTPModel.updateOne({ phone, purpose }, { $inc: { attempts: 1 } });
  },

  /**
   * Remove all expired OTP records (called on a timer in auth routes).
   */
  async purgeExpired() {
    const result = await OTPModel.deleteMany({ expiresAt: { $lt: Date.now() } });
    if (result.deletedCount > 0)
      console.log(`[db] Purged ${result.deletedCount} expired OTP(s)`);
  }
};

// ── Export ────────────────────────────────────────────────────────────
module.exports = { Users, OTPs, mongoose };
