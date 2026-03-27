'use strict';
/**
 * /api/auth routes
 *
 * POST /api/auth/register        — create account, send OTP
 * POST /api/auth/verify-otp      — verify OTP, activate account
 * POST /api/auth/resend-otp      — resend OTP (rate-limited)
 * POST /api/auth/login           — login with username + phone + password
 * POST /api/auth/login-otp       — request OTP-only login (passwordless option)
 * POST /api/auth/verify-login-otp— verify OTP for passwordless login
 * GET  /api/auth/me              — get current user profile (requires JWT)
 * POST /api/auth/logout          — (client-side; just returns success)
 */

const router    = require('express').Router();
const bcrypt    = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const { Users, OTPs }  = require('../db/db');
const { sendOTP }      = require('../services/sms');
const { signToken }    = require('../services/jwt');
const requireAuth      = require('../middleware/auth');

// ── Rate limits ────────────────────────────────────────────────────────
const otpLimit = rateLimit({
  windowMs    : 60 * 60 * 1000, // 1 hour
  max         : 5,
  // Key by phone number so the limit is per-number, not per-IP
  keyGenerator: (req) => (req.body?.phone ? String(req.body.phone).replace(/\s+/g,'') : req.ip),
  skip        : () => false,
  validate    : { xForwardedForHeader: false },
  message     : { error: 'Too many OTP requests. Try again in 1 hour.' }
});

const loginLimit = rateLimit({
  windowMs : 15 * 60 * 1000, // 15 min
  max      : 10,
  message  : { error: 'Too many login attempts. Wait 15 minutes.' }
});

// ── Helpers ────────────────────────────────────────────────────────────
function generateOTP()    { return String(Math.floor(100000 + Math.random() * 900000)); }
function normalizePhone(p){ p = String(p).trim().replace(/\s+/g,'');
  if (p.startsWith('0'))   return '+254' + p.slice(1);
  if (p.startsWith('254')) return '+' + p;
  if (p.startsWith('+'))   return p;
  return '+254' + p;
}
function safeUser(u)      { const {passwordHash:_, ...rest} = u; return rest; }

// ─────────────────────────────────────────────────────────────────────
// POST /api/auth/register
// Body: { username, phone, password }
// ─────────────────────────────────────────────────────────────────────
router.post('/register', otpLimit, async (req, res) => {
  try {
    let { username, phone, password } = req.body;

    // ── Validation ────────────────────────────────────────────────────
    if (!username || typeof username !== 'string')
      return res.status(400).json({ error: 'Username is required' });
    username = username.trim();
    if (!/^[a-zA-Z][a-zA-Z0-9_]{2,19}$/.test(username))
      return res.status(400).json({ error: 'Username must be 3–20 chars, start with a letter, letters/numbers/_ only' });

    if (!phone)
      return res.status(400).json({ error: 'Phone number is required' });
    phone = normalizePhone(phone);
    // Accept any Kenyan number: +254 followed by 9 digits
    if (!/^\+254\d{9}$/.test(phone))
      return res.status(400).json({ error: 'Enter a valid Kenyan phone number (Safaricom or Airtel)' });

    if (!password || typeof password !== 'string' || password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    // ── Uniqueness checks ─────────────────────────────────────────────
    if (Users.findByUsername(username))
      return res.status(409).json({ error: 'Username already taken' });
    if (Users.findByPhone(phone))
      return res.status(409).json({ error: 'This phone number is already registered' });

    // ── Hash password & create unverified user ────────────────────────
    const passwordHash = await bcrypt.hash(password, 12);
    const user = Users.create({
      id           : uuidv4(),
      username,
      phone,
      passwordHash,
      verified     : false,
      wallet       : 0,
      demoBalance  : 10000,
      createdAt    : Date.now(),
      lastLoginAt  : null,
      referredBy   : req.body.referredBy || null
    });

    // ── Generate & store OTP ──────────────────────────────────────────
    const code      = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    OTPs.upsert(phone, code, expiresAt, 'register');

    // ── Send SMS ──────────────────────────────────────────────────────
    const smsResult = await sendOTP(phone, code, 'register');
    if (!smsResult.success) {
      // Don't block registration — just warn. User can resend.
      console.warn('[register] SMS failed for', phone, ':', smsResult.error);
    }

    return res.status(201).json({
      message : 'Account created. Enter the 6-digit code sent to ' + phone,
      userId  : user.id,
      phone,
      smsSent : smsResult.success
    });

  } catch (err) {
    console.error('[register]', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─────────────────────────────────────────────────────────────────────
// POST /api/auth/verify-otp
// Body: { phone, code }
// ─────────────────────────────────────────────────────────────────────
router.post('/verify-otp', async (req, res) => {
  try {
    let { phone, code } = req.body;
    if (!phone || !code)
      return res.status(400).json({ error: 'Phone and code are required' });

    phone = normalizePhone(phone);
    code  = String(code).trim();

    const otpRecord = OTPs.find(phone, 'register');
    if (!otpRecord)
      return res.status(400).json({ error: 'No OTP found for this number. Request a new one.' });

    if (Date.now() > otpRecord.expiresAt) {
      OTPs.delete(phone, 'register');
      return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
    }

    if (otpRecord.attempts >= 5) {
      OTPs.delete(phone, 'register');
      return res.status(429).json({ error: 'Too many wrong attempts. Request a new code.' });
    }

    if (otpRecord.code !== code) {
      OTPs.incrementAttempts(phone, 'register');
      const left = 5 - (otpRecord.attempts + 1);
      return res.status(400).json({ error: `Wrong code. ${left} attempt${left!==1?'s':''} remaining.` });
    }

    // ── Verify user ───────────────────────────────────────────────────
    const user = Users.findByPhone(phone);
    if (!user) return res.status(404).json({ error: 'User not found' });

    Users.update(user.id, { verified: true, verifiedAt: Date.now() });
    OTPs.delete(phone, 'register');

    const token = signToken({ userId: user.id });

    return res.json({
      message : '✅ Phone verified! Welcome to PepetaHigh.',
      token,
      user    : safeUser({ ...user, verified: true })
    });

  } catch (err) {
    console.error('[verify-otp]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ─────────────────────────────────────────────────────────────────────
// POST /api/auth/resend-otp
// Body: { phone, purpose? }
// ─────────────────────────────────────────────────────────────────────
router.post('/resend-otp', otpLimit, async (req, res) => {
  try {
    let { phone, purpose = 'register' } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone is required' });
    phone = normalizePhone(phone);

    // Throttle: only allow resend if last OTP was sent >60s ago
    const existing = OTPs.find(phone, purpose);
    if (existing) {
      const age = Date.now() - (existing.expiresAt - (purpose === 'login' ? 5 : 10) * 60 * 1000);
      if (age < 60_000) {
        const wait = Math.ceil((60_000 - age) / 1000);
        return res.status(429).json({ error: `Please wait ${wait}s before requesting a new code.` });
      }
    }

    if (purpose === 'register') {
      const user = Users.findByPhone(phone);
      if (!user)    return res.status(404).json({ error: 'No account with this number.' });
      if (user.verified) return res.status(400).json({ error: 'Account already verified.' });
    }

    const code      = generateOTP();
    const expiresAt = Date.now() + (purpose === 'login' ? 5 : 10) * 60 * 1000;
    OTPs.upsert(phone, code, expiresAt, purpose);

    const smsResult = await sendOTP(phone, code, purpose);
    return res.json({
      message : 'New code sent to ' + phone,
      smsSent : smsResult.success
    });

  } catch (err) {
    console.error('[resend-otp]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ─────────────────────────────────────────────────────────────────────
// POST /api/auth/login
// Body: { username, phone, password }
// ─────────────────────────────────────────────────────────────────────
router.post('/login', loginLimit, async (req, res) => {
  try {
    let { username, phone, password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password is required' });

    let user;
    if (username) {
      user = Users.findByUsername(String(username).trim());
    } else if (phone) {
      user = Users.findByPhone(normalizePhone(phone));
    }

    if (!user)
      return res.status(401).json({ error: 'Invalid credentials' });

    if (!user.verified)
      return res.status(403).json({
        error   : 'Phone not verified. Please complete registration.',
        needsVerification: true,
        phone   : user.phone
      });

    const pwMatch = await bcrypt.compare(password, user.passwordHash);
    if (!pwMatch)
      return res.status(401).json({ error: 'Invalid credentials' });

    Users.update(user.id, { lastLoginAt: Date.now() });

    const token = signToken({ userId: user.id });
    return res.json({
      message : 'Welcome back, ' + user.username + '!',
      token,
      user    : safeUser(user)
    });

  } catch (err) {
    console.error('[login]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ─────────────────────────────────────────────────────────────────────
// POST /api/auth/login-otp  (passwordless — optional)
// Body: { phone }
// ─────────────────────────────────────────────────────────────────────
router.post('/login-otp', otpLimit, async (req, res) => {
  try {
    let { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone is required' });
    phone = normalizePhone(phone);

    const user = Users.findByPhone(phone);
    if (!user)
      return res.status(404).json({ error: 'No account found with this number.' });
    if (!user.verified)
      return res.status(403).json({ error: 'Account not verified yet.' });

    const code      = generateOTP();
    const expiresAt = Date.now() + 5 * 60 * 1000;
    OTPs.upsert(phone, code, expiresAt, 'login');

    const smsResult = await sendOTP(phone, code, 'login');
    return res.json({
      message : 'Login code sent to ' + phone,
      smsSent : smsResult.success
    });

  } catch (err) {
    console.error('[login-otp]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ─────────────────────────────────────────────────────────────────────
// POST /api/auth/verify-login-otp
// Body: { phone, code }
// ─────────────────────────────────────────────────────────────────────
router.post('/verify-login-otp', async (req, res) => {
  try {
    let { phone, code } = req.body;
    phone = normalizePhone(phone);
    code  = String(code || '').trim();

    const rec = OTPs.find(phone, 'login');
    if (!rec)           return res.status(400).json({ error: 'No OTP found. Request a new one.' });
    if (Date.now() > rec.expiresAt){ OTPs.delete(phone,'login'); return res.status(400).json({ error: 'OTP expired.' }); }
    if (rec.attempts >= 5){ OTPs.delete(phone,'login'); return res.status(429).json({ error: 'Too many attempts.' }); }
    if (rec.code !== code){ OTPs.incrementAttempts(phone,'login'); return res.status(400).json({ error: 'Wrong code.' }); }

    OTPs.delete(phone, 'login');
    const user = Users.findByPhone(phone);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    Users.update(user.id, { lastLoginAt: Date.now() });

    const token = signToken({ userId: user.id });
    return res.json({ message: 'Logged in!', token, user: safeUser(user) });

  } catch (err) {
    console.error('[verify-login-otp]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ─────────────────────────────────────────────────────────────────────
// GET /api/auth/me  (protected)
// ─────────────────────────────────────────────────────────────────────
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: safeUser(req.user) });
});

// ─────────────────────────────────────────────────────────────────────
// POST /api/auth/change-password  (protected)
// Body: { currentPassword, newPassword }
// ─────────────────────────────────────────────────────────────────────
router.post('/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: 'Both current and new password are required.' });
    if (newPassword.length < 6)
      return res.status(400).json({ error: 'New password must be at least 6 characters.' });

    const match = await bcrypt.compare(currentPassword, req.user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Current password is incorrect.' });

    const passwordHash = await bcrypt.hash(newPassword, 12);
    Users.update(req.user.id, { passwordHash });
    return res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    return res.status(500).json({ error: 'Server error.' });
  }
});

// Purge expired OTPs periodically
setInterval(() => OTPs.purgeExpired(), 5 * 60 * 1000);

module.exports = router;
