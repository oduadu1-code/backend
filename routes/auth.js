'use strict';
/**
 * routes/auth.js
 * Simple auth — no OTP, no SMS.
 * POST /api/auth/register
 * POST /api/auth/login
 * GET  /api/auth/me       (requires JWT)
 * POST /api/auth/change-password (requires JWT)
 */

const router    = require('express').Router();
const bcrypt    = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const { Users }     = require('../db/db');
const { signToken } = require('../services/jwt');
const requireAuth   = require('../middleware/auth');

// ── Rate limits ────────────────────────────────────────────────────────
const loginLimit = rateLimit({
  windowMs : 15 * 60 * 1000,
  max      : 10,
  message  : { error: 'Too many login attempts. Wait 15 minutes.' }
});

const registerLimit = rateLimit({
  windowMs : 60 * 60 * 1000,
  max      : 10,
  message  : { error: 'Too many registrations. Try again in 1 hour.' }
});

// ── Helpers ────────────────────────────────────────────────────────────
function normalizePhone(p) {
  p = String(p).trim().replace(/\s+/g, '');
  if (p.startsWith('0'))   return '+254' + p.slice(1);
  if (p.startsWith('254')) return '+' + p;
  if (p.startsWith('+'))   return p;
  return '+254' + p;
}

function safeUser(u) {
  const { passwordHash: _, ...rest } = u;
  return rest;
}

// ─────────────────────────────────────────────────────────────────────
// POST /api/auth/register
// Body: { username, phone, password }
// ─────────────────────────────────────────────────────────────────────
router.post('/register', registerLimit, async (req, res) => {
  try {
    let { username, phone, password } = req.body;

    // Validation
    if (!username || typeof username !== 'string')
      return res.status(400).json({ error: 'Username is required' });
    username = username.trim();
    if (!/^[a-zA-Z][a-zA-Z0-9_]{2,19}$/.test(username))
      return res.status(400).json({ error: 'Username must be 3–20 chars, start with a letter, letters/numbers/_ only' });

    if (!phone)
      return res.status(400).json({ error: 'Phone number is required' });
    phone = normalizePhone(phone);
    if (!/^\+254\d{9}$/.test(phone))
      return res.status(400).json({ error: 'Enter a valid Kenyan phone number' });

    if (!password || typeof password !== 'string' || password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    // Uniqueness checks
    if (await Users.findByUsername(username))
      return res.status(409).json({ error: 'Username already taken' });
    if (await Users.findByPhone(phone))
      return res.status(409).json({ error: 'Phone number already registered' });

    // Hash & create user
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await Users.create({
      id          : uuidv4(),
      username,
      phone,
      passwordHash,
      verified    : true, // auto-verified, no OTP needed
      wallet      : 0,
      demoBalance : 10000,
      createdAt   : Date.now(),
      lastLoginAt : null,
      referredBy  : req.body.referredBy || null
    });

    const token = signToken({ userId: user.id });

    return res.status(201).json({
      message : '✅ Account created! Welcome to PepetaHigh.',
      token,
      user    : safeUser(user)
    });

  } catch (err) {
    console.error('[register]', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─────────────────────────────────────────────────────────────────────
// POST /api/auth/login
// Body: { username, phone, password }  (username OR phone)
// ─────────────────────────────────────────────────────────────────────
router.post('/login', loginLimit, async (req, res) => {
  try {
    let { username, phone, password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password is required' });

    let user;
    if (username) {
      user = await Users.findByUsername(String(username).trim());
    } else if (phone) {
      user = await Users.findByPhone(normalizePhone(phone));
    } else {
      return res.status(400).json({ error: 'Username or phone is required' });
    }

    if (!user)
      return res.status(401).json({ error: 'Invalid credentials' });

    const pwMatch = await bcrypt.compare(password, user.passwordHash);
    if (!pwMatch)
      return res.status(401).json({ error: 'Invalid credentials' });

    await Users.update(user.id, { lastLoginAt: Date.now() });

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
    await Users.update(req.user.id, { passwordHash });
    return res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    return res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;