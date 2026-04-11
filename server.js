'use strict';
/**
 * PepetaHigh — server.js  (main backend)
 * ─────────────────────────────────────────────────────────────────────
 * Changes from previous version:
 *   + POST /api/wallet/debit  — called by game-server to deduct a bet
 *   + POST /api/wallet/credit — called by game-server to pay a win
 *   Both are protected by GAME_SERVER_SECRET (server-to-server only).
 *
 * New ENV VAR needed on Render:
 *   GAME_SERVER_SECRET=<same value you put in game-server's .env>
 */

require('dotenv').config();

const express  = require('express');
const cors     = require('cors');
const axios    = require('axios');
const mongoose = require('mongoose');

// ── DB connection ──────────────────────────────────────────────────────
const { Users } = require('./db/db');

const app = express();

// ── CORS ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: [
    'https://pepetahigh.com',
    'http://localhost:3000',
    'http://127.0.0.1:5500'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.options('*', cors());
app.use(express.json());

// ── Auth routes ────────────────────────────────────────────────────────
app.use('/api/auth', require('./routes/auth'));

// ── Health check ───────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

/* ─────────────────────────────────────────────
   🗄️  PAYMENT SCHEMA (MongoDB)
───────────────────────────────────────────── */
const paymentSchema = new mongoose.Schema({
  reference : { type: String, required: true, unique: true },
  status    : { type: String, default: 'pending' },
  amount    : { type: Number, required: true },
  phone     : { type: String, required: true },
  userId    : { type: String, required: true },
  mpesaRef  : { type: String, default: null },
}, { timestamps: true });

const Payment = mongoose.models.Payment || mongoose.model('Payment', paymentSchema);

/* ─────────────────────────────────────────────
   💰  WALLET ROUTES
───────────────────────────────────────────── */

// GET /api/wallet/:username  — frontend reads current balance
app.get('/api/wallet/:username', async (req, res) => {
  try {
    const user = await Users.findByUsername(req.params.username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ wallet: user.wallet });
  } catch (err) {
    console.error('[wallet]', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Internal helper used by PayHero callback only ─────────────────────
async function _creditWalletByUsername(username, amount) {
  try {
    const user = await Users.findByUsername(username);
    if (!user) { console.warn('[creditWallet] User not found:', username); return; }
    await Users.update(user.id, { wallet: (user.wallet || 0) + amount });
    console.log(`[wallet] Credited ${amount} to ${username}.`);
  } catch (err) {
    console.error('[creditWallet] Error:', err);
  }
}

// ── Middleware: verify GAME_SERVER_SECRET ─────────────────────────────
// This is what stops random people from calling /debit or /credit.
// Only the game-server knows this secret, so only it can move money.
function requireGameSecret(req, res, next) {
  const secret = process.env.GAME_SERVER_SECRET;
  if (!secret) {
    console.error('[game-secret] GAME_SERVER_SECRET env var is not set!');
    return res.status(500).json({ error: 'Server misconfigured' });
  }
  if (req.body.secret !== secret) {
    console.warn('[game-secret] Invalid secret from', req.ip);
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// POST /api/wallet/debit
// Called by game-server BEFORE accepting a bet — deducts the stake.
// Body: { userId, amount, game, secret }
// Returns: { ok: true, wallet: <new balance> }
app.post('/api/wallet/debit', requireGameSecret, async (req, res) => {
  const { userId, amount, game } = req.body;
  if (!userId || !amount || amount <= 0)
    return res.status(400).json({ error: 'Invalid debit request' });

  try {
    const user = await Users.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.wallet < amount)
      return res.status(400).json({ error: 'Insufficient balance', wallet: user.wallet });

    const newBalance = parseFloat((user.wallet - amount).toFixed(2));
    await Users.update(userId, { wallet: newBalance });

    console.log(`[wallet/debit]  ${user.username}  -${amount}  (${game})  →  ${newBalance}`);
    res.json({ ok: true, wallet: newBalance });
  } catch (err) {
    console.error('[wallet/debit]', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/wallet/credit
// Called by game-server after a win — adds the payout.
// Body: { userId, amount, game, reason, secret }
// Returns: { ok: true, wallet: <new balance> }
app.post('/api/wallet/credit', requireGameSecret, async (req, res) => {
  const { userId, amount, game, reason } = req.body;
  if (!userId || !amount || amount <= 0)
    return res.status(400).json({ error: 'Invalid credit request' });

  try {
    const user = await Users.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const newBalance = parseFloat((user.wallet + amount).toFixed(2));
    await Users.update(userId, { wallet: newBalance });

    console.log(`[wallet/credit] ${user.username}  +${amount}  (${game}: ${reason})  →  ${newBalance}`);
    res.json({ ok: true, wallet: newBalance });
  } catch (err) {
    console.error('[wallet/credit]', err);
    res.status(500).json({ error: 'Server error' });
  }
});


/* ─────────────────────────────────────────────
   💳  PAYHERO / M-PESA
───────────────────────────────────────────── */
const PAYHERO_CHANNEL_ID   = process.env.PAYHERO_CHANNEL_ID;
const PAYHERO_CALLBACK_URL = process.env.PAYHERO_CALLBACK_URL;
const PAYHERO_AUTH_TOKEN   = process.env.PAYHERO_AUTH_TOKEN?.replace(/[\r\n\s]+/g, '').trim();
const PORT                 = process.env.PORT || 3001;

// STK Push
app.post('/api/deposit/stk', async (req, res) => {
  console.log('[stk-push] token defined:', !!PAYHERO_AUTH_TOKEN, 'length:', PAYHERO_AUTH_TOKEN?.length);
  console.log('[stk-push] channel:', PAYHERO_CHANNEL_ID, 'callback:', PAYHERO_CALLBACK_URL);
  const { phone, amount, userId } = req.body;
// TO
  if (!phone || !amount || amount < 200)
    return res.status(400).json({ error: 'Invalid request. Minimum deposit is KES 200.' });

  try {
    const payload = {
      amount            : Math.round(amount),
      phone_number      : phone,
      channel_id        : PAYHERO_CHANNEL_ID,
      provider          : 'm-pesa',
      external_reference: userId,
      callback_url      : PAYHERO_CALLBACK_URL
    };
    console.log('[stk-push] auth:', PAYHERO_AUTH_TOKEN?.substring(0,10), 'channel:', PAYHERO_CHANNEL_ID, 'payload:', JSON.stringify(payload));
    const response = await axios.post(
      'https://backend.payhero.co.ke/api/v2/payments',
      payload,
      { headers: { 'Authorization': `Basic ${PAYHERO_AUTH_TOKEN}`, 'Content-Type': 'application/json' } }
    );
    const reference = response.data.reference;
    await Payment.create({ reference, amount, phone, userId });
    res.json({ CheckoutRequestID: reference });
  } catch (err) {
    console.error('[stk-push]', err?.response?.data || err.message);
    res.status(500).json({ error: 'STK push failed. Please try again.' });
  }
});

// PayHero Callback
app.post('/api/deposit/callback', async (req, res) => {
  const { status, reference } = req.body;
  try {
    const p = await Payment.findOne({ reference });
    if (!p) return res.json({ success: true });
    if (status === 'SUCCESS') {
      p.status   = 'completed';
      p.mpesaRef = reference;
      await p.save();
      await _creditWalletByUsername(p.userId, p.amount);
      console.log(`[payhero] Payment completed. Ref: ${reference}`);
    } else {
      p.status = 'failed';
      await p.save();
      console.warn(`[payhero] Payment failed. Status: ${status}`);
    }
  } catch (err) {
    console.error('[callback] Error:', err);
  }
  res.json({ success: true });
});

// STK Status check
app.get('/api/deposit/status/:checkoutId', async (req, res) => {
  try {
    const p = await Payment.findOne({ reference: req.params.checkoutId });
    if (!p) return res.status(404).json({ error: 'Payment not found' });
    res.json({ status: p.status, mpesaRef: p.mpesaRef || null });
  } catch (err) {
    console.error('[status]', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ─────────────────────────────────────────────
   🚀  START
───────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`🚀 PepetaHigh server running on port ${PORT}`);
});
