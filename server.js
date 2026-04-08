'use strict';
/**
 * PepetaHigh — server.js
 * Main entry point. SQLite has been removed; MongoDB Atlas is used via db/db.js.
 */

require('dotenv').config();

const express  = require('express');
const cors     = require('cors');
const axios    = require('axios');

// ── DB connection (Mongoose) — import early so it connects on startup ──
const { Users } = require('./db/db');

const app = express();

// ── Middleware ─────────────────────────────────────────────────────────
app.use(cors({
  origin      : ['https://pepetahigh.com', 'http://localhost:3000'],
  methods     : ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials : true
}));

// Explicitly handle preflight
app.options('*', cors());

// ── Auth routes (/api/auth/register, /login, /me, etc.) ───────────────
app.use('/api/auth', require('./routes/auth'));

// ── Health check ───────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

/* ─────────────────────────────────────────────
   💰 WALLET ROUTES
───────────────────────────────────────────── */

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

// Internal helper — credit a user's wallet after successful M-Pesa payment
async function creditWallet(username, amount) {
  try {
    const user = await Users.findByUsername(username);
    if (!user) { console.warn('[creditWallet] User not found:', username); return; }
    await Users.update(user.id, { wallet: (user.wallet || 0) + amount });
    console.log(`[wallet] Credited ${amount} to ${username}. New balance: ${user.wallet + amount}`);
  } catch (err) {
    console.error('[creditWallet] Error:', err);
  }
}

/* ─────────────────────────────────────────────
   💳 M-PESA
───────────────────────────────────────────── */

// In-memory map for pending STK push payments
// (Consider using MongoDB for this in production for persistence across restarts)
const payments = new Map();


const {
  PAYHERO_AUTH_TOKEN,
  PAYHERO_CHANNEL_ID,
  PAYHERO_CALLBACK_URL,
  PORT = 3001
} = process.env;

// ── STK Push ───────────────────────────────────────────────────────────
app.post('/api/deposit/stk', async (req, res) => {
  const { phone, amount, userId } = req.body;

  if (!phone || !amount || amount < 200)
    return res.status(400).json({ error: 'Invalid request. Minimum deposit is KES 200.' });

  try {
    const payload = {
      amount      : Math.round(amount),
      phone_number: phone,
      channel_id  : PAYHERO_CHANNEL_ID,
      provider    : 'm-pesa',
      external_ref: userId,
      callback_url: PAYHERO_CALLBACK_URL
    };

    const response = await axios.post(
      'https://backend.payhero.co.ke/api/v2/payments',
      payload,
      {
        headers: {
          'Authorization': PAYHERO_AUTH_TOKEN,
          'Content-Type' : 'application/json'
        }
      }
    );

    const reference = response.data.reference;
    payments.set(reference, { status: 'pending', amount, phone, userId, mpesaRef: null });

    res.json({ CheckoutRequestID: reference });

  } catch (err) {
    console.error('[stk-push]', err?.response?.data || err.message);
    res.status(500).json({ error: 'STK push failed. Please try again.' });
  }
});

// ── PayHero Callback ───────────────────────────────────────────────────
app.post('/api/deposit/callback', async (req, res) => {
  const { status, reference, external_ref } = req.body;

  const p = payments.get(reference);
  if (!p) return res.json({ success: true });

  if (status === 'SUCCESS') {
    p.status   = 'completed';
    p.mpesaRef = reference;
    await creditWallet(p.userId, p.amount);
    console.log(`[payhero] Payment completed. Ref: ${reference}`);
  } else {
    p.status = 'failed';
    console.warn(`[payhero] Payment failed. Status: ${status}`);
  }

  res.json({ success: true });
});

// ── STK Status check (optional polling endpoint) ───────────────────────
app.get('/api/deposit/status/:checkoutId', (req, res) => {
  const p = payments.get(req.params.checkoutId);
  if (!p) return res.status(404).json({ error: 'Payment not found' });
  res.json({ status: p.status, mpesaRef: p.mpesaRef || null });
});

/* ─────────────────────────────────────────────
   🚀 START
───────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`🚀 PepetaHigh server running on port ${PORT}`);
});
