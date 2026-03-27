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
  origin      : '*',
  methods     : ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

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
  MPESA_CONSUMER_KEY,
  MPESA_CONSUMER_SECRET,
  MPESA_SHORTCODE,
  MPESA_PASSKEY,
  MPESA_CALLBACK_URL,
  MPESA_ENV = 'sandbox',
  PORT      = 3001
} = process.env;

const MPESA_BASE = MPESA_ENV === 'production'
  ? 'https://api.safaricom.co.ke'
  : 'https://sandbox.safaricom.co.ke';

async function getMpesaToken() {
  const creds = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString('base64');
  const res   = await axios.get(`${MPESA_BASE}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${creds}` }
  });
  return res.data.access_token;
}

function stkPassword() {
  const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
  const raw       = `${MPESA_SHORTCODE}${MPESA_PASSKEY}${timestamp}`;
  return { password: Buffer.from(raw).toString('base64'), timestamp };
}

// ── STK Push ───────────────────────────────────────────────────────────
app.post('/api/deposit/stk', async (req, res) => {
  const { phone, amount, userId } = req.body;

  if (!phone || !amount || amount < 200)
    return res.status(400).json({ error: 'Invalid request. Minimum deposit is KES 200.' });

  try {
    const token                  = await getMpesaToken();
    const { password, timestamp} = stkPassword();

    const payload = {
      BusinessShortCode: MPESA_SHORTCODE,
      Password         : password,
      Timestamp        : timestamp,
      TransactionType  : 'CustomerPayBillOnline',
      Amount           : Math.round(amount),
      PartyA           : phone,
      PartyB           : MPESA_SHORTCODE,
      PhoneNumber      : phone,
      CallBackURL      : MPESA_CALLBACK_URL,
      AccountReference : userId,
      TransactionDesc  : 'PepetaHigh Deposit'
    };

    const stk        = await axios.post(
      `${MPESA_BASE}/mpesa/stkpush/v1/processrequest`,
      payload,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const checkoutId = stk.data.CheckoutRequestID;

    payments.set(checkoutId, { status: 'pending', amount, phone, userId, mpesaRef: null });

    res.json({ CheckoutRequestID: checkoutId });

  } catch (err) {
    console.error('[stk-push]', err?.response?.data || err.message);
    res.status(500).json({ error: 'STK push failed. Please try again.' });
  }
});

// ── M-Pesa Callback ────────────────────────────────────────────────────
app.post('/api/deposit/callback', async (req, res) => {
  const body = req.body?.Body?.stkCallback;
  if (!body) return res.json({ ResultCode: 0 });

  const { CheckoutRequestID: checkoutId, ResultCode: resultCode } = body;
  const p = payments.get(checkoutId);
  if (!p) return res.json({ ResultCode: 0 });

  if (resultCode === 0) {
    p.status   = 'completed';
    p.mpesaRef = body.CallbackMetadata?.Item?.find(i => i.Name === 'MpesaReceiptNumber')?.Value || null;

    // Credit the wallet in MongoDB
    await creditWallet(p.userId, p.amount);
    console.log(`[mpesa] Payment completed. Ref: ${p.mpesaRef}`);
  } else {
    p.status = 'failed';
    console.warn(`[mpesa] Payment failed. ResultCode: ${resultCode}`);
  }

  res.json({ ResultCode: 0 });
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
