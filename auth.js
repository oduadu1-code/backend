/**
 * PepetaHigh — Backend (NO SQLITE, TEMP MEMORY DB)
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const axios   = require('axios');
const crypto  = require('crypto');

const app = express();

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

/* ─────────────────────────────────────────────
   🗄 TEMP DATABASE (IN-MEMORY)
───────────────────────────────────────────── */

const users = []; // acts like your DB

/* ─────────────────────────────────────────────
   🔐 PASSWORD HASHING
───────────────────────────────────────────── */

function hashPassword(password, salt = null) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const verifyHash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === verifyHash;
}

/* ─────────────────────────────────────────────
   👤 AUTH ROUTES
───────────────────────────────────────────── */

app.post('/api/auth/register', (req, res) => {
  const { username, phone, password } = req.body;

  const exists = users.find(u => u.username === username || u.phone === phone);
  if (exists) return res.status(400).json({ error: 'User already exists' });

  const hashed = hashPassword(password);

  users.push({
    username,
    phone,
    password: hashed,
    wallet: 0,
    createdAt: Date.now()
  });

  res.json({ success: true });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (!verifyPassword(password, user.password)) {
    return res.status(401).json({ error: 'Wrong password' });
  }

  res.json({
    success: true,
    user: {
      username: user.username,
      phone: user.phone,
      wallet: user.wallet
    }
  });
});

/* ─────────────────────────────────────────────
   💰 WALLET ROUTES
───────────────────────────────────────────── */

app.get('/api/wallet/:username', (req, res) => {
  const { username } = req.params;

  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({ wallet: user.wallet });
});

function updateWallet(username, amount) {
  const user = users.find(u => u.username === username);
  if (user) user.wallet += amount;
}

/* ─────────────────────────────────────────────
   💳 M-PESA (UNCHANGED LOGIC)
───────────────────────────────────────────── */

const payments = new Map();

const {
  MPESA_CONSUMER_KEY,
  MPESA_CONSUMER_SECRET,
  MPESA_SHORTCODE,
  MPESA_PASSKEY,
  MPESA_CALLBACK_URL,
  MPESA_ENV = 'sandbox',
  PORT = 3001
} = process.env;

const BASE_URL = MPESA_ENV === 'production'
  ? 'https://api.safaricom.co.ke'
  : 'https://sandbox.safaricom.co.ke';

async function getToken() {
  const creds = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString('base64');
  const res = await axios.get(`${BASE_URL}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${creds}` }
  });
  return res.data.access_token;
}

function stkPassword() {
  const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
  const raw = `${MPESA_SHORTCODE}${MPESA_PASSKEY}${timestamp}`;
  return { password: Buffer.from(raw).toString('base64'), timestamp };
}

/* ─────────────────────────────────────────────
   🚀 STK PUSH
───────────────────────────────────────────── */

app.post('/api/deposit/stk', async (req, res) => {
  const { phone, amount, userId } = req.body;

  if (!phone || !amount || amount < 200) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  try {
    const token = await getToken();
    const { password, timestamp } = stkPassword();

    const payload = {
      BusinessShortCode: MPESA_SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Math.round(amount),
      PartyA: phone,
      PartyB: MPESA_SHORTCODE,
      PhoneNumber: phone,
      CallBackURL: MPESA_CALLBACK_URL,
      AccountReference: userId,
      TransactionDesc: 'PepetaHigh Deposit'
    };

    const stk = await axios.post(
      `${BASE_URL}/mpesa/stkpush/v1/processrequest`,
      payload,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    const checkoutId = stk.data.CheckoutRequestID;

    payments.set(checkoutId, {
      status: 'pending',
      amount,
      phone,
      userId,
      mpesaRef: null
    });

    res.json({ CheckoutRequestID: checkoutId });

  } catch (err) {
    res.status(500).json({ error: 'STK push failed' });
  }
});

/* ─────────────────────────────────────────────
   📡 CALLBACK
───────────────────────────────────────────── */

app.post('/api/deposit/callback', (req, res) => {
  const body = req.body?.Body?.stkCallback;
  if (!body) return res.json({ ResultCode: 0 });

  const checkoutId = body.CheckoutRequestID;
  const resultCode = body.ResultCode;
  const p = payments.get(checkoutId);

  if (!p) return res.json({ ResultCode: 0 });

  if (resultCode === 0) {
    p.status = 'completed';

    // ✅ CREDIT WALLET
    updateWallet(p.userId, p.amount);

  } else {
    p.status = 'failed';
  }

  res.json({ ResultCode: 0 });
});

/* ───────────────────────────────────────────── */

app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});