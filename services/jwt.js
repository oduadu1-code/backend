'use strict';
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET;
if (!SECRET) { console.error('[jwt] JWT_SECRET not set!'); process.exit(1); }

function signToken(payload)  { return jwt.sign(payload, SECRET, { expiresIn: '7d' }); }
function verifyToken(token)  { return jwt.verify(token, SECRET); }
module.exports = { signToken, verifyToken };