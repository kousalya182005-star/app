const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

console.log("DB_HOST:", process.env.DB_HOST);
console.log("DB_PORT:", process.env.DB_PORT);
console.log("DB_USER:", process.env.DB_USER);
console.log("DB_PASSWORD:", process.env.DB_PASSWORD ? "Loaded" : "Not Loaded");
console.log("DB_NAME:", process.env.DB_NAME);

const pool = new Pool({
  host: process.env.PGHOST || process.env.DB_HOST || 'localhost',
  user: process.env.PGUSER || process.env.DB_USER || 'postgres',
  password: process.env.PGPASSWORD || process.env.DB_PASSWORD || 'admin123',
  database: process.env.PGDATABASE || process.env.DB_NAME || 'login_db',
  port: Number(process.env.PGPORT || process.env.DB_PORT || 5432),
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

function normalizePhone(phone) {
  return phone.replace(/\D/g, '');
}

function isValidPhone(phone) {
  return /^[0-9]{10,15}$/.test(phone);
}

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function initializeDatabase() {
  try {
    await pool.query('SELECT 1');
    console.log('PostgreSQL connection available.');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(64) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        phone VARCHAR(20) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS pending_otps (
        id SERIAL PRIMARY KEY,
        username VARCHAR(64) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        otp VARCHAR(6) NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (username, phone)
      );
    `);
  } catch (error) {
    console.error('PostgreSQL connection failed.', error.message);
    throw error;
  }
}

async function createPendingOtp(username, phone, otp, expiresAt) {
  await pool.query(
    `INSERT INTO pending_otps (username, phone, otp, expires_at)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (username, phone)
     DO UPDATE SET otp = EXCLUDED.otp, expires_at = EXCLUDED.expires_at`,
    [username, phone, otp, expiresAt]
  );
}

async function getPendingOtp(username, phone) {
  const result = await pool.query(
    'SELECT otp, expires_at FROM pending_otps WHERE username = $1 AND phone = $2',
    [username, phone]
  );
  return result.rowCount > 0 ? result.rows[0] : null;
}

async function deletePendingOtp(username, phone) {
  await pool.query('DELETE FROM pending_otps WHERE username = $1 AND phone = $2', [username, phone]);
}

async function userExists(username) {
  const result = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
  return result.rowCount > 0;
}

async function findUserByUsernameAndPhone(username, phone) {
  const result = await pool.query(
    'SELECT id, password_hash FROM users WHERE username = $1 AND phone = $2',
    [username, phone]
  );
  return result.rowCount > 0 ? result.rows[0] : null;
}

async function createUser(username, passwordHash, phone) {
  await pool.query(
    'INSERT INTO users (username, password_hash, phone) VALUES ($1, $2, $3)',
    [username, passwordHash, phone]
  );
}

app.post('/generate-otp', async (req, res) => {
  const { username, phone, action } = req.body;

  if (!username || !phone || !action) {
    return res.status(400).json({ success: false, message: 'username, phone, and action are required.' });
  }

  const normalizedPhone = normalizePhone(phone);
  if (!isValidPhone(normalizedPhone)) {
    return res.status(400).json({ success: false, message: 'Enter a valid phone number with 10 to 15 digits.' });
  }

  if (!['register', 'signin'].includes(action)) {
    return res.status(400).json({ success: false, message: 'Action must be register or signin.' });
  }

  try {
    if (action === 'signin') {
      const user = await findUserByUsernameAndPhone(username, normalizedPhone);
      if (!user) {
        return res.status(400).json({ success: false, message: 'No account found for this username and phone number.' });
      }
    }

    const otp = generateOtp();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await createPendingOtp(username, normalizedPhone, otp, expiresAt);

    return res.json({ success: true, message: 'OTP generated.', otp });
  } catch (error) {
    console.error('generate-otp error:', error);
    return res.status(500).json({ success: false, message: 'Server error generating OTP.' });
  }
});

app.post('/register', async (req, res) => {
  const { username, password, phone, otp } = req.body;

  if (!username || !password || !phone || !otp) {
    return res.status(400).json({ success: false, message: 'username, password, phone, and otp are required.' });
  }

  const normalizedPhone = normalizePhone(phone);
  if (!isValidPhone(normalizedPhone)) {
    return res.status(400).json({ success: false, message: 'Enter a valid phone number with 10 to 15 digits.' });
  }

  try {
    if (await userExists(username)) {
      return res.status(400).json({ success: false, message: 'Username already exists. Choose a different username.' });
    }

    const otpRow = await getPendingOtp(username, normalizedPhone);
    if (!otpRow || otpRow.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP. Please generate a new OTP and try again.' });
    }

    if (new Date(otpRow.expires_at) < new Date()) {
      return res.status(400).json({ success: false, message: 'OTP has expired. Generate a new OTP.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await createUser(username, passwordHash, normalizedPhone);
    await deletePendingOtp(username, normalizedPhone);

    return res.json({ success: true, message: 'Account created successfully. You can now sign in.' });
  } catch (error) {
    console.error('register error:', error);
    return res.status(500).json({ success: false, message: 'Server error while registering the account.' });
  }
});

app.post('/signin', async (req, res) => {
  const { username, password, phone, otp } = req.body;

  if (!username || !password || !phone || !otp) {
    return res.status(400).json({ success: false, message: 'username, password, phone, and otp are required.' });
  }

  const normalizedPhone = normalizePhone(phone);
  if (!isValidPhone(normalizedPhone)) {
    return res.status(400).json({ success: false, message: 'Enter a valid phone number with 10 to 15 digits.' });
  }

  try {
    const user = await findUserByUsernameAndPhone(username, normalizedPhone);
    if (!user) {
      return res.status(400).json({ success: false, message: 'Username or phone number does not match any account.' });
    }

    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      return res.status(400).json({ success: false, message: 'Incorrect password.' });
    }

    const otpRow = await getPendingOtp(username, normalizedPhone);
    if (!otpRow || otpRow.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP. Please generate a new OTP.' });
    }

    if (new Date(otpRow.expires_at) < new Date()) {
      return res.status(400).json({ success: false, message: 'OTP has expired. Generate a new OTP.' });
    }

    await deletePendingOtp(username, normalizedPhone);

    const qrData = `Attend session as ${username} at ${new Date().toISOString()}`;
    return res.json({ success: true, message: 'Sign in successful.', qrData });
  } catch (error) {
    console.error('signin error:', error);
    return res.status(500).json({ success: false, message: 'Server error while signing in.' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login page.html'));
});

initializeDatabase().then(() => {
  app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });
}).catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
