const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// SIGNUP
app.post('/api/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (name, email, phone, password) VALUES ($1, $2, $3, $4)',
      [name, email, phone, hashedPassword]
    );
    res.json({ success: true, message: 'Account created!' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0)
      return res.status(401).json({ success: false, error: 'User not found' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ success: false, error: 'Wrong password' });

    res.json({ success: true, message: 'Login successful!', user: { name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// CONTACT
app.post('/api/contact', async (req, res) => {
  const { name, email, subject, message } = req.body;
  try {
    await pool.query(
      'INSERT INTO contacts (name, email, subject, message) VALUES ($1, $2, $3, $4)',
      [name, email, subject, message]
    );
    res.json({ success: true, message: 'Message received!' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
