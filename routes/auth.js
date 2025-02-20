// routes/auth.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const pool = require('../db');
const authMiddleware = require('../middleware/authMiddleware');
const roleMiddleware = require('../middleware/roleMiddleware');
const rateLimit = require('express-rate-limit');
const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                    // Limit each IP to 5 requests per `windowMs`
  message: 'Too many login attempts, please try again later.',
});


// User signup route
router.post(
  '/signup',
  [
    body('username').isString().notEmpty(),
    body('email').isEmail(),
    body('password').isLength({ min: 6 }),
    body('role').optional().isIn(['user', 'admin']), // Role validation
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, email, role = 'user' } = req.body;
    let conn;

    try {
      conn = await pool.getConnection();

      // Check if the email already exists in the database
      const [existingUser] = await conn.query(
        'SELECT * FROM users WHERE email = ?',
        [email]
      );

      if (existingUser?.length > 0) {
        return res.status(400).json({ message: 'Email already in use' });
      }

      // Hash password before storing
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert the new user into the database
      await conn.query(
        'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
        [username, hashedPassword, email, role]
      );

      res.status(201).json({ message: 'User created successfully' });
    } catch (err) {

      console.error(err.message);
      if (err.message.includes('Duplicate entry')) {
        return res.status(400).json({ message: 'Email already in use' });
      }

      res.status(500).json({ message: 'Internal server error' });

    } finally {

      if (conn) conn.release(); // Ensure the connection is released

    }
  }
);

// User login route
router.post('/login', loginLimiter,
  [
    body('username').isLength({ min: 3 }).trim().escape(),
    body('password').isLength({ min: 6 }).trim().escape()
  ], async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    let conn;

    try {
      conn = await pool.getConnection();
      const [user] = await conn.query('SELECT * FROM users WHERE username = ? or email = ?', [username, username]);


      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const isMatch = await bcrypt.compare(password, user?.password);

      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Create JWT tokens (access and refresh)
      const accessToken = jwt.sign(
        { username: user.username, role: user.role },   // Payload
        process.env.SECRET_KEY,                          // Secret key
        { expiresIn: '15m' }                             // Options (expires in 1 hour)
      );

      // Generate refresh token
      const refreshToken = jwt.sign(
        { username: user.username, role: user.role },   // Payload
        process.env.SECRET_KEY,                          // Secret key
        { expiresIn: '7d' }                             // Options (expires in 7 days)
      );

      // Store refresh token in the database
      await conn.query('UPDATE users SET refresh_token = ? WHERE id = ?', [refreshToken, user.id]);
      const info = { id: user?.id, name: user?.username, email: user?.email }
      res
        .cookie('refreshToken', refreshToken, {
          httpOnly: true,
          secure: true, // Only in HTTPS
          sameSite: 'Strict',
        })
        .json({ accessToken, info });

    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Internal server error' });
    } finally {
      if (conn) conn.release();// Ensure the connection is released
    }
  });

// Refresh token route
router.post('/refresh-token', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;  // Get refresh token from cookies

  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token required' });
  }

  let conn;
  try {
    conn = await pool.getConnection();
    const [user] = await conn.query('SELECT * FROM users WHERE refresh_token = ?', [refreshToken]);

    if (!user) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const decoded = jwt.decode(refreshToken, process.env.SECRET_KEY);
    const newAccessToken = jwt.sign(
      { username: decoded.username, role: decoded.role },
      process.env.SECRET_KEY,
      { expiresIn: '15m' }
    );

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    return res.status(401).json({ message: 'Invalid refresh token' });
  } finally {
    if (conn) conn.release(); // Ensure the connection is released
  }
});

// Logout Route
router.post('/logout', (req, res) => {
  const { refreshToken } = req.cookies;

  // Invalidate the refresh token
  const user = users.find((u) => u.refreshToken === refreshToken);
  if (user) user.refreshToken = null;

  res.clearCookie('refreshToken').json({ message: 'Logged out' });
});

// Admin protected route
router.get('/admin', authMiddleware, roleMiddleware('admin'), (req, res) => {
  try {
    res.json({ message: 'Welcome to the admin panel!' });
  } catch (err) {
    console.log(err)
  } finally {
    if (conn) conn.release();
  }
});

// User protected route
router.get('/user', authMiddleware, roleMiddleware('user'), (req, res) => {
  res.json({ message: 'Welcome to the user dashboard!' });
});

module.exports = router;
