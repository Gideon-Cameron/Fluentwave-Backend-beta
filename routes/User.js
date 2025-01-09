const express = require('express');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const BlacklistedToken = require('../models/BlacklistedToken');
const { authenticateUser } = require('../middleware/auth');
const { generateAccessToken, generateRefreshToken } = require('../utils/tokenUtils');

const router = express.Router();

// Multer setup for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/avatars');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg'];
    allowedTypes.includes(file.mimetype)
      ? cb(null, true)
      : cb(new Error('Only .jpeg, .png, and .jpg formats are allowed.'));
  },
});

// Helper function to send tokens and set cookie
const sendTokenResponse = (user, res) => {
  const accessToken = generateAccessToken(user._id);
  const refreshToken = generateRefreshToken(user._id);

  // Store refresh token in the user model
  user.refreshToken = refreshToken;
  user.save();

  // Set HTTP-only cookie for refresh token
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: 30 * 24 * 60 * 60 * 1000,  // 30 days
  });

  res.status(200).json({
    success: true,
    accessToken,
    data: { id: user._id, name: user.name, email: user.email },
  });
};

// POST /api/users/register
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Email already in use' });
    }

    const newUser = new User({ name, email, password });
    const savedUser = await newUser.save();

    sendTokenResponse(savedUser, res);
  } catch (error) {
    console.error('Error registering user:', error.message);
    res.status(500).json({ success: false, error: 'Server error. Could not register user.' });
  }
});

// POST /api/users/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    sendTokenResponse(user, res);
  } catch (error) {
    console.error('Error during login:', error.message);
    res.status(500).json({ success: false, error: 'Server error. Could not log in.' });
  }
});

// POST /api/users/logout
router.post('/logout', authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.refreshToken = '';
    await user.save();

    res.clearCookie('refreshToken');

    res.status(200).json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('Error during logout:', error.message);
    res.status(500).json({ success: false, error: 'Could not log out.' });
  }
});

// POST /api/users/refresh - Refresh Access Token
router.post('/refresh', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ success: false, error: 'No refresh token provided' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ success: false, error: 'Invalid refresh token' });
    }

    // Generate new access token and refresh token (token rotation)
    const accessToken = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    // Update refresh token in user record
    user.refreshToken = newRefreshToken;
    await user.save();

    // Update cookie with new refresh token
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({ success: true, accessToken });
  } catch (error) {
    console.error('Refresh token error:', error.message);
    res.status(403).json({ success: false, error: 'Token expired or invalid' });
  }
});

// GET /api/users/profile (Protected Route)
router.get('/profile', authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.status(200).json({ success: true, data: user });
  } catch (error) {
    console.error('Error fetching profile:', error.message);
    res.status(500).json({ success: false, error: 'Server error. Could not fetch user profile.' });
  }
});

// GET /api/users/leaderboard
router.get('/leaderboard', async (req, res) => {
  try {
    const topUsers = await User.find({}, 'name avatar totalXp level')
      .sort({ totalXp: -1 })
      .limit(50);

    res.status(200).json({ success: true, data: topUsers });
  } catch (error) {
    console.error('Error fetching leaderboard:', error.message);
    res.status(500).json({ success: false, error: 'Server error. Could not fetch leaderboard.' });
  }
});

module.exports = router;
