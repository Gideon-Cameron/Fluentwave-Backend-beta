const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Middleware function to authenticate users
exports.authenticateUser = async (req, res, next) => {
  try {
    console.log('Request Headers:', req.headers);  // Debugging incoming headers

    const authHeader = req.header('Authorization');

    if (!authHeader) {
      console.error('Missing Authorization header');
      return res.status(401).json({ success: false, error: 'Authorization header is missing' });
    }

    const token = authHeader.startsWith('Bearer ')
      ? authHeader.split(' ')[1]
      : authHeader;

    if (!token) {
      console.error('Token not provided');
      return res.status(401).json({ success: false, error: 'No token provided, authorization denied' });
    }

    // Attempt to verify the access token
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log('Access token valid:', decoded);

      // Fetch the user and attach to request
      const user = await User.findById(decoded.id).select('-password');
      if (!user) {
        return res.status(404).json({ success: false, error: 'User not found' });
      }

      req.user = user;
      return next();
    } catch (error) {
      // Handle token expiration or invalid cases
      if (error.name === 'TokenExpiredError') {
        console.log('Access token expired, attempting refresh...');
        return handleTokenRefresh(req, res, next);
      } else {
        console.error('Invalid token:', error.message);
        return res.status(401).json({ success: false, error: 'Invalid token' });
      }
    }
  } catch (error) {
    console.error('Authentication error:', error.message);
    res.status(500).json({ success: false, error: 'Internal server error during authentication' });
  }
};

// Helper function to handle token refresh
const handleTokenRefresh = async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ success: false, error: 'Refresh token missing' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || user.refreshToken !== refreshToken) {
      console.error('Refresh token mismatch or user not found');
      return res.status(403).json({ success: false, error: 'Invalid refresh token' });
    }

    // Generate new tokens and update the refresh token
    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    const newRefreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, {
      expiresIn: '30d',
    });

    user.refreshToken = newRefreshToken;
    await user.save();

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    // Attach user to request and continue to route
    req.user = user;
    req.token = accessToken;  // Optionally pass new token to client
    next();
  } catch (error) {
    console.error('Refresh token error:', error.message);
    return res.status(403).json({ success: false, error: 'Refresh token expired or invalid' });
  }
};
