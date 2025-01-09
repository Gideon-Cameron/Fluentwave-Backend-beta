require('dotenv').config(); // Load environment variables
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');  // Import cookie parser for refresh token
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('Uploads directory created at', uploadsDir);
}

// Middleware
app.use(
  cors({
    origin: ['http://localhost:3000', 'https://fluentwave-beta.netlify.app'],
    credentials: true,  // Allow cookies to be sent from frontend
  })
);
app.use(bodyParser.json());
app.use(cookieParser());  // Parse incoming cookies
app.use('/uploads', express.static(uploadsDir));

// MongoDB connection
const dbURI = process.env.MONGO_URI;
mongoose
  .connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected...'))
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1); // Exit if DB connection fails
  });

// Import Middleware and Models
const { authenticateUser } = require('./middleware/auth');
const BlacklistedToken = require('./models/BlacklistedToken');

// Routes
const lessonRoutes = require('./routes/lessons');
const quizCompletionRoutes = require('./routes/quizCompletion');
const userRoutes = require('./routes/User');
const fileUploadRoutes = require('./routes/FileUpload');

// Use Routes
app.use('/api/lessons', lessonRoutes);
app.use('/api/quiz-completion', quizCompletionRoutes);
app.use('/api/users', userRoutes);
app.use('/api/uploads', fileUploadRoutes);

// Test Endpoint
app.get('/api/test', (req, res) => {
  res.status(200).json({ message: 'Test endpoint is working!' });
});

// Health Check Route
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Server is healthy' });
});

// Serve static assets in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'client/build')));
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
  });
}

// Root route
app.get('/', (req, res) => {
  res.json({
    message: 'FluentWave Backend is Running!',
    environment: process.env.NODE_ENV || 'development',
  });
});

// Protected route example
app.get('/api/protected', authenticateUser, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.user });
});

// Logout Route - Clear Cookie and Blacklist Token
app.post('/api/users/logout', authenticateUser, async (req, res) => {
  try {
    const token = req.header('Authorization')?.split(' ')[1];
    const refreshToken = req.cookies.refreshToken;

    if (!token && !refreshToken) {
      return res.status(400).json({ error: 'No tokens provided' });
    }

    if (token) {
      await BlacklistedToken.create({ token });
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
    });

    res.status(200).json({ message: 'Successfully logged out' });
  } catch (error) {
    console.error('Logout error:', error.message);
    res.status(500).json({ error: 'Internal server error during logout' });
  }
});

// Refresh Token Route - Issue New Access Token
app.post('/api/users/refresh', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ error: 'No refresh token provided' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    const newAccessToken = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
    console.error('Refresh token error:', error.message);
    res.status(403).json({ error: 'Refresh token expired or invalid' });
  }
});

// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Global Error Handler:', err.stack);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Server Error',
  });
});

// Handle 404 for undefined routes
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found',
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
