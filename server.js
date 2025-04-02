require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const requestIp = require('request-ip');
const geoip = require('geoip-lite');

// Validate environment variables
const requiredEnvVars = [
  'MONGODB_URI', 'JWT_SECRET', 'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET', 'FRONTEND_URL',
  'EMAIL_USER', 'EMAIL_PASS', 'ADMIN_EMAIL'
];

requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    throw new Error(`Missing required environment variable: ${varName}`);
  }
});

const app = express();

// Configure trust proxy carefully (trust only Render's proxy)
app.set('trust proxy', 1);

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(requestIp.mw());

// Secure rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  validate: { 
    trustProxy: false // Don't trust X-Forwarded-For for rate limiting
  },
  keyGenerator: (req) => {
    return req.socket.remoteAddress;
  },
  message: 'Too many requests from this IP, please try again later'
});
app.use(limiter);

// Enhanced Database connection with error handling and retry logic
const connectWithRetry = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      maxPoolSize: 10
    });
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    console.log('Retrying connection in 5 seconds...');
    setTimeout(connectWithRetry, 5000);
  }
};

// Connection events
mongoose.connection.on('connected', () => {
  console.log('Mongoose connected to DB');
});

mongoose.connection.on('error', (err) => {
  console.error('Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose disconnected from DB');
  console.log('Attempting to reconnect...');
  connectWithRetry();
});

// Initialize connection
connectWithRetry();

// Graceful shutdown
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  console.log('Mongoose connection closed due to app termination');
  process.exit(0);
});

// User Schema with password reset fields
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String },
  googleId: { type: String },
  facebookId: { type: String },
  phone: { type: String },
  emailVerified: { type: Boolean, default: false },
  verificationToken: { type: String },
  verificationTokenExpires: { type: Date },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  ipAddress: { type: String },
  location: {
    country: { type: String },
    region: { type: String },
    city: { type: String },
    timezone: { type: String }
  },
  userAgent: { type: String },
  lastLogin: { type: Date }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Booking Schema (for reference only - actual booking should be in separate service)
const bookingSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  // ... other booking fields
}, { timestamps: true });

const Booking = mongoose.model('Booking', bookingSchema);

// Token Verification Middleware (MOVED TO TOP)
const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: 'Authorization token required'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: 'User not found'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(403).json({ 
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

// Google OAuth Client
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET
});

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Helper functions
const generateToken = () => crypto.randomBytes(32).toString('hex');

const generateJWT = (user) => {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      verified: user.emailVerified
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
};

const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({
      from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html
    });
  } catch (error) {
    console.error('Email sending error:', error);
  }
};

const getLocationFromIp = (ip) => {
  const geo = geoip.lookup(ip) || {};
  return {
    country: geo.country || 'Unknown',
    region: geo.region || 'Unknown',
    city: geo.city || 'Unknown',
    timezone: geo.timezone || 'Unknown'
  };
};

// Routes

// Health check endpoint with DB status
app.get('/api/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState;
  const statusMap = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };
  
  res.json({ 
    status: 'healthy', 
    timestamp: new Date(),
    services: {
      database: statusMap[dbStatus] || 'unknown',
      email: transporter ? 'configured' : 'not configured'
    }
  });
});

// User Details Endpoint (simplified - no booking details)
app.get('/api/user-details', authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        emailVerified: user.emailVerified,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch user details'
    });
  }
});

// [All your existing authentication routes remain unchanged...]
// Password Reset, Google Auth, Email Login/Signup etc.
// ...

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Frontend URL: ${process.env.FRONTEND_URL}`);
  console.log(`MongoDB URI: ${process.env.MONGODB_URI ? 'configured' : 'not configured'}`);
});
