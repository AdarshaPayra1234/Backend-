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

// Validate critical environment variables
const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'FRONTEND_URL', 'EMAIL_USER', 'EMAIL_PASS', 'ADMIN_EMAIL'];
requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    throw new Error(`Missing required environment variable: ${varName}`);
  }
});

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters long');
}

const app = express();

// Enhanced CORS Configuration
app.use(cors({
  origin: process.env.FRONTEND_URL,
  methods: ['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Middleware to parse JSON bodies and get client IP
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(requestIp.mw());

// Rate limiting for verification endpoints
const verificationLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 3,
  message: 'Too many verification attempts, please try again later'
});

// Database Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true,
  w: 'majority'
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Enhanced User Schema with location tracking
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String },
  googleId: { type: String },
  phone: { type: String },
  emailVerified: { type: Boolean, default: false },
  verificationToken: { type: String },
  verificationTokenExpires: { type: Date },
  emailVerificationAttempts: { type: Number, default: 0 },
  lastEmailVerificationAttempt: { type: Date },
  lastLogin: { type: Date, default: Date.now },
  ipAddress: { type: String },
  location: {
    country: { type: String },
    region: { type: String },
    city: { type: String },
    ll: { type: [Number] }, // latitude/longitude
    timezone: { type: String }
  },
  userAgent: { type: String }
}, { timestamps: true });

// Add indexes for better performance
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ googleId: 1 });
userSchema.index({ verificationToken: 1 });

const User = mongoose.model('User', userSchema);

// Initialize Google Auth Client
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET
});

// Email Transport Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Helper Functions
const generateToken = () => crypto.randomBytes(32).toString('hex');

const generateJWT = (user) => {
  return jwt.sign(
    {
      userId: user._id,
      email: user.email,
      emailVerified: user.emailVerified,
      iss: 'jokercreation-store-api',
      aud: 'jokercreation-store-client'
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h', algorithm: 'HS256' }
  );
};

// Enhanced Send Verification Email with HTML template
const sendVerificationEmail = async (email, name, token) => {
  const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
  
  const mailOptions = {
    from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verify Your Email Address',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
        <h2 style="color: #be9c65; text-align: center;">Welcome to Joker Creation Studio</h2>
        <p>Hello ${name},</p>
        <p>Please click the button below to verify your email address:</p>
        <div style="text-align: center; margin: 20px 0;">
          <a href="${verificationUrl}" 
             style="display: inline-block; padding: 12px 24px; background-color: #be9c65; color: white; 
                    text-decoration: none; border-radius: 4px; font-weight: bold;">
            Verify Email
          </a>
        </div>
        <p>If you didn't create an account, please ignore this email.</p>
        <p style="margin-top: 30px; font-size: 12px; color: #777;">
          This link will expire in 24 hours. You can request a new verification email if needed.
        </p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
};

// Send notification email to admin
const sendAdminNotification = async (subject, htmlContent) => {
  const mailOptions = {
    from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
    to: process.env.ADMIN_EMAIL,
    subject: subject,
    html: htmlContent
  };

  await transporter.sendMail(mailOptions);
};

// Get location from IP
const getLocationFromIp = (ip) => {
  // For local testing, use a default IP if localhost
  const testIp = ip === '::1' || ip === '127.0.0.1' ? '8.8.8.8' : ip;
  const geo = geoip.lookup(testIp);
  
  return geo ? {
    country: geo.country,
    region: geo.region,
    city: geo.city,
    ll: geo.ll,
    timezone: geo.timezone
  } : null;
};

// Routes

// Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date(),
    version: '1.0.0'
  });
});

// Google Sign-In Endpoint
app.post('/api/signup/google', async (req, res) => {
  try {
    const { credential, userAgent } = req.body;
    const clientIp = req.clientIp;
    
    if (!credential) {
      return res.status(400).json({ 
        success: false,
        message: 'No Google credential provided'
      });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const location = getLocationFromIp(clientIp);

    if (!payload.email_verified) {
      return res.status(400).json({ 
        success: false,
        message: 'Google email not verified'
      });
    }

    let user = await User.findOneAndUpdate(
      { $or: [{ email: payload.email }, { googleId: payload.sub }] },
      {
        $set: {
          name: payload.name,
          email: payload.email.toLowerCase(),
          googleId: payload.sub,
          emailVerified: true,
          lastLogin: new Date(),
          ipAddress: clientIp,
          location: location,
          userAgent: userAgent
        }
      },
      { upsert: true, new: true }
    );

    const token = generateJWT(user);

    // Send notification to admin
    const signupHtml = `
      <h2>New Google Signup</h2>
      <p><strong>Name:</strong> ${user.name}</p>
      <p><strong>Email:</strong> ${user.email}</p>
      <p><strong>IP Address:</strong> ${clientIp}</p>
      <p><strong>Location:</strong> ${location ? `${location.city}, ${location.region}, ${location.country}` : 'Unknown'}</p>
      <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
      <p><strong>User Agent:</strong> ${userAgent}</p>
    `;
    await sendAdminNotification('New Google Signup', signupHtml);

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        phone: user.phone
      }
    });

  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({
      success: false,
      message: 'Google authentication failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Regular Email Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password, phone, userAgent } = req.body;
    const clientIp = req.clientIp;
    const location = getLocationFromIp(clientIp);
    
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Name, email and password are required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Validate password strength
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters with uppercase, lowercase, number and special character'
      });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        message: 'Email already registered'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationToken = generateToken();

    const newUser = new User({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      phone,
      verificationToken,
      verificationTokenExpires: Date.now() + 24 * 3600000,
      emailVerificationAttempts: 1,
      lastEmailVerificationAttempt: new Date(),
      ipAddress: clientIp,
      location: location,
      userAgent: userAgent
    });

    await newUser.save();
    await sendVerificationEmail(email, name, verificationToken);

    // Send notification to admin
    const signupHtml = `
      <h2>New User Signup</h2>
      <p><strong>Name:</strong> ${name}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>Phone:</strong> ${phone || 'Not provided'}</p>
      <p><strong>IP Address:</strong> ${clientIp}</p>
      <p><strong>Location:</strong> ${location ? `${location.city}, ${location.region}, ${location.country}` : 'Unknown'}</p>
      <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
      <p><strong>User Agent:</strong> ${userAgent}</p>
    `;
    await sendAdminNotification('New User Signup', signupHtml);

    res.status(201).json({ 
      success: true,
      message: 'Registration successful. Please check your email for verification.',
      userId: newUser._id,
      email: newUser.email,
      attemptsRemaining: 4 // 5 total attempts - 1 used
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during registration'
    });
  }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password, userAgent } = req.body;
    const clientIp = req.clientIp;
    const location = getLocationFromIp(clientIp);
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Email and password are required'
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials'
      });
    }

    if (!user.password) {
      return res.status(401).json({ 
        success: false,
        message: 'Please use Google Sign-In or reset your password'
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Update user with login info
    user.lastLogin = new Date();
    user.ipAddress = clientIp;
    user.location = location;
    user.userAgent = userAgent;
    await user.save();

    const token = generateJWT(user);

    // Send login notification to admin
    const loginHtml = `
      <h2>User Login</h2>
      <p><strong>Name:</strong> ${user.name}</p>
      <p><strong>Email:</strong> ${user.email}</p>
      <p><strong>Phone:</strong> ${user.phone || 'Not provided'}</p>
      <p><strong>IP Address:</strong> ${clientIp}</p>
      <p><strong>Location:</strong> ${location ? `${location.city}, ${location.region}, ${location.country}` : 'Unknown'}</p>
      <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
      <p><strong>User Agent:</strong> ${userAgent}</p>
    `;
    await sendAdminNotification('User Login Notification', loginHtml);

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        phone: user.phone
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during login'
    });
  }
});

// Email Verification Endpoint
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    
    if (!token) {
      return res.status(400).json({ 
        success: false,
        message: 'Verification token is required'
      });
    }

    const user = await User.findOne({ 
      verificationToken: token,
      verificationTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired verification token'
      });
    }

    // Mark email as verified
    user.emailVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();

    // Generate new JWT
    const authToken = generateJWT(user);

    res.json({ 
      success: true,
      message: 'Email verified successfully',
      token: authToken,
      user: {
        id: user._id,
        emailVerified: true,
        phone: user.phone
      }
    });

  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during email verification'
    });
  }
});

// Resend Verification Email with Limits
app.post('/api/resend-verification', verificationLimiter, async (req, res) => {
  try {
    const { email, userId } = req.body;
    
    // 1. Input validation
    if (!email && !userId) {
      return res.status(400).json({ 
        success: false,
        message: 'Email or User ID is required',
        code: 'MISSING_IDENTIFIER'
      });
    }

    // 2. Find user
    const user = userId 
      ? await User.findById(userId)
      : await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // 3. Check if already verified
    if (user.emailVerified) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is already verified',
        code: 'ALREADY_VERIFIED'
      });
    }

    // 4. Check attempt limits (5 per day)
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    
    if (user.lastEmailVerificationAttempt > oneDayAgo && 
        user.emailVerificationAttempts >= 5) {
      const nextAttemptTime = new Date(user.lastEmailVerificationAttempt.getTime() + 24 * 60 * 60 * 1000);
      return res.status(429).json({ 
        success: false,
        message: 'Daily verification limit reached (5 emails per day)',
        code: 'DAILY_LIMIT_REACHED',
        nextAttempt: nextAttemptTime,
        attemptsRemaining: 0
      });
    }

    // 5. Check 1-minute cooldown
    const oneMinuteAgo = new Date(now.getTime() - 60 * 1000);
    if (user.lastEmailVerificationAttempt > oneMinuteAgo) {
      const nextAttemptTime = new Date(user.lastEmailVerificationAttempt.getTime() + 60 * 1000);
      return res.status(429).json({ 
        success: false,
        message: 'Please wait 1 minute before requesting another verification email',
        code: 'COOLDOWN_ACTIVE',
        nextAttempt: nextAttemptTime,
        attemptsRemaining: 5 - user.emailVerificationAttempts
      });
    }

    // 6. Generate new verification token
    const verificationToken = generateToken();
    user.verificationToken = verificationToken;
    user.verificationTokenExpires = Date.now() + 24 * 3600000; // 24 hours
    
    // 7. Update attempt tracking
    if (user.lastEmailVerificationAttempt <= oneDayAgo) {
      user.emailVerificationAttempts = 1; // Reset counter if >24hrs since last attempt
    } else {
      user.emailVerificationAttempts += 1;
    }
    user.lastEmailVerificationAttempt = now;
    
    // 8. Save user and send email
    await user.save();
    await sendVerificationEmail(user.email, user.name, verificationToken);

    // 9. Return success response
    res.json({ 
      success: true,
      message: 'Verification email resent successfully',
      attemptsRemaining: 5 - user.emailVerificationAttempts,
      nextAttemptAllowed: new Date(now.getTime() + 60 * 1000), // 1 minute cooldown
      verificationExpires: user.verificationTokenExpires
    });

  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to resend verification email',
      code: 'SERVER_ERROR',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Token Verification Endpoint
app.get('/api/verify-token', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ success: false, message: 'Invalid or expired token' });
      }
      res.json({ success: true, user });
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({ success: false, message: 'Server error during token verification' });
  }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`CORS configured for: ${process.env.FRONTEND_URL}`);
});
