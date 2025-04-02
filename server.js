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
  'MONGO_URI', 'JWT_SECRET', 'GOOGLE_CLIENT_ID',
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
    // Use the direct connection IP for rate limiting
    return req.socket.remoteAddress;
  },
  message: 'Too many requests from this IP, please try again later'
});
app.use(limiter);

// Database connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

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

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date(),
    services: {
      database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      email: transporter ? 'configured' : 'not configured'
    }
  });
});

// Password Reset Endpoints

// Forgot password - initiate reset process
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is required'
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'No user found with that email'
      });
    }

    // Generate and save reset token
    const resetToken = generateToken();
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // Send email with reset link
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password.html?token=${resetToken}`;
    await sendEmail(
      user.email,
      'Password Reset Request - Joker Creation Studio',
      `<div style="font-family: Arial, sans-serif;">
        <h2 style="color: #be9c65;">Password Reset Request</h2>
        <p>Hello ${user.name},</p>
        <p>You are receiving this because you (or someone else) have requested to reset the password for your account.</p>
        <p>Please click the button below to complete the process:</p>
        <a href="${resetUrl}" 
           style="display: inline-block; padding: 12px 24px; background-color: #be9c65; color: white; 
                  text-decoration: none; border-radius: 4px; font-weight: bold;">
          Reset Password
        </a>
        <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
        <p>The link will expire in 1 hour.</p>
      </div>`
    );

    res.json({
      success: true,
      message: 'Password reset email sent',
      token: resetToken // Return token for OTP flow
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error processing password reset request'
    });
  }
});

// Resend OTP endpoint
app.post('/api/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is required'
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'No user found with that email'
      });
    }

    // Generate new reset token
    const resetToken = generateToken();
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // Send email with new OTP
    await sendEmail(
      user.email,
      'New OTP for Password Reset - Joker Creation Studio',
      `<div style="font-family: Arial, sans-serif;">
        <h2 style="color: #be9c65;">New OTP for Password Reset</h2>
        <p>Hello ${user.name},</p>
        <p>Your new OTP for password reset is: <strong>${resetToken.substring(0, 6)}</strong></p>
        <p>Enter this code in the password reset form to verify your identity.</p>
        <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
        <p>The OTP will expire in 1 hour.</p>
      </div>`
    );

    res.json({
      success: true,
      message: 'New OTP sent',
      token: resetToken
    });

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error resending OTP'
    });
  }
});

// Verify OTP endpoint
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp, token } = req.body;
    
    if (!email || !otp || !token) {
      return res.status(400).json({ 
        success: false,
        message: 'Email, OTP and token are required'
      });
    }

    const user = await User.findOne({ 
      email: email.toLowerCase(),
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired OTP'
      });
    }

    // Simple OTP verification (first 6 chars of token)
    if (token.substring(0, 6) !== otp) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid OTP'
      });
    }

    res.json({
      success: true,
      message: 'OTP verified successfully',
      token: user.resetPasswordToken // Return same token for password reset
    });

  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error verifying OTP'
    });
  }
});

// Reset password endpoint
app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    
    if (!email || !token || !newPassword) {
      return res.status(400).json({ 
        success: false,
        message: 'Email, token and new password are required'
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ 
        success: false,
        message: 'Password must be at least 8 characters'
      });
    }

    const user = await User.findOne({ 
      email: email.toLowerCase(),
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired password reset token'
      });
    }

    // Update password and clear reset token
    user.password = await bcrypt.hash(newPassword, 12);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    // Send confirmation email
    await sendEmail(
      user.email,
      'Password Changed - Joker Creation Studio',
      `<div style="font-family: Arial, sans-serif;">
        <h2 style="color: #be9c65;">Password Changed Successfully</h2>
        <p>Hello ${user.name},</p>
        <p>This is a confirmation that the password for your account <strong>${user.email}</strong> has been changed.</p>
        <p>If you did not make this change, please contact us immediately.</p>
      </div>`
    );

    res.json({
      success: true,
      message: 'Password reset successfully'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error resetting password'
    });
  }
});

// Google Sign-In Endpoint (Signup)
app.post('/api/signup/google', async (req, res) => {
  try {
    const { credential, userAgent } = req.body;
    const ip = req.clientIp;
    const location = getLocationFromIp(ip);
    
    if (!credential) {
      return res.status(400).json({ 
        success: false,
        message: 'Google credential is required'
      });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

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
          ipAddress: ip,
          location,
          userAgent
        }
      },
      { upsert: true, new: true }
    );

    const token = generateJWT(user);

    await sendEmail(
      process.env.ADMIN_EMAIL,
      'New Google Signup',
      `<h2>New Google Signup</h2>
       <p><strong>Name:</strong> ${user.name}</p>
       <p><strong>Email:</strong> ${user.email}</p>
       <p><strong>IP:</strong> ${ip}</p>
       <p><strong>Location:</strong> ${location.city}, ${location.region}, ${location.country}</p>`
    );

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

// Google Login Endpoint
app.post('/api/login/google', async (req, res) => {
  try {
    const { credential, userAgent } = req.body;
    const ip = req.clientIp;
    const location = getLocationFromIp(ip);
    
    if (!credential) {
      return res.status(400).json({ 
        success: false,
        message: 'Google credential is required'
      });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

    const user = await User.findOne({ 
      $or: [
        { email: payload.email.toLowerCase() },
        { googleId: payload.sub }
      ]
    });

    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'No account found with this Google email'
      });
    }

    // Update user login info
    user.lastLogin = new Date();
    user.ipAddress = ip;
    user.location = location;
    user.userAgent = userAgent;
    await user.save();

    const token = generateJWT(user);

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
    console.error('Google login error:', error);
    
    // Handle HTML responses from sleeping server
    if (error.message.includes('Unexpected token')) {
      return res.status(503).json({
        success: false,
        message: 'Server is waking up. Please try again in 30 seconds.'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Google login failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Email Login Endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const ip = req.clientIp;
    const location = getLocationFromIp(ip);
    const userAgent = req.headers['user-agent'];

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

    // Check if password matches (only for non-OAuth users)
    if (user.password) {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ 
          success: false,
          message: 'Invalid credentials'
        });
      }
    } else {
      return res.status(401).json({ 
        success: false,
        message: 'This email is registered with Google login'
      });
    }

    // Update user login info
    user.lastLogin = new Date();
    user.ipAddress = ip;
    user.location = location;
    user.userAgent = userAgent;
    await user.save();

    const token = generateJWT(user);

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        phone: user.phone
      },
      redirectUrl: '/account.html'
    });

  } catch (error) {
    console.error('Login error:', error);
    
    // Handle HTML responses from sleeping server
    if (error.message.includes('Unexpected token')) {
      return res.status(503).json({
        success: false,
        message: 'Server is waking up. Please try again in 30 seconds.'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Email Signup Endpoint
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    const ip = req.clientIp;
    const location = getLocationFromIp(ip);
    const userAgent = req.headers['user-agent'];

    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Name, email and password are required'
      });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        message: 'Email already registered'
      });
    }

    const verificationToken = generateToken();
    const newUser = new User({
      name,
      email: email.toLowerCase(),
      password: await bcrypt.hash(password, 12),
      phone,
      verificationToken,
      verificationTokenExpires: Date.now() + 24 * 3600000,
      ipAddress: ip,
      location,
      userAgent
    });

    await newUser.save();

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email.html?token=${verificationToken}`;
    await sendEmail(
      email,
      'Verify Your Email - Joker Creation Studio',
      `<div style="font-family: Arial, sans-serif;">
        <h2 style="color: #be9c65;">Welcome to Joker Creation Studio</h2>
        <p>Hello ${name},</p>
        <p>Please verify your email by clicking the button below:</p>
        <a href="${verificationUrl}" 
           style="display: inline-block; padding: 12px 24px; background-color: #be9c65; color: white; 
                  text-decoration: none; border-radius: 4px; font-weight: bold;">
          Verify Email
        </a>
        <p>If you didn't create an account, please ignore this email.</p>
      </div>`
    );

    await sendEmail(
      process.env.ADMIN_EMAIL,
      'New User Signup',
      `<h2>New User Signup</h2>
       <p><strong>Name:</strong> ${name}</p>
       <p><strong>Email:</strong> ${email}</p>
       <p><strong>Phone:</strong> ${phone || 'Not provided'}</p>
       <p><strong>IP:</strong> ${ip}</p>
       <p><strong>Location:</strong> ${location.city}, ${location.region}, ${location.country}</p>`
    );

    res.status(201).json({ 
      success: true,
      message: 'Registration successful. Please check your email for verification.',
      userId: newUser._id
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during registration'
    });
  }
});

// Email Verification Endpoint
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token: verificationToken } = req.query;
    
    if (!verificationToken) {
      return res.status(400).json({ 
        success: false,
        message: 'Verification token is required'
      });
    }

    const user = await User.findOne({ 
      verificationToken: verificationToken,
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

    const authToken = generateJWT(user);

    // Return JSON response for API calls
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.json({
        success: true,
        message: 'Email verified successfully',
        token: authToken,
        userId: user._id
      });
    }

    // Redirect for browser requests
    res.redirect(`${process.env.FRONTEND_URL}/verify-email.html?success=true&token=${authToken}&userId=${user._id}`);

  } catch (error) {
    console.error('Email verification error:', error);
    
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(500).json({ 
        success: false,
        message: 'Email verification failed'
      });
    }
    
    res.redirect(`${process.env.FRONTEND_URL}/verify-email.html?success=false`);
  }
});

// Token Verification Middleware
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

// Protected Route Example
app.get('/api/user', authenticateUser, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      emailVerified: req.user.emailVerified,
      phone: req.user.phone
    }
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Frontend URL: ${process.env.FRONTEND_URL}`);
});
