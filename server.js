require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const axios = require('axios');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const app = express();

// Middleware
app.use(cors({ 
  origin: process.env.CORS_ORIGIN || 'https://jokercreation.store',
  credentials: true
}));
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Initialize Google OAuth Client
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET
});

// User Schema (unchanged)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String },
  phone: { type: String },
  status: { type: String, default: 'Active' },
  lastLogin: { type: Date, default: Date.now },
  otp: { type: String },
  otpExpiration: { type: Date },
  emailVerified: { type: Boolean, default: false },
  phoneVerified: { type: Boolean, default: false },
  verificationToken: { type: String },
  verificationTokenExpires: { type: Date },
  socialAuth: {
    provider: { type: String },
    id: { type: String }
  }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Helper Functions (unchanged)
const generateToken = () => crypto.randomBytes(32).toString('hex');
const generateJWT = (user) => jwt.sign(
  { userId: user._id, email: user.email }, 
  process.env.JWT_SECRET, 
  { expiresIn: '1h' }
);

// Email Transport (unchanged)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const sendVerificationEmail = async (email, name, token) => {
  const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
  
  await transporter.sendMail({
    from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verify Your Email Address',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #be9c65;">Welcome to Joker Creation Studio</h2>
        <p>Hello ${name},</p>
        <p>Please click the button below to verify your email address:</p>
        <a href="${verificationUrl}" 
           style="display: inline-block; padding: 10px 20px; background-color: #be9c65; color: white; text-decoration: none; border-radius: 4px;">
          Verify Email
        </a>
        <p>If you didn't create an account, please ignore this email.</p>
      </div>
    `
  });
};

// SMS Verification (unchanged)
const sendSmsVerification = async (phone, code) => {
  console.log(`SMS verification code ${code} sent to ${phone}`);
  return true;
};

// Routes

// Regular Signup (unchanged)
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = generateToken();

    const newUser = new User({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      phone,
      verificationToken,
      verificationTokenExpires: Date.now() + 24 * 3600000
    });

    await newUser.save();
    await sendVerificationEmail(email, name, verificationToken);

    res.status(201).json({ 
      success: true,
      userId: newUser._id,
      message: 'Registration successful. Please check your email for verification.'
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Improved Google Signup
app.post('/api/signup/google', async (req, res) => {
  try {
    const { credential } = req.body;
    
    if (!credential) {
      return res.status(400).json({ 
        success: false,
        message: 'No credential provided'
      });
    }

    // Verify the Google ID token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    console.log('Google payload:', payload);

    // Validate required fields
    if (!payload.email || !payload.email_verified) {
      return res.status(400).json({ 
        success: false,
        message: 'Google email not verified' 
      });
    }

    // Check token audience matches your client ID
    if (!payload.aud.includes(process.env.GOOGLE_CLIENT_ID)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid token audience' 
      });
    }

    // Check if user exists
    let user = await User.findOne({ 
      $or: [
        { email: payload.email.toLowerCase() },
        { 'socialAuth.id': payload.sub, 'socialAuth.provider': 'google' }
      ]
    });

    if (!user) {
      // Create new user
      user = new User({
        name: payload.name,
        email: payload.email.toLowerCase(),
        socialAuth: { provider: 'google', id: payload.sub },
        emailVerified: true
      });
      await user.save();
    }

    // Update last login
    user.lastLogin = Date.now();
    await user.save();

    // Generate JWT
    const token = generateJWT(user);

    res.status(200).json({
      success: true,
      token,
      userId: user._id,
      requiresProfileCompletion: !user.phone,
      user: {
        name: user.name,
        email: user.email,
        phone: user.phone,
        emailVerified: user.emailVerified,
        phoneVerified: user.phoneVerified
      }
    });

  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to authenticate with Google',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// All other existing routes remain unchanged
// Facebook Signup
app.post('/api/signup/facebook', async (req, res) => {
  /* ... existing code ... */
});

// Email Verification
app.get('/api/verify-email', async (req, res) => {
  /* ... existing code ... */
});

// Resend Verification Email
app.post('/api/resend-verification-email', async (req, res) => {
  /* ... existing code ... */
});

// Complete Profile
app.post('/api/complete-profile', async (req, res) => {
  /* ... existing code ... */
});

// Verify Phone Number
app.post('/api/verify-phone', async (req, res) => {
  /* ... existing code ... */
});

// Resend SMS Verification
app.post('/api/resend-sms-verification', async (req, res) => {
  /* ... existing code ... */
});

// Health Check
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
