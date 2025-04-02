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

// User Schema
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

// Helper Functions
const generateToken = () => crypto.randomBytes(32).toString('hex');
const generateJWT = (user) => jwt.sign(
  { userId: user._id, email: user.email }, 
  process.env.JWT_SECRET, 
  { expiresIn: '1h' }
);

// Email Transport
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

// SMS Verification (Mock - Replace with actual SMS service)
const sendSmsVerification = async (phone, code) => {
  console.log(`SMS verification code ${code} sent to ${phone}`);
  return true;
};

// Routes
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = generateToken();

    // Create new user
    const newUser = new User({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      phone,
      verificationToken,
      verificationTokenExpires: Date.now() + 24 * 3600000 // 24 hours
    });

    await newUser.save();
    
    // Send verification email
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

// Email Verification
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    
    const user = await User.findOne({ 
      verificationToken: token,
      verificationTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    // Mark email as verified
    user.emailVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    
    // If phone exists, send SMS verification
    if (user.phone) {
      const verificationCode = Math.floor(100000 + Math.random() * 900000);
      user.otp = verificationCode.toString();
      user.otpExpiration = Date.now() + 3600000; // 1 hour
      await sendSmsVerification(user.phone, verificationCode);
    }

    await user.save();

    res.status(200).json({ 
      success: true,
      requiresPhoneVerification: !!user.phone,
      message: user.phone 
        ? 'Email verified. Phone verification code sent.' 
        : 'Email verified successfully.'
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ message: 'Server error during email verification' });
  }
});

// Resend Verification Email
app.post('/api/resend-verification-email', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.emailVerified) {
      return res.status(400).json({ message: 'Email is already verified' });
    }

    // Generate new token
    const verificationToken = generateToken();
    user.verificationToken = verificationToken;
    user.verificationTokenExpires = Date.now() + 24 * 3600000;
    await user.save();

    await sendVerificationEmail(user.email, user.name, verificationToken);

    res.status(200).json({ message: 'Verification email resent successfully' });
  } catch (error) {
    console.error('Resend email error:', error);
    res.status(500).json({ message: 'Server error resending verification email' });
  }
});

// Facebook Login/Signup
app.post('/api/signup/facebook', async (req, res) => {
  try {
    const { accessToken } = req.body;
    
    // Verify Facebook token
    const { data } = await axios.get(
      `https://graph.facebook.com/v12.0/me?fields=id,name,email&access_token=${accessToken}`
    );

    const { id, name, email } = data;

    // Check if user exists
    let user = await User.findOne({ 
      $or: [
        { email: email.toLowerCase() },
        { 'socialAuth.id': id, 'socialAuth.provider': 'facebook' }
      ]
    });

    if (!user) {
      // Create new user
      user = new User({
        name,
        email: email.toLowerCase(),
        socialAuth: { provider: 'facebook', id },
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
    console.error('Facebook login error:', error);
    res.status(500).json({ message: 'Failed to authenticate with Facebook' });
  }
});

// Google Login/Signup
app.post('/api/signup/google', async (req, res) => {
  try {
    const { credential } = req.body;
    
    // Verify Google token
    const { data } = await axios.get(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`
    );

    const { sub: id, name, email } = data;

    // Check if user exists
    let user = await User.findOne({ 
      $or: [
        { email: email.toLowerCase() },
        { 'socialAuth.id': id, 'socialAuth.provider': 'google' }
      ]
    });

    if (!user) {
      // Create new user
      user = new User({
        name,
        email: email.toLowerCase(),
        socialAuth: { provider: 'google', id },
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
    console.error('Google login error:', error);
    res.status(500).json({ message: 'Failed to authenticate with Google' });
  }
});

// Complete Profile (for social signups)
app.post('/api/complete-profile', async (req, res) => {
  try {
    const { userId, name, phone } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update profile
    user.name = name || user.name;
    user.phone = phone;

    // Generate and send SMS verification
    const verificationCode = Math.floor(100000 + Math.random() * 900000);
    user.otp = verificationCode.toString();
    user.otpExpiration = Date.now() + 3600000; // 1 hour
    await user.save();

    await sendSmsVerification(phone, verificationCode);

    res.status(200).json({ 
      success: true,
      message: 'Profile updated. Verification code sent to your phone.'
    });
  } catch (error) {
    console.error('Complete profile error:', error);
    res.status(500).json({ message: 'Server error completing profile' });
  }
});

// Verify Phone Number
app.post('/api/verify-phone', async (req, res) => {
  try {
    const { userId, code } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if code matches and isn't expired
    if (!user.otp || !user.otpExpiration || 
        user.otp !== code || Date.now() > user.otpExpiration) {
      return res.status(400).json({ message: 'Invalid or expired verification code' });
    }

    // Mark phone as verified
    user.phoneVerified = true;
    user.otp = undefined;
    user.otpExpiration = undefined;
    await user.save();

    // Generate new JWT with updated claims
    const token = generateJWT(user);

    res.status(200).json({
      success: true,
      token,
      message: 'Phone number verified successfully'
    });
  } catch (error) {
    console.error('Phone verification error:', error);
    res.status(500).json({ message: 'Server error verifying phone number' });
  }
});

// Resend SMS Verification
app.post('/api/resend-sms-verification', async (req, res) => {
  try {
    const { userId } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.phone) {
      return res.status(400).json({ message: 'No phone number provided' });
    }

    if (user.phoneVerified) {
      return res.status(400).json({ message: 'Phone number already verified' });
    }

    // Generate new code
    const verificationCode = Math.floor(100000 + Math.random() * 900000);
    user.otp = verificationCode.toString();
    user.otpExpiration = Date.now() + 3600000; // 1 hour
    await user.save();

    await sendSmsVerification(user.phone, verificationCode);

    res.status(200).json({ 
      success: true,
      message: 'Verification code resent to your phone'
    });
  } catch (error) {
    console.error('Resend SMS error:', error);
    res.status(500).json({ message: 'Server error resending verification code' });
  }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
