require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const axios = require('axios'); // For social login verification

// Create the Express app
const app = express();

// Middleware
app.use(cors({ origin: process.env.CORS_ORIGIN || 'https://jokercreation.store' }));
app.use(bodyParser.json());

// MongoDB connection setup
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.log('Error connecting to MongoDB:', err));

// Enhanced MongoDB Schema for Users
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String },
  name: { type: String, required: true },
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
    provider: { type: String }, // 'facebook' or 'google'
    id: { type: String }
  }
});

const User = mongoose.model('User', userSchema);

// Helper function to generate JWT token
const generateJWT = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email, name: user.name },
    process.env.JWT_SECRET_KEY,
    { expiresIn: '1h' }
  );
};

// Middleware to verify JWT token
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ message: 'Authentication failed, token missing.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Authentication failed, invalid token.' });
  }
};

// Generate random token for email verification
const generateVerificationToken = () => {
  return require('crypto').randomBytes(32).toString('hex');
};

// Send verification email
const sendVerificationEmail = async (email, name, token) => {
  let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Verify Your Email Address',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Email Verification</h2>
        <p>Hello ${name},</p>
        <p>Please click the button below to verify your email address:</p>
        <a href="${verificationUrl}" 
           style="display: inline-block; padding: 10px 20px; background-color: #be9c65; color: white; text-decoration: none; border-radius: 4px;">
          Verify Email
        </a>
        <p>If you didn't create an account, please ignore this email.</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
};

// Send SMS verification code (mock - integrate with real SMS service)
const sendSmsVerification = async (phoneNumber, code) => {
  console.log(`Sending SMS verification code ${code} to ${phoneNumber}`);
  // In production, integrate with Twilio or similar service
  return true;
};

// Signup Route with Email Verification
app.post('/api/signup', async (req, res) => {
  const { email, password, name, phone } = req.body;
  const lowercaseEmail = email.toLowerCase();

  try {
    const existingUser = await User.findOne({ email: lowercaseEmail });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = generateVerificationToken();
    const verificationTokenExpires = Date.now() + 24 * 3600000; // 24 hours

    const newUser = new User({
      email: lowercaseEmail,
      password: hashedPassword,
      name,
      phone,
      verificationToken,
      verificationTokenExpires
    });

    await newUser.save();
    
    // Send verification email
    await sendVerificationEmail(lowercaseEmail, name, verificationToken);
    
    res.status(200).json({ 
      success: true,
      userId: newUser._id,
      message: 'User registered successfully. Please check your email for verification.' 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Verify Email Route
app.get('/api/verify-email', async (req, res) => {
  const { token } = req.query;

  try {
    const user = await User.findOne({ 
      verificationToken: token,
      verificationTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification token.' });
    }

    user.emailVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();

    // Send SMS verification if phone number exists
    if (user.phone) {
      const verificationCode = Math.floor(100000 + Math.random() * 900000);
      user.otp = verificationCode;
      user.otpExpiration = Date.now() + 3600000; // 1 hour
      await user.save();
      
      await sendSmsVerification(user.phone, verificationCode);
      
      return res.status(200).json({ 
        success: true,
        message: 'Email verified successfully. Please check your phone for verification code.',
        requiresPhoneVerification: true
      });
    }

    res.status(200).json({ 
      success: true,
      message: 'Email verified successfully.' 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Resend Verification Email
app.post('/api/resend-verification-email', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (user.emailVerified) {
      return res.status(400).json({ message: 'Email is already verified.' });
    }

    const verificationToken = generateVerificationToken();
    user.verificationToken = verificationToken;
    user.verificationTokenExpires = Date.now() + 24 * 3600000; // 24 hours
    await user.save();

    await sendVerificationEmail(user.email, user.name, verificationToken);
    
    res.status(200).json({ message: 'Verification email resent successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Facebook Signup/Login
app.post('/api/signup/facebook', async (req, res) => {
  const { accessToken } = req.body;

  try {
    // Verify Facebook access token
    const response = await axios.get(
      `https://graph.facebook.com/v12.0/me?fields=id,name,email&access_token=${accessToken}`
    );

    const { id, name, email } = response.data;

    // Check if user already exists
    let user = await User.findOne({ $or: [
      { email },
      { 'socialAuth.id': id, 'socialAuth.provider': 'facebook' }
    ]});

    if (user) {
      // Update last login and generate token
      user.lastLogin = Date.now();
      await user.save();
      
      const token = generateJWT(user);
      return res.status(200).json({
        success: true,
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          emailVerified: user.emailVerified,
          phoneVerified: user.phoneVerified
        }
      });
    }

    // Create new user
    user = new User({
      email,
      name,
      socialAuth: {
        provider: 'facebook',
        id
      },
      emailVerified: true // Facebook verifies emails
    });

    await user.save();

    const token = generateJWT(user);
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        emailVerified: user.emailVerified,
        phoneVerified: user.phoneVerified
      },
      requiresProfileCompletion: !user.phone
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to authenticate with Facebook.' });
  }
});

// Google Signup/Login
app.post('/api/signup/google', async (req, res) => {
  const { credential } = req.body;

  try {
    // Verify Google ID token
    const response = await axios.get(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`
    );

    const { sub: id, name, email } = response.data;

    // Check if user already exists
    let user = await User.findOne({ $or: [
      { email },
      { 'socialAuth.id': id, 'socialAuth.provider': 'google' }
    ]});

    if (user) {
      // Update last login and generate token
      user.lastLogin = Date.now();
      await user.save();
      
      const token = generateJWT(user);
      return res.status(200).json({
        success: true,
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          emailVerified: user.emailVerified,
          phoneVerified: user.phoneVerified
        }
      });
    }

    // Create new user
    user = new User({
      email,
      name,
      socialAuth: {
        provider: 'google',
        id
      },
      emailVerified: true // Google verifies emails
    });

    await user.save();

    const token = generateJWT(user);
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        emailVerified: user.emailVerified,
        phoneVerified: user.phoneVerified
      },
      requiresProfileCompletion: !user.phone
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to authenticate with Google.' });
  }
});

// Complete Profile (for social signups)
app.post('/api/complete-profile', authenticate, async (req, res) => {
  const { fullName, mobileNumber } = req.body;

  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    user.name = fullName || user.name;
    user.phone = mobileNumber;

    // Generate and send SMS verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000);
    user.otp = verificationCode;
    user.otpExpiration = Date.now() + 3600000; // 1 hour
    await user.save();

    await sendSmsVerification(mobileNumber, verificationCode);

    res.status(200).json({ 
      success: true,
      message: 'Profile updated successfully. Verification code sent to your phone.' 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Send SMS Verification Code
app.post('/api/send-sms-verification', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (!user.phone) {
      return res.status(400).json({ message: 'Phone number not provided.' });
    }

    if (user.phoneVerified) {
      return res.status(400).json({ message: 'Phone number already verified.' });
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000);
    user.otp = verificationCode;
    user.otpExpiration = Date.now() + 3600000; // 1 hour
    await user.save();

    await sendSmsVerification(user.phone, verificationCode);

    res.status(200).json({ 
      success: true,
      message: 'Verification code sent to your phone.' 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Verify Phone Number
app.post('/api/verify-phone', authenticate, async (req, res) => {
  const { verificationCode } = req.body;

  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (user.phoneVerified) {
      return res.status(400).json({ message: 'Phone number already verified.' });
    }

    if (!user.otp || !user.otpExpiration) {
      return res.status(400).json({ message: 'No verification code requested.' });
    }

    if (Date.now() > user.otpExpiration) {
      return res.status(400).json({ message: 'Verification code expired.' });
    }

    if (user.otp !== verificationCode) {
      return res.status(400).json({ message: 'Invalid verification code.' });
    }

    user.phoneVerified = true;
    user.otp = undefined;
    user.otpExpiration = undefined;
    await user.save();

    res.status(200).json({ 
      success: true,
      message: 'Phone number verified successfully.' 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Keep all your existing routes below this line (Login, Account, Forgot Password, etc.)
// ... [All your existing routes remain unchanged]

// Server listener
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
