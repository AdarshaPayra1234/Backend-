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

// Validate critical environment variables
const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'FRONTEND_URL', 'EMAIL_USER', 'EMAIL_PASS'];
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

// Middleware to parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// Enhanced User Schema with verification tracking
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String },
  googleId: { type: String },
  phone: { type: String },
  emailVerified: { type: Boolean, default: false },
  phoneVerified: { type: Boolean, default: false },
  verificationToken: { type: String },
  verificationTokenExpires: { type: Date },
  otp: { type: String },
  otpExpiration: { type: Date },
  emailVerificationAttempts: { type: Number, default: 0 },
  lastEmailVerificationAttempt: { type: Date },
  phoneVerificationAttempts: { type: Number, default: 0 },
  lastPhoneVerificationAttempt: { type: Date },
  lastLogin: { type: Date, default: Date.now }
}, { timestamps: true });

// Add indexes for better performance
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ googleId: 1 });
userSchema.index({ verificationToken: 1 });
userSchema.index({ otp: 1 });

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
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const generateJWT = (user) => {
  return jwt.sign(
    {
      userId: user._id,
      email: user.email,
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneVerified,
      iss: 'jokercreation-store-api',
      aud: 'jokercreation-store-client'
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h', algorithm: 'HS256' }
  );
};

// Enhanced Send Verification Email with HTML template
const sendVerificationEmail = async (email, name, token) => {
  const verificationUrl = `${process.env.FRONTEND_URL}/verify-email.html?token=${token}`;
  
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

// Enhanced SMS Verification (Mock - Replace with actual SMS service)
const sendSmsVerification = async (phone, code) => {
  console.log(`SMS verification code ${code} sent to ${phone}`);
  // In production, integrate with SMS service like Twilio
  return true;
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
    const { credential } = req.body;
    
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
          lastLogin: new Date()
        }
      },
      { upsert: true, new: true }
    );

    const token = generateJWT(user);

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        phone: user.phone,
        phoneVerified: user.phoneVerified
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
    const { name, email, password, phone } = req.body;
    
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
      lastEmailVerificationAttempt: new Date()
    });

    await newUser.save();
    await sendVerificationEmail(email, name, verificationToken);

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
// In your backend routes
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
            requiresPhoneVerification: !user.phoneVerified,
            user: {
                id: user._id,
                emailVerified: true,
                phoneVerified: user.phoneVerified
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

// Email Verification Endpoint
// Email Verification Endpoint
// In your backend (app.js)
app.get('/api/verify-email', async (req, res) => {
    try {
        const { token } = req.query;
        
        // Verify token and update user
        const user = await User.findOneAndUpdate(
            { verificationToken: token },
            { $set: { emailVerified: true, verificationToken: null } },
            { new: true }
        );

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid token' });
        }

        // Return user data including phone number
        res.json({
            success: true,
            message: 'Email verified successfully',
            user: {
                id: user._id,
                email: user.email,
                phone: user.phone,
                emailVerified: true,
                phoneVerified: user.phoneVerified
            }
        });

    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Send OTP endpoint
app.post('/api/send-phone-verification', async (req, res) => {
    try {
        const { userId, phone } = req.body;
        
        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiration = new Date(Date.now() + 5 * 60000); // 5 minutes expiry
        
        // Save OTP to user in database
        await User.findByIdAndUpdate(userId, {
            otp,
            otpExpiration
        });

        // In production: Actually send SMS using Twilio/other service
        console.log(`OTP for ${phone}: ${otp}`); // For testing
        
        res.json({ 
            success: true,
            message: 'OTP sent successfully'
        });

    } catch (error) {
        res.status(500).json({ 
            success: false,
            message: 'Failed to send OTP'
        });
    }
});

// Verify OTP endpoint
app.post('/api/verify-phone', async (req, res) => {
    try {
        const { userId, code } = req.body;
        
        const user = await User.findOne({
            _id: userId,
            otp: code,
            otpExpiration: { $gt: new Date() }
        });

        if (!user) {
            return res.status(400).json({ 
                success: false,
                message: 'Invalid or expired OTP'
            });
        }

        // Mark phone as verified
        await User.findByIdAndUpdate(userId, {
            phoneVerified: true,
            otp: null,
            otpExpiration: null
        });

        res.json({ 
            success: true,
            message: 'Phone verified successfully'
        });

    } catch (error) {
        res.status(500).json({ 
            success: false,
            message: 'Verification failed'
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

// Send Phone Verification with Limits
app.post('/api/send-phone-verification', verificationLimiter, async (req, res) => {
  try {
    const { userId, phone } = req.body;
    
    if (!userId || !phone) {
      return res.status(400).json({
        success: false,
        message: 'User ID and phone number are required'
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found'
      });
    }

    // Check phone attempt limits (3 per day)
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    
    if (user.lastPhoneVerificationAttempt > oneDayAgo && 
        user.phoneVerificationAttempts >= 3) {
      return res.status(429).json({ 
        success: false,
        message: 'Phone verification limit reached (3 per day)',
        nextAttemptAllowed: new Date(user.lastPhoneVerificationAttempt.getTime() + 24 * 60 * 60 * 1000)
      });
    }

    // Check 1-minute cooldown between attempts
    const oneMinuteAgo = new Date(now.getTime() - 60 * 1000);
    if (user.lastPhoneVerificationAttempt > oneMinuteAgo) {
      return res.status(429).json({ 
        success: false,
        message: 'Please wait 1 minute before requesting another verification code',
        nextAttemptAllowed: new Date(user.lastPhoneVerificationAttempt.getTime() + 60 * 1000)
      });
    }

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpiration = Date.now() + 3600000; // 1 hour expiration
    
    // Update attempt tracking
    if (user.lastPhoneVerificationAttempt <= oneDayAgo) {
      user.phoneVerificationAttempts = 1;
    } else {
      user.phoneVerificationAttempts += 1;
    }
    user.lastPhoneVerificationAttempt = now;
    
    await user.save();
    await sendSmsVerification(phone, otp);

    res.json({ 
      success: true,
      message: 'Verification code sent to your phone',
      attemptsRemaining: 3 - user.phoneVerificationAttempts,
      nextAttemptAllowed: new Date(now.getTime() + 60 * 1000) // 1 minute cooldown
    });

  } catch (error) {
    console.error('Phone verification error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to send verification code'
    });
  }
});

// Verify Phone OTP
app.post('/api/verify-phone', verificationLimiter, async (req, res) => {
  try {
    const { userId, code } = req.body;
    
    if (!userId || !code) {
      return res.status(400).json({
        success: false,
        message: 'User ID and verification code are required'
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found'
      });
    }

    if (!user.otp || user.otp !== code || Date.now() > user.otpExpiration) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired verification code'
      });
    }

    user.phoneVerified = true;
    user.otp = undefined;
    user.otpExpiration = undefined;
    await user.save();

    const token = generateJWT(user);

    res.json({
      success: true,
      token,
      message: 'Phone number verified successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        phone: user.phone,
        phoneVerified: user.phoneVerified
      }
    });

  } catch (error) {
    console.error('Phone verification error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during phone verification'
    });
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
// Add this to your backend routes
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
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`CORS configured for: ${process.env.FRONTEND_URL}`);
});
