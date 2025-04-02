require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const requestIp = require('request-ip');
const geoip = require('geoip-lite');
const session = require('express-session');

// Validate ALL required environment variables
const requiredEnvVars = [
  'MONGO_URI', 'JWT_SECRET', 'GOOGLE_CLIENT_ID', 
  'GOOGLE_CLIENT_SECRET', 'FRONTEND_URL', 
  'EMAIL_USER', 'EMAIL_PASS', 'ADMIN_EMAIL',
  'FACEBOOK_APP_ID', 'FACEBOOK_APP_SECRET',
  'SESSION_SECRET', 'BACKEND_URL'
];

requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    throw new Error(`Missing required environment variable: ${varName}`);
  }
});

const app = express();

// Middleware Setup
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(express.json());
app.use(requestIp.mw());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Database Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema (with ALL your required fields)
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

// Email Configuration (using your Gmail)
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

// ========================
// PASSPORT CONFIGURATION
// ========================

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Facebook Strategy
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: `${process.env.BACKEND_URL}/auth/facebook/callback`,
  profileFields: ['id', 'emails', 'name', 'displayName']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ facebookId: profile.id });
    
    if (!user) {
      user = new User({
        name: profile.displayName,
        email: profile.emails?.[0]?.value || `${profile.id}@facebook.com`,
        facebookId: profile.id,
        emailVerified: true
      });
      await user.save();
    }
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

// ========================
// ROUTES IMPLEMENTATION
// ========================

// 1. Facebook Authentication Routes
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  async (req, res) => {
    try {
      const ip = req.clientIp;
      const location = getLocationFromIp(ip);
      const userAgent = req.headers['user-agent'];

      const user = await User.findByIdAndUpdate(req.user._id, {
        ipAddress: ip,
        location,
        userAgent,
        lastLogin: new Date()
      }, { new: true });

      const token = generateJWT(user);

      // Admin notification
      await sendEmail(
        process.env.ADMIN_EMAIL,
        'New Facebook Login',
        `<h2>Facebook Login Notification</h2>
         <p><strong>User:</strong> ${user.name}</p>
         <p><strong>Email:</strong> ${user.email}</p>
         <p><strong>IP:</strong> ${ip}</p>
         <p><strong>Location:</strong> ${location.city}, ${location.region}, ${location.country}</p>
         <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>`
      );

      res.redirect(`${process.env.FRONTEND_URL}/auth-callback?token=${token}`);
    } catch (error) {
      console.error('Facebook callback error:', error);
      res.redirect(`${process.env.FRONTEND_URL}/login?error=facebook_auth_failed`);
    }
  }
);

// 2. Google Authentication (your existing implementation)
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET
});

app.post('/api/signup/google', async (req, res) => {
  try {
    const { credential, userAgent } = req.body;
    const ip = req.clientIp;
    const location = getLocationFromIp(ip);

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

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

    // Admin notification
    await sendEmail(
      process.env.ADMIN_EMAIL,
      'New Google Signup',
      `<h2>Google Signup Notification</h2>
       <p><strong>User:</strong> ${user.name}</p>
       <p><strong>Email:</strong> ${user.email}</p>
       <p><strong>IP:</strong> ${ip}</p>
       <p><strong>Location:</strong> ${location.city}, ${location.region}, ${location.country}</p>
       <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>`
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
      message: 'Google authentication failed'
    });
  }
});

// 3. Email Verification (using your exact URL)
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    
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

    user.emailVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();

    const authToken = generateJWT(user);

    // Redirect to your specific verification page
    res.redirect(`https://jokercreation.store/verify-email.html?token=${authToken}&success=true`);
  } catch (error) {
    console.error('Email verification error:', error);
    res.redirect('https://jokercreation.store/verify-email.html?success=false');
  }
});

// 4. Regular Email Signup (with phone number)
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    const ip = req.clientIp;
    const location = getLocationFromIp(ip);
    const userAgent = req.headers['user-agent'];

    // Input validation
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Name, email and password are required'
      });
    }

    // Check existing user
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        message: 'Email already registered'
      });
    }

    // Create new user
    const verificationToken = generateToken();
    const newUser = new User({
      name,
      email: email.toLowerCase(),
      password: await bcrypt.hash(password, 12),
      phone,
      verificationToken,
      verificationTokenExpires: Date.now() + 24 * 3600000, // 24 hours
      ipAddress: ip,
      location,
      userAgent
    });

    await newUser.save();

    // Send verification email with YOUR SPECIFIC URL
    const verificationUrl = `https://jokercreation.store/verify-email.html?token=${verificationToken}`;
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

    // Admin notification
    await sendEmail(
      process.env.ADMIN_EMAIL,
      'New User Signup',
      `<h2>New User Signup Notification</h2>
       <p><strong>Name:</strong> ${name}</p>
       <p><strong>Email:</strong> ${email}</p>
       <p><strong>Phone:</strong> ${phone || 'Not provided'}</p>
       <p><strong>IP:</strong> ${ip}</p>
       <p><strong>Location:</strong> ${location.city}, ${location.region}, ${location.country}</p>
       <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>`
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

// Add other routes (login, profile, etc.) as needed...

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Frontend: ${process.env.FRONTEND_URL}`);
  console.log(`Backend: ${process.env.BACKEND_URL}`);
});
