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
  'EMAIL_USER', 'EMAIL_PASS', 'ADMIN_EMAIL', 'ADMIN_SECRET_KEY',
  'SUPER_ADMIN_FINGERPRINT' // Added for fingerprint verification
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
  resetPasswordOtp: { type: String },
  ipAddress: { type: String },
  location: {
    country: { type: String },
    region: { type: String },
    city: { type: String },
    timezone: { type: String }
  },
  userAgent: { type: String },
  lastLogin: { type: Date },
  isAdmin: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  fingerprint: { type: String }, // Added for fingerprint authentication
  isSuperAdmin: { type: Boolean, default: false } // Added for super admin distinction
}, { timestamps: true });

// Booking Schema (Added for bookings management)
const bookingSchema = new mongoose.Schema({
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  customerName: { type: String, required: true },
  customerEmail: { type: String, required: true },
  package: { type: String, required: true },
  bookingDates: { type: String, required: true },
  status: { type: String, enum: ['pending', 'confirmed', 'cancelled'], default: 'pending' },
  notes: { type: String },
  createdAt: { type: Date, default: Date.now }
});

// Message Schema (Added for admin messaging system)
const messageSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userEmail: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Booking = mongoose.model('Booking', bookingSchema); // Added
const Message = mongoose.model('Message', messageSchema); // Added

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

const generateOTP = () => {
  // Generate a 6-digit numeric OTP
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const generateJWT = (user) => {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      verified: user.emailVerified,
      isAdmin: user.isAdmin,
      isSuperAdmin: user.isSuperAdmin // Added
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

const initializeAdminUser = async () => {
  try {
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_SECRET_KEY;
    
    if (!adminEmail || !adminPassword) {
      throw new Error('Admin credentials not configured in environment variables');
    }

    const existingAdmin = await User.findOne({ email: adminEmail });
    
    if (!existingAdmin) {
      // Create new admin user with super admin privileges
      const hashedPassword = await bcrypt.hash(adminPassword, 12);
      const adminUser = new User({
        name: 'Admin',
        email: adminEmail,
        password: hashedPassword,
        emailVerified: true,
        isAdmin: true,
        isSuperAdmin: true, // Mark as super admin
        isActive: true,
        fingerprint: process.env.SUPER_ADMIN_FINGERPRINT // Set super admin fingerprint
      });
      
      await adminUser.save();
      console.log('Super admin user created successfully');
    } else {
      // Update existing admin user if needed
      let needsUpdate = false;
      
      if (!existingAdmin.isAdmin) {
        existingAdmin.isAdmin = true;
        needsUpdate = true;
        console.log('Existing user promoted to admin');
      }
      
      if (!existingAdmin.isSuperAdmin) {
        existingAdmin.isSuperAdmin = true;
        needsUpdate = true;
        console.log('Existing admin promoted to super admin');
      }
      
      if (!existingAdmin.password) {
        const hashedPassword = await bcrypt.hash(adminPassword, 12);
        existingAdmin.password = hashedPassword;
        needsUpdate = true;
        console.log('Admin password set');
      }
      
      if (!existingAdmin.fingerprint) {
        existingAdmin.fingerprint = process.env.SUPER_ADMIN_FINGERPRINT;
        needsUpdate = true;
        console.log('Admin fingerprint set');
      }
      
      if (needsUpdate) {
        await existingAdmin.save();
      }
    }
  } catch (error) {
    console.error('Error initializing admin user:', error);
    // Exit if admin initialization fails
    process.exit(1);
  }
};

// Call the function to initialize admin user when server starts
initializeAdminUser();

// =============================================
// ADMIN ROUTES
// =============================================

// Middleware to verify admin status
const authenticateAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      return res.status(401).json({ 
        success: false,
        message: 'Authorization header missing'
      });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: 'Authorization token missing'
      });
    }

    // Verify token with proper error handling
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ 
        success: false,
        message: 'Invalid or expired token',
        error: err.message
      });
    }

    const user = await User.findById(decoded.id);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ 
        success: false,
        message: 'Admin access required'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error during authentication'
    });
  }
};

// Middleware to verify super admin status
const authenticateSuperAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      return res.status(401).json({ 
        success: false,
        message: 'Authorization header missing'
      });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: 'Authorization token missing'
      });
    }

    // Verify token with proper error handling
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ 
        success: false,
        message: 'Invalid or expired token',
        error: err.message
      });
    }

    const user = await User.findById(decoded.id);
    if (!user || !user.isSuperAdmin) {
      return res.status(403).json({ 
        success: false,
        message: 'Super admin access required'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Super admin authentication error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error during authentication'
    });
  }
};

// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user with case-insensitive email
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if user has a password (might be OAuth user)
    if (!user.password) {
      return res.status(401).json({ 
        success: false,
        message: 'This account uses social login. Please use the appropriate login method.'
      });
    }

    // Compare passwords with proper error handling
    let isMatch;
    try {
      isMatch = await bcrypt.compare(password, user.password);
    } catch (err) {
      console.error('Password comparison error:', err);
      return res.status(500).json({ 
        success: false,
        message: 'Error during authentication'
      });
    }

    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check admin status
    if (!user.isAdmin) {
      return res.status(403).json({ 
        success: false,
        message: 'Admin access not granted for this account'
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = generateJWT(user);

    // Return success response
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isAdmin: user.isAdmin,
        isSuperAdmin: user.isSuperAdmin
      }
    });

  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during login'
    });
  }
});

// Admin registration endpoint
app.post('/api/admin/register', authenticateSuperAdmin, async (req, res) => {
  try {
    const { name, email, password, fingerprint, isSuperAdmin } = req.body;
    
    // Validate input
    if (!name || !email || !password || !fingerprint) {
      return res.status(400).json({ 
        success: false,
        message: 'Name, email, password and fingerprint are required'
      });
    }

    // Check if email already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        message: 'Email already registered'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create new admin user
    const newAdmin = new User({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      fingerprint,
      emailVerified: true,
      isAdmin: true,
      isSuperAdmin: !!isSuperAdmin,
      isActive: true
    });

    await newAdmin.save();

    // Send welcome email
    await sendEmail(
      email,
      'Welcome to Joker Creation Studio Admin Panel',
      `<div style="font-family: Arial, sans-serif;">
        <h2 style="color: #be9c65;">Admin Account Created</h2>
        <p>Hello ${name},</p>
        <p>Your admin account for Joker Creation Studio has been successfully created.</p>
        <p>You can now login to the admin panel using your credentials.</p>
        <p>If you did not request this account, please contact the super admin immediately.</p>
      </div>`
    );

    res.status(201).json({
      success: true,
      message: 'Admin registered successfully',
      admin: {
        id: newAdmin._id,
        name: newAdmin.name,
        email: newAdmin.email,
        isSuperAdmin: newAdmin.isSuperAdmin
      }
    });

  } catch (error) {
    console.error('Admin registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Error registering admin'
    });
  }
});

// Verify fingerprint endpoint (for admin registration)
app.post('/api/admin/verify-fingerprint', authenticateAdmin, async (req, res) => {
  try {
    const { fingerprint } = req.body;
    
    if (!fingerprint) {
      return res.status(400).json({ 
        success: false,
        message: 'Fingerprint data is required'
      });
    }

    // In a real application, you would verify the fingerprint against stored data
    // For this example, we'll check against the super admin fingerprint
    const superAdmin = await User.findOne({ isSuperAdmin: true });
    
    if (!superAdmin) {
      return res.status(403).json({ 
        success: false,
        message: 'Super admin not found'
      });
    }

    // Compare fingerprints (in a real app, use proper biometric verification)
    const isMatch = fingerprint === superAdmin.fingerprint;

    if (!isMatch) {
      return res.status(403).json({ 
        success: false,
        message: 'Fingerprint verification failed'
      });
    }

    res.json({
      success: true,
      message: 'Fingerprint verified successfully'
    });

  } catch (error) {
    console.error('Fingerprint verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Error verifying fingerprint'
    });
  }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '', sort = '-createdAt', filter } = req.query;
    
    // Build query based on filter
    const query = {
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } }
      ]
    };

    // Apply filters if provided
    if (filter === 'admin') {
      query.isAdmin = true;
    } else if (filter === 'active') {
      query.isActive = true;
    } else if (filter === 'inactive') {
      query.isActive = false;
    } else if (filter === 'verified') {
      query.emailVerified = true;
    } else if (filter === 'unverified') {
      query.emailVerified = false;
    }

    const users = await User.find(query)
      .sort(sort)
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp -fingerprint');

    const total = await User.countDocuments(query);

    res.json({
      success: true,
      users,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching users'
    });
  }
});

// Get user details (admin only)
app.get('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp -fingerprint');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      user
    });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user'
    });
  }
});

// Create new user (admin only)
app.post('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { name, email, password, phone, isAdmin } = req.body;
    
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

    const newUser = new User({
      name,
      email: email.toLowerCase(),
      password: await bcrypt.hash(password, 12),
      phone,
      emailVerified: true,
      isAdmin: !!isAdmin
    });

    await newUser.save();

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        phone: newUser.phone,
        isAdmin: newUser.isAdmin,
        createdAt: newUser.createdAt
      }
    });

  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating user'
    });
  }
});

// Update user (admin only)
app.put('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { name, email, phone, isAdmin, isActive, emailVerified } = req.body;
    
    const updates = {};
    if (name) updates.name = name;
    if (email) updates.email = email.toLowerCase();
    if (phone) updates.phone = phone;
    if (typeof isAdmin !== 'undefined') updates.isAdmin = isAdmin;
    if (typeof isActive !== 'undefined') updates.isActive = isActive;
    if (typeof emailVerified !== 'undefined') updates.emailVerified = emailVerified;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp -fingerprint');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'User updated successfully',
      user
    });

  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating user'
    });
  }
});

// Delete user (admin only)
app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'User deleted successfully'
    });

  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting user'
    });
  }
});

// Reset user password (admin only)
app.post('/api/admin/users/:id/reset-password', authenticateAdmin, async (req, res) => {
  try {
    const { newPassword } = req.body;
    
    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ 
        success: false,
        message: 'New password must be at least 8 characters'
      });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found'
      });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    // Send email notification to user
    await sendEmail(
      user.email,
      'Your Password Has Been Reset - Joker Creation Studio',
      `<div style="font-family: Arial, sans-serif;">
        <h2 style="color: #be9c65;">Password Reset Notification</h2>
        <p>Hello ${user.name},</p>
        <p>Your account password has been reset by an administrator.</p>
        <p>If you did not request this change, please contact us immediately.</p>
      </div>`
    );

    res.json({
      success: true,
      message: 'Password reset successfully'
    });

  } catch (error) {
    console.error('Admin password reset error:', error);
    res.status(500).json({
      success: false,
      message: 'Error resetting password'
    });
  }
});

// Deactivate user (admin only)
app.post('/api/admin/users/:id/deactivate', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { isActive: false } },
      { new: true }
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp -fingerprint');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'User deactivated successfully',
      user
    });

  } catch (error) {
    console.error('Deactivate user error:', error);
    res.status(500).json({
      success: false,
      message: 'Error deactivating user'
    });
  }
});

// Activate user (admin only)
app.post('/api/admin/users/:id/activate', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { isActive: true } },
      { new: true }
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp -fingerprint');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'User activated successfully',
      user
    });

  } catch (error) {
    console.error('Activate user error:', error);
    res.status(500).json({
      success: false,
      message: 'Error activating user'
    });
  }
});

// Make user admin (admin only)
app.post('/api/admin/users/:id/make-admin', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { isAdmin: true } },
      { new: true }
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp -fingerprint');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'User promoted to admin successfully',
      user
    });

  } catch (error) {
    console.error('Make admin error:', error);
    res.status(500).json({
      success: false,
      message: 'Error making user admin'
    });
  }
});

// Remove admin privileges (admin only)
app.post('/api/admin/users/:id/remove-admin', authenticateAdmin, async (req, res) => {
  try {
    // Prevent removing admin from self
    if (req.params.id === req.user._id.toString()) {
      return res.status(400).json({
        success: false,
        message: 'You cannot remove admin privileges from yourself'
      });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { isAdmin: false } },
      { new: true }
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp -fingerprint');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Admin privileges removed successfully',
      user
    });

  } catch (error) {
    console.error('Remove admin error:', error);
    res.status(500).json({
      success: false,
      message: 'Error removing admin privileges'
    });
  }
});

// Verify user email (admin only)
app.post('/api/admin/users/:id/verify-email', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { 
        $set: { emailVerified: true },
        $unset: { verificationToken: 1, verificationTokenExpires: 1 }
      },
      { new: true }
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp -fingerprint');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Email verified successfully',
      user
    });

  } catch (error) {
    console.error('Verify email error:', error);
    res.status(500).json({
      success: false,
      message: 'Error verifying email'
    });
  }
});

// Get user statistics (admin only)
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ emailVerified: true });
    const googleUsers = await User.countDocuments({ googleId: { $exists: true } });
    const activeUsers = await User.countDocuments({ isActive: true });
    const adminUsers = await User.countDocuments({ isAdmin: true });

    // Get user signups per day for the last 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const signupsByDay = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: thirtyDaysAgo }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { "_id": 1 }
      }
    ]);

    res.json({
      success: true,
      stats: {
        totalUsers,
        verifiedUsers,
        googleUsers,
        activeUsers,
        adminUsers,
        signupsByDay
      }
    });

  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching statistics'
    });
  }
});

// =============================================
// BOOKINGS MANAGEMENT ROUTES (NEW)
// =============================================

// Create a new booking (admin only)
app.post('/api/admin/bookings', authenticateAdmin, async (req, res) => {
  try {
    const { customerId, customerName, customerEmail, package, bookingDates, notes } = req.body;
    
    if (!customerName || !customerEmail || !package || !bookingDates) {
      return res.status(400).json({ 
        success: false,
        message: 'Customer name, email, package and booking dates are required'
      });
    }

    const newBooking = new Booking({
      customerId,
      customerName,
      customerEmail,
      package,
      bookingDates,
      notes,
      status: 'pending'
    });

    await newBooking.save();

    res.status(201).json({
      success: true,
      message: 'Booking created successfully',
      booking: newBooking
    });

  } catch (error) {
    console.error('Create booking error:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating booking'
    });
  }
});

// Get all bookings (admin only)
app.get('/api/admin/bookings', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '', sort = '-createdAt', status } = req.query;
    
    // Build query
    const query = {
      $or: [
        { customerName: { $regex: search, $options: 'i' } },
        { customerEmail: { $regex: search, $options: 'i' } },
        { package: { $regex: search, $options: 'i' } }
      ]
    };

    // Add status filter if provided
    if (status && ['pending', 'confirmed', 'cancelled'].includes(status)) {
      query.status = status;
    }

    const bookings = await Booking.find(query)
      .sort(sort)
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Booking.countDocuments(query);

    res.json({
      success: true,
      bookings,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });

  } catch (error) {
    console.error('Get bookings error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching bookings'
    });
  }
});

// Get booking details (admin only)
app.get('/api/admin/bookings/:id', authenticateAdmin, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);

    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    res.json({
      success: true,
      booking
    });

  } catch (error) {
    console.error('Get booking error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching booking'
    });
  }
});

// Update booking status (admin only)
app.patch('/api/admin/bookings/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!status || !['pending', 'confirmed', 'cancelled'].includes(status)) {
      return res.status(400).json({ 
        success: false,
        message: 'Valid status is required (pending, confirmed, cancelled)'
      });
    }

    const booking = await Booking.findByIdAndUpdate(
      req.params.id,
      { $set: { status } },
      { new: true }
    );

    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Send email notification to customer
    await sendEmail(
      booking.customerEmail,
      `Your Booking Has Been ${status.charAt(0).toUpperCase() + status.slice(1)} - Joker Creation Studio`,
      `<div style="font-family: Arial, sans-serif;">
        <h2 style="color: #be9c65;">Booking Status Update</h2>
        <p>Hello ${booking.customerName},</p>
        <p>The status of your booking for "${booking.package}" has been updated to <strong>${status}</strong>.</p>
        <p>Booking Details:</p>
        <ul>
          <li>Package: ${booking.package}</li>
          <li>Dates: ${booking.bookingDates}</li>
          <li>Status: ${status}</li>
        </ul>
        <p>If you have any questions, please contact us.</p>
      </div>`
    );

    res.json({
      success: true,
      message: 'Booking status updated successfully',
      booking
    });

  } catch (error) {
    console.error('Update booking status error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating booking status'
    });
  }
});

// Update booking details (admin only)
app.put('/api/admin/bookings/:id', authenticateAdmin, async (req, res) => {
  try {
    const { customerName, customerEmail, package, bookingDates, notes } = req.body;
    
    const updates = {};
    if (customerName) updates.customerName = customerName;
    if (customerEmail) updates.customerEmail = customerEmail;
    if (package) updates.package = package;
    if (bookingDates) updates.bookingDates = bookingDates;
    if (notes !== undefined) updates.notes = notes;

    const booking = await Booking.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: true }
    );

    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    res.json({
      success: true,
      message: 'Booking updated successfully',
      booking
    });

  } catch (error) {
    console.error('Update booking error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating booking'
    });
  }
});

// Delete booking (admin only)
app.delete('/api/admin/bookings/:id', authenticateAdmin, async (req, res) => {
  try {
    const booking = await Booking.findByIdAndDelete(req.params.id);

    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    res.json({
      success: true,
      message: 'Booking deleted successfully'
    });

  } catch (error) {
    console.error('Delete booking error:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting booking'
    });
  }
});

// Get booking statistics (admin only)
app.get('/api/admin/bookings/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalBookings = await Booking.countDocuments();
    const pendingBookings = await Booking.countDocuments({ status: 'pending' });
    const confirmedBookings = await Booking.countDocuments({ status: 'confirmed' });
    const cancelledBookings = await Booking.countDocuments({ status: 'cancelled' });

    // Get bookings per day for the last 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const bookingsByDay = await Booking.aggregate([
      {
        $match: {
          createdAt: { $gte: thirtyDaysAgo }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { "_id": 1 }
      }
    ]);

    res.json({
      success: true,
      stats: {
        totalBookings,
        pendingBookings,
        confirmedBookings,
        cancelledBookings,
        bookingsByDay
      }
    });

  } catch (error) {
    console.error('Get booking stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching booking statistics'
    });
  }
});

// =============================================
// MESSAGING SYSTEM ROUTES (NEW)
// =============================================

// Send message to user (admin only)
app.post('/api/admin/messages', authenticateAdmin, async (req, res) => {
  try {
    const { userEmail, message } = req.body;
    
    if (!userEmail || !message) {
      return res.status(400).json({ 
        success: false,
        message: 'User email and message are required'
      });
    }

    const newMessage = new Message({
      adminId: req.user._id,
      userEmail,
      message
    });

    await newMessage.save();

    // Send email to user
    await sendEmail(
      userEmail,
      'Message from Joker Creation Studio Admin',
      `<div style="font-family: Arial, sans-serif;">
        <h2 style="color: #be9c65;">Admin Message</h2>
        <p>Hello,</p>
        <p>You have received a message from the Joker Creation Studio admin:</p>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0;">
          ${message}
        </div>
        <p>Please reply to this email if you need to contact us.</p>
      </div>`
    );

    res.status(201).json({
      success: true,
      message: 'Message sent successfully',
      sentMessage: newMessage
    });

  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({
      success: false,
      message: 'Error sending message'
    });
  }
});

// Get all sent messages (admin only)
app.get('/api/admin/messages', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '', sort = '-createdAt', filter } = req.query;
    
    // Build query
    const query = {
      $or: [
        { userEmail: { $regex: search, $options: 'i' } },
        { message: { $regex: search, $options: 'i' } }
      ]
    };

    // Apply time filters if provided
    if (filter === 'today') {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      query.createdAt = { $gte: today };
    } else if (filter === 'week') {
      const oneWeekAgo = new Date();
      oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
      query.createdAt = { $gte: oneWeekAgo };
    } else if (filter === 'month') {
      const oneMonthAgo = new Date();
      oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
      query.createdAt = { $gte: oneMonthAgo };
    }

    const messages = await Message.find(query)
      .sort(sort)
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .populate('adminId', 'name email');

    const total = await Message.countDocuments(query);

    res.json({
      success: true,
      messages,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit))
    });

  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching messages'
    });
  }
});

// Get message details (admin only)
app.get('/api/admin/messages/:id', authenticateAdmin, async (req, res) => {
  try {
    const message = await Message.findById(req.params.id)
      .populate('adminId', 'name email');

    if (!message) {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }

    res.json({
      success: true,
      message
    });

  } catch (error) {
    console.error('Get message error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching message'
    });
  }
});

// Delete message (admin only)
app.delete('/api/admin/messages/:id', authenticateAdmin, async (req, res) => {
  try {
    const message = await Message.findByIdAndDelete(req.params.id);

    if (!message) {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }

    res.json({
      success: true,
      message: 'Message deleted successfully'
    });

  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting message'
    });
  }
});

// =============================================
// EXISTING USER ROUTES (KEPT EXACTLY AS BEFORE)
// =============================================

// [All your existing user routes remain unchanged...]
// Password Reset Endpoints, Google Sign-In, Email Login/Signup, etc.

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

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Frontend URL: ${process.env.FRONTEND_URL}`);
});
