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
  'EMAIL_USER', 'EMAIL_PASS', 'ADMIN_EMAIL', 'ADMIN_SECRET_KEY'
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
  isActive: { type: Boolean, default: true }
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
      isAdmin: user.isAdmin
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
    const adminEmail = process.env.ADMIN_EMAIL_ID;
    const adminPassword = process.env.ADMIN_PASS; // Changed from ADMIN_SECRET_KEY
    
    if (!adminEmail || !adminPassword) {
      throw new Error('Admin credentials not configured in environment variables');
    }

    const existingAdmin = await User.findOne({ email: adminEmail });
    
    if (!existingAdmin) {
      // Create new admin user
      const hashedPassword = await bcrypt.hash(adminPassword, 12);
      const adminUser = new User({
        name: 'Admin',
        email: adminEmail,
        password: hashedPassword,
        emailVerified: true,
        isAdmin: true,
        isActive: true
      });
      
      await adminUser.save();
      console.log('Admin user created successfully');
    } else {
      // Update existing admin user if needed
      let needsUpdate = false;
      
      if (!existingAdmin.isAdmin) {
        existingAdmin.isAdmin = true;
        needsUpdate = true;
        console.log('Existing user promoted to admin');
      }
      
      if (!existingAdmin.password) {
        const hashedPassword = await bcrypt.hash(adminPassword, 12);
        existingAdmin.password = hashedPassword;
        needsUpdate = true;
        console.log('Admin password set');
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
// ADMIN ROUTES - Updated with better error handling
// =============================================

// Middleware to verify admin status - Updated with better JWT handling
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

// Admin login endpoint - Updated with better password validation
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
        isAdmin: user.isAdmin
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

// =============================================
// NEW USER MANAGEMENT ROUTES
// =============================================

/**
 * @api {get} /api/admin/users Get all users
 * @apiName GetAllUsers
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiQuery {Number} [page=1] Page number
 * @apiQuery {Number} [limit=10] Users per page
 * @apiQuery {String} [search] Search term (name, email, or phone)
 * @apiQuery {String} [sort=-createdAt] Sort field and direction
 * @apiQuery {String} [status] Filter by status (active, inactive)
 * @apiQuery {Boolean} [verified] Filter by email verification status
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {Array} users List of users
 * @apiSuccess {Number} total Total number of users
 * @apiSuccess {Number} page Current page number
 * @apiSuccess {Number} pages Total number of pages
 */
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 10, 
      search = '', 
      sort = '-createdAt',
      status,
      verified
    } = req.query;
    
    const query = {
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } }
      ]
    };

    // Add status filter if provided
    if (status === 'active') {
      query.isActive = true;
    } else if (status === 'inactive') {
      query.isActive = false;
    }

    // Add verification filter if provided
    if (verified === 'true') {
      query.emailVerified = true;
    } else if (verified === 'false') {
      query.emailVerified = false;
    }

    const users = await User.find(query)
      .sort(sort)
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp');

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

/**
 * @api {get} /api/admin/users/:id Get user details
 * @apiName GetUser
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiParam {String} id User ID
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {Object} user User details
 */
app.get('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp');

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

/**
 * @api {post} /api/admin/users Create new user
 * @apiName CreateUser
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiBody {String} name User's name
 * @apiBody {String} email User's email
 * @apiBody {String} password User's password
 * @apiBody {String} [phone] User's phone number
 * @apiBody {Boolean} [isAdmin=false] Whether user is admin
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} user Created user details
 */
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

/**
 * @api {put} /api/admin/users/:id Update user
 * @apiName UpdateUser
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiParam {String} id User ID
 * 
 * @apiBody {String} [name] User's name
 * @apiBody {String} [email] User's email
 * @apiBody {String} [phone] User's phone number
 * @apiBody {Boolean} [isAdmin] Whether user is admin
 * @apiBody {Boolean} [isActive] Whether user is active
 * @apiBody {Boolean} [emailVerified] Whether email is verified
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} user Updated user details
 */
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
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp');

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

/**
 * @api {delete} /api/admin/users/:id Delete user
 * @apiName DeleteUser
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiParam {String} id User ID
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {String} message Success message
 */
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

/**
 * @api {post} /api/admin/users/:id/reset-password Reset user password
 * @apiName ResetUserPassword
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiParam {String} id User ID
 * 
 * @apiBody {String} newPassword New password
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {String} message Success message
 */
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

/**
 * @api {post} /api/admin/users/:id/deactivate Deactivate user
 * @apiName DeactivateUser
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiParam {String} id User ID
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} user Updated user details
 */
app.post('/api/admin/users/:id/deactivate', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { isActive: false } },
      { new: true }
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp');

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

/**
 * @api {post} /api/admin/users/:id/activate Activate user
 * @apiName ActivateUser
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiParam {String} id User ID
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} user Updated user details
 */
app.post('/api/admin/users/:id/activate', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { isActive: true } },
      { new: true }
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp');

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

/**
 * @api {post} /api/admin/users/:id/make-admin Make user admin
 * @apiName MakeUserAdmin
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiParam {String} id User ID
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} user Updated user details
 */
app.post('/api/admin/users/:id/make-admin', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { isAdmin: true } },
      { new: true }
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp');

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

/**
 * @api {post} /api/admin/users/:id/remove-admin Remove admin privileges
 * @apiName RemoveAdmin
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiParam {String} id User ID
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} user Updated user details
 */
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
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp');

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

/**
 * @api {post} /api/admin/users/:id/verify-email Verify user email
 * @apiName VerifyUserEmail
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiParam {String} id User ID
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {String} message Success message
 * @apiSuccess {Object} user Updated user details
 */
app.post('/api/admin/users/:id/verify-email', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { 
        $set: { emailVerified: true },
        $unset: { verificationToken: 1, verificationTokenExpires: 1 }
      },
      { new: true }
    ).select('-password -googleId -facebookId -verificationToken -resetPasswordToken -resetPasswordOtp');

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

/**
 * @api {get} /api/admin/stats Get user statistics
 * @apiName GetUserStats
 * @apiGroup Admin
 * @apiPermission admin
 * 
 * @apiSuccess {Boolean} success True if the request was successful
 * @apiSuccess {Object} stats User statistics
 * @apiSuccess {Number} stats.totalUsers Total number of users
 * @apiSuccess {Number} stats.verifiedUsers Number of verified users
 * @apiSuccess {Number} stats.googleUsers Number of Google users
 * @apiSuccess {Number} stats.activeUsers Number of active users
 * @apiSuccess {Number} stats.adminUsers Number of admin users
 * @apiSuccess {Array} stats.signupsByDay Daily signups for last 30 days
 */
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

// [All other existing routes remain exactly the same...]

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
