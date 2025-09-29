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
const path = require('path');

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


// ==================== SHARED RBAC SCHEMAS ====================

// Shared Admin Profile Schema (used by both backends)
const adminProfileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  role: { 
    type: String, 
    required: true, 
    enum: ['super_admin', 'admin', 'editor', 'booking_manager', 'viewer'],
    default: 'viewer'
  },
  // Systems this admin can access
  systems: {
    user_management: { type: Boolean, default: false },
    booking_management: { type: Boolean, default: false }
  },
  // Specific permissions for each system
  permissions: {
    user_management: {
      users: { type: Boolean, default: false },
      analytics: { type: Boolean, default: false },
      system_settings: { type: Boolean, default: false }
    },
    booking_management: {
      bookings: { type: Boolean, default: false },
      gallery: { type: Boolean, default: false },
      messages: { type: Boolean, default: false },
      coupons: { type: Boolean, default: false },
      reports: { type: Boolean, default: false }
    }
  },
  isActive: { type: Boolean, default: true },
  lastLogin: Date,
  loginHistory: [{
    timestamp: Date,
    ipAddress: String,
    userAgent: String,
    system: { type: String, enum: ['user_management', 'booking_management'] }
  }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

// Shared Audit Log Schema (used by both backends)
const auditLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  adminEmail: String,
  action: { type: String, required: true }, // login, create, update, delete, etc.
  resource: { type: String, required: true }, // user, booking, etc.
  resourceId: String,
  system: { type: String, enum: ['user_management', 'booking_management'], required: true },
  ipAddress: String,
  userAgent: String,
  details: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now }
});

const AdminProfile = mongoose.model('AdminProfile', adminProfileSchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// ==================== ROLE PERMISSIONS CONFIGURATION ====================

const rolePermissions = {
  super_admin: {
    systems: {
      user_management: true,
      booking_management: true
    },
    permissions: {
      user_management: {
        users: true,
        analytics: true,
        system_settings: true
      },
      booking_management: {
        bookings: true,
        gallery: true,
        messages: true,
        coupons: true,
        reports: true
      }
    },
    description: 'Full access to all systems'
  },
  admin: {
    systems: {
      user_management: true,
      booking_management: true
    },
    permissions: {
      user_management: {
        users: true,
        analytics: true,
        system_settings: false
      },
      booking_management: {
        bookings: true,
        gallery: true,
        messages: true,
        coupons: true,
        reports: false
      }
    },
    description: 'Administrative access to most features'
  },
  editor: {
    systems: {
      user_management: false,
      booking_management: true
    },
    permissions: {
      user_management: {
        users: false,
        analytics: false,
        system_settings: false
      },
      booking_management: {
        bookings: true,
        gallery: true,
        messages: true,
        coupons: false,
        reports: false
      }
    },
    description: 'Content editing privileges for booking system'
  },
  booking_manager: {
    systems: {
      user_management: false,
      booking_management: true
    },
    permissions: {
      user_management: {
        users: false,
        analytics: false,
        system_settings: false
      },
      booking_management: {
        bookings: true,
        gallery: false,
        messages: true,
        coupons: false,
        reports: true
      }
    },
    description: 'Booking management privileges'
  },
  viewer: {
    systems: {
      user_management: true,
      booking_management: true
    },
    permissions: {
      user_management: {
        users: true,
        analytics: true,
        system_settings: false
      },
      booking_management: {
        bookings: true,
        gallery: true,
        messages: false,
        coupons: false,
        reports: true
      }
    },
    description: 'Read-only access to both systems'
  }
};

// Google OAuth Client
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET
});

// Email configuration
// Email configuration for Hostinger
const transporter = nodemailer.createTransport({
  host: 'smtp.hostinger.com',
  port: 465, // SSL port
  secure: true, // true for 465, false for other ports
  auth: {
    user: 'contact@jokercreation.store', // Your Hostinger email
    pass: process.env.EMAIL_PASS // Password from .env
  },
  tls: {
    rejectUnauthorized: false // For self-signed certificates
  },
  pool: true, // Use connection pooling
  maxConnections: 5,
  maxMessages: 100,
  rateLimit: 5,
  debug: process.env.NODE_ENV === 'development'
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

// ==================== ENHANCED ADMIN INITIALIZATION ====================

const initializeAdminUser = async () => {
  try {
    const adminEmail = process.env.ADMIN_EMAIL_ID;
    const adminPassword = process.env.ADMIN_SECRET_KEY;
    
    if (!adminEmail || !adminPassword) {
      throw new Error('Admin credentials not configured in environment variables');
    }

    const existingAdmin = await User.findOne({ email: adminEmail });
    
    if (!existingAdmin) {
      // Create new super admin user
      const hashedPassword = await bcrypt.hash(adminPassword, 12);
      const adminUser = new User({
        name: 'Super Admin',
        email: adminEmail,
        password: hashedPassword,
        emailVerified: true,
        isAdmin: true,
        isActive: true
      });
      
      await adminUser.save();
      
      // Create admin profile with super_admin role
      const adminProfile = new AdminProfile({
        userId: adminUser._id,
        role: 'super_admin',
        systems: rolePermissions.super_admin.systems,
        permissions: rolePermissions.super_admin.permissions,
        isActive: true
      });
      
      await adminProfile.save();
      console.log('✅ Super admin user created with full system access');
      
    } else {
      // Ensure existing admin has proper profile
      let adminProfile = await AdminProfile.findOne({ userId: existingAdmin._id });
      
      if (!adminProfile) {
        adminProfile = new AdminProfile({
          userId: existingAdmin._id,
          role: 'super_admin',
          systems: rolePermissions.super_admin.systems,
          permissions: rolePermissions.super_admin.permissions,
          isActive: true
        });
        await adminProfile.save();
        console.log('✅ Admin profile created for existing user');
      }
      
      // Ensure user is marked as admin
      if (!existingAdmin.isAdmin) {
        existingAdmin.isAdmin = true;
        await existingAdmin.save();
        console.log('✅ Existing user promoted to admin');
      }
    }
    
    console.log('✅ RBAC admin initialization completed');
    
  } catch (error) {
    console.error('❌ Error initializing admin user:', error);
    process.exit(1);
  }
};

// Call the function to initialize admin user when server starts
initializeAdminUser();

// =============================================
// ADMIN ROUTES
// =============================================

// Middleware to verify admin status
// ==================== SIMPLIFIED RBAC AUTHENTICATION ====================

// Enhanced admin authentication
const authenticateAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const targetSystem = req.headers['x-target-system'] || 'user_management';

    if (!authHeader) {
      return res.status(401).json({ 
        success: false,
        message: 'Authorization header missing',
        code: 'MISSING_AUTH_HEADER'
      });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: 'Authorization token missing',
        code: 'MISSING_TOKEN'
      });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ 
        success: false,
        message: 'Invalid or expired token',
        code: 'INVALID_TOKEN'
      });
    }

    const user = await User.findById(decoded.id);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ 
        success: false,
        message: 'Admin access required',
        code: 'ADMIN_ACCESS_REQUIRED'
      });
    }

    // Get admin profile from shared database
    const adminProfile = await AdminProfile.findOne({ userId: user._id });
    if (!adminProfile || !adminProfile.isActive) {
      return res.status(403).json({ 
        success: false,
        message: 'Admin profile not active or not found',
        code: 'ADMIN_PROFILE_INACTIVE'
      });
    }

    // Check if admin has access to the target system
    if (!adminProfile.systems[targetSystem]) {
      return res.status(403).json({ 
        success: false,
        message: `Access to ${targetSystem} system not granted`,
        code: 'SYSTEM_ACCESS_DENIED'
      });
    }

    // Add admin info to request
    req.user = user;
    req.adminProfile = adminProfile;
    req.targetSystem = targetSystem;

    // Log login activity
    await logAdminActivity(req, 'login', targetSystem);

    next();

  } catch (error) {
    console.error('Admin authentication error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error during authentication',
      code: 'AUTHENTICATION_ERROR'
    });
  }
};

// Permission check middleware
const checkPermission = (resource, action = 'access') => {
  return async (req, res, next) => {
    try {
      const { adminProfile, targetSystem } = req;

      // Super admin has all permissions
      if (adminProfile.role === 'super_admin') {
        return next();
      }

      // Check if admin has permission for this resource in the target system
      const hasPermission = adminProfile.permissions[targetSystem]?.[resource];
      
      if (!hasPermission) {
        return res.status(403).json({ 
          success: false,
          message: `Insufficient permissions for ${resource} in ${targetSystem}`,
          code: 'INSUFFICIENT_PERMISSIONS'
        });
      }

      next();
    } catch (err) {
      console.error('Permission check error:', err);
      res.status(500).json({ 
        success: false,
        message: 'Permission verification failed',
        code: 'PERMISSION_CHECK_FAILED'
      });
    }
  };
};

// Audit logging
const auditLog = (action, resource) => {
  return async (req, res, next) => {
    const originalSend = res.send;
    
    res.send = function(data) {
      // Log the action asynchronously
      if (req.adminProfile) {
        const auditRecord = new AuditLog({
          adminId: req.user._id,
          adminEmail: req.user.email,
          action,
          resource,
          resourceId: req.params.id,
          system: req.targetSystem,
          ipAddress: req.clientIp,
          userAgent: req.get('User-Agent'),
          details: {
            method: req.method,
            url: req.originalUrl
          },
          timestamp: new Date()
        });
        
        auditRecord.save().catch(err => 
          console.error('Audit log save error:', err)
        );
      }
      
      originalSend.call(this, data);
    };
    
    next();
  };
};

// Log admin activity
const logAdminActivity = async (req, action, system) => {
  try {
    await AdminProfile.findOneAndUpdate(
      { userId: req.user._id },
      {
        $set: { lastLogin: new Date() },
        $push: {
          loginHistory: {
            timestamp: new Date(),
            ipAddress: req.clientIp,
            userAgent: req.get('User-Agent'),
            system: system
          }
        }
      }
    );
  } catch (err) {
    console.error('Error logging admin activity:', err);
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

// Get all users (admin only)
app.get('/api/admin/users', 
  authenticateAdmin,
  checkPermission('users'),
  auditLog('read', 'users'),
  async (req, res) => {
  try {
      const { page = 1, limit = 10, search = '', sort = '-createdAt' } = req.query;
      
      const query = {
        $or: [
          { name: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
          { phone: { $regex: search, $options: 'i' } }
        ]
      };

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
  }
);

// Get user details (admin only)
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

// Create new user (admin only)
app.post('/api/admin/users',
  authenticateAdmin,
  checkPermission('users'),
  auditLog('create', 'users'),
  async (req, res) => {
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
app.put('/api/admin/users/:id',
  authenticateAdmin,
  checkPermission('users'),
  auditLog('update', 'users'),
  async (req, res) => {
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

// Activate user (admin only)
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

// Make user admin (admin only)
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


// ==================== ADMIN MANAGEMENT ROUTES ====================

// Get current admin's profile and permissions
app.get('/api/admin/my-profile', 
  authenticateAdmin,
  async (req, res) => {
    try {
      res.json({
        success: true,
        admin: {
          id: req.user._id,
          name: req.user.name,
          email: req.user.email,
          role: req.adminProfile.role,
          systems: req.adminProfile.systems,
          permissions: req.adminProfile.permissions,
          lastLogin: req.adminProfile.lastLogin
        }
      });
    } catch (err) {
      console.error('Error fetching admin profile:', err);
      res.status(500).json({ 
        success: false,
        message: 'Failed to fetch admin profile'
      });
    }
  }
);

// Get all admins (super_admin only)
app.get('/api/admin/management/admins',
  authenticateAdmin,
  checkPermission('system_settings'),
  auditLog('read', 'admins'),
  async (req, res) => {
    try {
      const admins = await User.aggregate([
        { $match: { isAdmin: true } },
        {
          $lookup: {
            from: 'adminprofiles',
            localField: '_id',
            foreignField: 'userId',
            as: 'profile'
          }
        },
        {
          $project: {
            password: 0,
            googleId: 0,
            facebookId: 0,
            verificationToken: 0,
            resetPasswordToken: 0,
            resetPasswordOtp: 0
          }
        },
        { $sort: { createdAt: -1 } }
      ]);
      
      // Format response
      const formattedAdmins = admins.map(admin => ({
        user: {
          id: admin._id,
          name: admin.name,
          email: admin.email,
          isActive: admin.isActive,
          createdAt: admin.createdAt
        },
        profile: admin.profile[0] || null
      }));
      
      res.json({ 
        success: true, 
        admins: formattedAdmins
      });
    } catch (err) {
      console.error('Error fetching admins:', err);
      res.status(500).json({ 
        success: false,
        message: 'Failed to fetch admins'
      });
    }
  }
);

// Create new admin
app.post('/api/admin/management/admins',
  authenticateAdmin,
  checkPermission('system_settings'),
  auditLog('create', 'admins'),
  async (req, res) => {
    try {
      const { email, password, name, role } = req.body;

      if (!email || !password || !name || !role) {
        return res.status(400).json({ 
          success: false,
          message: 'Email, password, name, and role are required'
        });
      }

      if (!rolePermissions[role]) {
        return res.status(400).json({ 
          success: false,
          message: 'Invalid role specified'
        });
      }

      // Check if user already exists
      const existingUser = await User.findOne({ email: email.toLowerCase() });
      if (existingUser) {
        return res.status(400).json({ 
          success: false,
          message: 'User with this email already exists'
        });
      }

      // Create new user
      const hashedPassword = await bcrypt.hash(password, 12);
      const newUser = new User({
        name,
        email: email.toLowerCase(),
        password: hashedPassword,
        emailVerified: true,
        isAdmin: true,
        isActive: true
      });

      await newUser.save();

      // Create admin profile with role-based permissions
      const adminProfile = new AdminProfile({
        userId: newUser._id,
        role: role,
        systems: rolePermissions[role].systems,
        permissions: rolePermissions[role].permissions,
        isActive: true,
        createdBy: req.user._id
      });

      await adminProfile.save();

      res.status(201).json({
        success: true,
        message: 'Admin created successfully',
        admin: {
          id: newUser._id,
          name: newUser.name,
          email: newUser.email,
          role: adminProfile.role,
          systems: adminProfile.systems
        }
      });

    } catch (err) {
      console.error('Error creating admin:', err);
      res.status(500).json({ 
        success: false,
        message: 'Failed to create admin'
      });
    }
  }
);

// Update admin role and permissions
app.put('/api/admin/management/admins/:id',
  authenticateAdmin,
  checkPermission('system_settings'),
  auditLog('update', 'admins'),
  async (req, res) => {
    try {
      const { role, isActive } = req.body;
      const adminId = req.params.id;

      // Prevent self-demotion
      if (adminId === req.user._id.toString() && role !== 'super_admin') {
        return res.status(400).json({ 
          success: false,
          message: 'Cannot remove your own super_admin role'
        });
      }

      const updates = {};
      if (role && rolePermissions[role]) {
        updates.role = role;
        updates.systems = rolePermissions[role].systems;
        updates.permissions = rolePermissions[role].permissions;
      }
      if (typeof isActive !== 'undefined') {
        updates.isActive = isActive;
      }

      const updatedProfile = await AdminProfile.findOneAndUpdate(
        { userId: adminId },
        { $set: updates },
        { new: true }
      ).populate('userId', 'name email');

      if (!updatedProfile) {
        return res.status(404).json({ 
          success: false,
          message: 'Admin profile not found'
        });
      }

      res.json({
        success: true,
        message: 'Admin updated successfully',
        admin: {
          id: updatedProfile.userId._id,
          name: updatedProfile.userId.name,
          email: updatedProfile.userId.email,
          role: updatedProfile.role,
          systems: updatedProfile.systems,
          isActive: updatedProfile.isActive
        }
      });

    } catch (err) {
      console.error('Error updating admin:', err);
      res.status(500).json({ 
        success: false,
        message: 'Failed to update admin'
      });
    }
  }
);

// Get audit logs
app.get('/api/admin/audit-logs',
  authenticateAdmin,
  checkPermission('analytics'),
  async (req, res) => {
    try {
      const { system, page = 1, limit = 50 } = req.query;
      
      let query = {};
      if (system) query.system = system;

      const skip = (page - 1) * limit;
      const logs = await AuditLog.find(query)
        .populate('adminId', 'name email')
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(parseInt(limit));

      const total = await AuditLog.countDocuments(query);

      res.json({
        success: true,
        logs,
        total,
        totalPages: Math.ceil(total / limit),
        currentPage: parseInt(page)
      });
    } catch (err) {
      console.error('Error fetching audit logs:', err);
      res.status(500).json({ 
        success: false,
        message: 'Failed to fetch audit logs'
      });
    }
  }
);

// =============================================
// EXISTING USER ROUTES (KEPT EXACTLY AS BEFORE)
// =============================================

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

    // Generate and save reset token and OTP
    const resetToken = generateToken();
    const otp = generateOTP();
    
    user.resetPasswordToken = resetToken;
    user.resetPasswordOtp = otp;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // Send email with OTP
    await sendEmail(
      user.email,
      'Password Reset OTP - Joker Creation Studio',
      `<div style="font-family: Arial, sans-serif;">
        <h2 style="color: #be9c65;">Password Reset OTP</h2>
        <p>Hello ${user.name},</p>
        <p>You are receiving this because you (or someone else) have requested to reset the password for your account.</p>
        <p>Your OTP for password reset is: <strong>${otp}</strong></p>
        <p>Enter this code in the password reset form to verify your identity.</p>
        <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
        <p>The OTP will expire in 1 hour.</p>
      </div>`
    );

    res.json({
      success: true,
      message: 'Password reset OTP sent',
      token: resetToken // Return token for subsequent verification
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error processing password reset request'
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
        message: 'Invalid or expired token'
      });
    }

    if (user.resetPasswordOtp !== otp) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid OTP'
      });
    }

    // OTP is valid, clear the OTP but keep the token for password reset
    user.resetPasswordOtp = undefined;
    await user.save();

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

// Resend OTP endpoint
app.post('/api/resend-otp', async (req, res) => {
  try {
    const { email, token } = req.body;
    
    if (!email || !token) {
      return res.status(400).json({ 
        success: false,
        message: 'Email and token are required'
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
        message: 'Invalid or expired token'
      });
    }

    // Generate new OTP
    const newOtp = generateOTP();
    user.resetPasswordOtp = newOtp;
    user.resetPasswordExpires = Date.now() + 3600000; // Reset expiration to 1 hour
    await user.save();

    // Send email with new OTP
    await sendEmail(
      user.email,
      'New Password Reset OTP - Joker Creation Studio',
      `<div style="font-family: Arial, sans-serif;">
        <h2 style="color: #be9c65;">New Password Reset OTP</h2>
        <p>Hello ${user.name},</p>
        <p>Your new OTP for password reset is: <strong>${newOtp}</strong></p>
        <p>Enter this code in the password reset form to verify your identity.</p>
        <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
        <p>The OTP will expire in 1 hour.</p>
      </div>`
    );

    res.json({
      success: true,
      message: 'New OTP sent successfully',
      token: user.resetPasswordToken // Return same token
    });

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error resending OTP'
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

    // Update password and clear reset fields
    user.password = await bcrypt.hash(newPassword, 12);
    user.resetPasswordToken = undefined;
    user.resetPasswordOtp = undefined;
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
// Google Sign-Up Endpoint (with Phone Verification Support)
app.post('/api/signup/google', async (req, res) => {
  try {
    const { credential, userAgent, name, email, googleId, picture, phone } = req.body;
    const ip = req.clientIp;
    const location = getLocationFromIp(ip);
    
    // Support both credential-based and direct data signup
    let payload;
    if (credential) {
      // Traditional Google OAuth flow
      const ticket = await googleClient.verifyIdToken({
        idToken: credential,
        audience: process.env.GOOGLE_CLIENT_ID
      });
      payload = ticket.getPayload();
    } else if (googleId && email) {
      // Direct data flow (from frontend modal with phone verification)
      payload = {
        sub: googleId,
        email: email,
        email_verified: true,
        name: name,
        picture: picture
      };
    } else {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid request parameters. Either credential or googleId+email are required.'
      });
    }

    if (!payload.email_verified) {
      return res.status(400).json({ 
        success: false,
        message: 'Google email not verified'
      });
    }

    // Check if user already exists
    let user = await User.findOne({ 
      $or: [
        { email: payload.email.toLowerCase() },
        { googleId: payload.sub }
      ]
    });

    if (user) {
      // Update existing user with phone number if provided
      if (phone) {
        user.phone = phone;
      }
      
      user.lastLogin = new Date();
      user.ipAddress = ip;
      user.location = location;
      user.userAgent = userAgent || req.headers['user-agent'];
      await user.save();
    } else {
      // Create new user
      user = new User({
        name: payload.name,
        email: payload.email.toLowerCase(),
        googleId: payload.sub,
        phone: phone,
        emailVerified: true,
        lastLogin: new Date(),
        ipAddress: ip,
        location: location,
        userAgent: userAgent || req.headers['user-agent']
      });
      await user.save();
    }

    const token = generateJWT(user);

    // Send notification email to admin
    await sendEmail(
      process.env.ADMIN_EMAIL,
      'New Google Signup - Joker Creation Studio',
      `<div style="font-family: Arial, sans-serif;">
        <h2 style="color: #be9c65;">New Google Signup</h2>
        <p><strong>Name:</strong> ${user.name}</p>
        <p><strong>Email:</strong> ${user.email}</p>
        <p><strong>Phone:</strong> ${user.phone || 'Not provided'}</p>
        <p><strong>IP:</strong> ${ip}</p>
        <p><strong>Location:</strong> ${location.city}, ${location.region}, ${location.country}</p>
        <p><strong>Signup Method:</strong> Google OAuth</p>
      </div>`
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
    
    // Handle specific errors
    if (error.message.includes('Invalid token signature')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid Google authentication token'
      });
    }
    
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

// Edit Profile Endpoint
app.put('/api/user', authenticateUser, async (req, res) => {
  try {
    const { name, phone } = req.body;
    
    // Validate input
    if (!name && !phone) {
      return res.status(400).json({ 
        success: false,
        message: 'At least one field (name or phone) is required for update'
      });
    }

    // Update only the fields that are provided
    const updateFields = {};
    if (name) updateFields.name = name;
    if (phone) updateFields.phone = phone;

    // Update user in database
    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { $set: updateFields },
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        emailVerified: updatedUser.emailVerified,
        phone: updatedUser.phone
      }
    });

  } catch (error) {
    console.error('Edit profile error:', error);
    
    // Handle validation errors
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        success: false,
        message: error.message
      });
    }
    
    res.status(500).json({ 
      success: false,
      message: 'Error updating profile'
    });
  }
});

// Health check endpoint
// ==================== RENDER FREE TIER KEEP-AWAKE ENDPOINTS ====================

// Simple keep-alive endpoint for Render free tier
app.get('/api/keep-alive', (req, res) => {
  console.log(`🏓 Keep-alive ping at: ${new Date().toISOString()} from IP: ${req.ip}`);
  
  res.json({ 
    success: true, 
    message: 'Server is awake!',
    timestamp: new Date().toISOString(),
    serverTime: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
    uptime: process.uptime()
  });
});

// Quick health check for cronjobs
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: Math.round(process.memoryUsage().rss / 1024 / 1024) + ' MB'
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Frontend URL: ${process.env.FRONTEND_URL}`);
});






