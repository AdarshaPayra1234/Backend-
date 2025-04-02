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
    return req.socket.remoteAddress;
  },
  message: 'Too many requests from this IP, please try again later'
});
app.use(limiter);

// Database connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// Enhanced User Schema with bookings reference
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
  lastLogin: { type: Date },
  bookings: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Booking' }]
}, { timestamps: true });

// Booking Schema
const bookingSchema = new mongoose.Schema({
  bookingId: { type: String, required: true, unique: true },
  customerName: { type: String, required: true },
  customerEmail: { type: String, required: true },
  customerPhone: { type: String, required: true },
  package: { type: String, required: true },
  bookingDate: { type: Date, required: true },
  eventDate: { type: Date, required: true },
  address: { type: String, required: true },
  transactionId: { type: String, required: true },
  amountPaid: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'confirmed', 'cancelled'], default: 'confirmed' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Booking = mongoose.model('Booking', bookingSchema);

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

const generateBookingId = () => {
  return 'JC-' + Date.now().toString(36).toUpperCase() + 
         Math.random().toString(36).substr(2, 4).toUpperCase();
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

// Enhanced User Details Endpoint
app.get('/api/user-details', authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .populate({
        path: 'bookings',
        select: 'bookingId package bookingDate eventDate status amountPaid',
        options: { sort: { createdAt: -1 } }
      });

    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        emailVerified: user.emailVerified,
        bookings: user.bookings,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch user details'
    });
  }
});

// Get User Bookings
app.get('/api/user-bookings', authenticateUser, async (req, res) => {
  try {
    const bookings = await Booking.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .select('bookingId package bookingDate eventDate status amountPaid transactionId');

    res.json({
      success: true,
      bookings
    });
  } catch (error) {
    console.error('Error fetching user bookings:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch bookings'
    });
  }
});

// Save Booking (integrated with user account)
app.post('/api/save-booking', authenticateUser, async (req, res) => {
  try {
    const {
      customerName,
      customerEmail,
      customerPhone,
      package,
      bookingDate,
      eventDate,
      address,
      transactionId,
      amountPaid
    } = req.body;

    const bookingId = generateBookingId();

    const newBooking = new Booking({
      bookingId,
      customerName,
      customerEmail,
      customerPhone,
      package,
      bookingDate,
      eventDate,
      address,
      transactionId,
      amountPaid,
      userId: req.user.id
    });

    const savedBooking = await newBooking.save();

    // Add booking to user's bookings array
    await User.findByIdAndUpdate(req.user.id, {
      $push: { bookings: savedBooking._id }
    });

    // Send confirmation email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: customerEmail,
      subject: 'Booking Confirmation - Joker Creation Studio',
      html: generateBookingConfirmationEmail(savedBooking)
    };

    await transporter.sendMail(mailOptions);

    res.json({
      success: true,
      message: 'Booking saved successfully',
      booking: {
        id: savedBooking._id,
        bookingId: savedBooking.bookingId,
        package: savedBooking.package,
        bookingDate: savedBooking.bookingDate,
        eventDate: savedBooking.eventDate,
        status: savedBooking.status
      }
    });

  } catch (error) {
    console.error('Error saving booking:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to save booking'
    });
  }
});

function generateBookingConfirmationEmail(booking) {
  return `
    <div style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
      <div style="max-width: 600px; margin: auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);">
        <h2 style="color: #2c3e50; text-align: center;">Booking Confirmation</h2>
        <p style="font-size: 16px; color: #34495e;">Hello ${booking.customerName},</p>
        <p style="font-size: 16px; color: #34495e;">Thank you for booking with Joker Creation Studio! Here are your booking details:</p>
        
        <table style="width: 100%; margin-top: 20px; border-collapse: collapse;">
          <tr style="background-color: #ecf0f1;">
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Booking ID</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e;">${booking.bookingId}</td>
          </tr>
          <tr>
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Package</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e;">${booking.package}</td>
          </tr>
          <tr style="background-color: #ecf0f1;">
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Booking Date</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e;">${new Date(booking.bookingDate).toLocaleDateString()}</td>
          </tr>
          <tr>
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Event Date</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e;">${new Date(booking.eventDate).toLocaleDateString()}</td>
          </tr>
          <tr style="background-color: #ecf0f1;">
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Amount Paid</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e;">₹${booking.amountPaid}</td>
          </tr>
          <tr>
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Status</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e; text-transform: capitalize;">${booking.status}</td>
          </tr>
        </table>

        <p style="font-size: 16px; color: #34495e; margin-top: 20px;">
          You can view and manage your booking in your <a href="${process.env.FRONTEND_URL}/account.html" style="color: #2980b9;">account page</a>.
        </p>

        <p style="font-size: 16px; color: #34495e; text-align: center; margin-top: 30px;">
          Regards, <br><strong>Joker Creation Studio</strong>
        </p>
      </div>
    </div>
  `;
}

// [All your existing authentication routes remain unchanged...]
// Password Reset, Google Auth, Email Login/Signup etc.
// ...

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

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Frontend URL: ${process.env.FRONTEND_URL}`);
});
