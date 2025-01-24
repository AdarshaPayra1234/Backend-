require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

// Create the Express app
const app = express();

// Middleware
app.use(cors({ origin: process.env.CORS_ORIGIN || 'https://jokercreation.store' })); // Allowing Netlify frontend to access backend
app.use(bodyParser.json()); // Parse incoming JSON requests

// MongoDB connection setup
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.log('Error connecting to MongoDB:', err));

// MongoDB Schema and Model for Users
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  phone: { type: String, required: true },
  status: { type: String, default: 'Active' },
  lastLogin: { type: Date, default: Date.now },
  otp: { type: String }, // Store OTP temporarily
  otpExpiration: { type: Date }, // OTP expiration time
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
    req.user = decoded; // Add user to request object
    next(); // Move to next middleware or route handler
  } catch (error) {
    return res.status(401).json({ message: 'Authentication failed, invalid token.' });
  }
};

// Signup Route
app.post('/api/signup', async (req, res) => {
  const { email, password, name, phone } = req.body;
  const lowercaseEmail = email.toLowerCase();

  try {
    const existingUser = await User.findOne({ email: lowercaseEmail });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email: lowercaseEmail,
      password: hashedPassword,
      name,
      phone,
    });

    await newUser.save();
    res.status(200).json({ message: 'User registered successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Login Route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const lowercaseEmail = email.toLowerCase();

  try {
    const user = await User.findOne({ email: lowercaseEmail });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Update last login date
    user.lastLogin = Date.now();
    await user.save();

    const token = generateJWT(user);
    res.status(200).json({
      success: true,
      token,
      message: 'Login successful',
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Account Route to fetch user details
app.get('/api/account', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json({
      user: {
        name: user.name,
        email: user.email,
        phone: user.phone,
        status: user.status,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Forgot Password Route
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
    user.otp = otp;
    user.otpExpiration = Date.now() + 3600000; // OTP expires in 1 hour
    await user.save();

    // Send OTP via email (Nodemailer setup)
    let transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP',
      html: `
        <html>
          <head>
            <style>
              body {
                font-family: Arial, sans-serif;
                background-color: #f4f7f6;
                color: #333;
                padding: 20px;
              }
              .email-container {
                background-color: #ffffff;
                border-radius: 8px;
                box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.1);
                padding: 20px;
                max-width: 600px;
                margin: 0 auto;
              }
              .header {
                background-color: #2980b9;
                color: white;
                text-align: center;
                padding: 15px;
                border-radius: 8px;
              }
              .header h2 {
                margin: 0;
                font-size: 24px;
              }
              .content {
                margin-top: 20px;
              }
              .content p {
                font-size: 16px;
                line-height: 1.5;
              }
              .otp-box {
                padding: 10px;
                background-color: #34495e;
                color: white;
                font-size: 20px;
                text-align: center;
                border-radius: 5px;
                margin-top: 15px;
                font-weight: bold;
              }
              .footer {
                margin-top: 20px;
                background-color: #2980b9;
                color: white;
                padding: 10px;
                text-align: center;
                border-radius: 8px;
              }
              .footer a {
                color: white;
                text-decoration: none;
                font-weight: bold;
              }
              .footer a:hover {
                text-decoration: underline;
              }
            </style>
          </head>
          <body>
            <div class="email-container">
              <div class="header">
                <h2>Password Reset Request</h2>
              </div>
              <div class="content">
                <p>Hello <strong>${user.name}</strong>,</p>
                <p>We received a request to reset your password. To complete the process, please use the OTP (One-Time Password) below:</p>
                <div class="otp-box">${otp}</div>
                <p>If you didn’t request a password reset, please ignore this email or contact support.</p>
                <p><strong>User Information:</strong></p>
                <ul>
                  <li><strong>Email:</strong> ${user.email}</li>
                  <li><strong>Phone Number:</strong> ${user.phone}</li>
                </ul>
              </div>
              <div class="footer">
                <p>If you need further assistance, feel free to <a href="mailto:support@jokercreation.com">contact us</a>.</p>
              </div>
            </div>
          </body>
        </html>
      `
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        return res.status(500).json({ message: 'Failed to send OTP email' });
      }
      res.status(200).json({ message: 'OTP sent to email.' });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Verify OTP Route
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if OTP is valid and not expired
    if (user.otp !== otp || Date.now() > user.otpExpiration) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    res.status(200).json({ message: 'OTP verified successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Reset Password Route
app.post('/api/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if OTP is valid and not expired
    if (user.otp !== otp || Date.now() > user.otpExpiration) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password and clear OTP
    user.password = hashedPassword;
    user.otp = null; // Clear OTP after successful password reset
    user.otpExpiration = null; // Clear OTP expiration time
    await user.save();

    res.status(200).json({ message: 'Password reset successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Server listener
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
