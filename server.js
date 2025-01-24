// server.js

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
app.use(cors({ origin: 'https://jokercreation.netlify.app' })); // Allowing Netlify frontend to access backend
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
  status: { type: String, default: 'Active' },  // Default status field
  lastLogin: { type: Date, default: Date.now },  // Last login time
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

    // Update last login date on successful login
    user.lastLogin = Date.now();
    await user.save();

    const token = generateJWT(user);
    res.status(200).json({
      token,
      message: 'Login successful',
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Password Reset Route (OTP generation & email sending)
app.post('/api/reset-password', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate OTP and set expiration time
    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
    const otpExpiration = new Date(Date.now() + 15 * 60 * 1000); // OTP valid for 15 minutes

    // Update OTP and OTP expiration in the database
    user.otp = otp;
    user.otpExpiration = otpExpiration;
    await user.save();

    // Send OTP via email (with a colorful, professional email format)
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request from Joker Creation Studio',
      html: `
        <div style="font-family: Arial, sans-serif; color: #333; padding: 20px; background-color: #f7f7f7;">
          <h2 style="color: #2196f3;">Hello ${user.name},</h2>
          <p style="font-size: 16px;">We received a request to reset your password at Joker Creation Studio. Please use the OTP below to reset your password:</p>
          <h3 style="color: #4caf50;">OTP: <strong>${otp}</strong></h3>
          <p style="font-size: 14px;">This OTP is valid for 15 minutes. If you did not request a password reset, please ignore this message.</p>
          <p style="color: #888;">Joker Creation Studio - Capture Moments, Create Memories</p>
          <p style="font-size: 14px; color: #888;">If you have any questions, feel free to contact us at <a href="mailto:support@jokercreation.com">support@jokercreation.com</a></p>
        </div>
      `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        return res.status(500).json({ message: 'Error sending OTP. Please try again.' });
      }
      res.status(200).json({ message: 'OTP sent to email' });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// OTP Verification Route
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if OTP is valid and not expired
    if (user.otp !== otp || user.otpExpiration < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    res.status(200).json({ message: 'OTP verified' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Password Update Route (after OTP verification)
app.post('/api/update-password', async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = null; // Clear OTP after password reset
    user.otpExpiration = null; // Clear OTP expiration time
    await user.save();

    res.status(200).json({ message: 'Password updated successfully' });
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
